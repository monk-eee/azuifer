//! Randomized comparison of snapshots, versions, soft delete and container restore with an
//! oracle (specification section 14).
//!
//! The oracle holds what Azure's documentation says should exist after each operation:
//! which contents a blob, its snapshots, its versions and its soft-deleted state keep, and
//! when each stops being visible. The store must agree on every listing and every byte read,
//! and on disk it must hold exactly one extent file per distinct retained content, so a
//! leaked extent or one freed too early fails the comparison.

mod run;

use super::*;
use crate::blob_snapshot::DeleteSnapshots;
use std::collections::{BTreeMap, BTreeSet};

const HOUR: i64 = 3_600_000;
const RETENTION: i64 = 48 * HOUR;
const NAMES: [&str; 3] = ["a", "b", "c"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Config {
    Plain,
    Soft,
    Versioned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Removed {
    Permanently,
    Kept,
}

/// A snapshot: soft-deleted (until `expires`) or live.
#[derive(Clone)]
struct Snap {
    content: u32,
    expires: Option<i64>,
    time: Option<Ticks>,
}

#[derive(Clone, Default)]
struct Blob {
    current: Option<u32>,
    snaps: Vec<Snap>,
    versions: Vec<u32>,
    /// The soft-deleted blob, with its expiry.
    tomb: Option<(u32, i64)>,
}

#[derive(Clone, Default)]
struct Container {
    blobs: BTreeMap<&'static str, Blob>,
}

#[derive(Clone)]
struct World {
    config: Config,
    /// Model time in milliseconds; only whole hours are ever added.
    now: i64,
    live: Option<Container>,
    /// Soft-deleted containers, oldest first, with their expiry.
    hidden: Vec<(Container, i64)>,
}

type Outcome<T> = std::result::Result<T, Error>;

impl World {
    /// Every store call first erases the soft-deleted containers whose retention ended.
    fn start(&mut self) {
        let now = self.now;
        self.hidden.retain(|(_, expires)| *expires > now);
    }

    /// An operation that also purges expired soft-deleted entries; if it fails its
    /// transaction rolls back, purge included.
    fn purging<T>(&mut self, operation: impl FnOnce(&mut Self) -> Outcome<T>) -> Outcome<T> {
        self.start();
        let saved = self.clone();
        self.purge();
        let result = operation(self);
        if result.is_err() {
            *self = saved;
        }
        result
    }

    fn plain<T>(&mut self, operation: impl FnOnce(&mut Self) -> Outcome<T>) -> Outcome<T> {
        self.start();
        operation(self)
    }

    fn purge(&mut self) {
        let now = self.now;
        let hidden = self.hidden.iter_mut().map(|(container, _)| container);
        for container in self.live.iter_mut().chain(hidden) {
            for blob in container.blobs.values_mut() {
                blob.snaps
                    .retain(|snap| snap.expires.is_none_or(|e| e > now));
                if blob.tomb.is_some_and(|(_, expires)| expires <= now) {
                    blob.tomb = None;
                }
            }
        }
    }

    fn container(&mut self) -> Outcome<&mut Container> {
        self.live.as_mut().ok_or(Error::ContainerMissing)
    }

    /// The blob that has a current state, and that state.
    fn existing(&mut self, name: &str) -> Outcome<(&mut Blob, u32)> {
        let blob = self.container()?.blobs.get_mut(name);
        let blob = blob.ok_or(Error::BlobMissing)?;
        let content = blob.current.ok_or(Error::BlobMissing)?;
        Ok((blob, content))
    }

    fn put(&mut self, name: &'static str, content: u32) -> Outcome<()> {
        self.plain(|w| {
            let (config, now) = (w.config, w.now);
            let blob = w.container()?.blobs.entry(name).or_default();
            if let Some(old) = blob.current.replace(content) {
                match config {
                    // Overwriting keeps the old state as a soft-deleted snapshot.
                    Config::Soft => blob.snaps.push(Snap {
                        content: old,
                        expires: Some(now + RETENTION),
                        time: None,
                    }),
                    Config::Versioned => blob.versions.push(old),
                    Config::Plain => {}
                }
            }
            Ok(())
        })
    }

    fn snapshot(&mut self, name: &str, time: Option<Ticks>) -> Outcome<()> {
        self.purging(|w| {
            let (blob, content) = w.existing(name)?;
            blob.snaps.push(Snap {
                content,
                expires: None,
                time,
            });
            Ok(())
        })
    }

    /// Deletes (or soft-deletes) the live snapshots, all of them or the one taken at `only`.
    fn drop_snapshots(config: Config, now: i64, blob: &mut Blob, only: Option<Ticks>) {
        let hits: Vec<usize> = blob
            .snaps
            .iter()
            .enumerate()
            .filter(|(_, snap)| snap.expires.is_none() && only.is_none_or(|t| snap.time == Some(t)))
            .map(|(index, _)| index)
            .collect();
        if config == Config::Soft {
            for index in hits {
                blob.snaps[index].expires = Some(now + RETENTION);
            }
        } else {
            for index in hits.into_iter().rev() {
                blob.snaps.remove(index);
            }
        }
    }

    fn delete(&mut self, name: &str, snapshots: DeleteSnapshots) -> Outcome<Removed> {
        self.purging(|w| {
            let (config, now) = (w.config, w.now);
            let (blob, content) = w.existing(name)?;
            let live = blob
                .snaps
                .iter()
                .filter(|snap| snap.expires.is_none())
                .count();
            if snapshots == DeleteSnapshots::Refuse && live > 0 {
                return Err(Error::SnapshotsPresent);
            }
            if snapshots != DeleteSnapshots::Refuse {
                Self::drop_snapshots(config, now, blob, None);
            }
            let soft = config == Config::Soft;
            if snapshots == DeleteSnapshots::Only {
                return Ok(if soft {
                    Removed::Kept
                } else {
                    Removed::Permanently
                });
            }
            blob.current = None;
            match config {
                Config::Versioned => blob.versions.push(content),
                Config::Soft => blob.tomb = Some((content, now + RETENTION)),
                Config::Plain => {}
            }
            Ok(if config == Config::Plain {
                Removed::Permanently
            } else {
                Removed::Kept
            })
        })
    }

    /// Deletes the snapshot of `name` taken at `time`; a soft-deleted one is not found.
    fn delete_snapshot(&mut self, name: &str, time: Ticks) -> Outcome<Removed> {
        self.purging(|w| {
            let (config, now) = (w.config, w.now);
            let blob = w
                .container()?
                .blobs
                .get_mut(name)
                .ok_or(Error::BlobMissing)?;
            if !blob
                .snaps
                .iter()
                .any(|snap| snap.expires.is_none() && snap.time == Some(time))
            {
                return Err(Error::BlobMissing);
            }
            Self::drop_snapshots(config, now, blob, Some(time));
            Ok(if config == Config::Soft {
                Removed::Kept
            } else {
                Removed::Permanently
            })
        })
    }

    fn delete_version(&mut self, name: &str, content: u32) -> Outcome<Removed> {
        self.purging(|w| {
            let blob = w
                .container()?
                .blobs
                .get_mut(name)
                .ok_or(Error::BlobMissing)?;
            if blob.current == Some(content) {
                blob.current = None;
            } else if let Some(position) = blob.versions.iter().position(|v| *v == content) {
                blob.versions.remove(position);
            } else {
                return Err(Error::BlobMissing);
            }
            Ok(Removed::Permanently)
        })
    }

    fn undelete(&mut self, name: &str) -> Outcome<()> {
        self.purging(|w| {
            let blob = w
                .container()?
                .blobs
                .get_mut(name)
                .ok_or(Error::BlobMissing)?;
            let deleted = blob.tomb.is_some() || blob.snaps.iter().any(|s| s.expires.is_some());
            if !deleted && blob.current.is_none() {
                return Err(Error::BlobMissing);
            }
            for snap in &mut blob.snaps {
                snap.expires = None;
            }
            if blob.current.is_none()
                && let Some((content, _)) = blob.tomb.take()
            {
                blob.current = Some(content);
            }
            Ok(())
        })
    }

    fn create_container(&mut self) -> Outcome<()> {
        self.plain(|w| {
            if w.live.is_some() {
                return Err(Error::ContainerExists);
            }
            w.live = Some(Container::default());
            Ok(())
        })
    }

    fn delete_container(&mut self) -> Outcome<()> {
        self.plain(|w| {
            let container = w.container()?.clone();
            w.live = None;
            if w.config == Config::Soft {
                w.hidden.push((container, w.now + RETENTION));
            }
            Ok(())
        })
    }

    fn restore_container(&mut self, index: usize) -> Outcome<()> {
        self.plain(|w| {
            if index >= w.hidden.len() {
                return Err(Error::ContainerMissing);
            }
            if w.live.is_some() {
                return Err(Error::ContainerExists);
            }
            w.live = Some(w.hidden.remove(index).0);
            Ok(())
        })
    }

    /// Every content that some entry still references, hidden containers included.
    fn retained(&self) -> BTreeSet<u32> {
        let hidden = self.hidden.iter().map(|(container, _)| container);
        let mut contents = BTreeSet::new();
        for blob in self
            .live
            .iter()
            .chain(hidden)
            .flat_map(|c| c.blobs.values())
        {
            contents.extend(blob.current);
            contents.extend(blob.versions.iter().copied());
            contents.extend(blob.snaps.iter().map(|snap| snap.content));
            contents.extend(blob.tomb.map(|(content, _)| content));
        }
        contents
    }

    fn visible(&self, expires: Option<i64>) -> bool {
        expires.is_none_or(|expires| expires > self.now)
    }
}
