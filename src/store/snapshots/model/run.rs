//! The walk: random operations against the store and the oracle, and every comparison.

use super::super::tests::{extents, key, options, removal};
use super::super::*;
use super::*;
use crate::{
    blob_snapshot::DeleteSnapshots,
    checksum::Hasher,
    clock::Clock,
    domain::{
        BlobRead, ContainerCreate, ContainerKey, Include, ListRequest, PageRequest, PublicAccess,
    },
    prng::Rng,
    service_props::{Retention, ServiceProperties},
    store::{PathRead, Payload},
};
use std::{
    collections::{BTreeMap, HashMap},
    io::Read as _,
    path::Path,
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Tag {
    Current,
    Snapshot,
    Version,
    Deleted,
}

/// What a listing shows: name, kind, content md5, and whether it is soft-deleted.
type Shown = (String, Tag, String, bool);

fn content(n: u32) -> Vec<u8> {
    format!("content {n}:{}", "x".repeat((n % 23) as usize)).into_bytes()
}

fn md5(n: u32) -> String {
    let mut hasher = Hasher::new();
    hasher.update(&content(n));
    hasher.finish(None).unwrap().md5_text()
}

fn same<T: std::fmt::Debug + PartialEq>(real: Outcome<T>, expected: Outcome<T>, at: &str) {
    assert_eq!(real, expected, "{at}");
}

struct Run {
    store: Store,
    clock: Clock,
    root: Option<tempfile::TempDir>,
    world: World,
    rng: Rng,
    next: u32,
    /// Version ids read from listings, by name and content.
    versions: HashMap<(&'static str, u32), Ticks>,
    by_md5: HashMap<String, u32>,
}

fn container_key() -> ContainerKey {
    key("x").container
}

fn page() -> PageRequest {
    PageRequest::parse(None, None, None).unwrap()
}

async fn payload_bytes(payload: Option<Payload>) -> Vec<u8> {
    match payload {
        Some(Payload::Disk(mut file)) => {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            bytes
        }
        Some(Payload::Memory(bytes)) => bytes,
        Some(Payload::Ranges(body)) => body.into_vec().unwrap(),
        None => Vec::new(),
    }
}

fn read() -> BlobRead {
    BlobRead {
        guard: Guard::default(),
        range: None,
        with_body: true,
        range_checksum: None,
    }
}

impl Run {
    async fn start(seed: u64, config: Config, disk: bool) -> Self {
        let root = disk.then(|| tempfile::tempdir().unwrap());
        let clock = Clock::new();
        let store = open(root.as_ref().map(|root| root.path()), &clock);
        let account = key("x").container.account;
        match config {
            Config::Soft => store
                .set_service_properties(
                    account,
                    ServiceProperties {
                        delete_retention: Some(Retention {
                            enabled: true,
                            days: Some(2),
                            allow_permanent_delete: None,
                        }),
                        ..Default::default()
                    },
                )
                .await
                .unwrap(),
            Config::Versioned => store.enable_versioning(vec!["acct".into()]).await.unwrap(),
            Config::Plain => {}
        }
        let mut run = Self {
            store,
            clock,
            root,
            world: World {
                config,
                now: 0,
                live: None,
                hidden: Vec::new(),
            },
            rng: Rng::seeded(seed),
            next: 0,
            versions: HashMap::new(),
            by_md5: HashMap::new(),
        };
        run.create_container("start").await;
        run
    }

    async fn create_container(&mut self, at: &str) {
        let real = self
            .store
            .create_container(
                container_key(),
                ContainerCreate {
                    metadata: Metadata::new(),
                    public_access: PublicAccess::Private,
                },
            )
            .await
            .map(drop);
        same(real, self.world.create_container(), at);
    }

    async fn put(&mut self, name: &'static str, at: &str) {
        self.next += 1;
        let n = self.next;
        self.by_md5.insert(md5(n), n);
        let bytes = content(n);
        let mut upload = self
            .store
            .begin_upload(ContentLength(bytes.len() as u64))
            .await
            .unwrap();
        upload.append(&bytes).await.unwrap();
        let upload = upload.finish(None).await.unwrap();
        let real = self
            .store
            .put_blob(key(name), options(), upload)
            .await
            .map(drop);
        same(real, self.world.put(name, n), at);
    }

    async fn step(&mut self, step: u32, seed: u64) {
        let config = self.world.config;
        let at = format!("seed {seed} {config:?} step {step}");
        self.clock.advance(Duration::from_millis(1));
        let name = *self.rng.pick(&NAMES);
        let store = self.store.clone();
        let outcome = |removed: Outcome<Deletion>| {
            removed.map(|d| match d {
                Deletion::Permanent => Removed::Permanently,
                Deletion::Retained => Removed::Kept,
            })
        };
        match self.rng.below(100) {
            0..=27 => self.put(name, &at).await,
            28..=39 => {
                let real = store.snapshot_blob(key(name), None, Guard::default()).await;
                let time = real.as_ref().ok().map(|snapshot| snapshot.time);
                same(real.map(drop), self.world.snapshot(name, time), &at);
            }
            40..=51 => {
                let mode = *self.rng.pick(&[
                    DeleteSnapshots::Refuse,
                    DeleteSnapshots::Include,
                    DeleteSnapshots::Only,
                ]);
                let real = store
                    .delete_blob(key(name), Guard::default(), removal(None, mode))
                    .await;
                same(
                    outcome(real),
                    self.world.delete(name, mode),
                    &format!("{at}: {mode:?}"),
                );
            }
            52..=60 => self.delete_a_snapshot(&at).await,
            61..=64 if config == Config::Versioned => self.delete_a_version(&at).await,
            61..=68 => {
                let real = store.undelete_blob(key(name)).await;
                same(real, self.world.undelete(name), &at);
            }
            69..=78 => {
                let hours = *self.rng.pick(&[1, 5, 12, 24, 25, 36, 48, 49]);
                self.world.now += hours * HOUR;
                self.clock.advance(Duration::from_secs(hours as u64 * 3600));
            }
            79..=82 if self.root.is_some() => {
                drop(store);
                self.restart();
            }
            83..=86 => {
                let real = store
                    .delete_container(container_key(), Guard::default())
                    .await;
                same(real, self.world.delete_container(), &at);
            }
            87..=91 => self.create_container(&at).await,
            92..=95 => self.restore_a_container(&at).await,
            _ => self.put(name, &at).await,
        }
        self.check(&at).await;
    }

    /// Reopens the data directory: soft-deleted entries that expired are purged on open.
    fn restart(&mut self) {
        let root = self.root.as_ref().map(|root| root.path().to_owned());
        let placeholder = Store::open(None, 1 << 20, self.clock.clone(), Default::default());
        drop(std::mem::replace(&mut self.store, placeholder.unwrap()));
        self.store = open(root.as_deref(), &self.clock);
        self.world.purge();
    }

    async fn delete_a_snapshot(&mut self, at: &str) {
        let mut candidates = Vec::new();
        if let Some(container) = &self.world.live {
            for (name, blob) in &container.blobs {
                for snap in &blob.snaps {
                    if let Some(time) = snap.time {
                        candidates.push((*name, time, snap.expires.is_none()));
                    }
                }
            }
        }
        let Some(&(name, time, live)) =
            candidates.get(self.rng.below(candidates.len() as u64) as usize)
        else {
            return;
        };
        let real = self
            .store
            .delete_blob(
                key(name),
                Guard::default(),
                removal(Some(Selector::Snapshot(time)), DeleteSnapshots::Refuse),
            )
            .await
            .map(|deletion| match deletion {
                Deletion::Permanent => Removed::Permanently,
                Deletion::Retained => Removed::Kept,
            });
        let expected = self.world.delete_snapshot(name, time);
        assert_eq!(
            expected.is_ok(),
            live,
            "{at}: only a live snapshot is found"
        );
        same(real, expected, at);
    }

    async fn delete_a_version(&mut self, at: &str) {
        let known: Vec<_> = self
            .versions
            .iter()
            .filter(|((name, content), _)| {
                self.world.live.as_ref().is_some_and(|c| {
                    c.blobs.get(name).is_some_and(|blob| {
                        blob.current == Some(*content) || blob.versions.contains(content)
                    })
                })
            })
            .map(|((name, content), version)| (*name, *content, *version))
            .collect();
        let mut known = known;
        known.sort_by_key(|(name, content, _)| (*name, *content));
        let Some(&(name, content, version)) =
            known.get(self.rng.below(known.len() as u64) as usize)
        else {
            return;
        };
        let real = self
            .store
            .delete_blob(
                key(name),
                Guard::default(),
                removal(Some(Selector::Version(version)), DeleteSnapshots::Refuse),
            )
            .await
            .map(|deletion| match deletion {
                Deletion::Permanent => Removed::Permanently,
                Deletion::Retained => Removed::Kept,
            });
        same(real, self.world.delete_version(name, content), at);
    }

    async fn restore_a_container(&mut self, at: &str) {
        self.world.start();
        let listed = self
            .store
            .list_containers_with_deleted(container_key().account, page())
            .await
            .unwrap();
        let deleted: Vec<_> = listed
            .items
            .iter()
            .filter_map(|(_, entry)| {
                entry
                    .deleted
                    .as_ref()
                    .map(|d| (entry.name.clone(), d.version.clone()))
            })
            .collect();
        assert_eq!(
            deleted.len(),
            self.world.hidden.len(),
            "{at}: deleted containers"
        );
        let index = self.rng.below(deleted.len() as u64 + 1) as usize;
        let Some((name, version)) = deleted.get(index).cloned() else {
            return;
        };
        let real = self
            .store
            .restore_container(name, version, container_key())
            .await
            .map(drop);
        same(real, self.world.restore_container(index), at);
    }

    /// Compares every listing, every byte, and the extent files with the oracle.
    async fn check(&mut self, at: &str) {
        let mut include = vec![Include::Snapshots, Include::Deleted];
        if self.world.config == Config::Versioned {
            include.push(Include::Versions);
        }
        let request = ListRequest {
            page: page(),
            delimiter: None,
            include,
        };
        self.world.start();
        let listing = self
            .store
            .list_extended(container_key(), request, None)
            .await;
        let Some(live) = self.world.live.clone() else {
            assert_eq!(listing.err(), Some(Error::ContainerMissing), "{at}");
            return self.check_containers_and_extents(at).await;
        };
        let listing = listing.unwrap_or_else(|error| panic!("{at}: listing failed: {error:?}"));
        let mut shown: Vec<Shown> = Vec::new();
        let mut order: BTreeMap<String, Vec<(Ticks, String)>> = BTreeMap::new();
        for entry in &listing.entries {
            let Listed::Blob(blob) = entry else { continue };
            let md5 = blob.info.md5.clone().unwrap_or_default();
            let tag = match (blob.snapshot, blob.deleted.is_some(), blob.version) {
                (Some(_), _, _) => Tag::Snapshot,
                (None, true, _) => Tag::Deleted,
                (None, false, Some(_)) if !blob.current_version => Tag::Version,
                _ => Tag::Current,
            };
            if let Some(time) = blob.snapshot {
                order
                    .entry(blob.name.clone())
                    .or_default()
                    .push((time, md5.clone()));
            }
            if let (Some(version), Some(content)) = (blob.version, self.by_md5.get(&md5))
                && let Some(name) = NAMES.iter().find(|name| **name == blob.name)
            {
                self.versions.insert((*name, *content), version);
            }
            shown.push((blob.name.clone(), tag, md5, blob.deleted.is_some()));
        }
        let mut expected: Vec<Shown> = Vec::new();
        for (name, blob) in &live.blobs {
            let name = (*name).to_owned();
            expected.extend(
                blob.current
                    .map(|c| (name.clone(), Tag::Current, md5(c), false)),
            );
            for snap in blob
                .snaps
                .iter()
                .filter(|snap| self.world.visible(snap.expires))
            {
                expected.push((
                    name.clone(),
                    Tag::Snapshot,
                    md5(snap.content),
                    snap.expires.is_some(),
                ));
            }
            expected.extend(
                blob.versions
                    .iter()
                    .map(|v| (name.clone(), Tag::Version, md5(*v), false)),
            );
            if let Some((c, expires)) = blob.tomb.filter(|(_, e)| self.world.visible(Some(*e))) {
                let _ = expires;
                expected.push((name.clone(), Tag::Deleted, md5(c), true));
            }
        }
        shown.sort();
        expected.sort();
        assert_eq!(shown, expected, "{at}: listing");

        // Snapshots come oldest first, and the listing gives each its time.
        for (name, blob) in self.world.live.iter_mut().flat_map(|c| c.blobs.iter_mut()) {
            let seen = order.remove(*name).unwrap_or_default();
            let now = self.world.now;
            let visible = blob
                .snaps
                .iter_mut()
                .filter(|snap| snap.expires.is_none_or(|e| e > now));
            let mut count = 0;
            for (snap, (time, listed)) in visible.zip(&seen) {
                assert_eq!(md5(snap.content), *listed, "{at}: snapshot order of {name}");
                assert!(
                    snap.time.is_none_or(|known| known == *time),
                    "{at}: snapshot time"
                );
                snap.time = Some(*time);
                count += 1;
            }
            assert_eq!(count, seen.len(), "{at}: snapshots of {name}");
            assert!(
                seen.windows(2).all(|pair| pair[0].0 < pair[1].0),
                "{at}: oldest first"
            );
        }
        self.check_bytes(at).await;
        self.check_containers_and_extents(at).await;
    }

    async fn check_bytes(&self, at: &str) {
        let Some(live) = &self.world.live else { return };
        for (name, blob) in &live.blobs {
            if let Some(content_id) = blob.current {
                let read = self.store.read_path(key(name), read()).await.unwrap();
                let PathRead::File(download) = read else {
                    panic!("{at}: {name} is not a file");
                };
                let bytes = payload_bytes(download.payload).await;
                assert_eq!(bytes, content(content_id), "{at}: current {name}");
            }
            for snap in blob.snaps.iter().filter(|snap| snap.expires.is_none()) {
                let time = snap
                    .time
                    .unwrap_or_else(|| panic!("{at}: a snapshot with no time"));
                let selected = self
                    .store
                    .read_selected(key(name), Selector::Snapshot(time), read())
                    .await
                    .unwrap();
                let bytes = payload_bytes(selected.download.payload).await;
                assert_eq!(bytes, content(snap.content), "{at}: snapshot of {name}");
            }
        }
    }

    async fn check_containers_and_extents(&mut self, at: &str) {
        let listed = self
            .store
            .list_containers_with_deleted(container_key().account, page())
            .await
            .unwrap();
        let deleted = listed
            .items
            .iter()
            .filter(|(_, e)| e.deleted.is_some())
            .count();
        let live = listed.items.len() - deleted;
        assert_eq!(
            deleted,
            self.world.hidden.len(),
            "{at}: soft-deleted containers"
        );
        assert_eq!(
            live,
            usize::from(self.world.live.is_some()),
            "{at}: live container"
        );
        if let Some(root) = &self.root {
            let held = extents(root.path());
            assert_eq!(held, self.world.retained().len(), "{at}: extent files");
        }
    }
}

fn open(root: Option<&Path>, clock: &Clock) -> Store {
    Store::open(root, 1 << 30, clock.clone(), Default::default()).unwrap()
}

async fn walk(seeds: std::ops::RangeInclusive<u64>, config: Config, disk: bool, steps: u32) {
    for seed in seeds {
        let mut run = Run::start(seed, config, disk).await;
        for step in 0..steps {
            run.step(step, seed).await;
        }
    }
}

#[tokio::test]
async fn random_operations_agree_with_the_oracle_in_memory() {
    for config in [Config::Plain, Config::Soft, Config::Versioned] {
        walk(1..=8, config, false, 50).await;
    }
}

#[tokio::test]
async fn random_operations_agree_with_the_oracle_on_disk_including_extents_and_restarts() {
    for config in [Config::Plain, Config::Soft, Config::Versioned] {
        walk(1..=2, config, true, 40).await;
    }
}
