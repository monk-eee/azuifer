//! Extent files that a download in flight still reads.
//!
//! A download of a page or append blob opens its extent files one after another as it is
//! sent, long after the metadata lock was released. Without a hold, an overwrite or delete
//! that reclaims an extent in between would cut the response short. A reader pins the
//! extents it will read; `reclaim` leaves a pinned file alone and the last reader to finish
//! removes it. A crash in between leaves an unreferenced file, which recovery removes.

use super::{extent, snapshots};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};
use uuid::Uuid;

struct Reading {
    readers: usize,
    /// Reclaimed while read; removed when the last reader is done.
    doomed: bool,
}

#[derive(Default)]
pub(super) struct Readers(Mutex<HashMap<Uuid, Reading>>);

impl Readers {
    fn lock(&self) -> MutexGuard<'_, HashMap<Uuid, Reading>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Marks `id` for removal by its last reader. False when nothing is reading it.
    fn defer(&self, id: Uuid) -> bool {
        self.lock()
            .get_mut(&id)
            .map(|reading| reading.doomed = true)
            .is_some()
    }
}

/// Holds extents in place until it is dropped.
pub(crate) struct ReadPins {
    readers: Arc<Readers>,
    extents: PathBuf,
    ids: Vec<Uuid>,
}

impl ReadPins {
    /// Call under the metadata lock, so that no reclaim can come between a read being
    /// planned and its extents being held.
    pub(super) fn new(readers: &Arc<Readers>, extents: &Path, ids: Vec<Uuid>) -> Self {
        let mut held = readers.lock();
        for id in &ids {
            held.entry(*id)
                .or_insert(Reading {
                    readers: 0,
                    doomed: false,
                })
                .readers += 1;
        }
        drop(held);
        Self {
            readers: readers.clone(),
            extents: extents.to_owned(),
            ids,
        }
    }
}

impl Drop for ReadPins {
    fn drop(&mut self) {
        let mut doomed = Vec::new();
        {
            let mut held = self.readers.lock();
            for id in &self.ids {
                let Some(reading) = held.get_mut(id) else {
                    continue;
                };
                reading.readers -= 1;
                if reading.readers == 0 {
                    if reading.doomed {
                        doomed.push(*id);
                    }
                    held.remove(id);
                }
            }
        }
        for id in doomed {
            remove(&self.extents, id);
        }
    }
}

fn remove(extents: &Path, id: Uuid) {
    if let Err(error) = std::fs::remove_file(extent(extents, id))
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(kind = ?error.kind(), "content cleanup deferred until recovery");
    }
}

/// Removes an extent nothing references any more, unless a snapshot, version or deleted
/// blob retains it or a download is still reading it.
pub(super) fn reclaim(mode: &super::Mode, id: Uuid) {
    if let super::Mode::Disk {
        extents,
        pinned,
        readers,
        ..
    } = mode
        && !snapshots::is_pinned(pinned, id)
        && !readers.defer(id)
    {
        remove(extents, id);
    }
}
