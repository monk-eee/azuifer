//! Page and append blob history and snapshots over shared extents (ADR-0015,
//! ADR-0018). A retained state keeps its range map in `history_ranges`, naming
//! the same immutable extents as the live blob, so a snapshot copies rows, never
//! bytes. Extents are freed only when no live range row and no history range row
//! references them.
//!
//! Also here: Get Page Ranges for a snapshot and the diff between two snapshots,
//! and Incremental Copy Blob.

use super::{
    Store, blob, blob_params,
    blobs::{ensure_parents, guard_write},
    check_memory_quota, container, db_error,
    pages::{
        Copied, PageRanges, RangeSource, Reclaim, discard, load_source_window, page_blob,
        save_window, set_kind,
    },
    require_blob, save_row, snapshots,
};
use crate::{
    blob_lifecycle::{Incremental, LifecycleError},
    blob_page::{BlobKind, RangeQuery},
    blob_snapshot::Selector,
    domain::{BlobKey, BlobWrite, ContentLength, Error, Result},
    lease::{LeaseNeed, LeaseOwner},
    ranges::RangeMap,
    stamp::Ticks,
};
use rusqlite::{Connection, ToSql, params};
use std::ops::Range;
use uuid::Uuid;

/// Copies the live blob's range rows into the history row `(kind, state)`.
pub(super) fn archive_ranges(db: &Connection, key: &BlobKey, kind: i64, state: i64) -> Result<()> {
    let [account, container, name] = blob_params(key);
    db.execute(
        "INSERT INTO history_ranges
         SELECT account, container, name, ?4, ?5, offset, length, extent, extent_offset
         FROM blob_ranges WHERE account=?1 AND container=?2 AND name=?3",
        params![account, container, name, kind, state],
    )
    .map_err(db_error)?;
    Ok(())
}

/// Moves a soft-deleted blob's ranges back to the live blob, which must already exist.
pub(super) fn restore_ranges(db: &Connection, key: &BlobKey) -> Result<()> {
    let [account, container, name] = blob_params(key);
    db.execute(
        "INSERT INTO blob_ranges
         SELECT account, container, name, offset, length, extent, extent_offset
         FROM history_ranges WHERE account=?1 AND container=?2 AND name=?3 AND kind=3",
        params![account, container, name],
    )
    .map_err(db_error)?;
    Ok(())
}

/// The extents referenced by the history rows `condition` selects (a predicate over
/// `blob_history` as `b`). Call it before deleting those rows, which cascades to
/// their ranges, then hand the result to [`free`] afterwards.
pub(super) fn extents_where(
    db: &Connection,
    condition: &str,
    arguments: &[&dyn ToSql],
) -> Result<Vec<Uuid>> {
    let mut query = db
        .prepare(&format!(
            "SELECT DISTINCT h.extent FROM history_ranges h JOIN blob_history b
               ON b.account=h.account AND b.container=h.container AND b.name=h.name
              AND b.kind=h.kind AND b.state_id=h.state_id
             WHERE {condition}"
        ))
        .map_err(db_error)?;
    query
        .query_map(arguments, |row| row.get(0))
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)
}

/// The extents among `candidates` that nothing references any more. Their bytes
/// leave an in-memory instance at once; the caller removes extent files after commit.
pub(super) fn free(
    db: &Connection,
    mode: &super::Mode,
    candidates: Vec<Uuid>,
) -> Result<Vec<Uuid>> {
    let mut reclaim = Reclaim::default();
    reclaim.add_ids(candidates);
    reclaim.finish(db, mode)
}

/// The extents the history rows of a container hold, for Delete Container.
pub(super) fn container_extents(db: &Connection, account: &str, name: &str) -> Result<Vec<Uuid>> {
    extents_where(
        db,
        "b.account=?1 AND b.container=?2",
        params![account, name],
    )
}

fn previous(
    db: &Connection,
    key: &BlobKey,
    time: Ticks,
    target: Option<Ticks>,
    now: i64,
) -> Result<(RangeSource, u64)> {
    if target.is_some_and(|target| time > target) {
        return Err(Error::Ext(LifecycleError::PreviousSnapshotCannotBeNewer));
    }
    let not_found = Error::Ext(LifecycleError::PreviousSnapshotNotFound);
    let (row, content) = snapshots::resolve_source(db, key, Some(Selector::Snapshot(time)), now)
        .map_err(|error| match error {
            Error::BlobMissing | Error::ContainerMissing => not_found,
            other => other,
        })?;
    page_blob(&row).map_err(|_| not_found)?;
    Ok((content.into(), row.info.length.0))
}

fn clip(range: &Range<u64>, window: &Range<u64>) -> Option<Range<u64>> {
    let (start, end) = (range.start.max(window.start), range.end.min(window.end));
    (start < end).then_some(start..end)
}

/// The ranges of one page of results: allocated ranges, or for a diff both the
/// changed and the cleared ranges, in offset order.
fn entries(
    current: &RangeMap<Uuid>,
    old: Option<&RangeMap<Uuid>>,
    window: &Range<u64>,
) -> Vec<(Range<u64>, bool)> {
    let mut entries: Vec<(Range<u64>, bool)> = match old {
        None => current
            .allocated_ranges_in(window.start, window.end.saturating_sub(window.start))
            .into_iter()
            .map(|range| (range, false))
            .collect(),
        Some(old) => {
            let diff = current.diff(old);
            let changed = diff.changed.iter().map(|range| (range, false));
            let cleared = diff.cleared.iter().map(|range| (range, true));
            changed
                .chain(cleared)
                .filter_map(|(range, cleared)| clip(range, window).map(|range| (range, cleared)))
                .collect()
        }
    };
    entries.sort_by_key(|(range, _)| range.start);
    entries
}

impl Store {
    /// Get Page Ranges: the allocated ranges of the blob or one of its snapshots, or
    /// with `prevsnapshot` the ranges that changed (and were cleared) since it.
    pub(crate) async fn page_ranges(&self, key: BlobKey, query: RangeQuery) -> Result<PageRanges> {
        self.run(move |db, _, now| {
            let (row, source) = match query.snapshot {
                None => {
                    let row = require_blob(db, &key, now)?;
                    row.lease.check(
                        query.guard.lease,
                        LeaseNeed::Optional,
                        LeaseOwner::Blob,
                        now,
                    )?;
                    (row, RangeSource::Current)
                }
                Some(time) => {
                    let (row, content) =
                        snapshots::resolve_source(db, &key, Some(Selector::Snapshot(time)), now)?;
                    (row, content.into())
                }
            };
            page_blob(&row)?;
            query.guard.conditions.check(Some(row.info.entity), true)?;
            let length = row.info.length.0;
            let old = query
                .previous
                .map(|time| previous(db, &key, time, query.snapshot, now))
                .transpose()?;
            let span = old.map_or(length, |(_, old_length)| length.max(old_length));
            let window = match &query.window {
                Some(range) => range.resolve(ContentLength(span))?,
                None => 0..span,
            };
            let from = query.marker.map_or(window.start, |at| at.max(window.start));
            let current = load_source_window(db, &key, source, window.start, window.end, length)?;
            let before = old
                .map(|(source, old_length)| {
                    load_source_window(db, &key, source, window.start, window.end, old_length)
                })
                .transpose()?;
            let mut listed: Vec<(Range<u64>, bool)> = entries(&current, before.as_ref(), &window)
                .into_iter()
                .filter_map(|(range, cleared)| {
                    clip(&range, &(from..window.end)).map(|range| (range, cleared))
                })
                .collect();
            let mut next = None;
            if let Some(limit) = query.limit.map(|limit| limit as usize)
                && listed.len() > limit
            {
                next = listed.get(limit).map(|(range, _)| range.start);
                listed.truncate(limit);
            }
            let (cleared, ranges): (Vec<_>, Vec<_>) =
                listed.into_iter().partition(|(_, cleared)| *cleared);
            Ok(PageRanges {
                entity: row.info.entity,
                length,
                ranges: ranges.into_iter().map(|(range, _)| range).collect(),
                cleared: cleared.into_iter().map(|(range, _)| range).collect(),
                next,
            })
        })
        .await
    }

    /// Incremental Copy Blob from a snapshot of a same-instance page blob. The
    /// destination page blob takes the snapshot's ranges (sharing its extents, so only
    /// what changed since the previous copy is new to it), and then gets a snapshot of
    /// its own, which later copies and diffs build on. Copies complete synchronously.
    pub(crate) async fn incremental_copy(
        &self,
        source: BlobKey,
        snapshot: Ticks,
        dest: BlobKey,
        options: BlobWrite,
    ) -> Result<Copied> {
        let hierarchical = self.hierarchical(&dest.container);
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            let (src, content) =
                snapshots::resolve_source(&tx, &source, Some(Selector::Snapshot(snapshot)), now)
                    .map_err(|error| match error {
                        Error::BlobMissing | Error::ContainerMissing => Error::CopySourceMissing,
                        other => other,
                    })?;
            let BlobKind::Page { .. } = src.info.kind else {
                return Err(Error::Ext(LifecycleError::InvalidSourceBlobType));
            };
            container(&tx, &dest.container)?;
            let old = blob(&tx, &dest, now)?;
            guard_write(&options.guard, old.as_ref(), false, now)?;
            match &old {
                Some(old) => {
                    page_blob(old)?;
                    let recorded = old.info.copy.as_ref().map(|copy| copy.source.as_str());
                    let requested = options.copy.as_ref().map(|copy| copy.source.as_str());
                    match old.info.lifecycle.incremental {
                        None => return Err(Error::BlobAlreadyExists),
                        Some(_) if recorded != requested => {
                            return Err(Error::Ext(LifecycleError::IncrementalCopyBlobMismatch));
                        }
                        Some(last) if snapshot < last.source => {
                            return Err(Error::Ext(
                                LifecycleError::IncrementalCopyOfEarlierSnapshot,
                            ));
                        }
                        Some(_) => (),
                    }
                }
                None => ensure_parents(&tx, &dest, hierarchical, now)?,
            }
            let length = src.info.length;
            let rows = load_source_window(&tx, &source, content.into(), 0, length.0, length.0)?;
            let version = snapshots::begin_write(
                &tx,
                mode,
                &dest,
                old.as_ref(),
                snapshots::Change::Properties,
                now,
            )?;
            let mut reclaim = Reclaim::default();
            reclaim.add_blob(&tx, &dest)?;
            let entity = save_row(&tx, &dest, &options, length, None, None, now)?;
            set_kind(&tx, &dest, src.info.kind)?;
            let entity = snapshots::finish_write(&tx, &dest, entity, version, None)?;
            save_window(&tx, &dest, &RangeMap::new(length.0), &rows)?;
            let time = snapshots::snapshot_current(&tx, mode, &dest, entity.id, now)?;
            super::expiry::write_incremental(
                &tx,
                &dest,
                Incremental {
                    source: snapshot,
                    destination: time,
                },
            )?;
            let free = reclaim.finish(&tx, mode)?;
            check_memory_quota(&tx, mode, 0, 0)?;
            tx.commit().map_err(db_error)?;
            if let Some(old) = old {
                super::reclaim(mode, old.info.entity.id);
            }
            discard(mode, &free);
            let copy_id = options.copy.map(|copy| copy.id).unwrap_or_default();
            Ok(Copied { entity, copy_id })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ranges::RangeMap, store::pages::RangeSource};

    fn map(length: u64, writes: &[(u64, u64, u32)]) -> RangeMap<Uuid> {
        let mut map = RangeMap::new(length);
        for (offset, size, id) in writes {
            map.write(*offset, *size, Uuid::from_u128(u128::from(*id)), 0)
                .unwrap();
        }
        map
    }

    #[test]
    fn a_plain_listing_reports_allocated_ranges_in_the_window() {
        let current = map(4096, &[(0, 512, 1), (1024, 1024, 2)]);
        assert_eq!(
            entries(&current, None, &(0..4096)),
            vec![(0..512, false), (1024..2048, false)]
        );
        assert_eq!(
            entries(&current, None, &(1536..4096)),
            vec![(1536..2048, false)]
        );
    }

    #[test]
    fn a_diff_reports_changed_and_cleared_ranges_in_offset_order() {
        let old = map(4096, &[(0, 512, 1), (1024, 512, 2), (2048, 512, 3)]);
        let mut current = old.clone();
        current.write(0, 512, Uuid::from_u128(9), 0).unwrap();
        current.clear(1024, 512).unwrap();
        current.write(3072, 512, Uuid::from_u128(8), 0).unwrap();
        assert_eq!(
            entries(&current, Some(&old), &(0..4096)),
            vec![(0..512, false), (1024..1536, true), (3072..3584, false)]
        );
        assert_eq!(
            entries(&current, Some(&old), &(1200..3200)),
            vec![(1200..1536, true), (3072..3200, false)],
            "ranges are clipped to the window"
        );
        assert!(entries(&old, Some(&old), &(0..4096)).is_empty());
    }

    #[test]
    fn a_shrunk_blob_reports_its_trailing_ranges_as_cleared() {
        let old = map(4096, &[(0, 512, 1), (3584, 512, 2)]);
        let mut current = old.clone();
        current.resize(2048);
        assert_eq!(
            entries(&current, Some(&old), &(0..4096)),
            vec![(3584..4096, true)]
        );
    }

    #[test]
    fn clipping_drops_ranges_outside_the_window() {
        assert_eq!(clip(&(0..10), &(5..20)), Some(5..10));
        assert_eq!(clip(&(0..5), &(5..20)), None);
        assert_eq!(
            RangeSource::Current,
            RangeSource::from(crate::store::ContentSource::Blob)
        );
    }
}
