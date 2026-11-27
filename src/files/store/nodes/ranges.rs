//! Byte ranges of a file: Put Range, Clear Range, reads with an optional MD5, and the
//! allocated-range listing.

use super::{
    Store, Want, check_file_lease, check_not_read_only, check_quota, content, db_error, find,
    finish, resolve, save_node,
    shares::{self, ShareRef, load_share},
    stamp_write, writable,
};
use crate::{
    files::{
        error::{Error, Result},
        lease::Use,
        model::{NodeInfo, TimeSpec},
        name::EntryPath,
    },
    ranges::RangeMap,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use md5::{Digest as _, Md5};
use std::ops::Range;

const MAX_MD5_RANGE: u64 = 4 * 1024 * 1024;

/// A `bytes=start-end` read range; `end` is inclusive and optional.
#[derive(Clone, Copy)]
pub(crate) struct ReadRange {
    pub(crate) start: u64,
    pub(crate) end: Option<u64>,
}

pub(crate) struct ReadOptions {
    pub(crate) lease_id: Option<String>,
    pub(crate) conditions: crate::files::model::Conditions,
    pub(crate) range: Option<ReadRange>,
    /// Return the MD5 of the returned range (`x-ms-range-get-content-md5`).
    pub(crate) want_md5: bool,
    /// False for Get File Properties, which reads no bytes.
    pub(crate) with_body: bool,
}

pub(crate) struct FileRead {
    pub(crate) info: NodeInfo,
    /// The returned byte range when the read was ranged.
    pub(crate) range: Option<Range<u64>>,
    pub(crate) body: content::FileBody,
    pub(crate) md5: Option<String>,
}

pub(crate) struct RangeListing {
    pub(crate) info: NodeInfo,
    pub(crate) ranges: Vec<Range<u64>>,
    pub(crate) cleared: Vec<Range<u64>>,
}

impl Store {
    /// Writes staged bytes at `offset` as a new extent (Put Range, `x-ms-write: update`).
    pub(crate) async fn put_range(
        &self,
        target: ShareRef,
        path: EntryPath,
        lease_id: Option<String>,
        offset: u64,
        data: content::Staged,
        last_write: TimeSpec,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            let mut node = find(&tx, &share, &path, Want::Regular)?;
            check_file_lease(&node, now, lease_id.as_deref(), Use::Write)?;
            check_not_read_only(&node)?;
            if offset
                .checked_add(data.length)
                .is_none_or(|end| end > node.length)
            {
                return Err(Error::InvalidRange);
            }
            let old = content::load_map(&tx, share.id, node.file_id, node.length)?;
            let mut new = old.clone();
            let extent = content::new_extent_id();
            new.write(offset, data.length, extent.clone(), 0)
                .map_err(|_| Error::InvalidRange)?;
            check_quota(&tx, &share, new.allocated_bytes(), old.allocated_bytes())?;
            data.publish(&tx, &env.mode, &extent)?;
            let result = (|| {
                content::save_map(&tx, share.id, node.file_id, &old, &new)?;
                let mut reclaim = content::Reclaim::default();
                reclaim.add_map(&old);
                stamp_write(&mut node, last_write, now);
                save_node(&tx, share.id, &node)?;
                let free = reclaim.finish(&tx, &env.mode)?;
                content::check_memory_quota(&tx, &env.mode)?;
                Ok(free)
            })();
            match result {
                Ok(free) => {
                    if let Err(error) = tx.commit().map_err(db_error) {
                        content::discard(env, std::slice::from_ref(&extent));
                        return Err(error);
                    }
                    content::discard(env, &free);
                    Ok(node)
                }
                Err(error) => {
                    drop(tx);
                    content::discard(env, std::slice::from_ref(&extent));
                    Err(error)
                }
            }
        })
        .await
    }

    /// Deallocates a range without writing zeros (Put Range, `x-ms-write: clear`).
    pub(crate) async fn clear_range(
        &self,
        target: ShareRef,
        path: EntryPath,
        lease_id: Option<String>,
        offset: u64,
        length: u64,
        last_write: TimeSpec,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            let mut node = find(&tx, &share, &path, Want::Regular)?;
            check_file_lease(&node, now, lease_id.as_deref(), Use::Write)?;
            check_not_read_only(&node)?;
            if offset
                .checked_add(length)
                .is_none_or(|end| end > node.length)
            {
                return Err(Error::InvalidRange);
            }
            let old = content::load_map(&tx, share.id, node.file_id, node.length)?;
            let mut new = old.clone();
            new.clear(offset, length).map_err(|_| Error::InvalidRange)?;
            content::save_map(&tx, share.id, node.file_id, &old, &new)?;
            let mut reclaim = content::Reclaim::default();
            reclaim.add_map(&old);
            stamp_write(&mut node, last_write, now);
            save_node(&tx, share.id, &node)?;
            finish(tx, env, reclaim)?;
            Ok(node)
        })
        .await
    }

    pub(crate) async fn read_file(
        &self,
        target: ShareRef,
        path: EntryPath,
        options: ReadOptions,
    ) -> Result<FileRead> {
        self.run(move |db, env| {
            let ReadOptions {
                lease_id,
                conditions,
                range,
                want_md5,
                with_body,
            } = options;
            let share = shares::load_share(db, &target)?;
            let node = find(
                db,
                &share,
                &path,
                if with_body { Want::Regular } else { Want::File },
            )?;
            check_file_lease(
                &node,
                env.clock.now_millis(),
                lease_id.as_deref(),
                Use::Read,
            )?;
            conditions.check(&node.etag, node.modified)?;
            let window = match range {
                Some(range) => {
                    if range.start >= node.length {
                        return Err(Error::InvalidRange);
                    }
                    let end = range
                        .end
                        .map_or(node.length, |end| end.saturating_add(1).min(node.length));
                    Some(range.start..end)
                }
                None => None,
            };
            let span = window.clone().unwrap_or(0..node.length);
            if want_md5 && span.end - span.start > MAX_MD5_RANGE {
                return Err(Error::InvalidHeaderValue);
            }
            if !with_body {
                return Ok(FileRead {
                    info: node,
                    range: window,
                    body: content::FileBody::empty(),
                    md5: None,
                });
            }
            let map = content::load_map(db, share.id, node.file_id, node.length)?;
            let mut body =
                content::FileBody::open(db, env, &map, span.start, span.end - span.start)?;
            let mut md5 = None;
            if want_md5 {
                let bytes = body.into_vec()?;
                md5 = Some(STANDARD.encode(Md5::digest(&bytes)));
                body = content::FileBody::from_vec(bytes);
            }
            Ok(FileRead {
                info: node,
                range: window,
                body,
                md5,
            })
        })
        .await
    }

    /// Allocated ranges of a file, or the difference against an earlier share snapshot.
    pub(crate) async fn list_ranges(
        &self,
        target: ShareRef,
        path: EntryPath,
        lease_id: Option<String>,
        window: Option<Range<u64>>,
        previous: Option<i64>,
    ) -> Result<RangeListing> {
        self.run(move |db, env| {
            let share = shares::load_share(db, &target)?;
            let node = find(db, &share, &path, Want::Regular)?;
            check_file_lease(
                &node,
                env.clock.now_millis(),
                lease_id.as_deref(),
                Use::Read,
            )?;
            let map = content::load_map(db, share.id, node.file_id, node.length)?;
            let window = window.unwrap_or(0..node.length);
            let clip = |ranges: Vec<Range<u64>>| -> Vec<Range<u64>> {
                ranges
                    .into_iter()
                    .filter_map(|range| {
                        let (start, end) =
                            (range.start.max(window.start), range.end.min(window.end));
                        (start < end).then_some(start..end)
                    })
                    .collect()
            };
            let (ranges, cleared) = if let Some(previous) = previous {
                if target.snapshot.is_some_and(|current| previous >= current) {
                    return Err(Error::PreviousSnapshotCannotBeNewer);
                }
                let earlier = ShareRef {
                    snapshot: Some(previous),
                    ..target.clone()
                };
                let earlier_share = load_share(db, &earlier).map_err(|error| match error {
                    Error::ShareSnapshotNotFound => Error::PreviousSnapshotNotFound,
                    other => other,
                })?;
                let before = match resolve(db, earlier_share.id, &path)?.node {
                    Some(old) if !old.directory => {
                        if old.file_id != node.file_id {
                            return Err(Error::FileGenerationMismatch);
                        }
                        content::load_map(db, earlier_share.id, old.file_id, old.length)?
                    }
                    _ => RangeMap::new(0),
                };
                let diff = map.diff(&before);
                (clip(diff.changed), clip(diff.cleared))
            } else {
                (clip(map.allocated_ranges()), Vec::new())
            };
            Ok(RangeListing {
                info: node,
                ranges,
                cleared,
            })
        })
        .await
    }
}
