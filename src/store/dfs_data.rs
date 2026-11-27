//! DFS Append Data and Flush Data (ADR-0015, ADR-0004, ADR-0020).
//!
//! An append streams into its own immutable extent, makes it durable, and then records a
//! range in `dfs_staged` in one transaction, so it stays invisible to Blob and DFS reads.
//! A flush publishes the contiguous staged ranges after the committed bytes as the
//! file's new content in one transaction: a new extent (or, for a file's first
//! flush of a single append, a hard link to the staged extent), the new length and
//! ETag, and the removal of the staged ranges. Staged rows carry the content id they
//! were appended to, so a Blob write that replaces the file orphans them.

use super::{
    BlobRow, ContentSource, Mode, Store, Uploaded, UploadedData, blob_params,
    blobs::touch,
    check_memory_quota, container, db_error,
    dfs_paths::{CreatePath, PathError, PathResult, create_file},
    expiry, extent, internal, io_error, namespace, open_extent, read_memory_slice, reclaim,
    require_blob, row_uint, save_row, snapshots, sqlite_int, staging_file, write_lease,
};
use crate::{
    conditions::Guard,
    domain::{BlobKey, BlobWrite, ContentHeaders, ContentLength, Entity, Error, Metadata, Result},
    lease::{LeaseAction, LeaseDuration, LeaseId, LeaseNeed, LeaseOwner, StoredLease},
    posix::{Creation, PathKind},
    ranges::{Mapping, RangeMap},
};
use rusqlite::{Connection, params};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read as _, Seek as _, SeekFrom, Write},
};
use uuid::Uuid;

/// What an Update Path data request does with the file's lease (`x-ms-lease-action`).
#[derive(Clone, Copy)]
pub(crate) enum LeaseUse {
    /// Only check the presented lease id.
    Hold,
    Acquire {
        duration: LeaseDuration,
        proposed: Option<LeaseId>,
    },
    /// Renew the presented lease after the operation.
    AutoRenew,
    /// Release the presented lease after the operation.
    Release,
    AcquireRelease {
        duration: LeaseDuration,
        proposed: Option<LeaseId>,
    },
}

/// The lease state to check against and the one to store after the operation.
struct LeasePlan {
    checked: StoredLease,
    id: Option<LeaseId>,
    use_: LeaseUse,
}

impl LeasePlan {
    fn begin(row: &BlobRow, guard: &Guard, use_: LeaseUse, now: i64) -> Result<Self> {
        let (checked, id) = match use_ {
            LeaseUse::Acquire { duration, proposed }
            | LeaseUse::AcquireRelease { duration, proposed } => {
                let outcome = row
                    .lease
                    .apply(LeaseAction::Acquire { duration, proposed }, now)?;
                (outcome.lease, outcome.id)
            }
            _ => (row.lease, guard.lease),
        };
        checked.check(id, LeaseNeed::Required, LeaseOwner::Blob, now)?;
        Ok(Self { checked, id, use_ })
    }

    /// Writes the lease the request leaves behind and returns the id to report.
    fn finish(
        self,
        db: &Connection,
        key: &BlobKey,
        original: &StoredLease,
        now: i64,
    ) -> Result<Option<LeaseId>> {
        let after = match self.use_ {
            LeaseUse::Hold => return Ok(None),
            LeaseUse::Acquire { .. } => self.checked,
            LeaseUse::AutoRenew => {
                let id = self.id.ok_or(Error::MissingHeader)?;
                self.checked.apply(LeaseAction::Renew(id), now)?.lease
            }
            LeaseUse::Release | LeaseUse::AcquireRelease { .. } => {
                let id = self.id.ok_or(Error::MissingHeader)?;
                self.checked.apply(LeaseAction::Release(id), now)?.lease
            }
        };
        if after != *original {
            write_lease(db, "blobs", &blob_params(key), &after)?;
        }
        Ok(matches!(self.use_, LeaseUse::Acquire { .. })
            .then_some(self.id)
            .flatten())
    }
}

type Rows = Vec<(u64, Mapping<Uuid>)>;

/// The staged rows of a file that belong to its current content, in offset order.
fn staged(db: &Connection, key: &BlobKey, content: Uuid, from: u64, to: u64) -> Result<Rows> {
    let [account, container, name] = blob_params(key);
    let mut query = db
        .prepare_cached(
            "SELECT offset, length, extent, extent_offset FROM dfs_staged
             WHERE account=?1 AND container=?2 AND name=?3 AND content=?4
               AND offset<?6 AND offset+length>?5
             ORDER BY offset",
        )
        .map_err(db_error)?;
    query
        .query_map(
            params![
                account,
                container,
                name,
                content,
                sqlite_int(from)?,
                sqlite_int(to)?
            ],
            |row| {
                Ok((
                    row_uint(row, 0)?,
                    Mapping {
                        length: row_uint(row, 1)?,
                        extent: row.get(2)?,
                        extent_offset: row_uint(row, 3)?,
                    },
                ))
            },
        )
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)
}

/// Removes staged rows that belong to older content of the file, and returns their extents.
fn drop_stale(db: &Connection, key: &BlobKey, content: Uuid) -> Result<Vec<Uuid>> {
    let [account, container, name] = blob_params(key);
    let mut delete = db
        .prepare_cached(
            "DELETE FROM dfs_staged WHERE account=?1 AND container=?2 AND name=?3 AND content<>?4
             RETURNING extent",
        )
        .map_err(db_error)?;
    delete
        .query_map(params![account, container, name, content], |row| row.get(0))
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)
}

/// Removes every staged row of a file that is being replaced or removed, and returns
/// the extents nothing else references.
pub(super) fn drop_staged(db: &Connection, mode: &Mode, key: &BlobKey) -> Result<Vec<Uuid>> {
    let [account, container, name] = blob_params(key);
    let mut delete = db
        .prepare_cached(
            "DELETE FROM dfs_staged WHERE account=?1 AND container=?2 AND name=?3 RETURNING extent",
        )
        .map_err(db_error)?;
    let dropped: Vec<Uuid> = delete
        .query_map(params![account, container, name], |row| row.get(0))
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)?;
    free_extents(db, mode, dropped)
}

/// Of the extents that lost a reference, those no staged row still uses. In memory
/// mode their bytes go too, so the quota sees the space again.
pub(super) fn free_extents(
    db: &Connection,
    mode: &Mode,
    candidates: impl IntoIterator<Item = Uuid>,
) -> Result<Vec<Uuid>> {
    let mut free = Vec::new();
    if matches!(mode, Mode::Memory { .. }) {
        // Staged rows that left with a deleted file leave their bytes behind.
        db.execute(
            "DELETE FROM dfs_staged_bytes WHERE extent NOT IN (SELECT extent FROM dfs_staged)",
            [],
        )
        .map_err(db_error)?;
    }
    for id in candidates.into_iter().collect::<BTreeSet<_>>() {
        let used: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM dfs_staged WHERE extent=?1)",
                [id],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if !used {
            if matches!(mode, Mode::Memory { .. }) {
                db.execute("DELETE FROM dfs_staged_bytes WHERE extent=?1", [id])
                    .map_err(db_error)?;
            }
            free.push(id);
        }
    }
    Ok(free)
}

/// Applies the difference between two states of the same window as row changes.
fn save_window(
    db: &Connection,
    key: &BlobKey,
    content: Uuid,
    old: &RangeMap<Uuid>,
    new: &RangeMap<Uuid>,
) -> Result<()> {
    let [account, container, name] = blob_params(key);
    let old_rows: std::collections::BTreeMap<u64, &Mapping<Uuid>> = old.mappings().collect();
    let new_rows: std::collections::BTreeMap<u64, &Mapping<Uuid>> = new.mappings().collect();
    for (offset, mapping) in &old_rows {
        if new_rows.get(offset) != Some(mapping) {
            db.execute(
                "DELETE FROM dfs_staged WHERE account=?1 AND container=?2 AND name=?3 AND offset=?4",
                params![account, container, name, sqlite_int(*offset)?],
            )
            .map_err(db_error)?;
        }
    }
    for (offset, mapping) in &new_rows {
        if old_rows.get(offset) != Some(mapping) {
            db.execute(
                "INSERT INTO dfs_staged (account, container, name, offset, length, extent, extent_offset, content)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    account,
                    container,
                    name,
                    sqlite_int(*offset)?,
                    sqlite_int(mapping.length)?,
                    mapping.extent,
                    sqlite_int(mapping.extent_offset)?,
                    content
                ],
            )
            .map_err(db_error)?;
        }
    }
    Ok(())
}

/// The file a data operation targets: it must exist, be a block-blob-like file, and
/// not be a directory.
fn data_target(db: &Connection, key: &BlobKey, now: i64) -> PathResult<BlobRow> {
    container(db, &key.container)?;
    if namespace::directory(db, &key.container, key.path.as_str())?.is_some() {
        return Err(PathError::ResourceTypeMismatch);
    }
    let row = require_blob(db, key, now)?;
    if !row.info.kind.is_block() {
        return Err(PathError::ResourceTypeMismatch);
    }
    Ok(row)
}

pub(crate) struct Append {
    pub(crate) key: BlobKey,
    pub(crate) position: u64,
    pub(crate) upload: Uploaded,
    pub(crate) guard: Guard,
    pub(crate) lease: LeaseUse,
    /// The largest file size a flush may publish.
    pub(crate) limit: u64,
    /// The owner of a file this append creates, when the path does not exist yet.
    pub(crate) owner: Option<String>,
}

pub(crate) struct Flush {
    pub(crate) key: BlobKey,
    pub(crate) position: u64,
    pub(crate) retain: bool,
    pub(crate) headers: crate::store::dfs_paths::PropertyUpdate,
    pub(crate) md5: Option<[u8; 16]>,
    pub(crate) guard: Guard,
    pub(crate) lease: LeaseUse,
    pub(crate) limit: u64,
}

impl Store {
    /// Append Data: stages `upload` at `position`. Overlapping staged data is replaced,
    /// so a retried chunk is harmless. A missing file is created empty, which is how the
    /// SDKs upload without overwriting. Data staged before the committed length never
    /// publishes: a flush only commits what follows the committed bytes.
    pub(crate) async fn append_path(&self, request: Append) -> PathResult<Option<LeaseId>> {
        self.run_path(move |db, mode, now| {
            let Append {
                key,
                position,
                upload,
                guard,
                lease,
                limit,
                owner,
            } = request;
            let length = upload.length.0;
            let tx = db.transaction().map_err(db_error)?;
            let row = match data_target(&tx, &key, now) {
                Err(PathError::Shared(Error::BlobMissing)) => {
                    let create = CreatePath {
                        key: key.clone(),
                        kind: PathKind::File,
                        guard: Guard::default(),
                        headers: ContentHeaders {
                            content_type: "application/octet-stream".into(),
                            ..ContentHeaders::default()
                        },
                        properties: Metadata::new(),
                        creation: Creation::default(),
                        default_owner: owner.clone(),
                        lease: None,
                        expiry: None,
                    };
                    create_file(&tx, mode, create, now, true)?;
                    data_target(&tx, &key, now)?
                }
                other => other?,
            };
            let plan = LeasePlan::begin(&row, &guard, lease, now)?;
            guard.conditions.check(Some(row.info.entity), false)?;
            let end = position
                .checked_add(length)
                .filter(|end| *end <= limit)
                .ok_or(Error::TooLarge)?;
            let content = row.info.entity.id;
            let mut candidates = drop_stale(&tx, &key, content)?;
            let id = Uuid::new_v4();
            if length > 0 {
                check_memory_quota(&tx, mode, 0, length)?;
                let rows = staged(&tx, &key, content, position, end)?;
                let span = rows
                    .iter()
                    .map(|(offset, mapping)| offset + mapping.length)
                    .max()
                    .unwrap_or(0)
                    .max(end);
                let before = RangeMap::from_mappings(span, rows)
                    .map_err(|_| internal("stored staged ranges are inconsistent"))?;
                let mut after = before.clone();
                after
                    .write(position, length, id, 0)
                    .map_err(|_| internal("staged range overflow"))?;
                save_window(&tx, &key, content, &before, &after)?;
                candidates.extend(before.extents().copied());
                if let (Mode::Memory { .. }, Some(bytes)) = (mode, upload.data.bytes()) {
                    tx.execute(
                        "INSERT INTO dfs_staged_bytes (extent, bytes) VALUES (?1, ?2)",
                        params![id, bytes],
                    )
                    .map_err(db_error)?;
                }
                upload.data.persist(mode, id)?;
            }
            let reported = plan.finish(&tx, &key, &row.lease, now)?;
            let free = free_extents(&tx, mode, candidates)?;
            tx.commit().map_err(db_error)?;
            for id in free {
                reclaim(mode, id);
            }
            Ok(reported)
        })
        .await
    }

    /// Flush Data: publishes the staged data contiguous with the committed bytes up to
    /// `position`, or only the properties when `position` is the committed length.
    pub(crate) async fn flush_path(&self, request: Flush) -> PathResult<(Entity, u64)> {
        self.run_path(move |db, mode, now| flush(db, mode, now, request))
            .await
    }
}

fn flush(db: &mut Connection, mode: &Mode, now: i64, request: Flush) -> PathResult<(Entity, u64)> {
    let Flush {
        key,
        position,
        retain,
        headers,
        md5,
        guard,
        lease,
        limit,
    } = request;
    let tx = db.transaction().map_err(db_error)?;
    let old = data_target(&tx, &key, now)?;
    let plan = LeasePlan::begin(&old, &guard, lease, now)?;
    let [account, container_name, name] = blob_params(&key);
    let pending: bool = tx
        .query_row(
            "SELECT dfs_pending IS NOT NULL AND dfs_pending=id FROM blobs
             WHERE account=?1 AND container=?2 AND name=?3",
            [account, container_name, name],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    // A file the first append created counts as absent until this flush publishes it.
    if !pending && guard.conditions.requires_absence() {
        return Err(Error::BlobAlreadyExists.into());
    }
    guard
        .conditions
        .check((!pending).then_some(old.info.entity), false)?;
    let committed = old.info.length.0;
    if position < committed {
        return Err(PathError::InvalidFlushPosition);
    }
    if position > limit {
        return Err(Error::TooLarge.into());
    }
    let content = old.info.entity.id;
    let mut candidates = drop_stale(&tx, &key, content)?;
    let rows = staged(&tx, &key, content, committed, u64::MAX / 2)?;
    let mut chain: Rows = Vec::new();
    let mut cursor = committed;
    for (offset, mapping) in &rows {
        if cursor >= position || *offset != cursor {
            break;
        }
        cursor += mapping.length;
        chain.push((*offset, mapping.clone()));
    }
    if cursor != position {
        return Err(PathError::InvalidFlushPosition);
    }
    let mut options = BlobWrite {
        headers: old.info.headers.clone(),
        metadata: old.info.metadata.clone(),
        guard: Guard::default(),
        tier: old.info.tier.map(|(tier, _)| tier),
        copy: None,
        md5,
        tags: old.info.tags.clone(),
    };
    for (slot, new) in [
        (&mut options.headers.content_type, &headers.content_type),
        (&mut options.headers.encoding, &headers.encoding),
        (&mut options.headers.language, &headers.language),
        (&mut options.headers.disposition, &headers.disposition),
        (&mut options.headers.cache_control, &headers.cache_control),
    ] {
        if let Some(new) = new {
            slot.clone_from(new);
        }
    }
    let entity;
    let mut released: Vec<Uuid> = Vec::new();
    if chain.is_empty() {
        let version = snapshots::begin_write(
            &tx,
            mode,
            &key,
            Some(&old),
            snapshots::Change::Properties,
            now,
        )?;
        let touched = touch(&tx, &key, now)?;
        entity = snapshots::finish_write(&tx, &key, touched, version, None)?;
        tx.execute(
            "UPDATE blobs SET content_type=?1, content_encoding=?2, content_language=?3,
                content_disposition=?4, cache_control=?5, md5=COALESCE(?6, md5), dfs_pending=NULL
             WHERE account=?7 AND container=?8 AND name=?9",
            params![
                options.headers.content_type,
                options.headers.encoding,
                options.headers.language,
                options.headers.disposition,
                options.headers.cache_control,
                md5.map(|md5| base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    md5
                )),
                account,
                container_name,
                name
            ],
        )
        .map_err(db_error)?;
    } else {
        let removed = committed + chain.iter().map(|(_, m)| m.length).sum::<u64>();
        check_memory_quota(&tx, mode, removed, position)?;
        let mut assembled = assemble(&tx, mode, &old, committed, &chain)?;
        let version =
            snapshots::begin_write(&tx, mode, &key, Some(&old), snapshots::Change::Content, now)?;
        let saved = save_row(
            &tx,
            &key,
            &options,
            ContentLength(position),
            assembled.bytes(),
            None,
            now,
        )?;
        entity = snapshots::finish_write(&tx, &key, saved, version, Some(&options.tags))?;
        tx.execute(
            "UPDATE blobs SET created=?1 WHERE account=?2 AND container=?3 AND name=?4",
            params![sqlite_int(old.info.created)?, account, container_name, name],
        )
        .map_err(db_error)?;
        // Flushing completes the same file, so a deadline set at creation stays with it.
        if old.info.lifecycle.expires.is_some() {
            expiry::write(&tx, &key, &old.info.lifecycle)?;
        }
        match assembled {
            Assembled::Adopt(staged_id) => link_extent(mode, staged_id, entity.id)?,
            Assembled::Built(data) => data.persist(mode, entity.id)?,
        }
        released.push(old.info.entity.id);
    }
    let dropped = {
        let mut delete = tx
            .prepare_cached(
                "DELETE FROM dfs_staged
                 WHERE account=?1 AND container=?2 AND name=?3 AND (?4=0 OR offset<?5)
                 RETURNING extent",
            )
            .map_err(db_error)?;
        let rows: Vec<Uuid> = delete
            .query_map(
                params![
                    account,
                    container_name,
                    name,
                    i64::from(retain),
                    sqlite_int(position)?
                ],
                |row| row.get(0),
            )
            .map_err(db_error)?
            .collect::<rusqlite::Result<_>>()
            .map_err(db_error)?;
        rows
    };
    candidates.extend(dropped);
    if retain {
        tx.execute(
            "UPDATE dfs_staged SET content=?1 WHERE account=?2 AND container=?3 AND name=?4",
            params![entity.id, account, container_name, name],
        )
        .map_err(db_error)?;
    }
    plan.finish(&tx, &key, &old.lease, now)?;
    released.extend(free_extents(&tx, mode, candidates)?);
    tx.commit().map_err(db_error)?;
    for id in released {
        reclaim(mode, id);
    }
    Ok((entity, position))
}

enum Assembled {
    /// The staged extent already holds exactly the new content.
    Adopt(Uuid),
    Built(UploadedData),
}

impl Assembled {
    fn bytes(&mut self) -> Option<&[u8]> {
        match self {
            Self::Built(data) => data.bytes(),
            Self::Adopt(_) => None,
        }
    }
}

/// Builds the new content: the committed bytes followed by the chain of staged ranges.
fn assemble(
    db: &Connection,
    mode: &Mode,
    old: &BlobRow,
    committed: u64,
    chain: &Rows,
) -> Result<Assembled> {
    if let Mode::Disk { extents, .. } = mode
        && committed == 0
        && let [(_, only)] = chain.as_slice()
        && only.extent_offset == 0
        && fs::metadata(extent(extents, only.extent)).is_ok_and(|meta| meta.len() == only.length)
    {
        return Ok(Assembled::Adopt(only.extent));
    }
    let mut data = match mode {
        Mode::Disk { extents, .. } => UploadedData::Disk(staging_file(extents).map_err(io_error)?),
        Mode::Memory { .. } => UploadedData::Memory(Vec::new()),
    };
    let sink = data.writer();
    if committed > 0 {
        match mode {
            Mode::Disk { extents, .. } => {
                let file = open_extent(extents, old.info.entity.id, committed, 0)?;
                copy_exact(file, committed, sink)?;
            }
            Mode::Memory { .. } => {
                let bytes =
                    read_memory_slice(db, ContentSource::Blob, old.info.entity.id, 0, committed)?;
                sink.write_all(&bytes).map_err(io_error)?;
            }
        }
    }
    for (_, mapping) in chain {
        match mode {
            Mode::Disk { extents, .. } => {
                let mut file = fs::File::open(extent(extents, mapping.extent)).map_err(io_error)?;
                file.seek(SeekFrom::Start(mapping.extent_offset))
                    .map_err(io_error)?;
                copy_exact(file, mapping.length, sink)?;
            }
            Mode::Memory { .. } => {
                let bytes: Vec<u8> = db
                    .query_row(
                        "SELECT substr(bytes, ?2, ?3) FROM dfs_staged_bytes WHERE extent=?1",
                        params![
                            mapping.extent,
                            sqlite_int(mapping.extent_offset + 1)?,
                            sqlite_int(mapping.length)?
                        ],
                        |row| row.get(0),
                    )
                    .map_err(db_error)?;
                if bytes.len() as u64 != mapping.length {
                    return Err(internal("staged bytes are shorter than their range"));
                }
                sink.write_all(&bytes).map_err(io_error)?;
            }
        }
    }
    Ok(Assembled::Built(data))
}

fn copy_exact(file: fs::File, length: u64, sink: &mut dyn Write) -> Result<()> {
    let copied = std::io::copy(&mut file.take(length), sink).map_err(io_error)?;
    if copied != length {
        return Err(internal("extent ended early"));
    }
    Ok(())
}

/// Publishes the staged extent under the file's new content id without copying it.
/// The staged name is removed after the metadata commit, and a crash before it leaves
/// an unreferenced extent that recovery collects.
fn link_extent(mode: &Mode, staged: Uuid, content: Uuid) -> Result<()> {
    let Mode::Disk { extents, .. } = mode else {
        return Err(internal("extent adoption needs the disk backend"));
    };
    let target = extent(extents, content);
    if fs::hard_link(extent(extents, staged), &target).is_err() {
        fs::copy(extent(extents, staged), &target).map_err(io_error)?;
    }
    fs::OpenOptions::new()
        .write(true)
        .open(&target)
        .and_then(|file| file.sync_all())
        .map_err(io_error)?;
    #[cfg(unix)]
    fs::File::open(extents)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)?;
    Ok(())
}
