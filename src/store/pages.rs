//! Page and append blob content: a range map over immutable extents (ADR-0015).
//!
//! Each write streams into a new extent, makes it durable, then commits the range
//! rows and the new ETag in one metadata transaction (ADR-0004). Clearing and
//! shrinking only change rows. An extent is deleted only when no blob row references
//! it any more, so same-instance copies can share extents.

use super::{
    BlobRow, ContentSource, Mode, Store, Uploaded, UploadedData, blob, blob_params,
    blobs::{ensure_parents, guard_write, touch},
    check_memory_quota, container, db_error, extent, internal, io_error, remove_staged,
    require_blob, row_uint, save_row, snapshots, sqlite_int, staging_file,
};
use crate::{
    blob_page::{
        BlobKind, Creation, PageError, PageWrite, PropertyChange, check_tier, check_within,
    },
    blob_snapshot::Selector,
    checksum::Hasher,
    conditions::Guard,
    domain::{BlobInfo, BlobKey, BlobWrite, ContentLength, Entity, Error, Result},
    lease::{LeaseNeed, LeaseOwner},
    ranges::{Mapping, RangeMap, Segment},
    store::SourceBytes,
};
use axum::body::Bytes;
use futures_util::{StreamExt as _, TryStreamExt as _, stream::BoxStream};
use rusqlite::{Connection, params};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    ops::Range,
    path::PathBuf,
};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

const CHUNK: usize = 64 * 1024;

/// Bytes a block blob holds in memory-mode quota; page and append blobs count their extents.
pub(super) fn block_length(info: &BlobInfo) -> u64 {
    if info.kind.is_block() {
        info.length.0
    } else {
        0
    }
}

/// The outcome of a Put Page.
pub(crate) struct PageWritten {
    pub(crate) entity: Entity,
    pub(crate) sequence: u64,
}

/// A page of Get Page Ranges results; `next` resumes after the last returned range.
/// `cleared` holds the clear ranges of a diff (`prevsnapshot`), empty otherwise.
pub(crate) struct PageRanges {
    pub(crate) entity: Entity,
    pub(crate) length: u64,
    pub(crate) ranges: Vec<Range<u64>>,
    pub(crate) cleared: Vec<Range<u64>>,
    pub(crate) next: Option<u64>,
}

/// The outcome of a same-instance copy of a page or append blob.
pub(crate) struct Copied {
    pub(crate) entity: Entity,
    pub(crate) copy_id: String,
}

type Rows = Vec<(u64, Mapping<Uuid>)>;

/// Where a blob's range rows live: the current blob, or a retained snapshot,
/// version, or soft-deleted entry (`kind` and `state` as in `blob_history`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RangeSource {
    Current,
    Retained { kind: i64, state: i64 },
}

impl From<ContentSource> for RangeSource {
    fn from(source: ContentSource) -> Self {
        match source {
            ContentSource::History(kind, state) => Self::Retained { kind, state },
            _ => Self::Current,
        }
    }
}

impl Uploaded {
    /// The number of bytes received.
    pub(crate) fn len(&self) -> u64 {
        self.length.0
    }
}

fn load_window(
    db: &Connection,
    key: &BlobKey,
    start: u64,
    end: u64,
    length: u64,
) -> Result<RangeMap<Uuid>> {
    load_source_window(db, key, RangeSource::Current, start, end, length)
}

/// Loads the ranges of `source` that overlap `[start, end)` of a blob `length` bytes long.
pub(super) fn load_source_window(
    db: &Connection,
    key: &BlobKey,
    source: RangeSource,
    start: u64,
    end: u64,
    length: u64,
) -> Result<RangeMap<Uuid>> {
    let [account, container, name] = blob_params(key);
    let (table, filter) = match source {
        RangeSource::Current => ("blob_ranges", String::new()),
        // Both values are integers, so formatting them into the statement is safe.
        RangeSource::Retained { kind, state } => (
            "history_ranges",
            format!(" AND kind={kind} AND state_id={state}"),
        ),
    };
    let sql = format!(
        "SELECT offset, length, extent, extent_offset FROM {table}
         WHERE account=?1 AND container=?2 AND name=?3 AND offset<?4 AND offset+length>?5{filter}
         ORDER BY offset"
    );
    let mut query = db.prepare_cached(&sql).map_err(db_error)?;
    let rows = query
        .query_map(
            params![
                account,
                container,
                name,
                sqlite_int(end)?,
                sqlite_int(start)?
            ],
            |row| {
                Ok((
                    row_uint(row, 0)?,
                    Mapping {
                        extent: row.get(2)?,
                        extent_offset: row_uint(row, 3)?,
                        length: row_uint(row, 1)?,
                    },
                ))
            },
        )
        .map_err(db_error)?
        .collect::<rusqlite::Result<Rows>>()
        .map_err(db_error)?;
    RangeMap::from_mappings(length, rows)
        .map_err(|_| internal("stored page ranges are inconsistent"))
}

/// Applies the difference between two loads of the same window as row changes.
pub(super) fn save_window(
    db: &Connection,
    key: &BlobKey,
    old: &RangeMap<Uuid>,
    new: &RangeMap<Uuid>,
) -> Result<()> {
    let [account, container, name] = blob_params(key);
    let old_rows: std::collections::BTreeMap<u64, &Mapping<Uuid>> = old.mappings().collect();
    let new_rows: std::collections::BTreeMap<u64, &Mapping<Uuid>> = new.mappings().collect();
    let mut delete = db
        .prepare_cached(
            "DELETE FROM blob_ranges WHERE account=?1 AND container=?2 AND name=?3 AND offset=?4",
        )
        .map_err(db_error)?;
    for (offset, mapping) in &old_rows {
        if new_rows.get(offset) != Some(mapping) {
            delete
                .execute(params![account, container, name, sqlite_int(*offset)?])
                .map_err(db_error)?;
        }
    }
    let mut insert = db
        .prepare_cached(
            "INSERT INTO blob_ranges (account, container, name, offset, length, extent, extent_offset)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .map_err(db_error)?;
    for (offset, mapping) in &new_rows {
        if old_rows.get(offset) != Some(mapping) {
            insert
                .execute(params![
                    account,
                    container,
                    name,
                    sqlite_int(*offset)?,
                    sqlite_int(mapping.length)?,
                    mapping.extent,
                    sqlite_int(mapping.extent_offset)?
                ])
                .map_err(db_error)?;
        }
    }
    Ok(())
}

pub(super) fn set_kind(db: &Connection, key: &BlobKey, kind: BlobKind) -> Result<()> {
    let [account, container, name] = blob_params(key);
    let (code, sequence, committed, sealed) = kind.columns();
    db.execute(
        "UPDATE blobs SET blob_type=?1, sequence_number=?2, append_count=?3, sealed=?4
         WHERE account=?5 AND container=?6 AND name=?7",
        params![code, sequence, committed, sealed, account, container, name],
    )
    .map_err(db_error)?;
    Ok(())
}

/// Extents that lost a reference inside a transaction. After the row changes, those
/// that no range references any more are collectable.
#[derive(Default)]
pub(super) struct Reclaim(BTreeSet<Uuid>);

impl Reclaim {
    fn add_map(&mut self, map: &RangeMap<Uuid>) {
        self.0.extend(map.extents().copied());
    }

    /// Notes extents that lost a reference outside this module (retained range rows).
    pub(super) fn add_ids(&mut self, ids: impl IntoIterator<Item = Uuid>) {
        self.0.extend(ids);
    }

    /// Notes every extent of a blob and deletes its range rows.
    pub(super) fn add_blob(&mut self, db: &Connection, key: &BlobKey) -> Result<()> {
        let [account, container, name] = blob_params(key);
        self.collect(
            db,
            "DELETE FROM blob_ranges WHERE account=?1 AND container=?2 AND name=?3 RETURNING extent",
            &[account, container, name],
        )
    }

    fn add_container(&mut self, db: &Connection, account: &str, name: &str) -> Result<()> {
        self.collect(
            db,
            "DELETE FROM blob_ranges WHERE account=?1 AND container=?2 RETURNING extent",
            &[account, name],
        )
    }

    fn collect(&mut self, db: &Connection, sql: &str, arguments: &[&str]) -> Result<()> {
        let mut statement = db.prepare(sql).map_err(db_error)?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(arguments), |row| {
                row.get::<_, Uuid>(0)
            })
            .map_err(db_error)?;
        for row in rows {
            self.0.insert(row.map_err(db_error)?);
        }
        Ok(())
    }

    /// Returns the unreferenced extents. In memory mode their bytes are removed here,
    /// inside the transaction, so the quota check sees the freed space.
    pub(super) fn finish(self, db: &Connection, mode: &Mode) -> Result<Vec<Uuid>> {
        let mut free = Vec::new();
        for id in self.0 {
            let referenced: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM blob_ranges WHERE extent=?1
                                   UNION ALL SELECT 1 FROM history_ranges WHERE extent=?1)",
                    [id],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if !referenced {
                if matches!(mode, Mode::Memory { .. }) {
                    db.execute("DELETE FROM blob_extents WHERE id=?1", [id])
                        .map_err(db_error)?;
                }
                free.push(id);
            }
        }
        Ok(free)
    }
}

/// Removes extent files after the transaction that dropped their last reference committed.
pub(super) fn discard(mode: &Mode, ids: &[Uuid]) {
    for id in ids {
        super::reclaim(mode, *id);
    }
}

/// Drops the content of a blob that is being replaced or deleted. Block blobs
/// have no range rows, so only page and append blobs do any work.
pub(super) fn retire(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    kind: BlobKind,
) -> Result<Vec<Uuid>> {
    if kind.is_block() {
        return Ok(Vec::new());
    }
    let mut reclaim = Reclaim::default();
    reclaim.add_blob(db, key)?;
    reclaim.finish(db, mode)
}

pub(super) fn retire_container(
    db: &Connection,
    mode: &Mode,
    account: &str,
    name: &str,
) -> Result<Vec<Uuid>> {
    let mut reclaim = Reclaim::default();
    reclaim.add_container(db, account, name)?;
    reclaim.finish(db, mode)
}

/// In memory mode, stores the extent's bytes in the transaction. On disk the
/// extent is published by [`UploadedData::persist`] just before the commit.
pub(super) fn stage_extent(
    db: &Connection,
    mode: &Mode,
    id: Uuid,
    data: &UploadedData,
    length: u64,
) -> Result<()> {
    if let (Mode::Memory { .. }, Some(bytes)) = (mode, data.bytes()) {
        db.execute(
            "INSERT INTO blob_extents (id, length, bytes) VALUES (?1, ?2, ?3)",
            params![id, sqlite_int(length)?, bytes],
        )
        .map_err(db_error)?;
    }
    Ok(())
}

enum Piece {
    Extent {
        path: PathBuf,
        offset: u64,
        length: u64,
    },
    Memory(Vec<u8>),
    Zeros(u64),
}

/// The bytes of a read: extent slices and zero-filled holes, in order. Extent files
/// are opened only when streamed, so a fragmented blob does not hold many handles.
pub(crate) struct RangeBody(Vec<Piece>);

impl RangeBody {
    fn open(
        db: &Connection,
        mode: &Mode,
        map: &RangeMap<Uuid>,
        offset: u64,
        length: u64,
    ) -> Result<Self> {
        let segments = map
            .resolve(offset, length)
            .map_err(|_| internal("range overflow"))?;
        let mut pieces = Vec::with_capacity(segments.len());
        for segment in segments {
            pieces.push(match segment {
                Segment::Hole { length, .. } => Piece::Zeros(length),
                Segment::Data {
                    extent: id,
                    extent_offset,
                    length,
                    ..
                } => match mode {
                    Mode::Disk { extents, .. } => {
                        let path = extent(extents, id);
                        super::require_file_if_present(&path).map_err(io_error)?;
                        let size = std::fs::metadata(&path).map_err(io_error)?.len();
                        if size < extent_offset + length {
                            return Err(internal("extent is shorter than its range"));
                        }
                        Piece::Extent {
                            path,
                            offset: extent_offset,
                            length,
                        }
                    }
                    Mode::Memory { .. } => {
                        let bytes: Vec<u8> = db
                            .query_row(
                                "SELECT substr(bytes, ?2, ?3) FROM blob_extents WHERE id=?1",
                                params![id, sqlite_int(extent_offset + 1)?, sqlite_int(length)?],
                                |row| row.get(0),
                            )
                            .map_err(db_error)?;
                        if bytes.len() as u64 != length {
                            return Err(internal("in-memory extent is shorter than its range"));
                        }
                        Piece::Memory(bytes)
                    }
                },
            });
        }
        Ok(Self(pieces))
    }

    /// Feeds every byte to `sink` in order, in bounded chunks.
    fn copy_into(self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut buffer = vec![0u8; CHUNK];
        for piece in self.0 {
            match piece {
                Piece::Extent {
                    path,
                    offset,
                    length,
                } => {
                    let mut file = File::open(path).map_err(io_error)?;
                    file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
                    let mut left = length;
                    while left > 0 {
                        let want = usize::try_from(left).unwrap_or(CHUNK).min(CHUNK);
                        let read = file.read(&mut buffer[..want]).map_err(io_error)?;
                        if read == 0 {
                            return Err(internal("extent ended early"));
                        }
                        sink(&buffer[..read])?;
                        left -= read as u64;
                    }
                }
                Piece::Memory(bytes) => sink(&bytes)?,
                Piece::Zeros(length) => {
                    buffer.fill(0);
                    let mut left = length;
                    while left > 0 {
                        let take = usize::try_from(left).unwrap_or(CHUNK).min(CHUNK);
                        sink(&buffer[..take])?;
                        left -= take as u64;
                    }
                }
            }
        }
        Ok(())
    }

    /// Reads everything into memory; callers bound the size (a ranged checksum).
    pub(crate) fn into_vec(self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.copy_into(&mut |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(bytes)
    }

    pub(crate) fn into_stream(self) -> BoxStream<'static, std::io::Result<Bytes>> {
        futures_util::stream::iter(self.0)
            .map(piece_stream)
            .flatten()
            .boxed()
    }
}

fn piece_stream(piece: Piece) -> BoxStream<'static, std::io::Result<Bytes>> {
    match piece {
        Piece::Extent {
            path,
            offset,
            length,
        } => futures_util::stream::once(async move {
            let mut file = tokio::fs::File::open(path).await?;
            file.seek(SeekFrom::Start(offset)).await?;
            Ok::<_, std::io::Error>(ReaderStream::new(file.take(length)))
        })
        .try_flatten()
        .boxed(),
        Piece::Memory(bytes) => {
            futures_util::stream::once(async move { Ok(Bytes::from(bytes)) }).boxed()
        }
        Piece::Zeros(length) => futures_util::stream::unfold(length, |left| async move {
            if left == 0 {
                return None;
            }
            let take = left.min(CHUNK as u64);
            let chunk = Bytes::from(vec![0u8; usize::try_from(take).unwrap_or(CHUNK)]);
            Some((Ok(chunk), left - take))
        })
        .boxed(),
    }
}

/// Resolves `window` of a page or append blob into readable pieces.
pub(super) fn open_body(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    source: RangeSource,
    length: u64,
    window: Range<u64>,
) -> Result<RangeBody> {
    let map = load_source_window(db, key, source, window.start, window.end, length)?;
    RangeBody::open(db, mode, &map, window.start, window.end - window.start)
}

/// Reads a window of a page or append blob into staging, as a copy source.
pub(super) fn source_bytes(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    source: RangeSource,
    info: BlobInfo,
    window: Range<u64>,
) -> Result<SourceBytes> {
    let length = window.end - window.start;
    if let Mode::Memory { limit } = mode
        && length > *limit
    {
        return Err(Error::QuotaExceeded);
    }
    let body = open_body(db, mode, key, source, info.length.0, window)?;
    let mut hasher = Hasher::new();
    let data = match mode {
        Mode::Disk { extents, .. } => {
            let temp = staging_file(extents).map_err(io_error)?;
            let mut sink = temp.reopen().map_err(io_error)?;
            body.copy_into(&mut |chunk| {
                hasher.update(chunk);
                sink.write_all(chunk).map_err(io_error)
            })?;
            sink.flush().map_err(io_error)?;
            UploadedData::Disk(temp)
        }
        Mode::Memory { .. } => {
            let mut bytes = Vec::new();
            body.copy_into(&mut |chunk| {
                hasher.update(chunk);
                bytes.extend_from_slice(chunk);
                Ok(())
            })?;
            UploadedData::Memory(bytes)
        }
    };
    Ok(SourceBytes {
        info,
        upload: Uploaded {
            length: ContentLength(length),
            checksums: hasher.finish(None)?,
            data,
        },
    })
}

/// Applies a page blob's resize and sequence-number change inside Set Blob Properties.
/// Returns the sequence number and the extents to remove once the transaction commits.
pub(super) fn apply_change(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    info: &BlobInfo,
    change: PropertyChange,
) -> Result<(Option<u64>, Vec<Uuid>)> {
    let BlobKind::Page { sequence } = info.kind else {
        return if change.is_empty() {
            Ok((None, Vec::new()))
        } else {
            Err(Error::Page(PageError::InvalidBlobType))
        };
    };
    let [account, container, name] = blob_params(key);
    let mut current = sequence;
    if let Some(action) = change.sequence {
        current = action.apply(sequence)?;
        db.execute(
            "UPDATE blobs SET sequence_number=?1 WHERE account=?2 AND container=?3 AND name=?4",
            params![sqlite_int(current)?, account, container, name],
        )
        .map_err(db_error)?;
    }
    let mut free = Vec::new();
    if let Some(length) = change.resize {
        let old_length = info.length.0;
        if length < old_length {
            let before = load_window(db, key, length, old_length, old_length)?;
            let mut after = before.clone();
            after.resize(length);
            let mut reclaim = Reclaim::default();
            reclaim.add_map(&before);
            save_window(db, key, &before, &after)?;
            free = reclaim.finish(db, mode)?;
        }
        db.execute(
            "UPDATE blobs SET length=?1 WHERE account=?2 AND container=?3 AND name=?4",
            params![sqlite_int(length)?, account, container, name],
        )
        .map_err(db_error)?;
    }
    Ok((Some(current), free))
}

pub(super) fn page_blob(row: &BlobRow) -> Result<u64> {
    match row.info.kind {
        BlobKind::Page { sequence } => Ok(sequence),
        _ => Err(Error::Page(PageError::InvalidBlobType)),
    }
}

impl Store {
    /// Put Blob for a page or append blob: replaces whatever the name held.
    pub(crate) async fn create_paged(
        &self,
        key: BlobKey,
        options: BlobWrite,
        creation: Creation,
    ) -> Result<Entity> {
        let hierarchical = self.hierarchical(&key.container);
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            container(&tx, &key.container)?;
            let old = blob(&tx, &key, now)?;
            guard_write(&options.guard, old.as_ref(), true, now)?;
            ensure_parents(&tx, &key, hierarchical, now)?;
            let kind = creation.kind();
            check_tier(kind, options.tier)?;
            let version = snapshots::begin_write(
                &tx,
                mode,
                &key,
                old.as_ref(),
                snapshots::Change::Content,
                now,
            )?;
            let mut reclaim = Reclaim::default();
            reclaim.add_blob(&tx, &key)?;
            let mut discard = remove_staged(&tx, &key)?;
            let length = ContentLength(creation.length());
            let entity = save_row(&tx, &key, &options, length, None, None, now)?;
            set_kind(&tx, &key, kind)?;
            let entity = snapshots::finish_write(&tx, &key, entity, version, Some(&options.tags))?;
            discard.extend(reclaim.finish(&tx, mode)?);
            check_memory_quota(&tx, mode, 0, 0)?;
            tx.commit().map_err(db_error)?;
            if let Some(old) = old {
                super::reclaim(mode, old.info.entity.id);
            }
            self::discard(mode, &discard);
            Ok(entity)
        })
        .await
    }

    /// Put Page: `upload` is the new content of `write.range`, or `None` to clear it.
    pub(crate) async fn put_page(
        &self,
        key: BlobKey,
        write: PageWrite,
        upload: Option<Uploaded>,
    ) -> Result<PageWritten> {
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            let old = require_blob(&tx, &key, now)?;
            let sequence = page_blob(&old)?;
            guard_write(&write.guard, Some(&old), false, now)?;
            if old.info.lifecycle.incremental.is_some() {
                return Err(Error::Ext(
                    crate::blob_lifecycle::LifecycleError::OperationNotAllowedOnIncrementalCopyBlob,
                ));
            }
            write.sequence.check(sequence)?;
            let length = old.info.length.0;
            check_within(&write.range, length)?;
            let size = write.range.end - write.range.start;
            if upload
                .as_ref()
                .is_some_and(|upload| upload.length.0 != size)
            {
                return Err(Error::InvalidHeader);
            }
            let version = snapshots::begin_write(
                &tx,
                mode,
                &key,
                Some(&old),
                snapshots::Change::Properties,
                now,
            )?;
            let before = load_window(&tx, &key, write.range.start, write.range.end, length)?;
            let mut after = before.clone();
            let mut reclaim = Reclaim::default();
            reclaim.add_map(&before);
            let mut staged = None;
            match upload {
                Some(upload) => {
                    let id = Uuid::new_v4();
                    after
                        .write(write.range.start, size, id, 0)
                        .map_err(|_| internal("page range overflow"))?;
                    stage_extent(&tx, mode, id, &upload.data, size)?;
                    staged = Some((id, upload.data));
                }
                None => after
                    .clear(write.range.start, size)
                    .map_err(|_| internal("page range overflow"))?,
            }
            save_window(&tx, &key, &before, &after)?;
            let free = reclaim.finish(&tx, mode)?;
            check_memory_quota(&tx, mode, 0, 0)?;
            let entity = touch(&tx, &key, now)?;
            let entity = snapshots::finish_write(&tx, &key, entity, version, None)?;
            if let Some((id, data)) = staged {
                data.persist(mode, id)?;
            }
            tx.commit().map_err(db_error)?;
            discard(mode, &free);
            Ok(PageWritten { entity, sequence })
        })
        .await
    }

    /// Same-instance Copy Blob of a page or append blob (or of a snapshot or version
    /// of one): the destination shares the source's extents and keeps its type.
    /// Returns `None`, changing nothing, when the source is a block blob. `make`
    /// builds the destination write from the source.
    pub(crate) async fn copy_ranges<F>(
        &self,
        source: BlobKey,
        selector: Option<Selector>,
        source_guard: Guard,
        dest: BlobKey,
        make: F,
    ) -> Result<Option<Copied>>
    where
        F: FnOnce(&BlobInfo) -> BlobWrite + Send + 'static,
    {
        let hierarchical = self.hierarchical(&dest.container);
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            let (src, content) = snapshots::resolve_source(&tx, &source, selector, now).map_err(
                |error| match error {
                    Error::BlobMissing | Error::ContainerMissing => Error::CopySourceMissing,
                    other => other,
                },
            )?;
            if src.info.kind.is_block() {
                return Ok(None);
            }
            src.lease.check(
                source_guard.lease,
                LeaseNeed::Optional,
                LeaseOwner::Blob,
                now,
            )?;
            source_guard
                .conditions
                .check(Some(src.info.entity), false)
                .map_err(|error| match error {
                    Error::ConditionNotMet => Error::SourceConditionNotMet,
                    other => other,
                })?;
            container(&tx, &dest.container)?;
            let old = blob(&tx, &dest, now)?;
            let options = make(&src.info);
            guard_write(&options.guard, old.as_ref(), true, now)?;
            ensure_parents(&tx, &dest, hierarchical, now)?;
            let kind = match src.info.kind {
                BlobKind::Append { committed, .. } => BlobKind::Append {
                    committed,
                    sealed: false,
                },
                other => other,
            };
            check_tier(kind, options.tier)?;
            let rows = load_source_window(
                &tx,
                &source,
                content.into(),
                0,
                src.info.length.0,
                src.info.length.0,
            )?;
            let version = snapshots::begin_write(
                &tx,
                mode,
                &dest,
                old.as_ref(),
                snapshots::Change::Content,
                now,
            )?;
            let mut reclaim = Reclaim::default();
            reclaim.add_blob(&tx, &dest)?;
            let mut discard = remove_staged(&tx, &dest)?;
            let entity = save_row(&tx, &dest, &options, src.info.length, None, None, now)?;
            set_kind(&tx, &dest, kind)?;
            let entity = snapshots::finish_write(&tx, &dest, entity, version, Some(&options.tags))?;
            save_window(&tx, &dest, &RangeMap::new(src.info.length.0), &rows)?;
            discard.extend(reclaim.finish(&tx, mode)?);
            check_memory_quota(&tx, mode, 0, 0)?;
            tx.commit().map_err(db_error)?;
            if let Some(old) = old {
                super::reclaim(mode, old.info.entity.id);
            }
            self::discard(mode, &discard);
            let copy_id = options.copy.map(|copy| copy.id).unwrap_or_default();
            Ok(Some(Copied { entity, copy_id }))
        })
        .await
    }
}
