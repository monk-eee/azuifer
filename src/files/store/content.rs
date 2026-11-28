//! Immutable content extents, staging, range-map persistence, and reclamation.

use super::{Env, Mode, Store, db_error, from_sql, internal, io_error, to_sql};
use crate::{
    checksum::{Checksum, Checksums, Hasher},
    extent_readers::{ExtentSlice, Piece, ReadBody},
    files::error::{Error, Result},
    ranges::{Mapping, RangeMap, Segment},
};
use axum::body::Bytes;
use futures_util::stream::BoxStream;
use rusqlite::{Connection, params};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt as _;
use uuid::Uuid;

/// A request body being streamed into staging.
pub(crate) struct Upload {
    expected: u64,
    received: u64,
    hash: Hasher,
    sink: Sink,
}

enum Sink {
    Disk(NamedTempFile, tokio::fs::File),
    Memory(Vec<u8>),
}

/// A fully received, checksum-verified body that is not yet an extent.
pub(crate) struct Staged {
    pub(crate) length: u64,
    pub(crate) checksums: Checksums,
    data: Data,
}

enum Data {
    Disk(NamedTempFile),
    Memory(Vec<u8>),
}

impl Store {
    pub(crate) async fn begin_upload(&self, length: u64) -> Result<Upload> {
        let sink = match &self.0.env.mode {
            Mode::Disk { extents, .. } => {
                let dir = extents.clone();
                let (temp, file) = tokio::task::spawn_blocking(move || {
                    let temp = tempfile::Builder::new()
                        .prefix("incoming-")
                        .tempfile_in(dir)?;
                    let file = temp.reopen()?;
                    Ok::<_, std::io::Error>((temp, file))
                })
                .await
                .map_err(|_| internal("could not start upload"))?
                .map_err(io_error)?;
                Sink::Disk(temp, tokio::fs::File::from_std(file))
            }
            Mode::Memory { limit } => {
                if length > *limit {
                    return Err(Error::InsufficientStorage);
                }
                Sink::Memory(Vec::new())
            }
        };
        Ok(Upload {
            expected: length,
            received: 0,
            hash: Hasher::new(),
            sink,
        })
    }
}

impl Upload {
    pub(crate) async fn append(&mut self, data: &[u8]) -> Result<()> {
        self.received += data.len() as u64;
        if self.received > self.expected {
            return Err(Error::InvalidInput);
        }
        self.hash.update(data);
        match &mut self.sink {
            Sink::Disk(_, file) => file.write_all(data).await.map_err(io_error)?,
            Sink::Memory(bytes) => bytes.extend_from_slice(data),
        }
        Ok(())
    }

    /// Verifies the length and the client's checksum, if it sent one.
    pub(crate) async fn finish(self, expected: Option<Checksum>) -> Result<Staged> {
        if self.received != self.expected {
            return Err(Error::InvalidInput);
        }
        let checksums = self.hash.finish(expected).map_err(|error| match error {
            crate::domain::Error::Md5Mismatch => Error::Md5Mismatch,
            crate::domain::Error::Crc64Mismatch => Error::Crc64Mismatch,
            _ => Error::Internal,
        })?;
        let data = match self.sink {
            Sink::Disk(temp, mut file) => {
                file.flush().await.map_err(io_error)?;
                drop(file);
                Data::Disk(temp)
            }
            Sink::Memory(bytes) => Data::Memory(bytes),
        };
        Ok(Staged {
            length: self.expected,
            checksums,
            data,
        })
    }
}

impl Staged {
    /// Makes the bytes a durable, reopenable extent named `id` (ADR-0004). On disk the file
    /// is synced and its directory entry is flushed before the caller commits metadata.
    pub(super) fn publish(self, db: &Connection, mode: &Mode, id: &str) -> Result<()> {
        match (self.data, mode) {
            (Data::Disk(temp), Mode::Disk { extents, .. }) => {
                let committed = temp
                    .persist_noclobber(extent_path(extents, id))
                    .map_err(|error| io_error(error.error))?;
                committed.sync_all().map_err(io_error)?;
                crate::store::guard::sync_directory(extents).map_err(io_error)
            }
            (Data::Memory(bytes), Mode::Memory { .. }) => db
                .execute(
                    "INSERT INTO extents (id, length, bytes) VALUES (?1, ?2, ?3)",
                    params![id, to_sql(self.length)?, bytes],
                )
                .map(drop)
                .map_err(db_error),
            _ => Err(internal("upload backend mismatch")),
        }
    }
}

pub(super) fn new_extent_id() -> String {
    Uuid::new_v4().simple().to_string()
}

fn extent_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("extent-{id}"))
}

/// Fails with `InsufficientStorage` when in-memory extents exceed the configured limit.
pub(super) fn check_memory_quota(db: &Connection, mode: &Mode) -> Result<()> {
    if let Mode::Memory { limit } = mode {
        let stored: i64 = db
            .query_row("SELECT COALESCE(SUM(length), 0) FROM extents", [], |row| {
                row.get(0)
            })
            .map_err(db_error)?;
        if from_sql(stored)? > *limit {
            return Err(Error::InsufficientStorage);
        }
    }
    Ok(())
}

pub(super) fn load_map(
    db: &Connection,
    share_id: i64,
    file_id: i64,
    length: u64,
) -> Result<RangeMap<String>> {
    let mut query = db
        .prepare_cached(
            "SELECT offset, length, extent, extent_offset FROM ranges
             WHERE share_id=?1 AND file_id=?2 ORDER BY offset",
        )
        .map_err(db_error)?;
    let rows = query
        .query_map(params![share_id, file_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(db_error)?;
    let mut mappings = Vec::new();
    for row in rows {
        let (offset, mapping_length, extent, extent_offset) = row.map_err(db_error)?;
        mappings.push((
            from_sql(offset)?,
            Mapping {
                extent,
                extent_offset: from_sql(extent_offset)?,
                length: from_sql(mapping_length)?,
            },
        ));
    }
    RangeMap::from_mappings(length, mappings)
        .map_err(|_| internal("stored ranges are inconsistent"))
}

/// Applies the difference between two maps of one file as row changes.
pub(super) fn save_map(
    db: &Connection,
    share_id: i64,
    file_id: i64,
    old: &RangeMap<String>,
    new: &RangeMap<String>,
) -> Result<()> {
    let old_rows: BTreeMap<u64, &Mapping<String>> = old.mappings().collect();
    let new_rows: BTreeMap<u64, &Mapping<String>> = new.mappings().collect();
    let mut delete = db
        .prepare_cached("DELETE FROM ranges WHERE share_id=?1 AND file_id=?2 AND offset=?3")
        .map_err(db_error)?;
    for (offset, mapping) in &old_rows {
        if new_rows.get(offset) != Some(mapping) {
            delete
                .execute(params![share_id, file_id, to_sql(*offset)?])
                .map_err(db_error)?;
        }
    }
    let mut insert = db
        .prepare_cached(
            "INSERT INTO ranges (share_id, file_id, offset, length, extent, extent_offset)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .map_err(db_error)?;
    for (offset, mapping) in &new_rows {
        if old_rows.get(offset) != Some(mapping) {
            insert
                .execute(params![
                    share_id,
                    file_id,
                    to_sql(*offset)?,
                    to_sql(mapping.length)?,
                    mapping.extent,
                    to_sql(mapping.extent_offset)?
                ])
                .map_err(db_error)?;
        }
    }
    Ok(())
}

/// Extents that lost a reference inside a transaction. After the row changes, those with no
/// remaining reference anywhere (any file, any snapshot) are collectable.
#[derive(Default)]
pub(super) struct Reclaim(BTreeSet<String>);

impl Reclaim {
    pub(super) fn add_map(&mut self, map: &RangeMap<String>) {
        self.0.extend(map.extents().cloned());
    }

    /// Notes every extent of one file, or of a whole share when `file_id` is `None`, before
    /// its rows are deleted.
    pub(super) fn add_stored(
        &mut self,
        db: &Connection,
        share_id: i64,
        file_id: Option<i64>,
    ) -> Result<()> {
        let mut query = db
            .prepare_cached(
                "SELECT DISTINCT extent FROM ranges
                 WHERE share_id=?1 AND (?2 IS NULL OR file_id=?2)",
            )
            .map_err(db_error)?;
        let rows = query
            .query_map(params![share_id, file_id], |row| row.get::<_, String>(0))
            .map_err(db_error)?;
        for row in rows {
            self.0.insert(row.map_err(db_error)?);
        }
        Ok(())
    }

    /// Returns the unreferenced extents; in memory mode their bytes are removed here, in the
    /// same transaction, so the quota check sees the freed space.
    pub(super) fn finish(self, db: &Connection, mode: &Mode) -> Result<Vec<String>> {
        let mut free = Vec::new();
        for id in self.0 {
            let referenced: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM ranges WHERE extent=?1)",
                    [&id],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if !referenced {
                if matches!(mode, Mode::Memory { .. }) {
                    db.execute("DELETE FROM extents WHERE id=?1", [&id])
                        .map_err(db_error)?;
                }
                free.push(id);
            }
        }
        Ok(free)
    }
}

/// Retires unreferenced extents after commit; in-flight downloads keep their pins.
pub(super) fn discard(env: &Env, ids: &[String]) {
    if let Mode::Disk {
        extents, readers, ..
    } = &env.mode
    {
        for id in ids {
            readers.reclaim(&extent_path(extents, id));
        }
    }
}

/// Startup recovery: drops abandoned staging files and extents no range references.
pub(super) fn recover(db: &Connection, dir: &Path) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let orphan = if name.starts_with("incoming-") {
            true
        } else if let Some(id) = name.strip_prefix("extent-") {
            !db.query_row(
                "SELECT EXISTS(SELECT 1 FROM ranges WHERE extent=?1)",
                [id],
                |row| row.get::<_, bool>(0),
            )?
        } else {
            false
        };
        if orphan && entry.file_type()?.is_file() {
            let bytes = entry.metadata()?.len();
            std::fs::remove_file(entry.path())?;
            crate::runtime_metrics::removed(crate::runtime_metrics::Removal::Recovered, bytes);
        }
    }
    Ok(())
}

/// The bytes of a read: extent slices and zero-filled holes, streamed in order.
pub(crate) struct FileBody(ReadBody);

impl FileBody {
    pub(crate) fn empty() -> Self {
        Self(ReadBody::default())
    }

    /// Resolves `[offset, offset + length)` of a file's map into readable pieces.
    pub(super) fn open(
        db: &Connection,
        env: &Env,
        map: &RangeMap<String>,
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
                    extent,
                    extent_offset,
                    length,
                    ..
                } => match &env.mode {
                    Mode::Disk { extents, .. } => {
                        let path = extent_path(extents, &extent);
                        crate::store::guard::require_file_if_present(&path).map_err(io_error)?;
                        let size = std::fs::metadata(&path).map_err(io_error)?.len();
                        if size < extent_offset + length {
                            return Err(internal("extent is shorter than its range"));
                        }
                        Piece::Disk(ExtentSlice {
                            path: Arc::from(path),
                            offset: extent_offset,
                            length,
                        })
                    }
                    Mode::Memory { .. } => {
                        let bytes: Vec<u8> = db
                            .query_row(
                                "SELECT substr(bytes, ?2, ?3) FROM extents WHERE id=?1",
                                params![extent, to_sql(extent_offset + 1)?, to_sql(length)?],
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
        let readers = match &env.mode {
            Mode::Disk { readers, .. } => Some(readers),
            Mode::Memory { .. } => None,
        };
        Ok(Self(ReadBody::new(pieces, readers)))
    }

    /// Reads everything into memory; callers bound the size (MD5 of a ranged read).
    pub(super) fn into_vec(self) -> Result<Vec<u8>> {
        self.0.into_vec().map_err(io_error)
    }

    pub(super) fn from_vec(bytes: Vec<u8>) -> Self {
        Self(ReadBody::new(vec![Piece::Memory(bytes)], None))
    }

    pub(crate) fn into_stream(self) -> BoxStream<'static, std::io::Result<Bytes>> {
        self.0.into_stream()
    }
}
