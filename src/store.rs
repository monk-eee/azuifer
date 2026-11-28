mod append;
mod blobs;
mod blocks;
mod containers;
mod copy;
mod deleted_containers;
mod dfs_acl;
mod dfs_data;
mod dfs_paths;
mod dfs_tree;
mod expiry;
mod immutability;
mod listing;
mod namespace;
mod page_history;
mod pages;
mod readers;
mod schema;
mod service;
mod snapshots;
mod tags;

use crate::blob_tags::Tags;
use crate::checksum::{Checksum, Checksums, Hasher};
use crate::clock::Clock;
use crate::domain::{
    BlobInfo, BlobKey, ContainerKey, ContentHeaders, ContentLength, CopyInfo, Entity, Error, Result,
};
use crate::extent_readers::Readers;
use crate::lease::{LeaseId, LeaseKind, StoredLease};
use crate::stamp::Ticks;
use anyhow::Context as _;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use readers::reclaim;
use rusqlite::{Connection, OptionalExtension as _, Row, params};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Seek as _, SeekFrom, Write},
    ops::Range,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt as _;
use uuid::Uuid;

pub(crate) use append::Appended;
pub(crate) use containers::LeaseResult;
pub(crate) use copy::SourceBytes;
pub(crate) use deleted_containers::ListedContainer;
pub(crate) use dfs_acl::{AclMode, RecursiveAcl, RecursiveOutcome};
pub(crate) use dfs_data::{Append, Flush, LeaseUse};
pub(crate) use dfs_paths::{
    AccessUpdate, Caller, CreatePath, Need, PathError, PathView, PropertyUpdate,
};
pub(crate) use dfs_tree::Rename;
pub(crate) use pages::{PageRanges, PageWritten, RangeBody};
pub(crate) use snapshots::{Deletion, ExtendedListing, Listed, Selected};
pub(crate) use tags::TaggedBlob;

#[derive(Clone)]
pub(crate) struct Store(Arc<Inner>);

struct Inner {
    db: Mutex<Connection>,
    mode: Mode,
    clock: Clock,
    hns_accounts: HashSet<crate::domain::AccountName>,
}

enum Mode {
    Disk {
        extents: PathBuf,
        _lock: File,
        /// Extents that snapshots, versions, or soft-deleted blobs still reference.
        pinned: snapshots::Pinned,
        /// Extents that downloads in flight still read.
        readers: Arc<Readers>,
    },
    Memory {
        limit: u64,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ContentSource {
    Blob,
    StagedBlock,
    /// Bytes held by a history row (`kind` and `state_id`); only the in-memory
    /// backend keeps block bytes in the row, and page ranges are found by the pair.
    History(i64, i64),
}

pub(crate) struct Upload {
    expected: ContentLength,
    received: u64,
    hash: Hasher,
    sink: Sink,
}

enum Sink {
    Disk(NamedTempFile, tokio::fs::File),
    Memory(Vec<u8>),
}

pub(crate) struct Uploaded {
    length: ContentLength,
    pub(crate) checksums: Checksums,
    data: UploadedData,
}

enum UploadedData {
    Disk(NamedTempFile),
    Memory(Vec<u8>),
}

pub(crate) enum Payload {
    Disk(File),
    Memory(Vec<u8>),
    /// Sparse content of a page or append blob: extent slices and zero-filled holes.
    Ranges(RangeBody),
}

pub(crate) struct Download {
    pub(crate) info: BlobInfo,
    pub(crate) range: Option<Range<u64>>,
    pub(crate) payload: Option<Payload>,
    /// Header name and Base64 value of the checksum of the returned range.
    pub(crate) range_checksum: Option<(&'static str, String)>,
}

pub(crate) enum PathRead {
    File(Box<Download>),
    /// A directory and its user-defined properties (Blob metadata).
    Directory(Entity, crate::domain::Metadata),
}

impl Store {
    pub(crate) fn open(
        location: Option<&Path>,
        memory_limit: u64,
        clock: Clock,
        hns_accounts: HashSet<crate::domain::AccountName>,
    ) -> anyhow::Result<Self> {
        let (mut db, mode) = if let Some(root) = location {
            fs::create_dir_all(root).context("could not create the storage directory")?;
            require_directory(root)?;
            let lock_path = root.join("azuifer.lock");
            require_file_if_present(&lock_path)?;
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)?;
            lock.try_lock()
                .context("the storage directory is already in use")?;
            let extents = root.join("content");
            fs::create_dir_all(&extents)?;
            require_directory(&extents)?;
            #[cfg(unix)]
            File::open(root)?.sync_all()?;
            for name in [
                "metadata.sqlite3",
                "metadata.sqlite3-wal",
                "metadata.sqlite3-shm",
            ] {
                require_file_if_present(&root.join(name))?;
            }
            let db = Connection::open(root.join("metadata.sqlite3"))
                .context("could not open metadata")?;
            let journal: String = db.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
            anyhow::ensure!(
                journal.eq_ignore_ascii_case("wal"),
                "storage does not support SQLite WAL"
            );
            db.pragma_update(None, "synchronous", "FULL")?;
            (
                db,
                Mode::Disk {
                    extents,
                    _lock: lock,
                    pinned: Default::default(),
                    readers: Default::default(),
                },
            )
        } else {
            (
                Connection::open_in_memory()?,
                Mode::Memory {
                    limit: memory_limit,
                },
            )
        };
        db.pragma_update(None, "foreign_keys", true)?;
        schema::migrate(&mut db).context("could not migrate metadata")?;
        namespace::restore_parents(&mut db, &hns_accounts, clock.now_millis())?;
        snapshots::load_pins(&db, &mode).context("could not load retained content")?;
        if let Mode::Disk { extents, .. } = &mode {
            recover(&db, extents).context("could not recover unreferenced content")?;
        }
        snapshots::purge_at_open(&db, &mode, clock.now_millis())
            .context("could not purge expired deleted content")?;
        Ok(Self(Arc::new(Inner {
            db: Mutex::new(db),
            mode,
            clock,
            hns_accounts,
        })))
    }

    fn hierarchical(&self, key: &ContainerKey) -> bool {
        self.0.hns_accounts.contains(&key.account)
    }

    /// Runs a metadata action on the blocking pool. The action receives the time
    /// read under the metadata lock, so lease evaluation matches the transaction.
    async fn run<T, F>(&self, action: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection, &Mode, i64) -> Result<T> + Send + 'static,
    {
        let inner = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = inner
                .db
                .lock()
                .map_err(|_| internal("poisoned metadata lock"))?;
            let now = inner.clock.now_millis();
            expiry::sweep(&mut db, &inner.mode, now)?;
            action(&mut db, &inner.mode, now)
        })
        .await
        .map_err(|_| internal("metadata operation did not complete"))?
    }

    pub(crate) async fn begin_upload(&self, length: ContentLength) -> Result<Upload> {
        let sink = match &self.0.mode {
            Mode::Disk { extents, .. } => {
                let path = extents.clone();
                let (temp, file) = tokio::task::spawn_blocking(move || {
                    let temp = staging_file(&path)?;
                    let file = temp.reopen()?;
                    Ok::<_, std::io::Error>((temp, file))
                })
                .await
                .map_err(|_| internal("could not start upload"))?
                .map_err(io_error)?;
                Sink::Disk(temp, tokio::fs::File::from_std(file))
            }
            Mode::Memory { limit } => {
                if length.0 > *limit {
                    return Err(Error::QuotaExceeded);
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
        if self.received > self.expected.0 {
            return Err(Error::InvalidLength);
        }
        self.hash.update(data);
        match &mut self.sink {
            Sink::Disk(_, file) => file.write_all(data).await.map_err(io_error)?,
            Sink::Memory(bytes) => bytes.extend_from_slice(data),
        }
        Ok(())
    }

    pub(crate) async fn finish(self, expected: Option<Checksum>) -> Result<Uploaded> {
        if self.received != self.expected.0 {
            return Err(Error::InvalidLength);
        }
        let checksums = self.hash.finish(expected)?;
        let data = match self.sink {
            Sink::Disk(temp, mut file) => {
                file.flush().await.map_err(io_error)?;
                drop(file);
                UploadedData::Disk(temp)
            }
            Sink::Memory(bytes) => UploadedData::Memory(bytes),
        };
        Ok(Uploaded {
            length: self.expected,
            checksums,
            data,
        })
    }
}

impl UploadedData {
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Memory(bytes) => Some(bytes),
            Self::Disk(_) => None,
        }
    }

    fn writer(&mut self) -> &mut dyn Write {
        match self {
            Self::Memory(bytes) => bytes,
            Self::Disk(file) => file.as_file_mut(),
        }
    }

    fn persist(self, mode: &Mode, id: Uuid) -> Result<()> {
        match (self, mode) {
            (Self::Disk(temp), Mode::Disk { extents, .. }) => {
                let committed = temp
                    .persist_noclobber(extent(extents, id))
                    .map_err(|error| io_error(error.error))?;
                committed.sync_all().map_err(io_error)?;
                #[cfg(unix)]
                File::open(extents)
                    .and_then(|directory| directory.sync_all())
                    .map_err(io_error)?;
                Ok(())
            }
            (Self::Memory(_), Mode::Memory { .. }) => Ok(()),
            _ => Err(internal("upload backend mismatch")),
        }
    }
}

fn staging_file(dir: &Path) -> std::io::Result<NamedTempFile> {
    tempfile::Builder::new()
        .prefix("incoming-")
        .tempfile_in(dir)
}

fn open_extent(dir: &Path, id: Uuid, length: u64, offset: u64) -> Result<File> {
    let path = extent(dir, id);
    require_file_if_present(&path).map_err(io_error)?;
    let mut file = File::open(path).map_err(io_error)?;
    if file.metadata().map_err(io_error)?.len() != length {
        return Err(internal("extent length does not match metadata"));
    }
    file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
    Ok(file)
}

fn read_memory_slice(
    db: &Connection,
    source: ContentSource,
    id: Uuid,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>> {
    // SQLite's substr returns NULL for an empty BLOB; the stored value is still a BLOB.
    let sql = match source {
        ContentSource::Blob => {
            "SELECT COALESCE(substr(bytes, ?2, ?3), bytes) FROM blobs WHERE id=?1"
        }
        ContentSource::StagedBlock => {
            "SELECT COALESCE(substr(bytes, ?2, ?3), bytes) FROM staged_blocks WHERE id=?1"
        }
        ContentSource::History(..) => {
            "SELECT COALESCE(substr(bytes, ?2, ?3), bytes) FROM blob_history
             WHERE content_id=?1 AND bytes IS NOT NULL LIMIT 1"
        }
    };
    let bytes: Vec<u8> = db
        .query_row(
            sql,
            params![id, sqlite_int(offset + 1)?, sqlite_int(length)?],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if bytes.len() as u64 != length {
        return Err(internal("in-memory content length does not match metadata"));
    }
    Ok(bytes)
}

fn blob_params(key: &BlobKey) -> [&str; 3] {
    [
        key.container.account.as_str(),
        key.container.name.as_str(),
        key.path.as_str(),
    ]
}

fn remove_staged(db: &Connection, key: &BlobKey) -> Result<Vec<Uuid>> {
    let mut query = db
        .prepare(
            "DELETE FROM staged_blocks WHERE account=?1 AND container=?2 AND name=?3 RETURNING id",
        )
        .map_err(db_error)?;
    query
        .query_map(blob_params(key), |row| row.get(0))
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)
}

fn check_memory_quota(db: &Connection, mode: &Mode, removed: u64, added: u64) -> Result<()> {
    if let Mode::Memory { limit } = mode {
        let stored = db.query_row(
            "SELECT (SELECT COALESCE(SUM(length),0) FROM blobs WHERE blob_type=0) + (SELECT COALESCE(SUM(length),0) FROM staged_blocks) + (SELECT COALESCE(SUM(length),0) FROM blob_extents)
                    + (SELECT COALESCE(SUM(length),0) FROM blob_history WHERE bytes IS NOT NULL)
                    + (SELECT COALESCE(SUM(length(bytes)),0) FROM dfs_staged_bytes)",
            [], |row| row_uint(row, 0),
        ).map_err(db_error)?;
        let remaining = stored
            .checked_sub(removed)
            .ok_or_else(|| internal("invalid memory quota accounting"))?;
        if remaining + added > *limit {
            return Err(Error::QuotaExceeded);
        }
    }
    Ok(())
}

const BLOB_COLUMNS: &str = "id, modified, COALESCE(etag, id), created, length, content_type, \
    content_encoding, content_language, content_disposition, cache_control, md5, metadata, \
    access_tier, access_tier_changed, lease_id, lease_state, lease_duration, lease_expiry, \
    copy_id, copy_source, copy_completed, blob_type, sequence_number, append_count, sealed";

/// The number of `BLOB_COLUMNS`; a query that selects more starts them at this index.
const BLOB_COLUMN_COUNT: usize = 25;

/// A blob row with its stored lease, for operations that must check or change it.
struct BlobRow {
    info: BlobInfo,
    lease: StoredLease,
}

/// Bytes ready to publish as a blob, with the digest computed while receiving them.
struct Content {
    length: ContentLength,
    data: UploadedData,
    computed_md5: Option<[u8; 16]>,
}

fn save_blob(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    options: &crate::domain::BlobWrite,
    content: Content,
    now: i64,
) -> Result<Entity> {
    let Content {
        length,
        data,
        computed_md5,
    } = content;
    crate::blob_page::check_tier(crate::blob_page::BlobKind::Block, options.tier)?;
    let entity = save_row(db, key, options, length, data.bytes(), computed_md5, now)?;
    data.persist(mode, entity.id)?;
    Ok(entity)
}

/// Publishes the blob row and resets its type to a block blob; page and append
/// callers set their type afterwards. Content persistence is the caller's job.
fn save_row(
    db: &Connection,
    key: &BlobKey,
    options: &crate::domain::BlobWrite,
    length: ContentLength,
    bytes: Option<&[u8]>,
    computed_md5: Option<[u8; 16]>,
    now: i64,
) -> Result<Entity> {
    let entity = new_entity(now)?;
    let metadata = serde_json::to_string(&options.metadata)
        .map_err(|_| internal("could not encode metadata"))?;
    let [account, container, name] = blob_params(key);
    let md5 = options.md5.or(computed_md5);
    let tier = options.tier.map_or("", |tier| tier.name());
    let (copy_id, copy_source, copy_completed) = options.copy.as_ref().map_or_else(
        || (String::new(), String::new(), 0),
        |copy| (copy.id.clone(), copy.source.clone(), entity.modified),
    );
    db.execute(
        "INSERT INTO blobs (account, container, name, id, etag, modified, created, length, \
            content_type, content_encoding, content_language, content_disposition, cache_control, \
            md5, metadata, bytes, access_tier, access_tier_changed, copy_id, copy_source, copy_completed)
         VALUES (?1,?2,?3,?4,?4,?5,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)
         ON CONFLICT(account,container,name) DO UPDATE SET
           id=excluded.id, etag=excluded.etag, modified=excluded.modified, created=excluded.created,
           length=excluded.length, content_type=excluded.content_type,
           content_encoding=excluded.content_encoding, content_language=excluded.content_language,
           content_disposition=excluded.content_disposition, cache_control=excluded.cache_control,
           md5=excluded.md5, metadata=excluded.metadata, bytes=excluded.bytes,
           access_tier=excluded.access_tier, access_tier_changed=excluded.access_tier_changed,
           copy_id=excluded.copy_id, copy_source=excluded.copy_source,
           copy_completed=excluded.copy_completed,
           blob_type=0, sequence_number=0, append_count=0, sealed=0",
        params![
            account,
            container,
            name,
            entity.id,
            sqlite_int(entity.modified)?,
            sqlite_int(length.0)?,
            options.headers.content_type,
            options.headers.encoding,
            options.headers.language,
            options.headers.disposition,
            options.headers.cache_control,
            md5.map_or_else(String::new, |md5| STANDARD.encode(md5)),
            metadata,
            bytes,
            tier,
            if options.tier.is_some() { sqlite_int(entity.modified)? } else { 0 },
            copy_id,
            copy_source,
            sqlite_int(copy_completed)?,
        ],
    )
    .map_err(db_error)?;
    db.execute(
        "DELETE FROM committed_blocks WHERE account=?1 AND container=?2 AND name=?3",
        blob_params(key),
    )
    .map_err(db_error)?;
    expiry::clear(db, key)?;
    Ok(entity)
}

fn container(db: &Connection, key: &ContainerKey) -> Result<Entity> {
    db.query_row(
        "SELECT id,modified,COALESCE(etag, id) FROM containers WHERE account=?1 AND name=?2",
        params![key.account.as_str(), key.name.as_str()],
        entity_row,
    )
    .optional()
    .map_err(db_error)?
    .ok_or(Error::ContainerMissing)
}

fn blob(db: &Connection, key: &BlobKey, now: i64) -> Result<Option<BlobRow>> {
    let row = db
        .query_row(
            &format!(
                "SELECT {BLOB_COLUMNS}, version_id FROM blobs
                 WHERE account=?1 AND container=?2 AND name=?3"
            ),
            params![
                key.container.account.as_str(),
                key.container.name.as_str(),
                key.path.as_str()
            ],
            |row| {
                let mut blob = blob_row(row, now)?;
                let version: i64 = row.get(BLOB_COLUMN_COUNT)?;
                blob.info.entity.version = (version != 0).then_some(Ticks(version));
                Ok(blob)
            },
        )
        .optional()
        .map_err(db_error)?;
    row.map(|row| tags::attach(db, key, row))
        .transpose()?
        .map(|row| expiry::attach(db, key, row))
        .transpose()
}

fn require_blob(db: &Connection, key: &BlobKey, now: i64) -> Result<BlobRow> {
    if let Some(blob) = blob(db, key, now)? {
        return Ok(blob);
    }
    container(db, &key.container)?;
    Err(Error::BlobMissing)
}

/// Reads `id, modified, etag` starting at column zero.
fn entity_row(row: &Row<'_>) -> rusqlite::Result<Entity> {
    Ok(Entity {
        id: row.get(0)?,
        modified: row_uint(row, 1)?,
        tag: row.get(2)?,
        version: None,
    })
}

fn row_uint(row: &Row<'_>, column: usize) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(column)?;
    value
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

fn sqlite_int(value: u64) -> Result<i64> {
    value
        .try_into()
        .map_err(|_| internal("number is outside the SQLite integer range"))
}

fn metadata_column(row: &Row<'_>, column: usize) -> rusqlite::Result<crate::domain::Metadata> {
    let json: String = row.get(column)?;
    serde_json::from_str(&json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

/// Reads the four lease columns starting at `first`.
fn lease_row(row: &Row<'_>, first: usize) -> rusqlite::Result<StoredLease> {
    let id: Option<String> = row.get(first)?;
    let id = id
        .map(|text| LeaseId::parse(&text))
        .transpose()
        .map_err(|_| {
            rusqlite::Error::InvalidColumnType(
                first,
                "lease_id".into(),
                rusqlite::types::Type::Text,
            )
        })?;
    Ok(StoredLease {
        id,
        kind: LeaseKind::from_code(row.get(first + 1)?),
        duration: row.get(first + 2)?,
        deadline: row.get(first + 3)?,
    })
}

fn blob_row(row: &Row<'_>, now: i64) -> rusqlite::Result<BlobRow> {
    let md5: String = row.get(10)?;
    let entity = entity_row(row)?;
    let created = row_uint(row, 3)?;
    let tier: String = row.get(12)?;
    let copy_id: String = row.get(18)?;
    let lease = lease_row(row, 14)?;
    Ok(BlobRow {
        info: BlobInfo {
            entity,
            created: if created == 0 {
                entity.modified
            } else {
                created
            },
            length: ContentLength(row_uint(row, 4)?),
            headers: ContentHeaders {
                content_type: row.get(5)?,
                encoding: row.get(6)?,
                language: row.get(7)?,
                disposition: row.get(8)?,
                cache_control: row.get(9)?,
            },
            md5: (!md5.is_empty()).then_some(md5),
            metadata: metadata_column(row, 11)?,
            tier: crate::domain::AccessTier::parse(&tier)
                .ok()
                .map(|tier| Ok::<_, rusqlite::Error>((tier, row_uint(row, 13)?)))
                .transpose()?,
            lease: lease.view(now),
            copy: if copy_id.is_empty() {
                None
            } else {
                Some(CopyInfo {
                    id: copy_id,
                    source: row.get(19)?,
                    completed: row_uint(row, 20)?,
                })
            },
            uncommitted: false,
            kind: crate::blob_page::BlobKind::from_stored(
                row.get(21)?,
                row.get(22)?,
                row.get(23)?,
                row.get(24)?,
            ),
            tags: Tags::new(),
            lifecycle: Default::default(),
        },
        lease,
    })
}

fn new_entity(now: i64) -> Result<Entity> {
    let id = Uuid::new_v4();
    Ok(Entity {
        id,
        tag: id,
        modified: seconds(now)?,
        version: None,
    })
}

fn seconds(now: i64) -> Result<u64> {
    u64::try_from(now / 1000).map_err(|_| internal("system clock predates the epoch"))
}

/// Persists a lease change on a blob or container row.
fn write_lease(db: &Connection, table: &str, key: &[&str], lease: &StoredLease) -> Result<()> {
    let sql = if table == "blobs" {
        "UPDATE blobs SET lease_id=?1, lease_state=?2, lease_duration=?3, lease_expiry=?4
         WHERE account=?5 AND container=?6 AND name=?7"
    } else {
        "UPDATE containers SET lease_id=?1, lease_state=?2, lease_duration=?3, lease_expiry=?4
         WHERE account=?5 AND name=?6"
    };
    let id = lease.id.map(LeaseId::text);
    let kind = lease.kind.code();
    let mut values: Vec<&dyn rusqlite::ToSql> = vec![&id, &kind, &lease.duration, &lease.deadline];
    values.extend(key.iter().map(|part| part as &dyn rusqlite::ToSql));
    db.execute(sql, values.as_slice()).map_err(db_error)?;
    Ok(())
}

fn extent(dir: &Path, id: Uuid) -> PathBuf {
    dir.join(format!("extent-{}", id.simple()))
}

fn recover(db: &Connection, dir: &Path) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let orphan = if name.starts_with("incoming-") {
            true
        } else if let Some(id) = name
            .strip_prefix("extent-")
            .and_then(|id| Uuid::parse_str(id).ok())
        {
            !db.query_row(
                "SELECT EXISTS(SELECT 1 FROM blobs WHERE id=?1 UNION ALL SELECT 1 FROM staged_blocks WHERE id=?1 UNION ALL SELECT 1 FROM blob_ranges WHERE extent=?1
                 UNION ALL SELECT 1 FROM dfs_staged WHERE extent=?1
                 UNION ALL SELECT 1 FROM history_ranges WHERE extent=?1
                 UNION ALL SELECT 1 FROM blob_history WHERE content_id=?1)",
                [id],
                |row| row.get::<_, bool>(0),
            )?
        } else {
            false
        };
        if orphan && entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn require_directory(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || is_link(&metadata) {
        return Err(std::io::Error::other("storage directory cannot be a link"));
    }
    Ok(())
}

fn require_file_if_present(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !is_link(&metadata) => Ok(()),
        Ok(_) => Err(std::io::Error::other("storage file must be a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    metadata.is_symlink()
}

fn db_error(error: rusqlite::Error) -> Error {
    tracing::error!(code = ?error.sqlite_error_code(), "metadata operation failed");
    Error::Internal
}

fn io_error(error: std::io::Error) -> Error {
    tracing::error!(kind = ?error.kind(), "content operation failed");
    Error::Internal
}

fn internal(reason: &'static str) -> Error {
    tracing::error!(reason, "storage operation failed");
    Error::Internal
}
