mod blocks;

use crate::checksum::{Checksum, Checksums, Hasher};
use crate::domain::{
    AccountName, BlobInfo, BlobKey, BlobWrite, ByteRange, Condition, ContainerKey, ContentLength,
    Entity, Error, Page, PageRequest, Result,
};
use anyhow::Context as _;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rusqlite::{Connection, OptionalExtension as _, Row, params};
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek as _, SeekFrom, Write},
    ops::Range,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt as _;
use uuid::Uuid;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS containers (
    account TEXT NOT NULL, name TEXT NOT NULL, id BLOB NOT NULL, modified INTEGER NOT NULL,
    PRIMARY KEY (account, name)
) STRICT;
CREATE TABLE IF NOT EXISTS blobs (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    id BLOB NOT NULL UNIQUE, modified INTEGER NOT NULL, length INTEGER NOT NULL,
    content_type TEXT NOT NULL, md5 TEXT NOT NULL, metadata TEXT NOT NULL, bytes BLOB,
    PRIMARY KEY (account, container, name),
    FOREIGN KEY (account, container) REFERENCES containers (account, name) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS staged_blocks (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    block_id TEXT NOT NULL, width INTEGER NOT NULL,
    id BLOB NOT NULL UNIQUE, length INTEGER NOT NULL, bytes BLOB,
    PRIMARY KEY (account, container, name, block_id),
    FOREIGN KEY (account, container) REFERENCES containers (account, name) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS committed_blocks (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    position INTEGER NOT NULL, block_id TEXT NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL,
    PRIMARY KEY (account, container, name, position),
    FOREIGN KEY (account, container, name) REFERENCES blobs (account, container, name) ON DELETE CASCADE
) STRICT;";

#[derive(Clone)]
pub(crate) struct Store(Arc<Inner>);

struct Inner {
    db: Mutex<Connection>,
    mode: Mode,
}

enum Mode {
    Disk { extents: PathBuf, _lock: File },
    Memory { limit: u64 },
}

#[derive(Clone, Copy)]
enum ContentSource {
    Blob,
    StagedBlock,
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
}

pub(crate) struct Download {
    pub(crate) info: BlobInfo,
    pub(crate) range: Option<Range<u64>>,
    pub(crate) payload: Option<Payload>,
}

impl Store {
    pub(crate) fn open(location: Option<&Path>, memory_limit: u64) -> anyhow::Result<Self> {
        let (db, mode) = if let Some(root) = location {
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
        db.execute_batch(SCHEMA)?;
        if let Mode::Disk { extents, .. } = &mode {
            recover(&db, extents).context("could not recover unreferenced content")?;
        }
        Ok(Self(Arc::new(Inner {
            db: Mutex::new(db),
            mode,
        })))
    }

    async fn run<T, F>(&self, action: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection, &Mode) -> Result<T> + Send + 'static,
    {
        let inner = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = inner
                .db
                .lock()
                .map_err(|_| internal("poisoned metadata lock"))?;
            action(&mut db, &inner.mode)
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

    pub(crate) async fn create_container(&self, key: ContainerKey) -> Result<Entity> {
        self.run(move |db, _| {
            let entity = new_entity()?;
            let changed = db.execute(
                "INSERT INTO containers VALUES (?1, ?2, ?3, ?4) ON CONFLICT(account, name) DO NOTHING",
                params![key.account.as_str(), key.name.as_str(), entity.id, sqlite_int(entity.modified)?],
            ).map_err(db_error)?;
            if changed == 0 {
                return Err(Error::ContainerExists);
            }
            Ok(entity)
        }).await
    }

    pub(crate) async fn container(&self, key: ContainerKey) -> Result<Entity> {
        self.run(move |db, _| container(db, &key)).await
    }

    pub(crate) async fn delete_container(&self, key: ContainerKey) -> Result<()> {
        self.run(move |db, mode| {
            let tx = db.transaction().map_err(db_error)?;
            let values = params![key.account.as_str(), key.name.as_str()];
            let ids = if matches!(mode, Mode::Disk { .. }) {
                let mut statement = tx
                    .prepare("SELECT id FROM blobs WHERE account=?1 AND container=?2
                              UNION ALL SELECT id FROM staged_blocks WHERE account=?1 AND container=?2")
                    .map_err(db_error)?;
                statement
                    .query_map(values, |row| row.get::<_, Uuid>(0))
                    .map_err(db_error)?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(db_error)?
            } else {
                Vec::new()
            };
            if tx
                .execute(
                    "DELETE FROM containers WHERE account=?1 AND name=?2",
                    values,
                )
                .map_err(db_error)?
                == 0
            {
                return Err(Error::ContainerMissing);
            }
            tx.commit().map_err(db_error)?;
            for id in ids {
                reclaim(mode, id);
            }
            Ok(())
        })
        .await
    }

    pub(crate) async fn list_containers(
        &self,
        account: AccountName,
        page: PageRequest,
    ) -> Result<Page<Entity>> {
        self.run(move |db, _| {
            let mut query = db
                .prepare(
                    "SELECT id, modified, name FROM containers
                 WHERE account=?1 AND name>?2 AND instr(name, ?3)=1 ORDER BY name LIMIT ?4",
                )
                .map_err(db_error)?;
            let rows = query
                .query_map(
                    params![account.as_str(), page.after, page.prefix, page.limit + 1],
                    |row| Ok((row.get(2)?, entity_row(row)?)),
                )
                .map_err(db_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db_error)?;
            Ok(Page::from_rows(rows, page.limit))
        })
        .await
    }

    pub(crate) async fn list_blobs(
        &self,
        key: ContainerKey,
        page: PageRequest,
    ) -> Result<Page<BlobInfo>> {
        self.run(move |db, _| {
            container(db, &key)?;
            let mut query = db.prepare(
                "SELECT id, modified, length, content_type, md5, metadata, name FROM blobs
                 WHERE account=?1 AND container=?2 AND name>?3 AND instr(name, ?4)=1 ORDER BY name LIMIT ?5"
            ).map_err(db_error)?;
            let rows = query.query_map(
                params![key.account.as_str(), key.name.as_str(), page.after, page.prefix, page.limit + 1],
                |row| Ok((row.get(6)?, blob_row(row)?)),
            ).map_err(db_error)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)?;
            Ok(Page::from_rows(rows, page.limit))
        }).await
    }

    pub(crate) async fn put_blob(
        &self,
        key: BlobKey,
        options: BlobWrite,
        upload: Uploaded,
    ) -> Result<Entity> {
        self.run(move |db, mode| {
            let tx = db.transaction().map_err(db_error)?;
            container(&tx, &key.container)?;
            let old = blob(&tx, &key)?;
            options
                .condition
                .check(old.as_ref().map(|b| b.entity), false)?;
            let discard = remove_staged(&tx, &key)?;
            check_memory_quota(
                &tx,
                mode,
                old.as_ref().map_or(0, |blob| blob.length.0),
                upload.length.0,
            )?;
            let entity = save_blob(
                &tx,
                mode,
                &key,
                &options,
                upload.length,
                upload.data,
                Some(upload.checksums.md5),
            )?;
            tx.commit().map_err(db_error)?;
            if let Some(old) = old {
                reclaim(mode, old.entity.id);
            }
            for id in discard {
                reclaim(mode, id);
            }
            Ok(entity)
        })
        .await
    }

    pub(crate) async fn read_blob(
        &self,
        key: BlobKey,
        condition: Condition,
        range: Option<ByteRange>,
        with_body: bool,
    ) -> Result<Download> {
        self.run(move |db, mode| {
            let info = require_blob(db, &key)?;
            condition.check(Some(info.entity), true)?;
            let range = range.map(|range| range.resolve(info.length)).transpose()?;
            let payload = if with_body {
                let offset = range.as_ref().map_or(0, |range| range.start);
                match mode {
                    Mode::Disk { extents, .. } => Some(Payload::Disk(open_extent(
                        extents,
                        info.entity.id,
                        info.length.0,
                        offset,
                    )?)),
                    Mode::Memory { .. } => {
                        let size = range
                            .as_ref()
                            .map_or(info.length.0, |range| range.end - range.start);
                        Some(Payload::Memory(read_memory_slice(
                            db,
                            ContentSource::Blob,
                            info.entity.id,
                            offset,
                            size,
                        )?))
                    }
                }
            } else {
                None
            };
            Ok(Download {
                info,
                range,
                payload,
            })
        })
        .await
    }

    pub(crate) async fn delete_blob(&self, key: BlobKey, condition: Condition) -> Result<()> {
        self.run(move |db, mode| {
            let tx = db.transaction().map_err(db_error)?;
            let old = require_blob(&tx, &key)?;
            condition.check(Some(old.entity), false)?;
            let discard = remove_staged(&tx, &key)?;
            tx.execute("DELETE FROM blobs WHERE id=?1", [old.entity.id])
                .map_err(db_error)?;
            tx.commit().map_err(db_error)?;
            reclaim(mode, old.entity.id);
            for id in discard {
                reclaim(mode, id);
            }
            Ok(())
        })
        .await
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
            "SELECT (SELECT COALESCE(SUM(length),0) FROM blobs) + (SELECT COALESCE(SUM(length),0) FROM staged_blocks)",
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

fn save_blob(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    options: &BlobWrite,
    length: ContentLength,
    data: UploadedData,
    md5: Option<[u8; 16]>,
) -> Result<Entity> {
    let entity = new_entity()?;
    let metadata = serde_json::to_string(&options.metadata)
        .map_err(|_| internal("could not encode metadata"))?;
    let [account, container, name] = blob_params(key);
    db.execute(
        "INSERT INTO blobs VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
         ON CONFLICT(account,container,name) DO UPDATE SET
           id=excluded.id, modified=excluded.modified, length=excluded.length,
           content_type=excluded.content_type, md5=excluded.md5, metadata=excluded.metadata, bytes=excluded.bytes",
        params![account, container, name, entity.id, sqlite_int(entity.modified)?, sqlite_int(length.0)?,
                options.content_type, md5.map_or_else(String::new, |md5| STANDARD.encode(md5)), metadata, data.bytes()],
    ).map_err(db_error)?;
    db.execute(
        "DELETE FROM committed_blocks WHERE account=?1 AND container=?2 AND name=?3",
        blob_params(key),
    )
    .map_err(db_error)?;
    data.persist(mode, entity.id)?;
    Ok(entity)
}

fn container(db: &Connection, key: &ContainerKey) -> Result<Entity> {
    db.query_row(
        "SELECT id,modified FROM containers WHERE account=?1 AND name=?2",
        params![key.account.as_str(), key.name.as_str()],
        entity_row,
    )
    .optional()
    .map_err(db_error)?
    .ok_or(Error::ContainerMissing)
}

fn blob(db: &Connection, key: &BlobKey) -> Result<Option<BlobInfo>> {
    db.query_row(
        "SELECT id,modified,length,content_type,md5,metadata FROM blobs WHERE account=?1 AND container=?2 AND name=?3",
        params![key.container.account.as_str(), key.container.name.as_str(), key.path.as_str()], blob_row,
    ).optional().map_err(db_error)
}

fn require_blob(db: &Connection, key: &BlobKey) -> Result<BlobInfo> {
    if let Some(blob) = blob(db, key)? {
        return Ok(blob);
    }
    container(db, &key.container)?;
    Err(Error::BlobMissing)
}

fn entity_row(row: &Row<'_>) -> rusqlite::Result<Entity> {
    Ok(Entity {
        id: row.get(0)?,
        modified: row_uint(row, 1)?,
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

fn blob_row(row: &Row<'_>) -> rusqlite::Result<BlobInfo> {
    let json: String = row.get(5)?;
    let metadata = serde_json::from_str(&json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let md5: String = row.get(4)?;
    Ok(BlobInfo {
        entity: entity_row(row)?,
        length: ContentLength(row_uint(row, 2)?),
        content_type: row.get(3)?,
        md5: (!md5.is_empty()).then_some(md5),
        metadata,
    })
}

fn new_entity() -> Result<Entity> {
    let modified = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| internal("system clock predates the epoch"))?
        .as_secs();
    Ok(Entity {
        id: Uuid::new_v4(),
        modified,
    })
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
                "SELECT EXISTS(SELECT 1 FROM blobs WHERE id=?1 UNION ALL SELECT 1 FROM staged_blocks WHERE id=?1)",
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

fn reclaim(mode: &Mode, id: Uuid) {
    if let Mode::Disk { extents, .. } = mode
        && let Err(error) = fs::remove_file(extent(extents, id))
    {
        tracing::warn!(kind = ?error.kind(), "content cleanup deferred until recovery");
    }
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
