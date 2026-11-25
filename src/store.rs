use crate::domain::{
    AccountName, BlobInfo, BlobKey, ByteRange, Condition, ContainerKey, ContentLength, Entity,
    Error, Metadata, Page, PageRequest, Result,
};
use anyhow::Context as _;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use md5::{Digest as _, Md5};
use rusqlite::{Connection, OptionalExtension as _, Row, params};
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek as _, SeekFrom},
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

pub(crate) struct Upload {
    expected: ContentLength,
    received: u64,
    hash: Md5,
    sink: Sink,
}

enum Sink {
    Disk(NamedTempFile, tokio::fs::File),
    Memory(Vec<u8>),
}

pub(crate) struct Uploaded {
    length: ContentLength,
    md5: String,
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

pub(crate) struct Put {
    pub(crate) key: BlobKey,
    pub(crate) condition: Condition,
    pub(crate) content_type: String,
    pub(crate) metadata: Metadata,
    pub(crate) upload: Uploaded,
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
                    let temp = tempfile::Builder::new()
                        .prefix("incoming-")
                        .tempfile_in(path)?;
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
            hash: Md5::new(),
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
                    .prepare("SELECT id FROM blobs WHERE account=?1 AND container=?2")
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

    pub(crate) async fn put_blob(&self, put: Put) -> Result<Entity> {
        self.run(move |db, mode| {
            let tx = db.transaction().map_err(db_error)?;
            container(&tx, &put.key.container)?;
            let old = blob(&tx, &put.key)?;
            put.condition.check(old.as_ref().map(|b| b.entity), false)?;
            let entity = new_entity()?;
            let metadata = serde_json::to_string(&put.metadata).map_err(|_| internal("could not encode metadata"))?;
            let bytes = match (&put.upload.data, mode) {
                (UploadedData::Memory(bytes), Mode::Memory { limit }) => {
                    let stored = tx.query_row("SELECT COALESCE(SUM(length), 0) FROM blobs", [], |row| row_uint(row, 0)).map_err(db_error)?;
                    let previous = old.as_ref().map_or(0, |blob| blob.length.0);
                    let remaining = stored.checked_sub(previous).ok_or_else(|| internal("invalid memory quota accounting"))?;
                    if remaining + put.upload.length.0 > *limit {
                        return Err(Error::QuotaExceeded);
                    }
                    Some(bytes.as_slice())
                }
                (UploadedData::Disk(_), Mode::Disk { .. }) => None,
                _ => return Err(internal("upload backend mismatch")),
            };
            tx.execute(
                "INSERT INTO blobs VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
                 ON CONFLICT(account,container,name) DO UPDATE SET
                    id=excluded.id, modified=excluded.modified, length=excluded.length,
                    content_type=excluded.content_type, md5=excluded.md5, metadata=excluded.metadata, bytes=excluded.bytes",
                params![put.key.container.account.as_str(), put.key.container.name.as_str(), put.key.path.as_str(),
                        entity.id, sqlite_int(entity.modified)?, sqlite_int(put.upload.length.0)?,
                        put.content_type, put.upload.md5, metadata, bytes],
            ).map_err(db_error)?;
            if let (UploadedData::Disk(temp), Mode::Disk { extents, .. }) = (put.upload.data, mode) {
                let committed = temp.persist_noclobber(extent(extents, entity.id)).map_err(|error| io_error(error.error))?;
                committed.sync_all().map_err(io_error)?;
                #[cfg(unix)]
                File::open(extents).and_then(|directory| directory.sync_all()).map_err(io_error)?;
            }
            tx.commit().map_err(db_error)?;
            if let Some(old) = old {
                reclaim(mode, old.entity.id);
            }
            Ok(entity)
        }).await
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
                    Mode::Disk { extents, .. } => {
                        let path = extent(extents, info.entity.id);
                        require_file_if_present(&path).map_err(io_error)?;
                        let mut file = File::open(path).map_err(io_error)?;
                        if file.metadata().map_err(io_error)?.len() != info.length.0 {
                            return Err(internal("extent length does not match metadata"));
                        }
                        file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
                        Some(Payload::Disk(file))
                    }
                    Mode::Memory { .. } => {
                        let size = range
                            .as_ref()
                            .map_or(info.length.0, |range| range.end - range.start);
                        let bytes = db
                            .query_row(
                                "SELECT substr(bytes, ?2, ?3) FROM blobs WHERE id=?1",
                                params![info.entity.id, sqlite_int(offset + 1)?, sqlite_int(size)?],
                                |row| row.get::<_, Vec<u8>>(0),
                            )
                            .map_err(db_error)?;
                        if bytes.len() as u64 != size {
                            return Err(internal(
                                "in-memory content length does not match metadata",
                            ));
                        }
                        Some(Payload::Memory(bytes))
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
            tx.execute("DELETE FROM blobs WHERE id=?1", [old.entity.id])
                .map_err(db_error)?;
            tx.commit().map_err(db_error)?;
            reclaim(mode, old.entity.id);
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

    pub(crate) async fn finish(self, expected_md5: Option<[u8; 16]>) -> Result<Uploaded> {
        if self.received != self.expected.0 {
            return Err(Error::InvalidLength);
        }
        let md5: [u8; 16] = self.hash.finalize().into();
        if expected_md5.is_some_and(|expected| expected != md5) {
            return Err(Error::Md5Mismatch);
        }
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
            md5: STANDARD.encode(md5),
            data,
        })
    }
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
    Ok(BlobInfo {
        entity: entity_row(row)?,
        length: ContentLength(row_uint(row, 2)?),
        content_type: row.get(3)?,
        md5: row.get(4)?,
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
                "SELECT EXISTS(SELECT 1 FROM blobs WHERE id=?1)",
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
