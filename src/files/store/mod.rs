//! FileREST persistence: SQLite metadata plus immutable content extents (ADR-0004, ADR-0010,
//! ADR-0015, ADR-0016).
//!
//! Shares, directories, and files are rows with parent references, so a directory rename is
//! one row update. File content is a range map of immutable extents; every Put Range writes
//! a new extent, makes it durable, then commits the map change in one transaction. A share
//! snapshot copies the share's rows, which share extents with the live share.

mod content;
mod fs;
mod nodes;
mod shares;
mod soft_delete;
#[cfg(test)]
mod tests;

pub(crate) use nodes::{
    CopyBy, CopyRequest, CopySource, FilePatch, Listing, NewFile, NfsCopy, ReadOptions, ReadRange,
    RenameFlags, Want,
};
pub(crate) use shares::{
    LeaseRequest, ListSharesRequest, NfsShareSettings, ShareOptions, ShareRef, SnapshotPolicy,
};

use super::{
    error::{Error, Result},
    lease::Lease,
    model::{
        Attributes, CopyState, FileKind, HttpProperties, NfsProps, NodeInfo, Protocol, RootSquash,
        ShareInfo,
    },
    name::EntryPath,
};
use crate::{clock::Clock, extent_readers::Readers};
use anyhow::Context as _;
use rusqlite::{Connection, OptionalExtension as _, Row, params};
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS shares (
    id INTEGER PRIMARY KEY, account TEXT NOT NULL, name TEXT NOT NULL, snapshot INTEGER NOT NULL,
    etag TEXT NOT NULL, modified INTEGER NOT NULL, quota INTEGER NOT NULL,
    access_tier TEXT NOT NULL, access_tier_changed INTEGER NOT NULL,
    metadata TEXT NOT NULL, acl TEXT NOT NULL, lease TEXT, next_file_id INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'SMB', root_squash TEXT,
    snapshot_vda INTEGER NOT NULL DEFAULT 1,
    UNIQUE (account, name, snapshot)
) STRICT;
CREATE TABLE IF NOT EXISTS nodes (
    share_id INTEGER NOT NULL REFERENCES shares (id) ON DELETE CASCADE,
    file_id INTEGER NOT NULL, parent_id INTEGER, name TEXT NOT NULL, key TEXT NOT NULL,
    is_dir INTEGER NOT NULL, etag TEXT NOT NULL, modified INTEGER NOT NULL,
    attributes INTEGER NOT NULL, creation INTEGER NOT NULL, last_write INTEGER NOT NULL,
    change_time INTEGER NOT NULL, permission_key TEXT NOT NULL, metadata TEXT NOT NULL,
    length INTEGER NOT NULL, content_type TEXT NOT NULL, content_encoding TEXT,
    content_language TEXT, content_disposition TEXT, cache_control TEXT, md5 TEXT,
    lease TEXT, copy TEXT,
    mode INTEGER, owner INTEGER, grp INTEGER, file_type TEXT NOT NULL DEFAULT '',
    link_text TEXT,
    PRIMARY KEY (share_id, file_id),
    UNIQUE (share_id, parent_id, key)
) STRICT;
CREATE INDEX IF NOT EXISTS nodes_by_parent ON nodes (share_id, parent_id, key);
CREATE TABLE IF NOT EXISTS links (
    share_id INTEGER NOT NULL, entry_id INTEGER NOT NULL, file_id INTEGER NOT NULL,
    parent_id INTEGER NOT NULL, name TEXT NOT NULL, key TEXT NOT NULL,
    PRIMARY KEY (share_id, entry_id),
    UNIQUE (share_id, parent_id, key),
    FOREIGN KEY (share_id, file_id) REFERENCES nodes (share_id, file_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX IF NOT EXISTS links_by_inode ON links (share_id, file_id);
CREATE TABLE IF NOT EXISTS ranges (
    share_id INTEGER NOT NULL, file_id INTEGER NOT NULL, offset INTEGER NOT NULL,
    length INTEGER NOT NULL, extent TEXT NOT NULL, extent_offset INTEGER NOT NULL,
    PRIMARY KEY (share_id, file_id, offset),
    FOREIGN KEY (share_id, file_id) REFERENCES nodes (share_id, file_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX IF NOT EXISTS ranges_by_extent ON ranges (extent);
CREATE TABLE IF NOT EXISTS extents (
    id TEXT PRIMARY KEY, length INTEGER NOT NULL, bytes BLOB NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS permissions (
    account TEXT NOT NULL, share TEXT NOT NULL, key TEXT NOT NULL, sddl TEXT NOT NULL,
    PRIMARY KEY (account, share, key)
) STRICT;";

#[derive(Clone)]
pub(crate) struct Store(Arc<Inner>);

struct Inner {
    db: Mutex<Connection>,
    env: Env,
}

/// Everything a metadata transaction needs besides the connection.
pub(super) struct Env {
    pub(super) mode: Mode,
    pub(super) clock: Clock,
    /// Days a deleted share stays restorable; zero deletes at once.
    pub(super) retention_days: std::sync::atomic::AtomicU32,
}

pub(super) enum Mode {
    Disk {
        extents: PathBuf,
        readers: Arc<Readers>,
        _lock: File,
    },
    Memory {
        limit: u64,
    },
}

impl Store {
    /// Opens `<location>/file/`, or an in-memory store when `location` is `None`.
    pub(crate) fn open(
        location: Option<&Path>,
        memory_limit: u64,
        clock: Clock,
    ) -> anyhow::Result<Self> {
        let (db, mode) = if let Some(root) = location {
            let root = root.join("file");
            std::fs::create_dir_all(&root)
                .context("could not create the file storage directory")?;
            fs::require_directory(&root)?;
            let lock_path = root.join("azuifer.lock");
            fs::require_file_if_present(&lock_path)?;
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)?;
            lock.try_lock()
                .context("the file storage directory is already in use")?;
            let extents = root.join("content");
            std::fs::create_dir_all(&extents)?;
            fs::require_directory(&extents)?;
            fs::sync_directory(&root)?;
            for name in [
                "metadata.sqlite3",
                "metadata.sqlite3-wal",
                "metadata.sqlite3-shm",
            ] {
                fs::require_file_if_present(&root.join(name))?;
            }
            let db = Connection::open(root.join("metadata.sqlite3"))
                .context("could not open file metadata")?;
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
                    readers: Arc::default(),
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
        migrate(&db).context("could not upgrade the file metadata")?;
        db.execute_batch(SCHEMA)?;
        db.execute_batch(super::service::SCHEMA)?;
        db.execute_batch(soft_delete::SCHEMA)?;
        if let Mode::Disk { extents, .. } = &mode {
            content::recover(&db, extents).context("could not recover unreferenced content")?;
        }
        Ok(Self(Arc::new(Inner {
            db: Mutex::new(db),
            env: Env {
                mode,
                clock,
                retention_days: std::sync::atomic::AtomicU32::new(0),
            },
        })))
    }

    pub(super) async fn run<T, F>(&self, action: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection, &Env) -> Result<T> + Send + 'static,
    {
        let inner = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = inner
                .db
                .lock()
                .map_err(|_| internal("poisoned metadata lock"))?;
            action(&mut db, &inner.env)
        })
        .await
        .map_err(|_| internal("metadata operation did not complete"))?
    }
}

/// Adds the columns a newer version introduced to tables an older version created. A table
/// that does not exist yet is left to `SCHEMA`.
fn migrate(db: &Connection) -> anyhow::Result<()> {
    const ADDED: [(&str, &[(&str, &str)]); 2] = [
        (
            "shares",
            &[
                ("protocol", "TEXT NOT NULL DEFAULT 'SMB'"),
                ("root_squash", "TEXT"),
                ("snapshot_vda", "INTEGER NOT NULL DEFAULT 1"),
            ],
        ),
        (
            "nodes",
            &[
                ("mode", "INTEGER"),
                ("owner", "INTEGER"),
                ("grp", "INTEGER"),
                ("file_type", "TEXT NOT NULL DEFAULT ''"),
                ("link_text", "TEXT"),
            ],
        ),
    ];
    for (table, columns) in ADDED {
        let mut info = db.prepare(&format!("PRAGMA table_info({table})"))?;
        let present = info
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(info);
        if present.is_empty() {
            continue;
        }
        for (name, definition) in columns {
            if !present.iter().any(|column| column == name) {
                db.execute(
                    &format!("ALTER TABLE {table} ADD COLUMN {name} {definition}"),
                    [],
                )?;
            }
        }
    }
    Ok(())
}

pub(super) fn db_error(error: rusqlite::Error) -> Error {
    tracing::error!(code = ?error.sqlite_error_code(), "file metadata operation failed");
    Error::Internal
}

pub(super) fn io_error(error: std::io::Error) -> Error {
    tracing::error!(kind = ?error.kind(), "file content operation failed");
    Error::Internal
}

pub(super) fn internal(reason: &'static str) -> Error {
    tracing::error!(reason, "file storage operation failed");
    Error::Internal
}

pub(super) fn new_etag() -> String {
    format!("\"0x{:016X}\"", Uuid::new_v4().as_u64_pair().0)
}

pub(super) fn to_sql(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| internal("number is outside the SQLite integer range"))
}

pub(super) fn from_sql(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| internal("negative stored length"))
}

fn json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| internal("could not encode stored JSON"))
}

fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> rusqlite::Result<T> {
    serde_json::from_str(text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn optional_json<T: serde::de::DeserializeOwned>(
    row: &Row<'_>,
    column: usize,
) -> rusqlite::Result<Option<T>> {
    row.get::<_, Option<String>>(column)?
        .map(|text| from_json(&text))
        .transpose()
}

/// A share row together with its identity and file-id allocator.
pub(super) struct ShareRow {
    pub(super) id: i64,
    pub(super) info: ShareInfo,
    pub(super) acl: Vec<super::model::AccessPolicy>,
}

pub(super) const SHARE_COLUMNS: &str = "id, name, snapshot, etag, modified, quota, access_tier, \
     access_tier_changed, metadata, acl, lease, protocol, root_squash, snapshot_vda";

pub(super) fn share_row(row: &Row<'_>) -> rusqlite::Result<ShareRow> {
    let snapshot: i64 = row.get(2)?;
    let quota: i64 = row.get(5)?;
    let protocol: String = row.get(11)?;
    let protocol = Protocol::parse(&protocol).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            11,
            rusqlite::types::Type::Text,
            "protocol".into(),
        )
    })?;
    let root_squash = row
        .get::<_, Option<String>>(12)?
        .map(|text| {
            RootSquash::parse(&text).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    12,
                    rusqlite::types::Type::Text,
                    "root squash".into(),
                )
            })
        })
        .transpose()?;
    Ok(ShareRow {
        id: row.get(0)?,
        info: ShareInfo {
            name: row.get(1)?,
            snapshot: (snapshot != 0).then_some(snapshot),
            etag: row.get(3)?,
            modified: row.get(4)?,
            quota: u64::try_from(quota)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, quota))?,
            access_tier: row.get(6)?,
            access_tier_changed: row.get(7)?,
            metadata: from_json(&row.get::<_, String>(8)?)?,
            lease: optional_json::<Lease>(row, 10)?,
            deleted: None,
            protocol,
            root_squash,
            snapshot_virtual_directory_access: row.get::<_, i64>(13)? != 0,
        },
        acl: from_json(&row.get::<_, String>(9)?)?,
    })
}

/// The columns `node_row` reads, for a query over `nodes` itself. Column 26 counts the
/// inode's names and column 27 is the `links` entry, absent for the first name.
pub(super) const NODE_COLUMNS: &str = "file_id, parent_id, name, is_dir, etag, modified, \
     attributes, creation, last_write, change_time, permission_key, metadata, length, \
     content_type, content_encoding, content_language, content_disposition, cache_control, \
     md5, lease, copy, mode, owner, grp, file_type, link_text, \
     1 + (SELECT COUNT(*) FROM links WHERE links.share_id = nodes.share_id \
          AND links.file_id = nodes.file_id), NULL";

/// The same columns for a name that is a hard link: the inode's properties under the link's
/// own parent and name. Selects `FROM links a JOIN nodes n`.
pub(super) const LINK_COLUMNS: &str = "n.file_id, a.parent_id, a.name, n.is_dir, n.etag, \
     n.modified, n.attributes, n.creation, n.last_write, n.change_time, n.permission_key, \
     n.metadata, n.length, n.content_type, n.content_encoding, n.content_language, \
     n.content_disposition, n.cache_control, n.md5, n.lease, n.copy, n.mode, n.owner, n.grp, \
     n.file_type, n.link_text, \
     1 + (SELECT COUNT(*) FROM links x WHERE x.share_id = n.share_id AND x.file_id = n.file_id), \
     a.entry_id";

pub(super) fn node_row(row: &Row<'_>) -> rusqlite::Result<NodeInfo> {
    let length: i64 = row.get(12)?;
    let bits: i64 = row.get(6)?;
    let nfs = match row.get::<_, Option<i64>>(21)? {
        None => None,
        Some(mode) => {
            let id = |index| -> rusqlite::Result<u32> {
                let value: i64 = row.get(index)?;
                u32::try_from(value)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
            };
            let kind: String = row.get(24)?;
            Some(NfsProps {
                mode: u32::try_from(mode)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(21, mode))?,
                owner: id(22)?,
                group: id(23)?,
                kind: FileKind::parse(&kind).ok_or_else(|| {
                    rusqlite::Error::FromSqlConversionFailure(
                        24,
                        rusqlite::types::Type::Text,
                        "file type".into(),
                    )
                })?,
                link_text: row.get(25)?,
            })
        }
    };
    Ok(NodeInfo {
        file_id: row.get(0)?,
        parent_id: row.get(1)?,
        name: row.get(2)?,
        directory: row.get::<_, i64>(3)? != 0,
        etag: row.get(4)?,
        modified: row.get(5)?,
        attributes: Attributes::from_bits(
            u16::try_from(bits).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(6, bits))?,
        ),
        creation: row.get(7)?,
        last_write: row.get(8)?,
        change: row.get(9)?,
        permission_key: row.get(10)?,
        metadata: from_json(&row.get::<_, String>(11)?)?,
        length: u64::try_from(length)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(12, length))?,
        http: HttpProperties {
            content_type: Some(row.get::<_, String>(13)?).filter(|value| !value.is_empty()),
            content_encoding: row.get(14)?,
            content_language: row.get(15)?,
            content_disposition: row.get(16)?,
            cache_control: row.get(17)?,
            md5: row.get(18)?,
        },
        lease: optional_json::<Lease>(row, 19)?,
        copy: optional_json::<CopyState>(row, 20)?,
        nfs,
        links: row.get(26)?,
        entry: row.get(27)?,
    })
}

/// Result of walking a path: the entry (if present) and its containing directory.
pub(super) struct Resolved {
    pub(super) node: Option<NodeInfo>,
    /// The directory that holds the entry; `None` for the root or when an ancestor is
    /// missing or is a file.
    pub(super) parent: Option<NodeInfo>,
}

/// The entry of a directory with this folded name: an inode's first name, else a hard link.
pub(super) fn child(
    db: &Connection,
    share_id: i64,
    parent_id: i64,
    key: &str,
) -> Result<Option<NodeInfo>> {
    let first = db
        .query_row(
            &format!(
                "SELECT {NODE_COLUMNS} FROM nodes WHERE share_id=?1 AND parent_id=?2 AND key=?3"
            ),
            params![share_id, parent_id, key],
            node_row,
        )
        .optional()
        .map_err(db_error)?;
    if first.is_some() {
        return Ok(first);
    }
    db.query_row(
        &format!(
            "SELECT {LINK_COLUMNS} FROM links a JOIN nodes n
             ON n.share_id = a.share_id AND n.file_id = a.file_id
             WHERE a.share_id=?1 AND a.parent_id=?2 AND a.key=?3"
        ),
        params![share_id, parent_id, key],
        node_row,
    )
    .optional()
    .map_err(db_error)
}

pub(super) fn root(db: &Connection, share_id: i64) -> Result<NodeInfo> {
    db.query_row(
        &format!("SELECT {NODE_COLUMNS} FROM nodes WHERE share_id=?1 AND parent_id IS NULL"),
        [share_id],
        node_row,
    )
    .map_err(db_error)
}

pub(super) fn resolve(db: &Connection, share_id: i64, path: &EntryPath) -> Result<Resolved> {
    let mut current = root(db, share_id)?;
    let Some((last, ancestors)) = path.components().split_last() else {
        return Ok(Resolved {
            node: Some(current),
            parent: None,
        });
    };
    for component in ancestors {
        match child(db, share_id, current.file_id, &super::name::fold(component))? {
            Some(next) if next.directory => current = next,
            _ => {
                return Ok(Resolved {
                    node: None,
                    parent: None,
                });
            }
        }
    }
    let node = child(db, share_id, current.file_id, &super::name::fold(last))?;
    Ok(Resolved {
        node,
        parent: Some(current),
    })
}

/// Writes every mutable column of an existing node. A node reached through a hard link
/// keeps the name and parent of its own `links` row: only the inode's properties change.
pub(super) fn save_node(db: &Connection, share_id: i64, node: &NodeInfo) -> Result<()> {
    let nfs = node.nfs.as_ref();
    db.execute(
        "UPDATE nodes SET parent_id=IIF(?23, parent_id, ?3), name=IIF(?23, name, ?4),
            key=IIF(?23, key, ?5), etag=?6, modified=?7, attributes=?8,
            creation=?9, last_write=?10, change_time=?11, permission_key=?12, metadata=?13,
            length=?14, content_type=?15, content_encoding=?16, content_language=?17,
            content_disposition=?18, cache_control=?19, md5=?20, lease=?21, copy=?22,
            mode=?24, owner=?25, grp=?26, file_type=?27, link_text=?28
         WHERE share_id=?1 AND file_id=?2",
        params![
            share_id,
            node.file_id,
            node.parent_id,
            node.name,
            super::name::fold(&node.name),
            node.etag,
            node.modified,
            i64::from(node.attributes.bits()),
            node.creation,
            node.last_write,
            node.change,
            node.permission_key,
            json(&node.metadata)?,
            to_sql(node.length)?,
            node.http.content_type.clone().unwrap_or_default(),
            node.http.content_encoding,
            node.http.content_language,
            node.http.content_disposition,
            node.http.cache_control,
            node.http.md5,
            node.lease.as_ref().map(json).transpose()?,
            node.copy.as_ref().map(json).transpose()?,
            node.entry.is_some(),
            nfs.map(|nfs| i64::from(nfs.mode)),
            nfs.map(|nfs| i64::from(nfs.owner)),
            nfs.map(|nfs| i64::from(nfs.group)),
            nfs.map_or("", |nfs| nfs.kind.as_str()),
            nfs.and_then(|nfs| nfs.link_text.as_deref()),
        ],
    )
    .map_err(db_error)?;
    Ok(())
}

/// Inserts a new node, allocating its file ID from the share.
pub(super) fn insert_node(db: &Connection, share_id: i64, node: &mut NodeInfo) -> Result<()> {
    node.file_id = db
        .query_row(
            "UPDATE shares SET next_file_id = next_file_id + 1 WHERE id=?1
             RETURNING next_file_id - 1",
            [share_id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    db.execute(
        "INSERT INTO nodes (share_id, file_id, parent_id, name, key, is_dir, etag, modified,
            attributes, creation, last_write, change_time, permission_key, metadata, length,
            content_type)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, '', 0, 0, 0, 0, 0, '', '{}', 0, '')",
        params![
            share_id,
            node.file_id,
            node.parent_id,
            node.name,
            super::name::fold(&node.name),
            i64::from(node.directory),
        ],
    )
    .map_err(db_error)?;
    save_node(db, share_id, node)
}
