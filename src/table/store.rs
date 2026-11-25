//! SQLite persistence for tables and entities (ADR-0010, ADR-0014).

use super::{
    codec,
    datetime::Ticks,
    error::{Kind, Result, TableError, db_error, internal},
    filter::Expr,
    model::{
        Entity, EntityKey, KeyRange, KeyValue, Precondition, Properties, TableName, Value,
        check_entity_limits,
    },
    service::AccessPolicy,
};
use crate::domain::AccountName;
use anyhow::Context as _;
use rusqlite::{Connection, OptionalExtension as _, params, params_from_iter};
use std::{
    borrow::Cow,
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    path::Path,
    sync::{Arc, Mutex},
};

const SCHEMA_VERSION: i64 = 1;
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS tables (
    account TEXT NOT NULL, key TEXT NOT NULL, name TEXT NOT NULL, acl TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (account, key)
) STRICT;
CREATE TABLE IF NOT EXISTS entities (
    account TEXT NOT NULL, tbl TEXT NOT NULL, pk TEXT NOT NULL, rk TEXT NOT NULL,
    timestamp INTEGER NOT NULL, props BLOB NOT NULL,
    PRIMARY KEY (account, tbl, pk, rk),
    FOREIGN KEY (account, tbl) REFERENCES tables (account, key) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS service_properties (
    account TEXT PRIMARY KEY, document TEXT NOT NULL
) STRICT, WITHOUT ROWID;";

#[derive(Clone)]
pub(super) struct Store(Arc<Inner>);

struct Inner {
    db: Mutex<Db>,
    _lock: Option<File>,
}

struct Db {
    conn: Connection,
    /// The newest modification time issued, so ETags never repeat within a run.
    last: Ticks,
}

#[derive(Clone)]
pub(super) enum WriteKind {
    Insert,
    Replace,
    Merge,
    Delete,
}

/// One entity write. `Replace` and `Merge` without a condition are the upserts.
pub(super) struct WriteOp {
    pub(super) kind: WriteKind,
    pub(super) key: EntityKey,
    pub(super) properties: Properties,
    pub(super) condition: Precondition,
}

pub(super) struct Written {
    pub(super) timestamp: Ticks,
    /// The stored entity after the write (absent for a delete).
    pub(super) entity: Option<Entity>,
}

/// A failed write set: which operation failed and why. Nothing was applied.
pub(super) struct Failure {
    pub(super) index: usize,
    pub(super) error: TableError,
}

pub(super) struct EntityScan {
    pub(super) filter: Option<Expr>,
    pub(super) top: usize,
    pub(super) start: Option<(String, String)>,
    pub(super) range: Option<KeyRange>,
}

pub(super) struct EntityPage {
    pub(super) entities: Vec<Entity>,
    pub(super) next: Option<(String, String)>,
}

pub(super) struct TablePage {
    pub(super) names: Vec<TableName>,
    pub(super) next: Option<TableName>,
}

impl Store {
    /// Opens the Table store in `<location>/table`, or in memory when `location` is `None`.
    pub(super) fn open(location: Option<&Path>) -> anyhow::Result<Self> {
        let (conn, lock) = if let Some(root) = location {
            let dir = root.join("table");
            fs::create_dir_all(&dir).context("could not create the Table storage directory")?;
            require_directory(&dir)?;
            let lock_path = dir.join("table.lock");
            require_file_if_present(&lock_path)?;
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)?;
            lock.try_lock()
                .context("the Table storage directory is already in use")?;
            for name in ["table.sqlite3", "table.sqlite3-wal", "table.sqlite3-shm"] {
                require_file_if_present(&dir.join(name))?;
            }
            let conn = Connection::open(dir.join("table.sqlite3"))
                .context("could not open Table metadata")?;
            let journal: String =
                conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
            anyhow::ensure!(
                journal.eq_ignore_ascii_case("wal"),
                "Table storage does not support SQLite WAL"
            );
            conn.pragma_update(None, "synchronous", "FULL")?;
            (conn, Some(lock))
        } else {
            (Connection::open_in_memory()?, None)
        };
        conn.pragma_update(None, "foreign_keys", true)?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        anyhow::ensure!(
            version <= SCHEMA_VERSION,
            "the Table storage was written by a newer version"
        );
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Self(Arc::new(Inner {
            db: Mutex::new(Db {
                conn,
                last: Ticks::new(0).unwrap_or_else(|| Ticks::from_system(std::time::UNIX_EPOCH)),
            }),
            _lock: lock,
        })))
    }

    async fn run<T, F>(&self, action: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Db) -> Result<T> + Send + 'static,
    {
        let inner = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = inner
                .db
                .lock()
                .map_err(|_| internal("poisoned Table metadata lock"))?;
            action(&mut db)
        })
        .await
        .map_err(|_| internal("Table metadata operation did not complete"))?
    }

    pub(super) async fn create_table(&self, account: AccountName, name: TableName) -> Result<()> {
        self.run(move |db| {
            let changed = db
                .conn
                .execute(
                    "INSERT INTO tables (account, key, name) VALUES (?1, ?2, ?3)
                     ON CONFLICT (account, key) DO NOTHING",
                    params![account.as_str(), name.key(), name.as_str()],
                )
                .map_err(db_error)?;
            if changed == 0 {
                return Err(TableError::new(Kind::TableAlreadyExists));
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn delete_table(&self, account: AccountName, name: TableName) -> Result<()> {
        self.run(move |db| {
            let changed = db
                .conn
                .execute(
                    "DELETE FROM tables WHERE account=?1 AND key=?2",
                    params![account.as_str(), name.key()],
                )
                .map_err(db_error)?;
            if changed == 0 {
                return Err(TableError::new(Kind::TableNotFound));
            }
            Ok(())
        })
        .await
    }

    /// The table with its stored (original-case) name.
    pub(super) async fn table(&self, account: AccountName, name: TableName) -> Result<TableName> {
        self.run(move |db| stored_name(&db.conn, account.as_str(), &name.key()))
            .await
    }

    pub(super) async fn query_tables(
        &self,
        account: AccountName,
        filter: Option<Expr>,
        top: usize,
        after: Option<String>,
    ) -> Result<TablePage> {
        self.run(move |db| {
            let mut statement = db
                .conn
                .prepare("SELECT name FROM tables WHERE account=?1 AND key>=?2 ORDER BY key")
                .map_err(db_error)?;
            let from = after.unwrap_or_default().to_ascii_lowercase();
            let mut rows = statement
                .query(params![account.as_str(), from])
                .map_err(db_error)?;
            let mut page = TablePage {
                names: Vec::new(),
                next: None,
            };
            while let Some(row) = rows.next().map_err(db_error)? {
                let name: String = row.get(0).map_err(db_error)?;
                let matched = filter.as_ref().is_none_or(|filter| {
                    filter.matches(&|property| {
                        (property == "TableName").then(|| Cow::Owned(Value::String(name.clone())))
                    })
                });
                if !matched {
                    continue;
                }
                let name = TableName::parse(&name).map_err(|_| internal("corrupt table name"))?;
                if page.names.len() == top {
                    page.next = Some(name);
                    break;
                }
                page.names.push(name);
            }
            Ok(page)
        })
        .await
    }

    pub(super) async fn table_acl(
        &self,
        account: AccountName,
        name: TableName,
    ) -> Result<Vec<AccessPolicy>> {
        self.run(move |db| {
            let acl: Option<String> = db
                .conn
                .query_row(
                    "SELECT acl FROM tables WHERE account=?1 AND key=?2",
                    params![account.as_str(), name.key()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            let acl = acl.ok_or_else(|| TableError::new(Kind::TableNotFound))?;
            serde_json::from_str(&acl).map_err(|_| internal("corrupt access policies"))
        })
        .await
    }

    pub(super) async fn set_table_acl(
        &self,
        account: AccountName,
        name: TableName,
        policies: Vec<AccessPolicy>,
    ) -> Result<()> {
        self.run(move |db| {
            let acl = serde_json::to_string(&policies)
                .map_err(|_| internal("could not encode access policies"))?;
            let changed = db
                .conn
                .execute(
                    "UPDATE tables SET acl=?3 WHERE account=?1 AND key=?2",
                    params![account.as_str(), name.key(), acl],
                )
                .map_err(db_error)?;
            if changed == 0 {
                return Err(TableError::new(Kind::TableNotFound));
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn service_properties(
        &self,
        account: AccountName,
    ) -> Result<BTreeMap<String, String>> {
        self.run(move |db| read_service_properties(&db.conn, account.as_str()))
            .await
    }

    /// Replaces the supplied top-level elements and keeps the others.
    pub(super) async fn update_service_properties(
        &self,
        account: AccountName,
        updates: BTreeMap<String, String>,
    ) -> Result<()> {
        self.run(move |db| {
            let tx = db.conn.transaction().map_err(db_error)?;
            let mut stored = read_service_properties(&tx, account.as_str())?;
            stored.extend(updates);
            let document = serde_json::to_string(&stored)
                .map_err(|_| internal("could not encode service properties"))?;
            tx.execute(
                "INSERT INTO service_properties (account, document) VALUES (?1, ?2)
                 ON CONFLICT (account) DO UPDATE SET document=excluded.document",
                params![account.as_str(), document],
            )
            .map_err(db_error)?;
            tx.commit().map_err(db_error)
        })
        .await
    }

    pub(super) async fn entity(
        &self,
        account: AccountName,
        table: TableName,
        key: EntityKey,
    ) -> Result<Entity> {
        self.run(move |db| {
            let tbl = table.key();
            table_exists(&db.conn, account.as_str(), &tbl)?;
            read_entity(&db.conn, account.as_str(), &tbl, &key)?
                .ok_or_else(|| TableError::new(Kind::ResourceNotFound))
        })
        .await
    }

    pub(super) async fn query_entities(
        &self,
        account: AccountName,
        table: TableName,
        scan: EntityScan,
    ) -> Result<EntityPage> {
        self.run(move |db| {
            let tbl = table.key();
            table_exists(&db.conn, account.as_str(), &tbl)?;
            scan_entities(&db.conn, account.as_str(), &tbl, &scan)
        })
        .await
    }

    /// Applies the writes in one transaction, in order. The first failure rolls back all.
    pub(super) async fn apply(
        &self,
        account: AccountName,
        table: TableName,
        ops: Vec<WriteOp>,
        now: Ticks,
    ) -> std::result::Result<Vec<Written>, Failure> {
        let outcome = self
            .run(move |db| Ok(apply_all(db, account.as_str(), &table.key(), ops, now)))
            .await;
        match outcome {
            Ok(result) => result,
            Err(error) => Err(Failure { index: 0, error }),
        }
    }
}

fn read_service_properties(conn: &Connection, account: &str) -> Result<BTreeMap<String, String>> {
    let document: Option<String> = conn
        .query_row(
            "SELECT document FROM service_properties WHERE account=?1",
            params![account],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    document.map_or_else(
        || Ok(BTreeMap::new()),
        |document| {
            serde_json::from_str(&document).map_err(|_| internal("corrupt service properties"))
        },
    )
}

fn stored_name(conn: &Connection, account: &str, key: &str) -> Result<TableName> {
    let name: Option<String> = conn
        .query_row(
            "SELECT name FROM tables WHERE account=?1 AND key=?2",
            params![account, key],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    let name = name.ok_or_else(|| TableError::new(Kind::TableNotFound))?;
    TableName::parse(&name).map_err(|_| internal("corrupt table name"))
}

fn table_exists(conn: &Connection, account: &str, key: &str) -> Result<()> {
    stored_name(conn, account, key).map(drop)
}

fn build_entity(pk: &str, rk: &str, timestamp: i64, props: &[u8]) -> Result<Entity> {
    let corrupt = || internal("corrupt stored entity");
    Ok(Entity {
        key: EntityKey {
            partition: KeyValue::parse(pk).map_err(|_| corrupt())?,
            row: KeyValue::parse(rk).map_err(|_| corrupt())?,
        },
        timestamp: Ticks::new(timestamp).ok_or_else(corrupt)?,
        properties: codec::decode(props).ok_or_else(corrupt)?,
    })
}

fn read_entity(
    conn: &Connection,
    account: &str,
    tbl: &str,
    key: &EntityKey,
) -> Result<Option<Entity>> {
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT timestamp, props FROM entities
             WHERE account=?1 AND tbl=?2 AND pk=?3 AND rk=?4",
            params![account, tbl, key.partition.as_str(), key.row.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db_error)?;
    row.map(|(timestamp, props)| {
        build_entity(key.partition.as_str(), key.row.as_str(), timestamp, &props)
    })
    .transpose()
}

fn scan_entities(
    conn: &Connection,
    account: &str,
    tbl: &str,
    scan: &EntityScan,
) -> Result<EntityPage> {
    let mut page = EntityPage {
        entities: Vec::new(),
        next: None,
    };
    let bounds = scan
        .filter
        .as_ref()
        .map(Expr::key_bounds)
        .unwrap_or_default();
    if bounds.empty {
        return Ok(page);
    }
    let mut partition_min = bounds.partition_min;
    let mut partition_max = bounds.partition_max;
    if let Some(range) = &scan.range {
        if let Some(min) = range.partition_min()
            && partition_min.as_deref().is_none_or(|m| m < min)
        {
            partition_min = Some(min.to_owned());
        }
        if let Some(max) = range.partition_max()
            && partition_max.as_deref().is_none_or(|m| m > max)
        {
            partition_max = Some(max.to_owned());
        }
    }
    // Row-key bounds only narrow the scan inside a single partition.
    let single = partition_min.is_some() && partition_min == partition_max;
    let mut lower = (
        partition_min.unwrap_or_default(),
        if single {
            bounds.row_min.unwrap_or_default()
        } else {
            String::new()
        },
    );
    if let Some(start) = &scan.start
        && *start > lower
    {
        lower = start.clone();
    }
    let mut sql = String::from(
        "SELECT pk, rk, timestamp, props FROM entities
         WHERE account=? AND tbl=? AND (pk, rk) >= (?, ?)",
    );
    let mut args = vec![account.to_owned(), tbl.to_owned(), lower.0, lower.1];
    if let Some(max) = partition_max {
        sql.push_str(" AND pk <= ?");
        args.push(max);
    }
    if single && let Some(max) = bounds.row_max {
        sql.push_str(" AND rk <= ?");
        args.push(max);
    }
    sql.push_str(" ORDER BY pk, rk");
    let mut statement = conn.prepare(&sql).map_err(db_error)?;
    let mut rows = statement.query(params_from_iter(args)).map_err(db_error)?;
    while let Some(row) = rows.next().map_err(db_error)? {
        let pk: String = row.get(0).map_err(db_error)?;
        let rk: String = row.get(1).map_err(db_error)?;
        let timestamp: i64 = row.get(2).map_err(db_error)?;
        let props: Vec<u8> = row.get(3).map_err(db_error)?;
        let entity = build_entity(&pk, &rk, timestamp, &props)?;
        if scan
            .range
            .as_ref()
            .is_some_and(|range| !range.contains(&entity.key))
        {
            continue;
        }
        let matched = scan.filter.as_ref().is_none_or(|filter| {
            filter.matches(&|name| match name {
                "PartitionKey" => Some(Cow::Owned(Value::String(pk.clone()))),
                "RowKey" => Some(Cow::Owned(Value::String(rk.clone()))),
                "Timestamp" => Some(Cow::Owned(Value::DateTime(entity.timestamp))),
                other => entity.properties.get(other).map(Cow::Borrowed),
            })
        });
        if !matched {
            continue;
        }
        if page.entities.len() == scan.top {
            page.next = Some((pk, rk));
            break;
        }
        page.entities.push(entity);
    }
    Ok(page)
}

fn apply_all(
    db: &mut Db,
    account: &str,
    tbl: &str,
    ops: Vec<WriteOp>,
    now: Ticks,
) -> std::result::Result<Vec<Written>, Failure> {
    let first = |error| Failure { index: 0, error };
    let Db { conn, last } = db;
    let tx = conn.transaction().map_err(|e| first(db_error(e)))?;
    table_exists(&tx, account, tbl).map_err(first)?;
    let mut written = Vec::with_capacity(ops.len());
    for (index, op) in ops.into_iter().enumerate() {
        let result = apply_one(&tx, last, account, tbl, op, now);
        written.push(result.map_err(|error| Failure { index, error })?);
    }
    tx.commit().map_err(|e| first(db_error(e)))?;
    Ok(written)
}

fn apply_one(
    conn: &Connection,
    last: &mut Ticks,
    account: &str,
    tbl: &str,
    op: WriteOp,
    now: Ticks,
) -> Result<Written> {
    let existing = read_entity(conn, account, tbl, &op.key)?;
    let stamp = |previous: Option<Ticks>, last: &mut Ticks| {
        let mut next = now.max(last.after());
        if let Some(previous) = previous {
            next = next.max(previous.after());
        }
        *last = next;
        next
    };
    let (timestamp, properties) = match (op.kind, existing) {
        (WriteKind::Insert, Some(_)) => {
            return Err(TableError::new(Kind::EntityAlreadyExists));
        }
        (WriteKind::Insert, None) => (stamp(None, last), op.properties),
        // Without If-Match, replace and merge create the entity when it is missing.
        (WriteKind::Replace | WriteKind::Merge, None) if op.condition == Precondition::None => {
            (stamp(None, last), op.properties)
        }
        (_, None) => return Err(TableError::new(Kind::ResourceNotFound)),
        (kind, Some(current)) => {
            if !op.condition.holds(current.timestamp) {
                return Err(TableError::new(Kind::UpdateConditionNotSatisfied));
            }
            let timestamp = stamp(Some(current.timestamp), last);
            match kind {
                WriteKind::Delete => {
                    conn.execute(
                        "DELETE FROM entities WHERE account=?1 AND tbl=?2 AND pk=?3 AND rk=?4",
                        params![account, tbl, op.key.partition.as_str(), op.key.row.as_str()],
                    )
                    .map_err(db_error)?;
                    return Ok(Written {
                        timestamp,
                        entity: None,
                    });
                }
                WriteKind::Merge => {
                    let mut merged = current.properties;
                    merged.extend(op.properties);
                    (timestamp, merged)
                }
                WriteKind::Insert | WriteKind::Replace => (timestamp, op.properties),
            }
        }
    };
    check_entity_limits(&op.key, &properties)?;
    conn.execute(
        "INSERT INTO entities (account, tbl, pk, rk, timestamp, props) VALUES (?1,?2,?3,?4,?5,?6)
         ON CONFLICT (account, tbl, pk, rk) DO UPDATE SET timestamp=excluded.timestamp, props=excluded.props",
        params![
            account,
            tbl,
            op.key.partition.as_str(),
            op.key.row.as_str(),
            timestamp.get(),
            codec::encode(&properties)
        ],
    )
    .map_err(db_error)?;
    Ok(Written {
        timestamp,
        entity: Some(Entity {
            key: op.key,
            timestamp,
            properties,
        }),
    })
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
