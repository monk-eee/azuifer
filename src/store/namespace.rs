use super::{
    Store, blob_params, container, db_error, entity_row, new_entity, row_uint, sqlite_int,
};
use crate::{
    conditions::Conditions,
    domain::{
        AccountName, BlobKey, BlobPath, ContainerKey, ContainerName, ContentLength, Entity, Error,
        Page, PageRequest, PathEntry, Result,
    },
};
use anyhow::Context as _;
use rusqlite::{Connection, OptionalExtension as _, params};
use std::collections::HashSet;
use uuid::Uuid;

pub(super) const SCHEMA: &str = "
CREATE TABLE directories (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    id BLOB NOT NULL, modified INTEGER NOT NULL, etag BLOB NOT NULL,
    PRIMARY KEY (account, container, name),
    FOREIGN KEY (account, container) REFERENCES containers (account, name) ON DELETE CASCADE
) STRICT;
CREATE VIEW namespace_entries AS
    SELECT account, container, name, id, modified, COALESCE(etag,id) AS etag, length, 0 AS directory
    FROM blobs
    UNION ALL
    SELECT account, container, name, id, modified, etag, 0, 1
    FROM directories;";

pub(super) fn restore_parents(
    db: &mut Connection,
    accounts: &HashSet<AccountName>,
    now: i64,
) -> anyhow::Result<()> {
    if accounts.is_empty() {
        return Ok(());
    }

    // Databases created before directory support only have file rows.
    let tx = db.transaction()?;
    for account in accounts {
        let mut files = tx.prepare("SELECT container, name FROM blobs WHERE account=?1")?;
        let mut rows = files.query([account.as_str()])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(0)?;
            let path: String = row.get(1)?;
            let restore = || -> Result<()> {
                let path = BlobPath::parse(path)?;
                path.check_hns()?;
                let key = BlobKey {
                    container: ContainerKey {
                        account: account.clone(),
                        name: ContainerName::parse(&name)?,
                    },
                    path,
                };
                prepare_file(&tx, &key, now)
            };
            restore().map_err(|error| {
                anyhow::anyhow!(
                    "stored paths in account `{}` cannot be opened with HNS: {error:?}",
                    account.as_str()
                )
            })?;
        }
    }
    tx.commit().context("could not update the HNS namespace")
}

impl Store {
    pub(crate) async fn create_directory(
        &self,
        key: BlobKey,
        conditions: Conditions,
    ) -> Result<Entity> {
        self.run(move |db, _, now| {
            let tx = db.transaction().map_err(db_error)?;
            container(&tx, &key.container)?;
            if file_exists(&tx, &key.container, key.path.as_str())? {
                return Err(Error::PathConflict);
            }
            conditions.check(directory(&tx, &key.container, key.path.as_str())?, false)?;
            parents(&tx, &key, Some(now))?;
            let entity = write_directory(&tx, &key.container, key.path.as_str(), now)?;
            tx.commit().map_err(db_error)?;
            Ok(entity)
        })
        .await
    }

    pub(crate) async fn list_paths(
        &self,
        key: ContainerKey,
        parent: Option<BlobPath>,
        recursive: bool,
        mut page: PageRequest,
    ) -> Result<(Entity, Page<PathEntry>)> {
        self.run(move |db, _, _| {
            let root = container(db, &key)?;
            let entity = if let Some(parent) = parent {
                let entity = directory(db, &key, parent.as_str())?.ok_or(Error::BlobMissing)?;
                page.prefix = format!("{}/", parent.as_str());
                entity
            } else {
                root
            };
            Ok((entity, list(db, &key, page, recursive)?))
        })
        .await
    }
}

fn list(
    db: &Connection,
    key: &ContainerKey,
    page: PageRequest,
    recursive: bool,
) -> Result<Page<PathEntry>> {
    let mut query = db
        .prepare(
            "SELECT id, modified, etag, length, name, directory
         FROM namespace_entries
         WHERE account=?1 AND container=?2 AND name>?3 AND name>=?4 AND instr(name, ?4)=1
           AND (?5 OR instr(substr(name, length(?4)+1), '/')=0)
         ORDER BY name LIMIT ?6",
        )
        .map_err(db_error)?;
    let rows = query
        .query_map(
            params![
                key.account.as_str(),
                key.name.as_str(),
                page.after,
                page.prefix,
                recursive,
                page.limit + 1,
            ],
            |row| {
                let entity = entity_row(row)?;
                let entry = if row.get(5)? {
                    PathEntry::Directory(entity)
                } else {
                    PathEntry::File(entity, ContentLength(row_uint(row, 3)?))
                };
                Ok((row.get(4)?, entry))
            },
        )
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)?;
    Ok(Page::from_rows(rows, page.limit))
}

pub(super) fn directory(db: &Connection, key: &ContainerKey, name: &str) -> Result<Option<Entity>> {
    db.prepare_cached(
        "SELECT id, modified, etag FROM directories WHERE account=?1 AND container=?2 AND name=?3",
    )
    .map_err(db_error)?
    .query_row([key.account.as_str(), key.name.as_str(), name], entity_row)
    .optional()
    .map_err(db_error)
}

pub(super) fn prepare_file(db: &Connection, key: &BlobKey, now: i64) -> Result<()> {
    file_target(db, key, Some(now))
}

pub(super) fn validate_staged_path(db: &Connection, key: &BlobKey) -> Result<()> {
    file_target(db, key, None)
}

fn file_target(db: &Connection, key: &BlobKey, create_at: Option<i64>) -> Result<()> {
    if directory(db, &key.container, key.path.as_str())?.is_some() {
        return Err(Error::PathConflict);
    }
    parents(db, key, create_at)
}

fn parents(db: &Connection, key: &BlobKey, create_at: Option<i64>) -> Result<()> {
    let path = key.path.as_str();
    for (separator, _) in path.match_indices('/') {
        let name = &path[..separator];
        if file_exists(db, &key.container, name)? {
            return Err(Error::PathConflict);
        }
        if let Some(now) = create_at
            && directory(db, &key.container, name)?.is_none()
        {
            write_directory(db, &key.container, name, now)?;
        }
    }
    Ok(())
}

fn write_directory(db: &Connection, key: &ContainerKey, name: &str, now: i64) -> Result<Entity> {
    let entity = new_entity(now)?;
    db.prepare_cached(
        "INSERT INTO directories VALUES (?1,?2,?3,?4,?5,?4)
         ON CONFLICT(account,container,name) DO UPDATE SET
           modified=excluded.modified, etag=excluded.etag
         RETURNING id, modified, etag",
    )
    .map_err(db_error)?
    .query_row(
        params![
            key.account.as_str(),
            key.name.as_str(),
            name,
            entity.id,
            sqlite_int(entity.modified)?,
        ],
        entity_row,
    )
    .map_err(db_error)
}

fn file_exists(db: &Connection, key: &ContainerKey, name: &str) -> Result<bool> {
    db.prepare_cached(
        "SELECT EXISTS(SELECT 1 FROM blobs WHERE account=?1 AND container=?2 AND name=?3)",
    )
    .map_err(db_error)?
    .query_row([key.account.as_str(), key.name.as_str(), name], |row| {
        row.get(0)
    })
    .map_err(db_error)
}

pub(super) fn remove_empty_directory(db: &Connection, key: &BlobKey) -> Result<Vec<Uuid>> {
    let [account, container, path] = blob_params(key);
    let prefix = format!("{path}/");
    // '/' and '0' are adjacent in the binary collation used by the path index.
    let upper = format!("{path}0");
    let has_children: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM namespace_entries WHERE account=?1 AND container=?2 AND name>=?3 AND name<?4)",
        params![account, container, prefix, upper],
        |row| row.get(0),
    ).map_err(db_error)?;
    if has_children {
        return Err(Error::DirectoryNotEmpty);
    }

    let mut staged = db.prepare(
        "DELETE FROM staged_blocks WHERE account=?1 AND container=?2 AND (name=?3 OR (name>=?4 AND name<?5)) RETURNING id",
    ).map_err(db_error)?;
    let discard = staged
        .query_map(params![account, container, path, prefix, upper], |row| {
            row.get(0)
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)?;
    db.execute(
        "DELETE FROM directories WHERE account=?1 AND container=?2 AND name=?3",
        [account, container, path],
    )
    .map_err(db_error)?;
    Ok(discard)
}
