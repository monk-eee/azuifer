//! DFS Delete Path (recursive, in bounded batches) and Rename Path (ADR-0003, ADR-0020).
//!
//! A rename is one metadata transaction that rewrites the path prefix of the source
//! and every descendant in every table that names paths, so a concurrent Blob or DFS
//! listing sees the old tree or the new tree, never a partial move.

use super::{
    Mode, Store, blob, container, db_error,
    dfs_data::drop_staged,
    dfs_paths::{PathError, PathResult, located, touch_path},
    namespace, remove_staged, snapshots, sqlite_int,
};
use crate::{
    blob_snapshot::DeleteSnapshots,
    conditions::Guard,
    domain::{BlobKey, ContainerKey, Entity, Error, Metadata, Result},
    lease::{LeaseNeed, LeaseOwner},
    posix::PathKind,
};
use rusqlite::{Connection, params};
use uuid::Uuid;

/// The tables that key rows by container path. Child tables of `blobs` and `blob_history`
/// either cascade the rename or are rewritten with the foreign keys deferred.
const PATH_TABLES: [&str; 7] = [
    "blobs",
    "directories",
    "staged_blocks",
    "committed_blocks",
    "blob_history",
    "history_blocks",
    "blob_tags",
];

pub(crate) struct Rename {
    pub(crate) source: BlobKey,
    pub(crate) destination: BlobKey,
    pub(crate) source_guard: Guard,
    pub(crate) destination_guard: Guard,
    /// `x-ms-properties` on the rename request replaces the moved path's properties.
    pub(crate) properties: Option<Metadata>,
}

/// The names below `path`: `path/` up to (excluding) `path0`, since '0' follows '/'.
/// The filesystem root (an empty path) holds every name.
fn subtree(path: &str) -> (String, String) {
    if path.is_empty() {
        return (String::new(), "\u{10FFFF}\u{10FFFF}".to_owned());
    }
    (format!("{path}/"), format!("{path}0"))
}

fn has_active_lease(db: &Connection, key: &ContainerKey, path: &str, now: i64) -> Result<bool> {
    let (low, high) = subtree(path);
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM blobs WHERE account=?1 AND container=?2
            AND (name=?3 OR (name>=?4 AND name<?5))
            AND ((lease_state=1 AND (lease_duration<0 OR ?6<lease_expiry))
              OR (lease_state=2 AND ?6<lease_expiry)))",
        params![
            key.account.as_str(),
            key.name.as_str(),
            path,
            low,
            high,
            now
        ],
        |row| row.get(0),
    )
    .map_err(db_error)
}

impl Store {
    /// Rename Path: moves a file or directory (with its subtree) within a filesystem,
    /// replacing an existing destination file or empty directory of the same kind.
    pub(crate) async fn rename_path(&self, request: Rename) -> PathResult<Entity> {
        self.run_path(move |db, mode, now| rename(db, mode, now, request))
            .await
    }

    /// Delete Path: removes a file, or a directory with its subtree when `recursive`.
    /// A subtree goes in batches of up to `batch` entries, deepest first, and the path
    /// last; a continuation marker is returned while entries remain, and the caller
    /// repeats the request with it. A non-empty directory without `recursive` is
    /// `DirectoryNotEmpty` and stays as it was.
    pub(crate) async fn delete_tree(
        &self,
        key: BlobKey,
        guard: Guard,
        batch: usize,
        recursive: bool,
    ) -> PathResult<Option<String>> {
        self.run_path(move |db, mode, now| {
            delete_tree(db, mode, now, &key, &guard, batch, recursive)
        })
        .await
    }
}

fn rename(db: &mut Connection, mode: &Mode, now: i64, request: Rename) -> PathResult<Entity> {
    let Rename {
        source,
        destination,
        source_guard,
        destination_guard,
        properties,
    } = request;
    let tx = db.transaction().map_err(db_error)?;
    container(&tx, &source.container)?;
    let (from, to) = (source.path.as_str(), destination.path.as_str());
    let container_key = &source.container;
    let found = located(&tx, container_key, from)?.ok_or(PathError::SourceNotFound)?;
    source_guard
        .conditions
        .check(Some(found.entity), false)
        .map_err(|error| match error {
            Error::ConditionNotMet => Error::SourceConditionNotMet,
            other => other,
        })?;
    if found.kind == PathKind::File {
        let row = blob(&tx, &source, now)?.ok_or(PathError::SourceNotFound)?;
        row.lease.check(
            source_guard.lease,
            LeaseNeed::Required,
            LeaseOwner::Blob,
            now,
        )?;
    } else {
        if source_guard.lease.is_some() {
            return Err(Error::LeaseNotPresentBlob.into());
        }
        if has_active_lease(&tx, container_key, from, now)? {
            return Err(Error::LeaseIdMissing.into());
        }
    }
    if from == to {
        return if found.kind == PathKind::File {
            Ok(found.entity)
        } else {
            Err(PathError::InvalidRenameSource)
        };
    }
    if to.starts_with(&format!("{from}/")) {
        return Err(PathError::InvalidRenameSource);
    }
    if let Some((parent, _)) = to.rsplit_once('/') {
        match located(&tx, container_key, parent)? {
            Some(directory) if directory.kind == PathKind::Directory => (),
            Some(_) => return Err(Error::PathConflict.into()),
            None => return Err(PathError::DestinationParentNotFound),
        }
    }
    let existing = located(&tx, container_key, to)?;
    if existing.is_some() && destination_guard.conditions.requires_absence() {
        return Err(Error::BlobAlreadyExists.into());
    }
    destination_guard
        .conditions
        .check(existing.as_ref().map(|found| found.entity), false)?;
    let mut released: Vec<Uuid> = Vec::new();
    match &existing {
        Some(target) if target.kind != found.kind => return Err(PathError::RenameTypeMismatch),
        Some(target) if target.kind == PathKind::File => {
            released.extend(drop_staged(&tx, mode, &destination)?);
            let guard = Guard {
                lease: destination_guard.lease,
                ..Guard::default()
            };
            snapshots::delete_current(
                &tx,
                mode,
                &destination,
                &guard,
                DeleteSnapshots::Include,
                now,
                &mut released,
            )?;
        }
        Some(_) => {
            if destination_guard.lease.is_some() {
                return Err(Error::LeaseNotPresentBlob.into());
            }
            released.extend(namespace::remove_empty_directory(&tx, &destination)?);
        }
        None if destination_guard.lease.is_some() => {
            return Err(Error::LeaseNotPresentBlob.into());
        }
        None => (),
    }
    tx.execute_batch("PRAGMA defer_foreign_keys = ON")
        .map_err(db_error)?;
    let (low, high) = subtree(from);
    for table in PATH_TABLES {
        tx.execute(
            &format!(
                "UPDATE {table} SET name = ?3 || substr(name, length(?4)+1)
                 WHERE account=?1 AND container=?2 AND (name=?4 OR (name>=?5 AND name<?6))"
            ),
            params![
                container_key.account.as_str(),
                container_key.name.as_str(),
                to,
                from,
                low,
                high
            ],
        )
        .map_err(db_error)?;
    }
    let mut entity = found.entity;
    if found.kind == PathKind::Directory {
        entity = touch_path(&tx, container_key, to, PathKind::Directory, now)?;
    }
    if let Some(properties) = properties {
        let json = serde_json::to_string(&properties)
            .map_err(|_| super::internal("could not encode metadata"))?;
        let table = if found.kind == PathKind::Directory {
            "directories"
        } else {
            "blobs"
        };
        tx.execute(
            &format!(
                "UPDATE {table} SET metadata=?1 WHERE account=?2 AND container=?3 AND name=?4"
            ),
            params![
                json,
                container_key.account.as_str(),
                container_key.name.as_str(),
                to
            ],
        )
        .map_err(db_error)?;
        if found.kind == PathKind::File {
            entity = touch_path(&tx, container_key, to, PathKind::File, now)?;
        }
    }
    tx.commit().map_err(db_error)?;
    snapshots::release(db, mode, &released);
    Ok(entity)
}

fn delete_tree(
    db: &mut Connection,
    mode: &Mode,
    now: i64,
    key: &BlobKey,
    guard: &Guard,
    batch: usize,
    recursive: bool,
) -> PathResult<Option<String>> {
    let tx = db.transaction().map_err(db_error)?;
    container(&tx, &key.container)?;
    let path = key.path.as_str();
    let found = located(&tx, &key.container, path)?.ok_or(Error::BlobMissing)?;
    let mut released: Vec<Uuid> = Vec::new();
    let mut remaining = false;
    if found.kind == PathKind::File {
        released.extend(drop_staged(&tx, mode, key)?);
        snapshots::delete_current(
            &tx,
            mode,
            key,
            guard,
            DeleteSnapshots::Include,
            now,
            &mut released,
        )?;
    } else {
        if guard.lease.is_some() {
            return Err(Error::LeaseNotPresentBlob.into());
        }
        guard.conditions.check(Some(found.entity), false)?;
        let (low, high) = subtree(path);
        let limit = sqlite_int(if recursive { batch as u64 } else { 0 })?;
        let entries: Vec<(String, bool)> = {
            let mut query = tx
                .prepare(
                    "SELECT name, directory FROM namespace_entries
                     WHERE account=?1 AND container=?2 AND name>=?3 AND name<?4
                     ORDER BY name DESC LIMIT ?5",
                )
                .map_err(db_error)?;
            let rows = query
                .query_map(
                    params![
                        key.container.account.as_str(),
                        key.container.name.as_str(),
                        low,
                        high,
                        limit + 1
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(db_error)?;
            rows.collect::<rusqlite::Result<_>>().map_err(db_error)?
        };
        remaining = entries.len() > if recursive { batch } else { 0 };
        if remaining && !recursive {
            return Err(Error::DirectoryNotEmpty.into());
        }
        for (name, directory) in entries.into_iter().take(batch) {
            let child = BlobKey {
                container: key.container.clone(),
                path: crate::domain::BlobPath::parse(name.clone())?,
            };
            if directory {
                tx.execute(
                    "DELETE FROM directories WHERE account=?1 AND container=?2 AND name=?3",
                    params![
                        key.container.account.as_str(),
                        key.container.name.as_str(),
                        name
                    ],
                )
                .map_err(db_error)?;
                released.extend(remove_staged(&tx, &child)?);
            } else {
                released.extend(drop_staged(&tx, mode, &child)?);
                snapshots::delete_current(
                    &tx,
                    mode,
                    &child,
                    &Guard::default(),
                    DeleteSnapshots::Include,
                    now,
                    &mut released,
                )?;
            }
        }
        if !remaining {
            released.extend(namespace::remove_empty_directory(&tx, key)?);
        }
    }
    tx.commit().map_err(db_error)?;
    snapshots::release(db, mode, &released);
    Ok(remaining.then(|| path.to_owned()))
}

/// Entities and kinds below a directory in name order, for recursive ACL batches.
pub(super) struct TreeEntry {
    pub(super) name: String,
    pub(super) kind: PathKind,
}

pub(super) fn tree_after(
    db: &Connection,
    key: &ContainerKey,
    root: &str,
    after: &str,
    limit: usize,
) -> Result<Vec<TreeEntry>> {
    let (low, high) = subtree(root);
    let start = if after.is_empty() || after < low.as_str() {
        low
    } else {
        format!("{after}\u{0}")
    };
    let mut query = db
        .prepare(
            "SELECT name, directory FROM namespace_entries
             WHERE account=?1 AND container=?2 AND name>=?3 AND name<?4
             ORDER BY name LIMIT ?5",
        )
        .map_err(db_error)?;
    let rows = query
        .query_map(
            params![
                key.account.as_str(),
                key.name.as_str(),
                start,
                high,
                sqlite_int(limit as u64)?
            ],
            |row| {
                let directory: bool = row.get(1)?;
                Ok(TreeEntry {
                    name: row.get(0)?,
                    kind: if directory {
                        PathKind::Directory
                    } else {
                        PathKind::File
                    },
                })
            },
        )
        .map_err(db_error)?;
    rows.collect::<rusqlite::Result<_>>().map_err(db_error)
}
