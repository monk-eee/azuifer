//! Per-blob lifecycle rows and Set Blob Expiry. A blob past its expiry is removed
//! lazily, before the next metadata action, so every operation (Blob and DFS alike)
//! sees it as gone on the shared clock (ADR-0012).

use super::{BlobRow, Mode, Store, blob, blob_params, db_error, require_blob, snapshots};
use crate::{
    blob_expiry::ExpiryOption,
    blob_immutability::{PolicyMode, Protection},
    blob_lifecycle::{Incremental, Lifecycle},
    conditions::Guard,
    domain::{AccountName, BlobKey, BlobPath, ContainerKey, ContainerName, Entity, Result},
    lease::{LeaseNeed, LeaseOwner},
    stamp::Ticks,
};
use rusqlite::{Connection, OptionalExtension as _, Row, params};
use std::collections::HashMap;

const COLUMNS: &str = "expires_at, immutable_until, immutability_mode, legal_hold, \
    incremental_source, incremental_destination";

fn lifecycle_row(row: &Row<'_>) -> rusqlite::Result<Lifecycle> {
    let mode: String = row.get(2)?;
    let source: Option<i64> = row.get(4)?;
    let destination: Option<i64> = row.get(5)?;
    Ok(Lifecycle {
        expires: row.get(0)?,
        protection: Protection {
            until: row.get(1)?,
            mode: PolicyMode::from_stored(&mode),
            legal_hold: row.get::<_, i64>(3)? != 0,
        },
        versioned: false,
        incremental: source
            .zip(destination)
            .map(|(source, destination)| Incremental {
                source: Ticks(source),
                destination: Ticks(destination),
            }),
    })
}

/// Loads the lifecycle state of a blob read for a single-blob operation.
pub(super) fn attach(db: &Connection, key: &BlobKey, mut row: BlobRow) -> Result<BlobRow> {
    let [account, container, name] = blob_params(key);
    let found = db
        .prepare_cached(&format!(
            "SELECT {COLUMNS} FROM blob_lifecycle WHERE account=?1 AND container=?2 AND name=?3"
        ))
        .map_err(db_error)?
        .query_row(params![account, container, name], lifecycle_row)
        .optional()
        .map_err(db_error)?;
    if let Some(mut lifecycle) = found {
        if lifecycle.protection.has_policy() || lifecycle.protection.legal_hold {
            lifecycle.versioned = snapshots::is_versioned(db, account)?;
        }
        row.info.lifecycle = lifecycle;
    }
    Ok(row)
}

/// The lifecycle state of every blob of a container that has any, by blob name, for listings.
pub(super) fn load_container(
    db: &Connection,
    account: &str,
    container: &str,
) -> Result<HashMap<String, Lifecycle>> {
    let mut query = db
        .prepare_cached(&format!(
            "SELECT {COLUMNS}, name FROM blob_lifecycle WHERE account=?1 AND container=?2"
        ))
        .map_err(db_error)?;
    query
        .query_map(params![account, container], |row| {
            Ok((row.get::<_, String>(6)?, lifecycle_row(row)?))
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)
}

/// Writes the whole lifecycle state of a blob, which must exist.
pub(super) fn write(db: &Connection, key: &BlobKey, lifecycle: &Lifecycle) -> Result<()> {
    let [account, container, name] = blob_params(key);
    let protection = &lifecycle.protection;
    db.execute(
        "INSERT INTO blob_lifecycle (account, container, name, expires_at, immutable_until,
            immutability_mode, legal_hold, incremental_source, incremental_destination)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(account, container, name) DO UPDATE SET
            expires_at=excluded.expires_at, immutable_until=excluded.immutable_until,
            immutability_mode=excluded.immutability_mode, legal_hold=excluded.legal_hold,
            incremental_source=excluded.incremental_source,
            incremental_destination=excluded.incremental_destination",
        params![
            account,
            container,
            name,
            lifecycle.expires,
            protection.until,
            protection.mode.map_or("", PolicyMode::name),
            i64::from(protection.legal_hold),
            lifecycle
                .incremental
                .map(|incremental| incremental.source.0),
            lifecycle
                .incremental
                .map(|incremental| incremental.destination.0),
        ],
    )
    .map_err(db_error)?;
    Ok(())
}

/// Marks a blob as an incremental copy destination after a copy finished.
pub(super) fn write_incremental(
    db: &Connection,
    key: &BlobKey,
    incremental: Incremental,
) -> Result<()> {
    let [account, container, name] = blob_params(key);
    db.execute(
        "INSERT INTO blob_lifecycle (account, container, name, incremental_source,
            incremental_destination)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(account, container, name) DO UPDATE SET
            incremental_source=excluded.incremental_source,
            incremental_destination=excluded.incremental_destination",
        params![
            account,
            container,
            name,
            incremental.source.0,
            incremental.destination.0
        ],
    )
    .map_err(db_error)?;
    Ok(())
}

/// Forgets the lifecycle state of a blob that a write replaced.
pub(super) fn clear(db: &Connection, key: &BlobKey) -> Result<()> {
    let [account, container, name] = blob_params(key);
    db.prepare_cached("DELETE FROM blob_lifecycle WHERE account=?1 AND container=?2 AND name=?3")
        .map_err(db_error)?
        .execute(params![account, container, name])
        .map_err(db_error)?;
    Ok(())
}

fn blob_key(account: &str, container: &str, name: &str) -> Option<BlobKey> {
    Some(BlobKey {
        container: ContainerKey {
            account: AccountName::parse(account).ok()?,
            name: ContainerName::parse(container).ok()?,
        },
        path: BlobPath::parse(name.to_owned()).ok()?,
    })
}

/// Removes expired blobs and soft-deleted containers whose retention ended. Runs
/// before each metadata action, so the action never sees them.
pub(super) fn sweep(db: &mut Connection, mode: &Mode, now: i64) -> Result<()> {
    super::deleted_containers::purge(db, mode, now)?;
    let due: Vec<(String, String, String)> = {
        let mut query = db
            .prepare_cached(
                "SELECT account, container, name FROM blob_lifecycle
                 WHERE expires_at IS NOT NULL AND expires_at <= ?1
                   AND instr(container, '~')=0 LIMIT 100",
            )
            .map_err(db_error)?;
        query
            .query_map([now], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(db_error)?
            .collect::<rusqlite::Result<_>>()
            .map_err(db_error)?
    };
    if due.is_empty() {
        return Ok(());
    }
    let tx = db.transaction().map_err(db_error)?;
    let mut released = Vec::new();
    for (account, container, name) in due {
        let Some(key) = blob_key(&account, &container, &name) else {
            clear_raw(&tx, &account, &container, &name)?;
            continue;
        };
        match blob(&tx, &key, now)? {
            Some(row) => snapshots::expire(&tx, mode, &key, &row, now, &mut released)?,
            None => clear(&tx, &key)?,
        }
    }
    tx.commit().map_err(db_error)?;
    snapshots::release(db, mode, &released);
    Ok(())
}

fn clear_raw(db: &Connection, account: &str, container: &str, name: &str) -> Result<()> {
    db.execute(
        "DELETE FROM blob_lifecycle WHERE account=?1 AND container=?2 AND name=?3",
        params![account, container, name],
    )
    .map_err(db_error)?;
    Ok(())
}

impl Store {
    /// Set Blob Expiry: sets, moves, or removes the deadline after which the blob is gone.
    pub(crate) async fn set_expiry(
        &self,
        key: BlobKey,
        option: ExpiryOption,
        guard: Guard,
    ) -> Result<Entity> {
        self.run(move |db, _, now| {
            let tx = db.transaction().map_err(db_error)?;
            let row = require_blob(&tx, &key, now)?;
            row.lease
                .check(guard.lease, LeaseNeed::Required, LeaseOwner::Blob, now)?;
            let mut lifecycle = row.info.lifecycle;
            lifecycle.expires = option.deadline(row.info.created, now)?;
            write(&tx, &key, &lifecycle)?;
            tx.commit().map_err(db_error)?;
            Ok(row.info.entity)
        })
        .await
    }
}
