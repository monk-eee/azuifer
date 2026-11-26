//! Share soft delete (ADR-0026). With `--share-retention-days` above zero, Delete Share keeps the
//! share, its snapshots and its permissions under a hidden name that no valid share name can
//! take, so every query by name misses them and the name is free at once. Restore Share renames
//! them back. Retention is evaluated lazily on the injected clock: expired shares are erased
//! before the next action that lists, restores or deletes shares.

use super::{Store, content, db_error, shares::load_share_by_name};
use crate::{
    domain::AccountName,
    files::{
        error::{Error, Result},
        model::{DeletedShare, ShareInfo},
    },
};
use rusqlite::{Connection, params};
use std::sync::atomic::Ordering;

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS deleted_shares (
    account TEXT NOT NULL, hidden TEXT NOT NULL, name TEXT NOT NULL, version INTEGER NOT NULL,
    deleted_at INTEGER NOT NULL, expires INTEGER NOT NULL,
    PRIMARY KEY (account, hidden), UNIQUE (account, name, version)
) STRICT;";

pub(super) const HIDDEN_PREFIX: &str = "$deleted/";
const DAY_MILLIS: i64 = 86_400_000;
/// A deleted share sorts after every snapshot of its name in a listing, in version order.
pub(crate) const DELETED_KEY_BASE: i64 = i64::MAX / 2;

impl Store {
    /// Sets how many days a deleted share stays restorable; zero deletes at once.
    pub(crate) fn set_share_retention_days(&self, days: u32) {
        self.0.env.retention_days.store(days, Ordering::Relaxed);
    }
}

pub(super) fn retention_days(env: &super::Env) -> u32 {
    env.retention_days.load(Ordering::Relaxed)
}

/// Moves a live share and its snapshots under a hidden name. The caller has already checked
/// leases and snapshot policy.
pub(super) fn keep(tx: &Connection, account: &str, name: &str, now: i64, days: u32) -> Result<()> {
    let mut version = now;
    while tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM deleted_shares WHERE account=?1 AND name=?2 AND version=?3)",
            params![account, name, version],
            |row| row.get::<_, bool>(0),
        )
        .map_err(db_error)?
    {
        version += 1;
    }
    let hidden = format!("{HIDDEN_PREFIX}{version}/{name}");
    tx.execute(
        "UPDATE shares SET name=?3, lease=NULL WHERE account=?1 AND name=?2",
        params![account, name, hidden],
    )
    .map_err(db_error)?;
    tx.execute(
        "UPDATE permissions SET share=?3 WHERE account=?1 AND share=?2",
        params![account, name, hidden],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO deleted_shares (account, hidden, name, version, deleted_at, expires)
         VALUES (?1, ?3, ?2, ?4, ?5, ?6)",
        params![
            account,
            name,
            hidden,
            version,
            now,
            now + i64::from(days) * DAY_MILLIS
        ],
    )
    .map_err(db_error)?;
    Ok(())
}

/// Erases the deleted shares whose retention ended.
pub(super) fn sweep(db: &mut Connection, env: &super::Env, now: i64) -> Result<()> {
    let tx = db.transaction().map_err(db_error)?;
    let expired = {
        let mut query = tx
            .prepare("SELECT account, hidden FROM deleted_shares WHERE expires <= ?1")
            .map_err(db_error)?;
        query
            .query_map([now], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(db_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db_error)?
    };
    if expired.is_empty() {
        return Ok(());
    }
    let mut reclaim = content::Reclaim::default();
    for (account, hidden) in expired {
        let ids = {
            let mut query = tx
                .prepare("SELECT id FROM shares WHERE account=?1 AND name=?2")
                .map_err(db_error)?;
            query
                .query_map(params![account, hidden], |row| row.get::<_, i64>(0))
                .map_err(db_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db_error)?
        };
        for id in ids {
            reclaim.add_stored(&tx, id, None)?;
            tx.execute("DELETE FROM shares WHERE id=?1", [id])
                .map_err(db_error)?;
        }
        tx.execute(
            "DELETE FROM permissions WHERE account=?1 AND share=?2",
            params![account, hidden],
        )
        .map_err(db_error)?;
        tx.execute(
            "DELETE FROM deleted_shares WHERE account=?1 AND hidden=?2",
            params![account, hidden],
        )
        .map_err(db_error)?;
    }
    let free = reclaim.finish(&tx, &env.mode)?;
    tx.commit().map_err(db_error)?;
    content::discard(env, &free);
    Ok(())
}

/// The live row of every deleted share of the account whose name starts with `prefix`, with
/// its sort key in a listing.
pub(super) fn listed(
    db: &Connection,
    account: &str,
    prefix: &str,
    now: i64,
) -> Result<Vec<(ShareInfo, i64)>> {
    let deleted = {
        let mut query = db
            .prepare(
                "SELECT hidden, name, version, deleted_at, expires FROM deleted_shares
                 WHERE account=?1 AND instr(name, ?2)=1",
            )
            .map_err(db_error)?;
        query
            .query_map(params![account, prefix], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(db_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db_error)?
    };
    let mut listed = Vec::new();
    for (hidden, name, version, deleted_at, expires) in deleted {
        let Some(mut info) = load_share_by_name(db, account, &hidden)? else {
            continue;
        };
        info.name = name;
        info.deleted = Some(DeletedShare {
            version: version.to_string(),
            deleted_at,
            remaining_days: u32::try_from(((expires - now).max(0) + DAY_MILLIS - 1) / DAY_MILLIS)
                .unwrap_or(u32::MAX),
        });
        listed.push((info, DELETED_KEY_BASE + version));
    }
    Ok(listed)
}
impl Store {
    /// Restores a deleted share under `destination`, which must be free.
    pub(crate) async fn restore_share(
        &self,
        account: AccountName,
        deleted_name: String,
        version: String,
        destination: String,
    ) -> Result<ShareInfo> {
        self.run(move |db, env| {
            sweep(db, env, env.clock.now_millis())?;
            let tx = db.transaction().map_err(db_error)?;
            let version: i64 = version.parse().map_err(|_| Error::ShareNotFound)?;
            let hidden: String = tx
                .query_row(
                    "SELECT hidden FROM deleted_shares WHERE account=?1 AND name=?2 AND version=?3",
                    params![account.as_str(), deleted_name, version],
                    |row| row.get(0),
                )
                .map_err(|_| Error::ShareNotFound)?;
            if load_share_by_name(&tx, account.as_str(), &destination)?.is_some() {
                return Err(Error::ShareAlreadyExists);
            }
            tx.execute(
                "UPDATE shares SET name=?3 WHERE account=?1 AND name=?2",
                params![account.as_str(), hidden, destination],
            )
            .map_err(db_error)?;
            tx.execute(
                "UPDATE permissions SET share=?3 WHERE account=?1 AND share=?2",
                params![account.as_str(), hidden, destination],
            )
            .map_err(db_error)?;
            tx.execute(
                "DELETE FROM deleted_shares WHERE account=?1 AND hidden=?2",
                params![account.as_str(), hidden],
            )
            .map_err(db_error)?;
            let info = load_share_by_name(&tx, account.as_str(), &destination)?
                .ok_or(Error::ShareNotFound)?;
            tx.commit().map_err(db_error)?;
            Ok(info)
        })
        .await
    }
}
