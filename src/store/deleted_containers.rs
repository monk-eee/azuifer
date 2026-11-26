//! Soft-deleted containers. With a `DeleteRetentionPolicy` on the account, Delete
//! Container keeps the container and everything in it under a hidden name until the
//! retention ends on the shared clock (ADR-0012), and Restore Container renames it
//! back. Expired entries are purged lazily, before the next metadata action.

use super::{
    Mode, Store,
    containers::{CONTAINER_COLUMNS, ContainerRow, container_row, erase},
    db_error,
};
use crate::{
    domain::{AccountName, ContainerInfo, ContainerKey, Entity, Error, Page, PageRequest, Result},
    stamp::Ticks,
};
use rusqlite::{Connection, OptionalExtension as _, params};

const DAY_MS: i64 = 86_400_000;

/// The hidden name of a deleted container. It contains `~`, which no container
/// name may, so listings and tag searches skip it with that one test.
const HIDDEN: &str = "~";

/// A soft-deleted container in a listing.
pub(crate) struct DeletedContainer {
    pub(crate) version: String,
    /// Deletion time in Unix seconds.
    pub(crate) deleted_at: u64,
    pub(crate) remaining_days: u64,
}

/// One entry of List Containers: a live container, or with `include=deleted` a
/// soft-deleted one.
pub(crate) struct ListedContainer {
    pub(crate) name: String,
    pub(crate) info: ContainerInfo,
    pub(crate) deleted: Option<DeletedContainer>,
}

/// Moves every row of container `from` to `to`, in one transaction. Each table that
/// has both `account` and `container` columns follows, so tables added later are
/// covered; foreign keys are checked at commit, once parents and children agree.
fn rename(tx: &Connection, account: &str, from: &str, to: &str) -> Result<()> {
    tx.execute_batch("PRAGMA defer_foreign_keys = ON")
        .map_err(db_error)?;
    tx.execute(
        "UPDATE containers SET name=?3 WHERE account=?1 AND name=?2",
        params![account, from, to],
    )
    .map_err(db_error)?;
    let mut query = tx
        .prepare(
            "SELECT m.name FROM sqlite_master m
             WHERE m.type='table' AND m.name NOT LIKE 'sqlite_%'
               AND (SELECT COUNT(*) FROM pragma_table_info(m.name)
                    WHERE name IN ('account', 'container')) = 2",
        )
        .map_err(db_error)?;
    let tables: Vec<String> = query
        .query_map([], |row| row.get(0))
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)?;
    for table in tables {
        tx.execute(
            &format!("UPDATE \"{table}\" SET container=?3 WHERE account=?1 AND container=?2"),
            params![account, from, to],
        )
        .map_err(db_error)?;
    }
    Ok(())
}

/// Hides a container for `retention` milliseconds instead of deleting it.
pub(super) fn retire(tx: &Connection, key: &ContainerKey, retention: i64, now: i64) -> Result<()> {
    let version = format!("{:016X}", Ticks::from_millis(now).0);
    let hidden = format!("deleted{HIDDEN}{version}{HIDDEN}{}", key.name.as_str());
    rename(tx, key.account.as_str(), key.name.as_str(), &hidden)?;
    tx.execute(
        "UPDATE containers SET lease_id=NULL, lease_state=0, lease_duration=0, lease_expiry=0
         WHERE account=?1 AND name=?2",
        params![key.account.as_str(), hidden],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO deleted_containers VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            key.account.as_str(),
            key.name.as_str(),
            version,
            hidden,
            now,
            now + retention
        ],
    )
    .map_err(db_error)?;
    Ok(())
}

/// Erases the containers whose retention ended.
pub(super) fn purge(db: &mut Connection, mode: &Mode, now: i64) -> Result<()> {
    let due: Vec<(String, String)> = {
        let mut query = db
            .prepare_cached(
                "SELECT account, hidden FROM deleted_containers WHERE expires_at <= ?1 LIMIT 50",
            )
            .map_err(db_error)?;
        query
            .query_map([now], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(db_error)?
            .collect::<rusqlite::Result<_>>()
            .map_err(db_error)?
    };
    if due.is_empty() {
        return Ok(());
    }
    let tx = db.transaction().map_err(db_error)?;
    let mut erased = Vec::new();
    for (account, hidden) in due {
        erased.push(erase(&tx, mode, &account, &hidden)?);
        tx.execute(
            "DELETE FROM deleted_containers WHERE account=?1 AND hidden=?2",
            params![account, hidden],
        )
        .map_err(db_error)?;
    }
    tx.commit().map_err(db_error)?;
    for erased in erased {
        erased.finish(mode);
    }
    Ok(())
}

fn live(db: &Connection, key: &ContainerKey) -> Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM containers WHERE account=?1 AND name=?2)",
        params![key.account.as_str(), key.name.as_str()],
        |row| row.get(0),
    )
    .map_err(db_error)
}

impl Store {
    /// List Containers with `include=deleted`: live containers and soft-deleted ones
    /// in one ordered list. The page key is the name, with the version after a
    /// character that sorts before any name character, so a marker resumes exactly.
    pub(crate) async fn list_containers_with_deleted(
        &self,
        account: AccountName,
        page: PageRequest,
    ) -> Result<Page<ListedContainer>> {
        self.run(move |db, _, now| {
            let mut query = db
                .prepare(&format!(
                    "SELECT {CONTAINER_COLUMNS}, name, name, NULL, NULL, NULL FROM containers
                      WHERE account=?1 AND instr(name, '{HIDDEN}')=0 AND name>?2
                        AND instr(name, ?3)=1
                     UNION ALL
                     SELECT {CONTAINER_COLUMNS}, d.name || char(1) || d.version, d.name, d.version,
                            d.deleted_at, d.expires_at
                       FROM containers c JOIN deleted_containers d
                         ON d.account=c.account AND d.hidden=c.name
                      WHERE d.account=?1 AND d.expires_at>?5 AND d.name || char(1) || d.version>?2
                        AND instr(d.name, ?3)=1
                     ORDER BY 11 LIMIT ?4"
                ))
                .map_err(db_error)?;
            let rows = query
                .query_map(
                    params![
                        account.as_str(),
                        page.after,
                        page.prefix,
                        page.limit + 1,
                        now
                    ],
                    |row| {
                        let ContainerRow { info, .. } = container_row(row, now)?;
                        let version: Option<String> = row.get(12)?;
                        let deleted_at: Option<i64> = row.get(13)?;
                        let expires_at: Option<i64> = row.get(14)?;
                        let deleted = version.zip(deleted_at).zip(expires_at).map(
                            |((version, at), expires)| DeletedContainer {
                                version,
                                deleted_at: u64::try_from(at / 1000).unwrap_or(0),
                                remaining_days: u64::try_from(
                                    (expires - now + DAY_MS - 1) / DAY_MS,
                                )
                                .unwrap_or(0),
                            },
                        );
                        Ok((
                            row.get::<_, String>(10)?,
                            ListedContainer {
                                name: row.get(11)?,
                                info,
                                deleted,
                            },
                        ))
                    },
                )
                .map_err(db_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db_error)?;
            Ok(Page::from_rows(rows, page.limit))
        })
        .await
    }

    /// Restore Container: renames a soft-deleted container to `dest`, which must
    /// be free. A deleted container whose retention ended is gone (404).
    pub(crate) async fn restore_container(
        &self,
        deleted_name: String,
        version: String,
        dest: ContainerKey,
    ) -> Result<Entity> {
        self.run(move |db, _, now| {
            let tx = db.transaction().map_err(db_error)?;
            let account = dest.account.as_str();
            let hidden: Option<String> = tx
                .query_row(
                    "SELECT hidden FROM deleted_containers
                     WHERE account=?1 AND name=?2 AND version=?3 AND expires_at>?4",
                    params![account, deleted_name, version, now],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            let hidden = hidden.ok_or(Error::ContainerMissing)?;
            if live(&tx, &dest)? {
                return Err(Error::ContainerExists);
            }
            rename(&tx, account, &hidden, dest.name.as_str())?;
            tx.execute(
                "DELETE FROM deleted_containers WHERE account=?1 AND hidden=?2",
                params![account, hidden],
            )
            .map_err(db_error)?;
            let entity = super::container(&tx, &dest)?;
            tx.commit().map_err(db_error)?;
            Ok(entity)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hidden_marker_cannot_appear_in_a_container_name() {
        assert!(crate::domain::ContainerName::parse(&format!("a{HIDDEN}b")).is_err());
    }
}
