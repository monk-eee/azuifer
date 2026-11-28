//! Immutability policies and legal holds on the current blob, retained versions,
//! and snapshots (ADR-0022, ADR-0039). A protected state refuses deletes (and
//! in-place writes on non-versioned accounts), and a container holding any
//! protected current blob, version, or snapshot cannot be deleted.

use super::{BlobRow, Store, blob, blob_params, db_error, require_blob, snapshots};
use crate::{
    blob_immutability::{PolicyMode, PolicyRequest, Protection},
    blob_lifecycle::LifecycleError,
    blob_snapshot::Selector,
    conditions::Guard,
    domain::{BlobKey, ContainerKey, Entity, Error, Result},
    stamp::Ticks,
};
use rusqlite::{Connection, OptionalExtension as _, params};

enum Target {
    Current(Box<BlobRow>),
    History {
        kind: i64,
        state: Ticks,
        entity: Entity,
        protection: Protection,
    },
}

impl Target {
    fn entity(&self) -> Entity {
        match self {
            Self::Current(row) => row.info.entity,
            Self::History { entity, .. } => *entity,
        }
    }

    fn protection(&self) -> Protection {
        match self {
            Self::Current(row) => row.info.lifecycle.protection,
            Self::History { protection, .. } => *protection,
        }
    }
}

/// Resolves the current blob, a retained version, or a snapshot.
fn target(db: &Connection, key: &BlobKey, selector: Option<Selector>, now: i64) -> Result<Target> {
    match selector {
        None => Ok(Target::Current(Box::new(require_blob(db, key, now)?))),
        Some(Selector::Version(version)) => {
            if let Some(row) = blob(db, key, now)?
                && row.info.entity.version == Some(version)
            {
                return Ok(Target::Current(Box::new(row)));
            }
            let row = snapshots::find_version(db, key, version, now)?
                .ok_or_else(|| snapshots::missing(db, key))?;
            Ok(Target::History {
                kind: 2,
                state: version,
                entity: row.info.entity,
                protection: row.info.lifecycle.protection,
            })
        }
        Some(Selector::Snapshot(time)) => {
            let row = snapshots::find_snapshot(db, key, time, now)?
                .ok_or_else(|| snapshots::missing(db, key))?;
            Ok(Target::History {
                kind: 1,
                state: time,
                entity: row.info.entity,
                protection: row.info.lifecycle.protection,
            })
        }
    }
}

fn protection_error(held: Option<i64>) -> Result<()> {
    match held {
        None => Ok(()),
        Some(0) => Err(Error::Ext(LifecycleError::ImmutableDueToPolicy)),
        Some(_) => Err(Error::Ext(LifecycleError::ImmutableDueToLegalHold)),
    }
}

/// Refuses to delete a container that holds any protected current blob, version,
/// or snapshot.
pub(super) fn check_container(db: &Connection, key: &ContainerKey, now: i64) -> Result<()> {
    let held: Option<i64> = db
        .query_row(
            "SELECT legal_hold FROM (
                SELECT legal_hold FROM blob_lifecycle
                WHERE account=?1 AND container=?2
                  AND (legal_hold=1 OR (immutability_mode<>'' AND immutable_until>?3))
                UNION ALL
                SELECT legal_hold FROM blob_history
                WHERE account=?1 AND container=?2 AND deleted_at IS NULL
                  AND (legal_hold=1 OR (immutability_mode<>'' AND immutable_until>?3))
             )
             ORDER BY legal_hold DESC LIMIT 1",
            params![key.account.as_str(), key.name.as_str(), now],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    protection_error(held)
}

/// Refuses `x-ms-delete-snapshots: include|only` if any live snapshot of the blob
/// is protected by a legal hold or an unexpired immutability policy.
pub(super) fn check_blob_snapshots(db: &Connection, key: &BlobKey, now: i64) -> Result<()> {
    let [account, container, name] = blob_params(key);
    let held: Option<i64> = db
        .query_row(
            "SELECT legal_hold FROM blob_history
             WHERE account=?1 AND container=?2 AND name=?3 AND kind=1 AND deleted_at IS NULL
               AND (legal_hold=1 OR (immutability_mode<>'' AND immutable_until>?4))
             ORDER BY legal_hold DESC LIMIT 1",
            params![account, container, name, now],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    protection_error(held)
}

impl Store {
    async fn change_protection<F>(
        &self,
        key: BlobKey,
        selector: Option<Selector>,
        guard: Guard,
        change: F,
    ) -> Result<Protection>
    where
        F: FnOnce(Protection, i64) -> Result<Protection> + Send + 'static,
    {
        self.run(move |db, _, now| {
            let tx = db.transaction().map_err(db_error)?;
            let found = target(&tx, &key, selector, now)?;
            guard.conditions.check(Some(found.entity()), false)?;
            let protection = change(found.protection(), now)?;
            match found {
                Target::Current(row) => {
                    let mut lifecycle = row.info.lifecycle;
                    lifecycle.protection = protection;
                    super::expiry::write(&tx, &key, &lifecycle)?;
                }
                Target::History { kind, state, .. } => {
                    let [account, container, name] = blob_params(&key);
                    tx.execute(
                        "UPDATE blob_history
                         SET immutable_until=?1, immutability_mode=?2, legal_hold=?3
                         WHERE account=?4 AND container=?5 AND name=?6 AND kind=?7 AND state_id=?8",
                        params![
                            protection.until,
                            protection.mode.map_or("", PolicyMode::name),
                            i64::from(protection.legal_hold),
                            account,
                            container,
                            name,
                            kind,
                            state.0,
                        ],
                    )
                    .map_err(db_error)?;
                }
            }
            tx.commit().map_err(db_error)?;
            Ok(protection)
        })
        .await
    }

    pub(crate) async fn set_immutability_policy(
        &self,
        key: BlobKey,
        selector: Option<Selector>,
        request: PolicyRequest,
        guard: Guard,
    ) -> Result<Protection> {
        self.change_protection(key, selector, guard, move |current, now| {
            current.set_policy(request, now)
        })
        .await
    }

    pub(crate) async fn delete_immutability_policy(
        &self,
        key: BlobKey,
        selector: Option<Selector>,
        guard: Guard,
    ) -> Result<Protection> {
        self.change_protection(key, selector, guard, |current, now| {
            current.clear_policy(now)
        })
        .await
    }

    pub(crate) async fn set_legal_hold(
        &self,
        key: BlobKey,
        selector: Option<Selector>,
        hold: bool,
        guard: Guard,
    ) -> Result<Protection> {
        self.change_protection(key, selector, guard, move |current, _| {
            Ok(current.with_legal_hold(hold))
        })
        .await
    }
}
