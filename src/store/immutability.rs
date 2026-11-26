//! Immutability policies and legal holds of the current blob. A protected blob
//! refuses writes and deletes through `guard_write` and `guard_delete`; a
//! container that holds a protected blob cannot be deleted.

use super::{BlobRow, Store, db_error, require_blob};
use crate::{
    blob_immutability::{PolicyRequest, Protection},
    blob_lifecycle::LifecycleError,
    blob_snapshot::Selector,
    conditions::Guard,
    domain::{BlobKey, ContainerKey, Error, Result},
};
use rusqlite::{Connection, OptionalExtension as _, params};

/// The blob an operation addresses. Only the current blob (or the version that is
/// current) carries a policy here; snapshots and older versions answer `NotImplemented`.
fn target(db: &Connection, key: &BlobKey, selector: Option<Selector>, now: i64) -> Result<BlobRow> {
    let row = require_blob(db, key, now)?;
    match selector {
        None => Ok(row),
        Some(Selector::Version(version)) if row.info.entity.version == Some(version) => Ok(row),
        Some(_) => Err(Error::Unsupported),
    }
}

/// Refuses to delete a container that holds a legal hold or an unexpired policy.
pub(super) fn check_container(db: &Connection, key: &ContainerKey, now: i64) -> Result<()> {
    let held: Option<i64> = db
        .query_row(
            "SELECT legal_hold FROM blob_lifecycle
             WHERE account=?1 AND container=?2
               AND (legal_hold=1 OR (immutability_mode<>'' AND immutable_until>?3))
             ORDER BY legal_hold DESC LIMIT 1",
            params![key.account.as_str(), key.name.as_str(), now],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    match held {
        None => Ok(()),
        Some(0) => Err(Error::Ext(LifecycleError::ImmutableDueToPolicy)),
        Some(_) => Err(Error::Ext(LifecycleError::ImmutableDueToLegalHold)),
    }
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
            let row = target(&tx, &key, selector, now)?;
            guard.conditions.check(Some(row.info.entity), false)?;
            let protection = change(row.info.lifecycle.protection, now)?;
            let mut lifecycle = row.info.lifecycle;
            lifecycle.protection = protection;
            super::expiry::write(&tx, &key, &lifecycle)?;
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
