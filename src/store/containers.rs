use super::{
    Store, db_error, entity_row, internal, lease_row, metadata_column, new_entity, reclaim,
    sqlite_int, write_lease,
};
use crate::{
    conditions::Guard,
    domain::{
        AccountName, ContainerCreate, ContainerInfo, ContainerKey, Entity, Error, Metadata, Page,
        PageRequest, PublicAccess, Result, SignedIdentifier,
    },
    lease::{LeaseAction, LeaseId, LeaseNeed, LeaseOwner, StoredLease},
};
use rusqlite::{Connection, OptionalExtension as _, Row, params};
use uuid::Uuid;

const CONTAINER_COLUMNS: &str = "id, modified, COALESCE(etag, id), metadata, public_access, acl, lease_id, lease_state, lease_duration, lease_expiry";

pub(crate) struct LeaseResult {
    pub(crate) entity: Entity,
    pub(crate) id: Option<LeaseId>,
    pub(crate) break_seconds: Option<u32>,
}

pub(super) struct ContainerRow {
    pub(super) info: ContainerInfo,
    pub(super) lease: StoredLease,
}

fn container_row(row: &Row<'_>, now: i64) -> rusqlite::Result<ContainerRow> {
    let public: String = row.get(4)?;
    let acl: String = row.get(5)?;
    let identifiers = serde_json::from_str(&acl).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let lease = lease_row(row, 6)?;
    Ok(ContainerRow {
        info: ContainerInfo {
            entity: entity_row(row)?,
            metadata: metadata_column(row, 3)?,
            public_access: PublicAccess::parse(&public).unwrap_or_default(),
            identifiers,
            lease: lease.view(now),
        },
        lease,
    })
}

pub(super) fn require_container(
    db: &Connection,
    key: &ContainerKey,
    now: i64,
) -> Result<ContainerRow> {
    db.query_row(
        &format!("SELECT {CONTAINER_COLUMNS} FROM containers WHERE account=?1 AND name=?2"),
        params![key.account.as_str(), key.name.as_str()],
        |row| container_row(row, now),
    )
    .optional()
    .map_err(db_error)?
    .ok_or(Error::ContainerMissing)
}

fn touch(db: &Connection, key: &ContainerKey, now: i64) -> Result<Entity> {
    let entity = new_entity(now)?;
    db.execute(
        "UPDATE containers SET etag=?1, modified=?2 WHERE account=?3 AND name=?4",
        params![
            entity.id,
            sqlite_int(entity.modified)?,
            key.account.as_str(),
            key.name.as_str()
        ],
    )
    .map_err(db_error)?;
    Ok(entity)
}

fn lease_guard(row: &ContainerRow, guard: &Guard, need: LeaseNeed, now: i64) -> Result<()> {
    row.lease
        .check(guard.lease, need, LeaseOwner::Container, now)?;
    guard.conditions.check(Some(row.info.entity), false)
}

impl Store {
    pub(crate) async fn create_container(
        &self,
        key: ContainerKey,
        options: ContainerCreate,
    ) -> Result<Entity> {
        self.run(move |db, _, now| {
            let entity = new_entity(now)?;
            let metadata = serde_json::to_string(&options.metadata)
                .map_err(|_| internal("could not encode metadata"))?;
            let changed = db
                .execute(
                    "INSERT INTO containers (account, name, id, modified, etag, metadata, public_access)
                     VALUES (?1, ?2, ?3, ?4, ?3, ?5, ?6) ON CONFLICT(account, name) DO NOTHING",
                    params![
                        key.account.as_str(),
                        key.name.as_str(),
                        entity.id,
                        sqlite_int(entity.modified)?,
                        metadata,
                        options.public_access.name().unwrap_or_default(),
                    ],
                )
                .map_err(db_error)?;
            if changed == 0 {
                return Err(Error::ContainerExists);
            }
            Ok(entity)
        })
        .await
    }

    /// Container properties with an optional lease id that must match an active lease.
    pub(crate) async fn container(
        &self,
        key: ContainerKey,
        lease: Option<LeaseId>,
    ) -> Result<ContainerInfo> {
        self.run(move |db, _, now| {
            let row = require_container(db, &key, now)?;
            row.lease
                .check(lease, LeaseNeed::Optional, LeaseOwner::Container, now)?;
            Ok(row.info)
        })
        .await
    }

    /// Public access and stored access policies, read by authorization without a lease check.
    pub(crate) async fn container_access(
        &self,
        key: ContainerKey,
    ) -> Result<(PublicAccess, Vec<SignedIdentifier>)> {
        self.run(move |db, _, now| {
            let info = require_container(db, &key, now)?.info;
            Ok((info.public_access, info.identifiers))
        })
        .await
    }

    pub(crate) async fn set_container_metadata(
        &self,
        key: ContainerKey,
        metadata: Metadata,
        guard: Guard,
    ) -> Result<Entity> {
        self.run(move |db, _, now| {
            let tx = db.transaction().map_err(db_error)?;
            let row = require_container(&tx, &key, now)?;
            lease_guard(&row, &guard, LeaseNeed::Optional, now)?;
            let json = serde_json::to_string(&metadata)
                .map_err(|_| internal("could not encode metadata"))?;
            let entity = touch(&tx, &key, now)?;
            tx.execute(
                "UPDATE containers SET metadata=?1 WHERE account=?2 AND name=?3",
                params![json, key.account.as_str(), key.name.as_str()],
            )
            .map_err(db_error)?;
            tx.commit().map_err(db_error)?;
            Ok(entity)
        })
        .await
    }

    pub(crate) async fn set_container_acl(
        &self,
        key: ContainerKey,
        public_access: PublicAccess,
        identifiers: Vec<SignedIdentifier>,
        guard: Guard,
    ) -> Result<Entity> {
        self.run(move |db, _, now| {
            let tx = db.transaction().map_err(db_error)?;
            let row = require_container(&tx, &key, now)?;
            lease_guard(&row, &guard, LeaseNeed::Optional, now)?;
            let json = serde_json::to_string(&identifiers)
                .map_err(|_| internal("could not encode access policies"))?;
            let entity = touch(&tx, &key, now)?;
            tx.execute(
                "UPDATE containers SET public_access=?1, acl=?2 WHERE account=?3 AND name=?4",
                params![
                    public_access.name().unwrap_or_default(),
                    json,
                    key.account.as_str(),
                    key.name.as_str()
                ],
            )
            .map_err(db_error)?;
            tx.commit().map_err(db_error)?;
            Ok(entity)
        })
        .await
    }

    pub(crate) async fn lease_container(
        &self,
        key: ContainerKey,
        action: LeaseAction,
        guard: Guard,
    ) -> Result<LeaseResult> {
        self.run(move |db, _, now| {
            let tx = db.transaction().map_err(db_error)?;
            let row = require_container(&tx, &key, now)?;
            guard.conditions.check(Some(row.info.entity), false)?;
            let outcome = row.lease.apply(action, now)?;
            write_lease(
                &tx,
                "containers",
                &[key.account.as_str(), key.name.as_str()],
                &outcome.lease,
            )?;
            tx.commit().map_err(db_error)?;
            Ok(LeaseResult {
                entity: row.info.entity,
                id: outcome.id,
                break_seconds: outcome.break_seconds,
            })
        })
        .await
    }

    pub(crate) async fn delete_container(&self, key: ContainerKey, guard: Guard) -> Result<()> {
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            let row = require_container(&tx, &key, now)?;
            lease_guard(&row, &guard, LeaseNeed::Required, now)?;
            let values = params![key.account.as_str(), key.name.as_str()];
            let ids = if matches!(mode, super::Mode::Disk { .. }) {
                let mut statement = tx
                    .prepare("SELECT id FROM blobs WHERE account=?1 AND container=?2
                              UNION ALL SELECT id FROM staged_blocks WHERE account=?1 AND container=?2")
                    .map_err(db_error)?;
                statement
                    .query_map(values, |row| row.get::<_, Uuid>(0))
                    .map_err(db_error)?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(db_error)?
            } else {
                Vec::new()
            };
            tx.execute(
                "DELETE FROM containers WHERE account=?1 AND name=?2",
                values,
            )
            .map_err(db_error)?;
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
    ) -> Result<Page<ContainerInfo>> {
        self.run(move |db, _, now| {
            let mut query = db
                .prepare(&format!(
                    "SELECT {CONTAINER_COLUMNS}, name FROM containers
                     WHERE account=?1 AND name>?2 AND instr(name, ?3)=1 ORDER BY name LIMIT ?4"
                ))
                .map_err(db_error)?;
            let rows = query
                .query_map(
                    params![account.as_str(), page.after, page.prefix, page.limit + 1],
                    |row| Ok((row.get(10)?, container_row(row, now)?.info)),
                )
                .map_err(db_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db_error)?;
            Ok(Page::from_rows(rows, page.limit))
        })
        .await
    }
}
