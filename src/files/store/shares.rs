//! Share-level operations: lifecycle, properties, metadata, access policies, leases,
//! snapshots, and the share's permission table.

use super::{
    SHARE_COLUMNS, ShareRow, Store, content, db_error, internal, json, new_etag, share_row, to_sql,
};
use crate::{
    domain::AccountName,
    files::{
        error::{Error, Result},
        lease::{self, Action, Kind, Outcome, State, Use},
        model::{
            AccessPolicy, Attributes, FileKind, Metadata, NfsProps, NodeInfo, Posix, Protocol,
            RootSquash, ShareInfo,
        },
        name::ShareName,
        time::TICKS_PER_MILLI,
    },
};
use rusqlite::{Connection, OptionalExtension as _, params};

pub(crate) const DEFAULT_QUOTA_GIB: u64 = 5120;
pub(crate) const DEFAULT_TIER: &str = "TransactionOptimized";
const ROOT_SDDL: &str = "O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;S-1-5-21-2127521184-1604012920-1887927527-72713)";

/// What Create Share fixes about a share's protocol.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ShareOptions {
    pub(crate) protocol: Protocol,
    pub(crate) root_squash: Option<RootSquash>,
    pub(crate) snapshot_virtual_directory_access: bool,
}

impl Default for ShareOptions {
    fn default() -> Self {
        Self {
            protocol: Protocol::Smb,
            root_squash: None,
            snapshot_virtual_directory_access: true,
        }
    }
}

/// The NFS settings Set Share Properties may change.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct NfsShareSettings {
    pub(crate) root_squash: Option<RootSquash>,
    pub(crate) snapshot_virtual_directory_access: Option<bool>,
}

/// A share (or one of its snapshots) in an account.
#[derive(Clone)]
pub(crate) struct ShareRef {
    pub(crate) account: AccountName,
    pub(crate) share: ShareName,
    pub(crate) snapshot: Option<i64>,
}

impl ShareRef {
    pub(crate) fn live(&self) -> Self {
        Self {
            snapshot: None,
            ..self.clone()
        }
    }
}

pub(crate) struct ListSharesRequest {
    pub(crate) prefix: String,
    /// Continue after this `(name, snapshot)`; snapshot 0 is the live share.
    pub(crate) after: Option<(String, i64)>,
    pub(crate) limit: u32,
    pub(crate) snapshots: bool,
    pub(crate) deleted: bool,
}

/// Finds a share or snapshot, reporting a missing snapshot separately from a missing share.
pub(super) fn load_share(db: &Connection, target: &ShareRef) -> Result<ShareRow> {
    let find = |snapshot: i64| {
        db.query_row(
            &format!(
                "SELECT {SHARE_COLUMNS} FROM shares WHERE account=?1 AND name=?2 AND snapshot=?3"
            ),
            params![target.account.as_str(), target.share.as_str(), snapshot],
            share_row,
        )
        .optional()
        .map_err(db_error)
    };
    if let Some(row) = find(target.snapshot.unwrap_or(0))? {
        return Ok(row);
    }
    Err(if target.snapshot.is_some() && find(0)?.is_some() {
        Error::ShareSnapshotNotFound
    } else {
        Error::ShareNotFound
    })
}

/// The live share of this exact name, if any.
pub(super) fn load_share_by_name(
    db: &Connection,
    account: &str,
    name: &str,
) -> Result<Option<ShareInfo>> {
    db.query_row(
        &format!("SELECT {SHARE_COLUMNS} FROM shares WHERE account=?1 AND name=?2 AND snapshot=0"),
        params![account, name],
        share_row,
    )
    .optional()
    .map(|row| row.map(|row| row.info))
    .map_err(db_error)
}

/// Loads a live share for an operation that snapshots do not support.
pub(super) fn load_writable(db: &Connection, target: &ShareRef) -> Result<ShareRow> {
    if target.snapshot.is_some() {
        return Err(Error::ShareSnapshotOperationNotSupported);
    }
    load_share(db, target)
}

fn save_share(db: &Connection, row: &ShareRow) -> Result<()> {
    db.execute(
        "UPDATE shares SET etag=?2, modified=?3, quota=?4, access_tier=?5,
            access_tier_changed=?6, metadata=?7, acl=?8, lease=?9, root_squash=?10,
            snapshot_vda=?11 WHERE id=?1",
        params![
            row.id,
            row.info.etag,
            row.info.modified,
            to_sql(row.info.quota)?,
            row.info.access_tier,
            row.info.access_tier_changed,
            json(&row.info.metadata)?,
            json(&row.acl)?,
            row.info.lease.as_ref().map(json).transpose()?,
            row.info.root_squash.map(RootSquash::as_str),
            row.info.snapshot_virtual_directory_access,
        ],
    )
    .map_err(db_error)?;
    Ok(())
}

fn touch(row: &mut ShareRow, now: i64) {
    row.info.etag = new_etag();
    row.info.modified = now;
}

pub(super) fn permission_key_for(sddl: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in sddl.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!("{hash}*1")
}

/// Stores a security descriptor for the share and returns its key. The same descriptor
/// always maps to the same key.
pub(super) fn intern_permission(db: &Connection, target: &ShareRef, sddl: &str) -> Result<String> {
    let key = permission_key_for(sddl);
    db.execute(
        "INSERT OR IGNORE INTO permissions (account, share, key, sddl) VALUES (?1, ?2, ?3, ?4)",
        params![target.account.as_str(), target.share.as_str(), key, sddl],
    )
    .map_err(db_error)?;
    Ok(key)
}

pub(super) fn permission_exists(db: &Connection, target: &ShareRef, key: &str) -> Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM permissions WHERE account=?1 AND share=?2 AND key=?3)",
        params![target.account.as_str(), target.share.as_str(), key],
        |row| row.get(0),
    )
    .map_err(db_error)
}

pub(super) fn permission_sddl(db: &Connection, target: &ShareRef, key: &str) -> Result<String> {
    db.query_row(
        "SELECT sddl FROM permissions WHERE account=?1 AND share=?2 AND key=?3",
        params![target.account.as_str(), target.share.as_str(), key],
        |row| row.get(0),
    )
    .optional()
    .map_err(db_error)?
    .ok_or(Error::FileInvalidPermissionKey)
}

pub(crate) fn valid_sddl(sddl: &str) -> bool {
    !sddl.is_empty() && sddl.len() <= 8 * 1024 && sddl.starts_with("O:") && sddl.contains("D:")
}

impl Store {
    pub(crate) async fn list_shares(
        &self,
        account: AccountName,
        request: ListSharesRequest,
    ) -> Result<(Vec<ShareInfo>, Option<(String, i64)>)> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            if request.deleted {
                super::soft_delete::sweep(db, env, now)?;
            }
            let (after_name, after_snapshot) = request.after.clone().unwrap_or_default();
            let mut query = db
                .prepare(&format!(
                    "SELECT {SHARE_COLUMNS} FROM shares
                     WHERE account=?1 AND instr(name, ?2)=1 AND (?3 OR snapshot=0)
                       AND substr(name, 1, 9) <> '$deleted/'
                       AND (name > ?4 OR (name = ?4 AND snapshot > ?5))
                     ORDER BY name, snapshot LIMIT ?6"
                ))
                .map_err(db_error)?;
            let mut rows = query
                .query_map(
                    params![
                        account.as_str(),
                        request.prefix,
                        request.snapshots,
                        after_name,
                        after_snapshot,
                        request.limit + 1
                    ],
                    share_row,
                )
                .map_err(db_error)?
                .map(|row| row.map(|row| row.info))
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db_error)?;
            let key = |share: &ShareInfo| match &share.deleted {
                Some(deleted) => {
                    super::soft_delete::DELETED_KEY_BASE
                        + deleted.version.parse::<i64>().unwrap_or(0)
                }
                None => share.snapshot.unwrap_or(0),
            };
            if request.deleted {
                let after = (after_name.as_str(), after_snapshot);
                let deleted =
                    super::soft_delete::listed(db, account.as_str(), &request.prefix, now)?;
                rows.extend(
                    deleted
                        .into_iter()
                        .filter(|(info, sort)| (info.name.as_str(), *sort) > after)
                        .map(|(info, _)| info),
                );
                rows.sort_by(|a, b| (&a.name, key(a)).cmp(&(&b.name, key(b))));
            }
            let mut next = None;
            if rows.len() > request.limit as usize {
                rows.truncate(request.limit as usize);
                next = rows.last().map(|last| (last.name.clone(), key(last)));
            }
            Ok((rows, next))
        })
        .await
    }

    pub(crate) async fn create_share(
        &self,
        target: ShareRef,
        quota: Option<u64>,
        tier: Option<String>,
        metadata: Metadata,
        options: ShareOptions,
    ) -> Result<ShareInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let tier = tier.unwrap_or_else(|| DEFAULT_TIER.to_owned());
            let changed = tx
                .execute(
                    "INSERT INTO shares (account, name, snapshot, etag, modified, quota,
                        access_tier, access_tier_changed, metadata, acl, lease, next_file_id,
                        protocol, root_squash, snapshot_vda)
                     VALUES (?1, ?2, 0, ?3, ?4, ?5, ?6, ?4, ?7, '[]', NULL, 1, ?8, ?9, ?10)
                     ON CONFLICT (account, name, snapshot) DO NOTHING",
                    params![
                        target.account.as_str(),
                        target.share.as_str(),
                        new_etag(),
                        now,
                        to_sql(quota.unwrap_or(DEFAULT_QUOTA_GIB))?,
                        tier,
                        json(&metadata)?,
                        options.protocol.as_str(),
                        options.root_squash.map(RootSquash::as_str),
                        options.snapshot_virtual_directory_access,
                    ],
                )
                .map_err(db_error)?;
            if changed == 0 {
                return Err(Error::ShareAlreadyExists);
            }
            let id = tx.last_insert_rowid();
            let key = intern_permission(&tx, &target, ROOT_SDDL)?;
            let root = NodeInfo {
                file_id: 0,
                parent_id: None,
                directory: true,
                name: String::new(),
                etag: new_etag(),
                modified: now,
                attributes: Attributes::DIRECTORY,
                creation: now * TICKS_PER_MILLI,
                last_write: now * TICKS_PER_MILLI,
                change: now * TICKS_PER_MILLI,
                permission_key: key,
                metadata: Metadata::new(),
                length: 0,
                http: Default::default(),
                lease: None,
                copy: None,
                nfs: (options.protocol == Protocol::Nfs)
                    .then(|| NfsProps::create(FileKind::Directory, Posix::default(), None)),
                links: 1,
                entry: None,
            };
            tx.execute(
                "INSERT INTO nodes (share_id, file_id, parent_id, name, key, is_dir, etag,
                    modified, attributes, creation, last_write, change_time, permission_key,
                    metadata, length, content_type)
                 VALUES (?1, 0, NULL, '', '', 1, '', 0, 0, 0, 0, 0, '', '{}', 0, '')",
                [id],
            )
            .map_err(db_error)?;
            super::save_node(&tx, id, &root)?;
            let row = load_share(&tx, &target)?;
            tx.commit().map_err(db_error)?;
            Ok(row.info)
        })
        .await
    }

    pub(crate) async fn share(&self, target: ShareRef) -> Result<ShareInfo> {
        self.run(move |db, _| Ok(load_share(db, &target)?.info))
            .await
    }

    /// Allocated bytes in the share, the usage `Get Share Stats` reports.
    pub(crate) async fn share_usage(&self, target: ShareRef) -> Result<u64> {
        self.run(move |db, _| {
            let id = load_share(db, &target)?.id;
            let bytes: i64 = db
                .query_row(
                    "SELECT COALESCE(SUM(length), 0) FROM ranges WHERE share_id=?1",
                    [id],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            super::from_sql(bytes)
        })
        .await
    }

    pub(crate) async fn set_share_properties(
        &self,
        target: ShareRef,
        lease_id: Option<String>,
        quota: Option<u64>,
        tier: Option<String>,
        nfs: NfsShareSettings,
    ) -> Result<ShareInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let mut row = load_writable(db, &target)?;
            lease::check_use(
                Kind::Share,
                row.info.lease.as_ref(),
                now,
                lease_id.as_deref(),
                Use::Write,
            )?;
            if row.info.protocol != Protocol::Nfs && nfs != NfsShareSettings::default() {
                return Err(Error::InvalidHeaderValue);
            }
            if let Some(quota) = quota {
                row.info.quota = quota;
            }
            if let Some(tier) = tier {
                if tier != row.info.access_tier {
                    row.info.access_tier_changed = now;
                }
                row.info.access_tier = tier;
            }
            if let Some(squash) = nfs.root_squash {
                row.info.root_squash = Some(squash);
            }
            if let Some(access) = nfs.snapshot_virtual_directory_access {
                row.info.snapshot_virtual_directory_access = access;
            }
            touch(&mut row, now);
            save_share(db, &row)?;
            Ok(row.info)
        })
        .await
    }

    pub(crate) async fn set_share_metadata(
        &self,
        target: ShareRef,
        lease_id: Option<String>,
        metadata: Metadata,
    ) -> Result<ShareInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let mut row = load_writable(db, &target)?;
            lease::check_use(
                Kind::Share,
                row.info.lease.as_ref(),
                now,
                lease_id.as_deref(),
                Use::Write,
            )?;
            row.info.metadata = metadata;
            touch(&mut row, now);
            save_share(db, &row)?;
            Ok(row.info)
        })
        .await
    }

    pub(crate) async fn share_acl(
        &self,
        target: ShareRef,
    ) -> Result<(ShareInfo, Vec<AccessPolicy>)> {
        self.run(move |db, _| {
            let row = load_writable(db, &target)?;
            Ok((row.info, row.acl))
        })
        .await
    }

    pub(crate) async fn set_share_acl(
        &self,
        target: ShareRef,
        lease_id: Option<String>,
        policies: Vec<AccessPolicy>,
    ) -> Result<ShareInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let mut row = load_writable(db, &target)?;
            lease::check_use(
                Kind::Share,
                row.info.lease.as_ref(),
                now,
                lease_id.as_deref(),
                Use::Write,
            )?;
            row.acl = policies;
            touch(&mut row, now);
            save_share(db, &row)?;
            Ok(row.info)
        })
        .await
    }

    /// Deletes a share with all its content, or one snapshot when `target.snapshot` is set.
    pub(crate) async fn delete_share(
        &self,
        target: ShareRef,
        lease_id: Option<String>,
        snapshot_policy: SnapshotPolicy,
    ) -> Result<()> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            super::soft_delete::sweep(db, env, now)?;
            let tx = db.transaction().map_err(db_error)?;
            let row = load_share(&tx, &target)?;
            lease::check_use(
                Kind::Share,
                row.info.lease.as_ref(),
                now,
                lease_id.as_deref(),
                Use::Delete,
            )?;
            let mut doomed = vec![row.id];
            if target.snapshot.is_none() {
                let mut query = tx
                    .prepare(
                        "SELECT id, lease FROM shares WHERE account=?1 AND name=?2 AND snapshot<>0",
                    )
                    .map_err(db_error)?;
                let snapshots = query
                    .query_map(
                        params![target.account.as_str(), target.share.as_str()],
                        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?)),
                    )
                    .map_err(db_error)?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(db_error)?;
                drop(query);
                if !snapshots.is_empty() && snapshot_policy == SnapshotPolicy::Refuse {
                    return Err(Error::ShareHasSnapshots);
                }
                for (id, stored) in snapshots {
                    let held = stored
                        .map(|text| serde_json::from_str::<lease::Lease>(&text))
                        .transpose()
                        .map_err(|_| internal("stored lease is not valid"))?;
                    let locked = matches!(
                        lease::state(held.as_ref(), now),
                        State::Leased | State::Breaking
                    );
                    if locked && snapshot_policy != SnapshotPolicy::IncludeLeased {
                        return Err(Error::DeleteShareWhenSnapshotLeased);
                    }
                    doomed.push(id);
                }
            }
            let days = super::soft_delete::retention_days(env);
            if target.snapshot.is_none() && days > 0 {
                super::soft_delete::keep(
                    &tx,
                    target.account.as_str(),
                    target.share.as_str(),
                    now,
                    days,
                )?;
                tx.commit().map_err(db_error)?;
                return Ok(());
            }
            let mut reclaim = content::Reclaim::default();
            for id in &doomed {
                reclaim.add_stored(&tx, *id, None)?;
                tx.execute("DELETE FROM shares WHERE id=?1", [id])
                    .map_err(db_error)?;
            }
            if target.snapshot.is_none() {
                tx.execute(
                    "DELETE FROM permissions WHERE account=?1 AND share=?2",
                    params![target.account.as_str(), target.share.as_str()],
                )
                .map_err(db_error)?;
            }
            let free = reclaim.finish(&tx, &env.mode)?;
            tx.commit().map_err(db_error)?;
            content::discard(env, &free);
            Ok(())
        })
        .await
    }

    pub(crate) async fn lease_share(
        &self,
        target: ShareRef,
        action: LeaseRequest,
    ) -> Result<(ShareInfo, Outcome)> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let mut row = load_share(db, &target)?;
            let (stored, outcome) = lease::apply(
                Kind::Share,
                row.info.lease.as_ref(),
                now,
                action.as_action(),
                || uuid::Uuid::new_v4().hyphenated().to_string(),
            )?;
            row.info.lease = stored;
            save_share(db, &row)?;
            Ok((row.info, outcome))
        })
        .await
    }

    /// Takes a read-only point-in-time copy of the live share. File content is shared by
    /// extent reference, not copied.
    pub(crate) async fn snapshot_share(
        &self,
        target: ShareRef,
        metadata: Option<Metadata>,
    ) -> Result<ShareInfo> {
        self.run(move |db, env| {
            let tx = db.transaction().map_err(db_error)?;
            let live = load_writable(&tx, &target)?;
            let mut snapshot = env.clock.now_millis();
            while tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM shares WHERE account=?1 AND name=?2 AND snapshot=?3)",
                    params![target.account.as_str(), target.share.as_str(), snapshot],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(db_error)?
            {
                snapshot += 1;
            }
            tx.execute(
                "INSERT INTO shares (account, name, snapshot, etag, modified, quota, access_tier,
                    access_tier_changed, metadata, acl, lease, next_file_id, protocol,
                    root_squash, snapshot_vda)
                 SELECT account, name, ?2, etag, modified, quota, access_tier,
                    access_tier_changed, ?3, acl, NULL, next_file_id, protocol,
                    root_squash, snapshot_vda FROM shares WHERE id=?1",
                params![
                    live.id,
                    snapshot,
                    json(metadata.as_ref().unwrap_or(&live.info.metadata))?
                ],
            )
            .map_err(db_error)?;
            let copy = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO nodes (share_id, file_id, parent_id, name, key, is_dir, etag,
                    modified, attributes, creation, last_write, change_time, permission_key,
                    metadata, length, content_type, content_encoding, content_language,
                    content_disposition, cache_control, md5, lease, copy, mode, owner, grp,
                    file_type, link_text)
                 SELECT ?2, file_id, parent_id, name, key, is_dir, etag, modified,
                    attributes, creation, last_write, change_time, permission_key, metadata,
                    length, content_type, content_encoding, content_language, content_disposition,
                    cache_control, md5, NULL, copy, mode, owner, grp, file_type, link_text
                 FROM nodes WHERE share_id=?1",
                params![live.id, copy],
            )
            .map_err(db_error)?;
            tx.execute(
                "INSERT INTO links (share_id, entry_id, file_id, parent_id, name, key)
                 SELECT ?2, entry_id, file_id, parent_id, name, key FROM links WHERE share_id=?1",
                params![live.id, copy],
            )
            .map_err(db_error)?;
            tx.execute(
                "INSERT INTO ranges SELECT ?2, file_id, offset, length, extent, extent_offset
                 FROM ranges WHERE share_id=?1",
                params![live.id, copy],
            )
            .map_err(db_error)?;
            let row = load_share(
                &tx,
                &ShareRef {
                    snapshot: Some(snapshot),
                    ..target
                },
            )?;
            tx.commit().map_err(db_error)?;
            Ok(row.info)
        })
        .await
    }

    pub(crate) async fn create_permission(&self, target: ShareRef, sddl: String) -> Result<String> {
        self.run(move |db, _| {
            load_share(db, &target.live())?;
            if !valid_sddl(&sddl) {
                return Err(Error::FileInvalidPermission);
            }
            intern_permission(db, &target, &sddl)
        })
        .await
    }

    pub(crate) async fn permission(&self, target: ShareRef, key: String) -> Result<String> {
        self.run(move |db, _| {
            load_share(db, &target.live())?;
            permission_sddl(db, &target, &key)
        })
        .await
    }
}

/// What Delete Share does with the share's snapshots (`x-ms-delete-snapshots`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SnapshotPolicy {
    Refuse,
    Include,
    IncludeLeased,
}

/// A requested share lease action with typed, validated arguments.
pub(crate) enum LeaseRequest {
    Acquire {
        duration: i64,
        proposed: Option<String>,
    },
    Renew(String),
    Change {
        id: String,
        proposed: String,
    },
    Release(String),
    Break(Option<i64>),
}

impl LeaseRequest {
    pub(super) fn as_action(&self) -> Action<'_> {
        match self {
            Self::Acquire { duration, proposed } => Action::Acquire {
                duration: *duration,
                proposed: proposed.as_deref(),
            },
            Self::Renew(id) => Action::Renew { id },
            Self::Change { id, proposed } => Action::Change { id, proposed },
            Self::Release(id) => Action::Release { id },
            Self::Break(period) => Action::Break { period: *period },
        }
    }
}
