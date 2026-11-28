//! Snapshots, versions, and soft-deleted blobs (ADR-0018).
//!
//! Every retained state of a blob is a `blob_history` row that references the
//! same immutable extent as the blob it came from. Disk extents are therefore
//! shared, not copied: an extent is pinned while any history row names it and is
//! deleted only once no blob, history row, or staged block references it.
//! (The in-memory backend keeps bytes in the rows, so it copies them.)

use super::{
    BLOB_COLUMN_COUNT, BlobRow, ContentSource, Download, Mode, Store, blob, blob_params, blob_row,
    blobs::read_row, check_memory_quota, container, db_error, internal, page_history, pages,
    require_blob, tags,
};
use crate::{
    blob_snapshot::Selector,
    blob_tags::Tags,
    conditions::Guard,
    domain::{
        AccountName, BlobKey, BlobRead, BlockList, BlockListKind, ContentLength, Entity, Error,
        Metadata, Result,
    },
    lease::{LeaseNeed, LeaseOwner},
    stamp::Ticks,
};
use rusqlite::{Connection, OptionalExtension as _, Row, params};
use std::{collections::HashSet, sync::Mutex};
use uuid::Uuid;

const DAY_MS: i64 = 86_400_000;

mod deletion;
mod listing;
#[cfg(test)]
mod model;
#[cfg(test)]
mod tests;

pub(crate) use deletion::Deletion;
use deletion::purge_expired;
pub(super) use deletion::{delete_current, expire, purge_at_open};
pub(crate) use listing::{ExtendedListing, Listed};

/// The ids of extents that history rows reference; the extent files stay until released.
pub(super) type Pinned = Mutex<HashSet<Uuid>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Snapshot,
    Version,
    Deleted,
}

impl Kind {
    fn code(self) -> i64 {
        match self {
            Self::Snapshot => 1,
            Self::Version => 2,
            Self::Deleted => 3,
        }
    }

    fn from_code(code: i64) -> Option<Self> {
        match code {
            1 => Some(Self::Snapshot),
            2 => Some(Self::Version),
            3 => Some(Self::Deleted),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct Tombstone {
    deleted_at: i64,
    expires_at: i64,
}

/// A history row read back as a blob, with how it is retained.
struct Retained {
    row: BlobRow,
    tombstone: Option<Tombstone>,
}

/// The first `BLOB_COLUMN_COUNT` columns match `BLOB_COLUMNS` so `blob_row` reads a
/// history row too. History rows carry no lease, so those columns are constants.
const HISTORY_BLOB: &str = "content_id, modified, etag, created, length, content_type, \
    content_encoding, content_language, content_disposition, cache_control, md5, metadata, \
    access_tier, access_tier_changed, NULL, 0, 0, 0, copy_id, copy_source, copy_completed, \
    blob_type, sequence_number, append_count, sealed";

fn retained(row: &Row<'_>, now: i64) -> rusqlite::Result<Retained> {
    let mut blob = blob_row(row, now)?;
    let at = BLOB_COLUMN_COUNT;
    let code: i64 = row.get(at)?;
    let kind = Kind::from_code(code).ok_or(rusqlite::Error::IntegralValueOutOfRange(at, code))?;
    let state = Ticks(row.get(at + 1)?);
    if kind == Kind::Version {
        blob.info.entity.version = Some(state);
    }
    let deleted_at: Option<i64> = row.get(at + 2)?;
    let expires_at: Option<i64> = row.get(at + 3)?;
    Ok(Retained {
        row: blob,
        tombstone: deleted_at
            .zip(expires_at)
            .map(|(deleted_at, expires_at)| Tombstone {
                deleted_at,
                expires_at,
            }),
    })
}

fn pin(mode: &Mode, id: Uuid) {
    if let Mode::Disk { pinned, .. } = mode {
        pinned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id);
    }
}

fn unpin(mode: &Mode, id: Uuid) {
    if let Mode::Disk { pinned, .. } = mode {
        pinned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
    }
}

pub(super) fn is_pinned(pinned: &Pinned, id: Uuid) -> bool {
    pinned
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(&id)
}

/// Pins every extent a history row references, so startup recovery and later
/// overwrites keep them (recovery itself also treats them as live).
pub(super) fn load_pins(db: &Connection, mode: &Mode) -> anyhow::Result<()> {
    if let Mode::Disk { .. } = mode {
        let mut query = db.prepare("SELECT DISTINCT content_id FROM blob_history")?;
        for id in query.query_map([], |row| row.get::<_, Uuid>(0))? {
            pin(mode, id?);
        }
    }
    Ok(())
}

/// Frees extents after a commit dropped a reference to each: history rows keep
/// them pinned; otherwise they go once no blob or staged block uses them either.
pub(super) fn release(db: &Connection, mode: &Mode, ids: &[Uuid]) {
    for id in ids {
        let used = |sql: &str| db.query_row(sql, [id], |row| row.get::<_, bool>(0));
        match used("SELECT EXISTS(SELECT 1 FROM blob_history WHERE content_id=?1)") {
            Ok(true) => continue,
            Ok(false) => unpin(mode, *id),
            Err(_) => continue,
        }
        let live = used(
            "SELECT EXISTS(SELECT 1 FROM blobs WHERE id=?1 UNION ALL SELECT 1 FROM staged_blocks WHERE id=?1
                           UNION ALL SELECT 1 FROM blob_ranges WHERE extent=?1
                           UNION ALL SELECT 1 FROM history_ranges WHERE extent=?1)",
        );
        if matches!(live, Ok(false)) {
            super::reclaim(mode, *id);
        }
    }
}

/// The extent ids a container's history rows hold, for Delete Container.
pub(super) fn history_ids(db: &Connection, account: &str, name: &str) -> Result<Vec<Uuid>> {
    let mut query = db
        .prepare("SELECT DISTINCT content_id FROM blob_history WHERE account=?1 AND container=?2")
        .map_err(db_error)?;
    query
        .query_map(params![account, name], |row| row.get(0))
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)
}

/// Forgets pins after a container's history rows were deleted by cascade.
pub(super) fn unpin_all(mode: &Mode, ids: &[Uuid]) {
    for id in ids {
        unpin(mode, *id);
    }
}

pub(super) fn is_versioned(db: &Connection, account: &str) -> Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM versioned_accounts WHERE account=?1)",
        [account],
        |row| row.get(0),
    )
    .map_err(db_error)
}

/// The soft-delete retention in milliseconds, when the account enabled it.
pub(super) fn retention(db: &Connection, account: &AccountName) -> Result<Option<i64>> {
    let policy = super::service::stored(db, account)?.delete_retention;
    Ok(policy
        .filter(|policy| policy.enabled)
        .and_then(|policy| policy.days)
        .map(|days| i64::from(days) * DAY_MS))
}

/// A timestamp no snapshot, version, or current version of this blob uses yet.
fn unique_ticks(
    db: &Connection,
    key: &BlobKey,
    start: Ticks,
    avoid: Option<Ticks>,
) -> Result<Ticks> {
    let [account, container, name] = blob_params(key);
    let mut ticks = start;
    loop {
        let taken: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM blob_history WHERE account=?1 AND container=?2
                               AND name=?3 AND kind IN (1, 2) AND state_id=?4)
                     OR EXISTS(SELECT 1 FROM blobs WHERE account=?1 AND container=?2
                               AND name=?3 AND version_id=?4)",
                params![account, container, name, ticks.0],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if !taken && avoid != Some(ticks) {
            return Ok(ticks);
        }
        ticks = Ticks(ticks.0 + 1);
    }
}

/// Copies the current blob row (and its block list) into a history row. The row
/// shares the blob's extent; the in-memory backend copies the bytes.
fn archive(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    id: Uuid,
    kind: Kind,
    state: Ticks,
    tombstone: Option<Tombstone>,
) -> Result<()> {
    let [account, container, name] = blob_params(key);
    db.execute(
        "INSERT INTO blob_history
            (account, container, name, kind, state_id, content_id, modified, etag, created, length,
             content_type, content_encoding, content_language, content_disposition, cache_control,
             md5, metadata, access_tier, access_tier_changed, copy_id, copy_source, copy_completed,
             bytes, deleted_at, expires_at, blob_type, sequence_number, append_count, sealed)
         SELECT account, container, name, ?4, ?5, id, modified, COALESCE(etag, id),
                CASE WHEN created=0 THEN modified ELSE created END, length,
                content_type, content_encoding, content_language, content_disposition, cache_control,
                md5, metadata, access_tier, access_tier_changed, copy_id, copy_source, copy_completed,
                CASE WHEN ?6 THEN bytes END, ?7, ?8, blob_type, sequence_number, append_count, sealed
         FROM blobs WHERE account=?1 AND container=?2 AND name=?3",
        params![
            account,
            container,
            name,
            kind.code(),
            state.0,
            matches!(mode, Mode::Memory { .. }),
            tombstone.map(|t| t.deleted_at),
            tombstone.map(|t| t.expires_at),
        ],
    )
    .map_err(db_error)?;
    db.execute(
        "INSERT INTO history_blocks
         SELECT account, container, name, ?4, ?5, position, block_id, offset, length
         FROM committed_blocks WHERE account=?1 AND container=?2 AND name=?3",
        params![account, container, name, kind.code(), state.0],
    )
    .map_err(db_error)?;
    page_history::archive_ranges(db, key, kind.code(), state.0)?;
    pin(mode, id);
    Ok(())
}

/// Snapshots the current blob: a history row sharing its content. Returns the snapshot time.
pub(super) fn snapshot_current(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    id: Uuid,
    now: i64,
) -> Result<Ticks> {
    let time = unique_ticks(db, key, Ticks::from_millis(now), None)?;
    archive(db, mode, key, id, Kind::Snapshot, time, None)?;
    Ok(time)
}

/// The `blob_tags.state` of a soft-deleted blob\'s tags.
const DELETED_TAGS: i64 = -1;

fn move_tags(db: &Connection, key: &BlobKey, state: Ticks) -> Result<()> {
    move_tags_to(db, key, 0, state.0)
}

fn move_tags_to(db: &Connection, key: &BlobKey, from: i64, to: i64) -> Result<()> {
    let [account, container, name] = blob_params(key);
    db.execute(
        "UPDATE blob_tags SET state=?5 WHERE account=?1 AND container=?2 AND name=?3 AND state=?4",
        params![account, container, name, from, to],
    )
    .map_err(db_error)?;
    Ok(())
}

fn drop_tags(db: &Connection, key: &BlobKey, state: i64) -> Result<()> {
    let [account, container, name] = blob_params(key);
    db.execute(
        "DELETE FROM blob_tags WHERE account=?1 AND container=?2 AND name=?3 AND state=?4",
        params![account, container, name, state],
    )
    .map_err(db_error)?;
    Ok(())
}

/// What a write changes about the blob: its content, or only properties and metadata.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Change {
    Content,
    Properties,
}

/// Runs just before a write replaces or updates the current blob row: retires
/// the old state (as a version, or as a soft-deleted snapshot of an overwrite)
/// and returns the version id the written blob receives. Callers create any
/// hierarchical-namespace parents before this, in the same transaction.
pub(super) fn begin_write(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    old: Option<&BlobRow>,
    change: Change,
    now: i64,
) -> Result<Option<Ticks>> {
    let account = &key.container.account;
    let versioned = is_versioned(db, account.as_str())?;
    let new = if versioned {
        Some(unique_ticks(db, key, Ticks::from_millis(now), None)?)
    } else {
        None
    };
    let Some(old) = old else { return Ok(new) };
    if versioned {
        let state = match old.info.entity.version {
            Some(version) => version,
            None => unique_ticks(db, key, Ticks::from_seconds(old.info.entity.modified), new)?,
        };
        archive(
            db,
            mode,
            key,
            old.info.entity.id,
            Kind::Version,
            state,
            None,
        )?;
        move_tags(db, key, state)?;
    } else if change == Change::Content
        && let Some(retention) = retention(db, account)?
    {
        let state = unique_ticks(db, key, Ticks::from_millis(now), None)?;
        let tombstone = Tombstone {
            deleted_at: now,
            expires_at: now + retention,
        };
        archive(
            db,
            mode,
            key,
            old.info.entity.id,
            Kind::Snapshot,
            state,
            Some(tombstone),
        )?;
    }
    Ok(new)
}

/// Runs right after the blob row was written: records its version id and, for a
/// content write, its tags.
pub(super) fn finish_write(
    db: &Connection,
    key: &BlobKey,
    mut entity: Entity,
    version: Option<Ticks>,
    tags: Option<&Tags>,
) -> Result<Entity> {
    let [account, container, name] = blob_params(key);
    db.execute(
        "UPDATE blobs SET version_id=?4 WHERE account=?1 AND container=?2 AND name=?3",
        params![
            account,
            container,
            name,
            version.map_or(0, |version| version.0)
        ],
    )
    .map_err(db_error)?;
    if let Some(tags) = tags {
        tags::replace(db, key, 0, tags)?;
    }
    entity.version = version;
    Ok(entity)
}

fn find(
    db: &Connection,
    key: &BlobKey,
    kind: Kind,
    state: Ticks,
    now: i64,
) -> Result<Option<Retained>> {
    let [account, container, name] = blob_params(key);
    db.query_row(
        &format!(
            "SELECT {HISTORY_BLOB}, kind, state_id, deleted_at, expires_at FROM blob_history
             WHERE account=?1 AND container=?2 AND name=?3 AND kind=?4 AND state_id=?5
               AND (deleted_at IS NULL OR expires_at > ?6)"
        ),
        params![account, container, name, kind.code(), state.0, now],
        |row| retained(row, now),
    )
    .optional()
    .map_err(db_error)
}

/// A live (not soft-deleted) retained version.
pub(super) fn find_version(
    db: &Connection,
    key: &BlobKey,
    version: Ticks,
    now: i64,
) -> Result<Option<BlobRow>> {
    Ok(find(db, key, Kind::Version, version, now)?
        .filter(|kept| kept.tombstone.is_none())
        .map(|kept| kept.row))
}

fn missing(db: &Connection, key: &BlobKey) -> Error {
    match container(db, &key.container) {
        Ok(_) => Error::BlobMissing,
        Err(error) => error,
    }
}

/// Finds the row a snapshot or version selector addresses. The flag reports
/// whether it is the current blob (a version id equal to the current one).
fn resolve(
    db: &Connection,
    key: &BlobKey,
    selector: Selector,
    now: i64,
) -> Result<(BlobRow, ContentSource, bool)> {
    let (kind, state) = match selector {
        Selector::Version(version) => {
            if let Some(row) = blob(db, key, now)?
                && row.info.entity.version == Some(version)
            {
                return Ok((row, ContentSource::Blob, true));
            }
            (Kind::Version, version)
        }
        Selector::Snapshot(time) => (Kind::Snapshot, time),
    };
    match find(db, key, kind, state, now)? {
        Some(kept) if kept.tombstone.is_none() => Ok((
            kept.row,
            ContentSource::History(kind.code(), state.0),
            false,
        )),
        _ => Err(missing(db, key)),
    }
}

/// The source row of a copy or read: the current blob, or a snapshot or version.
pub(super) fn resolve_source(
    db: &Connection,
    key: &BlobKey,
    selector: Option<Selector>,
    now: i64,
) -> Result<(BlobRow, ContentSource)> {
    match selector {
        None => Ok((require_blob(db, key, now)?, ContentSource::Blob)),
        Some(selector) => {
            let (mut row, source, current) = resolve(db, key, selector, now)?;
            if let Selector::Version(version) = selector
                && !current
            {
                row.info.tags = tags::load(db, key, version.0)?;
            }
            Ok((row, source))
        }
    }
}

/// A snapshot or version read, and whether it is the current version.
pub(crate) struct Selected {
    pub(crate) download: Download,
    pub(crate) current: bool,
}

pub(crate) struct Snapshot {
    pub(crate) entity: Entity,
    pub(crate) time: Ticks,
}

impl Store {
    /// Records which accounts keep versions (`--versioning-accounts`).
    pub(crate) async fn enable_versioning(&self, accounts: Vec<String>) -> Result<()> {
        self.run(move |db, _, _| {
            let tx = db.transaction().map_err(db_error)?;
            tx.execute("DELETE FROM versioned_accounts", [])
                .map_err(db_error)?;
            for account in accounts {
                tx.execute("INSERT INTO versioned_accounts VALUES (?1)", [account])
                    .map_err(db_error)?;
            }
            tx.commit().map_err(db_error)
        })
        .await
    }

    /// Snapshot Blob: a history row sharing the blob's extent. `metadata`, when
    /// given, replaces the metadata copied from the base blob.
    pub(crate) async fn snapshot_blob(
        &self,
        key: BlobKey,
        metadata: Option<Metadata>,
        guard: Guard,
    ) -> Result<Snapshot> {
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            let released = purge_expired(&tx, mode, now)?;
            let row = require_blob(&tx, &key, now)?;
            row.lease
                .check(guard.lease, LeaseNeed::Optional, LeaseOwner::Blob, now)?;
            guard.conditions.check(Some(row.info.entity), false)?;
            guard.conditions.check_tags(Some(&row.info.tags))?;
            check_memory_quota(&tx, mode, 0, pages::block_length(&row.info))?;
            let time = unique_ticks(&tx, &key, Ticks::from_millis(now), None)?;
            archive(
                &tx,
                mode,
                &key,
                row.info.entity.id,
                Kind::Snapshot,
                time,
                None,
            )?;
            if let Some(metadata) = metadata {
                let [account, container, name] = blob_params(&key);
                let json = serde_json::to_string(&metadata)
                    .map_err(|_| internal("could not encode metadata"))?;
                tx.execute(
                    "UPDATE blob_history SET metadata=?1
                     WHERE account=?2 AND container=?3 AND name=?4 AND kind=1 AND state_id=?5",
                    params![json, account, container, name, time.0],
                )
                .map_err(db_error)?;
            }
            tx.commit().map_err(db_error)?;
            release(db, mode, &released);
            Ok(Snapshot {
                entity: row.info.entity,
                time,
            })
        })
        .await
    }

    pub(crate) async fn read_selected(
        &self,
        key: BlobKey,
        selector: Selector,
        options: BlobRead,
    ) -> Result<Selected> {
        self.run(move |db, mode, now| {
            let (row, source, current) = resolve(db, &key, selector, now)?;
            let download = read_row(db, mode, now, row, &key, &options, source)?;
            Ok(Selected { download, current })
        })
        .await
    }

    /// Get Block List for a snapshot or version: its committed blocks.
    pub(crate) async fn blocks_selected(
        &self,
        key: BlobKey,
        selector: Selector,
        kind: BlockListKind,
        guard: Guard,
    ) -> Result<BlockList> {
        self.run(move |db, _, now| {
            let (row, source, _) = resolve(db, &key, selector, now)?;
            row.lease
                .check(guard.lease, LeaseNeed::Optional, LeaseOwner::Blob, now)?;
            guard.conditions.check(Some(row.info.entity), true)?;
            guard.conditions.check_tags(Some(&row.info.tags))?;
            let [account, container, name] = blob_params(&key);
            let (kind_code, state) = match selector {
                Selector::Snapshot(time) => (Kind::Snapshot.code(), time.0),
                Selector::Version(version) => (Kind::Version.code(), version.0),
            };
            let history = matches!(source, ContentSource::History(..));
            let mut query = db
                .prepare(if history {
                    "SELECT block_id, length FROM history_blocks
                     WHERE account=?1 AND container=?2 AND name=?3 AND kind=?4 AND state_id=?5
                     ORDER BY position"
                } else {
                    "SELECT block_id, length FROM committed_blocks
                     WHERE account=?1 AND container=?2 AND name=?3 ORDER BY position"
                })
                .map_err(db_error)?;
            let values: [&dyn rusqlite::ToSql; 5] =
                [&account, &container, &name, &kind_code, &state];
            let committed: Vec<(String, ContentLength)> = query
                .query_map(&values[..if history { 5 } else { 3 }], |r| {
                    Ok((r.get(0)?, ContentLength(super::row_uint(r, 1)?)))
                })
                .map_err(db_error)?
                .collect::<rusqlite::Result<_>>()
                .map_err(db_error)?;
            Ok(BlockList {
                entity: Some(row.info.entity),
                length: row.info.length,
                committed: (kind != BlockListKind::Uncommitted).then_some(committed),
                uncommitted: (kind != BlockListKind::Committed).then(Vec::new),
            })
        })
        .await
    }
}
