//! Snapshots, versions, and soft-deleted blobs (ADR-0018).
//!
//! Every retained state of a blob is a `blob_history` row that references the
//! same immutable extent as the blob it came from. Disk extents are therefore
//! shared, not copied: an extent is pinned while any history row names it and is
//! deleted only once no blob, history row, or staged block references it.
//! (The in-memory backend keeps bytes in the rows, so it copies them.)

use super::{
    BLOB_COLUMN_COUNT, BLOB_COLUMNS, BlobRow, ContentSource, Download, Mode, Store, blob,
    blob_params, blob_row,
    blobs::{guard_delete, read_row},
    check_memory_quota, container, db_error, internal, page_history, pages, remove_staged,
    require_blob, tags,
};
use crate::{
    blob_snapshot::{DeleteSnapshots, Removal, Selector},
    blob_tags::Tags,
    conditions::Guard,
    domain::{
        AccountName, BlobInfo, BlobKey, BlobRead, BlockList, BlockListKind, ContentLength, Entity,
        Error, Include, ListRequest, Metadata, Result,
    },
    lease::{LeaseNeed, LeaseOwner},
    stamp::Ticks,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, OptionalExtension as _, Row, params};
use std::{collections::HashSet, sync::Mutex};
use uuid::Uuid;

const DAY_MS: i64 = 86_400_000;

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

/// Deletes expired soft-deleted rows, returning the extents they referenced.
fn purge_expired(db: &Connection, mode: &Mode, now: i64) -> Result<Vec<Uuid>> {
    type Purged = (String, String, String, i64, i64, Uuid);
    let ranges = page_history::extents_where(
        db,
        "b.deleted_at IS NOT NULL AND b.expires_at <= ?1",
        params![now],
    )?;
    let mut statement = db
        .prepare(
            "DELETE FROM blob_history WHERE deleted_at IS NOT NULL AND expires_at <= ?1
             RETURNING account, container, name, kind, state_id, content_id",
        )
        .map_err(db_error)?;
    let purged: Vec<Purged> = statement
        .query_map([now], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)?;
    let mut ids = Vec::with_capacity(purged.len());
    for (account, container, name, kind, state, id) in purged {
        let tag_state = match Kind::from_code(kind) {
            Some(Kind::Version) => Some(state),
            Some(Kind::Deleted) => Some(DELETED_TAGS),
            _ => None,
        };
        if let Some(tag_state) = tag_state {
            db.execute(
                "DELETE FROM blob_tags WHERE account=?1 AND container=?2 AND name=?3 AND state=?4",
                params![account, container, name, tag_state],
            )
            .map_err(db_error)?;
        }
        ids.push(id);
    }
    ids.extend(page_history::free(db, mode, ranges)?);
    Ok(ids)
}

/// Reclaims the storage of soft-deleted entries that expired while the server was stopped.
pub(super) fn purge_at_open(db: &Connection, mode: &Mode, now: i64) -> anyhow::Result<()> {
    let ids = purge_expired(db, mode, now)
        .map_err(|_| anyhow::anyhow!("could not purge expired entries"))?;
    release(db, mode, &ids);
    Ok(())
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

/// How the delete went: permanently, or into soft-delete or version history.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Deletion {
    Permanent,
    Retained,
}

fn count_snapshots(db: &Connection, key: &BlobKey) -> Result<i64> {
    let [account, container, name] = blob_params(key);
    db.query_row(
        "SELECT COUNT(*) FROM blob_history
         WHERE account=?1 AND container=?2 AND name=?3 AND kind=1 AND deleted_at IS NULL",
        params![account, container, name],
        |row| row.get(0),
    )
    .map_err(db_error)
}

/// Deletes live snapshots or versions (`state`: one, or all of the kind), or
/// marks them soft-deleted when the account keeps deleted data.
fn remove_states(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    kind: Kind,
    state: Option<Ticks>,
    now: i64,
    released: &mut Vec<Uuid>,
) -> Result<()> {
    let [account, container, name] = blob_params(key);
    let all = i64::from(state.is_none());
    let state = state.map_or(0, |state| state.0);
    if let Some(retention) = retention(db, &key.container.account)? {
        db.execute(
            "UPDATE blob_history SET deleted_at=?6, expires_at=?7
             WHERE account=?1 AND container=?2 AND name=?3 AND kind=?4 AND deleted_at IS NULL
               AND (?8 OR state_id=?5)",
            params![
                account,
                container,
                name,
                kind.code(),
                state,
                now,
                now + retention,
                all
            ],
        )
        .map_err(db_error)?;
        return Ok(());
    }
    let ranges = page_history::extents_where(
        db,
        "b.account=?1 AND b.container=?2 AND b.name=?3 AND b.kind=?4 AND b.deleted_at IS NULL
         AND (?6 OR b.state_id=?5)",
        params![account, container, name, kind.code(), state, all],
    )?;
    let mut delete = db
        .prepare(
            "DELETE FROM blob_history
             WHERE account=?1 AND container=?2 AND name=?3 AND kind=?4 AND deleted_at IS NULL
               AND (?6 OR state_id=?5)
             RETURNING content_id, state_id",
        )
        .map_err(db_error)?;
    let gone: Vec<(Uuid, i64)> = delete
        .query_map(
            params![account, container, name, kind.code(), state, all],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)?;
    for (id, state) in gone {
        released.push(id);
        if kind == Kind::Version {
            db.execute(
                "DELETE FROM blob_tags WHERE account=?1 AND container=?2 AND name=?3 AND state=?4",
                params![account, container, name, state],
            )
            .map_err(db_error)?;
        }
    }
    released.extend(page_history::free(db, mode, ranges)?);
    Ok(())
}

/// Removes the current blob row, first retiring it into version history, or
/// into a soft-deleted entry, when the account keeps them.
fn retire_current(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    row: &BlobRow,
    keep_as_version: bool,
    now: i64,
    released: &mut Vec<Uuid>,
) -> Result<Deletion> {
    let [account, container, name] = blob_params(key);
    let id = row.info.entity.id;
    let outcome = if keep_as_version && is_versioned(db, account)? {
        let state = match row.info.entity.version {
            Some(version) => version,
            None => unique_ticks(db, key, Ticks::from_seconds(row.info.entity.modified), None)?,
        };
        archive(db, mode, key, id, Kind::Version, state, None)?;
        move_tags(db, key, state)?;
        Deletion::Retained
    } else {
        match retention(db, &key.container.account)? {
            Some(retention) => {
                // A soft-deleted blob keeps its tags (state -1) so an undelete restores them.
                drop_tags(db, key, DELETED_TAGS)?;
                move_tags_to(db, key, 0, DELETED_TAGS)?;
                let replaced_ranges = page_history::extents_where(
                    db,
                    "b.account=?1 AND b.container=?2 AND b.name=?3 AND b.kind=3",
                    params![account, container, name],
                )?;
                let replaced = db
                    .query_row(
                        "DELETE FROM blob_history WHERE account=?1 AND container=?2 AND name=?3
                           AND kind=3 RETURNING content_id",
                        params![account, container, name],
                        |row| row.get::<_, Uuid>(0),
                    )
                    .optional()
                    .map_err(db_error)?;
                released.extend(replaced);
                released.extend(page_history::free(db, mode, replaced_ranges)?);
                let tombstone = Tombstone {
                    deleted_at: now,
                    expires_at: now + retention,
                };
                archive(db, mode, key, id, Kind::Deleted, Ticks(0), Some(tombstone))?;
                Deletion::Retained
            }
            None => {
                drop_tags(db, key, 0)?;
                Deletion::Permanent
            }
        }
    };
    // A page or append blob keeps its extents through any history row copy of its ranges.
    released.extend(pages::retire(db, mode, key, row.info.kind)?);
    db.execute("DELETE FROM blobs WHERE id=?1", [id])
        .map_err(db_error)?;
    released.push(id);
    Ok(outcome)
}

/// Removes a blob that reached its expiry. Azure does not soft-delete an expired
/// blob, so the blob and its snapshots go for good; an account that keeps
/// versions keeps the blob as a version.
pub(super) fn expire(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    row: &BlobRow,
    now: i64,
    released: &mut Vec<Uuid>,
) -> Result<()> {
    let [account, container, name] = blob_params(key);
    released.extend(remove_staged(db, key)?);
    let ranges = page_history::extents_where(
        db,
        "b.account=?1 AND b.container=?2 AND b.name=?3 AND b.kind=1",
        params![account, container, name],
    )?;
    let mut delete = db
        .prepare(
            "DELETE FROM blob_history WHERE account=?1 AND container=?2 AND name=?3 AND kind=1
             RETURNING content_id",
        )
        .map_err(db_error)?;
    let snapshots: Vec<Uuid> = delete
        .query_map(params![account, container, name], |row| row.get(0))
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)?;
    released.extend(snapshots);
    released.extend(page_history::free(db, mode, ranges)?);
    let id = row.info.entity.id;
    if is_versioned(db, account)? {
        let state = match row.info.entity.version {
            Some(version) => version,
            None => unique_ticks(db, key, Ticks::from_millis(now), None)?,
        };
        archive(db, mode, key, id, Kind::Version, state, None)?;
        move_tags(db, key, state)?;
    } else {
        drop_tags(db, key, 0)?;
    }
    released.extend(pages::retire(db, mode, key, row.info.kind)?);
    db.execute("DELETE FROM blobs WHERE id=?1", [id])
        .map_err(db_error)?;
    released.push(id);
    Ok(())
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

    /// Delete Blob in all its forms: the current blob (with or without its
    /// snapshots), one snapshot, or one version.
    pub(crate) async fn delete_blob(
        &self,
        key: BlobKey,
        guard: Guard,
        removal: Removal,
    ) -> Result<Deletion> {
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            let mut released = purge_expired(&tx, mode, now)?;
            let outcome = match removal.selector {
                None => delete_current(
                    &tx,
                    mode,
                    &key,
                    &guard,
                    removal.snapshots,
                    now,
                    &mut released,
                )?,
                Some(Selector::Snapshot(time)) => delete_retained(
                    &tx,
                    mode,
                    &key,
                    &guard,
                    (Kind::Snapshot, time),
                    now,
                    &mut released,
                )?,
                Some(Selector::Version(version)) => {
                    let current = blob(&tx, &key, now)?
                        .filter(|row| row.info.entity.version == Some(version));
                    match current {
                        Some(row) => {
                            guard_delete(&guard, &row, now)?;
                            released.extend(remove_staged(&tx, &key)?);
                            retire_current(&tx, mode, &key, &row, false, now, &mut released)?
                        }
                        None => delete_retained(
                            &tx,
                            mode,
                            &key,
                            &guard,
                            (Kind::Version, version),
                            now,
                            &mut released,
                        )?,
                    }
                }
            };
            tx.commit().map_err(db_error)?;
            release(db, mode, &released);
            Ok(outcome)
        })
        .await
    }

    /// Undelete Blob: restores a soft-deleted blob and its soft-deleted
    /// snapshots and versions.
    pub(crate) async fn undelete_blob(&self, key: BlobKey) -> Result<()> {
        let hierarchical = self.hierarchical(&key.container);
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            let released = purge_expired(&tx, mode, now)?;
            container(&tx, &key.container)?;
            let current = blob(&tx, &key, now)?;
            let [account, container, name] = blob_params(&key);
            let mut query = tx
                .prepare(
                    "SELECT kind, state_id FROM blob_history
                     WHERE account=?1 AND container=?2 AND name=?3 AND deleted_at IS NOT NULL",
                )
                .map_err(db_error)?;
            let deleted: Vec<(i64, i64)> = query
                .query_map(params![account, container, name], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(db_error)?
                .collect::<rusqlite::Result<_>>()
                .map_err(db_error)?;
            drop(query);
            if deleted.is_empty() && current.is_none() {
                return Err(Error::BlobMissing);
            }
            let mut restored = Vec::new();
            for (kind, state) in deleted {
                if Kind::from_code(kind) == Some(Kind::Deleted) {
                    if current.is_none() {
                        restored.extend(restore_current(&tx, &key, hierarchical, now)?);
                    }
                } else {
                    tx.execute(
                        "UPDATE blob_history SET deleted_at=NULL, expires_at=NULL
                         WHERE account=?1 AND container=?2 AND name=?3 AND kind=?4 AND state_id=?5",
                        params![account, container, name, kind, state],
                    )
                    .map_err(db_error)?;
                }
            }
            tx.commit().map_err(db_error)?;
            release(db, mode, &[released, restored].concat());
            Ok(())
        })
        .await
    }
}

pub(super) fn delete_current(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    guard: &Guard,
    snapshots: DeleteSnapshots,
    now: i64,
    released: &mut Vec<Uuid>,
) -> Result<Deletion> {
    let old = require_blob(db, key, now)?;
    guard_delete(guard, &old, now)?;
    if snapshots == DeleteSnapshots::Refuse && count_snapshots(db, key)? > 0 {
        return Err(Error::SnapshotsPresent);
    }
    if snapshots != DeleteSnapshots::Refuse {
        remove_states(db, mode, key, Kind::Snapshot, None, now, released)?;
    }
    if snapshots == DeleteSnapshots::Only {
        return Ok(if retention(db, &key.container.account)?.is_some() {
            Deletion::Retained
        } else {
            Deletion::Permanent
        });
    }
    released.extend(remove_staged(db, key)?);
    retire_current(db, mode, key, &old, true, now, released)
}

fn delete_retained(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    guard: &Guard,
    (kind, state): (Kind, Ticks),
    now: i64,
    released: &mut Vec<Uuid>,
) -> Result<Deletion> {
    let Some(kept) = find(db, key, kind, state, now)?.filter(|kept| kept.tombstone.is_none())
    else {
        return Err(missing(db, key));
    };
    guard.conditions.check(Some(kept.row.info.entity), false)?;
    remove_states(db, mode, key, kind, Some(state), now, released)?;
    Ok(if retention(db, &key.container.account)?.is_some() {
        Deletion::Retained
    } else {
        Deletion::Permanent
    })
}

/// Moves a soft-deleted blob back to the current row, returning its extent id
/// so the release step can unpin it. On a hierarchical-namespace account the
/// parent directories are recreated first, and a name that is now a directory
/// is a `PathConflict`.
fn restore_current(
    db: &Connection,
    key: &BlobKey,
    hierarchical: bool,
    now: i64,
) -> Result<Option<Uuid>> {
    if hierarchical {
        super::namespace::prepare_file(db, key, now)?;
    }
    drop_tags(db, key, 0)?;
    move_tags_to(db, key, DELETED_TAGS, 0)?;
    let [account, container, name] = blob_params(key);
    db.execute(
        "INSERT INTO blobs (account, container, name, id, etag, modified, created, length,
            content_type, content_encoding, content_language, content_disposition, cache_control,
            md5, metadata, bytes, access_tier, access_tier_changed, copy_id, copy_source,
            copy_completed, blob_type, sequence_number, append_count, sealed)
         SELECT account, container, name, content_id, etag, modified, created, length,
            content_type, content_encoding, content_language, content_disposition, cache_control,
            md5, metadata, bytes, access_tier, access_tier_changed, copy_id, copy_source,
            copy_completed, blob_type, sequence_number, append_count, sealed
         FROM blob_history WHERE account=?1 AND container=?2 AND name=?3 AND kind=3",
        params![account, container, name],
    )
    .map_err(db_error)?;
    page_history::restore_ranges(db, key)?;
    db.execute(
        "INSERT INTO committed_blocks
         SELECT account, container, name, position, block_id, offset, length
         FROM history_blocks WHERE account=?1 AND container=?2 AND name=?3 AND kind=3",
        params![account, container, name],
    )
    .map_err(db_error)?;
    db.query_row(
        "DELETE FROM blob_history WHERE account=?1 AND container=?2 AND name=?3 AND kind=3
         RETURNING content_id",
        params![account, container, name],
        |row| row.get(0),
    )
    .optional()
    .map_err(db_error)
}

/// One entry of a listing that includes snapshots, versions, deleted blobs, or tags.
pub(crate) struct ListedBlob {
    pub(crate) name: String,
    pub(crate) info: BlobInfo,
    pub(crate) snapshot: Option<Ticks>,
    pub(crate) version: Option<Ticks>,
    pub(crate) current_version: bool,
    pub(crate) deleted: Option<DeletedInfo>,
    pub(crate) tags: Tags,
}

pub(crate) struct DeletedInfo {
    pub(crate) at: u64,
    pub(crate) remaining_days: u64,
}

pub(crate) enum Listed {
    Blob(Box<ListedBlob>),
    Prefix(String),
}

pub(crate) struct ExtendedListing {
    pub(crate) entries: Vec<Listed>,
    pub(crate) next: String,
}

/// Where a listing resumes: after a whole name, or after one entry of a name.
enum Cursor {
    Start,
    Name(String),
    Entry(String, i64, i64),
}

const MARKER: &str = "~v1:";
const AFTER_PREFIX: char = '\u{10FFFF}';

impl Cursor {
    fn parse(after: &str) -> Self {
        if after.is_empty() {
            return Self::Start;
        }
        let parsed = after.strip_prefix(MARKER).and_then(|rest| {
            let mut parts = rest.splitn(3, ':');
            let sort = parts.next()?.parse().ok()?;
            let kind = parts.next()?.parse().ok()?;
            Some(Self::Entry(parts.next()?.to_owned(), sort, kind))
        });
        parsed.unwrap_or_else(|| Self::Name(after.to_owned()))
    }

    fn name(&self) -> &str {
        match self {
            Self::Start => "",
            Self::Name(name) | Self::Entry(name, ..) => name,
        }
    }

    fn allows(&self, name: &str, sort: i64, kind: i64) -> bool {
        match self {
            Self::Start => true,
            Self::Name(after) => name > after.as_str(),
            Self::Entry(after, after_sort, after_kind) => {
                (name, sort, kind) > (after.as_str(), *after_sort, *after_kind)
            }
        }
    }
}

fn marker(name: &str, sort: i64, kind: i64) -> String {
    URL_SAFE_NO_PAD.encode(format!("{MARKER}{sort}:{kind}:{name}"))
}

impl Store {
    /// List Blobs with `include` values beyond the plain listing's. Within a
    /// name, snapshots and versions come oldest first and the current blob last.
    pub(crate) async fn list_extended(
        &self,
        key: crate::domain::ContainerKey,
        request: ListRequest,
        lease: Option<crate::lease::LeaseId>,
    ) -> Result<ExtendedListing> {
        self.run(move |db, _, now| {
            let owner = super::containers::require_container(db, &key, now)?;
            owner
                .lease
                .check(lease, LeaseNeed::Optional, LeaseOwner::Container, now)?;
            let has = |include| request.include.contains(&include);
            let (snapshots, versions, deleted, with_tags) = (
                has(Include::Snapshots),
                has(Include::Versions),
                has(Include::Deleted),
                has(Include::Tags),
            );
            let limit = request.page.limit as usize;
            let prefix = request.page.prefix.as_str();
            let cursor = Cursor::parse(&request.page.after);
            let lifecycle =
                super::expiry::load_container(db, key.account.as_str(), key.name.as_str())?;
            let sql = format!(
                "SELECT {BLOB_COLUMNS}, name, 0, 9223372036854775807, version_id, NULL, NULL
                   FROM blobs WHERE account=?1 AND container=?2 AND name>=?3 AND instr(name, ?4)=1
                 UNION ALL
                 SELECT {HISTORY_BLOB}, name, kind,
                        CASE WHEN kind=3 THEN deleted_at * 10000 ELSE state_id END,
                        state_id, deleted_at, expires_at
                   FROM blob_history WHERE account=?1 AND container=?2 AND name>=?3
                    AND instr(name, ?4)=1 AND (deleted_at IS NULL OR expires_at > ?5)
                 ORDER BY {}, {}, {}",
                BLOB_COLUMN_COUNT + 1,
                BLOB_COLUMN_COUNT + 3,
                BLOB_COLUMN_COUNT + 2
            );
            let mut statement = db.prepare(&sql).map_err(db_error)?;
            let mut rows = statement
                .query(params![
                    key.account.as_str(),
                    key.name.as_str(),
                    cursor.name(),
                    prefix,
                    now
                ])
                .map_err(db_error)?;
            let mut entries: Vec<(Listed, String)> = Vec::new();
            let mut collapsed: Option<String> = None;
            while let Some(row) = rows.next().map_err(db_error)? {
                let at = BLOB_COLUMN_COUNT;
                let name: String = row.get(at).map_err(db_error)?;
                let kind: i64 = row.get(at + 1).map_err(db_error)?;
                let sort: i64 = row.get(at + 2).map_err(db_error)?;
                if !cursor.allows(&name, sort, kind)
                    || collapsed.as_deref().is_some_and(|p| name.starts_with(p))
                {
                    continue;
                }
                let state: i64 = row.get(at + 3).map_err(db_error)?;
                let tombstone: Option<i64> = row.get(at + 4).map_err(db_error)?;
                let expires: Option<i64> = row.get(at + 5).map_err(db_error)?;
                let shown = match (kind, tombstone) {
                    (0, _) => true,
                    (1, None) => snapshots,
                    (1, Some(_)) => deleted && snapshots,
                    (2, None) => versions,
                    (2, Some(_)) => deleted && versions,
                    (3, _) => deleted,
                    _ => false,
                };
                if !shown {
                    continue;
                }
                if let Some(delimiter) = request.delimiter.as_deref()
                    && let Some(rest) = name.get(prefix.len()..)
                    && let Some(at) = rest.find(delimiter)
                {
                    let end = prefix.len() + at + delimiter.len();
                    let group = name[..end].to_owned();
                    let next = marker(&format!("{group}{AFTER_PREFIX}"), i64::MAX, 9);
                    entries.push((Listed::Prefix(group.clone()), next));
                    collapsed = Some(group);
                    if entries.len() > limit {
                        break;
                    }
                    continue;
                }
                let mut info = blob_row(row, now).map_err(db_error)?.info;
                if kind == 2 {
                    info.entity.version = Some(Ticks(state));
                }
                if kind == 0
                    && let Some(found) = lifecycle.get(&name)
                {
                    info.lifecycle = *found;
                }
                let current = kind == 0;
                let version = if current {
                    let id: i64 = row.get(at + 3).map_err(db_error)?;
                    (versions && id != 0).then_some(Ticks(id))
                } else {
                    (kind == 2).then_some(Ticks(state))
                };
                let tag_state = match kind {
                    0 => Some(0),
                    2 => Some(state),
                    _ => None,
                };
                let tags = match tag_state.filter(|_| with_tags) {
                    Some(tag_state) => tags::load_named(
                        db,
                        [key.account.as_str(), key.name.as_str(), &name],
                        tag_state,
                    )?,
                    None => Tags::new(),
                };
                let entry = ListedBlob {
                    snapshot: (kind == 1).then_some(Ticks(state)),
                    version,
                    current_version: current && version.is_some(),
                    deleted: tombstone.zip(expires).map(|(at, expires)| DeletedInfo {
                        at: u64::try_from(at / 1000).unwrap_or(0),
                        remaining_days: u64::try_from((expires - now + DAY_MS - 1) / DAY_MS)
                            .unwrap_or(0),
                    }),
                    tags,
                    info,
                    name: name.clone(),
                };
                entries.push((Listed::Blob(Box::new(entry)), marker(&name, sort, kind)));
                if entries.len() > limit {
                    break;
                }
            }
            let next = if entries.len() > limit {
                entries.truncate(limit);
                entries
                    .last()
                    .map_or_else(String::new, |(_, marker)| marker.clone())
            } else {
                String::new()
            };
            Ok(ExtendedListing {
                entries: entries.into_iter().map(|(entry, _)| entry).collect(),
                next,
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        clock::Clock,
        domain::{
            BlobPath, BlobWrite, ContainerCreate, ContainerKey, ContainerName, ContentHeaders,
            PublicAccess,
        },
    };
    use std::path::Path;

    fn key(name: &str) -> BlobKey {
        BlobKey {
            container: ContainerKey {
                account: AccountName::parse("acct").unwrap(),
                name: ContainerName::parse("box").unwrap(),
            },
            path: BlobPath::parse(name.to_owned()).unwrap(),
        }
    }

    async fn put(store: &Store, name: &str, bytes: &[u8]) {
        let mut upload = store
            .begin_upload(ContentLength(bytes.len() as u64))
            .await
            .unwrap();
        upload.append(bytes).await.unwrap();
        let upload = upload.finish(None).await.unwrap();
        let options = BlobWrite {
            headers: ContentHeaders::default(),
            metadata: Metadata::new(),
            guard: Guard::default(),
            tier: None,
            copy: None,
            md5: None,
            tags: Tags::new(),
        };
        store.put_blob(key(name), options, upload).await.unwrap();
    }

    async fn open(root: &Path) -> Store {
        let store = Store::open(Some(root), 0, Clock::new(), Default::default()).unwrap();
        let container = ContainerKey {
            account: AccountName::parse("acct").unwrap(),
            name: ContainerName::parse("box").unwrap(),
        };
        let _ = store
            .create_container(
                container,
                ContainerCreate {
                    metadata: Metadata::new(),
                    public_access: PublicAccess::Private,
                },
            )
            .await;
        store
    }

    fn extents(root: &Path) -> usize {
        std::fs::read_dir(root.join("content"))
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("extent-")
            })
            .count()
    }

    fn removal(selector: Option<Selector>, snapshots: DeleteSnapshots) -> Removal {
        Removal {
            selector,
            snapshots,
        }
    }

    fn options() -> BlobWrite {
        BlobWrite {
            headers: ContentHeaders::default(),
            metadata: Metadata::new(),
            guard: Guard::default(),
            tier: None,
            copy: None,
            md5: None,
            tags: Tags::new(),
        }
    }

    async fn write_page(store: &Store, name: &str, start: u64, bytes: &[u8]) {
        let mut upload = store
            .begin_upload(ContentLength(bytes.len() as u64))
            .await
            .unwrap();
        upload.append(bytes).await.unwrap();
        let upload = upload.finish(None).await.unwrap();
        let write = crate::blob_page::PageWrite {
            range: start..start + bytes.len() as u64,
            sequence: Default::default(),
            guard: Guard::default(),
        };
        store
            .put_page(key(name), write, Some(upload))
            .await
            .unwrap();
    }

    async fn read_snapshot(store: &Store, name: &str, time: Ticks) -> Vec<u8> {
        let read = crate::domain::BlobRead {
            guard: Guard::default(),
            range: None,
            with_body: true,
            range_checksum: None,
        };
        let selected = store
            .read_selected(key(name), Selector::Snapshot(time), read)
            .await
            .unwrap();
        match selected.download.payload {
            Some(crate::store::Payload::Ranges(body)) => body.into_vec().unwrap(),
            _ => panic!("a page blob snapshot reads through its range map"),
        }
    }

    #[tokio::test]
    async fn a_page_blob_snapshot_shares_extents_and_outlives_later_writes_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path()).await;
        store
            .create_paged(
                key("disk"),
                options(),
                crate::blob_page::Creation::Page {
                    length: 1024,
                    sequence: 0,
                },
            )
            .await
            .unwrap();
        write_page(&store, "disk", 0, &[b'a'; 512]).await;
        let snapshot = store
            .snapshot_blob(key("disk"), None, Guard::default())
            .await
            .unwrap();
        assert_eq!(extents(dir.path()), 1, "a snapshot shares the extent");
        write_page(&store, "disk", 0, &[b'b'; 512]).await;
        assert_eq!(extents(dir.path()), 2, "the overwritten extent is retained");
        let mut expected = vec![b'a'; 512];
        expected.extend([0u8; 512]);
        assert_eq!(read_snapshot(&store, "disk", snapshot.time).await, expected);
        let refuse = store
            .delete_blob(
                key("disk"),
                Guard::default(),
                removal(None, DeleteSnapshots::Refuse),
            )
            .await;
        assert_eq!(refuse.err(), Some(Error::SnapshotsPresent));
        store
            .delete_blob(
                key("disk"),
                Guard::default(),
                removal(None, DeleteSnapshots::Only),
            )
            .await
            .unwrap();
        assert_eq!(
            extents(dir.path()),
            1,
            "deleting the snapshot frees its extent"
        );
        let outcome = store
            .delete_blob(
                key("disk"),
                Guard::default(),
                removal(None, DeleteSnapshots::Refuse),
            )
            .await
            .unwrap();
        assert!(outcome == Deletion::Permanent);
        assert_eq!(extents(dir.path()), 0);
    }

    #[tokio::test]
    async fn history_ranges_keep_extents_across_restart_until_the_last_reference_goes() {
        let dir = tempfile::tempdir().unwrap();
        let time = {
            let store = open(dir.path()).await;
            store
                .create_paged(key("log"), options(), crate::blob_page::Creation::Append)
                .await
                .unwrap();
            let mut upload = store.begin_upload(ContentLength(3)).await.unwrap();
            upload.append(b"abc").await.unwrap();
            let upload = upload.finish(None).await.unwrap();
            store
                .append_block(
                    key("log"),
                    crate::blob_page::AppendWrite {
                        condition: Default::default(),
                        guard: Guard::default(),
                    },
                    upload,
                )
                .await
                .unwrap();
            let snapshot = store
                .snapshot_blob(key("log"), None, Guard::default())
                .await
                .unwrap();
            snapshot.time
        };
        let store = open(dir.path()).await;
        assert_eq!(extents(dir.path()), 1);
        let read = crate::domain::BlobRead {
            guard: Guard::default(),
            range: None,
            with_body: true,
            range_checksum: None,
        };
        let selected = store
            .read_selected(key("log"), Selector::Snapshot(time), read)
            .await
            .unwrap();
        assert_eq!(selected.download.info.length.0, 3);
        assert!(matches!(
            selected.download.info.kind,
            crate::blob_page::BlobKind::Append { committed: 1, .. }
        ));
    }
    #[tokio::test]
    async fn an_extent_lives_until_no_blob_snapshot_or_version_references_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path()).await;
        put(&store, "a", b"one").await;
        let snapshot = store
            .snapshot_blob(key("a"), None, Guard::default())
            .await
            .unwrap();
        assert_eq!(extents(dir.path()), 1, "a snapshot shares the extent");
        put(&store, "a", b"two!").await;
        assert_eq!(extents(dir.path()), 2, "the overwritten extent is retained");
        let refuse = store
            .delete_blob(
                key("a"),
                Guard::default(),
                removal(None, DeleteSnapshots::Refuse),
            )
            .await;
        assert_eq!(refuse.err(), Some(Error::SnapshotsPresent));
        store
            .delete_blob(
                key("a"),
                Guard::default(),
                removal(None, DeleteSnapshots::Only),
            )
            .await
            .unwrap();
        assert_eq!(
            extents(dir.path()),
            1,
            "deleting the snapshot frees only its extent"
        );
        put(&store, "a", b"three").await;
        assert_eq!(extents(dir.path()), 1);
        assert!(
            store
                .read_selected(
                    key("a"),
                    Selector::Snapshot(snapshot.time),
                    crate::domain::BlobRead {
                        guard: Guard::default(),
                        range: None,
                        with_body: false,
                        range_checksum: None,
                    },
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_snapshot_keeps_the_content_of_an_overwritten_blob_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let time = {
            let store = open(dir.path()).await;
            put(&store, "a", b"keep me").await;
            put(&store, "b", b"other").await;
            let snapshot = store
                .snapshot_blob(key("a"), None, Guard::default())
                .await
                .unwrap();
            put(&store, "a", b"replaced content").await;
            snapshot.time
        };
        let store = open(dir.path()).await;
        assert_eq!(extents(dir.path()), 3, "recovery keeps referenced extents");
        let read = store
            .read_selected(
                key("a"),
                Selector::Snapshot(time),
                crate::domain::BlobRead {
                    guard: Guard::default(),
                    range: None,
                    with_body: true,
                    range_checksum: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(read.download.info.length.0, 7);
        store
            .delete_blob(
                key("a"),
                Guard::default(),
                removal(Some(Selector::Snapshot(time)), DeleteSnapshots::Refuse),
            )
            .await
            .unwrap();
        assert_eq!(
            extents(dir.path()),
            2,
            "the last reference frees the extent"
        );
    }

    #[tokio::test]
    async fn deleting_a_container_frees_the_extents_its_history_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path()).await;
        put(&store, "a", b"one").await;
        store
            .snapshot_blob(key("a"), None, Guard::default())
            .await
            .unwrap();
        put(&store, "a", b"two").await;
        assert_eq!(extents(dir.path()), 2);
        store
            .delete_container(key("a").container, Guard::default())
            .await
            .unwrap();
        assert_eq!(extents(dir.path()), 0);
        drop(store);
        let reopened = open(dir.path()).await;
        put(&reopened, "a", b"fresh").await;
        assert_eq!(extents(dir.path()), 1);
    }

    #[tokio::test]
    async fn versions_retain_overwritten_content_until_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path()).await;
        store.enable_versioning(vec!["acct".into()]).await.unwrap();
        put(&store, "a", b"v1").await;
        put(&store, "a", b"v2").await;
        put(&store, "a", b"v3").await;
        assert_eq!(extents(dir.path()), 3);
        store
            .delete_blob(
                key("a"),
                Guard::default(),
                removal(None, DeleteSnapshots::Refuse),
            )
            .await
            .unwrap();
        assert_eq!(
            extents(dir.path()),
            3,
            "deleting the blob keeps its versions"
        );
        let listing = store
            .list_extended(
                key("a").container,
                ListRequest {
                    page: crate::domain::PageRequest::parse(None, None, None).unwrap(),
                    delimiter: None,
                    include: vec![Include::Versions],
                },
                None,
            )
            .await
            .unwrap();
        let versions: Vec<_> = listing
            .entries
            .iter()
            .filter_map(|entry| match entry {
                Listed::Blob(blob) => blob.version,
                Listed::Prefix(_) => None,
            })
            .collect();
        assert_eq!(versions.len(), 3);
        for version in versions {
            store
                .delete_blob(
                    key("a"),
                    Guard::default(),
                    removal(Some(Selector::Version(version)), DeleteSnapshots::Refuse),
                )
                .await
                .unwrap();
        }
        assert_eq!(extents(dir.path()), 0);
    }

    #[test]
    fn markers_resume_after_the_entry_they_name() {
        let encoded = marker("a:b", 5, 1);
        let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
        let cursor = Cursor::parse(&decoded);
        assert!(!cursor.allows("a:b", 5, 1));
        assert!(cursor.allows("a:b", 5, 2));
        assert!(cursor.allows("a:b", 6, 0));
        assert!(cursor.allows("a:c", 0, 0));
        assert!(!cursor.allows("a:a", 9, 9));
        assert!(matches!(Cursor::parse("plain/name"), Cursor::Name(_)));
        assert!(Cursor::parse("plain").allows("plainer", 0, 0));
        assert!(!Cursor::parse("plain").allows("plain", 0, 0));
    }
}
