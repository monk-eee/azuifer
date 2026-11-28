//! Deleting snapshots, versions and blobs, soft delete and its expiry, and Undelete Blob.

use super::{
    Archived, DELETED_TAGS, Kind, Tombstone, archive, drop_tags, find, is_versioned, missing,
    move_tags, move_tags_to, release, retention, unique_ticks,
};
use crate::{
    blob_immutability::Protection,
    blob_snapshot::{DeleteSnapshots, Removal, Selector},
    conditions::Guard,
    domain::{BlobKey, Error, Result},
    stamp::Ticks,
    store::{
        BlobRow, Mode, Store, blob, blob_params, blobs::guard_delete, container, db_error,
        immutability, page_history, pages, remove_staged, require_blob,
    },
};
use rusqlite::{Connection, OptionalExtension as _, params};
use uuid::Uuid;

/// Deletes expired soft-deleted rows, returning the extents they referenced.
pub(super) fn purge_expired(db: &Connection, mode: &Mode, now: i64) -> Result<Vec<Uuid>> {
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
pub(in crate::store) fn purge_at_open(
    db: &Connection,
    mode: &Mode,
    now: i64,
) -> anyhow::Result<()> {
    let ids = purge_expired(db, mode, now)
        .map_err(|_| anyhow::anyhow!("could not purge expired entries"))?;
    release(db, mode, &ids);
    Ok(())
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
        archive(
            db,
            mode,
            key,
            id,
            Archived {
                kind: Kind::Version,
                state,
                tombstone: None,
                protection: row.info.lifecycle.protection,
            },
        )?;
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
                archive(
                    db,
                    mode,
                    key,
                    id,
                    Archived {
                        kind: Kind::Deleted,
                        state: Ticks(0),
                        tombstone: Some(tombstone),
                        protection: Protection::default(),
                    },
                )?;
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
/// blob, so the blob and its unprotected snapshots go for good; an account that
/// keeps versions keeps the blob (and any WORM state) as a version. On a
/// non-versioned account, an active immutability policy or legal hold prevents
/// the lazy sweep from deleting the protected blob.
pub(in crate::store) fn expire(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    row: &BlobRow,
    now: i64,
    released: &mut Vec<Uuid>,
) -> Result<()> {
    let [account, container, name] = blob_params(key);
    let versioned = is_versioned(db, account)?;
    if !versioned && row.info.lifecycle.protection.check_delete(now).is_err() {
        return Ok(());
    }
    released.extend(remove_staged(db, key)?);
    let ranges = page_history::extents_where(
        db,
        "b.account=?1 AND b.container=?2 AND b.name=?3 AND b.kind=1
         AND b.legal_hold=0 AND (b.immutability_mode='' OR b.immutable_until<=?4)",
        params![account, container, name, now],
    )?;
    let mut delete = db
        .prepare(
            "DELETE FROM blob_history
             WHERE account=?1 AND container=?2 AND name=?3 AND kind=1
               AND legal_hold=0 AND (immutability_mode='' OR immutable_until<=?4)
             RETURNING content_id",
        )
        .map_err(db_error)?;
    let snapshots: Vec<Uuid> = delete
        .query_map(params![account, container, name, now], |row| row.get(0))
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)?;
    released.extend(snapshots);
    released.extend(page_history::free(db, mode, ranges)?);
    let id = row.info.entity.id;
    if versioned {
        let state = match row.info.entity.version {
            Some(version) => version,
            None => unique_ticks(db, key, Ticks::from_millis(now), None)?,
        };
        archive(
            db,
            mode,
            key,
            id,
            Archived {
                kind: Kind::Version,
                state,
                tombstone: None,
                protection: row.info.lifecycle.protection,
            },
        )?;
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

pub(in crate::store) fn delete_current(
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
        immutability::check_blob_snapshots(db, key, now)?;
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
    kept.row.info.lifecycle.protection.check_delete(now)?;
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
        crate::store::namespace::prepare_file(db, key, now)?;
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

impl Store {
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
