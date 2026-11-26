use super::{
    BlobRow, Content, ContentSource, Download, Mode, PathRead, Payload, Store, Uploaded, blob,
    blob_params, check_memory_quota, container, db_error, internal, io_error, namespace,
    new_entity, open_extent, pages, read_memory_slice, reclaim, remove_staged, require_blob,
    save_blob, snapshots, sqlite_int, write_lease,
};
use crate::{
    blob_page::PropertyChange,
    blob_snapshot::Removal,
    checksum::Hasher,
    conditions::{Conditions, Guard},
    domain::{
        AccessTier, BlobKey, BlobRead, BlobWrite, ContentHeaders, Entity, Error, Metadata,
        RangeChecksum, Result,
    },
    lease::{LeaseAction, LeaseId, LeaseNeed, LeaseOwner},
    store::{Deletion, LeaseResult},
};
use rusqlite::params;
use std::io::Read as _;

/// The largest range for which Azure computes a checksum on the fly.
const MAX_RANGE_CHECKSUM: u64 = 4 * 1024 * 1024;

/// Checks a write's lease and conditions against the current blob, if any.
/// `exclusive` marks Put Blob and Put Block List, where `If-None-Match: *`
/// on an existing blob is `BlobAlreadyExists` rather than a failed condition.
pub(super) fn guard_write(
    guard: &Guard,
    old: Option<&BlobRow>,
    exclusive: bool,
    now: i64,
) -> Result<()> {
    match old {
        Some(row) => row
            .lease
            .check(guard.lease, LeaseNeed::Required, LeaseOwner::Blob, now)?,
        None if guard.lease.is_some() => return Err(Error::LeaseNotPresentBlob),
        None => (),
    }
    if exclusive && old.is_some() && guard.conditions.requires_absence() {
        return Err(Error::BlobAlreadyExists);
    }
    guard.conditions.check_tags(old.map(|row| &row.info.tags))?;
    guard
        .conditions
        .check(old.map(|row| row.info.entity), false)
}

/// Creates the missing parent directories of a new blob inside the writer's
/// transaction, before its content is published, and rejects names that would
/// shadow a directory or sit under a file. Every writer of a new blob calls this
/// where Put Blob checks its guard; flat namespaces have no parents.
pub(super) fn ensure_parents(
    tx: &rusqlite::Connection,
    key: &BlobKey,
    hierarchical: bool,
    now: i64,
) -> Result<()> {
    if hierarchical {
        namespace::prepare_file(tx, key, now)
    } else {
        Ok(())
    }
}

pub(super) fn touch(db: &rusqlite::Connection, key: &BlobKey, now: i64) -> Result<Entity> {
    let entity = new_entity(now)?;
    db.execute(
        "UPDATE blobs SET etag=?1, modified=?2 WHERE account=?3 AND container=?4 AND name=?5",
        params![
            entity.id,
            sqlite_int(entity.modified)?,
            blob_params(key)[0],
            blob_params(key)[1],
            blob_params(key)[2]
        ],
    )
    .map_err(db_error)?;
    Ok(entity)
}

fn payload_bytes(payload: Payload, size: u64) -> Result<Vec<u8>> {
    match payload {
        Payload::Memory(bytes) => Ok(bytes),
        Payload::Ranges(body) => body.into_vec(),
        Payload::Disk(file) => {
            let mut bytes = Vec::new();
            file.take(size).read_to_end(&mut bytes).map_err(io_error)?;
            if bytes.len() as u64 != size {
                return Err(internal("content changed during a range read"));
            }
            Ok(bytes)
        }
    }
}

/// Checks the lease and read conditions of a blob (or a retained snapshot or
/// version) row and opens the requested bytes. `source` says where the
/// in-memory backend keeps them.
pub(super) fn read_row(
    db: &rusqlite::Connection,
    mode: &Mode,
    now: i64,
    row: BlobRow,
    key: &BlobKey,
    options: &BlobRead,
    source: ContentSource,
) -> Result<Download> {
    row.lease.check(
        options.guard.lease,
        LeaseNeed::Optional,
        LeaseOwner::Blob,
        now,
    )?;
    options
        .guard
        .conditions
        .check(Some(row.info.entity), true)?;
    options.guard.conditions.check_tags(Some(&row.info.tags))?;
    let info = row.info;
    if options.with_body && matches!(info.tier, Some((AccessTier::Archive, _))) {
        return Err(Error::BlobArchived);
    }
    let range = options
        .range
        .as_ref()
        .map(|range| range.resolve(info.length))
        .transpose()?;
    let mut payload = None;
    if options.with_body && !info.kind.is_block() {
        let window = range.clone().unwrap_or(0..info.length.0);
        payload = Some(Payload::Ranges(pages::open_body(
            db,
            mode,
            key,
            info.length.0,
            window,
        )?));
    } else if options.with_body {
        let offset = range.as_ref().map_or(0, |range| range.start);
        payload = Some(match mode {
            Mode::Disk { extents, .. } => {
                Payload::Disk(open_extent(extents, info.entity.id, info.length.0, offset)?)
            }
            Mode::Memory { .. } => {
                let size = range
                    .as_ref()
                    .map_or(info.length.0, |range| range.end - range.start);
                Payload::Memory(read_memory_slice(db, source, info.entity.id, offset, size)?)
            }
        });
    }
    let mut range_checksum = None;
    if let Some(kind) = options.range_checksum
        && let Some(range) = &range
        && let Some(body) = payload.take()
    {
        let size = range.end - range.start;
        if size > MAX_RANGE_CHECKSUM {
            return Err(Error::InvalidHeader);
        }
        let bytes = payload_bytes(body, size)?;
        let mut hasher = Hasher::new();
        hasher.update(&bytes);
        let checksums = hasher.finish(None)?;
        range_checksum = Some(match kind {
            RangeChecksum::Md5 => ("content-md5", checksums.md5_text()),
            RangeChecksum::Crc64 => ("x-ms-content-crc64", checksums.crc64_text()),
        });
        payload = Some(Payload::Memory(bytes));
    }
    Ok(Download {
        info,
        range,
        payload,
        range_checksum,
    })
}

impl Store {
    pub(crate) async fn put_blob(
        &self,
        key: BlobKey,
        options: BlobWrite,
        upload: Uploaded,
    ) -> Result<Entity> {
        let hierarchical = self.hierarchical(&key.container);
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            container(&tx, &key.container)?;
            if hierarchical {
                namespace::prepare_file(&tx, &key, now)?;
            }
            let old = blob(&tx, &key, now)?;
            guard_write(&options.guard, old.as_ref(), true, now)?;
            let mut discard = remove_staged(&tx, &key)?;
            if let Some(old) = &old {
                discard.extend(pages::retire(&tx, mode, &key, old.info.kind)?);
            }
            check_memory_quota(
                &tx,
                mode,
                old.as_ref().map_or(0, |row| pages::block_length(&row.info)),
                upload.length.0,
            )?;
            let content = Content {
                length: upload.length,
                data: upload.data,
                computed_md5: Some(upload.checksums.md5),
            };
            let version = snapshots::begin_write(
                &tx,
                mode,
                &key,
                old.as_ref(),
                snapshots::Change::Content,
                now,
            )?;
            let entity = save_blob(&tx, mode, &key, &options, content, now)?;
            let entity = snapshots::finish_write(&tx, &key, entity, version, Some(&options.tags))?;
            tx.commit().map_err(db_error)?;
            if let Some(old) = old {
                reclaim(mode, old.info.entity.id);
            }
            for id in discard {
                reclaim(mode, id);
            }
            Ok(entity)
        })
        .await
    }

    pub(crate) async fn read_path(&self, key: BlobKey, options: BlobRead) -> Result<PathRead> {
        let hierarchical = self.hierarchical(&key.container);
        self.run(move |db, mode, now| {
            if hierarchical
                && let Some(entity) = namespace::directory(db, &key.container, key.path.as_str())?
            {
                if options.guard.lease.is_some() {
                    return Err(Error::LeaseNotPresentBlob);
                }
                options.guard.conditions.check(Some(entity), true)?;
                if options.range.is_some() {
                    return Err(Error::InvalidRange(0));
                }
                let metadata =
                    namespace::directory_metadata(db, &key.container, key.path.as_str())?;
                return Ok(PathRead::Directory(entity, metadata));
            }
            let row = require_blob(db, &key, now)?;
            read_row(db, mode, now, row, &key, &options, ContentSource::Blob)
                .map(|download| PathRead::File(Box::new(download)))
        })
        .await
    }

    /// Delete Blob or DFS Delete Path. A directory is removed only when empty;
    /// everything else goes through the snapshot-aware delete.
    pub(crate) async fn delete_path(
        &self,
        key: BlobKey,
        guard: Guard,
        removal: Removal,
    ) -> Result<Deletion> {
        if self.hierarchical(&key.container) && removal.selector.is_none() {
            let (directory_key, directory_guard) = (key.clone(), guard.clone());
            let removed = self
                .run(move |db, mode, _| {
                    let tx = db.transaction().map_err(db_error)?;
                    let Some(entity) = namespace::directory(
                        &tx,
                        &directory_key.container,
                        directory_key.path.as_str(),
                    )?
                    else {
                        return Ok(false);
                    };
                    if directory_guard.lease.is_some() {
                        return Err(Error::LeaseNotPresentBlob);
                    }
                    directory_guard.conditions.check(Some(entity), false)?;
                    let discard = namespace::remove_empty_directory(&tx, &directory_key)?;
                    tx.commit().map_err(db_error)?;
                    for id in discard {
                        reclaim(mode, id);
                    }
                    Ok(true)
                })
                .await?;
            if removed {
                return Ok(Deletion::Permanent);
            }
        }
        self.delete_blob(key, guard, removal).await
    }

    /// Set Blob Properties. When `replace` is true every content property is
    /// overwritten, so properties absent from the request are cleared. A page
    /// blob's `change` resizes it or updates its sequence number; the result is
    /// the blob's sequence number when it is a page blob.
    pub(crate) async fn set_blob_properties(
        &self,
        key: BlobKey,
        headers: ContentHeaders,
        md5: Option<[u8; 16]>,
        replace: bool,
        guard: Guard,
        change: PropertyChange,
    ) -> Result<(Entity, Option<u64>)> {
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            let old = require_blob(&tx, &key, now)?;
            guard_write(&guard, Some(&old), false, now)?;
            let (sequence, free) = pages::apply_change(&tx, mode, &key, &old.info, change)?;
            let version = snapshots::begin_write(
                &tx,
                mode,
                &key,
                Some(&old),
                snapshots::Change::Properties,
                now,
            )?;
            let entity = touch(&tx, &key, now)?;
            let entity = snapshots::finish_write(&tx, &key, entity, version, None)?;
            if replace {
                let [account, container, name] = blob_params(&key);
                tx.execute(
                    "UPDATE blobs SET content_type=?1, content_encoding=?2, content_language=?3,
                        content_disposition=?4, cache_control=?5, md5=?6
                     WHERE account=?7 AND container=?8 AND name=?9",
                    params![
                        headers.content_type,
                        headers.encoding,
                        headers.language,
                        headers.disposition,
                        headers.cache_control,
                        md5.map_or_else(String::new, |md5| {
                            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, md5)
                        }),
                        account,
                        container,
                        name
                    ],
                )
                .map_err(db_error)?;
            }
            tx.commit().map_err(db_error)?;
            pages::discard(mode, &free);
            Ok((entity, sequence))
        })
        .await
    }

    pub(crate) async fn set_blob_metadata(
        &self,
        key: BlobKey,
        metadata: Metadata,
        guard: Guard,
    ) -> Result<Entity> {
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            let old = require_blob(&tx, &key, now)?;
            guard_write(&guard, Some(&old), false, now)?;
            let json = serde_json::to_string(&metadata)
                .map_err(|_| internal("could not encode metadata"))?;
            let version = snapshots::begin_write(
                &tx,
                mode,
                &key,
                Some(&old),
                snapshots::Change::Properties,
                now,
            )?;
            let entity = touch(&tx, &key, now)?;
            let entity = snapshots::finish_write(&tx, &key, entity, version, None)?;
            let [account, container, name] = blob_params(&key);
            tx.execute(
                "UPDATE blobs SET metadata=?1 WHERE account=?2 AND container=?3 AND name=?4",
                params![json, account, container, name],
            )
            .map_err(db_error)?;
            tx.commit().map_err(db_error)?;
            Ok(entity)
        })
        .await
    }

    /// Set Blob Tier. Returns true when the blob was archived, which Azure answers
    /// with 202 because rehydration is asynchronous; here it completes immediately.
    pub(crate) async fn set_blob_tier(
        &self,
        key: BlobKey,
        tier: AccessTier,
        lease: Option<LeaseId>,
    ) -> Result<bool> {
        self.run(move |db, _, now| {
            let old = require_blob(db, &key, now)?;
            crate::blob_page::check_tier(old.info.kind, Some(tier))?;
            old.lease
                .check(lease, LeaseNeed::Optional, LeaseOwner::Blob, now)?;
            let [account, container, name] = blob_params(&key);
            let changed = super::seconds(now)?;
            db.execute(
                "UPDATE blobs SET access_tier=?1, access_tier_changed=?2
                 WHERE account=?3 AND container=?4 AND name=?5",
                params![tier.name(), sqlite_int(changed)?, account, container, name],
            )
            .map_err(db_error)?;
            Ok(matches!(old.info.tier, Some((AccessTier::Archive, _)))
                && tier != AccessTier::Archive)
        })
        .await
    }

    pub(crate) async fn lease_blob(
        &self,
        key: BlobKey,
        action: LeaseAction,
        conditions: Conditions,
    ) -> Result<LeaseResult> {
        self.run(move |db, _, now| {
            let tx = db.transaction().map_err(db_error)?;
            let row = require_blob(&tx, &key, now)?;
            conditions.check(Some(row.info.entity), false)?;
            conditions.check_tags(Some(&row.info.tags))?;
            let outcome = row.lease.apply(action, now)?;
            write_lease(&tx, "blobs", &blob_params(&key), &outcome.lease)?;
            tx.commit().map_err(db_error)?;
            Ok(LeaseResult {
                entity: row.info.entity,
                id: outcome.id,
                break_seconds: outcome.break_seconds,
            })
        })
        .await
    }

    /// Abort Copy Blob. Copies complete synchronously, so none is ever pending.
    pub(crate) async fn abort_copy(
        &self,
        key: BlobKey,
        copy_id: String,
        lease: Option<LeaseId>,
    ) -> Result<()> {
        self.run(move |db, _, now| {
            let row = require_blob(db, &key, now)?;
            row.lease
                .check(lease, LeaseNeed::Optional, LeaseOwner::Blob, now)?;
            match row.info.copy {
                Some(copy) if copy.id != copy_id => Err(Error::CopyIdMismatch),
                _ => Err(Error::NoPendingCopy),
            }
        })
        .await
    }
}
