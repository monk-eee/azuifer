use super::{
    Content, ContentSource, Mode, Store, Uploaded, UploadedData, blob, blob_params,
    blobs::guard_write, check_memory_quota, container, db_error, internal, io_error, open_extent,
    read_memory_slice, reclaim, remove_staged, row_uint, save_blob, sqlite_int, staging_file,
};
use crate::{
    conditions::Guard,
    domain::{
        BlobKey, BlobWrite, BlockId, BlockList, BlockListKind, BlockSelection, BlockSource,
        ContentLength, Entity, Error, Result,
    },
    lease::{LeaseId, LeaseNeed, LeaseOwner},
};
use rusqlite::{Connection, OptionalExtension as _, params};
use std::{
    collections::HashMap,
    io::{Read as _, Write},
};
use uuid::Uuid;

const MAX_STAGED_BLOCKS: u32 = 100_000;

struct BlockRange {
    extent: Uuid,
    extent_length: u64,
    offset: u64,
    length: u64,
    source: ContentSource,
}

impl Store {
    pub(crate) async fn put_block(
        &self,
        key: BlobKey,
        block: BlockId,
        upload: Uploaded,
        lease: Option<LeaseId>,
    ) -> Result<()> {
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            container(&tx, &key.container)?;
            match blob(&tx, &key, now)? {
                Some(row) => row
                    .lease
                    .check(lease, LeaseNeed::Required, LeaseOwner::Blob, now)?,
                None if lease.is_some() => return Err(Error::LeaseNotPresentBlob),
                None => (),
            }
            let [account, container, name] = blob_params(&key);
            let (width, count): (Option<u32>, u32) = tx.query_row(
                "SELECT MIN(width), COUNT(*) FROM staged_blocks WHERE account=?1 AND container=?2 AND name=?3",
                [account, container, name], |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(db_error)?;
            if width.is_some_and(|width| width as usize != block.width) {
                return Err(Error::InvalidBlockId);
            }
            let existing = tx.query_row(
                "SELECT id, length FROM staged_blocks WHERE account=?1 AND container=?2 AND name=?3 AND block_id=?4",
                [account, container, name, block.as_str()], |row| Ok((row.get::<_, Uuid>(0)?, row_uint(row, 1)?)),
            ).optional().map_err(db_error)?;
            if existing.is_none() && count >= MAX_STAGED_BLOCKS {
                return Err(Error::BlockCountExceeded);
            }
            check_memory_quota(&tx, mode, existing.map_or(0, |(_, length)| length), upload.length.0)?;
            let id = Uuid::new_v4();
            tx.execute(
                "INSERT INTO staged_blocks VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(account,container,name,block_id) DO UPDATE SET
                    id=excluded.id, length=excluded.length, bytes=excluded.bytes",
                params![account, container, name, block.as_str(), block.width as u32, id,
                        sqlite_int(upload.length.0)?, upload.data.bytes()],
            ).map_err(db_error)?;
            upload.data.persist(mode, id)?;
            tx.commit().map_err(db_error)?;
            if let Some((old, _)) = existing {
                reclaim(mode, old);
            }
            Ok(())
        }).await
    }

    pub(crate) async fn commit_blocks(
        &self,
        key: BlobKey,
        options: BlobWrite,
        blocks: Vec<BlockSelection>,
        limit: u64,
    ) -> Result<Entity> {
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            container(&tx, &key.container)?;
            let old = blob(&tx, &key, now)?;
            guard_write(&options.guard, old.as_ref(), true, now)?;
            let staged: HashMap<_, _> = staged(&tx, &key)?.into_iter().collect();
            let committed: HashMap<_, _> = if let Some(old) = &old {
                committed(&tx, &key, old.info.entity.id, old.info.length.0)?
                    .into_iter()
                    .collect()
            } else {
                HashMap::new()
            };
            let mut total = 0u64;
            let mut resolved = Vec::with_capacity(blocks.len());
            for block in &blocks {
                let id = block.id.as_str();
                let range = match block.source {
                    BlockSource::Committed => committed.get(id),
                    BlockSource::Uncommitted => staged.get(id),
                    BlockSource::Latest => staged.get(id).or_else(|| committed.get(id)),
                }
                .ok_or(Error::InvalidBlockList)?;
                let offset = total;
                total = total
                    .checked_add(range.length)
                    .filter(|total| *total <= limit)
                    .ok_or(Error::TooLarge)?;
                resolved.push((id, offset, range));
            }
            let retired = staged.values().map(|block| block.length).sum::<u64>()
                + old.as_ref().map_or(0, |row| row.info.length.0);
            check_memory_quota(&tx, mode, retired, total)?;
            let mut assembled = match mode {
                Mode::Disk { extents, .. } => {
                    UploadedData::Disk(staging_file(extents).map_err(io_error)?)
                }
                Mode::Memory { .. } => UploadedData::Memory(Vec::new()),
            };
            for (_, _, block) in &resolved {
                copy_block(&tx, mode, block, assembled.writer())?;
            }
            let content = Content {
                length: ContentLength(total),
                data: assembled,
                computed_md5: None,
            };
            let entity = save_blob(&tx, mode, &key, &options, content, now)?;
            let discard = remove_staged(&tx, &key)?;
            {
                let [account, container, name] = blob_params(&key);
                let mut insert = tx
                    .prepare("INSERT INTO committed_blocks VALUES (?1,?2,?3,?4,?5,?6,?7)")
                    .map_err(db_error)?;
                for (index, (id, offset, block)) in resolved.into_iter().enumerate() {
                    insert
                        .execute(params![
                            account,
                            container,
                            name,
                            index as u32,
                            id,
                            sqlite_int(offset)?,
                            sqlite_int(block.length)?
                        ])
                        .map_err(db_error)?;
                }
            }
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

    pub(crate) async fn blocks(
        &self,
        key: BlobKey,
        kind: BlockListKind,
        guard: Guard,
    ) -> Result<BlockList> {
        self.run(move |db, _, now| {
            container(db, &key.container)?;
            let row = blob(db, &key, now)?;
            let uncommitted = if kind == BlockListKind::Committed {
                None
            } else {
                Some(staged(db, &key)?)
            };
            if row.is_none() && uncommitted.as_ref().is_none_or(Vec::is_empty) {
                return Err(Error::BlobMissing);
            }
            let blob = row.as_ref().map(|row| &row.info);
            if let Some(row) = &row {
                row.lease
                    .check(guard.lease, LeaseNeed::Optional, LeaseOwner::Blob, now)?;
            } else if guard.lease.is_some() {
                return Err(Error::LeaseNotPresentBlob);
            }
            let entity = blob.map(|blob| blob.entity);
            guard.conditions.check(entity, true)?;
            let committed = if kind == BlockListKind::Uncommitted {
                None
            } else if let Some(blob) = blob {
                Some(committed(db, &key, blob.entity.id, blob.length.0)?)
            } else {
                Some(Vec::new())
            };
            let describe = |entries: Vec<(String, BlockRange)>| {
                entries
                    .into_iter()
                    .map(|(name, block)| (name, ContentLength(block.length)))
                    .collect()
            };
            Ok(BlockList {
                entity,
                length: blob.map_or(ContentLength(0), |blob| blob.length),
                committed: committed.map(describe),
                uncommitted: uncommitted.map(describe),
            })
        })
        .await
    }
}

fn staged(db: &Connection, key: &BlobKey) -> Result<Vec<(String, BlockRange)>> {
    let mut query = db
        .prepare(
            "SELECT block_id, id, length FROM staged_blocks
         WHERE account=?1 AND container=?2 AND name=?3 ORDER BY block_id",
        )
        .map_err(db_error)?;
    query
        .query_map(blob_params(key), |row| {
            let length = row_uint(row, 2)?;
            Ok((
                row.get(0)?,
                BlockRange {
                    extent: row.get(1)?,
                    length,
                    extent_length: length,
                    offset: 0,
                    source: ContentSource::StagedBlock,
                },
            ))
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)
}

fn committed(
    db: &Connection,
    key: &BlobKey,
    id: Uuid,
    extent_length: u64,
) -> Result<Vec<(String, BlockRange)>> {
    let mut query = db
        .prepare(
            "SELECT block_id, offset, length FROM committed_blocks
         WHERE account=?1 AND container=?2 AND name=?3 ORDER BY position",
        )
        .map_err(db_error)?;
    query
        .query_map(blob_params(key), |row| {
            Ok((
                row.get(0)?,
                BlockRange {
                    extent: id,
                    extent_length,
                    offset: row_uint(row, 1)?,
                    length: row_uint(row, 2)?,
                    source: ContentSource::Blob,
                },
            ))
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)
}

fn copy_block(
    db: &Connection,
    mode: &Mode,
    block: &BlockRange,
    dest: &mut dyn Write,
) -> Result<()> {
    if block
        .offset
        .checked_add(block.length)
        .is_none_or(|end| end > block.extent_length)
    {
        return Err(internal("block range exceeds extent length"));
    }
    match mode {
        Mode::Disk { extents, .. } => {
            let mut file = open_extent(extents, block.extent, block.extent_length, block.offset)?
                .take(block.length);
            let copied = std::io::copy(&mut file, dest).map_err(io_error)?;
            if copied != block.length {
                return Err(internal("block changed during assembly"));
            }
        }
        Mode::Memory { .. } => {
            let bytes =
                read_memory_slice(db, block.source, block.extent, block.offset, block.length)?;
            dest.write_all(&bytes).map_err(io_error)?;
        }
    }
    Ok(())
}
