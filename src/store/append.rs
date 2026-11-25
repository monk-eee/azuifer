//! Append blob writes: Append Block and Seal (ADR-0015).
//!
//! An append adds one immutable extent at the current end. Only the new range row,
//! the length, and the committed block count change, so appending never loads the
//! blob's existing ranges.

use super::{
    Store, Uploaded, blob_params,
    blobs::{guard_write, touch},
    check_memory_quota, db_error, internal,
    pages::stage_extent,
    require_blob, sqlite_int,
};
use crate::{
    blob_page::{AppendWrite, BlobKind, MAX_APPEND_BLOCKS, PageError},
    domain::{BlobKey, Entity, Error, Result},
};
use rusqlite::params;
use uuid::Uuid;

/// The outcome of an Append Block.
pub(crate) struct Appended {
    pub(crate) entity: Entity,
    /// Where the block starts in the blob.
    pub(crate) offset: u64,
    pub(crate) committed: u64,
}

impl Store {
    pub(crate) async fn append_block(
        &self,
        key: BlobKey,
        write: AppendWrite,
        upload: Uploaded,
    ) -> Result<Appended> {
        self.run(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            let old = require_blob(&tx, &key, now)?;
            let BlobKind::Append { committed, sealed } = old.info.kind else {
                return Err(Error::Page(PageError::InvalidBlobType));
            };
            guard_write(&write.guard, Some(&old), false, now)?;
            if sealed {
                return Err(Error::Page(PageError::BlobIsSealed));
            }
            let offset = old.info.length.0;
            let size = upload.length.0;
            write.condition.check(offset, size)?;
            if committed >= MAX_APPEND_BLOCKS {
                return Err(Error::BlockCountExceeded);
            }
            let committed = committed + 1;
            let id = Uuid::new_v4();
            let [account, container, name] = blob_params(&key);
            stage_extent(&tx, mode, id, &upload.data, size)?;
            tx.execute(
                "INSERT INTO blob_ranges (account, container, name, offset, length, extent, extent_offset)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                params![account, container, name, sqlite_int(offset)?, sqlite_int(size)?, id],
            )
            .map_err(db_error)?;
            let end = offset
                .checked_add(size)
                .ok_or_else(|| internal("append length overflow"))?;
            tx.execute(
                "UPDATE blobs SET length=?1, append_count=?2
                 WHERE account=?3 AND container=?4 AND name=?5",
                params![sqlite_int(end)?, sqlite_int(committed)?, account, container, name],
            )
            .map_err(db_error)?;
            check_memory_quota(&tx, mode, 0, 0)?;
            let entity = touch(&tx, &key, now)?;
            upload.data.persist(mode, id)?;
            tx.commit().map_err(db_error)?;
            Ok(Appended {
                entity,
                offset,
                committed,
            })
        })
        .await
    }

    /// Seal makes an append blob read-only. Sealing a sealed blob changes nothing.
    pub(crate) async fn seal_blob(&self, key: BlobKey, write: AppendWrite) -> Result<Entity> {
        self.run(move |db, _, now| {
            let tx = db.transaction().map_err(db_error)?;
            let old = require_blob(&tx, &key, now)?;
            let BlobKind::Append { sealed, .. } = old.info.kind else {
                return Err(Error::Page(PageError::InvalidBlobType));
            };
            guard_write(&write.guard, Some(&old), false, now)?;
            write.condition.check(old.info.length.0, 0)?;
            if sealed {
                return Ok(old.info.entity);
            }
            let [account, container, name] = blob_params(&key);
            tx.execute(
                "UPDATE blobs SET sealed=1 WHERE account=?1 AND container=?2 AND name=?3",
                params![account, container, name],
            )
            .map_err(db_error)?;
            let entity = touch(&tx, &key, now)?;
            tx.commit().map_err(db_error)?;
            Ok(entity)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blob_page::{AppendCondition, Creation},
        clock::Clock,
        conditions::Guard,
        domain::{
            AccountName, BlobPath, BlobWrite, ContainerCreate, ContainerKey, ContainerName,
            ContentHeaders, ContentLength, PublicAccess,
        },
    };
    use std::collections::BTreeSet;

    async fn store_with_append_blob() -> (Store, BlobKey) {
        let store = Store::open(None, 1 << 20, Clock::new(), Default::default()).unwrap();
        let container = ContainerKey {
            account: AccountName::parse("testaccount").unwrap(),
            name: ContainerName::parse("box").unwrap(),
        };
        store
            .create_container(
                container.clone(),
                ContainerCreate {
                    metadata: Default::default(),
                    public_access: PublicAccess::Private,
                },
            )
            .await
            .unwrap();
        let key = BlobKey {
            container,
            path: BlobPath::parse("log".into()).unwrap(),
        };
        let options = BlobWrite {
            headers: ContentHeaders::default(),
            metadata: Default::default(),
            guard: Guard::default(),
            tier: None,
            copy: None,
            md5: None,
            tags: Default::default(),
        };
        store
            .create_paged(key.clone(), options, Creation::Append)
            .await
            .unwrap();
        (store, key)
    }

    async fn append_one(store: &Store, key: &BlobKey) -> Result<Appended> {
        let mut upload = store.begin_upload(ContentLength(1)).await?;
        upload.append(b"x").await?;
        let upload = upload.finish(None).await?;
        let write = AppendWrite {
            condition: AppendCondition::default(),
            guard: Guard::default(),
        };
        store.append_block(key.clone(), write, upload).await
    }

    #[tokio::test]
    async fn append_blobs_on_hns_accounts_create_parents_and_reject_collisions() {
        let account = AccountName::parse("testaccount").unwrap();
        let store = Store::open(
            None,
            1 << 20,
            Clock::new(),
            std::collections::HashSet::from([account.clone()]),
        )
        .unwrap();
        let container = ContainerKey {
            account,
            name: ContainerName::parse("box").unwrap(),
        };
        store
            .create_container(
                container.clone(),
                ContainerCreate {
                    metadata: Default::default(),
                    public_access: PublicAccess::Private,
                },
            )
            .await
            .unwrap();
        let key = |path: &str| BlobKey {
            container: container.clone(),
            path: BlobPath::parse(path.into()).unwrap(),
        };
        let options = || BlobWrite {
            headers: ContentHeaders::default(),
            metadata: Default::default(),
            guard: Guard::default(),
            tier: None,
            copy: None,
            md5: None,
            tags: Default::default(),
        };
        store
            .create_paged(key("a/b/log"), options(), Creation::Append)
            .await
            .unwrap();
        let directories: i64 = store
            .0
            .db
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM directories", [], |row| row.get(0))
            .unwrap();
        assert_eq!(directories, 2, "a and a/b are created with the blob");
        assert_eq!(
            store
                .create_paged(key("a"), options(), Creation::Append)
                .await
                .err(),
            Some(Error::PathConflict),
            "a file cannot shadow a directory"
        );
        assert_eq!(
            store
                .create_paged(key("a/b/log/child"), options(), Creation::Append)
                .await
                .err(),
            Some(Error::PathConflict),
            "a path cannot sit under a file"
        );
    }

    #[tokio::test]
    async fn the_fifty_thousandth_block_is_the_last() {
        let (store, key) = store_with_append_blob().await;
        {
            let db = store.0.db.lock().unwrap();
            db.execute(
                "UPDATE blobs SET append_count=?1",
                [MAX_APPEND_BLOCKS as i64 - 1],
            )
            .unwrap();
        }
        let last = append_one(&store, &key).await.unwrap();
        assert_eq!(last.committed, MAX_APPEND_BLOCKS);
        assert_eq!(
            append_one(&store, &key).await.err(),
            Some(Error::BlockCountExceeded)
        );
    }

    #[tokio::test]
    async fn concurrent_appends_get_distinct_contiguous_offsets() {
        let (store, key) = store_with_append_blob().await;
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let (store, key) = (store.clone(), key.clone());
                tokio::spawn(async move { append_one(&store, &key).await.unwrap().offset })
            })
            .collect();
        let mut offsets = BTreeSet::new();
        for task in tasks {
            offsets.insert(task.await.unwrap());
        }
        assert_eq!(offsets, (0..16).collect());
    }
}
