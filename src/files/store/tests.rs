//! Store behavior that HTTP tests cannot reach: manual-clock leases, extent reclamation,
//! recovery of orphaned content, and memory-mode quota.

use super::*;
use crate::{
    clock::Clock,
    domain::AccountName,
    files::{
        error::Error,
        lease::Outcome,
        model::{Conditions, HttpProperties, Metadata, Posix, Protocol, SmbProperties, TimeSpec},
        name::{EntryPath, ShareName},
    },
};
use content::Staged;
use std::{path::Path, time::Duration};

fn share_ref(name: &str) -> ShareRef {
    ShareRef {
        account: AccountName::parse("testaccount").unwrap(),
        share: ShareName::parse(name).unwrap(),
        snapshot: None,
    }
}

fn path(value: &str) -> EntryPath {
    EntryPath::parse(value, false).unwrap()
}

async fn stage(store: &Store, bytes: &[u8]) -> Staged {
    let mut upload = store.begin_upload(bytes.len() as u64).await.unwrap();
    upload.append(bytes).await.unwrap();
    upload.finish(None).await.unwrap()
}

async fn new_file(store: &Store, share: &str, name: &str, length: u64) {
    store
        .create_file(
            share_ref(share),
            path(name),
            NewFile {
                length,
                http: HttpProperties::default(),
                smb: SmbProperties::for_create(),
                metadata: Metadata::new(),
                posix: Posix::default(),
            },
            None,
        )
        .await
        .unwrap();
}

async fn write(store: &Store, share: &str, name: &str, offset: u64, bytes: &[u8]) -> Result<()> {
    let staged = stage(store, bytes).await;
    store
        .put_range(
            share_ref(share),
            path(name),
            None,
            offset,
            staged,
            TimeSpec::Now,
        )
        .await
        .map(drop)
}

async fn read(store: &Store, share: &str, name: &str) -> Vec<u8> {
    use futures_util::TryStreamExt as _;
    let read = store
        .read_file(
            share_ref(share),
            path(name),
            ReadOptions {
                lease_id: None,
                conditions: Conditions::default(),
                range: None,
                want_md5: false,
                with_body: true,
            },
        )
        .await
        .unwrap();
    let chunks: Vec<_> = read.body.into_stream().try_collect().await.unwrap();
    chunks.concat()
}

fn extent_files(location: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(location.join("file").join("content"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

async fn create_share(store: &Store, name: &str) {
    store
        .create_share(
            share_ref(name),
            None,
            None,
            Metadata::new(),
            ShareOptions::default(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn fixed_share_leases_expire_on_the_manual_clock() {
    let clock = Clock::new();
    let store = Store::open(None, 1 << 20, clock.clone()).unwrap();
    create_share(&store, "leased").await;
    let (_, outcome) = store
        .lease_share(
            share_ref("leased"),
            LeaseRequest::Acquire {
                duration: 15,
                proposed: None,
            },
        )
        .await
        .unwrap();
    let Outcome::Acquired(id) = outcome else {
        panic!("expected an acquired lease");
    };
    let blocked = store
        .delete_share(share_ref("leased"), None, SnapshotPolicy::Refuse)
        .await;
    assert_eq!(blocked, Err(Error::LeaseIdMissingWithFileShareOperation));

    clock.advance(Duration::from_secs(16));
    let (_, renewed) = store
        .lease_share(share_ref("leased"), LeaseRequest::Renew(id.clone()))
        .await
        .unwrap();
    assert_eq!(
        renewed,
        Outcome::Renewed(id.clone()),
        "expired leases renew"
    );
    clock.advance(Duration::from_secs(16));
    store
        .delete_share(share_ref("leased"), None, SnapshotPolicy::Refuse)
        .await
        .expect("an expired lease no longer blocks deletes");
}

#[tokio::test]
async fn a_deleted_share_is_restorable_until_its_retention_ends() {
    let clock = Clock::new();
    let store = Store::open(None, 1 << 20, clock.clone()).unwrap();
    store.set_share_retention_days(2);
    create_share(&store, "keep").await;
    new_file(&store, "keep", "a.txt", 4).await;
    write(&store, "keep", "a.txt", 0, b"data").await.unwrap();
    store
        .delete_share(share_ref("keep"), None, SnapshotPolicy::Refuse)
        .await
        .unwrap();
    assert_eq!(
        store.share(share_ref("keep")).await.unwrap_err(),
        Error::ShareNotFound,
        "the name is free at once"
    );
    let account = AccountName::parse("testaccount").unwrap();
    let request = |deleted| ListSharesRequest {
        prefix: String::new(),
        after: None,
        limit: 10,
        snapshots: false,
        deleted,
    };
    let (live, _) = store
        .list_shares(account.clone(), request(false))
        .await
        .unwrap();
    assert!(live.is_empty());
    let (all, _) = store
        .list_shares(account.clone(), request(true))
        .await
        .unwrap();
    assert_eq!(all.len(), 1);
    let deleted = all[0].deleted.clone().unwrap();
    assert_eq!((all[0].name.as_str(), deleted.remaining_days), ("keep", 2));

    clock.advance(Duration::from_secs(86_400 + 60));
    let restored = store
        .restore_share(
            account.clone(),
            "keep".into(),
            deleted.version.clone(),
            "again".into(),
        )
        .await
        .unwrap();
    assert_eq!(restored.name, "again");
    assert_eq!(read(&store, "again", "a.txt").await, b"data");
    assert_eq!(
        store
            .restore_share(
                account.clone(),
                "keep".into(),
                deleted.version,
                "again".into()
            )
            .await
            .unwrap_err(),
        Error::ShareNotFound,
        "a version restores once"
    );

    store
        .delete_share(share_ref("again"), None, SnapshotPolicy::Refuse)
        .await
        .unwrap();
    clock.advance(Duration::from_secs(3 * 86_400));
    let (after, _) = store.list_shares(account, request(true)).await.unwrap();
    assert!(after.is_empty(), "an expired share is erased");
}
#[tokio::test]
async fn a_breaking_share_lease_becomes_broken_after_its_period() {
    let clock = Clock::new();
    let store = Store::open(None, 1 << 20, clock.clone()).unwrap();
    create_share(&store, "breaking").await;
    store
        .lease_share(
            share_ref("breaking"),
            LeaseRequest::Acquire {
                duration: -1,
                proposed: None,
            },
        )
        .await
        .unwrap();
    let (_, outcome) = store
        .lease_share(share_ref("breaking"), LeaseRequest::Break(Some(10)))
        .await
        .unwrap();
    assert_eq!(outcome, Outcome::Broken(10));
    assert_eq!(
        store
            .delete_share(share_ref("breaking"), None, SnapshotPolicy::Refuse)
            .await,
        Err(Error::LeaseIdMissingWithFileShareOperation)
    );
    clock.advance(Duration::from_secs(11));
    store
        .delete_share(share_ref("breaking"), None, SnapshotPolicy::Refuse)
        .await
        .unwrap();
}

#[tokio::test]
async fn file_leases_are_infinite_and_survive_the_clock() {
    let clock = Clock::new();
    let store = Store::open(None, 1 << 20, clock.clone()).unwrap();
    create_share(&store, "files").await;
    new_file(&store, "files", "a.txt", 10).await;
    store
        .lease_file(
            share_ref("files"),
            path("a.txt"),
            LeaseRequest::Acquire {
                duration: -1,
                proposed: None,
            },
        )
        .await
        .unwrap();
    clock.advance(Duration::from_secs(86_400));
    assert_eq!(
        write(&store, "files", "a.txt", 0, b"x").await,
        Err(Error::LeaseIdMissingWithFileOperation)
    );
}

#[tokio::test]
async fn overwritten_and_deleted_content_is_reclaimed_but_snapshots_keep_theirs() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(Some(directory.path()), 0, Clock::new()).unwrap();
    create_share(&store, "reclaim").await;
    new_file(&store, "reclaim", "a.bin", 100).await;
    write(&store, "reclaim", "a.bin", 0, &[1; 50])
        .await
        .unwrap();
    assert_eq!(extent_files(directory.path()).len(), 1);
    write(&store, "reclaim", "a.bin", 0, &[2; 50])
        .await
        .unwrap();
    assert_eq!(
        extent_files(directory.path()).len(),
        1,
        "the fully overwritten extent is collected"
    );

    let snapshot = store
        .snapshot_share(share_ref("reclaim"), None)
        .await
        .unwrap();
    write(&store, "reclaim", "a.bin", 0, &[3; 50])
        .await
        .unwrap();
    assert_eq!(
        extent_files(directory.path()).len(),
        2,
        "the snapshot holds the old extent"
    );
    let at_snapshot = ShareRef {
        snapshot: snapshot.snapshot,
        ..share_ref("reclaim")
    };
    let old = store
        .read_file(
            at_snapshot,
            path("a.bin"),
            ReadOptions {
                lease_id: None,
                conditions: Conditions::default(),
                range: None,
                want_md5: true,
                with_body: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(read(&store, "reclaim", "a.bin").await[..50], [3; 50]);
    assert!(old.md5.is_some());

    store
        .delete_file(share_ref("reclaim"), path("a.bin"), None)
        .await
        .unwrap();
    assert_eq!(
        extent_files(directory.path()).len(),
        1,
        "only the snapshot's extent remains"
    );
    store
        .delete_share(share_ref("reclaim"), None, SnapshotPolicy::Include)
        .await
        .unwrap();
    assert!(extent_files(directory.path()).is_empty());
}

#[tokio::test]
async fn a_rejected_range_write_leaves_no_extent_behind() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(Some(directory.path()), 0, Clock::new()).unwrap();
    create_share(&store, "reject").await;
    new_file(&store, "reject", "a.bin", 10).await;
    assert_eq!(
        write(&store, "reject", "a.bin", 8, &[1; 5]).await,
        Err(Error::InvalidRange)
    );
    assert_eq!(
        write(&store, "reject", "missing.bin", 0, &[1]).await,
        Err(Error::ResourceNotFound)
    );
    assert!(extent_files(directory.path()).is_empty());
}

#[tokio::test]
async fn startup_recovery_drops_orphans_and_keeps_referenced_extents() {
    let directory = tempfile::tempdir().unwrap();
    {
        let store = Store::open(Some(directory.path()), 0, Clock::new()).unwrap();
        create_share(&store, "recover").await;
        new_file(&store, "recover", "a.bin", 10).await;
        write(&store, "recover", "a.bin", 0, b"kept").await.unwrap();
        let content = directory.path().join("file").join("content");
        std::fs::write(content.join("incoming-partial"), b"half").unwrap();
        std::fs::write(
            content.join(format!("extent-{}", Uuid::new_v4().simple())),
            b"orphan",
        )
        .unwrap();
        assert_eq!(extent_files(directory.path()).len(), 3);
        assert!(
            Store::open(Some(directory.path()), 0, Clock::new()).is_err(),
            "a second process cannot open the same directory"
        );
    }
    let store = Store::open(Some(directory.path()), 0, Clock::new()).unwrap();
    assert_eq!(extent_files(directory.path()).len(), 1);
    assert_eq!(read(&store, "recover", "a.bin").await[..4], *b"kept");
}

#[tokio::test]
async fn a_hard_linked_file_keeps_its_extents_until_the_last_name_is_deleted() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(Some(directory.path()), 0, Clock::new()).unwrap();
    store
        .create_share(
            share_ref("nfs"),
            None,
            None,
            Metadata::new(),
            ShareOptions {
                protocol: Protocol::Nfs,
                ..ShareOptions::default()
            },
        )
        .await
        .unwrap();
    new_file(&store, "nfs", "a.bin", 100).await;
    write(&store, "nfs", "a.bin", 0, &[7; 40]).await.unwrap();
    let count = |name: &'static str| {
        let store = store.clone();
        async move {
            store
                .node(
                    share_ref("nfs"),
                    path(name),
                    Want::File,
                    None,
                    Conditions::default(),
                )
                .await
        }
    };
    for link in ["b.bin", "c.bin"] {
        store
            .create_hard_link(share_ref("nfs"), path(link), path("a.bin"))
            .await
            .unwrap();
    }
    let linked = count("c.bin").await.unwrap();
    assert_eq!(linked.links, 3);
    assert_eq!(linked.file_id, count("a.bin").await.unwrap().file_id);
    assert_eq!(extent_files(directory.path()).len(), 1);
    assert_eq!(store.share_usage(share_ref("nfs")).await.unwrap(), 40);

    // A snapshot of the share holds the file, links and all, by reference.
    let snapshot = store.snapshot_share(share_ref("nfs"), None).await.unwrap();

    // Each delete reports the count it leaves; the extent stays while any name does.
    let delete = |name: &'static str| {
        let store = store.clone();
        async move {
            store
                .delete_file(share_ref("nfs"), path(name), None)
                .await
                .unwrap()
        }
    };
    assert_eq!(
        delete("a.bin").await,
        Some(2),
        "the first name goes, the file stays"
    );
    assert_eq!(read(&store, "nfs", "c.bin").await[..40], [7; 40]);
    assert_eq!(count("b.bin").await.unwrap().links, 2);
    assert_eq!(delete("b.bin").await, Some(1));
    assert_eq!(delete("c.bin").await, Some(0));
    assert_eq!(
        extent_files(directory.path()).len(),
        1,
        "the snapshot still holds the extent after every live name is gone"
    );
    assert_eq!(store.share_usage(share_ref("nfs")).await.unwrap(), 0);

    let at_snapshot = ShareRef {
        snapshot: snapshot.snapshot,
        ..share_ref("nfs")
    };
    let kept = store
        .node(
            at_snapshot,
            path("b.bin"),
            Want::File,
            None,
            Conditions::default(),
        )
        .await
        .unwrap();
    assert_eq!(kept.links, 3, "the snapshot kept all three names");
    store
        .delete_share(share_ref("nfs"), None, SnapshotPolicy::Include)
        .await
        .unwrap();
    assert!(extent_files(directory.path()).is_empty());
}

#[tokio::test]
async fn memory_mode_enforces_its_quota_and_frees_overwritten_bytes() {
    let store = Store::open(None, 1000, Clock::new()).unwrap();
    create_share(&store, "quota").await;
    new_file(&store, "quota", "a.bin", 4000).await;
    write(&store, "quota", "a.bin", 0, &[1; 600]).await.unwrap();
    assert_eq!(
        write(&store, "quota", "a.bin", 1000, &[2; 600]).await,
        Err(Error::InsufficientStorage)
    );
    for _ in 0..5 {
        write(&store, "quota", "a.bin", 0, &[3; 600]).await.unwrap();
    }
    assert_eq!(read(&store, "quota", "a.bin").await[..600], [3; 600]);
    assert_eq!(
        store.begin_upload(1001).await.err(),
        Some(Error::InsufficientStorage)
    );
}

#[tokio::test]
async fn share_quota_limits_allocated_bytes_not_logical_size() {
    let store = Store::open(None, 1 << 30, Clock::new()).unwrap();
    store
        .create_share(
            share_ref("small"),
            Some(1),
            None,
            Metadata::new(),
            ShareOptions::default(),
        )
        .await
        .unwrap();
    new_file(&store, "small", "sparse.bin", 1 << 40).await;
    write(&store, "small", "sparse.bin", 1 << 39, b"fits")
        .await
        .unwrap();
    assert_eq!(store.share_usage(share_ref("small")).await.unwrap(), 4);
}

#[tokio::test]
async fn renaming_a_directory_moves_its_subtree_in_one_step() {
    let store = Store::open(None, 1 << 20, Clock::new()).unwrap();
    create_share(&store, "tree").await;
    for dir in ["a", "a/b"] {
        store
            .create_directory(
                share_ref("tree"),
                path(dir),
                SmbProperties::for_create(),
                Metadata::new(),
                Posix::default(),
            )
            .await
            .unwrap();
    }
    new_file(&store, "tree", "a/b/c.txt", 4).await;
    write(&store, "tree", "a/b/c.txt", 0, b"deep")
        .await
        .unwrap();
    store
        .rename(
            share_ref("tree"),
            path("A"),
            path("moved"),
            RenameFlags {
                replace: false,
                ignore_readonly: false,
                source_lease: None,
                dest_lease: None,
                content_type: None,
                metadata: None,
                smb: SmbProperties::for_update(),
            },
        )
        .await
        .unwrap();
    assert_eq!(read(&store, "tree", "Moved/B/c.txt").await, b"deep");
    assert_eq!(
        store
            .node(
                share_ref("tree"),
                path("a/b/c.txt"),
                Want::File,
                None,
                Conditions::default()
            )
            .await
            .err(),
        Some(Error::ParentNotFound)
    );
}
