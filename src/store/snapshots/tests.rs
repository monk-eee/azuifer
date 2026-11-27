//! Tests of extent sharing and retention across snapshots, versions and soft delete.

use super::*;
use crate::{
    blob_snapshot::{DeleteSnapshots, Removal},
    domain::{Include, ListRequest},
};
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
