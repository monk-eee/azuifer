//! Randomized comparison of NFS file shares (hard links, symbolic links, ranges, copies,
//! renames, snapshots and quota) with an inode-table oracle (specification section 14).
//!
//! The oracle is a table of inodes and a map of names to inodes. Each byte of an inode
//! remembers which extent write produced it, so the oracle also knows exactly which extents
//! are still referenced by the live share or a snapshot: on disk the store must hold one
//! extent file for each, no more (a leak) and no fewer (freed too early).

use super::tests::{extent_files, path, share_ref, stage};
use super::*;
use crate::{
    files::{
        error::Error,
        model::{Conditions, FileKind, Metadata, Protocol, SmbProperties, TimeSpec},
    },
    prng::Rng,
};
use futures_util::TryStreamExt as _;
use std::collections::{BTreeMap, BTreeSet};

const NAMES: [&str; 5] = ["n0", "n1", "n2", "n3", "n4"];
const MAX_LENGTH: u64 = 40;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Content {
    /// Bytes as read, and for each byte the extent write that allocated it.
    File {
        data: Vec<u8>,
        extents: Vec<Option<u32>>,
    },
    Symlink(String),
}

#[derive(Clone, Default)]
struct State {
    names: BTreeMap<&'static str, usize>,
    inodes: BTreeMap<usize, Content>,
}

/// An error a case must report exactly (`Some`), or any error at all (`None`).
type Refused = Option<Error>;
type Judged<T> = std::result::Result<T, Refused>;

impl State {
    fn links(&self, inode: usize) -> u32 {
        self.names.values().filter(|i| **i == inode).count() as u32
    }

    fn fresh(&self) -> usize {
        self.inodes.keys().next_back().map_or(1, |last| last + 1)
    }

    /// Removes `name`, and its inode with the last name; returns the links left.
    fn unlink(&mut self, name: &str) -> u32 {
        let inode = self.names.remove(name).unwrap_or_default();
        let left = self.links(inode);
        if left == 0 {
            self.inodes.remove(&inode);
        }
        left
    }

    fn regular(&self, name: &str) -> Judged<usize> {
        let inode = *self.names.get(name).ok_or(None)?;
        match self.inodes.get(&inode) {
            Some(Content::File { .. }) => Ok(inode),
            _ => Err(Some(Error::XNfs4FileTypeUnsupportedException)),
        }
    }

    fn tokens(&self) -> BTreeSet<u32> {
        let files = self.inodes.values();
        files
            .filter_map(|content| match content {
                Content::File { extents, .. } => Some(extents.iter().flatten().copied()),
                Content::Symlink(_) => None,
            })
            .flatten()
            .collect()
    }

    fn allocated(&self) -> u64 {
        self.inodes
            .values()
            .map(|content| match content {
                Content::File { extents, .. } => extents.iter().flatten().count() as u64,
                Content::Symlink(_) => 0,
            })
            .sum()
    }

    fn file_mut(&mut self, inode: usize) -> (&mut Vec<u8>, &mut Vec<Option<u32>>) {
        match self.inodes.get_mut(&inode) {
            Some(Content::File { data, extents }) => (data, extents),
            _ => unreachable!("the caller checked that the inode is a regular file"),
        }
    }

    fn create_file(&mut self, name: &'static str, length: u64) -> Judged<()> {
        let blank = Content::File {
            data: vec![0; length as usize],
            extents: vec![None; length as usize],
        };
        match self.names.get(name).copied() {
            Some(inode) => {
                if matches!(self.inodes.get(&inode), Some(Content::Symlink(_))) {
                    return Err(Some(Error::XNfs4FileTypeUnsupportedException));
                }
                self.inodes.insert(inode, blank);
            }
            None => {
                let inode = self.fresh();
                self.inodes.insert(inode, blank);
                self.names.insert(name, inode);
            }
        }
        Ok(())
    }

    fn create_symlink(&mut self, name: &'static str, text: String) -> Judged<()> {
        if self.names.contains_key(name) {
            return Err(Some(Error::ResourceAlreadyExists));
        }
        let inode = self.fresh();
        self.inodes.insert(inode, Content::Symlink(text));
        self.names.insert(name, inode);
        Ok(())
    }

    fn hard_link(&mut self, name: &'static str, source: &str) -> Judged<()> {
        if self.names.contains_key(name) {
            return Err(Some(Error::ResourceAlreadyExists));
        }
        let inode = *self.names.get(source).ok_or(None)?;
        if matches!(self.inodes.get(&inode), Some(Content::Symlink(_))) {
            return Err(Some(Error::XNfs4FileTypeUnsupportedException));
        }
        self.names.insert(name, inode);
        Ok(())
    }

    fn write(&mut self, name: &str, at: u64, bytes: &[u8], extent: u32) -> Judged<()> {
        let inode = self.regular(name)?;
        let (data, extents) = self.file_mut(inode);
        let end = at + bytes.len() as u64;
        if end > data.len() as u64 {
            return Err(Some(Error::InvalidRange));
        }
        data[at as usize..end as usize].copy_from_slice(bytes);
        extents[at as usize..end as usize].fill(Some(extent));
        Ok(())
    }

    fn clear(&mut self, name: &str, at: u64, length: u64) -> Judged<()> {
        let inode = self.regular(name)?;
        let (data, extents) = self.file_mut(inode);
        let end = at + length;
        if end > data.len() as u64 {
            return Err(Some(Error::InvalidRange));
        }
        data[at as usize..end as usize].fill(0);
        extents[at as usize..end as usize].fill(None);
        Ok(())
    }

    fn resize(&mut self, name: &str, length: u64) -> Judged<()> {
        let inode = *self.names.get(name).ok_or(None)?;
        if let Some(Content::Symlink(text)) = self.inodes.get(&inode) {
            return if text.len() as u64 == length {
                Ok(())
            } else {
                Err(Some(Error::XNfs4FileTypeUnsupportedException))
            };
        }
        let (data, extents) = self.file_mut(inode);
        data.resize(length as usize, 0);
        extents.resize(length as usize, None);
        Ok(())
    }

    fn copy(&mut self, name: &'static str, source: &str) -> Judged<()> {
        let from = *self
            .names
            .get(source)
            .ok_or(Some(Error::CannotVerifyCopySource))?;
        let Some(content) = self.inodes.get(&from).cloned() else {
            return Err(None);
        };
        if matches!(content, Content::Symlink(_)) {
            return Err(Some(Error::XNfs4FileTypeUnsupportedException));
        }
        match self.names.get(name).copied() {
            Some(existing) => {
                if matches!(self.inodes.get(&existing), Some(Content::Symlink(_))) {
                    return Err(Some(Error::XNfs4FileTypeUnsupportedException));
                }
                if existing == from {
                    return Err(Some(Error::InvalidInput));
                }
                self.inodes.insert(existing, content);
            }
            None => {
                let inode = self.fresh();
                self.inodes.insert(inode, content);
                self.names.insert(name, inode);
            }
        }
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &'static str, replace: bool) -> Judged<()> {
        let inode = *self.names.get(from).ok_or(None)?;
        match self.names.get(to).copied() {
            Some(existing) if existing != inode => {
                if !replace {
                    return Err(Some(Error::ResourceAlreadyExists));
                }
                self.unlink(to);
            }
            // The same file under another name is left as it is.
            Some(_) => return Ok(()),
            None => {}
        }
        self.names.remove(from);
        self.names.insert(to, inode);
        Ok(())
    }

    fn delete(&mut self, name: &str) -> Judged<u32> {
        if !self.names.contains_key(name) {
            return Err(None);
        }
        Ok(self.unlink(name))
    }
}

struct Run {
    store: Store,
    root: Option<tempfile::TempDir>,
    state: State,
    snapshots: Vec<(i64, State)>,
    rng: Rng,
    extent: u32,
    label: String,
}

fn nfs_options() -> ShareOptions {
    ShareOptions {
        protocol: Protocol::Nfs,
        ..ShareOptions::default()
    }
}

fn at_snapshot(snapshot: Option<i64>) -> ShareRef {
    ShareRef {
        snapshot,
        ..share_ref("model")
    }
}

thread_local! {
    static TRACE: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn trace() -> String {
    TRACE.with(|trace| {
        let trace = trace.borrow();
        trace[trace.len().saturating_sub(14)..].join("\n")
    })
}

fn compare<T: std::fmt::Debug + PartialEq>(real: Result<T>, expected: Judged<T>, at: &str) {
    TRACE.with(|trace| {
        trace
            .borrow_mut()
            .push(format!("{at}: {real:?} / {expected:?}"))
    });
    match (real, expected) {
        (Ok(real), Ok(expected)) => assert_eq!(real, expected, "{at}"),
        (Err(real), Err(Some(expected))) => assert_eq!(real, expected, "{at}"),
        (Err(error), Err(None)) => assert_ne!(error, Error::Internal, "{at}: {error:?}"),
        (real, expected) => panic!("{at}: the store gave {real:?}, the oracle {expected:?}"),
    }
}

async fn read_at(store: &Store, share: ShareRef, name: &str) -> Result<Vec<u8>> {
    let read = store
        .read_file(
            share,
            path(name),
            ReadOptions {
                lease_id: None,
                conditions: Conditions::default(),
                range: None,
                want_md5: false,
                with_body: true,
            },
        )
        .await?;
    let chunks: Vec<_> = read.body.into_stream().try_collect().await.unwrap();
    Ok(chunks.concat())
}

async fn node(store: &Store, share: ShareRef, name: &str) -> Result<NodeInfo> {
    store
        .node(share, path(name), Want::File, None, Conditions::default())
        .await
}

impl Run {
    async fn start(seed: u64, disk: bool) -> Self {
        let root = disk.then(|| tempfile::tempdir().unwrap());
        let store = Store::open(root.as_ref().map(|r| r.path()), 1 << 30, Clock::new()).unwrap();
        store
            .create_share(
                share_ref("model"),
                None,
                None,
                Metadata::new(),
                nfs_options(),
            )
            .await
            .unwrap();
        Self {
            store,
            root,
            state: State::default(),
            snapshots: Vec::new(),
            rng: Rng::seeded(seed),
            extent: 0,
            label: format!("seed {seed} disk={disk}"),
        }
    }

    fn name(&mut self) -> &'static str {
        self.rng.pick(&NAMES)
    }

    async fn step(&mut self, step: u32) {
        let at = format!("{} step {step}", self.label);
        let store = self.store.clone();
        let target = share_ref("model");
        let (a, b) = (self.name(), self.name());
        let length = self.rng.below(MAX_LENGTH + 1);
        let offset = self.rng.below(MAX_LENGTH);
        let span = self.rng.below(9) + 1;
        match self.rng.below(100) {
            0..=14 => {
                let new = NewFile {
                    length,
                    http: Default::default(),
                    smb: SmbProperties::for_create(),
                    metadata: Metadata::new(),
                    posix: Default::default(),
                };
                let real = store.create_file(target, path(a), new, None).await;
                compare(
                    real.map(drop),
                    self.state.create_file(a, length),
                    &format!("{at}: create {a}"),
                );
            }
            15..=22 => {
                let text = format!("target-{}", self.rng.below(100));
                let real = store
                    .create_symlink(
                        target,
                        path(a),
                        text.clone(),
                        Default::default(),
                        Metadata::new(),
                        SmbProperties::for_create(),
                    )
                    .await;
                compare(
                    real.map(drop),
                    self.state.create_symlink(a, text),
                    &format!("{at}: symlink {a}"),
                );
            }
            23..=36 => {
                let real = store.create_hard_link(target, path(a), path(b)).await;
                let expected = self
                    .state
                    .hard_link(a, b)
                    .map(|()| self.state.links(self.state.names[a]));
                compare(
                    real.map(|info| info.links),
                    expected,
                    &format!("{at}: link {a} -> {b}"),
                );
            }
            37..=58 => {
                self.extent += 1;
                let bytes: Vec<u8> = (0..span)
                    .map(|i| (self.extent as u8).wrapping_add(i as u8))
                    .collect();
                let staged = stage(&store, &bytes).await;
                let real = store
                    .put_range(target, path(a), None, offset, staged, TimeSpec::Now)
                    .await;
                compare(
                    real.map(drop),
                    self.state.write(a, offset, &bytes, self.extent),
                    &format!("{at}: put {a} @{offset}+{span}"),
                );
            }
            59..=66 => {
                let real = store
                    .clear_range(target, path(a), None, offset, span, TimeSpec::Now)
                    .await;
                compare(
                    real.map(drop),
                    self.state.clear(a, offset, span),
                    &format!("{at}: clear {a} @{offset}+{span}"),
                );
            }
            67..=72 => {
                let patch = FilePatch {
                    length: Some(length),
                    http: None,
                    smb: SmbProperties::for_create(),
                    posix: Default::default(),
                };
                let real = store
                    .set_file_properties(target, path(a), None, patch)
                    .await;
                compare(
                    real.map(drop),
                    self.state.resize(a, length),
                    &format!("{at}: resize {a} to {length}"),
                );
            }
            73..=80 => {
                let source = CopySource {
                    target: share_ref("model"),
                    path: path(b),
                    url: format!("http://model/{b}"),
                };
                let request = CopyRequest {
                    dest_lease: None,
                    ignore_readonly: false,
                    metadata: None,
                    smb: None,
                    nfs: Default::default(),
                };
                let real = store.copy_file(source, target, path(a), request).await;
                compare(
                    real.map(drop),
                    self.state.copy(a, b),
                    &format!("{at}: copy {b} -> {a}"),
                );
            }
            81..=88 => {
                let replace = self.rng.below(2) == 0;
                let flags = RenameFlags {
                    replace,
                    ignore_readonly: false,
                    source_lease: None,
                    dest_lease: None,
                    content_type: None,
                    metadata: None,
                    smb: SmbProperties::for_create(),
                };
                let real = store.rename(target, path(b), path(a), flags).await;
                compare(
                    real.map(drop),
                    self.state.rename(b, a, replace),
                    &format!("{at}: rename {b} -> {a} replace={replace}"),
                );
            }
            89..=96 => {
                let real = store.delete_file(target, path(a), None).await;
                compare(
                    real,
                    self.state.delete(a).map(Some),
                    &format!("{at}: delete {a}"),
                );
            }
            _ => {
                let info = store.snapshot_share(target, None).await.unwrap();
                let id = info.snapshot.expect("a snapshot has an id");
                self.snapshots.push((id, self.state.clone()));
            }
        }
        self.check(&at).await;
    }

    async fn check_state(&self, share: ShareRef, state: &State, at: &str) {
        let mut ids: BTreeMap<&str, i64> = BTreeMap::new();
        for name in NAMES {
            let found = node(&self.store, share.clone(), name).await;
            let Some(inode) = state.names.get(name) else {
                assert!(found.is_err(), "{at}: {name} should not exist");
                continue;
            };
            let info = found.unwrap_or_else(|error| panic!("{at}: {name}: {error:?}\n{}", trace()));
            ids.insert(name, info.file_id);
            assert_eq!(info.links, state.links(*inode), "{at}: links of {name}");
            let nfs = info
                .nfs
                .as_ref()
                .expect("an NFS share has POSIX properties");
            match &state.inodes[inode] {
                Content::File { data, .. } => {
                    assert_eq!(nfs.kind, FileKind::Regular, "{at}: kind of {name}");
                    assert_eq!(info.length, data.len() as u64, "{at}: length of {name}");
                    let bytes = read_at(&self.store, share.clone(), name).await;
                    assert_eq!(bytes.as_ref(), Ok(data), "{at}: bytes of {name}");
                }
                Content::Symlink(text) => {
                    assert_eq!(nfs.kind, FileKind::SymLink, "{at}: kind of {name}");
                    assert_eq!(
                        nfs.link_text.as_deref(),
                        Some(text.as_str()),
                        "{at}: link of {name}"
                    );
                    assert_eq!(info.length, text.len() as u64, "{at}: symlink length");
                }
            }
        }
        for (first, left) in &ids {
            for (second, right) in &ids {
                let same = state.names[first] == state.names[second];
                assert_eq!(
                    left == right,
                    same,
                    "{at}: {first} and {second} share an inode"
                );
            }
        }
    }

    async fn check(&self, at: &str) {
        self.check_state(share_ref("model"), &self.state, at).await;
        for (id, state) in &self.snapshots {
            self.check_state(
                at_snapshot(Some(*id)),
                state,
                &format!("{at}: snapshot {id}"),
            )
            .await;
        }
        let usage = self.store.share_usage(share_ref("model")).await.unwrap();
        assert_eq!(usage, self.state.allocated(), "{at}: share usage");
        self.check_extents(at).await;
    }

    /// One extent file on disk, or one extent row in memory, for each extent still referenced.
    async fn check_extents(&self, at: &str) {
        let mut held = self.state.tokens();
        for (_, state) in &self.snapshots {
            held.extend(state.tokens());
        }
        let stored = match &self.root {
            Some(root) => extent_files(root.path()).len(),
            None => self
                .store
                .run(|db, _| {
                    db.query_row("SELECT COUNT(*) FROM extents", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .map_err(super::db_error)
                })
                .await
                .unwrap() as usize,
        };
        assert_eq!(stored, held.len(), "{at}: stored extents");
    }
}

async fn walk(seeds: std::ops::RangeInclusive<u64>, disk: bool, steps: u32) {
    for seed in seeds {
        let mut run = Run::start(seed, disk).await;
        for step in 0..steps {
            run.step(step).await;
        }
        // Deleting the share with its snapshots frees every extent.
        run.store
            .delete_share(share_ref("model"), None, SnapshotPolicy::Include)
            .await
            .unwrap();
        run.state = State::default();
        run.snapshots.clear();
        run.check_extents("after deleting the share").await;
    }
}

#[tokio::test]
async fn random_file_operations_agree_with_the_inode_oracle_in_memory() {
    walk(1..=8, false, 50).await;
}

#[tokio::test]
async fn random_file_operations_agree_with_the_inode_oracle_on_disk_including_extents() {
    walk(1..=2, true, 40).await;
}

/// POSIX: renaming one name of a file onto another name of the same file changes nothing.
/// This once moved the first name onto the second and left the namespace holding the target
/// twice and the source not at all.
#[tokio::test]
async fn renaming_one_hard_link_onto_another_name_of_the_same_file_is_a_no_op() {
    for replace in [false, true] {
        let store = Store::open(None, 1 << 20, Clock::new()).unwrap();
        store
            .create_share(
                share_ref("model"),
                None,
                None,
                Metadata::new(),
                nfs_options(),
            )
            .await
            .unwrap();
        let mut state = State::default();
        state.create_file("n0", 4).unwrap();
        state.hard_link("n1", "n0").unwrap();
        let new = NewFile {
            length: 4,
            http: Default::default(),
            smb: SmbProperties::for_create(),
            metadata: Metadata::new(),
            posix: Default::default(),
        };
        store
            .create_file(share_ref("model"), path("n0"), new, None)
            .await
            .unwrap();
        store
            .create_hard_link(share_ref("model"), path("n1"), path("n0"))
            .await
            .unwrap();
        for (from, to) in [("n0", "n1"), ("n1", "n0")] {
            let flags = RenameFlags {
                replace,
                ignore_readonly: false,
                source_lease: None,
                dest_lease: None,
                content_type: None,
                metadata: None,
                smb: SmbProperties::for_create(),
            };
            store
                .rename(share_ref("model"), path(from), path(to), flags)
                .await
                .unwrap();
            let run = Run {
                store: store.clone(),
                root: None,
                state: state.clone(),
                snapshots: Vec::new(),
                rng: Rng::seeded(1),
                extent: 0,
                label: format!("{from} -> {to} replace={replace}"),
            };
            run.check(&run.label).await;
        }
        let listing = store
            .list_directory(share_ref("model"), path(""), String::new(), None, 100)
            .await
            .unwrap();
        let mut names: Vec<_> = listing
            .entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        names.sort();
        assert_eq!(names, ["n0", "n1"], "replace={replace}");
    }
}

/// Renaming a name that is a hard link (not the inode's first name) moves that name. It
/// once changed nothing, yet still deleted the file the rename was to replace.
#[tokio::test]
async fn renaming_a_hard_link_moves_that_name_and_replaces_its_target() {
    let store = Store::open(None, 1 << 20, Clock::new()).unwrap();
    store
        .create_share(
            share_ref("model"),
            None,
            None,
            Metadata::new(),
            nfs_options(),
        )
        .await
        .unwrap();
    let mut run = Run {
        store: store.clone(),
        root: None,
        state: State::default(),
        snapshots: Vec::new(),
        rng: Rng::seeded(1),
        extent: 0,
        label: String::new(),
    };
    for name in ["n0", "n2"] {
        let new = NewFile {
            length: 4,
            http: Default::default(),
            smb: SmbProperties::for_create(),
            metadata: Metadata::new(),
            posix: Default::default(),
        };
        store
            .create_file(share_ref("model"), path(name), new, None)
            .await
            .unwrap();
        run.state.create_file(name, 4).unwrap();
    }
    store
        .create_hard_link(share_ref("model"), path("n1"), path("n0"))
        .await
        .unwrap();
    run.state.hard_link("n1", "n0").unwrap();
    let rename = |from: &'static str, to: &'static str, replace| {
        let store = store.clone();
        async move {
            let flags = RenameFlags {
                replace,
                ignore_readonly: false,
                source_lease: None,
                dest_lease: None,
                content_type: None,
                metadata: None,
                smb: SmbProperties::for_create(),
            };
            store
                .rename(share_ref("model"), path(from), path(to), flags)
                .await
        }
    };
    // n1 is the link; n3 is free.
    rename("n1", "n3", false).await.unwrap();
    run.state.rename("n1", "n3", false).unwrap();
    run.check("move a link to a free name").await;
    // n3 (a link) replaces n2, a different file.
    rename("n3", "n2", true).await.unwrap();
    run.state.rename("n3", "n2", true).unwrap();
    run.check("a link replaces another file").await;
}
