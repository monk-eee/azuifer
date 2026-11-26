//! Recursive ACL changes in bounded batches with a stable continuation (ADR-0020).
//!
//! Each request edits up to `max_records` entries below a directory in name order,
//! starting with the directory itself, and returns the name of the last entry it
//! handled. Names order the tree the same way on every call, so repeating the request
//! with that name continues where it stopped even if entries were added or removed.

use super::{
    Store, container, db_error,
    dfs_paths::{Caller, PathResult, located, save_attributes},
    dfs_tree::tree_after,
};
use crate::{
    domain::{BlobPath, ContainerKey, Error},
    posix::{Entry, PathKind},
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AclMode {
    /// Replace the ACL of every path.
    Set,
    /// Add or replace the given entries and keep the others.
    Modify,
    /// Drop the named entries.
    Remove,
}

pub(crate) struct RecursiveAcl {
    pub(crate) key: ContainerKey,
    pub(crate) path: Option<BlobPath>,
    pub(crate) mode: AclMode,
    pub(crate) entries: Vec<Entry>,
    /// The last path a previous call handled.
    pub(crate) after: Option<String>,
    pub(crate) max_records: usize,
    /// Keep going after a path the caller may not change.
    pub(crate) force: bool,
    pub(crate) caller: Caller,
}

pub(crate) struct AclFailure {
    pub(crate) name: String,
    pub(crate) kind: PathKind,
}

#[derive(Default)]
pub(crate) struct RecursiveOutcome {
    pub(crate) directories: u64,
    pub(crate) files: u64,
    pub(crate) failures: Vec<AclFailure>,
    /// Set when entries remain: the last path handled by this call.
    pub(crate) next: Option<String>,
}

impl Store {
    pub(crate) async fn change_access_recursive(
        &self,
        request: RecursiveAcl,
    ) -> PathResult<RecursiveOutcome> {
        self.run_path(move |db, _, _| {
            let RecursiveAcl {
                key,
                path,
                mode,
                entries,
                after,
                max_records,
                force,
                caller,
            } = request;
            let tx = db.transaction().map_err(db_error)?;
            container(&tx, &key)?;
            let root = path.as_ref().map_or("", BlobPath::as_str);
            let top = located(&tx, &key, root)?.ok_or(Error::BlobMissing)?;
            let mut outcome = RecursiveOutcome::default();
            let mut queue: Vec<(String, PathKind)> = Vec::new();
            let resuming = after.is_some();
            if !resuming {
                queue.push((root.to_owned(), top.kind));
            }
            if top.kind == PathKind::Directory {
                let want = max_records + 1 - queue.len().min(max_records);
                let start = after.as_deref().unwrap_or(root);
                for entry in tree_after(&tx, &key, root, start, want)? {
                    queue.push((entry.name, entry.kind));
                }
            }
            let more = queue.len() > max_records;
            let mut last: Option<String> = None;
            for (name, kind) in queue.into_iter().take(max_records) {
                let Some(found) = located(&tx, &key, &name)? else {
                    continue;
                };
                let allowed = match &caller {
                    Caller::Superuser => true,
                    Caller::Principal(oid) => found.attributes.owned_by(oid.as_deref()),
                };
                if allowed {
                    let mut attributes = found.attributes;
                    match mode {
                        AclMode::Set => attributes.replace_acl(&entries, kind),
                        AclMode::Modify => attributes.modify_acl(&entries, kind),
                        AclMode::Remove => attributes.remove_acl(&entries),
                    }
                    save_attributes(&tx, &key, &name, kind, &attributes)?;
                    match kind {
                        PathKind::Directory => outcome.directories += 1,
                        PathKind::File => outcome.files += 1,
                    }
                    last = Some(name);
                } else {
                    outcome.failures.push(AclFailure {
                        name: name.clone(),
                        kind,
                    });
                    if !force {
                        outcome.next = last.or(after);
                        tx.commit().map_err(db_error)?;
                        return Ok(outcome);
                    }
                    last = Some(name);
                }
            }
            outcome.next = if more { last } else { None };
            tx.commit().map_err(db_error)?;
            Ok(outcome)
        })
        .await
    }
}
