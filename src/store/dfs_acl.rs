//! Recursive ACL changes in bounded batches with a stable continuation (ADR-0020).
//!
//! Each request edits up to `max_records` entries below a directory in name order,
//! starting with the directory itself, and returns the name of the last entry it
//! handled. Names order the tree the same way on every call, so repeating the request
//! with that name continues where it stopped even if entries were added or removed.
//!
//! A bearer caller changes an entry it owns and can reach: it needs execute on the
//! directory the request names and on every directory between that one and the entry
//! (ADR-0031). An entry it cannot reach is a failure like one it does not own.

use super::{
    Store, container, db_error,
    dfs_paths::{Caller, PathResult, ancestors, located, save_attributes},
    dfs_tree::tree_after,
};
use crate::{
    domain::{BlobPath, ContainerKey, Error},
    posix::{Entry, PathKind, Perms, Subject},
};
use rusqlite::Connection;
use std::collections::HashMap;

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

/// Whether the caller may search each directory of the subtree, judged from the ACLs a
/// call finds before it changes them, so a change cannot lock out its own descendants.
struct Reach<'a> {
    caller: &'a Caller,
    top: &'a str,
    searchable: HashMap<String, bool>,
}

impl Reach<'_> {
    fn subject(&self) -> Subject<'_> {
        Subject {
            oid: self.caller.oid(),
            groups: &[],
        }
    }

    /// Records the search right of a directory about to be changed.
    fn note(&mut self, name: &str, attributes: &crate::posix::Attributes) {
        let allowed = attributes.permits(&self.subject(), Perms::EXECUTE);
        self.searchable.insert(name.to_owned(), allowed);
    }

    /// Whether every directory from the requested one down to the entry's parent can be
    /// searched.
    fn reaches(&mut self, db: &Connection, key: &ContainerKey, name: &str) -> PathResult<bool> {
        if matches!(self.caller, Caller::Superuser) || name == self.top {
            return Ok(true);
        }
        let inside = |directory: &&str| {
            self.top.is_empty()
                || *directory == self.top
                || directory.starts_with(&format!("{}/", self.top))
        };
        let directories: Vec<String> = ancestors(name)
            .into_iter()
            .filter(inside)
            .map(str::to_owned)
            .collect();
        for directory in directories {
            let allowed = match self.searchable.get(&directory) {
                Some(allowed) => *allowed,
                None => {
                    let Some(found) = located(db, key, &directory)? else {
                        return Ok(false);
                    };
                    let allowed = found.attributes.permits(&self.subject(), Perms::EXECUTE);
                    self.searchable.insert(directory, allowed);
                    allowed
                }
            };
            if !allowed {
                return Ok(false);
            }
        }
        Ok(true)
    }
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
            let mut reach = Reach {
                caller: &caller,
                top: root,
                searchable: HashMap::new(),
            };
            for (name, kind) in queue.into_iter().take(max_records) {
                let Some(found) = located(&tx, &key, &name)? else {
                    continue;
                };
                let owned = match &caller {
                    Caller::Superuser => true,
                    Caller::Principal(oid) => found.attributes.owned_by(oid.as_deref()),
                };
                let allowed = owned && reach.reaches(&tx, &key, &name)?;
                if kind == PathKind::Directory {
                    reach.note(&name, &found.attributes);
                }
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
