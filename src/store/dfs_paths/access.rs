//! The POSIX rights of the caller of a DFS operation (ADR-0020).

//! DFS path operations on the shared Blob/DFS namespace (ADR-0003, ADR-0020): creating
//! and reading files and directories, their POSIX attributes and properties, and leases.
//!
//! Every function runs as one metadata transaction on the shared connection. Files are
//! ordinary block-blob rows; directories are `directories` rows. Owner, group, ACL and
//! sticky bit are columns on the container (the filesystem root), directory and blob
//! tables, so a rename carries them and a Blob-created path simply has the defaults.

use crate::store::container;
use crate::{
    domain::{ContainerKey, Error},
    posix::{Attributes, PathKind, Perms, Subject},
};
use rusqlite::Connection;

use super::{PathError, PathResult, located};

/// Who is asking, for the POSIX access check.
#[derive(Clone, Debug)]
pub(crate) enum Caller {
    /// Shared Key, account and service SAS, and bearer tokens with a data role: no ACL check.
    Superuser,
    /// A principal whose rights come from the ACLs; `None` has no object id.
    Principal(Option<String>),
}

impl Caller {
    pub(crate) fn oid(&self) -> Option<&str> {
        match self {
            Self::Superuser => None,
            Self::Principal(oid) => oid.as_deref(),
        }
    }
}

/// The POSIX rights an operation needs: `leaf` on the path itself (when it exists) and
/// `parent` on its directory. Execute on every ancestor is always needed.
#[derive(Clone, Copy)]
pub(crate) struct Need {
    pub(crate) leaf: Perms,
    pub(crate) parent: Perms,
}

impl Need {
    pub(crate) const TRAVERSE: Self = Self {
        leaf: Perms::NONE,
        parent: Perms::NONE,
    };
    pub(crate) const READ: Self = Self {
        leaf: Perms::READ,
        parent: Perms::NONE,
    };
    pub(crate) const WRITE: Self = Self {
        leaf: Perms::WRITE,
        parent: Perms::NONE,
    };
    /// Create or delete a child: write and search the directory.
    pub(crate) const CHANGE_PARENT: Self = Self {
        leaf: Perms::NONE,
        parent: Perms::WRITE.union(Perms::EXECUTE),
    };
    /// Overwrite an existing file or add a new one.
    pub(crate) const REPLACE: Self = Self {
        leaf: Perms::WRITE,
        parent: Perms::WRITE.union(Perms::EXECUTE),
    };
    /// List a directory: read and search it.
    pub(crate) const LIST: Self = Self {
        leaf: Perms::READ.union(Perms::EXECUTE),
        parent: Perms::NONE,
    };
}

/// The names whose directories must be searched to reach `path`: the root (empty)
/// and every ancestor directory, outermost first.
pub(in crate::store) fn ancestors(path: &str) -> Vec<&str> {
    let mut names = vec![""];
    names.extend(path.match_indices('/').map(|(index, _)| &path[..index]));
    names
}

/// Checks the POSIX rights of a bearer caller (ADR-0020). Missing parents are
/// ignored here: the operation itself answers 404, or creates them, and the
/// rights of the deepest existing directory apply.
pub(in crate::store) fn check_access(
    db: &Connection,
    caller: &Caller,
    key: &ContainerKey,
    path: Option<&str>,
    need: Need,
) -> PathResult<()> {
    let Caller::Principal(oid) = caller else {
        return Ok(());
    };
    container(db, key)?;
    let subject = Subject {
        oid: oid.as_deref(),
        groups: &[],
    };
    let allow = |attributes: &Attributes, wanted: Perms| {
        if attributes.permits(&subject, wanted) {
            Ok(())
        } else {
            Err(PathError::Shared(Error::PermissionMismatch))
        }
    };
    let Some(path) = path else {
        let root = located(db, key, "")?.ok_or(Error::ContainerMissing)?;
        return allow(&root.attributes, need.leaf);
    };
    let mut deepest: Option<Attributes> = None;
    for name in ancestors(path) {
        match located(db, key, name)? {
            Some(directory) if directory.kind == PathKind::Directory => {
                allow(&directory.attributes, Perms::EXECUTE)?;
                deepest = Some(directory.attributes);
            }
            _ => break,
        }
    }
    if let Some(parent) = &deepest {
        allow(parent, need.parent)?;
    }
    if let Some(leaf) = located(db, key, path)?
        && need.leaf != Perms::NONE
    {
        allow(&leaf.attributes, need.leaf)?;
    }
    Ok(())
}
