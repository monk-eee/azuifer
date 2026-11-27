//! Create Path: new files and directories with implicit parents and inherited attributes.

//! DFS path operations on the shared Blob/DFS namespace (ADR-0003, ADR-0020): creating
//! and reading files and directories, their POSIX attributes and properties, and leases.
//!
//! Every function runs as one metadata transaction on the shared connection. Files are
//! ordinary block-blob rows; directories are `directories` rows. Owner, group, ACL and
//! sticky bit are columns on the container (the filesystem root), directory and blob
//! tables, so a rename carries them and a Blob-created path simply has the defaults.

use crate::store::{
    Content, Mode, blob, blob_params, blobs::guard_write, container, db_error, dfs_data, namespace,
    pages, remove_staged, save_blob, snapshots, write_lease,
};
use crate::{
    blob_lifecycle::Lifecycle,
    blob_tags::Tags,
    conditions::Guard,
    domain::{BlobKey, BlobWrite, ContentLength, Error},
    lease::LeaseAction,
    posix::{Attributes, Creation, PathKind},
};
use rusqlite::{Connection, params};
use uuid::Uuid;

use super::{CreatePath, Created, PathError, PathResult, empty_upload, located, save_attributes};

/// Creates the missing ancestors of `key` as directories with inherited attributes and
/// returns the attributes of its immediate parent.
pub(super) fn ensure_parents(
    db: &Connection,
    key: &BlobKey,
    owner: Option<&str>,
    now: i64,
) -> PathResult<Attributes> {
    let path = key.path.as_str();
    let root = located(db, &key.container, "")?.ok_or(Error::ContainerMissing)?;
    let mut parent = root.attributes;
    let creation = Creation {
        owner: owner.map(str::to_owned),
        ..Creation::default()
    };
    for (separator, _) in path.match_indices('/') {
        let name = &path[..separator];
        if namespace::file_exists(db, &key.container, name)? {
            return Err(Error::PathConflict.into());
        }
        match located(db, &key.container, name)? {
            Some(directory) => parent = directory.attributes,
            None => {
                let attributes = Attributes::inherit(&parent, PathKind::Directory, &creation)?;
                namespace::write_directory(db, &key.container, name, now)?;
                save_attributes(db, &key.container, name, PathKind::Directory, &attributes)?;
                parent = attributes;
            }
        }
    }
    Ok(parent)
}

pub(super) fn create_directory(
    tx: &Connection,
    request: CreatePath,
    now: i64,
) -> PathResult<Created> {
    let CreatePath {
        key,
        guard,
        properties,
        creation,
        lease,
        default_owner,
        ..
    } = request;
    container(tx, &key.container)?;
    let name = key.path.as_str();
    if blob(tx, &key, now)?.is_some() {
        return Err(Error::PathConflict.into());
    }
    if lease.is_some() {
        return Err(PathError::ResourceTypeMismatch);
    }
    let existing = located(tx, &key.container, name)?;
    if existing.is_some() && guard.lease.is_some() {
        return Err(Error::LeaseNotPresentBlob.into());
    }
    if existing.is_some() && guard.conditions.requires_absence() {
        return Err(Error::BlobAlreadyExists.into());
    }
    guard
        .conditions
        .check(existing.as_ref().map(|found| found.entity), false)?;
    let parent = ensure_parents(tx, &key, default_owner.as_deref(), now)?;
    let attributes = match existing {
        Some(found) => explicit(found.attributes, &creation, PathKind::Directory),
        None => Attributes::inherit(
            &parent,
            PathKind::Directory,
            &new_path_rights(&creation, default_owner),
        )?,
    };
    let entity = namespace::write_directory(tx, &key.container, name, now)?;
    save_attributes(tx, &key.container, name, PathKind::Directory, &attributes)?;
    let metadata = serde_json::to_string(&properties)
        .map_err(|_| crate::store::internal("could not encode metadata"))?;
    tx.execute(
        "UPDATE directories SET metadata=?1 WHERE account=?2 AND container=?3 AND name=?4",
        params![
            metadata,
            key.container.account.as_str(),
            key.container.name.as_str(),
            name
        ],
    )
    .map_err(db_error)?;
    Ok(Created {
        entity,
        lease: None,
    })
}

/// The rights of a new path: what the request names, owned by the caller unless it says otherwise.
fn new_path_rights(creation: &Creation, default_owner: Option<String>) -> Creation {
    Creation {
        owner: creation.owner.clone().or(default_owner),
        ..creation.clone()
    }
}

/// Applies the attributes a request names to the ones a path already has.
fn explicit(mut attributes: Attributes, creation: &Creation, kind: PathKind) -> Attributes {
    if let Some(owner) = &creation.owner {
        attributes.owner.clone_from(owner);
    }
    if let Some(group) = &creation.group {
        attributes.group.clone_from(group);
    }
    if let Some(mode) = creation.permissions {
        attributes.set_mode(mode);
    }
    if let Some(acl) = &creation.acl {
        attributes.replace_acl(acl, kind);
    }
    attributes
}

pub(in crate::store) fn create_file(
    tx: &Connection,
    mode: &Mode,
    request: CreatePath,
    now: i64,
    pending: bool,
) -> PathResult<(Created, Vec<Uuid>)> {
    let CreatePath {
        key,
        guard,
        headers,
        properties,
        creation,
        lease,
        default_owner,
        expiry,
        ..
    } = request;
    // A new file has no creation time to measure from, so only `now` matters here.
    let deadline = expiry
        .map(|option| option.deadline(u64::try_from(now / 1000).unwrap_or(0), now))
        .transpose()?
        .flatten();
    container(tx, &key.container)?;
    let name = key.path.as_str();
    if namespace::directory(tx, &key.container, name)?.is_some() {
        return Err(Error::PathConflict.into());
    }
    let parent = ensure_parents(tx, &key, default_owner.as_deref(), now)?;
    let old = blob(tx, &key, now)?;
    guard_write(&guard, old.as_ref(), true, now)?;
    let mut discard = remove_staged(tx, &key)?;
    if let Some(old) = &old {
        discard.extend(pages::retire(tx, mode, &key, old.info.kind)?);
        discard.extend(dfs_data::drop_staged(tx, mode, &key)?);
        discard.push(old.info.entity.id);
    }
    let attributes = match located(tx, &key.container, name)? {
        Some(found) => explicit(found.attributes, &creation, PathKind::File),
        None => Attributes::inherit(
            &parent,
            PathKind::File,
            &new_path_rights(&creation, default_owner),
        )?,
    };
    let options = BlobWrite {
        headers,
        metadata: properties,
        guard: Guard::default(),
        tier: None,
        copy: None,
        md5: None,
        tags: Tags::new(),
    };
    let content = Content {
        length: ContentLength(0),
        data: empty_upload(mode)?.data,
        computed_md5: None,
    };
    let version = snapshots::begin_write(
        tx,
        mode,
        &key,
        old.as_ref(),
        snapshots::Change::Content,
        now,
    )?;
    crate::store::check_memory_quota(
        tx,
        mode,
        old.as_ref().map_or(0, |row| pages::block_length(&row.info)),
        0,
    )?;
    let entity = save_blob(tx, mode, &key, &options, content, now)?;
    let entity = snapshots::finish_write(tx, &key, entity, version, Some(&options.tags))?;
    save_attributes(tx, &key.container, name, PathKind::File, &attributes)?;
    if deadline.is_some() {
        let lifecycle = Lifecycle {
            expires: deadline,
            ..Lifecycle::default()
        };
        crate::store::expiry::write(tx, &key, &lifecycle)?;
    }
    if pending {
        tx.execute(
            "UPDATE blobs SET dfs_pending=id WHERE account=?1 AND container=?2 AND name=?3",
            blob_params(&key),
        )
        .map_err(db_error)?;
    }
    let mut lease_id = None;
    if let Some((duration, proposed)) = lease {
        let current = old.as_ref().map(|row| row.lease).unwrap_or_default();
        let outcome = current.apply(LeaseAction::Acquire { duration, proposed }, now)?;
        write_lease(tx, "blobs", &blob_params(&key), &outcome.lease)?;
        lease_id = outcome.id;
    }
    Ok((
        Created {
            entity,
            lease: lease_id,
        },
        discard,
    ))
}
