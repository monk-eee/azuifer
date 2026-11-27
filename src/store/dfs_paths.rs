//! DFS path operations on the shared Blob/DFS namespace (ADR-0003, ADR-0020): creating
//! and reading files and directories, their POSIX attributes and properties, and leases.
//!
//! Every function runs as one metadata transaction on the shared connection. Files are
//! ordinary block-blob rows; directories are `directories` rows. Owner, group, ACL and
//! sticky bit are columns on the container (the filesystem root), directory and blob
//! tables, so a rename carries them and a Blob-created path simply has the defaults.

use super::{
    Content, ContentSource, Mode, PathRead, Store, Uploaded, UploadedData, blob, blob_params,
    blobs::{guard_write, read_row, touch},
    container, db_error, dfs_data, entity_row, io_error, namespace, pages, remove_staged,
    require_blob, save_blob, snapshots, staging_file, write_lease,
};
use crate::{
    blob_expiry::ExpiryOption,
    blob_lifecycle::Lifecycle,
    blob_tags::Tags,
    checksum::Hasher,
    conditions::Guard,
    domain::{
        BlobKey, BlobPath, BlobRead, BlobWrite, ContainerKey, ContentHeaders, ContentLength,
        Entity, Error, Metadata, Result,
    },
    lease::{LeaseAction, LeaseDuration, LeaseId},
    posix::{Attributes, Creation, Entry, Mode as Permissions, PathKind, Perms, Subject},
    store::LeaseResult,
};
use rusqlite::{Connection, OptionalExtension as _, Row, params};
use uuid::Uuid;

/// Version 5 (ADR-0015, ADR-0020): POSIX owner, group, ACL (`x-ms-acl` text, access
/// entries then `default:` entries; empty means the defaults for the path kind) and
/// sticky bit on the filesystem root, directories and files; user-defined properties
/// of directories; and the unflushed ranges of DFS appends. `dfs_staged` maps file
/// offsets to immutable extents like `blob_ranges` does for page blobs, and stays
/// invisible to Blob and DFS reads until a flush publishes it. `content` is the file's
/// content id at append time, so rows left by a replaced file are recognisably stale.
/// `dfs_staged_bytes` holds the extent bytes of an in-memory instance. `blobs.dfs_pending`
/// is the content id of a file that an Append Data created implicitly and no flush has
/// published yet: until then the file does not count as existing for `If-None-Match: *`
/// on the flush, which is how the Data Lake SDKs upload without overwriting.
pub(super) const SCHEMA: &str = "
ALTER TABLE containers ADD COLUMN posix_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE containers ADD COLUMN posix_group TEXT NOT NULL DEFAULT '';
ALTER TABLE containers ADD COLUMN posix_acl TEXT NOT NULL DEFAULT '';
ALTER TABLE containers ADD COLUMN posix_sticky INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blobs ADD COLUMN posix_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE blobs ADD COLUMN posix_group TEXT NOT NULL DEFAULT '';
ALTER TABLE blobs ADD COLUMN posix_acl TEXT NOT NULL DEFAULT '';
ALTER TABLE blobs ADD COLUMN posix_sticky INTEGER NOT NULL DEFAULT 0;
ALTER TABLE directories ADD COLUMN posix_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE directories ADD COLUMN posix_group TEXT NOT NULL DEFAULT '';
ALTER TABLE directories ADD COLUMN posix_acl TEXT NOT NULL DEFAULT '';
ALTER TABLE directories ADD COLUMN posix_sticky INTEGER NOT NULL DEFAULT 0;
ALTER TABLE directories ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}';
DROP VIEW namespace_entries;
CREATE VIEW namespace_entries AS
    SELECT account, container, name, id, modified, COALESCE(etag,id) AS etag, length, 0 AS directory,
           posix_owner, posix_group, posix_acl, posix_sticky
    FROM blobs
    UNION ALL
    SELECT account, container, name, id, modified, etag, 0, 1,
           posix_owner, posix_group, posix_acl, posix_sticky
    FROM directories;
CREATE TABLE IF NOT EXISTS dfs_staged (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    offset INTEGER NOT NULL, length INTEGER NOT NULL,
    extent BLOB NOT NULL, extent_offset INTEGER NOT NULL, content BLOB NOT NULL,
    PRIMARY KEY (account, container, name, offset),
    FOREIGN KEY (account, container, name) REFERENCES blobs (account, container, name)
        ON DELETE CASCADE ON UPDATE CASCADE
) STRICT;
CREATE INDEX IF NOT EXISTS dfs_staged_extent ON dfs_staged (extent);
CREATE TABLE IF NOT EXISTS dfs_staged_bytes (
    extent BLOB NOT NULL PRIMARY KEY, bytes BLOB NOT NULL
) STRICT;
ALTER TABLE blobs ADD COLUMN dfs_pending BLOB;";

/// A DFS failure: a shared domain error, or one of the DFS-only conflicts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PathError {
    Shared(Error),
    /// The flush position is not the end of the contiguous uploaded data.
    InvalidFlushPosition,
    /// The path exists but is not the kind of resource the operation needs.
    ResourceTypeMismatch,
    SourceNotFound,
    DestinationParentNotFound,
    /// A directory cannot move onto itself or into its own subtree.
    InvalidRenameSource,
    /// Rename needs a file for a file and a directory for a directory.
    RenameTypeMismatch,
}

impl From<Error> for PathError {
    fn from(error: Error) -> Self {
        Self::Shared(error)
    }
}

pub(crate) type PathResult<T> = std::result::Result<T, PathError>;

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

const ATTRIBUTE_COLUMNS: &str = "posix_owner, posix_group, posix_acl, posix_sticky";

/// Reads the four attribute columns starting at `first`.
pub(super) fn attributes_row(
    row: &Row<'_>,
    first: usize,
    kind: PathKind,
) -> rusqlite::Result<Attributes> {
    let owner: String = row.get(first)?;
    let group: String = row.get(first + 1)?;
    let acl: String = row.get(first + 2)?;
    let sticky: i64 = row.get(first + 3)?;
    Attributes::stored(kind, &owner, &group, &acl, sticky != 0).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            first + 2,
            rusqlite::types::Type::Text,
            "stored ACL is not valid".into(),
        )
    })
}

/// A path found in the namespace: the filesystem root (`name` empty), a directory or a file.
pub(super) struct Located {
    pub(super) kind: PathKind,
    pub(super) entity: Entity,
    pub(super) attributes: Attributes,
}

pub(super) fn located(db: &Connection, key: &ContainerKey, name: &str) -> Result<Option<Located>> {
    let [account, container] = [key.account.as_str(), key.name.as_str()];
    let found = |kind: PathKind, sql: String, values: &[&str]| {
        db.query_row(&sql, rusqlite::params_from_iter(values), |row| {
            Ok(Located {
                kind,
                entity: entity_row(row)?,
                attributes: attributes_row(row, 3, kind)?,
            })
        })
        .optional()
        .map_err(db_error)
    };
    if name.is_empty() {
        return found(
            PathKind::Directory,
            format!(
                "SELECT id, modified, COALESCE(etag, id), {ATTRIBUTE_COLUMNS} FROM containers
                 WHERE account=?1 AND name=?2"
            ),
            &[account, container],
        );
    }
    let directory = found(
        PathKind::Directory,
        format!(
            "SELECT id, modified, etag, {ATTRIBUTE_COLUMNS} FROM directories
             WHERE account=?1 AND container=?2 AND name=?3"
        ),
        &[account, container, name],
    )?;
    if directory.is_some() {
        return Ok(directory);
    }
    found(
        PathKind::File,
        format!(
            "SELECT id, modified, COALESCE(etag, id), {ATTRIBUTE_COLUMNS} FROM blobs
             WHERE account=?1 AND container=?2 AND name=?3"
        ),
        &[account, container, name],
    )
}

pub(super) fn save_attributes(
    db: &Connection,
    key: &ContainerKey,
    name: &str,
    kind: PathKind,
    attributes: &Attributes,
) -> Result<()> {
    let acl = attributes.acl_text();
    let sticky = i64::from(attributes.mode().sticky);
    let values = params![
        attributes.owner,
        attributes.group,
        acl,
        sticky,
        key.account.as_str(),
        key.name.as_str(),
        name
    ];
    let sql = if name.is_empty() {
        "UPDATE containers SET posix_owner=?1, posix_group=?2, posix_acl=?3, posix_sticky=?4
         WHERE account=?5 AND name=?6 AND ?7=''"
    } else if kind == PathKind::Directory {
        "UPDATE directories SET posix_owner=?1, posix_group=?2, posix_acl=?3, posix_sticky=?4
         WHERE account=?5 AND container=?6 AND name=?7"
    } else {
        "UPDATE blobs SET posix_owner=?1, posix_group=?2, posix_acl=?3, posix_sticky=?4
         WHERE account=?5 AND container=?6 AND name=?7"
    };
    db.execute(sql, values).map_err(db_error)?;
    Ok(())
}

/// The names whose directories must be searched to reach `path`: the root (empty)
/// and every ancestor directory, outermost first.
pub(super) fn ancestors(path: &str) -> Vec<&str> {
    let mut names = vec![""];
    names.extend(path.match_indices('/').map(|(index, _)| &path[..index]));
    names
}

/// Checks the POSIX rights of a bearer caller (ADR-0020). Missing parents are
/// ignored here: the operation itself answers 404, or creates them, and the
/// rights of the deepest existing directory apply.
pub(super) fn check_access(
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

/// Creates the missing ancestors of `key` as directories with inherited attributes and
/// returns the attributes of its immediate parent.
fn ensure_parents(
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

fn touch_directory(db: &Connection, key: &ContainerKey, name: &str, now: i64) -> Result<Entity> {
    let entity = super::new_entity(now)?;
    db.execute(
        "UPDATE directories SET etag=?1, modified=?2 WHERE account=?3 AND container=?4 AND name=?5",
        params![
            entity.id,
            super::sqlite_int(entity.modified)?,
            key.account.as_str(),
            key.name.as_str(),
            name
        ],
    )
    .map_err(db_error)?;
    Ok(entity)
}

fn touch_container(db: &Connection, key: &ContainerKey, now: i64) -> Result<Entity> {
    let entity = super::new_entity(now)?;
    db.execute(
        "UPDATE containers SET etag=?1, modified=?2 WHERE account=?3 AND name=?4",
        params![
            entity.id,
            super::sqlite_int(entity.modified)?,
            key.account.as_str(),
            key.name.as_str()
        ],
    )
    .map_err(db_error)?;
    Ok(entity)
}

/// Bumps the ETag and modified time of whatever `located` found.
pub(super) fn touch_path(
    db: &Connection,
    key: &ContainerKey,
    name: &str,
    kind: PathKind,
    now: i64,
) -> Result<Entity> {
    match (name.is_empty(), kind) {
        (true, _) => touch_container(db, key, now),
        (false, PathKind::Directory) => touch_directory(db, key, name, now),
        (false, PathKind::File) => touch(
            db,
            &BlobKey {
                container: key.clone(),
                path: BlobPath::parse(name.to_owned())?,
            },
            now,
        ),
    }
}

fn empty_upload(mode: &Mode) -> Result<Uploaded> {
    let data = match mode {
        Mode::Disk { extents, .. } => UploadedData::Disk(staging_file(extents).map_err(io_error)?),
        Mode::Memory { .. } => UploadedData::Memory(Vec::new()),
    };
    Ok(Uploaded {
        length: ContentLength(0),
        checksums: Hasher::new().finish(None)?,
        data,
    })
}

/// A Create Path request.
pub(crate) struct CreatePath {
    pub(crate) key: BlobKey,
    pub(crate) kind: PathKind,
    pub(crate) guard: Guard,
    pub(crate) headers: ContentHeaders,
    pub(crate) properties: Metadata,
    pub(crate) creation: Creation,
    /// The owner of new paths and implicit parents when the request names none: the
    /// bearer caller's object id.
    pub(crate) default_owner: Option<String>,
    /// Acquire a lease on the new file, as `x-ms-proposed-lease-id` asks.
    pub(crate) lease: Option<(LeaseDuration, Option<LeaseId>)>,
    /// The deadline of a new file, as `x-ms-expiry-option` asks (ADR-0030).
    pub(crate) expiry: Option<ExpiryOption>,
}

pub(crate) struct Created {
    pub(crate) entity: Entity,
    pub(crate) lease: Option<LeaseId>,
}

/// What Read Path and Get Path Properties return.
pub(crate) struct PathView {
    pub(crate) read: PathRead,
    pub(crate) attributes: Attributes,
    /// User-defined properties of a directory; a file's are in its download.
    pub(crate) directory_properties: Metadata,
}

/// Changes of Update Path with `action=setProperties`; `None` keeps the stored value.
#[derive(Default)]
pub(crate) struct PropertyUpdate {
    pub(crate) content_type: Option<String>,
    pub(crate) encoding: Option<String>,
    pub(crate) language: Option<String>,
    pub(crate) disposition: Option<String>,
    pub(crate) cache_control: Option<String>,
    pub(crate) properties: Option<Metadata>,
}

/// Changes of Update Path with `action=setAccessControl`.
#[derive(Default)]
pub(crate) struct AccessUpdate {
    pub(crate) owner: Option<String>,
    pub(crate) group: Option<String>,
    pub(crate) permissions: Option<Permissions>,
    pub(crate) acl: Option<Vec<Entry>>,
}

impl Store {
    pub(super) async fn run_path<T, F>(&self, action: F) -> PathResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection, &Mode, i64) -> PathResult<T> + Send + 'static,
    {
        self.run(move |db, mode, now| Ok(action(db, mode, now)))
            .await?
    }

    /// Checks a bearer caller's POSIX rights before an operation; callers that
    /// bypass ACLs return immediately.
    pub(crate) async fn authorize_path(
        &self,
        caller: Caller,
        key: ContainerKey,
        path: Option<BlobPath>,
        need: Need,
    ) -> PathResult<()> {
        if matches!(caller, Caller::Superuser) {
            return Ok(());
        }
        self.run_path(move |db, _, _| {
            check_access(db, &caller, &key, path.as_ref().map(BlobPath::as_str), need)
        })
        .await
    }

    /// Create Path for a file or directory, creating missing parents in the same
    /// transaction. Overwrites a file unless a condition forbids it.
    pub(crate) async fn create_path(&self, request: CreatePath) -> PathResult<Created> {
        self.run_path(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            let created = match request.kind {
                PathKind::Directory => create_directory(&tx, request, now)?,
                PathKind::File => {
                    let (created, discard) = create_file(&tx, mode, request, now, false)?;
                    tx.commit().map_err(db_error)?;
                    for id in discard {
                        super::reclaim(mode, id);
                    }
                    return Ok(created);
                }
            };
            tx.commit().map_err(db_error)?;
            Ok(created)
        })
        .await
    }

    /// Read Path and Get Path Properties: the file or directory with its attributes.
    pub(crate) async fn read_path_view(
        &self,
        key: BlobKey,
        options: BlobRead,
    ) -> PathResult<PathView> {
        self.run_path(move |db, mode, now| {
            let name = key.path.as_str();
            let found = located(db, &key.container, name)?;
            if let Some(directory) = found.as_ref().filter(|l| l.kind == PathKind::Directory) {
                if options.guard.lease.is_some() {
                    return Err(Error::LeaseNotPresentBlob.into());
                }
                options
                    .guard
                    .conditions
                    .check(Some(directory.entity), true)?;
                if options.range.is_some() {
                    return Err(Error::InvalidRange(0).into());
                }
                let metadata = namespace::directory_metadata(db, &key.container, name)?;
                return Ok(PathView {
                    read: PathRead::Directory(directory.entity, metadata.clone()),
                    attributes: directory.attributes.clone(),
                    directory_properties: metadata,
                });
            }
            let row = require_blob(db, &key, now)?;
            let download = read_row(db, mode, now, row, &key, &options, ContentSource::Blob)?;
            let attributes = found.map_or_else(
                || Attributes::initial(PathKind::File),
                |located| located.attributes,
            );
            Ok(PathView {
                read: PathRead::File(Box::new(download)),
                attributes,
                directory_properties: Metadata::new(),
            })
        })
        .await
    }

    /// Update Path `setProperties`: user-defined properties and content headers.
    pub(crate) async fn set_path_properties(
        &self,
        key: BlobKey,
        guard: Guard,
        update: PropertyUpdate,
    ) -> PathResult<Entity> {
        self.run_path(move |db, mode, now| {
            let tx = db.transaction().map_err(db_error)?;
            container(&tx, &key.container)?;
            let name = key.path.as_str();
            let [account, container_name] = [
                key.container.account.as_str(),
                key.container.name.as_str(),
            ];
            let metadata = update
                .properties
                .as_ref()
                .map(|metadata| {
                    serde_json::to_string(metadata)
                        .map_err(|_| super::internal("could not encode metadata"))
                })
                .transpose()?;
            let entity = if let Some(directory) =
                namespace::directory(&tx, &key.container, name)?
            {
                if guard.lease.is_some() {
                    return Err(Error::LeaseNotPresentBlob.into());
                }
                guard.conditions.check(Some(directory), false)?;
                let entity = touch_directory(&tx, &key.container, name, now)?;
                if let Some(metadata) = metadata {
                    tx.execute(
                        "UPDATE directories SET metadata=?1 WHERE account=?2 AND container=?3 AND name=?4",
                        params![metadata, account, container_name, name],
                    )
                    .map_err(db_error)?;
                }
                entity
            } else {
                let old = require_blob(&tx, &key, now)?;
                guard_write(&guard, Some(&old), false, now)?;
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
                let headers = &old.info.headers;
                let pick = |new: &Option<String>, current: &str| {
                    new.as_deref().unwrap_or(current).to_owned()
                };
                tx.execute(
                    "UPDATE blobs SET content_type=?1, content_encoding=?2, content_language=?3,
                        content_disposition=?4, cache_control=?5,
                        metadata=COALESCE(?6, metadata)
                     WHERE account=?7 AND container=?8 AND name=?9",
                    params![
                        pick(&update.content_type, &headers.content_type),
                        pick(&update.encoding, &headers.encoding),
                        pick(&update.language, &headers.language),
                        pick(&update.disposition, &headers.disposition),
                        pick(&update.cache_control, &headers.cache_control),
                        metadata,
                        account,
                        container_name,
                        name
                    ],
                )
                .map_err(db_error)?;
                entity
            };
            tx.commit().map_err(db_error)?;
            Ok(entity)
        })
        .await
    }

    /// Update Path `setAccessControl` (and the filesystem root's equivalent): owner,
    /// group, permissions or ACL. A bearer caller must own the path.
    pub(crate) async fn set_access(
        &self,
        key: ContainerKey,
        path: Option<BlobPath>,
        update: AccessUpdate,
        guard: Guard,
        caller: Caller,
    ) -> PathResult<Entity> {
        self.run_path(move |db, _, now| {
            let tx = db.transaction().map_err(db_error)?;
            container(&tx, &key)?;
            let name = path.as_ref().map_or("", BlobPath::as_str);
            let found = located(&tx, &key, name)?.ok_or(Error::BlobMissing)?;
            guard.conditions.check(Some(found.entity), false)?;
            if let Caller::Principal(oid) = &caller
                && (!found.attributes.owned_by(oid.as_deref())
                    || update.owner.is_some()
                    || update.group.is_some()
                        && update.group.as_deref() != Some(&found.attributes.group))
            {
                return Err(Error::PermissionMismatch.into());
            }
            let mut attributes = found.attributes;
            if let Some(owner) = update.owner {
                attributes.owner = owner;
            }
            if let Some(group) = update.group {
                attributes.group = group;
            }
            if let Some(mode) = update.permissions {
                attributes.set_mode(mode);
            }
            if let Some(acl) = &update.acl {
                attributes.replace_acl(acl, found.kind);
            }
            save_attributes(&tx, &key, name, found.kind, &attributes)?;
            let entity = touch_path(&tx, &key, name, found.kind, now)?;
            tx.commit().map_err(db_error)?;
            Ok(entity)
        })
        .await
    }

    /// The root directory's ETag and attributes, for ACL reads of the filesystem root.
    pub(crate) async fn access_of(&self, key: ContainerKey) -> PathResult<(Entity, Attributes)> {
        self.run_path(move |db, _, _| {
            container(db, &key)?;
            let root = located(db, &key, "")?.ok_or(Error::ContainerMissing)?;
            Ok((root.entity, root.attributes))
        })
        .await
    }

    /// Lease Path. Only files hold leases; a directory is a resource type mismatch.
    pub(crate) async fn lease_path(
        &self,
        key: BlobKey,
        action: LeaseAction,
        conditions: crate::conditions::Conditions,
    ) -> PathResult<LeaseResult> {
        let directory = {
            let key = key.clone();
            self.run_path(move |db, _, _| {
                Ok(namespace::directory(db, &key.container, key.path.as_str())?.is_some())
            })
            .await?
        };
        if directory {
            return Err(PathError::ResourceTypeMismatch);
        }
        Ok(self.lease_blob(key, action, conditions).await?)
    }
}

fn create_directory(tx: &Connection, request: CreatePath, now: i64) -> PathResult<Created> {
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
        .map_err(|_| super::internal("could not encode metadata"))?;
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

pub(super) fn create_file(
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
    super::check_memory_quota(
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
        super::expiry::write(tx, &key, &lifecycle)?;
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
