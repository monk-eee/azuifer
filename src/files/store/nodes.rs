//! Directory and file operations.

use super::{
    Env, LINK_COLUMNS, NODE_COLUMNS, ShareRow, Store, content, db_error, insert_node, internal,
    new_etag, node_row, resolve, save_node, shares,
    shares::{ShareRef, intern_permission, permission_exists, valid_sddl},
};
use crate::files::{
    error::{Error, Result},
    lease::{self, Kind, Outcome, Use},
    model::{
        Attributes, FileKind, HttpProperties, Metadata, NfsProps, NodeInfo, PermissionSpec, Posix,
        Protocol, SmbProperties, TimeSpec,
    },
    name::{EntryPath, fold},
    time::TICKS_PER_MILLI,
};
use rusqlite::{Connection, OptionalExtension as _, params};

const GIB: u64 = 1 << 30;

mod copy;
mod links;
mod ranges;

pub(crate) use copy::{CopyBy, CopyRequest, CopySource, NfsCopy};
pub(crate) use ranges::{ReadOptions, ReadRange};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Want {
    Directory,
    /// A file of any kind, including an NFS symbolic link.
    File,
    /// A file whose bytes can be read or written: not a symbolic link.
    Regular,
    Any,
}

pub(crate) struct NewFile {
    pub(crate) length: u64,
    pub(crate) http: HttpProperties,
    pub(crate) smb: SmbProperties,
    pub(crate) metadata: Metadata,
    pub(crate) posix: Posix,
}

/// What Set File Properties changes.
pub(crate) struct FilePatch {
    pub(crate) length: Option<u64>,
    pub(crate) http: Option<HttpProperties>,
    pub(crate) smb: SmbProperties,
    pub(crate) posix: Posix,
}

pub(crate) struct Listing {
    pub(crate) directory_id: i64,
    pub(crate) entries: Vec<NodeInfo>,
    /// Folded name of the last returned entry when more remain.
    pub(crate) next: Option<String>,
}

pub(crate) struct RenameFlags {
    pub(crate) replace: bool,
    pub(crate) ignore_readonly: bool,
    pub(crate) source_lease: Option<String>,
    pub(crate) dest_lease: Option<String>,
    pub(crate) content_type: Option<String>,
    pub(crate) metadata: Option<Metadata>,
    pub(crate) smb: SmbProperties,
}

fn find(db: &Connection, share: &ShareRow, path: &EntryPath, want: Want) -> Result<NodeInfo> {
    let resolved = resolve(db, share.id, path)?;
    let Some(node) = resolved.node else {
        return Err(if resolved.parent.is_some() {
            Error::ResourceNotFound
        } else {
            Error::ParentNotFound
        });
    };
    match (want, node.directory) {
        (Want::Directory, false) | (Want::File | Want::Regular, true) => {
            Err(Error::ResourceTypeMismatch)
        }
        (Want::Regular, false) if is_symlink(&node) => {
            Err(Error::XNfs4FileTypeUnsupportedException)
        }
        _ => Ok(node),
    }
}

fn is_symlink(node: &NodeInfo) -> bool {
    node.nfs
        .as_ref()
        .is_some_and(|nfs| nfs.kind == FileKind::SymLink)
}

fn is_nfs(share: &ShareRow) -> bool {
    share.info.protocol == Protocol::Nfs
}

/// The POSIX properties a new node of an NFS share starts with; `None` on an SMB share.
fn new_nfs(
    share: &ShareRow,
    kind: FileKind,
    posix: Posix,
    link_text: Option<String>,
) -> Option<NfsProps> {
    is_nfs(share).then(|| NfsProps::create(kind, posix, link_text))
}

/// NFS shares have no SMB attributes or permissions: whatever a request carried for them
/// is dropped, so a client that sends them anyway is not refused (ADR-0029).
fn for_share(share: &ShareRow, mut smb: SmbProperties) -> SmbProperties {
    if is_nfs(share) {
        smb.attributes = None;
        smb.change = None;
        smb.permission = match smb.permission {
            PermissionSpec::Preserve => PermissionSpec::Preserve,
            _ => PermissionSpec::Inherit,
        };
    }
    smb
}

/// File leases do not exist on NFS shares: a lease header is ignored.
fn check_file_lease(node: &NodeInfo, now: i64, lease_id: Option<&str>, action: Use) -> Result<()> {
    if node.nfs.is_some() {
        return Ok(());
    }
    lease::check_use(Kind::File, node.lease.as_ref(), now, lease_id, action)
}

fn touch(node: &mut NodeInfo, now: i64) {
    node.etag = new_etag();
    node.modified = now;
}

fn resolve_permission(
    db: &Connection,
    target: &ShareRef,
    spec: &PermissionSpec,
    inherited: &str,
    current: &str,
) -> Result<String> {
    match spec {
        PermissionSpec::Inherit => Ok(inherited.to_owned()),
        PermissionSpec::Preserve => Ok(current.to_owned()),
        PermissionSpec::Key(key) => {
            if permission_exists(db, target, key)? {
                Ok(key.clone())
            } else {
                Err(Error::FileInvalidPermissionKey)
            }
        }
        PermissionSpec::Sddl(sddl) => {
            if !valid_sddl(sddl) {
                return Err(Error::FileInvalidPermission);
            }
            intern_permission(db, target, sddl)
        }
    }
}

/// Applies SMB attributes, timestamps, and permission, then stamps a new ETag.
fn apply_smb(
    db: &Connection,
    target: &ShareRef,
    node: &mut NodeInfo,
    smb: &SmbProperties,
    inherited: &str,
    now: i64,
) -> Result<()> {
    node.attributes = smb
        .attributes
        .unwrap_or(node.attributes)
        .normalized(node.directory);
    node.creation = smb.creation.resolve(now, node.creation);
    node.last_write = smb.last_write.resolve(now, node.last_write);
    node.change = smb
        .change
        .unwrap_or(TimeSpec::Now)
        .resolve(now, node.change);
    node.permission_key =
        resolve_permission(db, target, &smb.permission, inherited, &node.permission_key)?;
    touch(node, now);
    Ok(())
}

fn blank(parent: &NodeInfo, name: &str, directory: bool, now: i64) -> NodeInfo {
    NodeInfo {
        file_id: 0,
        parent_id: Some(parent.file_id),
        directory,
        name: name.to_owned(),
        etag: new_etag(),
        modified: now,
        attributes: Attributes::default(),
        creation: now * TICKS_PER_MILLI,
        last_write: now * TICKS_PER_MILLI,
        change: now * TICKS_PER_MILLI,
        permission_key: parent.permission_key.clone(),
        metadata: Metadata::new(),
        length: 0,
        http: HttpProperties::default(),
        lease: None,
        copy: None,
        nfs: None,
        links: 1,
        entry: None,
    }
}

fn file_http(mut http: HttpProperties) -> HttpProperties {
    if http.content_type.is_none() {
        http.content_type = Some("application/octet-stream".to_owned());
    }
    http
}

fn check_quota(db: &Connection, share: &ShareRow, added: u64, removed: u64) -> Result<()> {
    let used: i64 = db
        .query_row(
            "SELECT COALESCE(SUM(length), 0) FROM ranges WHERE share_id=?1",
            [share.id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let used = u64::try_from(used).map_err(|_| internal("negative usage"))?;
    if used.saturating_sub(removed) + added > share.info.quota.saturating_mul(GIB) {
        return Err(Error::ShareSizeLimitReached);
    }
    Ok(())
}

fn writable(db: &Connection, target: &ShareRef) -> Result<ShareRow> {
    shares::load_writable(db, target)
}

/// Removes one name. A hard link's name just goes. When the inode's first name goes while
/// links remain, the oldest link's name becomes the inode's, so the content and file id
/// stay; only the last name frees the content.
fn delete_node(
    db: &Connection,
    share_id: i64,
    node: &NodeInfo,
    reclaim: &mut content::Reclaim,
) -> Result<()> {
    if let Some(entry) = node.entry {
        db.execute(
            "DELETE FROM links WHERE share_id=?1 AND entry_id=?2",
            params![share_id, entry],
        )
        .map_err(db_error)?;
        return Ok(());
    }
    let oldest: Option<(i64, i64, String, String)> = db
        .query_row(
            "SELECT entry_id, parent_id, name, key FROM links
             WHERE share_id=?1 AND file_id=?2 ORDER BY entry_id LIMIT 1",
            params![share_id, node.file_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(db_error)?;
    if let Some((entry, parent, name, key)) = oldest {
        db.execute(
            "DELETE FROM links WHERE share_id=?1 AND entry_id=?2",
            params![share_id, entry],
        )
        .map_err(db_error)?;
        db.execute(
            "UPDATE nodes SET parent_id=?3, name=?4, key=?5 WHERE share_id=?1 AND file_id=?2",
            params![share_id, node.file_id, parent, name, key],
        )
        .map_err(db_error)?;
        return Ok(());
    }
    reclaim.add_stored(db, share_id, Some(node.file_id))?;
    db.execute(
        "DELETE FROM nodes WHERE share_id=?1 AND file_id=?2",
        params![share_id, node.file_id],
    )
    .map_err(db_error)?;
    Ok(())
}

fn check_not_read_only(node: &NodeInfo) -> Result<()> {
    if node.attributes.contains(Attributes::READ_ONLY) {
        return Err(Error::ReadOnlyAttribute);
    }
    Ok(())
}

/// Commits a transaction, then removes the extents that lost their last reference.
fn finish(tx: rusqlite::Transaction<'_>, env: &Env, reclaim: content::Reclaim) -> Result<()> {
    let free = reclaim.finish(&tx, &env.mode)?;
    content::check_memory_quota(&tx, &env.mode)?;
    tx.commit().map_err(db_error)?;
    content::discard(env, &free);
    Ok(())
}

impl Store {
    pub(crate) async fn create_directory(
        &self,
        target: ShareRef,
        path: EntryPath,
        smb: SmbProperties,
        metadata: Metadata,
        posix: Posix,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            let resolved = resolve(&tx, share.id, &path)?;
            let name = path.name().ok_or(Error::ResourceAlreadyExists)?;
            let parent = resolved.parent.ok_or(Error::ParentNotFound)?;
            if resolved.node.is_some() {
                return Err(Error::ResourceAlreadyExists);
            }
            let mut node = blank(&parent, name, true, now);
            node.metadata = metadata;
            node.nfs = new_nfs(&share, FileKind::Directory, posix, None);
            let smb = for_share(&share, smb);
            apply_smb(&tx, &target, &mut node, &smb, &parent.permission_key, now)?;
            insert_node(&tx, share.id, &mut node)?;
            tx.commit().map_err(db_error)?;
            Ok(node)
        })
        .await
    }

    /// Looks up a directory or file; `conditions` are evaluated as for a read.
    pub(crate) async fn node(
        &self,
        target: ShareRef,
        path: EntryPath,
        want: Want,
        lease_id: Option<String>,
        conditions: crate::files::model::Conditions,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let share = shares::load_share(db, &target)?;
            let node = find(db, &share, &path, want)?;
            if !node.directory {
                check_file_lease(
                    &node,
                    env.clock.now_millis(),
                    lease_id.as_deref(),
                    Use::Read,
                )?;
            }
            conditions.check(&node.etag, node.modified)?;
            Ok(node)
        })
        .await
    }

    pub(crate) async fn set_directory_properties(
        &self,
        target: ShareRef,
        path: EntryPath,
        smb: SmbProperties,
        posix: Posix,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let share = writable(db, &target)?;
            let mut node = find(db, &share, &path, Want::Directory)?;
            let inherited = node.permission_key.clone();
            let smb = for_share(&share, smb);
            apply_smb(db, &target, &mut node, &smb, &inherited, now)?;
            if let Some(nfs) = node.nfs.as_mut() {
                nfs.update(posix);
            }
            save_node(db, share.id, &node)?;
            Ok(node)
        })
        .await
    }

    pub(crate) async fn set_metadata(
        &self,
        target: ShareRef,
        path: EntryPath,
        want: Want,
        lease_id: Option<String>,
        metadata: Metadata,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let share = writable(db, &target)?;
            let mut node = find(db, &share, &path, want)?;
            if !node.directory {
                check_file_lease(&node, now, lease_id.as_deref(), Use::Write)?;
                if node.nfs.is_none() {
                    lease::after_write(Kind::File, &mut node.lease, now);
                }
            }
            node.metadata = metadata;
            node.change = now * TICKS_PER_MILLI;
            touch(&mut node, now);
            save_node(db, share.id, &node)?;
            Ok(node)
        })
        .await
    }

    pub(crate) async fn delete_directory(&self, target: ShareRef, path: EntryPath) -> Result<()> {
        self.run(move |db, _| {
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            if path.is_root() {
                return Err(Error::CannotDeleteFileOrDirectory);
            }
            let node = find(&tx, &share, &path, Want::Directory)?;
            let occupied: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM nodes WHERE share_id=?1 AND parent_id=?2)
                         OR EXISTS(SELECT 1 FROM links WHERE share_id=?1 AND parent_id=?2)",
                    params![share.id, node.file_id],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if occupied {
                return Err(Error::DirectoryNotEmpty);
            }
            tx.execute(
                "DELETE FROM nodes WHERE share_id=?1 AND file_id=?2",
                params![share.id, node.file_id],
            )
            .map_err(db_error)?;
            tx.commit().map_err(db_error)
        })
        .await
    }

    /// One page of a directory's children, sorted by folded name, files and directories mixed.
    pub(crate) async fn list_directory(
        &self,
        target: ShareRef,
        path: EntryPath,
        prefix: String,
        after: Option<String>,
        limit: u32,
    ) -> Result<Listing> {
        self.run(move |db, _| {
            let share = shares::load_share(db, &target)?;
            let directory = find(db, &share, &path, Want::Directory)?;
            let mut query = db
                .prepare(&format!(
                    "SELECT {NODE_COLUMNS}, key AS sort_key FROM nodes
                     WHERE share_id=?1 AND parent_id=?2 AND key>?3 AND instr(key, ?4)=1
                     UNION ALL
                     SELECT {LINK_COLUMNS}, a.key FROM links a JOIN nodes n
                       ON n.share_id = a.share_id AND n.file_id = a.file_id
                     WHERE a.share_id=?1 AND a.parent_id=?2 AND a.key>?3 AND instr(a.key, ?4)=1
                     ORDER BY sort_key LIMIT ?5"
                ))
                .map_err(db_error)?;
            let mut entries = query
                .query_map(
                    params![
                        share.id,
                        directory.file_id,
                        after.unwrap_or_default(),
                        fold(&prefix),
                        limit + 1
                    ],
                    node_row,
                )
                .map_err(db_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db_error)?;
            let mut next = None;
            if entries.len() > limit as usize {
                entries.truncate(limit as usize);
                next = entries.last().map(|last| fold(&last.name));
            }
            Ok(Listing {
                directory_id: directory.file_id,
                entries,
                next,
            })
        })
        .await
    }

    pub(crate) async fn rename(
        &self,
        target: ShareRef,
        source: EntryPath,
        dest: EntryPath,
        flags: RenameFlags,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            if source.is_root() || dest.is_root() {
                return Err(Error::InvalidResourceName);
            }
            let mut node = find(&tx, &share, &source, Want::Any)?;
            if !node.directory {
                lease::check_use(
                    Kind::File,
                    node.lease.as_ref(),
                    now,
                    flags.source_lease.as_deref(),
                    Use::Write,
                )?;
            }
            if node.directory
                && dest.starts_with(&source)
                && dest.components().len() > source.components().len()
            {
                return Err(Error::RenameCycle);
            }
            let resolved = resolve(&tx, share.id, &dest)?;
            let parent = resolved.parent.ok_or(Error::ParentNotFound)?;
            let mut reclaim = content::Reclaim::default();
            if let Some(existing) = resolved
                .node
                .filter(|existing| existing.file_id != node.file_id)
            {
                if existing.directory {
                    return Err(if node.directory {
                        Error::ResourceAlreadyExists
                    } else {
                        Error::RenameDirectoryOperationNotSupported
                    });
                }
                if node.directory || !flags.replace {
                    return Err(Error::ResourceAlreadyExists);
                }
                if existing.attributes.contains(Attributes::READ_ONLY) && !flags.ignore_readonly {
                    return Err(Error::ReadOnlyAttribute);
                }
                lease::check_use(
                    Kind::File,
                    existing.lease.as_ref(),
                    now,
                    flags.dest_lease.as_deref(),
                    Use::Delete,
                )?;
                delete_node(&tx, share.id, &existing, &mut reclaim)?;
            }
            node.parent_id = Some(parent.file_id);
            node.name = dest.name().ok_or(Error::InvalidResourceName)?.to_owned();
            if let Some(content_type) = flags.content_type {
                node.http.content_type = Some(content_type);
            }
            if let Some(metadata) = flags.metadata {
                node.metadata = metadata;
            }
            let inherited = node.permission_key.clone();
            apply_smb(&tx, &target, &mut node, &flags.smb, &inherited, now)?;
            if !node.directory {
                lease::after_write(Kind::File, &mut node.lease, now);
            }
            save_node(&tx, share.id, &node)?;
            finish(tx, env, reclaim)?;
            Ok(node)
        })
        .await
    }

    /// Creates a file, or replaces an existing file as Azure's Create File does.
    pub(crate) async fn create_file(
        &self,
        target: ShareRef,
        path: EntryPath,
        file: NewFile,
        lease_id: Option<String>,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let NewFile {
                length,
                http,
                smb,
                metadata,
                posix,
            } = file;
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            let resolved = resolve(&tx, share.id, &path)?;
            let name = path.name().ok_or(Error::ResourceTypeMismatch)?;
            let parent = resolved.parent.ok_or(Error::ParentNotFound)?;
            let mut reclaim = content::Reclaim::default();
            let mut node = match resolved.node {
                Some(existing) if existing.directory => return Err(Error::ResourceTypeMismatch),
                Some(existing) if is_symlink(&existing) => {
                    return Err(Error::XNfs4FileTypeUnsupportedException);
                }
                Some(existing) => {
                    check_file_lease(&existing, now, lease_id.as_deref(), Use::Write)?;
                    check_not_read_only(&existing)?;
                    reclaim.add_stored(&tx, share.id, Some(existing.file_id))?;
                    tx.execute(
                        "DELETE FROM ranges WHERE share_id=?1 AND file_id=?2",
                        params![share.id, existing.file_id],
                    )
                    .map_err(db_error)?;
                    let mut node = blank(&parent, &existing.name, false, now);
                    node.file_id = existing.file_id;
                    node.parent_id = existing.parent_id;
                    node.entry = existing.entry;
                    node.links = existing.links;
                    node.lease = existing.lease;
                    if existing.nfs.is_none() {
                        lease::after_write(Kind::File, &mut node.lease, now);
                    }
                    node
                }
                None => blank(&parent, name, false, now),
            };
            node.length = length;
            node.http = file_http(http);
            node.metadata = metadata;
            node.nfs = new_nfs(&share, FileKind::Regular, posix, None);
            let smb = for_share(&share, smb);
            apply_smb(&tx, &target, &mut node, &smb, &parent.permission_key, now)?;
            if node.file_id == 0 {
                insert_node(&tx, share.id, &mut node)?;
            } else {
                save_node(&tx, share.id, &node)?;
            }
            finish(tx, env, reclaim)?;
            Ok(node)
        })
        .await
    }

    /// Set File Properties: SMB properties, replacement HTTP properties, and a resize.
    pub(crate) async fn set_file_properties(
        &self,
        target: ShareRef,
        path: EntryPath,
        lease_id: Option<String>,
        patch: FilePatch,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let FilePatch {
                length,
                http,
                smb,
                posix,
            } = patch;
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            let mut node = find(&tx, &share, &path, Want::File)?;
            check_file_lease(&node, now, lease_id.as_deref(), Use::Write)?;
            if is_symlink(&node) && length.is_some_and(|length| length != node.length) {
                return Err(Error::XNfs4FileTypeUnsupportedException);
            }
            let mut reclaim = content::Reclaim::default();
            if let Some(length) = length.filter(|length| *length != node.length) {
                let old = content::load_map(&tx, share.id, node.file_id, node.length)?;
                let mut new = old.clone();
                new.resize(length);
                content::save_map(&tx, share.id, node.file_id, &old, &new)?;
                reclaim.add_map(&old);
                node.length = length;
                node.last_write = now * TICKS_PER_MILLI;
            }
            if let Some(http) = http {
                node.http = file_http(http);
            }
            let inherited = node.permission_key.clone();
            let smb = for_share(&share, smb);
            apply_smb(&tx, &target, &mut node, &smb, &inherited, now)?;
            if let Some(nfs) = node.nfs.as_mut() {
                nfs.update(posix);
            } else {
                lease::after_write(Kind::File, &mut node.lease, now);
            }
            save_node(&tx, share.id, &node)?;
            finish(tx, env, reclaim)?;
            Ok(node)
        })
        .await
    }

    /// Deletes a file or symbolic link name. On an NFS share the answer is the inode's link
    /// count after the delete.
    pub(crate) async fn delete_file(
        &self,
        target: ShareRef,
        path: EntryPath,
        lease_id: Option<String>,
    ) -> Result<Option<u32>> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            let node = find(&tx, &share, &path, Want::File)?;
            check_file_lease(&node, now, lease_id.as_deref(), Use::Delete)?;
            check_not_read_only(&node)?;
            let mut reclaim = content::Reclaim::default();
            delete_node(&tx, share.id, &node, &mut reclaim)?;
            finish(tx, env, reclaim)?;
            Ok(node.nfs.is_some().then(|| node.links - 1))
        })
        .await
    }

    pub(crate) async fn lease_file(
        &self,
        target: ShareRef,
        path: EntryPath,
        action: shares::LeaseRequest,
    ) -> Result<(NodeInfo, Outcome)> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let share = writable(db, &target)?;
            let mut node = find(db, &share, &path, Want::File)?;
            let (stored, outcome) = lease::apply(
                Kind::File,
                node.lease.as_ref(),
                now,
                action.as_action(),
                || uuid::Uuid::new_v4().hyphenated().to_string(),
            )?;
            node.lease = stored;
            save_node(db, share.id, &node)?;
            Ok((node, outcome))
        })
        .await
    }
}

fn stamp_write(node: &mut NodeInfo, last_write: TimeSpec, now: i64) {
    node.last_write = last_write.resolve(now, node.last_write);
    node.change = now * TICKS_PER_MILLI;
    lease::after_write(Kind::File, &mut node.lease, now);
    touch(node, now);
}
