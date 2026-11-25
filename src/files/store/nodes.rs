//! Directory and file operations.

use super::{
    Env, NODE_COLUMNS, ShareRow, Store, content, db_error, insert_node, internal, new_etag,
    node_row, resolve, save_node, shares,
    shares::{ShareRef, intern_permission, load_share, permission_exists, valid_sddl},
};
use crate::{
    files::{
        error::{Error, Result},
        lease::{self, Kind, Outcome, Use},
        model::{
            Attributes, CopyState, HttpProperties, Metadata, NodeInfo, PermissionSpec,
            SmbProperties, TimeSpec,
        },
        name::{EntryPath, fold},
    },
    ranges::RangeMap,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use md5::{Digest as _, Md5};
use rusqlite::{Connection, params};
use std::ops::Range;

const MAX_MD5_RANGE: u64 = 4 * 1024 * 1024;
const GIB: u64 = 1 << 30;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Want {
    Directory,
    File,
    Any,
}

/// A `bytes=start-end` read range; `end` is inclusive and optional.
#[derive(Clone, Copy)]
pub(crate) struct ReadRange {
    pub(crate) start: u64,
    pub(crate) end: Option<u64>,
}

pub(crate) struct NewFile {
    pub(crate) length: u64,
    pub(crate) http: HttpProperties,
    pub(crate) smb: SmbProperties,
    pub(crate) metadata: Metadata,
}

pub(crate) struct ReadOptions {
    pub(crate) lease_id: Option<String>,
    pub(crate) conditions: crate::files::model::Conditions,
    pub(crate) range: Option<ReadRange>,
    /// Return the MD5 of the returned range (`x-ms-range-get-content-md5`).
    pub(crate) want_md5: bool,
    /// False for Get File Properties, which reads no bytes.
    pub(crate) with_body: bool,
}

pub(crate) struct FileRead {
    pub(crate) info: NodeInfo,
    /// The returned byte range when the read was ranged.
    pub(crate) range: Option<Range<u64>>,
    pub(crate) body: content::FileBody,
    pub(crate) md5: Option<String>,
}

pub(crate) struct RangeListing {
    pub(crate) info: NodeInfo,
    pub(crate) ranges: Vec<Range<u64>>,
    pub(crate) cleared: Vec<Range<u64>>,
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

/// A same-instance copy source.
pub(crate) struct CopySource {
    pub(crate) target: ShareRef,
    pub(crate) path: EntryPath,
    /// The URL as the client sent it, minus any query string, for the copy properties.
    pub(crate) url: String,
}

pub(crate) struct CopyRequest {
    pub(crate) dest_lease: Option<String>,
    pub(crate) ignore_readonly: bool,
    pub(crate) metadata: Option<Metadata>,
    /// Present for `x-ms-file-copy-mode: override`.
    pub(crate) smb: Option<SmbProperties>,
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
        (Want::Directory, false) | (Want::File, true) => Err(Error::ResourceTypeMismatch),
        _ => Ok(node),
    }
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
        creation: now,
        last_write: now,
        change: now,
        permission_key: parent.permission_key.clone(),
        metadata: Metadata::new(),
        length: 0,
        http: HttpProperties::default(),
        lease: None,
        copy: None,
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

fn delete_node(
    db: &Connection,
    share_id: i64,
    node: &NodeInfo,
    reclaim: &mut content::Reclaim,
) -> Result<()> {
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
                lease::check_use(
                    Kind::File,
                    node.lease.as_ref(),
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
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let share = writable(db, &target)?;
            let mut node = find(db, &share, &path, Want::Directory)?;
            let inherited = node.permission_key.clone();
            apply_smb(db, &target, &mut node, &smb, &inherited, now)?;
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
                lease::check_use(
                    Kind::File,
                    node.lease.as_ref(),
                    now,
                    lease_id.as_deref(),
                    Use::Write,
                )?;
                lease::after_write(Kind::File, &mut node.lease, now);
            }
            node.metadata = metadata;
            node.change = now;
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
                    "SELECT EXISTS(SELECT 1 FROM nodes WHERE share_id=?1 AND parent_id=?2)",
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
                    "SELECT {NODE_COLUMNS} FROM nodes
                     WHERE share_id=?1 AND parent_id=?2 AND key>?3 AND instr(key, ?4)=1
                     ORDER BY key LIMIT ?5"
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
                Some(existing) => {
                    lease::check_use(
                        Kind::File,
                        existing.lease.as_ref(),
                        now,
                        lease_id.as_deref(),
                        Use::Write,
                    )?;
                    check_not_read_only(&existing)?;
                    reclaim.add_stored(&tx, share.id, Some(existing.file_id))?;
                    tx.execute(
                        "DELETE FROM ranges WHERE share_id=?1 AND file_id=?2",
                        params![share.id, existing.file_id],
                    )
                    .map_err(db_error)?;
                    let mut node = blank(&parent, &existing.name, false, now);
                    node.file_id = existing.file_id;
                    node.lease = existing.lease;
                    lease::after_write(Kind::File, &mut node.lease, now);
                    node
                }
                None => blank(&parent, name, false, now),
            };
            node.length = length;
            node.http = file_http(http);
            node.metadata = metadata;
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
        length: Option<u64>,
        http: Option<HttpProperties>,
        smb: SmbProperties,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            let mut node = find(&tx, &share, &path, Want::File)?;
            lease::check_use(
                Kind::File,
                node.lease.as_ref(),
                now,
                lease_id.as_deref(),
                Use::Write,
            )?;
            let mut reclaim = content::Reclaim::default();
            if let Some(length) = length.filter(|length| *length != node.length) {
                let old = content::load_map(&tx, share.id, node.file_id, node.length)?;
                let mut new = old.clone();
                new.resize(length);
                content::save_map(&tx, share.id, node.file_id, &old, &new)?;
                reclaim.add_map(&old);
                node.length = length;
                node.last_write = now;
            }
            if let Some(http) = http {
                node.http = file_http(http);
            }
            let inherited = node.permission_key.clone();
            apply_smb(&tx, &target, &mut node, &smb, &inherited, now)?;
            lease::after_write(Kind::File, &mut node.lease, now);
            save_node(&tx, share.id, &node)?;
            finish(tx, env, reclaim)?;
            Ok(node)
        })
        .await
    }

    pub(crate) async fn delete_file(
        &self,
        target: ShareRef,
        path: EntryPath,
        lease_id: Option<String>,
    ) -> Result<()> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            let node = find(&tx, &share, &path, Want::File)?;
            lease::check_use(
                Kind::File,
                node.lease.as_ref(),
                now,
                lease_id.as_deref(),
                Use::Delete,
            )?;
            check_not_read_only(&node)?;
            let mut reclaim = content::Reclaim::default();
            delete_node(&tx, share.id, &node, &mut reclaim)?;
            finish(tx, env, reclaim)
        })
        .await
    }

    /// Writes staged bytes at `offset` as a new extent (Put Range, `x-ms-write: update`).
    pub(crate) async fn put_range(
        &self,
        target: ShareRef,
        path: EntryPath,
        lease_id: Option<String>,
        offset: u64,
        data: content::Staged,
        last_write: TimeSpec,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            let mut node = find(&tx, &share, &path, Want::File)?;
            lease::check_use(
                Kind::File,
                node.lease.as_ref(),
                now,
                lease_id.as_deref(),
                Use::Write,
            )?;
            check_not_read_only(&node)?;
            if offset
                .checked_add(data.length)
                .is_none_or(|end| end > node.length)
            {
                return Err(Error::InvalidRange);
            }
            let old = content::load_map(&tx, share.id, node.file_id, node.length)?;
            let mut new = old.clone();
            let extent = content::new_extent_id();
            new.write(offset, data.length, extent.clone(), 0)
                .map_err(|_| Error::InvalidRange)?;
            check_quota(&tx, &share, new.allocated_bytes(), old.allocated_bytes())?;
            data.publish(&tx, &env.mode, &extent)?;
            let result = (|| {
                content::save_map(&tx, share.id, node.file_id, &old, &new)?;
                let mut reclaim = content::Reclaim::default();
                reclaim.add_map(&old);
                stamp_write(&mut node, last_write, now);
                save_node(&tx, share.id, &node)?;
                let free = reclaim.finish(&tx, &env.mode)?;
                content::check_memory_quota(&tx, &env.mode)?;
                Ok(free)
            })();
            match result {
                Ok(free) => {
                    if let Err(error) = tx.commit().map_err(db_error) {
                        content::discard(env, std::slice::from_ref(&extent));
                        return Err(error);
                    }
                    content::discard(env, &free);
                    Ok(node)
                }
                Err(error) => {
                    drop(tx);
                    content::discard(env, std::slice::from_ref(&extent));
                    Err(error)
                }
            }
        })
        .await
    }

    /// Deallocates a range without writing zeros (Put Range, `x-ms-write: clear`).
    pub(crate) async fn clear_range(
        &self,
        target: ShareRef,
        path: EntryPath,
        lease_id: Option<String>,
        offset: u64,
        length: u64,
        last_write: TimeSpec,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            let mut node = find(&tx, &share, &path, Want::File)?;
            lease::check_use(
                Kind::File,
                node.lease.as_ref(),
                now,
                lease_id.as_deref(),
                Use::Write,
            )?;
            check_not_read_only(&node)?;
            if offset
                .checked_add(length)
                .is_none_or(|end| end > node.length)
            {
                return Err(Error::InvalidRange);
            }
            let old = content::load_map(&tx, share.id, node.file_id, node.length)?;
            let mut new = old.clone();
            new.clear(offset, length).map_err(|_| Error::InvalidRange)?;
            content::save_map(&tx, share.id, node.file_id, &old, &new)?;
            let mut reclaim = content::Reclaim::default();
            reclaim.add_map(&old);
            stamp_write(&mut node, last_write, now);
            save_node(&tx, share.id, &node)?;
            finish(tx, env, reclaim)?;
            Ok(node)
        })
        .await
    }

    pub(crate) async fn read_file(
        &self,
        target: ShareRef,
        path: EntryPath,
        options: ReadOptions,
    ) -> Result<FileRead> {
        self.run(move |db, env| {
            let ReadOptions {
                lease_id,
                conditions,
                range,
                want_md5,
                with_body,
            } = options;
            let share = shares::load_share(db, &target)?;
            let node = find(db, &share, &path, Want::File)?;
            lease::check_use(
                Kind::File,
                node.lease.as_ref(),
                env.clock.now_millis(),
                lease_id.as_deref(),
                Use::Read,
            )?;
            conditions.check(&node.etag, node.modified)?;
            let window = match range {
                Some(range) => {
                    if range.start >= node.length {
                        return Err(Error::InvalidRange);
                    }
                    let end = range
                        .end
                        .map_or(node.length, |end| end.saturating_add(1).min(node.length));
                    Some(range.start..end)
                }
                None => None,
            };
            let span = window.clone().unwrap_or(0..node.length);
            if want_md5 && span.end - span.start > MAX_MD5_RANGE {
                return Err(Error::InvalidHeaderValue);
            }
            if !with_body {
                return Ok(FileRead {
                    info: node,
                    range: window,
                    body: content::FileBody::empty(),
                    md5: None,
                });
            }
            let map = content::load_map(db, share.id, node.file_id, node.length)?;
            let mut body =
                content::FileBody::open(db, env, &map, span.start, span.end - span.start)?;
            let mut md5 = None;
            if want_md5 {
                let bytes = body.into_vec()?;
                md5 = Some(STANDARD.encode(Md5::digest(&bytes)));
                body = content::FileBody::from_vec(bytes);
            }
            Ok(FileRead {
                info: node,
                range: window,
                body,
                md5,
            })
        })
        .await
    }

    /// Allocated ranges of a file, or the difference against an earlier share snapshot.
    pub(crate) async fn list_ranges(
        &self,
        target: ShareRef,
        path: EntryPath,
        lease_id: Option<String>,
        window: Option<Range<u64>>,
        previous: Option<i64>,
    ) -> Result<RangeListing> {
        self.run(move |db, env| {
            let share = shares::load_share(db, &target)?;
            let node = find(db, &share, &path, Want::File)?;
            lease::check_use(
                Kind::File,
                node.lease.as_ref(),
                env.clock.now_millis(),
                lease_id.as_deref(),
                Use::Read,
            )?;
            let map = content::load_map(db, share.id, node.file_id, node.length)?;
            let window = window.unwrap_or(0..node.length);
            let clip = |ranges: Vec<Range<u64>>| -> Vec<Range<u64>> {
                ranges
                    .into_iter()
                    .filter_map(|range| {
                        let (start, end) =
                            (range.start.max(window.start), range.end.min(window.end));
                        (start < end).then_some(start..end)
                    })
                    .collect()
            };
            let (ranges, cleared) = if let Some(previous) = previous {
                if target.snapshot.is_some_and(|current| previous >= current) {
                    return Err(Error::PreviousSnapshotCannotBeNewer);
                }
                let earlier = ShareRef {
                    snapshot: Some(previous),
                    ..target.clone()
                };
                let earlier_share = load_share(db, &earlier).map_err(|error| match error {
                    Error::ShareSnapshotNotFound => Error::PreviousSnapshotNotFound,
                    other => other,
                })?;
                let before = match resolve(db, earlier_share.id, &path)?.node {
                    Some(old) if !old.directory => {
                        if old.file_id != node.file_id {
                            return Err(Error::FileGenerationMismatch);
                        }
                        content::load_map(db, earlier_share.id, old.file_id, old.length)?
                    }
                    _ => RangeMap::new(0),
                };
                let diff = map.diff(&before);
                (clip(diff.changed), clip(diff.cleared))
            } else {
                (clip(map.allocated_ranges()), Vec::new())
            };
            Ok(RangeListing {
                info: node,
                ranges,
                cleared,
            })
        })
        .await
    }

    /// Copy File within this instance: the destination shares the source's extents.
    pub(crate) async fn copy_file(
        &self,
        source: CopySource,
        target: ShareRef,
        path: EntryPath,
        request: CopyRequest,
    ) -> Result<(NodeInfo, String)> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let source_share =
                load_share(&tx, &source.target).map_err(|_| Error::CannotVerifyCopySource)?;
            let from = find(&tx, &source_share, &source.path, Want::File)
                .map_err(|_| Error::CannotVerifyCopySource)?;
            let share = writable(&tx, &target)?;
            let resolved = resolve(&tx, share.id, &path)?;
            let name = path.name().ok_or(Error::ResourceTypeMismatch)?;
            let parent = resolved.parent.ok_or(Error::ParentNotFound)?;
            let mut reclaim = content::Reclaim::default();
            let mut removed = 0;
            let mut node = match resolved.node {
                Some(existing) if existing.directory => return Err(Error::ResourceTypeMismatch),
                Some(existing) => {
                    lease::check_use(
                        Kind::File,
                        existing.lease.as_ref(),
                        now,
                        request.dest_lease.as_deref(),
                        Use::Write,
                    )?;
                    if !request.ignore_readonly {
                        check_not_read_only(&existing)?;
                    }
                    if existing.file_id == from.file_id && share.id == source_share.id {
                        return Err(Error::InvalidInput);
                    }
                    removed = content::load_map(&tx, share.id, existing.file_id, existing.length)?
                        .allocated_bytes();
                    reclaim.add_stored(&tx, share.id, Some(existing.file_id))?;
                    tx.execute(
                        "DELETE FROM ranges WHERE share_id=?1 AND file_id=?2",
                        params![share.id, existing.file_id],
                    )
                    .map_err(db_error)?;
                    let mut node = blank(&parent, &existing.name, false, now);
                    node.file_id = existing.file_id;
                    node.lease = existing.lease;
                    lease::after_write(Kind::File, &mut node.lease, now);
                    node
                }
                None => blank(&parent, name, false, now),
            };
            node.length = from.length;
            node.http = from.http.clone();
            node.metadata = request.metadata.unwrap_or_else(|| from.metadata.clone());
            node.attributes = from.attributes;
            node.creation = from.creation;
            node.last_write = from.last_write;
            node.permission_key = from.permission_key.clone();
            if let Some(smb) = &request.smb {
                apply_smb(&tx, &target, &mut node, smb, &parent.permission_key, now)?;
            } else {
                touch(&mut node, now);
            }
            node.change = now;
            let copy_id = uuid::Uuid::new_v4().hyphenated().to_string();
            node.copy = Some(CopyState {
                id: copy_id.clone(),
                source: source.url,
                length: from.length,
                completed: now,
            });
            if node.file_id == 0 {
                insert_node(&tx, share.id, &mut node)?;
            } else {
                save_node(&tx, share.id, &node)?;
            }
            let from_map = content::load_map(&tx, source_share.id, from.file_id, from.length)?;
            check_quota(&tx, &share, from_map.allocated_bytes(), removed)?;
            content::save_map(
                &tx,
                share.id,
                node.file_id,
                &RangeMap::new(from.length),
                &from_map,
            )?;
            finish(tx, env, reclaim)?;
            Ok((node, copy_id))
        })
        .await
    }

    pub(crate) async fn abort_copy(
        &self,
        target: ShareRef,
        path: EntryPath,
        copy_id: String,
        lease_id: Option<String>,
    ) -> Result<()> {
        self.run(move |db, env| {
            let share = writable(db, &target)?;
            let node = find(db, &share, &path, Want::File)?;
            lease::check_use(
                Kind::File,
                node.lease.as_ref(),
                env.clock.now_millis(),
                lease_id.as_deref(),
                Use::Write,
            )?;
            // Copies complete synchronously, so none is ever pending.
            let _ = (node.copy, copy_id);
            Err(Error::NoPendingCopyOperation)
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
    node.change = now;
    lease::after_write(Kind::File, &mut node.lease, now);
    touch(node, now);
}
