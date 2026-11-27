//! NFS hard links and symbolic links (ADR-0029).

use super::{
    Store, Want, apply_smb, blank, db_error, file_http, find, for_share, insert_node, is_nfs,
    is_symlink, resolve, save_node, shares, shares::ShareRef, touch, writable,
};
use crate::files::{
    error::{Error, Result},
    model::{FileKind, HttpProperties, Metadata, NfsProps, NodeInfo, Posix, SmbProperties},
    name::{EntryPath, fold},
    time::TICKS_PER_MILLI,
};
use rusqlite::params;

const MAX_LINK_TEXT_BYTES: usize = 4096;

impl Store {
    /// Create Hard Link: another name for an existing regular file of an NFS share. The link
    /// shares the inode, so content, properties and file id are the file's.
    pub(crate) async fn create_hard_link(
        &self,
        target: ShareRef,
        path: EntryPath,
        source: EntryPath,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            if !is_nfs(&share) {
                return Err(Error::InvalidQueryParameterValue);
            }
            let resolved = resolve(&tx, share.id, &path)?;
            let name = path.name().ok_or(Error::ResourceAlreadyExists)?;
            let parent = resolved.parent.ok_or(Error::ParentNotFound)?;
            if resolved.node.is_some() {
                return Err(Error::ResourceAlreadyExists);
            }
            let mut inode = find(&tx, &share, &source, Want::Any)?;
            if inode.directory {
                return Err(Error::InvalidHeaderValue);
            }
            if is_symlink(&inode) {
                return Err(Error::XNfs4FileTypeUnsupportedException);
            }
            let entry: i64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(entry_id), 0) + 1 FROM links WHERE share_id=?1",
                    [share.id],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            tx.execute(
                "INSERT INTO links (share_id, entry_id, file_id, parent_id, name, key)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    share.id,
                    entry,
                    inode.file_id,
                    parent.file_id,
                    name,
                    fold(name)
                ],
            )
            .map_err(db_error)?;
            inode.change = now * TICKS_PER_MILLI;
            touch(&mut inode, now);
            save_node(&tx, share.id, &inode)?;
            tx.commit().map_err(db_error)?;
            inode.parent_id = Some(parent.file_id);
            inode.name = name.to_owned();
            inode.entry = Some(entry);
            inode.links += 1;
            Ok(inode)
        })
        .await
    }

    /// Create Symbolic Link: a node that holds `link_text` as given and nothing else.
    pub(crate) async fn create_symlink(
        &self,
        target: ShareRef,
        path: EntryPath,
        link_text: String,
        posix: Posix,
        metadata: Metadata,
        smb: SmbProperties,
    ) -> Result<NodeInfo> {
        self.run(move |db, env| {
            let now = env.clock.now_millis();
            let tx = db.transaction().map_err(db_error)?;
            let share = writable(&tx, &target)?;
            if !is_nfs(&share) {
                return Err(Error::InvalidQueryParameterValue);
            }
            if link_text.is_empty() || link_text.len() > MAX_LINK_TEXT_BYTES {
                return Err(Error::InvalidHeaderValue);
            }
            let resolved = resolve(&tx, share.id, &path)?;
            let name = path.name().ok_or(Error::ResourceAlreadyExists)?;
            let parent = resolved.parent.ok_or(Error::ParentNotFound)?;
            if resolved.node.is_some() {
                return Err(Error::ResourceAlreadyExists);
            }
            let mut node = blank(&parent, name, false, now);
            node.length = link_text.len() as u64;
            node.http = file_http(HttpProperties::default());
            node.metadata = metadata;
            node.nfs = Some(NfsProps::create(FileKind::SymLink, posix, Some(link_text)));
            let smb = for_share(&share, smb);
            apply_smb(&tx, &target, &mut node, &smb, &parent.permission_key, now)?;
            insert_node(&tx, share.id, &mut node)?;
            tx.commit().map_err(db_error)?;
            Ok(node)
        })
        .await
    }

    /// Read Symbolic Link, on a live share or a snapshot.
    pub(crate) async fn read_symlink(&self, target: ShareRef, path: EntryPath) -> Result<NodeInfo> {
        self.run(move |db, _| {
            let share = shares::load_share(db, &target)?;
            if !is_nfs(&share) {
                return Err(Error::InvalidQueryParameterValue);
            }
            let node = find(db, &share, &path, Want::File)?;
            if is_symlink(&node) {
                Ok(node)
            } else {
                Err(Error::XNfs4FileTypeUnsupportedException)
            }
        })
        .await
    }
}
