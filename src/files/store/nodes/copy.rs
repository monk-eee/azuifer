//! Copy File within one instance, aborting a copy, and the NFS mode and owner choices a
//! copy makes.

use super::{
    Store, Want, apply_smb, blank, check_file_lease, check_not_read_only, check_quota, content,
    db_error, find, finish, for_share, insert_node, is_symlink, new_nfs, resolve, save_node,
    shares::{ShareRef, load_share},
    touch, writable,
};
use crate::{
    files::{
        error::{Error, Result},
        lease::{self, Kind, Use},
        model::{CopyState, FileKind, Metadata, NodeInfo, Posix, SmbProperties},
        name::EntryPath,
        time::TICKS_PER_MILLI,
    },
    ranges::RangeMap,
};
use rusqlite::params;

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
    /// The NFS mode and owner choices, used when the destination share is NFS.
    pub(crate) nfs: NfsCopy,
}

/// Where a copy takes a property of an NFS destination from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CopyBy {
    Source,
    Override,
}

/// `x-ms-file-mode-copy-mode`, `x-ms-file-owner-copy-mode`, and the values they override with.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NfsCopy {
    pub(crate) mode: CopyBy,
    pub(crate) owner: CopyBy,
    pub(crate) posix: Posix,
}

impl Default for NfsCopy {
    fn default() -> Self {
        Self {
            mode: CopyBy::Source,
            owner: CopyBy::Source,
            posix: Posix::default(),
        }
    }
}

/// The POSIX properties a copy gives an NFS destination: each of mode and owner comes from
/// the source or from the request, as `x-ms-file-mode-copy-mode` and
/// `x-ms-file-owner-copy-mode` say. A source without POSIX properties yields the defaults.
fn copied_posix(from: &NodeInfo, copy: &NfsCopy) -> Posix {
    let source = from.nfs.as_ref();
    let (owner, group) = match copy.owner {
        CopyBy::Override => (copy.posix.owner, copy.posix.group),
        CopyBy::Source => (source.map(|nfs| nfs.owner), source.map(|nfs| nfs.group)),
    };
    Posix {
        mode: match copy.mode {
            CopyBy::Override => copy.posix.mode,
            CopyBy::Source => source.map(|nfs| nfs.mode),
        },
        owner,
        group,
    }
}

impl Store {
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
            let share_source =
                load_share(&tx, &source.target).map_err(|_| Error::CannotVerifyCopySource)?;
            let from = find(&tx, &share_source, &source.path, Want::Regular).map_err(|error| {
                if error == Error::XNfs4FileTypeUnsupportedException {
                    error
                } else {
                    Error::CannotVerifyCopySource
                }
            })?;
            let share = writable(&tx, &target)?;
            let resolved = resolve(&tx, share.id, &path)?;
            let name = path.name().ok_or(Error::ResourceTypeMismatch)?;
            let parent = resolved.parent.ok_or(Error::ParentNotFound)?;
            let mut reclaim = content::Reclaim::default();
            let mut removed = 0;
            let mut node = match resolved.node {
                Some(existing) if existing.directory => return Err(Error::ResourceTypeMismatch),
                Some(existing) if is_symlink(&existing) => {
                    return Err(Error::XNfs4FileTypeUnsupportedException);
                }
                Some(existing) => {
                    check_file_lease(&existing, now, request.dest_lease.as_deref(), Use::Write)?;
                    if !request.ignore_readonly {
                        check_not_read_only(&existing)?;
                    }
                    if existing.file_id == from.file_id && share.id == share_source.id {
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
            node.length = from.length;
            node.http = from.http.clone();
            node.metadata = request.metadata.unwrap_or_else(|| from.metadata.clone());
            node.attributes = from.attributes;
            node.creation = from.creation;
            node.last_write = from.last_write;
            node.permission_key = from.permission_key.clone();
            node.nfs = new_nfs(
                &share,
                FileKind::Regular,
                copied_posix(&from, &request.nfs),
                None,
            );
            if let Some(smb) = request.smb.map(|smb| for_share(&share, smb)) {
                apply_smb(&tx, &target, &mut node, &smb, &parent.permission_key, now)?;
            } else {
                touch(&mut node, now);
            }
            node.change = now * TICKS_PER_MILLI;
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
            let from_map = content::load_map(&tx, share_source.id, from.file_id, from.length)?;
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
}
