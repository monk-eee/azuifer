use super::{
    Mode, Store, Uploaded, UploadedData, io_error, open_extent, read_memory_slice, snapshots,
    staging_file,
};
use crate::{
    blob_snapshot::Selector,
    checksum::Hasher,
    conditions::Guard,
    domain::{AccessTier, BlobInfo, BlobKey, ByteRange, ContentLength, Error, Result},
    lease::{LeaseNeed, LeaseOwner},
};
use std::io::{Read as _, Write as _};

/// The bytes and properties of a same-instance copy source.
pub(crate) struct SourceBytes {
    pub(crate) info: BlobInfo,
    pub(crate) upload: Uploaded,
}

impl Store {
    /// Reads a source blob (or a range of it) into a staged upload that Put Blob,
    /// Put Block, or a copy can publish. Source conditions and its lease are
    /// checked here; a failed condition is `SourceConditionNotMet`. A selector
    /// reads a snapshot or version instead of the current blob.
    pub(crate) async fn read_source(
        &self,
        key: BlobKey,
        selector: Option<Selector>,
        guard: Guard,
        range: Option<ByteRange>,
    ) -> Result<SourceBytes> {
        self.run(move |db, mode, now| {
            let (row, source) = snapshots::resolve_source(db, &key, selector, now)?;
            row.lease
                .check(guard.lease, LeaseNeed::Optional, LeaseOwner::Blob, now)?;
            guard
                .conditions
                .check_tags(Some(&row.info.tags))
                .map_err(|error| match error {
                    Error::ConditionNotMet => Error::SourceConditionNotMet,
                    other => other,
                })?;
            guard
                .conditions
                .check(Some(row.info.entity), false)
                .map_err(|error| match error {
                    Error::ConditionNotMet => Error::SourceConditionNotMet,
                    other => other,
                })?;
            let info = row.info;
            if matches!(info.tier, Some((AccessTier::Archive, _))) {
                return Err(Error::BlobArchived);
            }
            let window = match &range {
                Some(range) => range.resolve(info.length)?,
                None => 0..info.length.0,
            };
            let length = window.end - window.start;
            if !info.kind.is_block() {
                return super::pages::source_bytes(db, mode, &key, info, window);
            }
            let mut hasher = Hasher::new();
            let data = match mode {
                Mode::Disk { extents, .. } => {
                    let mut source =
                        open_extent(extents, info.entity.id, info.length.0, window.start)?
                            .take(length);
                    let temp = staging_file(extents).map_err(io_error)?;
                    let mut sink = temp.reopen().map_err(io_error)?;
                    let mut buffer = vec![0u8; 64 * 1024];
                    loop {
                        let read = source.read(&mut buffer).map_err(io_error)?;
                        if read == 0 {
                            break;
                        }
                        hasher.update(&buffer[..read]);
                        sink.write_all(&buffer[..read]).map_err(io_error)?;
                    }
                    sink.flush().map_err(io_error)?;
                    UploadedData::Disk(temp)
                }
                Mode::Memory { .. } => {
                    let bytes =
                        read_memory_slice(db, source, info.entity.id, window.start, length)?;
                    hasher.update(&bytes);
                    UploadedData::Memory(bytes)
                }
            };
            let checksums = hasher.finish(None)?;
            Ok(SourceBytes {
                info,
                upload: Uploaded {
                    length: ContentLength(length),
                    checksums,
                    data,
                },
            })
        })
        .await
    }
}
