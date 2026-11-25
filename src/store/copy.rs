use super::{
    ContentSource, Mode, Store, Uploaded, UploadedData, io_error, open_extent, read_memory_slice,
    require_blob, staging_file,
};
use crate::{
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
    /// checked here; a failed condition is `SourceConditionNotMet`.
    pub(crate) async fn read_source(
        &self,
        key: BlobKey,
        guard: Guard,
        range: Option<ByteRange>,
    ) -> Result<SourceBytes> {
        self.run(move |db, mode, now| {
            let row = require_blob(db, &key, now)?;
            row.lease
                .check(guard.lease, LeaseNeed::Optional, LeaseOwner::Blob, now)?;
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
                    let bytes = read_memory_slice(
                        db,
                        ContentSource::Blob,
                        info.entity.id,
                        window.start,
                        length,
                    )?;
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
