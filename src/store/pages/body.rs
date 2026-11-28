//! Materializes sparse range windows for downloads and staged copies.

use super::super::{
    Mode, SourceBytes, Uploaded, UploadedData, db_error, extent, internal, io_error,
    require_file_if_present, sqlite_int, staging_file,
};
use super::{RangeSource, load_source_window};
use crate::{
    checksum::Hasher,
    domain::{BlobInfo, BlobKey, ContentLength, Error, Result},
    extent_readers::{ExtentSlice, Piece, ReadBody},
    ranges::{RangeMap, Segment},
};
use axum::body::Bytes;
use futures_util::stream::BoxStream;
use rusqlite::{Connection, params};
use std::{io::Write as _, ops::Range, sync::Arc};
use uuid::Uuid;

/// The bytes of a read: extent slices and zero-filled holes, in order.
pub(crate) struct RangeBody(ReadBody);

impl RangeBody {
    fn open(
        db: &Connection,
        mode: &Mode,
        map: &RangeMap<Uuid>,
        offset: u64,
        length: u64,
    ) -> Result<Self> {
        let segments = map
            .resolve(offset, length)
            .map_err(|_| internal("range overflow"))?;
        let mut pieces = Vec::with_capacity(segments.len());
        for segment in segments {
            pieces.push(match segment {
                Segment::Hole { length, .. } => Piece::Zeros(length),
                Segment::Data {
                    extent: id,
                    extent_offset,
                    length,
                    ..
                } => match mode {
                    Mode::Disk { extents, .. } => {
                        let path = extent(extents, id);
                        require_file_if_present(&path).map_err(io_error)?;
                        let size = std::fs::metadata(&path).map_err(io_error)?.len();
                        if size < extent_offset + length {
                            return Err(internal("extent is shorter than its range"));
                        }
                        Piece::Disk(ExtentSlice {
                            path: Arc::from(path),
                            offset: extent_offset,
                            length,
                        })
                    }
                    Mode::Memory { .. } => {
                        let bytes: Vec<u8> = db
                            .query_row(
                                "SELECT substr(bytes, ?2, ?3) FROM blob_extents WHERE id=?1",
                                params![id, sqlite_int(extent_offset + 1)?, sqlite_int(length)?],
                                |row| row.get(0),
                            )
                            .map_err(db_error)?;
                        if bytes.len() as u64 != length {
                            return Err(internal("in-memory extent is shorter than its range"));
                        }
                        Piece::Memory(bytes)
                    }
                },
            });
        }
        let readers = match mode {
            Mode::Disk { readers, .. } => Some(readers),
            Mode::Memory { .. } => None,
        };
        Ok(Self(ReadBody::new(pieces, readers)))
    }

    /// Reads everything into memory; callers bound the size (a ranged checksum).
    pub(crate) fn into_vec(self) -> Result<Vec<u8>> {
        self.0.into_vec().map_err(io_error)
    }

    pub(crate) fn into_stream(self) -> BoxStream<'static, std::io::Result<Bytes>> {
        self.0.into_stream()
    }
}

/// Resolves `window` of a page or append blob into readable pieces.
pub(in crate::store) fn open_body(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    source: RangeSource,
    length: u64,
    window: Range<u64>,
) -> Result<RangeBody> {
    let map = load_source_window(db, key, source, window.start, window.end, length)?;
    RangeBody::open(db, mode, &map, window.start, window.end - window.start)
}

/// Reads a window of a page or append blob into staging, as a copy source.
pub(in crate::store) fn source_bytes(
    db: &Connection,
    mode: &Mode,
    key: &BlobKey,
    source: RangeSource,
    info: BlobInfo,
    window: Range<u64>,
) -> Result<SourceBytes> {
    let length = window.end - window.start;
    if let Mode::Memory { limit } = mode
        && length > *limit
    {
        return Err(Error::QuotaExceeded);
    }
    let body = open_body(db, mode, key, source, info.length.0, window)?;
    let mut hasher = Hasher::new();
    let data = match mode {
        Mode::Disk { extents, .. } => {
            let temp = staging_file(extents).map_err(io_error)?;
            let mut sink = temp.reopen().map_err(io_error)?;
            body.0
                .copy_into(|chunk| {
                    hasher.update(chunk);
                    sink.write_all(chunk)
                })
                .map_err(io_error)?;
            sink.flush().map_err(io_error)?;
            UploadedData::Disk(temp)
        }
        Mode::Memory { .. } => {
            let mut bytes = Vec::new();
            body.0
                .copy_into(|chunk| {
                    hasher.update(chunk);
                    bytes.extend_from_slice(chunk);
                    Ok(())
                })
                .map_err(io_error)?;
            UploadedData::Memory(bytes)
        }
    };
    Ok(SourceBytes {
        info,
        upload: Uploaded {
            length: ContentLength(length),
            checksums: hasher.finish(None)?,
            data,
        },
    })
}
