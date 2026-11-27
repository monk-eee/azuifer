//! Materializes sparse range windows for downloads and staged copies.

use super::super::{
    Mode, SourceBytes, Uploaded, UploadedData, db_error, extent, internal, io_error,
    require_file_if_present, sqlite_int, staging_file,
};
use super::{RangeSource, load_source_window};
use crate::{
    checksum::Hasher,
    domain::{BlobInfo, BlobKey, ContentLength, Error, Result},
    ranges::{RangeMap, Segment},
};
use axum::body::Bytes;
use futures_util::{StreamExt as _, TryStreamExt as _, stream::BoxStream};
use rusqlite::{Connection, params};
use std::{
    fs::File,
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    ops::Range,
    path::PathBuf,
};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

const CHUNK: usize = 64 * 1024;

enum Piece {
    Extent {
        path: PathBuf,
        offset: u64,
        length: u64,
    },
    Memory(Vec<u8>),
    Zeros(u64),
}

/// The bytes of a read: extent slices and zero-filled holes, in order. Extent files
/// are opened only when streamed, so a fragmented blob does not hold many handles.
pub(crate) struct RangeBody(Vec<Piece>);

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
                        Piece::Extent {
                            path,
                            offset: extent_offset,
                            length,
                        }
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
        Ok(Self(pieces))
    }

    /// Feeds every byte to `sink` in order, in bounded chunks.
    fn copy_into(self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut buffer = vec![0u8; CHUNK];
        for piece in self.0 {
            match piece {
                Piece::Extent {
                    path,
                    offset,
                    length,
                } => {
                    let mut file = File::open(path).map_err(io_error)?;
                    file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
                    let mut left = length;
                    while left > 0 {
                        let want = usize::try_from(left).unwrap_or(CHUNK).min(CHUNK);
                        let read = file.read(&mut buffer[..want]).map_err(io_error)?;
                        if read == 0 {
                            return Err(internal("extent ended early"));
                        }
                        sink(&buffer[..read])?;
                        left -= read as u64;
                    }
                }
                Piece::Memory(bytes) => sink(&bytes)?,
                Piece::Zeros(length) => {
                    buffer.fill(0);
                    let mut left = length;
                    while left > 0 {
                        let take = usize::try_from(left).unwrap_or(CHUNK).min(CHUNK);
                        sink(&buffer[..take])?;
                        left -= take as u64;
                    }
                }
            }
        }
        Ok(())
    }

    /// Reads everything into memory; callers bound the size (a ranged checksum).
    pub(crate) fn into_vec(self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.copy_into(&mut |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(bytes)
    }

    pub(crate) fn into_stream(self) -> BoxStream<'static, std::io::Result<Bytes>> {
        futures_util::stream::iter(self.0)
            .map(piece_stream)
            .flatten()
            .boxed()
    }
}

fn piece_stream(piece: Piece) -> BoxStream<'static, std::io::Result<Bytes>> {
    match piece {
        Piece::Extent {
            path,
            offset,
            length,
        } => futures_util::stream::once(async move {
            let mut file = tokio::fs::File::open(path).await?;
            file.seek(SeekFrom::Start(offset)).await?;
            Ok::<_, std::io::Error>(ReaderStream::new(file.take(length)))
        })
        .try_flatten()
        .boxed(),
        Piece::Memory(bytes) => {
            futures_util::stream::once(async move { Ok(Bytes::from(bytes)) }).boxed()
        }
        Piece::Zeros(length) => futures_util::stream::unfold(length, |left| async move {
            if left == 0 {
                return None;
            }
            let take = left.min(CHUNK as u64);
            let chunk = Bytes::from(vec![0u8; usize::try_from(take).unwrap_or(CHUNK)]);
            Some((Ok(chunk), left - take))
        })
        .boxed(),
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
            body.copy_into(&mut |chunk| {
                hasher.update(chunk);
                sink.write_all(chunk).map_err(io_error)
            })?;
            sink.flush().map_err(io_error)?;
            UploadedData::Disk(temp)
        }
        Mode::Memory { .. } => {
            let mut bytes = Vec::new();
            body.copy_into(&mut |chunk| {
                hasher.update(chunk);
                bytes.extend_from_slice(chunk);
                Ok(())
            })?;
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
