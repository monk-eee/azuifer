//! Read plans keep immutable extent files alive after the metadata lock is released.

use crate::runtime_metrics::{self, Failure, Removal};
use axum::body::Bytes;
use futures_util::{
    StreamExt as _,
    stream::{self, BoxStream},
};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read as _, Seek as _, SeekFrom},
    path::Path,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

const CHUNK: usize = 64 * 1024;

struct Reading {
    readers: usize,
    doomed: bool,
}

#[derive(Default)]
pub(crate) struct Readers(Mutex<HashMap<Arc<Path>, Reading>>);

impl Readers {
    fn lock(&self) -> MutexGuard<'_, HashMap<Arc<Path>, Reading>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Called after the metadata change commits and no stored reference remains.
    pub(crate) fn reclaim(&self, path: &Path) {
        if let Some(reading) = self.lock().get_mut(path) {
            reading.doomed = true;
            return;
        }
        remove(path);
    }
}

struct Pins {
    readers: Arc<Readers>,
    paths: Vec<Arc<Path>>,
}

impl Pins {
    fn new(readers: &Arc<Readers>, paths: Vec<Arc<Path>>) -> Self {
        let mut held = readers.lock();
        for path in &paths {
            held.entry(path.clone())
                .or_insert(Reading {
                    readers: 0,
                    doomed: false,
                })
                .readers += 1;
        }
        Self {
            readers: readers.clone(),
            paths,
        }
    }
}

impl Drop for Pins {
    fn drop(&mut self) {
        let mut doomed = Vec::new();
        {
            let mut held = self.readers.lock();
            for path in &self.paths {
                let Some(reading) = held.get_mut(path) else {
                    continue;
                };
                reading.readers -= 1;
                if reading.readers == 0 {
                    if reading.doomed {
                        doomed.push(path.clone());
                    }
                    held.remove(path);
                }
            }
        }
        if !doomed.is_empty() {
            let cleanup = move || doomed.iter().for_each(|path| remove(path));
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn_blocking(cleanup);
            } else {
                cleanup();
            }
        }
    }
}

fn remove(path: &Path) {
    let bytes = std::fs::metadata(path).map_or(0, |metadata| metadata.len());
    match std::fs::remove_file(path) {
        Ok(()) => runtime_metrics::removed(Removal::Reclaimed, bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "content cleanup deferred until recovery");
            runtime_metrics::failure(runtime_metrics::Store::Content, Failure::Io);
        }
    }
}

pub(crate) enum Piece {
    Disk(ExtentSlice),
    Memory(Vec<u8>),
    Zeros(u64),
}

pub(crate) struct ExtentSlice {
    pub(crate) path: Arc<Path>,
    pub(crate) offset: u64,
    pub(crate) length: u64,
}

impl ExtentSlice {
    fn open(&self) -> io::Result<File> {
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(self.offset))?;
        Ok(file)
    }
}

#[derive(Default)]
pub(crate) struct ReadBody {
    pieces: Vec<Piece>,
    pins: Option<Arc<Pins>>,
}

impl ReadBody {
    /// Plans and pins a read under the metadata lock. No descriptor is kept open.
    pub(crate) fn new(pieces: Vec<Piece>, readers: Option<&Arc<Readers>>) -> Self {
        let pins = readers.map(|readers| {
            Arc::new(Pins::new(
                readers,
                pieces
                    .iter()
                    .filter_map(|piece| match piece {
                        Piece::Disk(slice) => Some(slice.path.clone()),
                        _ => None,
                    })
                    .collect(),
            ))
        });
        Self { pieces, pins }
    }

    pub(crate) fn copy_into(self, mut sink: impl FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
        let _held = self.pins;
        let mut buffer = vec![0; CHUNK];
        for piece in self.pieces {
            match piece {
                Piece::Disk(slice) => {
                    let mut file = slice.open()?;
                    let mut left = slice.length;
                    while left != 0 {
                        let len = left.min(CHUNK as u64) as usize;
                        file.read_exact(&mut buffer[..len])?;
                        sink(&buffer[..len])?;
                        left -= len as u64;
                    }
                }
                Piece::Memory(bytes) => sink(&bytes)?,
                Piece::Zeros(mut left) => {
                    buffer.fill(0);
                    while left != 0 {
                        let len = left.min(CHUNK as u64) as usize;
                        sink(&buffer[..len])?;
                        left -= len as u64;
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn into_vec(self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.copy_into(|chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(bytes)
    }

    pub(crate) fn into_stream(self) -> BoxStream<'static, io::Result<Bytes>> {
        stream::iter(self.pieces)
            .map(move |piece| match piece {
                Piece::Disk(slice) => {
                    let state = DiskRead {
                        file: None,
                        slice,
                        _pins: self.pins.clone(),
                    };
                    stream::try_unfold(state, |state| async move {
                        if state.slice.length == 0 {
                            return Ok(None);
                        }
                        tokio::task::spawn_blocking(move || state.read_chunk())
                            .await
                            .map_err(io::Error::other)?
                            .map(Some)
                    })
                    .boxed()
                }
                Piece::Memory(bytes) => stream::once(async move { Ok(Bytes::from(bytes)) }).boxed(),
                Piece::Zeros(length) => stream::unfold(length, |left| async move {
                    let len = left.min(CHUNK as u64) as usize;
                    (len != 0).then(|| (Ok(Bytes::from(vec![0; len])), left - len as u64))
                })
                .boxed(),
            })
            .flatten()
            .boxed()
    }
}

// Each worker owns a pin until its file closes, even if the HTTP stream is cancelled
// while the blocking read is running. Fields drop in declaration order.
struct DiskRead {
    file: Option<File>,
    slice: ExtentSlice,
    _pins: Option<Arc<Pins>>,
}

impl DiskRead {
    fn read_chunk(self) -> io::Result<(Bytes, Self)> {
        self.read().inspect_err(|_| {
            runtime_metrics::failure(runtime_metrics::Store::Content, Failure::Io);
        })
    }

    fn read(mut self) -> io::Result<(Bytes, Self)> {
        let file = match &mut self.file {
            Some(file) => file,
            slot @ None => slot.insert(self.slice.open()?),
        };
        let len = self.slice.length.min(CHUNK as u64) as usize;
        let mut bytes = vec![0; len];
        file.read_exact(&mut bytes)?;
        self.slice.length -= len as u64;
        if self.slice.length == 0 {
            drop(self.file.take());
        }
        Ok((Bytes::from(bytes), self))
    }
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    use super::*;

    fn open_extents(paths: &[Arc<Path>]) -> Vec<Arc<Path>> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            paths
                .iter()
                .filter(|path| {
                    std::fs::OpenOptions::new()
                        .read(true)
                        .share_mode(0)
                        .open(path)
                        .is_err()
                })
                .cloned()
                .collect()
        }
        #[cfg(target_os = "linux")]
        {
            let descriptors: Vec<_> = std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|entry| std::fs::read_link(entry.unwrap().path()).ok())
                .collect();
            paths
                .iter()
                .filter(|path| {
                    descriptors
                        .iter()
                        .any(|open| open.as_path() == path.as_ref())
                })
                .cloned()
                .collect()
        }
    }

    #[tokio::test]
    async fn a_paused_download_has_only_its_current_extent_open() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let paths: Vec<Arc<Path>> = (0..3)
            .map(|i| Arc::from(root.join(i.to_string())))
            .collect();
        let size = CHUNK + 1;
        for path in &paths {
            std::fs::write(path, vec![b'x'; size]).unwrap();
        }
        let pieces = paths
            .iter()
            .map(|path| {
                Piece::Disk(ExtentSlice {
                    path: path.clone(),
                    offset: 0,
                    length: size as u64,
                })
            })
            .collect();
        let mut stream = ReadBody::new(pieces, Some(&Arc::default())).into_stream();
        assert!(open_extents(&paths).is_empty());
        for path in &paths {
            assert_eq!(stream.next().await.unwrap().unwrap().len(), CHUNK);
            assert_eq!(open_extents(&paths).as_slice(), std::slice::from_ref(path));
            assert_eq!(stream.next().await.unwrap().unwrap().len(), 1);
        }
        assert!(stream.next().await.is_none());
        assert!(open_extents(&paths).is_empty());
    }
}
