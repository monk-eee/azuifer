//! Checks every persistent store makes on its data directory before it trusts what is there,
//! shared so that Blob and DFS, Files, Queue and Table refuse the same things.
//!
//! A store's directory, lock file, database and its write-ahead and shared-memory files must
//! be what they appear to be: a link would let another path decide where metadata and content
//! land. The schema stamped in `PRAGMA user_version` must not be newer than the build knows,
//! since an older release that migrated or wrote such a database would damage it.

use anyhow::{Context as _, Result, ensure};
use rusqlite::{Connection, OpenFlags};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// The files SQLite keeps beside `<stem>.sqlite3` in write-ahead logging mode.
const SIDE_FILES: [&str; 2] = ["-wal", "-shm"];

pub(crate) fn require_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if is_link(&metadata) {
        return Err(refusal(
            path,
            "is a link; Azuifer does not follow links in its data",
        ));
    }
    if !metadata.is_dir() {
        return Err(refusal(path, "must be a directory"));
    }
    Ok(())
}

/// A file that does not exist yet passes; one that exists must be a regular file.
pub(crate) fn require_file_if_present(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_link(&metadata) => Err(refusal(
            path,
            "is a link; Azuifer does not follow links in its data",
        )),
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(refusal(path, "must be a regular file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Checks the database and its write-ahead and shared-memory files.
pub(crate) fn require_database(directory: &Path, file_name: &str) -> io::Result<()> {
    require_file_if_present(&directory.join(file_name))?;
    for suffix in SIDE_FILES {
        require_file_if_present(&directory.join(format!("{file_name}{suffix}")))?;
    }
    Ok(())
}

/// Makes a new directory entry durable where the platform allows it.
pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn refusal(path: &Path, what: &str) -> io::Error {
    io::Error::other(format!("storage path {} {what}", path.display()))
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    metadata.is_symlink()
}

pub(crate) fn user_version(db: &Connection) -> rusqlite::Result<i64> {
    db.pragma_query_value(None, "user_version", |row| row.get(0))
}

/// Refuses a database whose schema is newer than `supported`.
pub(crate) fn require_known_schema(found: i64, supported: i64, store: &str) -> Result<()> {
    ensure!(
        found <= supported,
        "the {store} storage was written by a newer Azuifer (schema {found}; this build reads up to \
         {supported}); run that release, or use another --location"
    );
    Ok(())
}

/// Where one store keeps its files below the data directory, and the newest schema this
/// build reads for it.
pub(crate) struct Layout {
    pub(crate) store: &'static str,
    pub(crate) directory: PathBuf,
    pub(crate) database: &'static str,
    pub(crate) lock: &'static str,
    /// The directory of content files, for the stores that keep content outside SQLite.
    pub(crate) content: Option<PathBuf>,
    pub(crate) supported: i64,
}

pub(crate) fn layouts(location: &Path) -> [Layout; 4] {
    let at = |name: &str| location.join(name);
    [
        Layout {
            store: "Blob and DFS",
            directory: location.to_owned(),
            database: "metadata.sqlite3",
            lock: "azuifer.lock",
            content: Some(at("content")),
            supported: super::schema::supported(),
        },
        Layout {
            store: "Files",
            directory: at("file"),
            database: "metadata.sqlite3",
            lock: "azuifer.lock",
            content: Some(at("file").join("content")),
            supported: crate::files::SCHEMA_VERSION,
        },
        Layout {
            store: "Queue",
            directory: at("queue"),
            database: "queue.sqlite3",
            lock: "queue.lock",
            content: None,
            supported: crate::queue::SCHEMA_VERSION,
        },
        Layout {
            store: "Table",
            directory: at("table"),
            database: "table.sqlite3",
            lock: "table.lock",
            content: None,
            supported: crate::table::SCHEMA_VERSION,
        },
    ]
}

/// What `azuifer doctor` can say about a store directory without opening it for writing:
/// `Ok(None)` when the store was never used, `Ok(Some(note))` when it is sound, and an error
/// naming the first problem.
pub(crate) fn inspect(layout: &Layout) -> Result<Option<String>> {
    if fs::symlink_metadata(&layout.directory).is_err() {
        return Ok(None);
    }
    require_directory(&layout.directory)?;
    require_file_if_present(&layout.directory.join(layout.lock))?;
    if let Some(content) = &layout.content
        && fs::symlink_metadata(content).is_ok()
    {
        require_directory(content)?;
    }
    require_database(&layout.directory, layout.database)?;
    let path = layout.directory.join(layout.database);
    if fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("{} is not a readable SQLite database", path.display()))?;
    let found = user_version(&db)
        .with_context(|| format!("{} is not a readable SQLite database", path.display()))?;
    require_known_schema(found, layout.supported, layout.store)?;
    let check: String = db
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .with_context(|| format!("{} failed its integrity check", path.display()))?;
    ensure!(check == "ok", "{} is corrupt: {check}", path.display());
    Ok(Some(format!("schema {found} of {}", layout.supported)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_must_be_a_directory_and_a_file_a_regular_file_and_a_missing_file_passes() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("plain");
        fs::write(&file, b"x").unwrap();
        assert!(require_directory(root.path()).is_ok());
        let error = require_directory(&file).unwrap_err().to_string();
        assert!(
            error.contains("must be a directory") && error.contains("plain"),
            "{error}"
        );
        assert!(require_file_if_present(&file).is_ok());
        assert!(require_file_if_present(&root.path().join("absent")).is_ok());
        let error = require_file_if_present(root.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be a regular file"), "{error}");
        assert_eq!(
            require_directory(&root.path().join("absent"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn a_database_and_its_side_files_are_each_checked() {
        let root = tempfile::tempdir().unwrap();
        assert!(require_database(root.path(), "x.sqlite3").is_ok());
        fs::create_dir(root.path().join("x.sqlite3-shm")).unwrap();
        let error = require_database(root.path(), "x.sqlite3")
            .unwrap_err()
            .to_string();
        assert!(error.contains("x.sqlite3-shm"), "{error}");
    }

    #[test]
    fn the_schema_check_accepts_the_known_and_refuses_the_newer() {
        assert!(require_known_schema(0, 3, "Queue").is_ok());
        assert!(require_known_schema(3, 3, "Queue").is_ok());
        let error = require_known_schema(4, 3, "Queue").unwrap_err().to_string();
        assert!(error.contains("Queue") && error.contains("newer Azuifer") && error.contains('4'));
    }

    #[test]
    fn inspect_tells_an_unused_store_from_a_sound_a_newer_and_a_corrupt_one() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout {
            store: "Test",
            directory: root.path().join("store"),
            database: "t.sqlite3",
            lock: "t.lock",
            content: None,
            supported: 2,
        };
        assert_eq!(inspect(&layout).unwrap(), None);
        fs::create_dir(&layout.directory).unwrap();
        assert_eq!(inspect(&layout).unwrap(), None, "no database yet");
        let path = layout.directory.join("t.sqlite3");
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch("CREATE TABLE t (x); PRAGMA user_version = 2")
                .unwrap();
        }
        assert_eq!(inspect(&layout).unwrap().as_deref(), Some("schema 2 of 2"));
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 3)
            .unwrap();
        let error = inspect(&layout).unwrap_err().to_string();
        assert!(error.contains("newer Azuifer"), "{error}");
        fs::write(&path, vec![1u8; 4096]).unwrap();
        let error = format!("{:#}", inspect(&layout).unwrap_err());
        assert!(error.contains("t.sqlite3"), "{error}");
    }
}
