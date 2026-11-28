//! Removing content a crash left behind.

use crate::runtime_metrics::{self, Removal};
use rusqlite::Connection;
use std::{fs, path::Path};
use uuid::Uuid;

/// Deletes staging files and extents that no metadata references.
pub(super) fn recover(db: &Connection, dir: &Path) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let orphan = if name.starts_with("incoming-") {
            true
        } else if let Some(id) = name
            .strip_prefix("extent-")
            .and_then(|id| Uuid::parse_str(id).ok())
        {
            !db.query_row(
                "SELECT EXISTS(SELECT 1 FROM blobs WHERE id=?1 UNION ALL SELECT 1 FROM staged_blocks WHERE id=?1 UNION ALL SELECT 1 FROM blob_ranges WHERE extent=?1
                 UNION ALL SELECT 1 FROM dfs_staged WHERE extent=?1
                 UNION ALL SELECT 1 FROM history_ranges WHERE extent=?1
                 UNION ALL SELECT 1 FROM blob_history WHERE content_id=?1)",
                [id],
                |row| row.get::<_, bool>(0),
            )?
        } else {
            false
        };
        if orphan && entry.file_type()?.is_file() {
            let bytes = entry.metadata()?.len();
            fs::remove_file(entry.path())?;
            runtime_metrics::removed(Removal::Recovered, bytes);
        }
    }
    Ok(())
}
