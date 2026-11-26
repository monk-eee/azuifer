use super::{
    BLOB_COLUMN_COUNT, BLOB_COLUMNS, Store, blob_row, containers::require_container, db_error,
    entity_row,
};
use crate::{
    domain::{BlobListing, Include, ListEntry, ListRequest, Result},
    lease::{LeaseId, LeaseNeed, LeaseOwner},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, params};

/// Sorts after every name that starts with a collapsed prefix, so a scan can skip it.
const AFTER_PREFIX: char = '\u{10FFFF}';

fn query(
    sql: &str,
    db: &Connection,
    arguments: &[&str],
    limit: usize,
    now: i64,
) -> Result<Vec<ListEntry>> {
    let mut statement = db.prepare(sql).map_err(db_error)?;
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    statement
        .query_map(
            params![
                arguments[0],
                arguments[1],
                arguments[2],
                arguments[3],
                limit
            ],
            |row| {
                let kind: i64 = row.get(BLOB_COLUMN_COUNT + 1)?;
                let name = row.get(BLOB_COLUMN_COUNT)?;
                if kind == 2 {
                    Ok(ListEntry::Directory(name, entity_row(row)?))
                } else {
                    let mut info = blob_row(row, now)?.info;
                    info.uncommitted = kind == 0;
                    Ok(ListEntry::Blob(name, Box::new(info)))
                }
            },
        )
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)
}

/// Committed blobs, plus (when requested) names that exist only as staged blocks.
fn listing_sql(uncommitted: bool, directories: bool) -> String {
    let mut sql = format!(
        "SELECT {BLOB_COLUMNS}, name, 1 FROM blobs
         WHERE account=?1 AND container=?2 AND name>?3 AND instr(name, ?4)=1"
    );
    if directories {
        sql.push_str(
            " UNION ALL SELECT id, modified, etag, modified, 0, '', '', '', '', '', '', '{}', '',
                       0, NULL, 0, 0, 0, '', '', 0, 0, 0, 0, 0, name, 2
              FROM directories WHERE account=?1 AND container=?2 AND name>?3 AND instr(name, ?4)=1",
        );
    }
    if uncommitted {
        sql.push_str(
            " UNION ALL
         SELECT randomblob(16), 0, randomblob(16), 0, 0, 'application/octet-stream', '', '', '', '', '',
                '{}', '', 0, NULL, 0, 0, 0, '', '', 0, 0, 0, 0, 0, name, 0
         FROM staged_blocks s
         WHERE account=?1 AND container=?2 AND name>?3 AND instr(name, ?4)=1
           AND NOT EXISTS (SELECT 1 FROM blobs b
                           WHERE b.account=s.account AND b.container=s.container AND b.name=s.name)",
        );
        if directories {
            sql.push_str(
                " AND NOT EXISTS (SELECT 1 FROM directories d
                                  WHERE d.account=s.account AND d.container=s.container AND d.name=s.name)",
            );
        }
        sql.push_str(" GROUP BY name");
    }
    sql.push_str(" ORDER BY name LIMIT ?5");
    sql
}

impl Store {
    pub(crate) async fn list_blobs(
        &self,
        key: crate::domain::ContainerKey,
        request: ListRequest,
        lease: Option<LeaseId>,
    ) -> Result<BlobListing> {
        let directories = self.hierarchical(&key) && request.delimiter.is_none();
        self.run(move |db, _, now| {
            let container = require_container(db, &key, now)?;
            container
                .lease
                .check(lease, LeaseNeed::Optional, LeaseOwner::Container, now)?;
            let sql = listing_sql(request.include.contains(&Include::Uncommitted), directories);
            let limit = request.page.limit as usize;
            let prefix = request.page.prefix.as_str();
            let mut cursor = request.page.after.clone();
            // Each entry carries the marker that resumes the scan just after it.
            let mut entries: Vec<(ListEntry, String)> = Vec::new();
            'scan: loop {
                let arguments = [
                    key.account.as_str(),
                    key.name.as_str(),
                    cursor.as_str(),
                    prefix,
                ];
                let rows = query(&sql, db, &arguments, limit + 1, now)?;
                let fetched = rows.len();
                for entry in rows {
                    let name = match &entry {
                        ListEntry::Blob(name, _)
                        | ListEntry::Directory(name, _)
                        | ListEntry::Prefix(name) => name,
                    };
                    let collapsed = request.delimiter.as_deref().and_then(|delimiter| {
                        let rest = name.get(prefix.len()..)?;
                        let end = prefix.len() + rest.find(delimiter)? + delimiter.len();
                        name.get(..end).map(str::to_owned)
                    });
                    if let Some(collapsed) = collapsed {
                        cursor = format!("{collapsed}{AFTER_PREFIX}");
                        entries.push((ListEntry::Prefix(collapsed), cursor.clone()));
                        if entries.len() > limit {
                            break 'scan;
                        }
                        continue 'scan;
                    }
                    cursor = name.clone();
                    entries.push((entry, cursor.clone()));
                    if entries.len() > limit {
                        break 'scan;
                    }
                }
                if fetched <= limit {
                    break;
                }
            }
            let next = if entries.len() > limit {
                entries.truncate(limit);
                entries
                    .last()
                    .map_or_else(String::new, |(_, marker)| URL_SAFE_NO_PAD.encode(marker))
            } else {
                String::new()
            };
            let lifecycle =
                super::expiry::load_container(db, key.account.as_str(), key.name.as_str())?;
            let mut entries: Vec<ListEntry> = entries.into_iter().map(|(entry, _)| entry).collect();
            for entry in &mut entries {
                if let ListEntry::Blob(name, info) = entry
                    && let Some(found) = lifecycle.get(name.as_str())
                {
                    info.lifecycle = *found;
                }
            }
            Ok(BlobListing { entries, next })
        })
        .await
    }
}
