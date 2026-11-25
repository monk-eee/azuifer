use super::{BLOB_COLUMNS, Store, blob_row, containers::require_container, db_error};
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
) -> Result<Vec<(String, crate::domain::BlobInfo)>> {
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
                let committed: i64 = row.get(22)?;
                let mut info = blob_row(row, now)?.info;
                info.uncommitted = committed == 0;
                Ok((row.get(21)?, info))
            },
        )
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)
}

/// Committed blobs, plus (when requested) names that exist only as staged blocks.
fn listing_sql(uncommitted: bool) -> String {
    let committed = format!(
        "SELECT {BLOB_COLUMNS}, name, 1 FROM blobs
         WHERE account=?1 AND container=?2 AND name>?3 AND instr(name, ?4)=1"
    );
    if !uncommitted {
        return format!("{committed} ORDER BY name LIMIT ?5");
    }
    format!(
        "{committed} UNION ALL
         SELECT randomblob(16), 0, randomblob(16), 0, 0, 'application/octet-stream', '', '', '', '', '',
                '{{}}', '', 0, NULL, 0, 0, 0, '', '', 0, name, 0
         FROM staged_blocks s
         WHERE account=?1 AND container=?2 AND name>?3 AND instr(name, ?4)=1
           AND NOT EXISTS (SELECT 1 FROM blobs b
                           WHERE b.account=s.account AND b.container=s.container AND b.name=s.name)
         GROUP BY name
         ORDER BY name LIMIT ?5"
    )
}

impl Store {
    pub(crate) async fn list_blobs(
        &self,
        key: crate::domain::ContainerKey,
        request: ListRequest,
        lease: Option<LeaseId>,
    ) -> Result<BlobListing> {
        self.run(move |db, _, now| {
            let container = require_container(db, &key, now)?;
            container
                .lease
                .check(lease, LeaseNeed::Optional, LeaseOwner::Container, now)?;
            let sql = listing_sql(request.include.contains(&Include::Uncommitted));
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
                for (name, info) in rows {
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
                    entries.push((ListEntry::Blob(name.clone(), Box::new(info)), name));
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
            Ok(BlobListing {
                entries: entries.into_iter().map(|(entry, _)| entry).collect(),
                next,
            })
        })
        .await
    }
}
