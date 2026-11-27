//! Listings that include snapshots, versions, deleted blobs and tags, with resumable markers.

use super::{DAY_MS, HISTORY_BLOB};
use crate::{
    blob_tags::Tags,
    domain::{BlobInfo, Include, ListRequest, Result},
    lease::{LeaseNeed, LeaseOwner},
    stamp::Ticks,
    store::{BLOB_COLUMN_COUNT, BLOB_COLUMNS, Store, blob_row, db_error, tags},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::params;

/// One entry of a listing that includes snapshots, versions, deleted blobs, or tags.
pub(crate) struct ListedBlob {
    pub(crate) name: String,
    pub(crate) info: BlobInfo,
    pub(crate) snapshot: Option<Ticks>,
    pub(crate) version: Option<Ticks>,
    pub(crate) current_version: bool,
    pub(crate) deleted: Option<DeletedInfo>,
    pub(crate) tags: Tags,
}

pub(crate) struct DeletedInfo {
    pub(crate) at: u64,
    pub(crate) remaining_days: u64,
}

pub(crate) enum Listed {
    Blob(Box<ListedBlob>),
    Prefix(String),
}

pub(crate) struct ExtendedListing {
    pub(crate) entries: Vec<Listed>,
    pub(crate) next: String,
}

/// Where a listing resumes: after a whole name, or after one entry of a name.
enum Cursor {
    Start,
    Name(String),
    Entry(String, i64, i64),
}

const MARKER: &str = "~v1:";
const AFTER_PREFIX: char = '\u{10FFFF}';

impl Cursor {
    fn parse(after: &str) -> Self {
        if after.is_empty() {
            return Self::Start;
        }
        let parsed = after.strip_prefix(MARKER).and_then(|rest| {
            let mut parts = rest.splitn(3, ':');
            let sort = parts.next()?.parse().ok()?;
            let kind = parts.next()?.parse().ok()?;
            Some(Self::Entry(parts.next()?.to_owned(), sort, kind))
        });
        parsed.unwrap_or_else(|| Self::Name(after.to_owned()))
    }

    fn name(&self) -> &str {
        match self {
            Self::Start => "",
            Self::Name(name) | Self::Entry(name, ..) => name,
        }
    }

    fn allows(&self, name: &str, sort: i64, kind: i64) -> bool {
        match self {
            Self::Start => true,
            Self::Name(after) => name > after.as_str(),
            Self::Entry(after, after_sort, after_kind) => {
                (name, sort, kind) > (after.as_str(), *after_sort, *after_kind)
            }
        }
    }
}

fn marker(name: &str, sort: i64, kind: i64) -> String {
    URL_SAFE_NO_PAD.encode(format!("{MARKER}{sort}:{kind}:{name}"))
}

impl Store {
    /// List Blobs with `include` values beyond the plain listing's. Within a
    /// name, snapshots and versions come oldest first and the current blob last.
    pub(crate) async fn list_extended(
        &self,
        key: crate::domain::ContainerKey,
        request: ListRequest,
        lease: Option<crate::lease::LeaseId>,
    ) -> Result<ExtendedListing> {
        self.run(move |db, _, now| {
            let owner = crate::store::containers::require_container(db, &key, now)?;
            owner
                .lease
                .check(lease, LeaseNeed::Optional, LeaseOwner::Container, now)?;
            let has = |include| request.include.contains(&include);
            let (snapshots, versions, deleted, with_tags) = (
                has(Include::Snapshots),
                has(Include::Versions),
                has(Include::Deleted),
                has(Include::Tags),
            );
            let limit = request.page.limit as usize;
            let prefix = request.page.prefix.as_str();
            let cursor = Cursor::parse(&request.page.after);
            let lifecycle =
                crate::store::expiry::load_container(db, key.account.as_str(), key.name.as_str())?;
            let sql = format!(
                "SELECT {BLOB_COLUMNS}, name, 0, 9223372036854775807, version_id, NULL, NULL
                   FROM blobs WHERE account=?1 AND container=?2 AND name>=?3 AND instr(name, ?4)=1
                 UNION ALL
                 SELECT {HISTORY_BLOB}, name, kind,
                        CASE WHEN kind=3 THEN deleted_at * 10000 ELSE state_id END,
                        state_id, deleted_at, expires_at
                   FROM blob_history WHERE account=?1 AND container=?2 AND name>=?3
                    AND instr(name, ?4)=1 AND (deleted_at IS NULL OR expires_at > ?5)
                 ORDER BY {}, {}, {}",
                BLOB_COLUMN_COUNT + 1,
                BLOB_COLUMN_COUNT + 3,
                BLOB_COLUMN_COUNT + 2
            );
            let mut statement = db.prepare(&sql).map_err(db_error)?;
            let mut rows = statement
                .query(params![
                    key.account.as_str(),
                    key.name.as_str(),
                    cursor.name(),
                    prefix,
                    now
                ])
                .map_err(db_error)?;
            let mut entries: Vec<(Listed, String)> = Vec::new();
            let mut collapsed: Option<String> = None;
            while let Some(row) = rows.next().map_err(db_error)? {
                let at = BLOB_COLUMN_COUNT;
                let name: String = row.get(at).map_err(db_error)?;
                let kind: i64 = row.get(at + 1).map_err(db_error)?;
                let sort: i64 = row.get(at + 2).map_err(db_error)?;
                if !cursor.allows(&name, sort, kind)
                    || collapsed.as_deref().is_some_and(|p| name.starts_with(p))
                {
                    continue;
                }
                let state: i64 = row.get(at + 3).map_err(db_error)?;
                let tombstone: Option<i64> = row.get(at + 4).map_err(db_error)?;
                let expires: Option<i64> = row.get(at + 5).map_err(db_error)?;
                let shown = match (kind, tombstone) {
                    (0, _) => true,
                    (1, None) => snapshots,
                    (1, Some(_)) => deleted && snapshots,
                    (2, None) => versions,
                    (2, Some(_)) => deleted && versions,
                    (3, _) => deleted,
                    _ => false,
                };
                if !shown {
                    continue;
                }
                if let Some(delimiter) = request.delimiter.as_deref()
                    && let Some(rest) = name.get(prefix.len()..)
                    && let Some(at) = rest.find(delimiter)
                {
                    let end = prefix.len() + at + delimiter.len();
                    let group = name[..end].to_owned();
                    let next = marker(&format!("{group}{AFTER_PREFIX}"), i64::MAX, 9);
                    entries.push((Listed::Prefix(group.clone()), next));
                    collapsed = Some(group);
                    if entries.len() > limit {
                        break;
                    }
                    continue;
                }
                let mut info = blob_row(row, now).map_err(db_error)?.info;
                if kind == 2 {
                    info.entity.version = Some(Ticks(state));
                }
                if kind == 0
                    && let Some(found) = lifecycle.get(&name)
                {
                    info.lifecycle = *found;
                }
                let current = kind == 0;
                let version = if current {
                    let id: i64 = row.get(at + 3).map_err(db_error)?;
                    (versions && id != 0).then_some(Ticks(id))
                } else {
                    (kind == 2).then_some(Ticks(state))
                };
                let tag_state = match kind {
                    0 => Some(0),
                    2 => Some(state),
                    _ => None,
                };
                let tags = match tag_state.filter(|_| with_tags) {
                    Some(tag_state) => tags::load_named(
                        db,
                        [key.account.as_str(), key.name.as_str(), &name],
                        tag_state,
                    )?,
                    None => Tags::new(),
                };
                let entry = ListedBlob {
                    snapshot: (kind == 1).then_some(Ticks(state)),
                    version,
                    current_version: current && version.is_some(),
                    deleted: tombstone.zip(expires).map(|(at, expires)| DeletedInfo {
                        at: u64::try_from(at / 1000).unwrap_or(0),
                        remaining_days: u64::try_from((expires - now + DAY_MS - 1) / DAY_MS)
                            .unwrap_or(0),
                    }),
                    tags,
                    info,
                    name: name.clone(),
                };
                entries.push((Listed::Blob(Box::new(entry)), marker(&name, sort, kind)));
                if entries.len() > limit {
                    break;
                }
            }
            let next = if entries.len() > limit {
                entries.truncate(limit);
                entries
                    .last()
                    .map_or_else(String::new, |(_, marker)| marker.clone())
            } else {
                String::new()
            };
            Ok(ExtendedListing {
                entries: entries.into_iter().map(|(entry, _)| entry).collect(),
                next,
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_resume_after_the_entry_they_name() {
        let encoded = marker("a:b", 5, 1);
        let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
        let cursor = Cursor::parse(&decoded);
        assert!(!cursor.allows("a:b", 5, 1));
        assert!(cursor.allows("a:b", 5, 2));
        assert!(cursor.allows("a:b", 6, 0));
        assert!(cursor.allows("a:c", 0, 0));
        assert!(!cursor.allows("a:a", 9, 9));
        assert!(matches!(Cursor::parse("plain/name"), Cursor::Name(_)));
        assert!(Cursor::parse("plain").allows("plainer", 0, 0));
        assert!(!Cursor::parse("plain").allows("plain", 0, 0));
    }
}
