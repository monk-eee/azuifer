//! Blob index tags in their own indexed table (ADR-0019), so Find Blobs by Tags
//! and `x-ms-if-tags` never touch content rows.

use super::{BlobRow, Store, blob, blob_params, container, db_error, require_blob, snapshots};
use crate::{
    blob_tags::{TagFilter, Tags, Term},
    conditions::Guard,
    domain::{BlobKey, ContainerKey, Error, Page, PageRequest, Result},
    lease::{LeaseNeed, LeaseOwner},
    stamp::Ticks,
};
use rusqlite::{Connection, params, params_from_iter, types::Value};

/// A blob that matched a Find Blobs by Tags filter.
pub(crate) struct TaggedBlob {
    pub(crate) container: String,
    pub(crate) name: String,
    pub(crate) tags: Tags,
}

pub(super) fn load(db: &Connection, key: &BlobKey, state: i64) -> Result<Tags> {
    load_named(db, blob_params(key), state)
}

pub(super) fn load_named(
    db: &Connection,
    [account, container, name]: [&str; 3],
    state: i64,
) -> Result<Tags> {
    let mut query = db
        .prepare(
            "SELECT key, value FROM blob_tags
             WHERE account=?1 AND container=?2 AND name=?3 AND state=?4",
        )
        .map_err(db_error)?;
    query
        .query_map(params![account, container, name, state], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)
}

/// Replaces the tags of the current blob (state 0) or of one version.
pub(super) fn replace(db: &Connection, key: &BlobKey, state: i64, tags: &Tags) -> Result<()> {
    let [account, container, name] = blob_params(key);
    db.execute(
        "DELETE FROM blob_tags WHERE account=?1 AND container=?2 AND name=?3 AND state=?4",
        params![account, container, name, state],
    )
    .map_err(db_error)?;
    let mut insert = db
        .prepare("INSERT INTO blob_tags VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
        .map_err(db_error)?;
    for (tag, value) in tags {
        insert
            .execute(params![account, container, name, state, tag, value])
            .map_err(db_error)?;
    }
    Ok(())
}

pub(super) fn attach(db: &Connection, key: &BlobKey, mut row: BlobRow) -> Result<BlobRow> {
    row.info.tags = load(db, key, 0)?;
    Ok(row)
}

/// The blob or retained version whose tags an operation addresses, with its tag state.
fn target(
    db: &Connection,
    key: &BlobKey,
    version: Option<Ticks>,
    now: i64,
) -> Result<(i64, BlobRow)> {
    let Some(version) = version else {
        return Ok((0, require_blob(db, key, now)?));
    };
    match blob(db, key, now)? {
        Some(row) if row.info.entity.version == Some(version) => Ok((0, row)),
        _ => {
            let kept = snapshots::find_version(db, key, version, now)?;
            let mut row = kept.ok_or(Error::BlobMissing)?;
            row.info.tags = load(db, key, version.0)?;
            Ok((version.0, row))
        }
    }
}

impl Store {
    pub(crate) async fn set_blob_tags(
        &self,
        key: BlobKey,
        version: Option<Ticks>,
        tags: Tags,
        guard: Guard,
    ) -> Result<()> {
        self.run(move |db, _, now| {
            let tx = db.transaction().map_err(db_error)?;
            container(&tx, &key.container)?;
            let (state, row) = target(&tx, &key, version, now)?;
            row.lease
                .check(guard.lease, LeaseNeed::Optional, LeaseOwner::Blob, now)?;
            guard.conditions.check_tags(Some(&row.info.tags))?;
            replace(&tx, &key, state, &tags)?;
            tx.commit().map_err(db_error)
        })
        .await
    }

    pub(crate) async fn blob_tags(
        &self,
        key: BlobKey,
        version: Option<Ticks>,
        guard: Guard,
    ) -> Result<Tags> {
        self.run(move |db, _, now| {
            container(db, &key.container)?;
            let (_, row) = target(db, &key, version, now)?;
            row.lease
                .check(guard.lease, LeaseNeed::Optional, LeaseOwner::Blob, now)?;
            guard.conditions.check_tags(Some(&row.info.tags))?;
            Ok(row.info.tags)
        })
        .await
    }

    /// Find Blobs by Tags over an account, or one container. The marker is
    /// `container/blob` of the last result, so pages follow container then blob name.
    pub(crate) async fn find_blobs_by_tags(
        &self,
        account: crate::domain::AccountName,
        scope: Option<ContainerKey>,
        filter: TagFilter,
        page: PageRequest,
    ) -> Result<Page<TaggedBlob>> {
        self.run(move |db, _, _| {
            if let Some(scope) = &scope {
                container(db, scope)?;
            }
            let mut sql = String::from(
                "SELECT b.container, b.name FROM blobs b WHERE b.account=? AND instr(b.container, '~')=0",
            );
            let mut values: Vec<Value> = vec![account.as_str().to_owned().into()];
            if let Some(scope) = &scope {
                sql.push_str(" AND b.container=?");
                values.push(scope.name.as_str().to_owned().into());
            }
            if let Some((container, name)) = page.after.split_once('/') {
                sql.push_str(" AND (b.container, b.name) > (?, ?)");
                values.push(container.to_owned().into());
                values.push(name.to_owned().into());
            }
            for term in &filter.terms {
                match term {
                    Term::Container(name) => {
                        sql.push_str(" AND b.container=?");
                        values.push(name.clone().into());
                    }
                    Term::Tag { key, op, value } => {
                        sql.push_str(&format!(
                            " AND EXISTS (SELECT 1 FROM blob_tags t WHERE t.account=b.account \
                             AND t.container=b.container AND t.name=b.name AND t.state=0 \
                             AND t.key=? AND t.value {} ?)",
                            op.sql()
                        ));
                        values.push(key.clone().into());
                        values.push(value.clone().into());
                    }
                }
            }
            sql.push_str(" ORDER BY b.container, b.name LIMIT ?");
            values.push(i64::from(page.limit + 1).into());
            let mut query = db.prepare(&sql).map_err(db_error)?;
            let found: Vec<(String, String)> = query
                .query_map(params_from_iter(values), |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(db_error)?
                .collect::<rusqlite::Result<_>>()
                .map_err(db_error)?;
            let mut items = Vec::with_capacity(found.len());
            for (container, name) in found {
                let tags = load_named(db, [account.as_str(), &container, &name], 0)?;
                items.push((
                    format!("{container}/{name}"),
                    TaggedBlob {
                        container,
                        name,
                        tags,
                    },
                ));
            }
            Ok(Page::from_rows(items, page.limit))
        })
        .await
    }
}
