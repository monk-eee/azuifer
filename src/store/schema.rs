//! Metadata schema and its forward-only migrations.
//!
//! The first release created `BASE`. Each later release raises `PRAGMA user_version`
//! after adding columns with defaults, so an existing data directory keeps opening.

use rusqlite::Connection;

const BASE: &str = "
CREATE TABLE IF NOT EXISTS containers (
    account TEXT NOT NULL, name TEXT NOT NULL, id BLOB NOT NULL, modified INTEGER NOT NULL,
    PRIMARY KEY (account, name)
) STRICT;
CREATE TABLE IF NOT EXISTS blobs (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    id BLOB NOT NULL UNIQUE, modified INTEGER NOT NULL, length INTEGER NOT NULL,
    content_type TEXT NOT NULL, md5 TEXT NOT NULL, metadata TEXT NOT NULL, bytes BLOB,
    PRIMARY KEY (account, container, name),
    FOREIGN KEY (account, container) REFERENCES containers (account, name) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS staged_blocks (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    block_id TEXT NOT NULL, width INTEGER NOT NULL,
    id BLOB NOT NULL UNIQUE, length INTEGER NOT NULL, bytes BLOB,
    PRIMARY KEY (account, container, name, block_id),
    FOREIGN KEY (account, container) REFERENCES containers (account, name) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS committed_blocks (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    position INTEGER NOT NULL, block_id TEXT NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL,
    PRIMARY KEY (account, container, name, position),
    FOREIGN KEY (account, container, name) REFERENCES blobs (account, container, name) ON DELETE CASCADE
) STRICT;";

/// Version 1: Blob properties, leases, container metadata and ACLs, copy state,
/// access tiers, and the per-account service settings row (ADR-0017, ADR-0019).
/// Lease columns hold the id, kind (0 none, 1 leased, 2 breaking), duration in
/// seconds (-1 infinite), and the expiry or break deadline in Unix milliseconds.
const V1: &str = "
ALTER TABLE containers ADD COLUMN etag BLOB;
ALTER TABLE containers ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}';
ALTER TABLE containers ADD COLUMN public_access TEXT NOT NULL DEFAULT '';
ALTER TABLE containers ADD COLUMN acl TEXT NOT NULL DEFAULT '[]';
ALTER TABLE containers ADD COLUMN lease_id TEXT;
ALTER TABLE containers ADD COLUMN lease_state INTEGER NOT NULL DEFAULT 0;
ALTER TABLE containers ADD COLUMN lease_duration INTEGER NOT NULL DEFAULT 0;
ALTER TABLE containers ADD COLUMN lease_expiry INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blobs ADD COLUMN etag BLOB;
ALTER TABLE blobs ADD COLUMN created INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blobs ADD COLUMN content_encoding TEXT NOT NULL DEFAULT '';
ALTER TABLE blobs ADD COLUMN content_language TEXT NOT NULL DEFAULT '';
ALTER TABLE blobs ADD COLUMN content_disposition TEXT NOT NULL DEFAULT '';
ALTER TABLE blobs ADD COLUMN cache_control TEXT NOT NULL DEFAULT '';
ALTER TABLE blobs ADD COLUMN access_tier TEXT NOT NULL DEFAULT '';
ALTER TABLE blobs ADD COLUMN access_tier_changed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blobs ADD COLUMN lease_id TEXT;
ALTER TABLE blobs ADD COLUMN lease_state INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blobs ADD COLUMN lease_duration INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blobs ADD COLUMN lease_expiry INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blobs ADD COLUMN copy_id TEXT NOT NULL DEFAULT '';
ALTER TABLE blobs ADD COLUMN copy_source TEXT NOT NULL DEFAULT '';
ALTER TABLE blobs ADD COLUMN copy_completed INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS account_settings (
    account TEXT NOT NULL PRIMARY KEY, service_properties TEXT NOT NULL
) STRICT;";

const MIGRATIONS: [&str; 1] = [V1];

pub(super) fn migrate(db: &mut Connection) -> rusqlite::Result<()> {
    db.execute_batch(BASE)?;
    let current: i64 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let applied = usize::try_from(current).unwrap_or(0);
    for (index, migration) in MIGRATIONS.iter().enumerate().skip(applied) {
        let tx = db.transaction()?;
        tx.execute_batch(migration)?;
        tx.execute_batch(&format!("PRAGMA user_version = {}", index + 1))?;
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_database_from_the_previous_schema_gains_defaults() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch(BASE).unwrap();
        db.execute_batch(
            "INSERT INTO containers VALUES ('acct', 'box', x'01', 5);
             INSERT INTO blobs VALUES ('acct', 'box', 'a', x'02', 7, 3, 'text/plain', '', '{}', NULL);",
        )
        .unwrap();
        migrate(&mut db).unwrap();
        migrate(&mut db).unwrap();
        let (state, tier, created, public): (i64, String, i64, String) = db
            .query_row(
                "SELECT b.lease_state, b.access_tier, b.created, c.public_access
                 FROM blobs b JOIN containers c ON b.container = c.name",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            (state, tier.as_str(), created, public.as_str()),
            (0, "", 0, "")
        );
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
    }
}
