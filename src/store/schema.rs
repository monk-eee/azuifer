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

/// Version 4: page and append blobs (ADR-0015). `blob_type` is 0 block, 1 page, 2
/// append. `blob_ranges` maps blob offsets to immutable extents; `blob_extents`
/// holds the extent bytes of an in-memory instance.
const V4: &str = "
ALTER TABLE blobs ADD COLUMN blob_type INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blobs ADD COLUMN sequence_number INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blobs ADD COLUMN append_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blobs ADD COLUMN sealed INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS blob_ranges (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    offset INTEGER NOT NULL, length INTEGER NOT NULL,
    extent BLOB NOT NULL, extent_offset INTEGER NOT NULL,
    PRIMARY KEY (account, container, name, offset),
    FOREIGN KEY (account, container, name) REFERENCES blobs (account, container, name)
        ON DELETE CASCADE ON UPDATE CASCADE
) STRICT;
CREATE INDEX IF NOT EXISTS blob_ranges_extent ON blob_ranges (extent);
CREATE TABLE IF NOT EXISTS blob_extents (
    id BLOB NOT NULL PRIMARY KEY, length INTEGER NOT NULL, bytes BLOB NOT NULL
) STRICT;";

/// Version 3 (ADR-0018, ADR-0019): snapshots, versions, and soft-deleted blobs as
/// `blob_history` rows that reference the same immutable content as the current
/// blob; their committed block lists; blob index tags; and the accounts that
/// keep versions. `blobs.version_id` holds the current version's ticks (0: none).
/// `blob_history.kind` is 1 snapshot, 2 version, 3 soft-deleted blob; `state_id`
/// is the snapshot or version ticks (0 for a deleted blob); `deleted_at` and
/// `expires_at` (Unix milliseconds) mark a soft-deleted row until retention ends.
/// `blob_tags.state` is 0 for the current blob or a version's ticks.
const V3: &str = "
ALTER TABLE blobs ADD COLUMN version_id INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS blob_history (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    kind INTEGER NOT NULL, state_id INTEGER NOT NULL, content_id BLOB NOT NULL,
    modified INTEGER NOT NULL, etag BLOB NOT NULL, created INTEGER NOT NULL, length INTEGER NOT NULL,
    content_type TEXT NOT NULL, content_encoding TEXT NOT NULL, content_language TEXT NOT NULL,
    content_disposition TEXT NOT NULL, cache_control TEXT NOT NULL, md5 TEXT NOT NULL,
    metadata TEXT NOT NULL, access_tier TEXT NOT NULL, access_tier_changed INTEGER NOT NULL,
    copy_id TEXT NOT NULL, copy_source TEXT NOT NULL, copy_completed INTEGER NOT NULL,
    bytes BLOB, deleted_at INTEGER, expires_at INTEGER,
    PRIMARY KEY (account, container, name, kind, state_id),
    FOREIGN KEY (account, container) REFERENCES containers (account, name) ON DELETE CASCADE
) STRICT;
CREATE INDEX IF NOT EXISTS blob_history_content ON blob_history (content_id);
CREATE TABLE IF NOT EXISTS history_blocks (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    kind INTEGER NOT NULL, state_id INTEGER NOT NULL,
    position INTEGER NOT NULL, block_id TEXT NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL,
    PRIMARY KEY (account, container, name, kind, state_id, position),
    FOREIGN KEY (account, container, name, kind, state_id)
        REFERENCES blob_history (account, container, name, kind, state_id) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS blob_tags (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    state INTEGER NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (account, container, name, state, key),
    FOREIGN KEY (account, container) REFERENCES containers (account, name) ON DELETE CASCADE
) STRICT;
CREATE INDEX IF NOT EXISTS blob_tags_lookup ON blob_tags (account, key, value);
CREATE TABLE IF NOT EXISTS versioned_accounts (account TEXT NOT NULL PRIMARY KEY) STRICT;";

/// Version 6 (ADR-0015, ADR-0018, ADR-0019): page and append blobs in history,
/// per-blob lifecycle state, and soft-deleted containers. History rows gain the
/// blob type columns and `history_ranges` holds the range map of a snapshot,
/// version, or soft-deleted page or append blob over the same immutable extents
/// as the live blob. `blob_lifecycle` holds a blob's expiry and immutability
/// state in Unix milliseconds, plus the snapshots of an incremental copy blob.
/// `deleted_containers` records a soft-deleted container: its data stays in the
/// `containers` row named `hidden` until `expires_at` or a restore.
const V6: &str = "
ALTER TABLE blob_history ADD COLUMN blob_type INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blob_history ADD COLUMN sequence_number INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blob_history ADD COLUMN append_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blob_history ADD COLUMN sealed INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS history_ranges (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    kind INTEGER NOT NULL, state_id INTEGER NOT NULL,
    offset INTEGER NOT NULL, length INTEGER NOT NULL,
    extent BLOB NOT NULL, extent_offset INTEGER NOT NULL,
    PRIMARY KEY (account, container, name, kind, state_id, offset),
    FOREIGN KEY (account, container, name, kind, state_id)
        REFERENCES blob_history (account, container, name, kind, state_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX IF NOT EXISTS history_ranges_extent ON history_ranges (extent);
CREATE TABLE IF NOT EXISTS blob_lifecycle (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    expires_at INTEGER, immutable_until INTEGER,
    immutability_mode TEXT NOT NULL DEFAULT '', legal_hold INTEGER NOT NULL DEFAULT 0,
    incremental_source INTEGER, incremental_destination INTEGER,
    PRIMARY KEY (account, container, name),
    FOREIGN KEY (account, container, name) REFERENCES blobs (account, container, name)
        ON DELETE CASCADE ON UPDATE CASCADE
) STRICT;
CREATE INDEX IF NOT EXISTS blob_lifecycle_expiry ON blob_lifecycle (expires_at)
    WHERE expires_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS deleted_containers (
    account TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, hidden TEXT NOT NULL,
    deleted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    PRIMARY KEY (account, name, version)
) STRICT;";

/// Each migration is keyed by the `PRAGMA user_version` it leaves behind. Numbers
/// need not be consecutive: branches that add migrations in parallel reserve their
/// own number, and a database applies every migration above its version.
const MIGRATIONS: &[(i64, &str)] = &[
    (1, V1),
    (2, super::namespace::SCHEMA),
    (3, V3),
    (4, V4),
    (5, super::dfs_paths::SCHEMA),
    (6, V6),
];

pub(super) fn migrate(db: &mut Connection) -> rusqlite::Result<()> {
    db.execute_batch(BASE)?;
    let current: i64 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    for (version, migration) in MIGRATIONS.iter().filter(|(version, _)| *version > current) {
        let tx = db.transaction()?;
        tx.execute_batch(migration)?;
        tx.execute_batch(&format!("PRAGMA user_version = {version}"))?;
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
        assert_eq!(version, 6);
    }

    #[test]
    fn page_and_append_columns_and_tables_arrive_with_their_migration() {
        let mut db = Connection::open_in_memory().unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        db.execute_batch(BASE).unwrap();
        db.execute_batch(V1).unwrap();
        db.pragma_update(None, "user_version", 1).unwrap();
        db.execute_batch(
            "INSERT INTO containers (account, name, id, modified) VALUES ('acct', 'box', x'01', 5);
             INSERT INTO blobs (account, container, name, id, modified, length, content_type, md5, metadata)
             VALUES ('acct', 'box', 'a', x'02', 7, 3, 'text/plain', '', '{}');",
        )
        .unwrap();
        migrate(&mut db).unwrap();
        db.execute_batch("INSERT INTO blob_ranges VALUES ('acct', 'box', 'a', 0, 3, x'0a', 0);")
            .unwrap();
        let (kind, sequence, count, sealed): (i64, i64, i64, i64) = db
            .query_row(
                "SELECT blob_type, sequence_number, append_count, sealed FROM blobs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!((kind, sequence, count, sealed), (0, 0, 0, 0));
        db.execute("DELETE FROM blobs", []).unwrap();
        let ranges: i64 = db
            .query_row("SELECT COUNT(*) FROM blob_ranges", [], |row| row.get(0))
            .unwrap();
        assert_eq!(ranges, 0, "deleting a blob drops its ranges");
    }

    #[test]
    fn snapshot_history_tags_and_versioned_accounts_arrive_with_their_migration() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch(BASE).unwrap();
        db.execute_batch(V1).unwrap();
        db.pragma_update(None, "user_version", 1).unwrap();
        db.execute_batch(
            "INSERT INTO containers (account, name, id, modified) VALUES ('acct', 'box', x'01', 5);
             INSERT INTO blobs (account, container, name, id, modified, length, content_type, md5, metadata)
             VALUES ('acct', 'box', 'a', x'02', 7, 3, 'text/plain', '', '{}');",
        )
        .unwrap();
        migrate(&mut db).unwrap();
        db.execute_batch(
            "INSERT INTO versioned_accounts VALUES ('acct');
             INSERT INTO blob_tags VALUES ('acct', 'box', 'a', 0, 'k', 'v');",
        )
        .unwrap();
        let (version_id, history): (i64, i64) = db
            .query_row(
                "SELECT (SELECT version_id FROM blobs), (SELECT COUNT(*) FROM blob_history)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((version_id, history), (0, 0));
    }

    #[test]
    fn page_history_lifecycle_and_deleted_container_tables_arrive_with_their_migration() {
        let mut db = Connection::open_in_memory().unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        db.execute_batch(BASE).unwrap();
        db.execute_batch(V1).unwrap();
        db.pragma_update(None, "user_version", 1).unwrap();
        db.execute_batch(
            "INSERT INTO containers (account, name, id, modified) VALUES ('acct', 'box', x'01', 5);
             INSERT INTO blobs (account, container, name, id, modified, length, content_type, md5, metadata)
             VALUES ('acct', 'box', 'a', x'02', 7, 3, 'text/plain', '', '{}');",
        )
        .unwrap();
        migrate(&mut db).unwrap();
        db.execute_batch(
            "INSERT INTO blob_lifecycle (account, container, name, expires_at, legal_hold)
             VALUES ('acct', 'box', 'a', 99, 1);
             INSERT INTO blob_history
               (account, container, name, kind, state_id, content_id, modified, etag, created, length,
                content_type, content_encoding, content_language, content_disposition, cache_control,
                md5, metadata, access_tier, access_tier_changed, copy_id, copy_source, copy_completed,
                blob_type)
             VALUES ('acct', 'box', 'a', 1, 5, x'02', 7, x'02', 7, 3, '', '', '', '', '', '', '{}',
                '', 0, '', '', 0, 1);
             INSERT INTO history_ranges VALUES ('acct', 'box', 'a', 1, 5, 0, 3, x'0a', 0);
             INSERT INTO deleted_containers VALUES ('acct', 'old', '01D', 'deleted~01D~old', 5, 9);",
        )
        .unwrap();
        let count = |sql: &str| -> i64 { db.query_row(sql, [], |row| row.get(0)).unwrap() };
        assert_eq!(count("SELECT blob_type FROM blob_history"), 1);
        assert_eq!(count("SELECT COUNT(*) FROM history_ranges"), 1);
        db.execute("DELETE FROM blob_history", []).unwrap();
        assert_eq!(
            count("SELECT COUNT(*) FROM history_ranges"),
            0,
            "deleting a history row drops its ranges"
        );
        db.execute("DELETE FROM blobs", []).unwrap();
        assert_eq!(
            count("SELECT COUNT(*) FROM blob_lifecycle"),
            0,
            "deleting a blob drops its lifecycle row"
        );
    }

    #[test]
    fn a_migration_applies_after_a_gap_in_the_numbering() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch(BASE).unwrap();
        db.execute_batch(V1).unwrap();
        db.execute_batch(super::super::namespace::SCHEMA).unwrap();
        db.execute_batch("PRAGMA user_version = 2").unwrap();
        migrate(&mut db).unwrap();
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 6);
    }
}
