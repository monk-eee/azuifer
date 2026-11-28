# ADR-0034: Refuse newer schemas and linked storage in every persistent store

- **Status:** Proposed

## Context

Blob and DFS, Files, Queue, and Table each keep their metadata in SQLite and had grown their own startup checks. Queue and Table refused a database whose `PRAGMA user_version` was newer than the build. The Blob and DFS migration ignored it and returned success, and the Files store never stamped one, so an older release opened a newer database and could migrate or write it wrongly. The checks that a directory, lock file, database, write-ahead log, and shared-memory file are not links existed three times with the same text, and Queue had none, so a link there decided where Queue metadata landed.

## Decision and scope

One module, `src/store/guard.rs`, holds the checks, and every store calls it.

- **Schema.** A store reads `user_version` before it changes anything and fails startup when it is newer than the build supports, naming both numbers. It stamps its version only after that check passes, so a refused open leaves the database as it was. Files now stamps version 1; a database written before it did reads as 0 and is upgraded as before. A newer database is not downgraded, and returns to service when it is opened by a release that knows it.
- **Paths.** Each store requires its directory, lock file, database, `-wal`, `-shm`, and content directory to be what they should be, and the error names the path. A link, including a Windows junction, is refused.
- **Doctor.** `azuifer doctor` runs the same checks on each store directory that exists, opens each database read-only, and runs `PRAGMA quick_check`, so a link, a newer schema, or corruption is reported with its path before a server is started. Startup does not run the integrity check, to keep it fast.

## Alternatives and consequences

Checking the schema only at the moment of migration would keep each store's code simpler but leaves the Files case, which has no migration number. Running `quick_check` on every start would catch truncation sooner but costs time proportional to the data. A truncated database already fails startup in the cases tested, because SQLite reports the missing pages when the store reads its schema.

A data directory that deliberately uses a link now fails to start. Use the target path as `--location`.

## Verification criteria

- Opening a database with a future `user_version` fails startup for each store, with a message naming the schema, and leaves `user_version` unchanged.
- A database from the first release opens, keeps its data, and is stamped.
- A corrupt or truncated database stops startup with an error and no panic.
- A link in place of a directory, lock, database, or content directory stops startup and names it.
- `azuifer doctor` reports each of these for the store that has it.