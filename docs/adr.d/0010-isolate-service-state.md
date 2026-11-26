# ADR-0010: Isolate service state and share only Blob with DFS

- **Status:** Proposed

## Context

[ADR-0003](0003-share-the-blob-and-dfs-namespace.md) requires Blob and DFS to share one namespace. Queue, Table, and FileREST have unrelated data models, and a bug or migration in one must not corrupt another. The current Blob store owns the storage directory, its lock, and its SQLite file.

## Decision and scope

Blob and DFS keep sharing the existing store at the storage root. Queue, Table, and FileREST each open their own store in `<location>/queue`, `<location>/table`, and `<location>/file`, each with its own SQLite WAL database, schema version, exclusive directory lock, and (for FileREST) content-extent directory following [ADR-0004](0004-commit-durable-content-references.md). Startup recovery for one store never scans or deletes another store's files. `--in-memory` gives each store its own in-memory database; `--memory-limit` applies separately to each service that holds payload bytes (Blob and FileREST). Queue and Table message and entity sizes are bounded by their protocol limits instead.

There are no cross-service transactions. Only the Blob/DFS pair needs one, and it already shares a connection.

## Alternatives and consequences

A single database for everything allows cross-service transactions nobody needs and couples schema migrations. Separate processes per store lose the one-binary goal. Isolated stores multiply open files and WAL checkpoints, and mean one backup is a directory tree rather than a file.

## Verification criteria

- Persistent runs create only the documented subdirectories and the Blob root files.
- Corrupting or removing one service directory leaves the other services starting and serving their data.
- Blob recovery leaves Queue, Table, and File subdirectories untouched.
- Each service rejects a second process on its own directory with a clear error.
