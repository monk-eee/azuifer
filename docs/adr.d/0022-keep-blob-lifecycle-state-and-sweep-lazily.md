# ADR-0022: Keep blob lifecycle state beside the content and sweep it lazily on the clock

- **Status:** Proposed

## Context

Wave 3 adds blob expiry, immutability policies and legal holds, soft-deleted containers, and snapshots and versions of page and append blobs. Each is state that changes what a request may see or do at a later time, measured on the injected clock ([ADR-0012](0012-inject-time-through-one-clock.md)), and each must hold for every writer: Blob, DFS, and any later service on the shared namespace ([ADR-0003](0003-share-the-blob-and-dfs-namespace.md)).

## Decision and scope

Store per-blob lifecycle state (expiry, policy, hold, incremental-copy snapshots) in a `blob_lifecycle` table keyed like the blob and cascading with it. Load it with the blob so the central write and delete guards see it, instead of each operation querying it. Retain page and append blob history as range maps in `history_ranges` over the same immutable extents ([ADR-0015](0015-map-mutable-ranges-over-immutable-extents.md), [ADR-0018](0018-model-snapshots-versions-and-copy-as-immutable-references.md)); an extent is collectable only when no live or retained range row references it. Evaluate time lazily: before each metadata action the store removes blobs past their expiry and erases soft-deleted containers past their retention, so no operation sees an expired entry and no timer runs. Keep a soft-deleted container under a hidden name that no valid container name can take, renaming every table row that carries `account` and `container` in one transaction, so later tables follow without code changes. Reject a delete or a replacing write of a protected blob in `guard_write` and `guard_delete`, the functions every writer already calls.

## Alternatives and consequences

Columns on `blobs` would widen every blob query and listing union. A background timer would need its own clock handling and would race the test clock. Copying a deleted container's rows to separate tables would duplicate every schema change, and DFS tables would be missed. The cost is one indexed query per request for the sweep, one more per single-blob read for the lifecycle row, and a rename that touches every row of a deleted container.

## Verification criteria

- A blob past its expiry is absent from reads, listings, and DFS at the same clock time, and its extents are freed.
- A protected blob refuses writes and deletes with Azure's error codes through every writer, and a versioned account keeps the protected state as a version.
- A snapshot of a page or append blob keeps its bytes across later writes, deletes, container deletion, and restart, and its extents are freed after the last reference goes.
- A soft-deleted container restores under another name with its blobs, snapshots, and tags, and its data is erased once retention ends.
