# ADR-0015: Map mutable ranges over immutable extents

- **Status:** Proposed

## Context

Page blobs, append blobs, Azure Files, and DFS append/flush all modify parts of an object. [ADR-0004](0004-commit-durable-content-references.md) publishes immutable extents by reference so a crash never leaves committed metadata pointing at partial bytes. In-place writes would break that guarantee, and Azure exposes allocated ranges through listing operations.

## Decision and scope

Represent range-addressable content as a metadata range map from object offset to `(extent, extent offset, length)`. Each range write streams into a new immutable extent, makes it durable, then commits the map change and the new ETag in one metadata transaction. Clearing a range removes it from the map without writing zeros. Reads assemble bytes from the map and return zeros for unmapped offsets. Resize adjusts the logical length and trims or extends the map. Append writes add a range at the current end, and DFS append stays unpublished until flush commits the length. Range listings (`Get Page Ranges`, `List Ranges`) and diffs are derived from the map. Extents no longer referenced by any live map, snapshot, or version become collectable. Compaction of fragmented ranges is not part of the first implementation.

This applies to page blobs, append blobs, FileREST files, and DFS files. Block blobs keep their block-list model from ADR-0004.

## Alternatives and consequences

Sparse files with in-place writes are simple but make partial writes visible after a crash and complicate snapshots. Rewriting the whole object per write is correct but costly for large page blobs and files. The map keeps crash behavior and snapshots simple at the cost of fragmentation and a bounded number of ranges per object.

## Verification criteria

- Overlapping, adjacent, and cleared range writes read back exactly and report correct allocated ranges.
- Interrupting a range write before or after extent durability leaves the prior content or the full new range, never a partial write.
- A snapshot taken before a range write still returns its original bytes after later writes and clears.
- A large sparse object does not allocate bytes for unwritten ranges.
