# ADR-0018: Model snapshots, versions, and copy as immutable references

- **Status:** Proposed

## Context

Blob snapshots, blob versions, and copy all produce another readable object from existing content. The extent store ([ADR-0004](0004-commit-durable-content-references.md)) keeps bytes immutable, so these features can share bytes instead of copying them. Garbage collection must then understand every reference.

## Decision and scope

Make an object's content a set of references (an extent list or a range map from [ADR-0015](0015-map-mutable-ranges-over-immutable-extents.md)) plus metadata. A snapshot copies the metadata and references into a new row identified by a timestamp snapshot id. When account versioning is enabled, each overwrite retires the previous state into a version row with a version id. Same-instance copy duplicates references, and Copy Blob completes immediately with `x-ms-copy-status: success` and a copy id. Copy and put from a URL on a different host stays a documented `known-difference` until an outbound fetch is designed. Extents become collectable only when no blob, snapshot, version, or staged block references them. Support the operations that read or list these rows: `snapshot`, `versionid`, `include=snapshots,versions` listings, snapshot and version delete, and promote by copy. Preserve the snapshot's content-type, metadata, and ETag as Azure defines.

## Alternatives and consequences

Copying bytes per snapshot is simple but wastes space and time. Treating a snapshot as a flag on the blob row cannot keep independent history. Reference sharing needs reference-aware garbage collection, and recovery must treat any referenced extent as live.

## Verification criteria

- A snapshot keeps its original bytes and metadata after the base blob is overwritten or deleted.
- Version listings return the previous states in order, and a version can be read, deleted, or promoted.
- Garbage collection after deleting the base blob preserves snapshot and version content, and reclaims it once the last reference is removed.
- Same-instance copy leaves source and destination independent afterward.
