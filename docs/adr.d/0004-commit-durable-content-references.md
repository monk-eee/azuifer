# ADR-0004: Commit only durable content references

- **Status:** Proposed

## Context

Large payloads must stream without tying up the metadata database. Storing metadata and bytes separately introduces a crash window: a database commit must never make unreadable content visible.

## Decision and scope

Use SQLite WAL for transactional metadata and immutable filesystem extents for persistent bytes. Stream into staging, validate length and checksums, and place the extent so it is durably reopenable before committing the metadata reference. If that commit fails, the extent may be orphaned, but no committed object can point to missing bytes. Garbage collection must respect in-flight writes and all live references, including snapshots and versions. In-memory mode uses the same service semantics without disk state and with a configurable memory limit.

For block blobs, acknowledge staged blocks only after their extents are durable. Keep them separate from normal Blob reads. A block-list commit resolves the selected staged and committed sources, checks the write condition, and publishes one new immutable extent and its ordered block offsets in the same metadata transaction. Retire discarded extents after the commit.

Page, append, and FileREST downloads pin the resolved extent files before releasing the metadata lock. They open only the extent being read. If a transaction removes an extent's last stored reference, reclamation waits for the last reader and any outstanding disk read to close.

## Alternatives and consequences

Storing all bytes in SQLite simplifies the transaction boundary but couples large streaming I/O to metadata load. Committing a reference before the extent is durable saves an ordering step but risks acknowledged data loss. Durable content first adds filesystem synchronization and cleanup work; the recoverable failure case is unused bytes, not a broken object reference.

## Verification criteria

- Crash tests interrupt writes before and after extent durability and metadata commit. Restart exposes the previously committed state or the complete new state, never a committed reference to missing or truncated bytes.
- Recovery collects abandoned staging and orphaned extents but preserves referenced snapshots/versions and active writes.
- In-memory tests observe no storage directory writes and a predictable failure at the configured memory limit.
- Block staging survives restart without replacing the committed blob. An invalid or conflicting block-list commit preserves both the preceding blob and its staged blocks.
