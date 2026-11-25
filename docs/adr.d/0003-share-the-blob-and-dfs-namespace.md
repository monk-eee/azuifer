# ADR-0003: Share the Blob and DFS namespace

- **Status:** Proposed

## Context

Blob and DFS address the same stored data in an HNS-enabled account. Separate implementations that synchronize after a write cannot guarantee immediate cross-protocol visibility or atomic directory rename.

## Decision and scope

Use one canonical metadata identity and one content reference per object across the two adapters. Represent directories explicitly and commit a rename as one metadata transaction. Keep protocol-specific projections at the adapter boundary. Preserve conditions, ETags, leases, and DFS ownership and ACL data on the shared objects. This design applies to HNS-enabled Blob and DFS; reject DFS on disabled accounts. FileREST keeps a separate share namespace; Queue and Table keep separate domain models.

## Alternatives and consequences

Mirroring separate stores duplicates bytes and creates stale views. Treating directories as inferred name prefixes would make atomic rename and directory ACLs unreliable. Shared identity eliminates synchronization, but both adapters must preserve the same invariants when they mutate metadata.

## Verification criteria

- Blob writes read through DFS and DFS writes read through Blob with the same content and appropriate object metadata.
- A concurrent listing during a directory rename sees the old paths or the new paths, never a partial move. After a successful rename, Blob listing reflects it.
- Cross-protocol leases and conditions remain coherent; DFS requests fail appropriately for an HNS-disabled account, and a FileREST operation cannot mutate the shared namespace.
