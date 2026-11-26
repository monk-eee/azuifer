# ADR-0026: Keep deleted shares under a hidden name and restore them by renaming

- **Status:** Proposed

## Context

Azure Files can keep a deleted share for a retention period and restore it with Restore Share (`PUT ?restype=share&comp=undelete`, with `x-ms-deleted-share-name` and `x-ms-deleted-share-version`), and List Shares reports them with `include=deleted`. The retention setting lives in the management plane, which Azuifer does not serve, so the data plane alone cannot turn it on. Restore Share answered `501`.

## Decision and scope

Add `--share-retention-days` (`AZUIFER_SHARE_RETENTION_DAYS`, 0 to 365, default 0, meaning delete at once). When it is above zero, Delete Share of a live share checks leases and snapshot policy as before, then renames the share, its snapshots and its permission rows to `$deleted/{version}/{name}` and records the deletion with its expiry in a `deleted_shares` table. No valid share name starts with `$`, so every lookup by name misses the hidden rows and the name is free at once, as in [ADR-0022](0022-keep-blob-lifecycle-state-and-sweep-lazily.md) for containers. Restore Share renames the rows back to the destination in the path inside one transaction; a taken destination is `ShareAlreadyExists`, an unknown name or version `ShareNotFound`. Expired shares are erased, with their extents, before the next action that deletes, lists with `include=deleted`, or restores, measured on the injected clock. The version is the deletion time in milliseconds. A deleted share sorts after its live namesake and snapshots in a listing, so continuation markers stay unambiguous.

## Alternatives and consequences

A `deleted` column on `shares` would need a filter in every query. A background timer would race the test clock. Tying soft delete to File service properties would invent a setting Azure does not have on the data plane. The cost is one query per sweep and an operator flag that Azure does not have; deleting a share still frees nothing until retention ends.

## Verification criteria

- With retention on, a deleted share is absent from reads and plain listings, present in `include=deleted` with `Deleted`, `Version` and `RemainingRetentionDays`, and restorable with its files under the same or another name.
- A restored version cannot be restored twice, and a taken destination is refused.
- After retention a share is gone and its extents are freed; with retention off, behavior is unchanged.