# ADR-0039: Per-version and per-snapshot Blob immutability policies and legal holds

- **Status:** Proposed

## Context

`Set Blob Immutability Policy` (`PUT ?comp=immutabilityPolicies`), `Delete Blob Immutability Policy` (`DELETE ?comp=immutabilityPolicies`), and `Set Blob Legal Hold` (`PUT ?comp=legalhold`) previously applied only to the current blob row in `blob_lifecycle` ([ADR-0022](0022-keep-blob-lifecycle-state-and-sweep-lazily.md)): targeting a historical `versionid=` or `snapshot=` answered `501 NotImplemented`, overwriting a protected blob on a versioned account dropped its WORM state when the old version retired to `blob_history`, `Delete Blob ?versionid=...` and `Delete Container` did not inspect historical versions or snapshots for protection, and `List Blobs` refused `include=immutabilitypolicy` and `include=legalhold` with `501 NotImplemented`.

Verification against `Azure/azure-rest-api-specs` (`specification/storage/data-plane/BlobStorage/Common/routes.tsp`), the Microsoft Learn REST pages for [Set Blob Immutability Policy](https://learn.microsoft.com/en-us/rest/api/storageservices/set-blob-immutability-policy), [Delete Blob Immutability Policy](https://learn.microsoft.com/en-us/rest/api/storageservices/delete-blob-immutability-policy), [Set Blob Legal Hold](https://learn.microsoft.com/en-us/rest/api/storageservices/set-blob-legal-hold), [List Blobs](https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs), and [Version-level WORM policies](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-version-level-worm-policies), and the Azure SDK for .NET recorded suite (`ImmutableStorageWithVersioningTests.cs`) establishes:

1. All three operations accept both `versionid=` and `snapshot=` (as of REST `2020-06-12`), never both together (`400 InvalidQueryParameterValue`), and do not change `ETag` or `Last-Modified`.
2. `Unlocked` policies can be shortened, extended, deleted, or transitioned to `Locked`; `Locked` policies can only be extended while unexpired and cannot be unlocked, shortened, or deleted (`409 BlobImmutableDueToPolicy`). Legal holds (`x-ms-legal-hold: true|false`) are independent of time-based policies (`409 BlobImmutableDueToLegalHold`).
3. On a versioned account, overwriting a blob retires the previous current version into history preserving its immutability policy and legal hold, while the new current version starts without the previous version's policy or hold.
4. `Delete Blob` refuses deleting any version or snapshot protected by a legal hold or an unexpired immutability policy (and `x-ms-delete-snapshots: include|only` cannot delete a protected snapshot), and `Delete Container` refuses deleting a container holding any protected current blob, version, or snapshot.
5. `GET`/`HEAD` (`?versionid=...`, `?snapshot=...`) surface per-state `x-ms-immutability-policy-until-date`, `x-ms-immutability-policy-mode`, and `x-ms-legal-hold`; `List Blobs` accepts `include=immutabilitypolicy` and `include=legalhold` alongside `versions` and `snapshots` and surfaces `<ImmutabilityPolicyUntilDate>`, `<ImmutabilityPolicyMode>`, and `<LegalHold>` per listed entry.

## Decision and scope

- **Schema migration `V7` (`src/store/schema.rs`).** Add three columns to `blob_history` in forward-only migration 7 (`PRAGMA user_version = 7`): `immutable_until INTEGER`, `immutability_mode TEXT NOT NULL DEFAULT ''`, and `legal_hold INTEGER NOT NULL DEFAULT 0`. Existing `V0`–`V6` databases upgrade cleanly without losing `blob_lifecycle` or `blob_history` rows; databases with `user_version > 7` remain refused ([ADR-0034](0034-refuse-newer-schemas-and-linked-storage.md)).
- **Target resolution (`src/store/immutability.rs`).** `Set Blob Immutability Policy`, `Delete Blob Immutability Policy`, and `Set Blob Legal Hold` resolve:
  - no selector -> current blob (`blob_lifecycle`);
  - `versionid=` matching the current blob's `version_id` -> current blob (`blob_lifecycle`);
  - `versionid=` matching a live historical version (`blob_history`, `kind = 2`, `deleted_at IS NULL`) -> that version row;
  - `snapshot=` matching a live snapshot (`blob_history`, `kind = 1`, `deleted_at IS NULL`) -> that snapshot row;
  - missing container -> `404 ContainerNotFound`; missing or soft-deleted blob/version/snapshot -> `404 BlobNotFound`.
- **Version retirement preservation (`src/store/snapshots.rs`, `src/store/expiry.rs`).** `archive` records `Protection` on `blob_history`. When `begin_write`, `retire_current`, or `expire` retires a current blob as `Kind::Version`, it copies `old.info.lifecycle.protection` into `blob_history`, and `begin_write` clears protection on `blob_lifecycle` (`expiry::clear_protection`) so property/metadata writes on a versioned account do not leak the old version's policy or hold onto the new current version. Snapshots (`Kind::Snapshot`) start unprotected and carry independent state.
- **WORM delete enforcement (`src/store/snapshots/deletion.rs`, `src/store/immutability.rs`).**
  - `delete_retained` enforces `protection.check_delete(now)` before deleting any historical version or snapshot.
  - `delete_current` with `x-ms-delete-snapshots: include|only` checks that no live snapshot of the blob is protected before deleting any snapshot or the current blob.
  - `check_container` checks both `blob_lifecycle` and live (`deleted_at IS NULL`) `blob_history` rows before allowing `Delete Container` (permanent or soft-deleted).
  - Lazy expiry sweep (`snapshots::expire`) skips deleting a WORM-protected blob on a non-versioned account and preserves any WORM-protected snapshots.
- **Read and list visibility (`src/store/snapshots.rs`, `src/store/snapshots/listing.rs`, `src/domain.rs`, `src/protocol/headers.rs`, `src/respond.rs`, `src/blob_snapshot.rs`, `src/blob_lifecycle.rs`).** `retained` and `list_extended` load `immutable_until`, `immutability_mode`, and `legal_hold` from `blob_history` so `GET`/`HEAD` (`?versionid=...`, `?snapshot=...`) and `List Blobs` (`include=versions`, `include=snapshots`, `include=immutabilitypolicy`, `include=legalhold`) surface per-entry protection. `List Blobs` accepts `include=immutabilitypolicy` and `include=legalhold` (while `include=permissions` remains `501 NotImplemented`).
- **Out of scope.** Container-level immutability policies, account-level default policies, `x-ms-immutable-storage-with-versioning` container creation headers, immutability headers on `Put Blob`, and blob-version/snapshot SAS scopes (`sr=bv`/`sr=bs`) remain unimplemented.

## Unverified until live Azure recording

No immutability journey has been recorded against a live version-level-WORM Azure account yet (B-30 and the new B-49 in the [recording plan](../compatibility/azure-recording-plan.md) are pending), so all affected operations stay `known-difference`:

- Exact conditional header support on `Set Blob Immutability Policy` / `Delete Blob Immutability Policy` / `Set Blob Legal Hold` (TypeSpec lists only `If-Unmodified-Since` on `Set Blob Immutability Policy`; Azuifer accepts standard `CONDITIONS` on all three).
- Whether `List Blobs` omits `<ImmutabilityPolicy*>` / `<LegalHold>` when `include=immutabilitypolicy` / `include=legalhold` are not requested (Azuifer accepts those `include` values and continues emitting set policy/hold elements in plain listings for compatibility with existing local behavior, plus `<LegalHold>false</LegalHold>` when `include=legalhold` is requested on unprotected entries).
- Whether `Set Blob Metadata` / `Set Blob Properties` on a versioned protected blob creates a new version or is refused (`409 BlobImmutableDueToPolicy` / `BlobImmutableDueToLegalHold`) on live Azure — Learn's scenario table lists `Set Blob Metadata` as prohibited even though `Put Blob` creates a new version; Azuifer keeps existing versioned-write behavior (`Lifecycle::check_write`) and preserves the old version's protection.
- Whether `x-ms-delete-snapshots: include|only` returns `409 BlobImmutableDueToPolicy` / `BlobImmutableDueToLegalHold` atomically when one snapshot is protected, and the exact precedence when a container holds both a policy and a legal hold.
- Whether `Set Blob Immutability Policy` / `Set Blob Legal Hold` with `snapshot=` is rejected on accounts without version-level immutability enabled (Azuifer does not model per-container VLW enablement).

## Alternatives and consequences

- **A separate `blob_history_lifecycle` table** would duplicate the five-column primary key and add a join on every `blob_history` read and listing; adding three nullable/defaulted columns directly to `blob_history` via `V7` keeps every version/snapshot read single-table and mirrors `V6`'s addition of page/append columns to `blob_history`.
- **Refusing `snapshot=` with `400`/`501`** was rejected after `routes.tsp`, Learn, and `.NET` SDK's live-recorded `ImmutableStorageWithVersioningTests.cs` confirmed Azure supports both `snapshot=` and `versionid=` on all three operations.

## Verification criteria

- Schema tests in `src/store/schema.rs` prove a `V6` database with current-blob `blob_lifecycle` protection and `blob_history` rows migrates cleanly to `V7` without data loss, and `user_version > 7` is refused.
- HTTP protocol tests in `tests/blob_versions_http.rs` (written failing-first) cover current and historical `versionid=` policies (unlocked/locked/extend/shorten-refused/delete), legal holds, overwrite preservation across versions, `Delete Blob ?versionid=...` and `Delete Container` protection until expiry/unlock/clear on the test clock, `GET`/`HEAD`/`List Blobs` (`include=versions,immutabilitypolicy,legalhold`), `snapshot=` policy/hold + `x-ms-delete-snapshots` protection, and persistence across disk restart.
- Official Python SDK tests in `tests/blob_snapshots_sdk.py` exercise `set_immutability_policy`, `delete_immutability_policy`, and `set_legal_hold` on versioned blobs (`version_id=...`) and verify `get_blob_properties(version_id=...)` and `list_blobs(include=["versions", "immutabilitypolicy", "legalhold"])`.
