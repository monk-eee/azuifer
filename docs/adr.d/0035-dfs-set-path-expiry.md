# ADR-0035: ADLS Gen2 Set Path Expiry over `PUT ?comp=expiry` and DFS expiry visibility

- **Status:** Proposed

## Context

The DFS guide previously listed Set Path Expiry as unimplemented, and an earlier proposal assumed a DFS-only `PATCH ?action=setExpiry` endpoint. Verification against `Azure/azure-rest-api-specs` (`specification/storage/data-plane/DataLakeStorage/routes.tsp` and `BlobStorage/Common/routes.tsp`), the Microsoft Learn REST reference for [Set Blob Expiry](https://learn.microsoft.com/en-us/rest/api/storageservices/set-blob-expiry), [Path - Get Properties](https://learn.microsoft.com/en-us/rest/api/storageservices/datalakestoragegen2/path/get-properties), and [Path - List](https://learn.microsoft.com/en-us/rest/api/storageservices/datalakestoragegen2/path/list), and all five official Azure Data Lake SDKs (Python, JavaScript, .NET, Java, and Go) establishes that `PATCH ?action=setExpiry` does not exist in Azure ADLS Gen2. Real ADLS Gen2 `Path.setExpiry` is `PUT /{account}/{filesystem}/{path}?comp=expiry` — the same operation as Blob Set Blob Expiry, routed through the Blob endpoint (which Azuifer's DFS listener already forwards via [ADR-0023](0023-serve-blob-calls-addressed-to-the-blob-host-on-the-dfs-listener.md) and `?comp=` forwarding).

Because `PUT ?comp=expiry` already writes to the shared `blob_lifecycle` table swept lazily on the shared clock ([ADR-0022](0022-keep-blob-lifecycle-state-and-sweep-lazily.md)), four real HNS / ADLS Gen2 gaps remained:

1. Calling `PUT ?comp=expiry` against an existing HNS directory looked only in the `blobs` table and answered `404 BlobNotFound` instead of rejecting the directory target.
2. Calling `PUT ?comp=expiry` on an HNS account bypassed DFS POSIX ACL write enforcement for non-role bearer tokens and user-delegation SAS callers.
3. DFS `HEAD` (`Get Path Properties`, `action=getStatus`, `action=getAccessControl`) omitted `x-ms-expiry-time` and `x-ms-creation-time`, even though `DataLakeStorage/routes.tsp` and REST version `2023-05-03` onward document both headers on DFS `HEAD`.
4. DFS `List Paths` JSON entries omitted `expiryTime` and `creationTime`, which `DataLakeStorage/models.tsp` defines on `PathItem` and the official SDKs parse as decimal Windows FILETIME 100-nanosecond tick strings (JavaScript's `windowsFileTimeTicksToTime` accepts only FILETIME ticks, while Python, Java, and .NET accept FILETIME ticks with an RFC 1123 fallback).

## Decision and scope

- **Wire route.** Do not add a synthetic `PATCH ?action=setExpiry` route. ADLS Gen2 Set Path Expiry is `PUT /{account}/{filesystem}/{path}?comp=expiry` with `x-ms-expiry-option` (`RelativeToCreation`, `RelativeToNow`, `Absolute`, `NeverExpire`, case-insensitive) and `x-ms-expiry-time`, handled by the existing `LifecycleOperation::SetExpiry` path on both the Blob and DFS listeners.
- **Directory rejection on HNS accounts.** In `Store::set_expiry`, when the target account has HNS enabled, check `namespace::directory` before `require_blob` in the same transaction and reject an existing directory with `Error::PathConflict`, which maps to `409 BlobOperationNotSupported` on the Blob wire surface — consistent with every other Blob-side operation that cannot target an HNS directory (`Put Blob`, `Put Block List`, `Copy Blob`, `Undelete Blob`). Flat (non-HNS) accounts keep existing Set Blob Expiry behavior unchanged.
- **POSIX ACL write enforcement on HNS accounts.** Move the caller classification (`Superuser` vs `Principal(oid)`) onto `blob_auth::Credentials::dfs_caller` so DFS and Blob lifecycle share one implementation. On HNS accounts, `Store::set_expiry` runs `dfs_paths::check_access` with `Need::WRITE` (execute on every ancestor directory and write on the target path) inside the same metadata transaction before touching the row. Shared Key, Shared Key Lite, account SAS, service SAS, and role-bearing bearer tokens bypass ACLs as in Azure; non-role bearer tokens and user-delegation SAS callers (`skoid`) must pass the POSIX check or receive `403 AuthorizationPermissionMismatch`.
- **DFS `HEAD` headers.** `dfs::respond::path_view` emits `x-ms-creation-time` (RFC 1123) on `HEAD` (`Get Path Properties`, `getStatus`, `getAccessControl`) for files (from `blobs.created`) and directories (from `directories.modified`, since directories do not keep a separate creation column), and emits `x-ms-expiry-time` (RFC 1123) on `HEAD` for files when an expiry deadline is set. DFS `Read File` (`GET`) does not add these headers, matching `DataLakeStorage/routes.tsp`.
- **DFS `List Paths` JSON.** `namespace::list` joins `blobs` and `blob_lifecycle` on the paged rows (no SQLite schema migration) to read `created` and `expires_at`. `dfs::respond::list_paths` formats `creationTime` for every entry and `expiryTime` for files with a deadline as decimal Windows FILETIME 100-ns tick strings (`116444736000000000 + unix_ticks`) via `Ticks::filetime`, omitting `expiryTime` when unset.

## Unverified until live Azure recording

None of these HNS behaviors have been recorded against a live Azure HNS account yet, so `Set Path Expiry`, `Get Path Properties`, and `List Paths` remain `known-difference` in `specs/conformance/dfs.json`, and row D-16 in the [recording plan](../compatibility/azure-recording-plan.md) tracks live verification of:

- The exact HTTP status and Azure error code returned when `PUT ?comp=expiry` targets an existing HNS directory (Learn states only that expiry cannot be set on a directory; Azuifer answers `409 BlobOperationNotSupported`, whereas live Azure could return `400 InvalidOperation`, `409 ResourceTypeMismatch`, or another code).
- Whether live Azure checks POSIX ACLs before or after the directory check on `PUT ?comp=expiry`, and whether non-role bearer / user-delegation SAS write permission is checked identically to DFS write operations.
- Whether `List Paths` omits `expiryTime` or returns `"0"` for directories and non-expiring files (Python, JS, Java, and .NET all map both `"0"` and absence to `None`/`null`/`undefined`; Go exposes `*string`).
- Whether `x-ms-creation-time` and `x-ms-expiry-time` are returned on `action=getAccessControl` as well as default `HEAD` and `action=getStatus`, and whether a directory's `x-ms-creation-time` stays fixed when its properties or ACL change.
- Whether `PUT ?comp=expiry` updates `ETag` or `Last-Modified` on a live HNS account (Azuifer keeps both unchanged, matching existing Blob Set Blob Expiry tests).

## Alternatives and consequences

- **Inventing `PATCH ?action=setExpiry`** would diverge from real Azure REST and break alignment with every official SDK, all of which call `PUT ?comp=expiry`.
- **Adding a `created` column to `directories`** would require a SQLite schema migration (`PRAGMA user_version = 7`) solely to separate directory creation from directory modification; using `directories.modified` avoids an unnecessary schema bump while satisfying SDK `creationTime` parsing until a live recording shows separate tracking is needed.
- **Formatting `List Paths` timestamps as RFC 1123** would break `@azure/storage-file-datalake`, whose `windowsFileTimeTicksToTime` parses only decimal FILETIME ticks. Emitting decimal FILETIME ticks works across all five official SDKs.

## Verification criteria

- Protocol HTTP tests in `tests/dfs_http.rs` prove that `PUT ?comp=expiry` rejects an HNS directory with `409 BlobOperationNotSupported` (not `404 BlobNotFound`), enforces POSIX ACL execute+write for non-role bearer and user-delegation SAS callers, surfaces `x-ms-expiry-time` and `x-ms-creation-time` on DFS `HEAD` / `action=getStatus`, surfaces decimal FILETIME `expiryTime` and `creationTime` in DFS `List Paths`, and removes the file once the test clock passes the deadline.
- Cross-service tests in `tests/dfs_cross_http.rs` prove that `PUT ?comp=expiry` via DFS/Blob agrees across DFS `HEAD`, DFS `List Paths`, and Blob `HEAD`, removes the file on both endpoints at the deadline, and clearing with `NeverExpire` keeps both endpoints serving past the old deadline.
- The official Python SDK suite in `tests/dfs_sdk.py` exercises `DataLakeFileClient.set_file_expiry(...)` and verifies `get_file_properties()` and `get_paths()` reflect the expiry and its clearing with `NeverExpire`.
- Unit tests in `src/stamp.rs` verify Windows FILETIME tick conversion and bounds.
