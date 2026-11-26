# Azure Files (FileREST) wire compatibility

Azuifer serves the Azure Files data plane on its own listener (default port `10004`, `--file-port`, or an ephemeral port when `--port 0`). It targets API version `2023-11-03` with path-style (`http://127.0.0.1:10004/{account}/...`) and host-style (`http://{account}.file.localhost:10004/...`) endpoints, and has its own namespace, store, leases, and handles ([ADR-0016](../adr.d/0016-give-filerest-its-own-namespace.md)). [The manifest](../../specs/conformance/files.json) is the operation inventory; no operation has been rated against Azure yet (`azure_differential_verified` is `false`), so every state is `implemented`, `known-difference` or `unsupported`, never `exact`.

```sh
azuifer serve --services file --in-memory
# file_url=http://127.0.0.1:10004
```

Clients keep their storage client and set only the file endpoint, for example the connection string `DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=<key>;FileEndpoint=http://127.0.0.1:10004/devstoreaccount1;`. The account and keys come from the same configuration as Blob.

## Operations

| Area | Operations |
| --- | --- |
| Shares | List Shares, Create, Get Properties, Get/Set Metadata, Set Properties, Delete, Get/Set ACL, Get Stats, Lease, Snapshot, Create/Get Permission |
| Directories | Create, Get Properties, Set Properties, Get/Set Metadata, Delete, List Directories and Files, Rename, List Handles, Force Close Handles |
| Files | Create, Get, Get Properties, Set Properties, Get/Set Metadata, Delete, Put Range (update and clear), Put Range From URL (a file on this instance and account), List Ranges (including `prevsharesnapshot` diffs), Copy, Abort Copy, Lease, Rename, List/Force Close Handles |
| Service | Get/Set File Service Properties: metrics, CORS rules and the SMB multichannel flag are validated and stored per account and returned on request, but never acted on |
| Soft delete | Restore Share and `include=deleted` in List Shares, when `--share-retention-days` (`AZUIFER_SHARE_RETENTION_DAYS`, 0 to 365, default 0) is above zero: Delete Share then keeps the share and its snapshots hidden for that many days on the injected clock ([ADR-0026](../adr.d/0026-keep-deleted-shares-under-a-hidden-name.md)). Azure keeps this setting in the management plane, and the restore version here is the deletion time in milliseconds |
| Recognised, answered with `501 NotImplemented` | The NFS hard link and symbolic link operations |

Share, directory and file URIs are `/{account}/{share}/{path}`. Resources are selected by `restype` and `comp` exactly as in the Microsoft reference; an unknown combination returns `InvalidQueryParameterValue` and a known one with the wrong verb returns `UnsupportedHttpVerb`.

## Authentication and versions

- Shared Key and Shared Key Lite with the File canonicalization, including multi-valued query parameters, `x-ms-date` or `Date`, and the 15-minute skew limit. Either of two configured keys validates.
- Account SAS (`ss=f`, resource types `s`, `c`, `o`, permissions `r w d l c`) and service SAS for a share (`sr=s`, `rcwdl`) or a file (`sr=f`, `rcwd`), from `sv=2015-04-05` on. Stored access policies set with Set Share ACL are honored through `si`. `rscc`, `rscd`, `rsce`, `rscl` and `rsct` override the matching Get File response headers. Share-level operations, including snapshots and leases, need an account SAS because a service SAS cannot grant them.
- `sip` is part of the signature but the client address is not checked, and `spr=https` is not enforced on the HTTP listener.
- A missing credential returns `NoAuthenticationInformation`; a bad signature, expired token or unknown account returns `AuthenticationFailed`; a SAS that does not cover the operation returns `AuthorizationPermissionMismatch`. Bearer tokens follow the [bearer-token modes](blob.md#bearer-tokens-oauth): rejected with 401 `InvalidAuthenticationInfo` by default, validated with `--oauth basic` or `--oauth jwks`, and `x-ms-file-request-intent` is not required.
- `x-ms-version` is required except on SAS requests. Only `2023-11-03` is accepted; a newer well-formed version is accepted with `--skip-api-version-check` and answered with the effective version in `x-ms-version`. Older versions are rejected.

## Namespace and content

- Names are case-insensitive and case-preserving, with Azure's rules: 255 characters per component, 2048 per path, 250 levels, no `" \ / : | < > * ?` or control characters, no reserved device names, and trailing dots dropped unless `x-ms-allow-trailing-dot: true`. A file and a directory cannot share a name.
- Share, directory and file rows have parent references, so a directory rename is one row update and a share delete cascades in one transaction. Share snapshots copy the rows and share extents.
- File content is a range map from offset to immutable extent ([ADR-0015](../adr.d/0015-map-mutable-ranges-over-immutable-extents.md)) held by the reusable [`ranges`](../../src/ranges.rs) module. Create sets only the logical size. Each Put Range streams into a new extent, which is verified, synced, and published with the map change in one transaction; clearing deallocates without writing zeros, and holes read as zeros. An extent is deleted only when no file or snapshot references it.
- `--location ./data` keeps FileREST state in `./data/file/` (`metadata.sqlite3`, `content/`, `azuifer.lock`), separate from Blob. Startup removes abandoned staging files and unreferenced extents. A second process on the directory fails to start.
- `--in-memory` keeps extents in memory and fails predictably with `507 InsufficientStorage` when they exceed `--memory-limit`; overwritten extents are freed in the same transaction.
- Share quota (GiB) is enforced on allocated bytes with `ShareSizeLimitReached` (403), and `Get Share Stats` reports the same figure.

## Leases

Share leases implement the full table: durations of 15 to 60 seconds or infinite, `Available`, `Leased`, `Expired`, `Breaking` and `Broken`, with break periods up to 60 seconds. File leases are infinite and have `Available`, `Leased` and `Broken`; `renew` is rejected and `break` is immediate. State is computed from the stored lease and the clock on each access ([ADR-0017](../adr.d/0017-model-leases-as-a-clocked-state-machine.md)), so leases survive restart and need no timer. With `--test-clock`, `POST /_azuifer/clock/advance?seconds=N` on the admin listener moves the clock all services share, which expires a 15 to 60 second share lease without sleeping. The outcome tables in the lease documents list 409 for a wrong lease ID on an ordinary operation, while the error list assigns 412 to `LeaseIdMismatchWithFileOperation` and `LeaseIdMismatchWithFileShareOperation`; Azuifer follows the error list. Lease operations themselves return 409 codes.

## Addressing

Any `{account}.file.{domain}` host names the account, so `http://{account}.file.localhost:10004/{share}/{path}` equals `http://127.0.0.1:10004/{account}/{share}/{path}`. Shared Key and Shared Key Lite sign the path exactly as sent, after `/{account}` (so `/{account}/{share}/{path}` host-style and `/{account}/{account}/{share}/{path}` path-style); SAS strings (`/file/{account}/{share}/...`) do not depend on the style. List Shares and List Directories and Files report `ServiceEndpoint` as the host the client used. `azure-storage-file-share` cannot infer the account from a `.file.localhost` host and raises `Unable to determine account name`, so pass `credential={"account_name": ..., "account_key": ...}`; the client then works against the host-style URL ([`tests/addressing_sdk.py`](../../tests/addressing_sdk.py)). The client machine must resolve `*.localhost` to loopback.

## Known differences

- Handles are not modeled: List Handles returns an empty list and Force Close Handles reports zero closed.
- Put Range From URL takes `x-ms-copy-source`, `x-ms-source-range`, and `x-ms-range` of the same length (up to 4 MiB), with `Content-Length: 0` and `x-ms-write: update`. Like Copy File it reads a file on this listener and account (a share snapshot is allowed) and does not check a SAS on the source URL; a source on another host or account, including a Blob, is not served. It takes no source checksum or conditions.
- SMB timestamps (creation, last write, change) keep the 100 ns precision of the seven-digit ISO form; `Last-Modified` and share times stay in milliseconds. `x-ms-file-last-write-time` accepts `now` and `preserve` in any case on Put Range, and AzCopy sends `Preserve`. A data directory written before this change stored these timestamps in milliseconds, and they now read as dates near 1970.
- Copy File is synchronous and limited to a source on this instance and account (a share snapshot is allowed). `{account}.file.*` host names of a configured account are treated as local because Azure CLI builds source URLs that way. Abort Copy always returns `NoPendingCopyOperation`.
- Set File Properties replaces the HTTP properties as a set only when one of them is sent, so a pure resize keeps the content type.
- Standard conditional headers are evaluated on reads even though Azure does not document them for Files. Permissions are stored SDDL strings and are never evaluated; there is no SMB or NFS.
- Soft delete, provisioned IOPS and bandwidth, the 200-snapshot limit and access-tier transition rules are not modeled.
- Unsupported operations and options return a stable `501 NotImplemented` Azure-shaped error.

## AzCopy

AzCopy 10.34.2 (Windows amd64) ran against a debug build serving `--services blob,file,dfs` with an account SAS (`ss=f`, `srt=sco`) made from the public `devstoreaccount1` key, loopback only. These pass:

- `copy --from-to LocalFile` of one file and of a tree of 60 small files plus a 300 MiB file, and `copy --from-to FileLocal` back, compared by SHA-256; `list --location File`; `remove --from-to FileTrash --recursive`.
- `sync` in both directions: nothing is re-sent when unchanged, and only changed files are when they differ. AzCopy creates a file with a write time of 1970, uploads, then sets the source's NTFS timestamp, and re-sends any file whose source time is newer than the stored one, so the 100 ns precision above is what makes the second `sync` a no-op.
- `copy --from-to FileFile --recursive` between two shares of the account, which uses Put Range From URL.

Limits you meet when using AzCopy against Azuifer:

- AzCopy needs `--from-to` (`LocalFile`, `FileLocal`, `FileFile`, `FileTrash`) and `--location File` for `list`, and `azcopy make` cannot create a share: it rejects an IP endpoint, and the host-style form (which Files does serve) was not tried with AzCopy. Create the share with the SDK, `az storage share create`, or one HTTP request. AzCopy never creates a missing share.
- Copies between Blob and Files (`BlobFile`, `FileBlob`) fail: the two services keep separate stores and Azuifer makes no outbound requests. Download to disk and upload instead.
- A request waits up to 5 seconds for one of the 16 active-request slots before it is answered `503 ServerBusy`, which AzCopy retries.

[`tests/azcopy_smoke.py`](../../tests/azcopy_smoke.py) runs a compact Blob and Files scenario with 30 `PASS`/`FAIL` steps against a running server; the Files half covers the items above. Start Azuifer with `--services blob,file --skip-api-version-check --memory-limit 1073741824`, then `python tests/azcopy_smoke.py --azcopy /path/to/azcopy` (`pip install azure-storage-blob azure-storage-file-share` generates the SAS tokens; `--file-url` and `--file-sas` select your own). It shows that this AzCopy version moves the expected bytes and makes the expected `sync` decisions, not wire equivalence with Azure Files. [`tests/azcopy_regressions_http.rs`](../../tests/azcopy_regressions_http.rs) pins each defect AzCopy found as an HTTP test.

## Verification

- `cargo test` runs unit tests for the range map, lease state machine, names, XML bodies, authentication string-to-sign layouts and the store, and the [HTTP suite](../../tests/files_http.rs), which starts the real binary and covers share, directory and file lifecycles, ranges and checksums, snapshots and diffs, rename, copy, leases, permissions, SAS and Shared Key authentication, restart persistence, abrupt termination with a partial upload, the memory limit, and the manifest. The [addressing suite](../../tests/addressing_http.rs) covers host-style Shared Key and SAS, and the [shared clock suite](../../tests/shared_clock_http.rs) expires a share lease on the admin `--test-clock`.
- [`tests/files_sdk.py`](../../tests/files_sdk.py) drives the built binary with `azure-storage-file-share` and `az storage share|directory|file`. It is run manually: `pip install azure-storage-file-share`, then `python tests/files_sdk.py --binary target/debug/azuifer`.
