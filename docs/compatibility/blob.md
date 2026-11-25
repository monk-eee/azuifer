# Blob wire compatibility

Use the [quick start](../../README.md#run-locally) with the Blob API version `2023-11-03`. [The manifest](../../specs/conformance/blob.json) is the operation inventory: each operation is `implemented`, `known-difference`, or `unsupported`, with its authorization modes and notes. No operation has been rated `exact`, and none has been differentially verified against Azure Storage yet.

This slice covers block, page, and append blobs. Snapshots, versions, tags, batch, and DFS are separate work.

## Operations

| Target | Requests implemented |
| --- | --- |
| `/{account}` | `GET comp=list` (List Containers, `include=metadata`); `GET` or `PUT restype=service&comp=properties` (service properties and CORS); `GET restype=service&comp=stats`; `GET` or `HEAD restype=account&comp=properties` |
| `/{account}/{container}` | `PUT`, `GET`, `HEAD`, `DELETE` with `restype=container`; `comp=metadata` (`GET`, `HEAD`, `PUT`); `comp=acl` (`GET`, `PUT`); `PUT comp=lease`; `GET comp=list` (List Blobs); `GET` or `HEAD restype=account&comp=properties` |
| `/{account}/{container}/{blob}` | `PUT` with `x-ms-blob-type: BlockBlob`, `PageBlob`, or `AppendBlob` (Put Blob; Put Blob From URL with `x-ms-copy-source` for block blobs); `PUT` with `x-ms-copy-source` and no blob type (Copy Blob); `GET`, `HEAD`, `DELETE` |
| `…/{blob}?comp=…` | `block` (Put Block, or Put Block From URL), `blocklist` (`PUT`, `GET`), `page` (Put Page, or Put Page From URL), `pagelist` (`GET`), `appendblock` (Append Block, or Append Block From URL), `seal` (`PUT`), `properties` (`PUT`, including page blob resize and sequence number), `metadata` (`PUT`, `GET`, `HEAD`), `tier` (`PUT`), `lease` (`PUT`), `copy&copyid=…` (Abort Copy, `x-ms-copy-action: abort`) |
| any path | `OPTIONS` preflight, answered from the account's CORS rules |

Anything else, including unsupported query parameters and `x-ms-*` headers, answers an Azure-shaped `NotImplemented` error instead of being ignored.

### Page blobs and append blobs

Page and append blob content is a map from blob offsets to immutable extents ([ADR-0015](../adr.d/0015-map-mutable-ranges-over-immutable-extents.md)). Every write streams into a new extent, is made durable, and then commits its range rows and new ETag in one metadata transaction ([ADR-0004](../adr.d/0004-commit-durable-content-references.md)), so a crash exposes the previous content or the whole new write. Clearing and shrinking change rows only, unwritten ranges allocate nothing, and extents are deleted when no blob references them. Startup recovery keeps referenced extents and removes staging files and orphans.

- **Create.** `Put Blob` with `x-ms-blob-type: PageBlob` requires `x-ms-blob-content-length` (a multiple of 512 up to 8 TiB) and accepts `x-ms-blob-sequence-number` and a premium `x-ms-access-tier` (`P4` to `P80`). `AppendBlob` creates an empty blob. Both need `Content-Length: 0`, replace any blob of the same name (and so change its type) subject to the usual conditions and lease, and discard uncommitted blocks.
- **Put Page.** `x-ms-page-write: update` writes up to 4 MiB at a 512-aligned `x-ms-range` or `Range` and accepts `Content-MD5` or `x-ms-content-crc64`. `clear` takes `Content-Length: 0` and any aligned range. `x-ms-if-sequence-number-le`, `-lt`, and `-eq` must all hold or the answer is 412 `SequenceNumberConditionNotMet`. A misaligned or out-of-bounds range is 416 `InvalidPageRange`. Responses carry `x-ms-blob-sequence-number`.
- **Get Page Ranges.** `GET comp=pagelist` lists allocated ranges, optionally inside an `x-ms-range` or `Range` window, with `maxresults` and `marker` paging through `NextMarker`. Touching allocated ranges are reported as one range. `snapshot` and `prevsnapshot` answer `NotImplemented` until snapshots exist, so no clear ranges are reported.
- **Resize and sequence number.** Set Blob Properties with `x-ms-blob-content-length` resizes (shrinking discards trailing data, growing adds a hole). `x-ms-sequence-number-action` is `max`, `update`, or `increment` with `x-ms-blob-sequence-number` for the first two. Either can accompany content properties.
- **Append Block.** Up to 4 MiB and 50,000 blocks, with `Content-MD5` or crc64, `x-ms-blob-condition-maxsize` (412 `MaxBlobSizeConditionNotMet`), and `x-ms-blob-condition-appendpos` (412 `AppendPositionConditionNotMet`). The 201 response reports `x-ms-blob-append-offset` and `x-ms-blob-committed-block-count`. The 50,001st block is 409 `BlockCountExceedsLimit`. Zero-length blocks are rejected.
- **Seal.** `PUT comp=seal` (optionally with `x-ms-blob-condition-appendpos`) makes an append blob read-only: later appends are 409 `BlobIsSealed`, while metadata changes and delete still work. Sealing a sealed blob changes nothing.
- **Reads and listings.** Get Blob streams page blob holes as zeros and returns an append blob as its concatenated blocks, both with range support. Get and Head report `x-ms-blob-type`, `x-ms-blob-sequence-number` (page), and `x-ms-blob-committed-block-count` and `x-ms-blob-sealed` (append, sealed only when true). List Blobs reports `BlobType`, `Content-Length` (the logical length), `x-ms-blob-sequence-number`, and `Sealed`. Page blobs show an access tier only after one was set, and the tiers `P4` to `P80` are accepted only on page blobs.
- **Wrong blob type.** Put Block, Put Block List, and Get Block List on a page or append blob, Put Page, Get Page Ranges, resize, and sequence changes on other types, and Append Block and Seal on other types answer 409 `InvalidBlobType`.
- **From URL and copy.** Put Page From URL and Append Block From URL read a range of a same-instance source with the same authorization as Copy Blob; Put Page From URL needs `x-ms-source-range` and a `Content-Length: 0` request. Copy Blob of a page or append blob keeps the type, sequence number, and committed block count, shares the source's extents (so holes stay holes), and leaves the copy unsealed.

Known differences: `x-ms-source-content-md5`, `x-ms-seal-blob`, and incremental copy are not implemented. Put Blob From URL and Put Block From URL accept only block blob destinations, and a page blob source is read densely (holes become zeros), so reading a very large sparse source this way is costly. Premium tiers are stored and reported but do not change behavior. A partly overwritten extent stays allocated until every range using it is replaced, so storage can exceed the live data. Snapshot and version interaction arrives with [ADR-0018](../adr.d/0018-model-snapshots-versions-and-copy-as-immutable-references.md).

### Properties, metadata, conditions

Put Blob and Put Block List store `x-ms-blob-content-type`, `-encoding`, `-language`, `-disposition`, `-cache-control`, and `-md5` (Put Blob also accepts the plain `Content-Type`, `Content-Encoding`, `Content-Language`, `Content-Disposition`, and `Cache-Control`), `x-ms-meta-*`, and `x-ms-access-tier`. Get and Head return them, with creation time, lease, copy, and tier headers. Set Blob Properties replaces all six content properties when any is sent. Metadata names are lowercase: the HTTP layer folds header case, so `x-ms-meta-Owner` reads back as `owner`.

`If-Match`, `If-None-Match`, `If-Modified-Since`, and `If-Unmodified-Since` apply to every blob operation (both ETag conditions together too), and the date conditions to container operations. A failed condition answers 304 for reads where Azure does and 412 `ConditionNotMet` otherwise; copy source conditions answer `SourceConditionNotMet`. `If-None-Match: *` on an existing blob is 409 `BlobAlreadyExists` for Put Blob and Put Block List. Range reads take one `bytes=start-end` range, and `x-ms-range-get-content-md5` or `-crc64` returns the checksum of ranges up to 4 MiB.

### Listings

List Blobs supports `prefix`, `delimiter` (with `BlobPrefix` entries), `maxresults`, opaque `marker` tokens, and `include=metadata,copy,uncommittedblobs`. Pages count blobs and prefixes together, and a marker after a collapsed prefix skips everything under it. `include=snapshots`, `versions`, `deleted`, `tags`, and the other values answer `NotImplemented`.

### Leases

Blob and container leases follow [ADR-0017](../adr.d/0017-model-leases-as-a-clocked-state-machine.md): acquire (15 to 60 seconds or `-1`), renew, change, release, and break (period 0 to 60), with `x-ms-lease-state`, `-status`, and `-duration` on Get and Head, container properties, and listings. Every mutating blob operation, Delete Container, and Put Block require `x-ms-lease-id` while a lease is active. Reads, Set Blob Tier, and container metadata or ACL changes accept an optional id that must match. The responses use Azure's codes: `LeaseIdMissing`, `LeaseIdMismatchWithBlobOperation` and `…WithContainerOperation` and `…WithLeaseOperation`, `LeaseNotPresentWith…Operation`, `LeaseAlreadyPresent`, `LeaseLost`, `LeaseIsBreakingAndCannotBeAcquired`, `LeaseIsBreakingAndCannotBeChanged`, and `LeaseIsBrokenAndCannotBeRenewed`. Expiry is evaluated against the clock on each request, and the lease fields persist across restart.

### Copy

Copy Blob, Put Blob From URL, and Put Block From URL accept **same-instance sources only**: a path-style (`http://127.0.0.1:10000/{account}/…`) or host-style URL on this listener. A URL for any other host answers `NotImplemented`, which the manifest records as a known difference. Copies complete synchronously with `x-ms-copy-status: success` and an `x-ms-copy-id`, so Abort Copy always answers `NoPendingCopyOperation` (or `CopyIdMismatch`). The source is readable with the caller's Shared Key inside the same account, with a read SAS on the source URL, or through public access; otherwise the request answers 403 `CannotVerifyCopySource`. Copies of block blobs duplicate the bytes for now; page and append blob copies already share extents (see above), and block blob sharing arrives with snapshots ([ADR-0018](../adr.d/0018-model-snapshots-versions-and-copy-as-immutable-references.md)). Note that `az storage blob copy start --source-blob` builds a `core.windows.net` source URL, so use `--source-uri` with the local URL.

## Authentication

Requests authenticate with Shared Key, Shared Key Lite, an account SAS, a service SAS on a blob or container (`sr=b` or `sr=c`), or anonymously where public access allows ([ADR-0011](../adr.d/0011-compose-authentication-from-shared-primitives.md), [ADR-0019](../adr.d/0019-store-account-level-blob-features-separately.md)).

- SAS strings-to-sign follow signed versions 2015-04-05 through 2023-11-03, including the 2018-11-09 resource fields and the 2020-12-06 encryption scope. Permissions `r a c w d x y l t f m e o p` are accepted; each operation names the letters it needs, and a `c`-only SAS can also overwrite on Put Blob. Stored access policies (`si`) supply permissions and times from the container ACL. `rscc`, `rscd`, `rsce`, `rscl`, and `rsct` override Get Blob headers. Account SAS checks `ss`, `srt`, and `sp`.
- Errors use Azure's codes: `AuthenticationFailed` for signature, window, and resource mismatches, `AuthorizationPermissionMismatch`, `AuthorizationResourceTypeMismatch`, `AuthorizationServiceMismatch`, and `AuthorizationProtocolMismatch` (`spr=https` on this HTTP-only listener).
- `sip` is parsed but not enforced: the listener does not expose the client address to the router. User-delegation SAS (`skoid`) needs Get User Delegation Key and answers `NotImplemented`.
- A container's public access level (`x-ms-blob-public-access`, stored with its ACL) allows anonymous Get Blob, Get Blob Properties and Metadata, and Get Block List at `blob` level, and also List Blobs and Get Container Properties and Metadata at `container` level. A blocked anonymous blob read answers 404 `ResourceNotFound`; other blocked requests answer 403.
- `x-ms-version` is required on Shared Key requests and optional with SAS or anonymous access. `--skip-api-version-check` still lets a client that sends a newer well-formed version use the baseline; the response reports the effective version. `x-ms-client-request-id` is echoed.

## Service properties and CORS

Service properties (logging, metrics, CORS rules, default service version, delete retention, static website) are stored per account and returned on request, with Azure's defaults for a new account; an update changes only the elements it contains. Only CORS is acted on: `OPTIONS` preflights and requests with an `Origin` header are matched against the rules at the HTTP edge. Get Blob Service Stats and Get Account Information return fixed, correctly shaped values.

## Addressing

Both addressing styles work: `http://127.0.0.1:10000/{account}/{container}/{blob}` and `http://{account}.blob.localhost:10000/{container}/{blob}` (any `{account}.blob.{domain}` host). Shared Key signs the path as sent. `UseDevelopmentStorage=true` resolves to the path-style endpoint of the built-in `devstoreaccount1` account. Python's SDK cannot infer the account from a `.blob.localhost` host, so pass `credential={"account_name": …, "account_key": …}`.

## Storage and configuration

- `serve --location ./data` uses SQLite WAL for metadata and filesystem extents for payloads. Uploads are staged, checked, and synced before publishing the metadata reference. Startup reclaims unreferenced files from interrupted writes. Keep the directory private to one process and use a local filesystem. Opening a directory created by an earlier release adds the new columns and tables with defaults (`PRAGMA user_version`); old blobs keep their ETags, and a container keeps its ETag until it changes.
- `serve --in-memory` keeps storage off disk, discards it at shutdown, and defaults to 64 MiB of committed and staged payloads (`--memory-limit` in bytes). Page and append blobs count the bytes of their extents, not their logical length, so a sparse 8 TiB page blob costs nothing until written.
- Per-request limits, all in bytes: `--max-blob-bytes` for a single Put Blob request (default 256 MiB, up to 5000 MiB), `--max-block-bytes` for Put Block (default 5000 MiB), and `--max-assembled-blob-bytes` for a committed block blob (default 512 MiB).
- `--port`, `--admin-port`, and `--bind` select the listeners. Use `--config` for a TOML file; flags override `AZUIFER_*` environment values, then file values, then defaults. Run `cargo run --locked -- config validate` with the same options to validate settings.
- `--skip-api-version-check` is described under Authentication. Omit it for strict mode, or use `--skip-api-version-check=false` to override a setting from the environment or file.
- `--upload-timeout-seconds` bounds time spent receiving a single upload body (1 to 600 seconds; default 60). An incomplete timed-out upload does not replace an existing Blob. `serve --shutdown-on-stdin-eof` lets a process supervisor close a piped stdin to shut the listeners down gracefully.
- `--test-clock` ([ADR-0012](../adr.d/0012-inject-time-through-one-clock.md)) is refused with a non-loopback bind. It adds `GET /_azuifer/clock` and `POST /_azuifer/clock/advance?seconds=N` (or `ms=N`) to the Blob listener, so tests can expire leases, SAS tokens, and policies without sleeping. Signed requests still carry the real date, so keep the total shift under the 15 minute skew window when using Shared Key. The endpoints are on the Blob listener rather than the admin listener.
- A TOML file can use `[[accounts]]` entries with `name` and a `keys` array containing one or two Base64 Shared Keys. Keep such files out of version control. `AZUIFER_ACCOUNT_KEY` overrides the keys for `AZUIFER_ACCOUNT_NAME` (defaults to `devstoreaccount1` if omitted).

Blob names are case-sensitive database keys, not filenames. The [HTTP suite](../../tests/blob_http.rs) checks case and Unicode distinctions across restart, including names reserved by Windows filesystems, and opens a data directory with spaces. Use a private local data path on each host rather than sharing a live SQLite directory across hosts.

## Tests

- The [HTTP suite](../../tests/blob_http.rs) drives the built binary for every operation above: status, headers, body, and resulting state, including lease and SAS tables run on the test clock, anonymous access, CORS, copy, host-style addressing, restart persistence, and opening a data directory from the previous schema.
- The [page and append blob suite](../../tests/blob_page_append_http.rs) drives the built binary for page and append blobs: sparse reads, alignment, sequence numbers, resize, append conditions and sealing, copy and from-URL sources, type errors, quota, restart, and interrupted writes.
- The [Python SDK script](../../tests/blob_sdk.py) runs the official `azure-storage-blob` client against a running Azuifer: containers, properties, metadata, leases, SAS tokens the SDK generates, stored policies, anonymous access, delimiter listings, copy, and service properties. Start Azuifer with `--skip-api-version-check --test-clock`, then run `python tests/blob_sdk.py`. [tests/blob_page_append_sdk.py](../../tests/blob_page_append_sdk.py) does the same for `PageBlobClient` and `AppendBlobClient`.

## Azure CLI

The [Azure CLI matrix](../../tests/azure_cli_matrix.py) tests the newest pinned stable release and the three before it. Each official CLI image is [pinned by digest](../../tests/azure_cli_versions.json), and the suite checks the installed version before running the same [storage workflows](../../tests/azure_cli.py): create/list, upload, rejected overwrite, ETag-conditioned read and delete, exact byte ranges, metadata, and a SHA-256-verified multipart transfer of 256 MiB plus one byte.

Each CLI gets a fresh non-root Azuifer container with a read-only root, isolated loopback, and a synthetic Shared Key. The matrix also checks that `az storage fs` and the [DFS endpoint](dfs.md) can read the same data. The [CI workflow](../../.github/workflows/rust.yml) fails if any version fails and uploads `azure-cli-compatibility`, a JSON report identifying the tested images, API baseline, and results. This proves these workflows against the container; tests against real Azure are separate.

Run the same gate locally with Docker and Python:

```sh
docker build -t azuifer:ci .
python3 tests/azure_cli_matrix.py
```

The report is written to `dist/azure-cli-compatibility.json`. When updating the CLI window, pin the new stable image and keep its three immediate predecessors. Verify all four without skipping failing cases.

The matrix uses `--skip-api-version-check` because these clients request a newer API version than the Blob baseline. To exercise your installed CLI instead, start Azuifer with that flag, a disposable data directory, and a synthetic `AZUIFER_ACCOUNT_KEY`, then run `python3 tests/azure_cli.py` with the same key. `--blob-url` and `--admin-url` select non-default loopback ports. The default single-request limit of 256 MiB already covers the CLI's upload threshold. Beyond the matrix, lease, tier, metadata, `generate-sas`, container policy, service-properties, and `copy start --source-uri` commands were run by hand against this build.

## Container

Follow the [Docker quickstart](../../README.md#run-locally) to build the [Azure Linux image](../../Dockerfile) and try it with Azure CLI. The explicit in-container bind allows port forwarding while the published host ports stay loopback-only. That bind requires a custom Shared Key: use 32 to 64 random bytes encoded in Base64, never a production credential.

The binary runs as UID and GID `65532`. For persistence, mount a volume writable by that user at `/data` and start with `--location /data` in place of `--in-memory`.

The [product specification](../specs/azuifer.md) covers the remaining operations and surfaces.
