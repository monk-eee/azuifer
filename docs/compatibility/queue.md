# Queue wire compatibility

Azuifer serves the Azure Queue Storage data plane on its own listener (default port `10001`, `--queue-port` to change it; `--port 0` makes it ephemeral). The implemented API baseline is `2023-11-03` and the operation inventory is [`specs/conformance/queue.json`](../../specs/conformance/queue.json). No operation has been compared with real Azure yet, so none is rated `exact`; see [ADR-0013](../adr.d/0013-model-queue-messages-in-sqlite.md) and [ADR-0021](../adr.d/0021-publish-one-conformance-manifest-per-service.md).

Start it with `azuifer serve --services queue --in-memory`. Current Azure SDKs and `az` request API versions newer than the baseline, so add `--skip-api-version-check`. Connect with a connection string such as:

```text
DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=<key>;QueueEndpoint=http://127.0.0.1:10001/devstoreaccount1;
```

`devstoreaccount1` and its public key are the default account; `AZUIFER_ACCOUNT_NAME`/`AZUIFER_ACCOUNT_KEY` or a TOML `[[accounts]]` entry replace them.

## Addressing

Both styles work: `http://127.0.0.1:10001/{account}/{queue}/messages` and `http://{account}.queue.localhost:10001/{queue}/messages` (any `{account}.queue.{domain}` host). In the host-style form the path does not repeat the account, and Shared Key and Shared Key Lite sign the path exactly as sent, so the canonical resource is `/{account}/{queue}/messages` host-style and `/{account}/{account}/{queue}/messages` path-style. Service SAS strings use `/queue/{account}/{queue}` either way. List Queues reports `ServiceEndpoint` as the host the client used. `azure-storage-queue` cannot infer the account from a `.queue.localhost` host and raises `Unable to determine account name`, so pass `credential={"account_name": ..., "account_key": ...}`; the client then works against `http://{account}.queue.localhost:PORT` ([`tests/addressing_sdk.py`](../../tests/addressing_sdk.py)). The client machine must resolve `*.localhost` to loopback.

## Operations

| Operation | Request | Success |
| --- | --- | --- |
| Get / Set Queue Service Properties | `GET`/`PUT /{account}?restype=service&comp=properties` | 200 / 202 |
| Get Queue Service Stats | `GET /{account}?restype=service&comp=stats` | 200 |
| Preflight Queue Request | `OPTIONS` on any queue URL | 200 |
| List Queues | `GET /{account}?comp=list` (`prefix`, `marker`, `maxresults`, `include=metadata`) | 200 |
| Create Queue | `PUT /{account}/{queue}` | 201, or 204 for identical metadata |
| Delete Queue | `DELETE /{account}/{queue}` | 204 |
| Get / Set Queue Metadata | `GET`/`HEAD`/`PUT /{account}/{queue}?comp=metadata` | 200 / 204 |
| Get / Set Queue ACL | `GET`/`PUT /{account}/{queue}?comp=acl` | 200 / 204 |
| Put Message | `POST /{account}/{queue}/messages` (`visibilitytimeout`, `messagettl`) | 201 |
| Get / Peek Messages | `GET /{account}/{queue}/messages` (`numofmessages`, `visibilitytimeout`, `peekonly=true`) | 200 |
| Update Message | `PUT /{account}/{queue}/messages/{id}?popreceipt=&visibilitytimeout=` | 204 |
| Delete Message | `DELETE /{account}/{queue}/messages/{id}?popreceipt=` | 204 |
| Clear Messages | `DELETE /{account}/{queue}/messages` | 204 |

Every response carries `x-ms-request-id`, `x-ms-version` and `date`; `x-ms-client-request-id` is echoed. Errors use Azure's XML shape with `x-ms-error-code`, and the message includes `RequestId:` and `Time:` lines. Message and ACL times in XML bodies use RFC 1123 and ISO 8601 respectively; a message that never expires reports `Fri, 31 Dec 9999 23:59:59 GMT`.

## Authentication

| Mode | Notes |
| --- | --- |
| Shared Key | Queue canonicalization: the Blob string-to-sign with the resource `/{account}{path}` plus sorted `name:value` query lines. Because the URL path already holds the account, it appears twice, as the Azure emulator contract expects. Either of two account keys validates. |
| Shared Key Lite | `VERB, Content-MD5, Content-Type, Date, CanonicalizedHeaders` and a resource carrying only `comp`. |
| Account SAS | Checks signature (including the encryption scope line from `2020-12-06`), validity window, `spr`, service `q`, resource type `s`/`c`/`o` and permission per the [account SAS table](https://learn.microsoft.com/rest/api/storageservices/create-account-sas). |
| Service SAS | Resource `/queue/{account}/{queue}` with the field set of the signed version (legacy through `2023-11-03`); permissions `r a u p` only; `si` resolves a stored access policy for missing `sp`/`st`/`se`. |
| Anonymous | Rejected with 403 `AuthenticationFailed`. |

Wrong service, resource type, permission or protocol return `AuthorizationServiceMismatch`, `AuthorizationResourceTypeMismatch`, `AuthorizationPermissionMismatch` and `AuthorizationProtocolMismatch`. Operations a service SAS cannot grant (create, delete, list, clear, set metadata or ACL, service operations) are rejected. Bearer tokens and user delegation SAS are not supported.

## Limits and behavior

- Message text is limited to 64 KiB (UTF-8 bytes); more returns 413 `RequestBodyTooLarge`. `messagettl` is `1` or more seconds or `-1`; the default is 7 days. `visibilitytimeout` is `0`-`604800` on put and update and `1`-`604800` (default 30) on get. `numofmessages` is `1`-`32`. Put requires `visibilitytimeout` below `messagettl`.
- Queue names are 3-63 characters of lowercase letters, digits and single hyphens that neither start nor end the name. Length failures return `OutOfRangeInput`, other failures `InvalidResourceName`. Metadata is limited to 8 KiB, names must be identifiers, and names are returned lower-cased. Up to five stored access policies are allowed.
- Each operation is one SQLite transaction through `spawn_blocking`. Times are Unix milliseconds from the injectable `Clock`; expired messages are ignored on read and purged on the next write to that queue. Dequeue count, pop receipt and visibility survive restart and an abrupt kill.
- Persistent state lives in `<location>/queue/queue.sqlite3` (WAL) with its own `queue.lock`; a second process on the same directory is refused. `--in-memory` keeps it in memory.
- Messages are served in insertion order, which Azure does not guarantee.

## Known differences

- `sip` is signed but not enforced (the router sees no peer address); `spr=https` is always rejected because the listener is plain HTTP.
- Logging and metrics settings are stored and returned but no analytics data is produced. Get Queue Service Stats is served on the primary endpoint with a constant `live` status.
- Deleted queues can be recreated immediately (`QueueBeingDeleted` is not modeled). An Update Message visibility time is not capped at the expiry time.
- `AuthenticationErrorDetail` is omitted so no signing material is echoed. Pop receipts are opaque Base64 values, not Azure's format, and list markers are local tokens.
- `x-ms-version` reports the baseline; older versions are rejected and newer ones need `--skip-api-version-check`.
- With `--test-clock`, the admin listener serves `GET /_azuifer/clock` and `POST /_azuifer/clock/advance?seconds=N` (or `ms=N`) for the one clock every service shares ([ADR-0012](../adr.d/0012-inject-time-through-one-clock.md)), so visibility timeouts and TTLs expire without sleeping. Signed dates still need to follow the server clock, or stay inside the 15 minute skew window.

## Tests

- `cargo test` runs the unit tests (XML, string-to-sign, store with an advanced `Clock`, routing, CORS) and the [HTTP suite](../../tests/queue_http.rs), which starts the real binary and covers lifecycle, visibility, pop receipts, TTL, restart and crash persistence, all authentication modes and failures, ACLs, CORS and version policy. The [addressing suite](../../tests/addressing_http.rs) covers host-style Shared Key and SAS, and the [shared clock suite](../../tests/shared_clock_http.rs) advances the admin `--test-clock` and observes visibility and TTL expiry over HTTP.
- [`tests/queue_sdk.py`](../../tests/queue_sdk.py) drives `azure-storage-queue` and [`tests/queue_azure_cli.py`](../../tests/queue_azure_cli.py) drives `az storage queue` and `az storage message`. They are run manually (`pip install azure-storage-queue`) against a server started as above and are not part of `cargo test`.
