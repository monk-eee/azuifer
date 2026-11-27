# Table wire compatibility

The Table service runs on its own listener (`--table-port`, default 10002; ephemeral when `--port 0`) with API baseline `2023-11-03`, path-style (`http://127.0.0.1:10002/{account}/...`) and host-style (`http://{account}.table.localhost:10002/...`) endpoints, and JSON payloads only. [The manifest](../../specs/conformance/table.json) is the operation inventory; every state is `implemented`, `known-difference`, or `unsupported`, and nothing has been differentially verified against Azure.

The behavior follows [ADR-0014](../adr.d/0014-evaluate-table-queries-in-rust-over-typed-entities.md): entities are typed values in SQLite, `$filter` is parsed to an AST and evaluated in Rust, and batches commit in one transaction.

## Operations

| Request | Operation |
| --- | --- |
| `GET /Tables`, `GET /Tables('t')` | Query Tables |
| `POST /Tables`, `DELETE /Tables('t')` | Create Table, Delete Table |
| `GET`/`PUT /{table}?comp=acl` | Get and Set Table ACL |
| `GET`/`PUT /?restype=service&comp=properties`, `GET /?restype=service&comp=stats` | Table Service Properties and Stats |
| `GET /{table}()`, `GET /{table}(PartitionKey='p',RowKey='r')` | Query Entities |
| `POST /{table}` | Insert Entity |
| `PUT`, `MERGE`, `PATCH`, `DELETE /{table}(PartitionKey='p',RowKey='r')` | Update, Merge, Delete; without `If-Match`, Insert Or Replace and Insert Or Merge |
| `POST /$batch` | Entity Group Transactions (one change set, or one query) |

`POST` with `X-HTTP-Method: MERGE | PATCH | PUT | DELETE` is accepted as an override. The `-secondary` account suffix (`/{account}-secondary/...` or the host `{account}-secondary.table.{domain}`) answers `GET` only.

## Addressing

Any `{account}.table.{domain}` host names the account, so `http://{account}.table.localhost:10002/Tables` equals `http://127.0.0.1:10002/{account}/Tables`. Shared Key signs the path exactly as sent and the string-to-sign always holds `/{account}` once before it (`/{account}/Tables` host-style, `/{account}/{account}/Tables` path-style). Account and service SAS strings do not depend on the style. The `odata.metadata`, `odata.id` and `Location` URLs use the host the client addressed. `azure-data-tables` takes the account from `AzureNamedKeyCredential`, so it works with a host-style endpoint without further configuration ([`tests/addressing_sdk.py`](../../tests/addressing_sdk.py)); the client machine must resolve `*.localhost` to loopback.

## Authentication

Shared Key and Shared Key Lite use the Table canonicalization: `VERB, Content-MD5, Content-Type, Date`, then `/account` plus the encoded path, and only `?comp=` from the query (`x-ms-date` takes the `Date` position). Account SAS (`ss` must include `t`; `srt` `s`, `c` or `o` by operation; permissions `r w d l a c u`) and service SAS (`tn`, permissions `r a u d`, `spk`/`srk`/`epk`/`erk` ranges, `si` stored policies, string-to-sign by signed version) are verified. Either of two configured account keys validates. Unknown, expired, not-yet-valid, wrong-table, wrong-permission, out-of-range and tampered tokens are refused with 403. Bearer tokens follow the [bearer-token modes](blob.md#bearer-tokens-oauth): 401 `InvalidAuthenticationInfo` by default, validated with `--oauth basic` or `--oauth jwks`.

Known differences: the SAS signed IP range (`sip`) is not enforced because the listener does not expose peer addresses to the router; `spr=https` is refused unless [TLS](blob.md#tls) is enabled. Table ACL calls cannot use SAS; the [read-only settings cassette](../../tests/contracts/cassettes/table-read-only-settings.json) verifies a bearer read of an empty ACL, not a policy write.

## Limits

| Limit | Value |
| --- | --- |
| Table name | 3-63 alphanumerics, starts with a letter, case-insensitive; `tables` is reserved |
| `PartitionKey` / `RowKey` | up to 1024 UTF-16 code units; no `/ \ # ?` or control characters; empty is valid |
| Properties | 252 user properties, names up to 255 characters (letters, digits, `_`, not starting with a digit) |
| Values | strings up to 32K UTF-16 characters, binary up to 64 KiB, entity up to about 1 MiB |
| `$filter` | at most 15 comparisons |
| Page size | `$top` up to 1000 (default 1000) |
| Batch | 100 operations, one table, one partition, each row key once; request body up to 5 MiB |
| `DateTime` | 1601-01-01 through 9999-12-31, 100 ns resolution |

## Representation

All Edm types round-trip: `String`, `Boolean`, `Int32`, `Int64` (JSON string), `Double` (`NaN`, `Infinity`, `-Infinity` as annotated strings; `-0.0` is stored as `0.0`), `DateTime`, `Guid`, and `Binary` (base64), using `<prop>@odata.type` annotations. `nometadata`, `minimalmetadata` and `fullmetadata` come from `Accept` or `$format`; a bare `application/json` is minimal. Null properties are never stored or returned (except `$select` of an absent property, which returns `null`). Timestamps and ETags have 100 ns resolution, never repeat within a run, and the ETag is `W/"datetime'...'"` derived from `Timestamp` (header `ETag` and `odata.etag`).

Table catalog operations omit the legacy `DataServiceVersion` response header. Duplicate create returns `TableAlreadyExists`; reading or deleting a missing named table returns `ResourceNotFound`. The error code is in the negotiated `odata.error` JSON, not in `x-ms-error-code`. The [Azure Table lifecycle cassette](../../tests/contracts/cassettes/table-lifecycle.json) verifies these behaviors for bearer authentication with `odata=nometadata`; it does not cover entity or authentication errors.

## Known differences

- Comparisons in `$filter` need identical Edm types. An unsuffixed integer outside the Int32 range is an `Int64` literal. A missing property satisfies only `ne`. Key ordering uses UTF-8 bytes, not UTF-16.
- No 5 second query timeout, no short pages at partition boundaries, and no `$orderby`, `$skip`, `$expand`, `$count` or filter functions (these return 501 or 400).
- Logging and metrics settings are stored and returned but do not produce analytics data. CORS rules are validated when set and enforced. With no CORS rules, the [read-only settings cassette](../../tests/contracts/cassettes/table-read-only-settings.json) verifies 403 `CorsPreflightFailure` for an anonymous preflight and 400 `InvalidHeaderValue` if a required header is missing. With XML Accept, both errors use OData XML and carry `x-ms-error-code`. The cassette also checks the XML service properties and empty ACL responses without `DataServiceVersion`. Successful preflights with configured rules are not recorded. Service stats are always `live`.
- Batches parse and validate every operation before executing, so error index precedence can differ from Azure when several operations are invalid.
- Atom payloads are rejected with 415 `AtomFormatNotSupported`. An [Atom Accept header](../../tests/contracts/cassettes/table-atom-accept.json) or [Atom `$format` override](../../tests/contracts/cassettes/table-atom-format.json) gets an OData XML error. An [Atom request body with JSON Accept](../../tests/contracts/cassettes/table-atom-content.json) gets a negotiated OData JSON error. These recorded errors carry the code in the body, not in `x-ms-error-code`.
- An [incomplete entity filter](../../tests/contracts/cassettes/table-incomplete-filter.json) returns 400 `InvalidInput` in negotiated OData JSON with the position and expression. That recording does not cover successful entity queries, filter functions, or entity authorization.
- `x-ms-version` values at or below the baseline are accepted and echoed; newer values are accepted (and the baseline reported) only with `--skip-api-version-check`.

## Storage

`serve --location ./data` keeps Table state in `./data/table/` (`table.sqlite3` in WAL mode plus an exclusive `table.lock`); a second process on the same directory fails to start. `--in-memory` keeps it in process memory. State, ETags and stored access policies survive restart.

## Tests

- Unit tests live beside the code in `src/table/` (filter parser and evaluator, Edm serialization, string-to-sign and SAS, batch parsing, ETags).
- [HTTP suite](../../tests/table_http.rs) runs the real binary: table lifecycle, every entity operation, ETag concurrency, batches, paging, limits, authentication, ACLs, and restart persistence. The [addressing suite](../../tests/addressing_http.rs) covers host-style Shared Key, SAS and the secondary host.
- [SDK and CLI script](../../tests/table_sdk.py) drives the `azure-data-tables` Python SDK and the Azure CLI (`az storage table`, `az storage entity`) against the built binary. It is a manual run, not part of `cargo test`:

```sh
pip install azure-data-tables
cargo build
python tests/table_sdk.py            # add --skip-az to omit the Azure CLI checks
```
