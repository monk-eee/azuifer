# Data Lake Storage Gen2 wire compatibility

Blob and DFS share a store on hierarchical namespace (HNS) accounts. A filesystem created on DFS is visible as a Blob container. A committed Blob is readable as a file on DFS, with the same bytes and ETag.

## Run locally

Enable HNS for a configured account. This example uses the loopback development account:

```sh
cargo run --locked -- serve --in-memory --services blob,dfs --hns-accounts devstoreaccount1
```

The path-style DFS endpoint is `http://127.0.0.1:10003/devstoreaccount1`, and the default Blob port is `10000`. Use `--dfs-port` to change the DFS port. Use `--location ./data` instead of `--in-memory` to retain the shared data across restarts. In Docker, publish the DFS port on loopback alongside the Blob and admin ports in the [quickstart](../../README.md#run-locally).

Set `AZUIFER_HNS_ACCOUNTS` or `hns_accounts` in the TOML config as an alternative to `--hns-accounts`. The value is a comma-separated list of configured account names. HNS is off by default. DFS requires Shared Key, including when both listeners are enabled, and rejects authenticated requests to accounts not enabled for HNS. Both listeners use API version `2023-11-03`; `--skip-api-version-check` lets a well-formed newer version use that baseline without bypassing authentication.

## Supported requests

| Target | Requests |
| --- | --- |
| `/{account}?resource=account` | `GET` lists filesystems. Supports `prefix`, `maxResults`, and opaque `continuation` tokens from `x-ms-continuation`. |
| `/{account}/{filesystem}?resource=filesystem` | `PUT` creates, `HEAD` reads properties, and `DELETE` removes the shared container and its contents. |
| `/{account}/{filesystem}/{path}` | `GET` reads committed bytes and `HEAD` reads properties for a file. Supports `If-Match` or `If-None-Match`; `GET` also supports a single `Range` with a starting offset. |

File metadata written by Blob is returned in `x-ms-properties` with base64-encoded values. Filesystem metadata, soft delete, and the filesystem recreation delay are not implemented. Nested Blob names are readable as files but don't create usable directories on DFS yet. Path listing and writes, rename, ACLs, leases, date conditions, and requested range checksums are not implemented. See the [DFS operation inventory](../../specs/conformance/dfs.json) for the tracked differences.

The Azure CLI command `az storage fs file show` also requests the file's ACL, so it isn't supported yet. Use `az storage fs file metadata show` to read user metadata.

## Verify it

The [HTTP tests](../../tests/blob_http.rs) write over Blob, restart with only DFS enabled, and read and range-check the same file. They also verify that deletion over DFS is visible on the Blob endpoint. The [four-version Azure CLI matrix](blob.md#azure-cli) checks `az storage fs` and uses the official Data Lake SDK packaged with each pinned CLI image to call the DFS port directly. This matters because the CLI's high-level filesystem and file-property calls use Blob. These checks do not compare against live Azure.
