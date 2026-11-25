# Data Lake Storage Gen2 wire compatibility

Blob and DFS share a store on hierarchical namespace (HNS) accounts. A filesystem created on DFS is visible as a Blob container. A committed Blob is readable as a file on DFS with the same bytes and ETag. Directories, including empty directories, are persistent resources visible on both endpoints.

## Run locally

Enable HNS for a configured account. This example uses the loopback development account:

```sh
cargo run --locked -- serve --in-memory --services blob,dfs --hns-accounts devstoreaccount1
```

The path-style DFS endpoint is `http://127.0.0.1:10003/devstoreaccount1`, and the default Blob port is `10000`. The host-style form `http://devstoreaccount1.dfs.localhost:10003/` (any `{account}.dfs.{domain}` host) addresses the same account without the account path segment; Shared Key signs the path exactly as sent after `/{account}`, so path-style signs `/{account}/{account}/{filesystem}` and host-style signs `/{account}/{filesystem}`. The Data Lake SDKs were not run against host-style endpoints; the [addressing suite](../../tests/addressing_http.rs) covers it over HTTP. Use `--dfs-port` to change the DFS port. Use `--location ./data` instead of `--in-memory` to retain the shared data across restarts. In Docker, publish the DFS port on loopback alongside the Blob and admin ports in the [quickstart](../../README.md#run-locally).

Set `AZUIFER_HNS_ACCOUNTS` or `hns_accounts` in the TOML config as an alternative to `--hns-accounts`. The value is a comma-separated list of configured account names. HNS is off by default. DFS requires Shared Key, including when both listeners are enabled, and rejects authenticated requests to accounts not enabled for HNS. Both listeners use API version `2023-11-03`; `--skip-api-version-check` lets a well-formed newer version use that baseline without bypassing authentication.

## Supported requests

| Target | Requests |
| --- | --- |
| `/{account}?resource=account` | `GET` lists filesystems. Supports `prefix`, `maxResults`, and opaque `continuation` tokens from `x-ms-continuation`. |
| `/{account}/{filesystem}?resource=filesystem` | `PUT` creates, `HEAD` reads properties, and `DELETE` removes the shared container and its contents. |
| `/{account}/{filesystem}?resource=filesystem&recursive={true\|false}` | `GET` lists files and directories, optionally under `directory`. Use `maxResults` and `continuation` to page. |
| `/{account}/{filesystem}/{path}?resource=directory` | `PUT` creates a directory, including missing parents. Use `If-None-Match: *` to prevent replacing an existing directory's properties. |
| `/{account}/{filesystem}/{path}` | `GET` reads committed file bytes; `HEAD` returns file or directory properties. Supports `If-Match` or `If-None-Match`; file reads also support a single `Range` with a starting offset. |
| `/{account}/{filesystem}/{path}?recursive=false` | `DELETE` removes a file or empty directory. A non-empty directory returns `DirectoryNotEmpty` and is not changed. |

On an HNS account, a committed Blob write creates any missing parent directories in the same transaction. Staged blocks do not create visible directories. A file cannot replace a directory or have descendants. Enabling HNS on existing data creates the missing parents without replacing files; startup rejects paths that cannot form a hierarchy. Flat Blob listings show directories; Blob listings with a delimiter still derive prefixes from blob names.

File metadata written by Blob is returned in `x-ms-properties` with base64-encoded values. A Blob lease protects a file from DFS deletion unless the caller supplies the matching lease ID. Filesystem metadata, soft delete, and the filesystem recreation delay are not implemented. Path listings use binary name order, not Azure's slash-first order. DFS file writes, recursive delete, rename, ACLs, lease management, date conditions, and requested range checksums are not implemented. See the [DFS operation inventory](../../specs/conformance/dfs.json) for the tracked differences.

The Azure CLI command `az storage fs file show` also requests the file's ACL, so it isn't supported yet. Use `az storage fs file metadata show` to read user metadata.

## Verify it

The [HTTP tests](../../tests/blob_http.rs) check directory identity across restart, rejected conflicts, and that staged Blob blocks don't publish paths. The [four-version Azure CLI matrix](blob.md#azure-cli) runs `az storage fs directory create` and pages `az storage fs file list` against DFS. It also uses the official Data Lake SDK packaged with each CLI image to read a CLI-uploaded file directly from the DFS port, since the CLI's file download routes through Blob. These checks do not compare against live Azure.
