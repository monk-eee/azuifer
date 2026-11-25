# Blob wire compatibility

Use the [quick start](../../README.md#run-locally) with the Blob API version `2023-11-03`, path-style endpoints, and Shared Key. [The manifest](../../specs/conformance/blob.json) is the local operation inventory. No operation has been rated against Azure yet.

| Target | Requests implemented |
| --- | --- |
| `/{account}` | `GET` with `comp=list` |
| `/{account}/{container}` | `PUT`, `GET` or `HEAD`, and `DELETE` with `restype=container`; `GET` with `restype=container&comp=list` |
| `/{account}/{container}/{blob}` | `PUT` with `x-ms-blob-type: BlockBlob`; `GET`, `HEAD`, and `DELETE` |
| `/{account}/{container}/{blob}?comp=block` | `PUT` to stage a block by `blockid` |
| `/{account}/{container}/{blob}?comp=blocklist` | `PUT` to commit ordered `Committed`, `Uncommitted`, or `Latest` blocks; `GET` for committed and/or uncommitted block lists |

Flat listings support `prefix`, `maxresults`, and opaque local markers. Blob listings also support `include=metadata`. Uploads require `Content-Length` and verify `Content-MD5` or `x-ms-content-crc64` when supplied. Blob operations support one `If-Match` or `If-None-Match` condition, and reads accept single byte ranges with a starting offset. Supported Blob properties include content type, length, MD5, ETag, last-modified time, and user metadata.

Staged blocks survive restart and remain separate from normal Blob reads until a commit succeeds. A failed commit leaves both the previous content and the staged blocks available. The wire differences still tracked for this operation include Azure's staging expiration, listing uncommitted blobs through `List Blobs`, and Azure's larger size limits.

The [product specification](../specs/azuifer.md) covers the remaining operations and surfaces. Unsupported requests receive Azure-shaped errors.

## Storage and configuration

- `serve --location ./data` uses SQLite WAL for metadata and filesystem extents for payloads. Uploads are staged, checked, and synced before publishing the metadata reference. Startup reclaims unreferenced files from interrupted writes. Keep the directory private to one process and use a local filesystem.
- `serve --in-memory` keeps storage off disk, discards it at shutdown, and defaults to 64 MiB of committed and staged payloads (`--memory-limit` in bytes). The default per-request data limit is 16 MiB (`--max-blob-bytes`). The default assembled block blob limit is 512 MiB (`--max-assembled-blob-bytes`). Both limits are in bytes and apply to either storage mode.
- `--port`, `--admin-port`, and `--bind` select the listeners. Use `--config` for a TOML file; flags override `AZUIFER_*` environment values, then file values, then defaults. Run `cargo run --locked -- config validate` with the same options to validate settings.
- `--skip-api-version-check` lets clients that send a well-formed newer version use the pinned baseline. The server reports the effective version and still rejects unsupported operations and invalid authentication. Omit the flag for strict mode, or use `--skip-api-version-check=false` to override a setting from the environment or file.
- `--upload-timeout-seconds` bounds time spent receiving a single upload body (1 to 600 seconds; default 60). An incomplete timed-out upload does not replace an existing Blob. `serve --shutdown-on-stdin-eof` lets a process supervisor close a piped stdin to shut the listeners down gracefully.
- A TOML file can use `[[accounts]]` entries with `name` and a `keys` array containing one or two Base64 Shared Keys. Keep such files out of version control. `AZUIFER_ACCOUNT_KEY` overrides the keys for `AZUIFER_ACCOUNT_NAME` (defaults to `devstoreaccount1` if omitted).

Blob names are case-sensitive database keys, not filenames. The [HTTP suite](../../tests/blob_http.rs) checks case and Unicode distinctions across restart, including names reserved by Windows filesystems, and opens a data directory with spaces. Use a private local data path on each host rather than sharing a live SQLite directory across hosts.

## Azure CLI

The [Azure CLI matrix](../../tests/azure_cli_matrix.py) tests the newest pinned stable release and the three before it. Each official CLI image is [pinned by digest](../../tests/azure_cli_versions.json), and the suite checks the installed version before running the same [storage workflows](../../tests/azure_cli.py): create/list, upload, rejected overwrite, ETag-conditioned read and delete, exact byte ranges, metadata, and a SHA-256-verified multipart transfer of 256 MiB plus one byte.

Each CLI gets a fresh non-root Azuifer container with a read-only root, isolated loopback, and a synthetic Shared Key. The [CI workflow](../../.github/workflows/rust.yml) fails if any version fails and uploads `azure-cli-compatibility`, a JSON report identifying the tested images, Blob API baseline, and results. This proves these CLI workflows against the container; tests against real Azure are separate.

Run the same gate locally with Docker and Python:

```sh
docker build -t azuifer:ci .
python3 tests/azure_cli_matrix.py
```

The report is written to `dist/azure-cli-compatibility.json`. When updating the CLI window, pin the new stable image and keep its three immediate predecessors. Verify all four without skipping failing cases.

The matrix uses `--skip-api-version-check` because these clients request a newer API version than the Blob baseline. To exercise your installed CLI instead, start Azuifer with that flag, a disposable data directory, and a synthetic `AZUIFER_ACCOUNT_KEY`, then run `python3 tests/azure_cli.py` with the same key. `--blob-url` and `--admin-url` select non-default loopback ports. To allow single-request Azure CLI uploads between 16 and 256 MiB, use `--max-blob-bytes 268435456`.

## Container

Build the [Azure Linux image](../../Dockerfile) locally. Set `AZUIFER_ACCOUNT_KEY` in your environment to a fresh Base64-encoded random key of 32 to 64 bytes. Don't reuse production credentials.

```sh
docker build -t azuifer:local .
docker run --rm --read-only -p 127.0.0.1:10000:10000 -p 127.0.0.1:10005:10005 -e AZUIFER_ACCOUNT_KEY azuifer:local serve --bind 0.0.0.0 --in-memory
```

The explicit in-container bind allows port forwarding; the published host ports remain loopback-only. For persistence, use `--location /data` instead of `--in-memory` and mount a writable volume at `/data`. The binary runs as UID and GID `65532`.
