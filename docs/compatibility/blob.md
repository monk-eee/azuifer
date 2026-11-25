# First Blob slice

Use the [quick start](../../README.md#run-locally) with the Blob API version `2023-11-03`, path-style endpoints, and Shared Key. [The manifest](../../specs/conformance/blob.json) is the local operation inventory. No operation has been rated against Azure yet.

| Target | Requests implemented |
| --- | --- |
| `/{account}` | `GET` with `comp=list` |
| `/{account}/{container}` | `PUT`, `GET` or `HEAD`, and `DELETE` with `restype=container`; `GET` with `restype=container&comp=list` |
| `/{account}/{container}/{blob}` | `PUT` with `x-ms-blob-type: BlockBlob`; `GET`, `HEAD`, and `DELETE` |

Flat listings support `prefix`, `maxresults`, and opaque local markers. Blob listings also support `include=metadata`. Single-request Blob uploads require `Content-Length` and can validate `Content-MD5`. Blob operations support one `If-Match` or `If-None-Match` condition, and reads accept single byte ranges with a starting offset. Supported Blob properties include content type, length, MD5, ETag, last-modified time, and user metadata.

Other operations and options, including multipart uploads, leases, snapshots, versioning, delimiter listings, SAS, bearer tokens, TLS, host-style addressing, and every non-Blob surface, are not implemented. Unsupported Blob requests receive Azure-shaped errors instead of being forwarded or treated as successful. The emulator writes structured logs locally and does not yet include OpenTelemetry export.

## Storage and configuration

- `serve --location ./data` uses SQLite WAL for metadata and filesystem extents for payloads. Uploads are staged, checked, and synced before publishing the metadata reference. Startup reclaims unreferenced files from interrupted writes. Keep the directory private to one process and use a local filesystem.
- `serve --in-memory` keeps storage off disk, discards it at shutdown, and defaults to 64 MiB of stored payloads (`--memory-limit` in bytes). The default single-upload limit is 16 MiB (`--max-blob-bytes` in bytes) in either mode.
- `--port`, `--admin-port`, and `--bind` select the listeners. Use `--config` for a TOML file; flags override `AZUIFER_*` environment values, then file values, then defaults. Run `cargo run --locked -- config validate` with the same options to validate settings.
- `--skip-api-version-check` lets clients that send a well-formed newer version use the pinned baseline. The server reports the effective version and still rejects unsupported operations and invalid authentication. Omit the flag for strict mode, or use `--skip-api-version-check=false` to override a setting from the environment or file.
- `--upload-timeout-seconds` bounds time spent receiving a single upload body (1 to 600 seconds; default 60). An incomplete timed-out upload does not replace an existing Blob. `serve --shutdown-on-stdin-eof` lets a process supervisor close a piped stdin to shut the listeners down gracefully.
- A TOML file can use `[[accounts]]` entries with `name` and a `keys` array containing one or two Base64 Shared Keys. Keep such files out of version control. `AZUIFER_ACCOUNT_KEY` overrides the keys for `AZUIFER_ACCOUNT_NAME` (defaults to `devstoreaccount1` if omitted).

Blob names are case-sensitive database keys, not filenames. The [HTTP suite](../../tests/blob_http.rs) checks case and Unicode distinctions across restart, including names reserved by Windows filesystems, and opens a data directory with spaces. Use a private local data path on each host rather than sharing a live SQLite directory across hosts.

## Azure CLI

The [Azure CLI suite](../../tests/azure_cli.py) uses a scratch CLI configuration and a synthetic Shared Key to exercise create/list, upload, rejected overwrite, ETag reads, ranged download, and delete. Azure CLI 2.93.0 requests a newer API version, so start Azuifer with `--skip-api-version-check` for this client. The [CI workflow](../../.github/workflows/rust.yml) runs the pinned CLI in the emulator's isolated network namespace, without a cloud account or published ports.

To run it locally, start a disposable in-memory Azuifer instance with `--skip-api-version-check` and a synthetic `AZUIFER_ACCOUNT_KEY`. Run `python tests/azure_cli.py` with the same key and Azure CLI on `PATH`. Use `--blob-url` and `--admin-url` if you changed the listener ports.

## Container

Build the [Azure Linux image](../../Dockerfile) locally. Set `AZUIFER_ACCOUNT_KEY` in your environment to a fresh Base64-encoded random key of 32 to 64 bytes. Don't reuse production credentials.

```sh
docker build -t azuifer:local .
docker run --rm --read-only -p 127.0.0.1:10000:10000 -p 127.0.0.1:10005:10005 -e AZUIFER_ACCOUNT_KEY azuifer:local serve --bind 0.0.0.0 --in-memory
```

The explicit in-container bind allows port forwarding; the published host ports remain loopback-only. For persistence, use `--location /data` instead of `--in-memory` and mount a writable volume at `/data`. The binary runs as UID and GID `65532`.
