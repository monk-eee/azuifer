# Azuifer

<p align="center">
  <img src="assets/azuifer_logo.jpg" alt="Azuifer fish mascot holding a storage cube" width="360">
</p>

[![CI](https://github.com/monk-eee/azuifer/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/monk-eee/azuifer/actions/workflows/rust.yml)

**Run Azure Storage clients locally.** Azuifer is a high-fidelity Azure Storage emulator for Blob, Data Lake Storage Gen2 (DFS), Azure Files FileREST, Queue, and Table.

**Wire compatibility is the contract:** supported operations are expected to produce the same observable HTTP behavior and storage state as Azure Storage. Compatibility is published by service, operation, and API version in the [conformance manifests](specs/conformance/), and an operation is only marked as matching Azure once it has been compared against a real Azure account.

Blob is available now: create containers, upload and download block blobs, read byte ranges, and keep data across restarts. Queue, Table, DFS, and Azure Files are landing next. The primary runtime is a non-root Azure Linux container.

[Docker quickstart](#run-locally) | [Connect an SDK](#connect-an-sdk) | [Supported operations](#what-works) | [Compatibility evidence](#verify-compatibility)

## Run locally

### 1. Start the container

These Bash commands use Git, Docker, OpenSSL, and Azure CLI (`az`). No Azure account or `az login` is needed. Use the same shell for both steps so the client gets the disposable key.

```sh
git clone https://github.com/monk-eee/azuifer.git
cd azuifer
docker build -t azuifer:quickstart .

export AZUIFER_ACCOUNT_KEY="$(openssl rand -base64 32)"
docker run --detach --rm --name azuifer-quickstart --read-only \
  -p 127.0.0.1:10000:10000 -p 127.0.0.1:10005:10005 \
  -e AZUIFER_ACCOUNT_KEY azuifer:quickstart \
  serve --bind 0.0.0.0 --in-memory --skip-api-version-check
curl --noproxy 127.0.0.1 --fail --retry 5 --retry-connrefused http://127.0.0.1:10005/readyz
```

The readiness endpoint returns `ready`. Blob listens on port `10000`; health and readiness are on `10005`. Both ports are published only on localhost.

### 2. Upload and download a blob

```sh
export AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=$AZUIFER_ACCOUNT_KEY;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
scratch="$(mktemp -d)"
printf 'hello Azuifer\n' > "$scratch/hello.txt"

az storage container create --name example --auth-mode key --output none
az storage blob upload --container-name example --name hello.txt \
  --file "$scratch/hello.txt" --overwrite false --auth-mode key --output none
az storage blob download --container-name example --name hello.txt \
  --file "$scratch/downloaded.txt" --auth-mode key --output none
cmp "$scratch/hello.txt" "$scratch/downloaded.txt" && printf 'Download matches the upload.\n'
```

This run keeps data in memory. To use a persistent Docker volume, add `--mount type=volume,source=azuifer-data,target=/data` before the image name and replace `--in-memory` with `--location /data`. Keep the same key and volume when recreating the container.

## Connect an SDK

Leave the container running and reuse `AZURE_STORAGE_CONNECTION_STRING` from the quickstart. The endpoint includes the account name, and the Blob API baseline is `2023-11-03`. The quickstart enables version fallback for newer Azure CLI clients; omit `--skip-api-version-check` when testing a client pinned to the baseline.

For example, with `azure-storage-blob` installed, read the same blob from Python:

```python
import os

from azure.storage.blob import BlobServiceClient

with BlobServiceClient.from_connection_string(
    os.environ["AZURE_STORAGE_CONNECTION_STRING"], api_version="2023-11-03"
) as service:
    blob = service.get_blob_client(container="example", blob="hello.txt")
    print(blob.download_blob().readall().decode(), end="")
```

Stop the container with `docker stop azuifer-quickstart` when you're done.

## What works

| Workflow | Available on Azuifer |
| --- | --- |
| Authentication | Shared Key at a path-style endpoint |
| Blob containers | Create, list, read properties, and delete |
| Block blobs | Upload, read, list, delete, stage blocks, and get or commit block lists |
| Reads and writes | Byte ranges, ETag conditions, upload checksums, and metadata on writes |
| Data Lake (DFS) | Manage filesystems, create and list directories, read Blob-written files, and delete files or empty directories on HNS-enabled accounts |
| Storage | In-memory or SQLite metadata with persistent payloads |

Use the [Blob guide](docs/compatibility/blob.md) and [Data Lake guide](docs/compatibility/dfs.md) for supported operations, flags, and limits. Blob and DFS see the same data and ETags on hierarchical namespace (HNS) accounts. The [product specification](docs/specs/azuifer.md) tracks the full set of operations.

## Verify compatibility

The [required CI check](https://github.com/monk-eee/azuifer/actions/workflows/rust.yml) runs the current pinned Azure CLI release and its three predecessors against fresh Azuifer containers. It checks bytes, ranges, metadata, rejected overwrites, ETags, and a hash-matching multipart transfer of **256 MiB + 1 byte**. It also checks `az storage fs` and uses the CLI image's Data Lake SDK to read CLI-uploaded bytes over the DFS endpoint. Each run publishes the image IDs and per-version outcomes as `azure-cli-compatibility`.

See [how to run the same matrix locally](docs/compatibility/blob.md#azure-cli). To see the operation inventory from your built image:

```sh
docker run --rm azuifer:quickstart conformance export
```

## Build natively

Use Rustup and a C compiler for bundled SQLite: Command Line Tools on macOS, GCC or Clang on Linux, or MSVC Build Tools on Windows. From the repository root:

```sh
cargo run --locked -- serve --in-memory
```

Native runs use the same Blob and admin ports. Use `--location ./data` for persistence or `--skip-api-version-check` for newer CLI clients. SDKs that accept `UseDevelopmentStorage=true` can use it with the loopback Blob endpoint and the pinned API version.

## Project docs

| Start here | What you'll find |
| --- | --- |
| [Onboarding](ONBOARDING.md) | How the pieces fit together and where to contribute |
| [Architecture decision records](docs/adr.d/README.md) | Design choices, alternatives, and the evidence each choice will need |
| [Contributing](CONTRIBUTING.md) | How to propose, validate, and review changes |
| [Releases](docs/releases.md) | Native archives, the Azure Linux image, and Docker Hub opt-in |
| [Security policy](SECURITY.md) | How to report a security issue privately |
| [Agent instructions](AGENTS.md) | Constraints for automated contributors |

Azuifer is not affiliated with or endorsed by Microsoft. The repository is licensed under either the [MIT License](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option.
