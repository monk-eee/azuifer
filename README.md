# Azuifer

<p align="center">
  <img src="assets/azuifer_logo.jpg" alt="Azuifer fish mascot holding a storage cube" width="360">
</p>

[![CI](https://github.com/monk-eee/azuifer/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/monk-eee/azuifer/actions/workflows/rust.yml)

**Run Azure Storage clients locally.** Azuifer is a high-fidelity Azure Storage emulator for Blob, Data Lake Storage Gen2 (DFS), Azure Files FileREST, Queue, and Table.

**Wire compatibility is the contract:** supported operations are expected to produce the same observable HTTP behavior and storage state as Azure Storage. Compatibility is published by service, operation, and API version in the [conformance manifests](specs/conformance/), and an operation is only marked as matching Azure once it has been compared against a real Azure account.

All five services run from one binary: Blob on port `10000`, Queue `10001`, Table `10002`, DFS `10003`, and Azure Files `10004`, with health, readiness, and metrics on `10005`. Use `--services` to run a subset. The primary runtime is a non-root Azure Linux container.

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

The readiness endpoint returns `ready`. Blob listens on port `10000`; health, readiness, and status are on `10005`. Both ports are published only on localhost. To reach Queue, Table, DFS, or Azure Files from the host, publish `10001` through `10004` the same way. Check the running instance with `docker exec azuifer-quickstart /azuifer status`.

Observability is opt-in and sends nothing unless you configure a destination: `--prometheus` serves `/metrics` on the admin port, `--otlp-endpoint http://collector:4317` (with `--otlp-protocol grpc|http`) exports traces and metrics, and `--log-format json|text` and `--log-file <path>` select the log output. `azuifer doctor` checks configuration, ports, and the data directory, and `azuifer reset --yes` deletes persisted state while the emulator is stopped. See the [Compose example](packaging/compose.yaml) and the [Testcontainers guide](docs/testcontainers.md).

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

### 3. Optional: HTTPS and bearer tokens

Azure SDKs send bearer tokens only over HTTPS. Start Azuifer with a generated development certificate and reduced-validation bearer tokens, then trust the `tls_cert=` file it prints:

```sh
azuifer serve --in-memory --tls-generate --oauth basic --skip-api-version-check
```

PEM and PFX certificates, validated tokens (`--oauth jwks`), and user-delegation SAS are described in the [Blob guide](docs/compatibility/blob.md#authentication).

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

| Service | Available on Azuifer |
| --- | --- |
| Blob | Containers, block, page, and append blobs, snapshots, versions and soft delete (including soft-deleted containers), blob index tags, Submit Batch, leases, Set Blob Expiry, immutability policies and legal holds, page range diffs, incremental copy, copy within the instance (external sources only when allowlisted), CORS, ACLs and public access, service properties, and a static website served from `{account}.web.localhost` |
| Queue | Queues, metadata, ACLs, service properties, and messages with visibility timeouts, pop receipts, and TTL |
| Table | Tables, ACLs, every entity operation, OData `$filter` and `$select`, paging, ETag concurrency, and atomic entity-group batches |
| Azure Files | Shares, snapshots, directories, files, ranges, rename, copy, leases, permissions, and service properties |
| Data Lake (DFS) | Filesystems and their properties; files and directories with append and flush, reads, atomic rename, recursive delete, leases, POSIX owner, group, permissions and ACLs (default-ACL inheritance, recursive changes) on HNS-enabled accounts, sharing Blob's data and ETags |
| Authentication | Shared Key, Shared Key Lite, account and service SAS (including DFS directory SAS), user-delegation SAS, and bearer tokens (`--oauth`), over HTTP or HTTPS (`--tls-generate`, PEM, or PFX), at path-style or host-style endpoints. DFS checks bearer callers against POSIX ACLs |
| Storage | In-memory or SQLite metadata with persistent payloads, per service |
| Operations | `status`, `doctor`, and `reset` commands, Prometheus metrics, opt-in OpenTelemetry export, and a Compose example |

Each service guide lists the supported operations, limits, and known differences: [Blob](docs/compatibility/blob.md), [Queue](docs/compatibility/queue.md), [Table](docs/compatibility/table.md), [Azure Files](docs/compatibility/files.md), and [Data Lake](docs/compatibility/dfs.md). Blob and DFS see the same data and ETags on hierarchical namespace (HNS) accounts. The [product specification](docs/specs/azuifer.md) tracks the full set of operations.

## Verify compatibility

The [required CI check](https://github.com/monk-eee/azuifer/actions/workflows/rust.yml) runs the current pinned Azure CLI release and its three predecessors against fresh Azuifer containers. It checks bytes, ranges, metadata, rejected overwrites, ETags, and a hash-matching multipart transfer of **256 MiB + 1 byte**. It also checks `az storage fs` and uses the CLI image's Data Lake SDK to read CLI-uploaded bytes over the DFS endpoint. Each run publishes the image IDs and per-version outcomes as `azure-cli-compatibility`.

See [how to run the same matrix locally](docs/compatibility/blob.md#azure-cli). A separate CI job runs [30 .NET SDK scenarios](tests/dotnet_sdk/Program.cs) (`dotnet run --project tests/dotnet_sdk` against a server started with `--services blob,queue,table,file,dfs --hns-accounts devstoreaccount1`) through the Blob, Queue, Table, Files and Data Lake clients: chunked parallel transfers, SAS, leases, tags, batch delete, table transactions, DFS rename and ACLs. These show that the .NET clients complete those workflows against Azuifer, not that responses match Azure. A matching [JavaScript SDK job](tests/js_sdk/probe.js) (`npm ci && node probe.js` there) runs 21 scenarios through the five JavaScript clients; the Data Lake client needs a host-style URL on a non-emulator port (see [dfs.md](docs/compatibility/dfs.md#data-lake-sdks-and-the-azure-cli)). A [Java SDK job](tests/java_sdk/src/main/java/probe/Probe.java) runs 19 scenarios (`mvn compile exec:java` there); the Java Files client ignores the port and account path of its endpoint, so Files needs a host-style URL on port 80 (`--file-port 80`). A [Go SDK job](tests/go_sdk/main.go) runs 11 scenarios (`go run .` there; use an IP address as the host, because the Go SDKs read other host names as host-style). To see the operation inventory from your built image:

```sh
docker run --rm azuifer:quickstart conformance export
```

The [Azure contract harness](docs/compatibility/azure-contracts.md) can separately compare a Blob SAS scenario with a dedicated Azure test account. The regular Rust suite replays contract fixtures offline; it doesn't need Azure credentials.

## Build natively

Use Rustup and a C compiler for bundled SQLite: Command Line Tools on macOS, GCC or Clang on Linux, or MSVC Build Tools on Windows. From the repository root:

```sh
cargo run --locked -- serve --in-memory
```

Native runs use the same ports. Use `--location ./data` for persistence or `--skip-api-version-check` for clients that send a newer API version than the `2023-11-03` baseline; older versions are served with baseline behavior. SDKs that accept `UseDevelopmentStorage=true` can use it with the loopback endpoints.

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
