# Azuifer product and technical specification

**Goal: 100% Azure Storage data-plane wire compatibility.** This specification defines that contract. The [compatibility guide](../compatibility/blob.md) tracks implementation and verification; the [ADR index](../adr.d/README.md) records architecture decisions.

## 1. Product definition

Azuifer is an independent, open-source Rust implementation of the Azure Storage data plane for local development, CI, integration testing, and compatibility testing. The five target surfaces are Azure Blob Storage, Azure Data Lake Storage Gen2 (DFS), Azure Files FileREST, Azure Queue Storage, and Azure Table Storage.

Applications keep their storage client and change endpoint configuration. Azuifer is not a fork, wrapper, process manager, or extension of Azurite. Its distribution target is one Rust binary and an Azure Linux-based OCI image, under `MIT OR Apache-2.0`.

## 2. Positioning relative to Azurite

Azurite is an established option for projects whose Blob, Queue, and Table workflows it covers. Azuifer's intended differentiation is first-class DFS and FileREST, shared Blob/DFS hierarchical behavior, a native Rust runtime without a Node.js sidecar, OpenTelemetry, and measured operation-level conformance. The language choice alone is not a claim about performance or compatibility.

## 3. Engineering goals

Implement all five data-plane surfaces without delegation and preserve Blob/DFS interoperability. Match Azure's request handling, responses, errors, and state transitions, and track every gap until it is closed. Support persistent and in-memory operation, bounded resource usage, local testing on Windows, Linux, and macOS, and a small non-root container usable with Compose and Testcontainers. Scale and durability are measured separately from wire conformance.

## 4. Compatibility contract

The boundary is Azure Storage REST as exercised by supported language SDKs, `az storage`, applicable AzCopy operations, Storage Explorer where it supports custom endpoints, and raw HTTP. Compatibility covers methods, URI forms, query parsing, header canonicalization, XML/JSON shapes, status and error codes, ETags, conditionals, dates, version headers, request IDs, pagination, authentication string-to-sign, leases, concurrency, copy/range semantics, and subsequent state transitions.

Classify each operation, API version, authentication mode, and relevant feature:

| State | Meaning |
| --- | --- |
| `exact` | Observed behavior matches Azure for the tested contract. |
| `compatible` | Normal clients work with a documented, non-material difference. |
| `known-difference` | The operation is implemented but differs materially; the difference is documented. |
| `unsupported` | The operation is recognized but not implemented and returns a stable Azure-shaped error. |
| `not-applicable` | The operation or behavior has no meaningful local equivalent. |

Keep the canonical matrix in version-controlled YAML or JSON. Project it into generated documentation, release notes, CLI output, and test results. Never claim parity beyond the evidence.

Pin a per-service API baseline in a versioned support manifest. Known `x-ms-version` values select the corresponding behavior. Strict mode rejects newer unknown versions; support older versions only when listed. `--skip-api-version-check` can select the nearest supported behavior for a newer unknown version. Report the effective version where the protocol permits. Keep version policy in data, not in unrelated handler constants.

## 5. Functional scope

### Common account model

One process can host multiple accounts. Each account can configure its name, one or two Shared Keys, enabled services, HNS, versioning and other account features, authentication modes, quotas, persistence backend, and optional fault profile. Account configuration or environment variables can supply credentials; rotating a key does not discard stored data.

A built-in local development account should support `UseDevelopmentStorage=true` for Blob, Queue, and Table. Use explicit DFS and FileREST endpoints when a client cannot derive them.

### Blob

- Service properties, CORS, container listing and lifecycle, metadata, ACLs/public access, and container leases.
- Block, page, and append blobs. Put/get/head/delete; metadata/properties; staged blocks and block-list commits; page ranges; append blocks.
- Snapshots, versions, leases, conditionals, range reads and writes, supported checksums, tags, batch operations, copy and abort, and copy/put from URL.
- Listings with prefixes, delimiters, versions, snapshots, tags, and continuation.

Remote copy may initially be limited to the same instance. Document that restriction as `known-difference` when the operation is implemented with that limit.

### DFS and hierarchical namespace

HNS is a core data model, not an adapter over an independent Blob store. Directories are first-class metadata. Writes in either protocol are immediately visible through the other, over a single content copy, with coherent ETags, conditions, and leases. Directory rename is one metadata transaction, not object-by-object copy and delete.

Support file system creation/deletion, file and directory creation, append/flush, reads and properties, path listing and rename, permissions and ACL operations, and version-appropriate leases. Preserve POSIX owner, group, mode, and ACLs. Recursive ACL operations need stable continuation; directory deletion must enforce the DFS non-empty behavior.

For an HNS-enabled account, a Blob write to `foo/bar.md` must be readable through DFS as the same object. After renaming `docs` to `archive` through DFS, Blob lists the new paths without exposing a partial move.

### Azure Files FileREST

Files uses a distinct share and directory namespace. Support share lifecycle, metadata, properties, quotas, statistics, ACLs, leases, and snapshots. Support directory lifecycle and rename; file creation, resize, reads, writes, deletion, ranges and range clearing; metadata, HTTP properties, handles and forced closure, permissions, copy, SAS, conditionals, leases, Azure-shaped errors, and continuation.

FileREST is the v1 protocol. SMB 3.1.1 and NFS 4.1 are possible later protocol packs, not prerequisites.

### Queue

Support properties and CORS; queue lifecycle, metadata, and ACLs; and put, peek, receive, update, delete, and clear operations on messages. Match visibility, TTL, dequeue counts, pop receipt, and encoding behavior. Support Shared Key, account SAS, service SAS, and configured bearer authentication. Do not promise stronger ordering than Azure.

### Table

Support table lifecycle and entity insert, retrieve, replace, merge, delete, insert-or-replace, and insert-or-merge. Implement partition and row keys, ETags and optimistic concurrency, supported OData projections and filters, ordering where allowed, continuation, entity types and serialization, and atomic partition-scoped batches. Include ACLs and service properties as represented by the baseline. Support Shared Key, Shared Key Lite, SAS, and configured bearer authentication. Reject unsupported OData expressions with stable Azure-shaped errors instead of ignoring them.

## 6. System architecture

```text
Azure SDKs / CLI / AzCopy / REST clients
                  |
     Service-specific HTTP adapters
                  |
 Auth / versions / errors / conditions / leases
                  |
   Blob + DFS core     Files / Queue / Table cores
                  |
       Metadata transaction interface
                  |
         SQLite WAL + content store
```

Use Rust from the network boundary to persistence. Separate HTTP parsing and protocol serialization, authentication, service semantics, and storage. Parse and validate wire input once, pass typed operations to the domain, and map typed outcomes and structured errors back to the Azure wire contract. Generated protocol models are allowed; keep service behavior handwritten and testable. Use async network and content I/O, stream bodies, and keep service modules behind the transaction interface. Keep backend seams internal; prioritize one reliable local persistent implementation over a broad plugin framework.

Services depend on the shared core, protocol, auth, and storage foundations, not on other service implementations. Share primitives when their semantics agree; keep protocol differences separate. See the [Rust boundary ADR](../adr.d/0002-build-an-independent-rust-binary.md) and [engineering rules](../../AGENTS.md).

## 7. Persistence model

Use SQLite in WAL mode for metadata, indexes, locks, leases, queue messages, table entities and secondary query structures, and transactions. Metadata also tracks account features, namespaces and objects, versions and snapshots, ETags, conditions, ACLs, handles, copy state, and content references. Store Blob, DFS, and Files payloads in immutable filesystem extents, with temporary staging for incomplete writes and background collection of unreachable content.

Metadata changes commit in SQLite transactions. Stream content into staging, validate length and checksums, and publish the content reference transactionally. Make the referenced extent durably reopenable by the time the transaction commits; no crash may leave committed metadata pointing at a missing extent. Recovery reclaims abandoned staging and unreferenced content without deleting bytes still reachable from objects, snapshots, or versions. See the [persistence ADR](../adr.d/0004-commit-durable-content-references.md) for the proposed ordering.

`--in-memory` is an ephemeral alternative with the same service semantics. It writes no storage data to disk, sets a configurable memory limit, fails predictably when the limit is reached, and reports that state will be lost on shutdown.

## 8. Endpoints and networking

All ports are configurable. The proposed defaults are:

| Surface | Port |
| --- | --- |
| Blob | `10000` |
| Queue | `10001` |
| Table | `10002` |
| DFS | `10003` |
| FileREST | `10004` |
| Administration, health, and metrics | `10005` |

Support path-style addresses such as `http://127.0.0.1:10000/{account}/{container}/{blob}` and host-style addresses such as `http://{account}.blob.localhost:10000/{container}/{blob}`, with corresponding `dfs`, `file`, `queue`, and `table` forms. Bind to loopback by default; non-loopback binding requires explicit configuration. Support TLS using PEM, PFX/PKCS#12, or optional generated development certificates, with shared or per-service certificates.

## 9. Authentication and authorization

- Anonymous Blob access only where public access is allowed.
- Shared Key and, where applicable, Shared Key Lite.
- Account SAS, service SAS, and service-appropriate user-delegation SAS.
- Validated bearer tokens: verify signature, issuer, audience, expiry, and configured claims with local keys or JWKS.
- An explicitly enabled reduced-validation mode for controlled local tests only, with loopback binding by default. It is not a supported network deployment mode.

Return Azure-shaped authentication errors. Do not emit secrets, signatures, SAS tokens, or complete authorization headers in diagnostics.

## 10. Configuration and CLI

Precedence, highest first: command-line arguments, `AZUIFER_*` environment variables, TOML configuration, defaults. Commands:

| Command | Purpose |
| --- | --- |
| `azuifer serve` | Start the configured services. |
| `azuifer serve --in-memory` | Keep storage state in memory only. |
| `azuifer serve --location ./data` | Select a local persistent storage directory. |
| `azuifer serve --services blob,dfs,file` | Start only the selected services. |
| `azuifer status` | Show the status of a running instance from its admin `/healthz` and `/status` (`--admin-url`, `--json`, `--ready`). |
| `azuifer doctor` | Check configuration, port availability, data directory writability and lock, SQLite WAL support, free disk, and container hints. Exits non-zero on a failed check. |
| `azuifer reset --yes` | Delete the emulator state under `--location`. Refuses while another process holds the directory lock. |
| `azuifer conformance export` | Export conformance data. |
| `azuifer config validate` | Validate local configuration. |

Strict protocol behavior is the default. A named compatibility mode may allow selected unknown parameters or headers; each relaxation must be observable in logs and conformance results.

## 11. Observability

Use OpenTelemetry for traces of requests, authentication, metadata transactions, content operations, and copy. Collect metrics for rate, latency, statuses, bytes, queue depth, active leases, SQLite contention, garbage collection, and backend failures. Emit structured logs with request IDs and trace correlation.

Support opt-in OTLP/gRPC, OTLP/HTTP, Prometheus, and structured console/file output. There is no unsolicited product telemetry; diagnostics are not transmitted to external collectors without explicit configuration. Redact sensitive values before export.

Implemented surface: `--otlp-endpoint` (`AZUIFER_OTLP_ENDPOINT`, plain `http://` collectors) with `--otlp-protocol grpc|http` exports a server span for each data-plane request across Blob, DFS, FileREST, Queue, and Table. Authentication and operation execution have `authenticate` and `storage` children when those phases run. Blob and FileREST copies that reach execution, including the supported From URL variants, add a `copy` child on the same server span. Its attributes identify the operation and local or external source kind, not the source URL or credentials. Request text recorded on the server span passes through a redactor that masks configured account keys, SAS signature and similar query values, and Authorization credentials. The [OTLP trace test](../../tests/ops_http/traces.rs) checks exported parent and trace IDs and the absence of synthetic credentials.

OTLP exports request, latency, status, byte, and active-request metrics. `--prometheus` serves the same request metrics at `GET /metrics` on the admin listener. `--log-format json|text` and `--log-file` select the log output. Both exporters also carry the store metrics, read from one source so they agree (OTLP names use dots, for example `azuifer.queue.messages`):

| Prometheus series | Labels | Meaning |
| --- | --- | --- |
| `azuifer_queue_messages` | `account`, `queue`, `state` (`visible`, `invisible`) | Messages in each queue. A queue with no messages reports zero. |
| `azuifer_active_leases` | `kind` (`blob`, `container`, `share`, `file`) | Leases held or still breaking, evaluated on the store clock. A DFS path is a blob. A kind appears once its store is running. |
| `azuifer_store_lock_acquisitions_total`, `_contended_total`, `_wait_seconds_total` | `store` (`namespace`, `queue`, `table`, `files`) | Acquisitions of the metadata lock that serializes each store's SQLite connection, those that had to wait, and the time spent waiting. SQLite is never contended inside a process, so this lock is where operations queue. |
| `azuifer_gc_extents_total`, `azuifer_gc_bytes_total` | `reason` (`reclaimed`, `recovered`) | Disk content files removed: `reclaimed` once nothing references or still reads them, `recovered` when startup found them unreferenced after a crash. In-memory content has no files. |
| `azuifer_backend_failures_total` | `store` (`namespace`, `queue`, `table`, `files`, `content`), `kind` (`database`, `busy`, `io`, `internal`) | Storage failures answered with an internal error. `namespace` serves Blob and DFS; `content` is a streamed read that failed after its response began. |

The counters restart with the process. Labels hold only these fixed values and account and queue names, so no credential reaches a metric; the log and exporter tests assert that.

## 12. Security requirements

Use loopback defaults, explicit non-loopback opt-in, TLS on every service, and an unprivileged user in the container. Use a read-only container root where practical and an explicit writable data directory. Guard against path traversal, symlinks and junctions, oversized headers and requests, and unbounded streaming. Use timing-resistant authentication comparisons and redact credentials and sensitive data from diagnostics.

Audit dependencies and releases, test parsers and signing canonicalization through fuzzing (URI, XML, OData, SAS, and Shared Key), sign release artifacts, and publish SBOMs. Document private reporting in the [security policy](../../SECURITY.md). Direct exposure to untrusted networks is unsupported.

## 13. Packaging and distribution

Release targets are Windows, Linux, and macOS binaries on x64 and ARM64, plus a multi-architecture Azure Linux OCI image. Publish checksums, signatures, provenance attestations, and SBOMs for binaries and images. Provide a Compose example and Testcontainers documentation.

Run all selected surfaces in one process. The image must run as non-root, expose configurable service ports, use a documented persistent volume, support health and readiness probes, and shut down gracefully. Avoid shells and package managers in the runtime image unless diagnostics require them.

## 14. Testing and conformance

Use Rust unit tests, serialization and authentication vectors, persistence and crash recovery, cross-service tests, SDK/CLI/AzCopy integration, differential tests, property and state-machine tests, fuzzing, upgrade/migration checks, and container smoke tests.

Every compatibility claim needs differential evidence for the stated operation, API version, authentication mode, and feature. Run the same scenario against Azuifer and an isolated Azure Storage test account. Compare statuses, headers, error codes, body shapes, state transitions, follow-up reads, listings, and concurrency. Normalize dynamic timestamps and request IDs only where the protocol permits a difference. Run live tests on protected infrastructure with explicit credentials; publish only sanitized fixtures, never credentials or customer data.

Minimum cross-service and persistence cases:

- Blob write to DFS read, and DFS write to Blob read.
- Atomic DFS directory rename reflected in Blob listing.
- Blob versions/snapshots remain coherent through supported DFS views.
- HNS-disabled accounts reject DFS operations correctly.
- FileREST ranges, Queue visibility and pop receipts survive restart.
- A failing Table partition batch leaves no partial writes.
- Concurrent leases yield consistent conflicts.

State-machine tests drive thousands of seeded random operation sequences against a simple oracle written from the documented rules rather than from the implementation, so a failure names its seed and step. The generator is in `src/prng.rs` and adds no dependency. They cover the range map (bytes, allocation, and every refused operation leaving the map unchanged); the blob lease state machine, including time-driven expiry and breaks and each lease-id check (`src/lease/model.rs`); blob snapshots, versions, soft delete, undelete and container restore, with restarts and the exact set of extent files on disk (`src/store/snapshots/model/`); and NFS file shares, with hard links, symbolic links, ranges, copies, renames, snapshots and quota, again with the exact set of extents (`src/files/store/model.rs`).
## 15. Reliability and performance

Stream large payloads within bounded memory, apply backpressure, bound internal queues, and keep blocking SQLite and filesystem work off the async executor. Recover from abrupt termination and preserve committed metadata and content. Expose contention, support parallel test workers and quotas, and make time injectable for TTL, leases, and SAS expiry. Publish release-over-release benchmarks as regression measurements, not comparisons claiming Azure performance equivalence.

The [benchmark runner](../benchmarks.md) measures throughput, latency, and peak process memory for all five services in both storage modes, and compares versioned reports from matching environments.

## 16. Planned repository layout

The following is a target, not a list of existing paths. Introduce pieces as their first consumer lands.

| Area | Proposed contents |
| --- | --- |
| `Cargo.toml`, `crates/` | Candidate crates: `azuifer-server`, `azuifer-protocol`, `azuifer-auth`, `azuifer-core`, `azuifer-storage` (metadata and content modules), `azuifer-blob`, `azuifer-dfs`, `azuifer-files`, `azuifer-queue`, `azuifer-table`, `azuifer-telemetry`, `azuifer-cli`, and `azuifer-testkit`. Split only when there is a concrete boundary. |
| `specs/` | Versioned API manifests and conformance inputs |
| `tests/`, `fuzz/` | SDK, CLI, differential, crash, compatibility, and fuzz suites |
| `docs/` | Specifications, architecture, compatibility, and [decision records](../adr.d/README.md) |
| `packaging/` | Container, Compose, and Testcontainers material |
| Repository root | Contributor and security guidance, code of conduct, and dual license texts |

Generated sources must be reproducible from pinned public inputs and a pinned generator version.

## 17. Open-source governance

Keep the roadmap, issues, material design proposals, ADRs, and conformance data public. Document maintainer and reviewer responsibilities. Use `MIT OR Apache-2.0` and Developer Certificate of Origin sign-off for contributions. Maintain contribution, conduct, and security policies and automate dependency updates. Ordinary contribution tests require no Azure account; maintain credentialed differential tests separately. Releases must be reproducible without a private protocol generator.

## 18. Delivery roadmap

| Milestone | Target |
| --- | --- |
| 0. Foundation | Cargo workspace and [CI merge checks](../../AGENTS.md#ci-and-completion), HTTP and config, account routing, SQLite WAL, content staging, Shared Key/SAS foundations, Azure-shaped errors, OpenTelemetry, Azure Linux image, and conformance schema |
| 1. Blob slice | Containers, block blobs, listings, metadata, conditions, streaming, leases, SDK and CLI validation, and restart tests |
| 2. HNS and DFS | Canonical namespace, HNS accounts, files and directories, append/flush, atomic rename, POSIX and recursive ACLs, and Blob/DFS invariant tests |
| 3. FileREST | Shares, directories, file ranges, permissions, handles, snapshots, copy, SAS, and SDK/CLI validation |
| 4. Queue and Table | Common Queue flows and persisted timing and receipts; Table entities, queries, ETags, partition batches, and SDK/CLI matrices |
| 5. Breadth and hardening | Page/append blobs, versions, snapshots, tags and copy variants, more API versions, OAuth validation, crash/corruption and upgrade tests, fuzzing, and signed platform releases |

Post-v1 possibilities: SMB 3.1.1, NFS 4.1, additional storage backends, fault-injection scenarios, distributed test topologies, Storage Explorer integration, and IDE extensions.

## 19. v1 release criteria

1. All five REST surfaces run from one Rust binary without Azurite or Node.js.
2. Blob and DFS share a namespace; cross-protocol writes, reads, and atomic renames pass tests.
3. FileREST passes its documented core workflow; Queue preserves timing and receipts across restart; Table enforces ETags and atomic partition batches.
4. Supported clients pass the published compatibility matrix. Every recognized operation has a conformance state, and unsupported operations return stable Azure-shaped errors.
5. Persistent state survives abrupt termination tests.
6. OpenTelemetry works without proprietary components, and the Azure Linux container runs as non-root.
7. Release artifacts include signatures, provenance, and SBOMs. No documentation claims parity contradicted by the conformance manifest.

## 20. Project summary

Azuifer targets one locally runnable Rust implementation of five Azure Storage REST surfaces, with a coherent Blob/DFS namespace, a separate Files model, explicit conformance data, and optional standards-based observability. Its value is testable storage behavior for developers and CI, not an assertion that it is the cloud service.
