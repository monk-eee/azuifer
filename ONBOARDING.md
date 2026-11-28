# Onboarding to Azuifer

## What to read first

1. Read the [project overview](README.md) to understand the project's scope and current status.
2. Read the [specification](docs/specs/azuifer.md), starting with the compatibility contract, functional scope, and delivery roadmap.
3. Use the [ADR index](docs/adr.d/README.md) to find the rationale and verification criteria for the part you want to change. The initial ADRs are proposals, not evidence that the design has been implemented.
4. Read the [contribution guide](CONTRIBUTING.md) before opening an issue or pull request. The [Rust engineering rules](AGENTS.md) apply to both people and agents and define the tests and merge checks.

## The mental model

Clients keep using their storage SDKs or REST tools; the intended change is endpoint configuration. A request enters a service-specific HTTP adapter. Protocol concerns such as version selection, authentication, conditions, and error mapping sit between the adapter and the service's domain logic. The domain logic uses a transaction interface for metadata and streams bytes through the content layer.

Follow a file written through Blob on an HNS-enabled account. DFS reads the same content and object identity; it does not fetch a copy from a second store. A directory move through DFS changes the namespace in one transaction, so Blob listings see the move without a partial tree. See the [namespace decision](docs/adr.d/0003-share-the-blob-and-dfs-namespace.md) and [DFS guide](docs/compatibility/dfs.md) for ranged MD5, file expiry, and recursive ACL traversal.

Azure Files serves a separate share namespace, with [NFS properties and links and SMB permissions](docs/compatibility/files.md) over FileREST, not an SMB or NFS server. Queue and Table have their own domain semantics. A response that looks correct once is not enough: a queue receipt still has to work after a restart, and a failed table partition batch must not leave a partial update.

## Read the evidence

Run `azuifer conformance export --format markdown` to see which of the 153 recognized operations are implemented (151) and which have recorded Azure scenarios. The [recording plan](docs/compatibility/azure-recording-plan.md) tracks pending account profiles and the [Azure cassette guide](docs/compatibility/azure-contracts.md) explains what a match proves. The five official SDK suites and four-version Azure CLI matrix in [CI](.github/workflows/rust.yml) test clients against Azuifer; they do not add live Azure matches.

## First contribution

Follow the [quick start](README.md#run-locally), then run the [merge checks](AGENTS.md#ci-and-completion). Azuifer is one Rust executable. [Protocol parsing](src/protocol) hands typed operations to the [server](src/server.rs); [storage](src/store.rs) applies domain conditions and commits metadata and content without depending on HTTP types.

- If you're new to the project, review one proposed ADR. Check that its scope is bounded, its trade-off is clear, and its verification criteria could actually fail if the invariant is broken.
- If you want to extend an implementation, start with the [service guides](README.md#what-works), then look for the matching protocol, store, and test code. Review the [Rust baseline proposal](docs/adr.d/0002-build-an-independent-rust-binary.md) before splitting modules into crates. Keep the workflow usable on macOS, Linux, and Windows.
- For a protocol contribution, identify the service, operation, API version, and authentication mode. Describe the request, response, and follow-up state a test should observe. The [conformance decision](docs/adr.d/0005-publish-operation-level-conformance.md) explains how that evidence becomes a support claim.

## Where the code lives

| Area | Where to look |
| --- | --- |
| Startup, flags, `doctor`, `conformance export` | [main.rs](src/main.rs), [config.rs](src/config.rs), [commands.rs](src/commands.rs), [conformance.rs](src/conformance.rs) |
| HTTP edge, wire parsing, addressing | [server.rs](src/server.rs), [protocol/](src/protocol), [respond/](src/respond), [address.rs](src/address.rs), [wire.rs](src/wire.rs), [xml_tree.rs](src/xml_tree.rs) |
| Authentication | [auth.rs](src/auth.rs), [sas.rs](src/sas.rs), [delegation.rs](src/delegation.rs), [oauth.rs](src/oauth.rs), [jwt.rs](src/jwt.rs), [tls.rs](src/tls.rs) |
| Blob and DFS (one shared namespace) | [store/](src/store), [dfs/](src/dfs), the `blob_*.rs` modules such as [blob_copy.rs](src/blob_copy.rs) and [blob_lifecycle.rs](src/blob_lifecycle.rs), [blob_query/](src/blob_query) |
| Content and ranges | [ranges/](src/ranges), [extent_readers.rs](src/extent_readers.rs), [checksum.rs](src/checksum.rs) |
| Leases and time | [lease/](src/lease), [clock.rs](src/clock.rs), [stamp.rs](src/stamp.rs) |
| Queue, Table, Azure Files | [queue/](src/queue), [table/](src/table), [files/](src/files), [posix/](src/posix) |
| Persistence safety | [store/schema.rs](src/store/schema.rs) and [store/guard.rs](src/store/guard.rs) refuse newer schemas and linked storage ([ADR-0034](docs/adr.d/0034-refuse-newer-schemas-and-linked-storage.md)) |
| Telemetry and metrics | [telemetry.rs](src/telemetry.rs), [metrics.rs](src/metrics.rs), [runtime_metrics.rs](src/runtime_metrics.rs), [redact.rs](src/redact.rs) |
| Test helpers | [hostile.rs](src/hostile.rs) for hostile-input parser tests, [prng.rs](src/prng.rs) for the seeded model tests |

Integration tests under [tests/](tests) start the built binary. The [Python audit and benchmark scripts](scripts) are stdlib-only; [audit-docs.py](scripts/audit-docs.py) checks that these docs resolve and agree with the conformance manifests.

Local development and ordinary contributions must not need a cloud account or private package feed. Live differential tests are a separate, credential-gated activity; public examples and fixtures use synthetic data.
