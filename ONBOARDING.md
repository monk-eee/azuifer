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

Follow the [quick start](README.md#run-locally), then run the [merge checks](AGENTS.md#ci-and-completion). The initial workspace has one executable. [Protocol parsing](src/protocol.rs) hands typed operations to the [server](src/server.rs); [storage](src/store.rs) applies domain conditions and commits metadata and content without depending on HTTP types.

- If you're new to the project, review one proposed ADR. Check that its scope is bounded, its trade-off is clear, and its verification criteria could actually fail if the invariant is broken.
- If you want to extend an implementation, start with the [service guides](README.md#what-works), then look for the matching protocol, store, and test code. Review the [Rust baseline proposal](docs/adr.d/0002-build-an-independent-rust-binary.md) before splitting modules into crates. Keep the workflow usable on macOS, Linux, and Windows.
- For a protocol contribution, identify the service, operation, API version, and authentication mode. Describe the request, response, and follow-up state a test should observe. The [conformance decision](docs/adr.d/0005-publish-operation-level-conformance.md) explains how that evidence becomes a support claim.

Local development and ordinary contributions must not need a cloud account or private package feed. Live differential tests are a separate, credential-gated activity; public examples and fixtures use synthetic data.
