# Working on Azuifer

> **Azuifer should contain the minimum amount of code necessary to express Azure Storage semantics correctly.**
>
> Reuse implementations when semantics are shared. Keep them separate when semantics differ. Introduce an abstraction only once its boundary is understood and it removes more complexity than it adds. Every compatibility behavior must be testable.

Start with the [specification](docs/specs/azuifer.md) and [ADR index](docs/adr.d/README.md). The [local Blob guide](docs/compatibility/blob.md) describes the runnable slice. Treat other proposed behavior as a target, never as an implemented endpoint or a passing test.

## Before writing

- Search the workspace for relevant types, parsers, utilities, and boundaries. Extend or refactor the existing implementation instead of creating a parallel one. Don't refactor unrelated code.
- Find the decision that covers the change. If the work introduces a new architectural choice or exceeds the existing scope, draft a bounded ADR before writing code. Link relevant records in the pull request. See [Contributing](CONTRIBUTING.md) for review expectations.

## Reuse and dependency direction

- **One concept, one implementation.** Share Shared Key canonicalization, ETag and range parsing, XML error writing, continuation tokens, HTTP header handling, and SAS validation where the protocol semantics agree. Abstract duplicated knowledge, not duplicated syntax. Compare the Azure contract before sharing code across services; similar-looking Blob and FileREST checks may need different behavior.
- **Start concrete.** Prefer a function, then a module, concrete type, generic type, trait, or macro/code generation. Justify each step toward more abstraction. Use the rule of three with judgment: implement the first case concretely, compare the second, and extract when the third confirms the same behavior. Known cross-cutting concepts such as authentication, ETags, and leases need not wait for three copies.
- **Traits and crates need real boundaries.** Use traits for actual substitution (metadata, content storage, time, or identity validation), not hypothetical mocking. Prefer modules inside a crate. A new crate should justify its dependency direction, ownership, compilation isolation, or value as an independent library. See the [proposed workspace boundaries](docs/adr.d/0002-build-an-independent-rust-binary.md).
- **Dependencies point down.** Service crates use shared core, protocol, auth, and storage foundations, not each other's implementation. Move genuinely shared code below the services. Keep Blob and DFS on one object identity and FileREST in its own namespace. Service code uses the metadata transaction interface.
- Keep each function focused on one operation at one abstraction level. Separate parsing, authorization, domain changes, persistence, and response mapping by responsibility. Don't split clear code merely to satisfy a line count.

## Types, protocol, and errors

- Use validated domain types instead of passing raw strings and numbers through layers: `AccountName`, `ContainerName`, `BlobPath`, `ApiVersion`, `ETag`, `LeaseId`, `RequestId`, `ContentLength`, and `ContinuationToken`. Don't weaken types for convenience.
- Parse and validate wire input once at the protocol boundary, then hand the domain a typed request. Domain code still checks rules that depend on stored state, such as whether an ETag or lease matches. Don't reparse the request in service or storage code.
- Keep `HeaderMap`, `Request<Body>`, and Axum extractors at the HTTP edge. Map the wire request to a typed operation and its typed outcome to the Azure response. Public APIs expose the contract, not incidental implementation details.
- Preserve structured errors in libraries. At the protocol boundary, map errors to the Azure error code, HTTP status, required headers, and body. `anyhow` is appropriate at application seams such as CLI startup, not as the error model for the domain or protocol. Never match on error-message text or turn unsupported operations and persistence failures into successful responses.

## Rust safety and dependencies

- No `unwrap()`, `expect()`, `panic!()`, or `todo!()` on normal request paths. Bound streaming and keep blocking database and filesystem work off async executor threads.
- Explain and narrowly scope any `#[allow(...)]`. No `unsafe` Rust without an ADR explaining why safe Rust cannot reasonably satisfy the requirement and documenting the safety invariants.
- Use the standard library or an existing workspace dependency when it meets the need. Keep builds reproducible with portable tooling and public inputs. Don't add private dependencies or publish credentials, internal links, or real datasets.

## Tests

| What changes | Required evidence |
| --- | --- |
| Bug | Write a regression test first. Show it fails before the fix and passes after it. |
| Reusable primitive | Unit tests for parsing, canonicalization, conditions, ACL evaluation, ETags, ranges, SAS, or continuation behavior as applicable. |
| Azure operation | Protocol tests covering status, headers, body, and resulting state. |
| Important workflow | Integration tests with a running Azuifer server and a real client. |
| CLI flag or command | Drive the built binary, then verify its exit, persisted state, or wire behavior. For Azure CLI, run the real `az storage` workflow against Azuifer. |
| Compatibility claim | Differential tests against Azuifer and real Azure Storage for the operation, API version, auth mode, and feature. Normalize only inherently variable fields the protocol permits to differ. |
| Blob/DFS invariant | Cross-service tests: Blob write then DFS read, DFS write then Blob read, and DFS rename then Blob listing, as applicable to the invariant. |

Test outcomes, not implementation details. For a conditional write, assert the stored content, properties, and ETag, not the number of repository calls. Reserve mocks for external boundaries or difficult-to-induce conditions, not core workflow tests. Cover meaningful behavior and failure paths, such as a lease conflict during an HNS rename; don't optimize for an arbitrary line-coverage percentage. Keep wire behavior, tests, and conformance records in sync. Keep ordinary tests independent of Azure credentials.

## CI and completion

Every implementation change needs appropriate tests. Run the complete affected suites, not just the new test. Use the pinned Cargo toolchain to run the minimum CI merge gate before declaring completion:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Warnings fail the gate. The [CI workflow](.github/workflows/rust.yml) runs the HTTP protocol suite on macOS, Linux, and Windows, drives the Azure Linux container with the real Azure CLI, records Rust coverage, and checks dependencies, vulnerabilities, and licenses. Inspect uncovered behavior and failure paths rather than adding tests just to raise the total. Add cross-service tests when an invariant is touched and fuzz and protected differential suites on an appropriate cadence; a new compatibility claim still needs differential evidence before publication.

Before finishing, inspect your diff for duplication, unnecessary complexity, and unrelated changes. For docs-only changes, check links and consistency across the spec, decision records, and contributor docs. Report what you validated and what you could not run.
