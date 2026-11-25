# ADR-0002: Build an independent Rust binary

- **Status:** Proposed

## Context

The [product specification](../specs/azuifer.md#1-product-definition) targets five protocols with one local lifecycle. Composing multiple emulators would couple users to different runtimes and make shared state harder to reason about.

## Decision and scope

Implement service semantics in Rust, in one executable with selectable services. Keep protocol adapters separate from domain and storage code. Use a reproducible Cargo workspace with the build toolchain and lockfile pinned when the workspace is introduced. Use public dependencies and reproducible public inputs for generated code. Do not delegate a protocol to Azurite, a Node.js process, or real Azure Storage. The Azure Linux image runs the same executable.

## Alternatives and consequences

Wrapping an existing emulator could deliver some endpoints sooner, but would add a runtime and split lifecycle, state, and compatibility ownership. Multiple binaries could isolate services, but would sacrifice the one-command local experience. One native executable makes distribution simpler while leaving all five implementations and platform validation to this project.

## Verification criteria

- A clean checkout builds with the pinned Rust toolchain using only public dependencies; the release image starts as non-root without a Node.js runtime or emulator sidecar.
- Platform release checks exercise the binary on each claimed target, and integration tests verify that it starts only the configured services.
