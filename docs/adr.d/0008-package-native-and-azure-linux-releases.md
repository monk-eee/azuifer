# ADR-0008: Package native and Azure Linux releases

- **Status:** Proposed

## Context

Azure Linux is the main container runtime, but contributors also need a native binary. A Linux executable linked to a recent glibc would make working on older distributions unnecessarily hard.

## Decision and scope

Build a static Linux executable for x64 and ARM64. Use it both for the portable Linux archive and as the entry point in the non-root Azure Linux image. Build macOS and Windows binaries on native runners for each architecture. A matching version tag may publish the complete archive set, license texts, checksums, Cargo dependency SBOM, and signed build provenance. Only an explicitly configured Docker Hub repository receives the versioned OCI image. A manual workflow run previews artifacts without publishing them.

## Alternatives and consequences

Depending on a recent glibc would reduce build setup but narrow Linux portability. A separate `.deb` or `.rpm` per distribution would add packaging and maintenance work before the project has a stable release contract. Standalone archives cover more local environments with fewer packaging paths, but users manage installation. Build attestation is not operating-system code signing or macOS notarization.

## Verification criteria

- Extract and run the Linux binary without its build toolchain on Debian, Ubuntu, Alpine, and Red Hat UBI. Run the macOS and Windows binaries on the matching native runners.
- Every archive contains the compiled executable and both license texts. The release rejects a mismatched tag or an incomplete artifact set before publication.
- The Azure Linux image starts as non-root with read-only root and a writable data mount. Publishing requires an explicit Docker Hub destination and emits x64/ARM64 variants plus image SBOM and provenance.
