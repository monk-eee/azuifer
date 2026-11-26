# ADR-0016: Give FileREST its own namespace, leases, and handles

- **Status:** Proposed

## Context

Azure Files shares, directories, and files look similar to Blob containers and DFS paths, but their rules differ: directories must be created explicitly, names are case-insensitive and case-preserving, files have a fixed logical size set by `Create`, quotas apply per share, and handle and lease behavior is distinct. [ADR-0003](0003-share-the-blob-and-dfs-namespace.md) keeps FileREST out of the Blob/DFS namespace.

## Decision and scope

Implement FileREST as its own service with its own store ([ADR-0010](0010-isolate-service-state.md)). Model shares, directories, and files as rows with parent references, so directory rename is one metadata transaction. Use case-insensitive unique names that preserve the original case. Create sets a file's logical size; Put Range, Clear Range, and resize use the range map from [ADR-0015](0015-map-mutable-ranges-over-immutable-extents.md). Support share and directory lifecycle, metadata, properties, quotas and usage, share snapshots, file and share leases, file copy within the instance, listings with continuation, conditionals, and Azure-shaped errors. Open handles are recorded metadata that can be listed and force-closed, since there is no SMB session. SMB and NFS protocol packs are out of scope. Authorization uses the shared primitives in ADR-0011.

## Alternatives and consequences

Reusing the Blob/DFS store would force Blob semantics onto fixed-size, case-insensitive files and risk cross-protocol mutation. A separate model duplicates some listing and condition code, which should be shared only where Azure's behavior agrees.

## Verification criteria

- Name lookup is case-insensitive while listings return the original case.
- Create, range write, range clear, resize, and read agree on size and content, including after restart.
- Directory rename moves the subtree atomically, and deleting a non-empty directory fails with the Azure error.
- No FileREST operation changes any Blob or DFS object.
- Official Files SDK and `az storage file` workflows pass.
