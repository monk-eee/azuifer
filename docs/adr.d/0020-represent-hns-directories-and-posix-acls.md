# ADR-0020: Represent HNS directories and POSIX ACLs on the shared namespace

- **Status:** Proposed

## Context

[ADR-0003](0003-share-the-blob-and-dfs-namespace.md) requires one object identity for Blob and DFS and an atomic directory rename. DFS also has owner, group, permissions, POSIX ACLs, and `flush` semantics for appended files. Blob listings and names need full-path prefix lookup.

## Decision and scope

On an HNS account, store every file and directory under its full normalized path, so Blob prefix and delimiter listings remain index scans. Directories are first-class rows, created implicitly for missing parents by DFS and Blob writes. A directory rename rewrites the path prefix of all descendants in one metadata transaction, with conflicts checked before the commit, so a reader sees the old tree or the new tree. Deleting a non-empty directory requires `recursive=true` and follows DFS continuation. Each object holds owner, group, a permissions mode, and an access ACL; directories also hold a default ACL that new children inherit, subject to the umask. Recursive ACL set, update, and remove run in bounded batches with a continuation token. Append and flush use the range map from [ADR-0015](0015-map-mutable-ranges-over-immutable-extents.md), where flush publishes the length. Shared Key and account SAS bypass ACL checks as Azure does. Bearer tokens are checked against the ACL and the caller's `oid`. An HNS-disabled account rejects DFS with the Azure error.

## Alternatives and consequences

Parent-id storage makes rename cheaper but turns prefix listings into recursive queries and complicates the shared Blob view. Inferring directories from prefixes cannot hold ACLs or empty directories. Prefix rewrite makes large renames proportional to subtree size, which is acceptable locally.

## Verification criteria

- A Blob write to `a/b.txt` is readable and listable through DFS as a file under directory `a`, and the reverse holds.
- A concurrent listing during a rename never shows a partially moved tree.
- Default ACL inheritance, umask, and recursive ACL operations match the documented results, with stable continuation.
- Non-empty delete, rename-over-existing, and HNS-disabled requests return the Azure errors.
- Official Data Lake SDK and AzCopy workflows pass.
