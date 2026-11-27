# ADR-0028: Address the root container by a single path segment

- **Status:** Proposed

## Context

Azure has two special container names that Azuifer refused: `$root` and `$logs`. `$root` also has a short form: `https://account.blob.core.windows.net/blob.txt` is a blob in `$root`, because a container operation always carries `restype=container` and a lone path segment without it can only be a blob. Applications and AzCopy that keep files at the top of an account use that form.

## Decision and scope

`ContainerName::parse` accepts `$root` and `$logs` as it accepts `$web`. Before the target is parsed, a request whose logical path is exactly `/{account}/{segment}`, with no `restype=container` and a segment that does not start with `$`, is rewritten to `/{account}/$root/{segment}`. Authorization still signs the path the client sent. The rewrite applies on the Blob listener only; DFS, Table, Queue and Files address resources differently. `$root` and `$logs` otherwise behave as ordinary containers. Azuifer produces no analytics logs, so `$logs` stays empty.

## Alternatives and consequences

Accepting only the explicit `/$root/blob` form would leave the short form, which most clients use, answering a container error. Rewriting in the target parser would need the query there, and its other callers (DFS, batch) have none. The cost is that a container request that omits `restype=container` now reads as a root blob and answers `BlobNotFound` instead of an invalid-query error. Azure behaves the same way.

## Verification criteria

- A blob written to `/{account}/$root/a.txt` reads at `/{account}/a.txt`, and the reverse, with Shared Key signing the path as sent.
- `$root` and `$logs` can be created, listed and deleted; a container request with `restype=container` is never taken for a root blob.
- A differential recording against real Azure is still needed before this is called compatible.
