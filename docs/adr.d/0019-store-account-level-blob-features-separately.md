# ADR-0019: Store account-level Blob features separately from blob content

- **Status:** Proposed

## Context

Blob clients also use service properties and CORS, container ACLs and public access, blob index tags, and batch requests. They do not belong to a blob's content model, yet they affect every request: CORS must answer preflight, and public access changes authentication.

## Decision and scope

Keep service properties (logging, metrics, CORS rules, default service version, static website, delete retention) in a per-account settings row. Evaluate CORS at the HTTP edge, answering `OPTIONS` and adding `Access-Control-*` headers from the stored rules. Store container ACL and public-access level on the container row; the authentication layer ([ADR-0011](0011-compose-authentication-from-shared-primitives.md)) reads it to permit anonymous requests. Store blob index tags in a separate indexed table so `Find Blobs by Tags` and tag conditions query it without touching content rows. Execute `Submit Batch` by parsing the multipart sub-requests and running each through the normal operation path with its own authorization, returning a multipart response with per-operation results. Settings that a local emulator cannot honor, such as real replication or metrics collection, are accepted and stored but not acted on, and the conformance manifest marks them `known-difference`.

## Alternatives and consequences

Embedding these fields in blob rows spreads account behavior across the content schema. Skipping CORS blocks browser-based clients. A batch that bypasses per-operation authorization would be unsafe, so every sub-request pays the normal parsing cost.

## Verification criteria

- A browser-style preflight returns the configured CORS headers, and requests from non-matching origins do not.
- Anonymous reads succeed only on containers whose public-access level allows them.
- Setting, getting, and filtering by tags works and respects tag conditions.
- A batch of deletes returns correct per-item statuses, including an unauthorized item that does not fail the others.
