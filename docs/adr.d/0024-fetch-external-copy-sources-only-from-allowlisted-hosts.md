# ADR-0024: Fetch external copy sources only from allowlisted hosts

- **Status:** Proposed

## Context

Copy Blob and the `From URL` operations name a source URL. Azure fetches an external one itself; [ADR-0018](0018-model-snapshots-versions-and-copy-as-immutable-references.md) left such sources unsupported until an outbound fetch was designed. An emulator that fetches arbitrary URLs becomes a server-side request forgery proxy into the developer's network, which [ADR-0006](0006-default-to-local-only.md) exists to prevent.

## Decision and scope

Make external sources opt-in: `--allow-external-copy-sources` (also `AZUIFER_` and TOML) lists hosts, `host:port` pairs, and `*.domain` suffixes, and is empty by default, so any other source answers `NotImplemented` as before. When enabled, fetch with the existing `reqwest` dependency, resolve the host once and connect to that address, follow no redirects, bound connect and total time, and require an announced length under the assembled-blob limit. Refuse loopback, private, link-local, shared-range, documentation, multicast, and reserved addresses (and IPv4-mapped and NAT64 forms) unless the operator named that exact host or address; a wildcard entry accepts only public addresses. Stream the body into the normal upload path so quotas, checksums, and namespace rules apply. Pass a SAS in the source URL to the source and never log or record it. Complete copies synchronously, as for same-instance sources, and document the difference from Azure's asynchronous copy.

## Alternatives and consequences

Allowing any host is simplest and unsafe. Resolving twice, or following redirects, lets a listed host forward the request to an internal address. Emulating asynchronous copy needs a background copy state machine that no client depends on locally. The cost is an operator step for each external source and a fetch that holds a request slot while it runs.

## Verification criteria

- With no allowlist, no request reaches a source host; a host that is not listed is not contacted.
- Private and metadata addresses are refused for wildcard entries, redirects are refused, and a missing length or an oversize body fails without storing a blob.
- A listed host serves Copy Blob and each `From URL` operation, including a ranged read, and the destination takes the source content properties.
- A source SAS never appears in logs or in the destination's recorded copy source.
