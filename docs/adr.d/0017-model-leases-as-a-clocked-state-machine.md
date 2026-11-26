# ADR-0017: Model leases as a clocked state machine

- **Status:** Proposed

## Context

Blob and container leases (and the lease rules DFS and Files reuse) have defined states and transitions: acquire, renew, change, release, break. They also have fixed or infinite durations and break periods. Conflicting requests must fail consistently, and a lease must keep working across restart.

## Decision and scope

Store the lease on the object it protects: id, state, duration, expiry, and break deadline. Compute the effective state (`available`, `leased`, `expired`, `breaking`, `broken`) from the stored fields and the clock ([ADR-0012](0012-inject-time-through-one-clock.md)) inside the same transaction that evaluates a write, so there is no timer thread. Implement one transition table for Blob and container leases, with durations 15 to 60 seconds or infinite and break periods 0 to 60 seconds. Every mutating Blob operation checks `x-ms-lease-id` against the effective state, returning the Azure lease error codes for missing, mismatched, and not-allowed cases. A lease on a blob also governs its snapshots and versions as Azure defines. Leases for FileREST use the same stored fields with their own, simpler transition set and are covered in ADR-0016. DFS lease operations operate on the shared Blob lease.

## Alternatives and consequences

A background timer releasing expired leases is simple but races with requests and needs injectable scheduling. In-memory leases would not survive restart. Lazy evaluation puts the logic in one transition table at the cost of recomputing state on each access.

## Verification criteria

- A table-driven test covers every state, transition, and mismatch for blob and container leases.
- Concurrent acquire requests yield one success and the Azure conflict for the rest.
- A write without the lease id fails while leased, and succeeds after expiry on the manual clock.
- Lease state and breaking deadlines survive restart.
