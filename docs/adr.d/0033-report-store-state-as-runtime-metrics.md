# ADR-0033: Report store state as runtime metrics

- **Status:** Proposed

## Context

[ADR-0007](0007-opt-in-opentelemetry.md) required metrics for queue depth, active leases, SQLite contention, garbage collection, and backend failures, but only request metrics existed. The specification listed the rest as not yet emitted. The stores (the shared Blob and DFS namespace, Queue, Table, Files) are opened by their services, not by telemetry, so none of them has a handle to an exporter.

## Decision and scope

Add `src/runtime_metrics.rs`, one source for Prometheus and OTLP.

- **Counters are process-wide atomics** bumped where the event happens: acquisitions of each store's metadata lock (and how many had to wait, and for how long), content files removed, and internal errors by store and kind. A global suits events with no natural owner, such as the shared extent tracker that serves Blob, DFS, and Files, and it keeps the hooks to one line each.
- **Gauges are sampled when read.** A store registers a weak `Probe`; each Prometheus scrape or OTLP collection asks the live stores for their current state, evaluated on the store clock. Active leases count held and still-breaking leases; queue depth counts messages that can be received now and those that are invisible. A dropped store is forgotten. Nothing is cached, so a gauge cannot go stale.
- **The metadata lock is the contention point.** Each store serializes its one SQLite connection behind a mutex, so `SQLITE_BUSY` cannot occur inside a process. The wait for that lock is the queueing an operation experiences, and it is what the contention counters report. SQLite busy and locked errors are still counted, as the `busy` failure kind.
- **Labels are fixed vocabularies plus account and queue names.** No request value, key, signature, or header is a label.

OTLP registers one observable instrument per series that reads the same collection function, so the two exporters cannot disagree. The Prometheus handler renders on the blocking pool because sampling waits for store locks.

## Alternatives and consequences

Passing an exporter handle into every store would touch every constructor and test and still need a place for the shared extent tracker. Pushing gauge changes from each lease and message operation would drift whenever a lease expires by time or a message becomes visible by time, since neither is an event. Sampling costs a short query per scrape; with the default 60 s OTLP interval that is negligible.

A process-wide registry means in-process tests share counters, so unit tests assert increases and the black-box tests assert exact values against a server they started. Counters restart with the process, which Prometheus handles as a reset.

## Verification criteria

- Black-box tests read `GET /metrics` after queue puts, receives, and clears, after lease acquire and release on blobs, containers, shares, and files, after overwrite and delete of disk content, after a restart that finds crash leftovers, and after reading damaged content, and assert the counts.
- An OTLP collector receives each series.
- Seeded credentials are absent from the log file and the metrics after requests carrying them.