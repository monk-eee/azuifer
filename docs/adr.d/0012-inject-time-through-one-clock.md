# ADR-0012: Inject time through one clock

- **Status:** Proposed

## Context

Queue visibility and TTL, blob and file leases, SAS validity, request date skew, and conditional headers all depend on time. Tests that sleep are slow and flaky, and recovery after restart needs times stored in a stable form.

## Decision and scope

Every service reads time through one `Clock` abstraction with a system implementation and a manual implementation. Persisted timestamps are UTC Unix milliseconds. A running emulator uses the system clock unless started with `--test-clock`; that flag exposes loopback-only administration endpoints to read the clock, advance it, and set it, and the flag is refused with non-loopback binding. Expiry is evaluated lazily when a record is read or modified, so no background timer is required for correctness.

This ADR does not decide response formats for dates; each protocol keeps its own.

## Alternatives and consequences

Calling `SystemTime::now()` directly is simpler but makes lease, visibility, and SAS tests wait in real time. A mocked clock only in unit tests cannot cover the real HTTP and restart paths. A test-clock endpoint adds a hazardous control surface, so it is opt-in and loopback-only.

## Verification criteria

- Unit and HTTP tests advance a manual clock to expire a queue message TTL, a visibility timeout, a lease, and a SAS without sleeping.
- No production request path calls the system clock outside the clock implementation.
- The test-clock endpoints are absent by default and rejected with non-loopback binding.
- Times written before a restart compare correctly with times read after it.
