# ADR-0013: Model queue messages as transactional SQLite state

- **Status:** Proposed

## Context

Queue semantics are defined by visibility timeouts, pop receipts, dequeue counts, and TTL. Clients rely on a received message becoming invisible, on a stale pop receipt being rejected, and on state surviving restart. Azure does not promise strict ordering.

## Decision and scope

Store each queue and message in the Queue store ([ADR-0010](0010-isolate-service-state.md)). A message row holds an opaque id, insertion time, expiry (or none), next-visible time, dequeue count, current pop receipt, and the body exactly as sent. Each operation runs in one SQLite transaction, using the clock from [ADR-0012](0012-inject-time-through-one-clock.md):

- Put creates a message with the requested visibility delay and TTL (default seven days, `-1` for none).
- Get selects up to 32 visible, unexpired messages in insertion order, increments the dequeue count, issues a new pop receipt, and sets the next-visible time, all atomically so concurrent consumers never receive the same message.
- Peek reads without changing state.
- Update and Delete require the current pop receipt; a stale receipt returns `PopReceiptMismatch`. Update may replace the body and visibility, and issues a new receipt.
- Clear removes all messages. Expired messages are ignored on read and purged lazily.

Queue create is idempotent when metadata matches and returns `QueueAlreadyExists` when it differs. Message bodies are not interpreted; Base64 encoding stays a client concern. Enforce the 64 KiB message and metadata limits, queue-name rules, and the XML wire shapes for the supported API version. Do not promise ordering stronger than insertion order among visible messages.

## Alternatives and consequences

An in-memory queue with periodic snapshots is faster but loses receipts and timing on crash. A separate table of in-flight messages adds joins without changing the observable contract. Transactions serialize writers on one database, which is acceptable for local testing.

## Verification criteria

- A message received with a visibility timeout is absent from concurrent Get calls and reappears after the clock advances; its dequeue count and pop receipt differ.
- Update or Delete with a stale pop receipt fails with the Azure code and leaves the message intact.
- Messages, visibility times, receipts, and dequeue counts survive a restart.
- Official Queue SDK and `az storage message` workflows pass against a running server.
