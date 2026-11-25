# ADR-0007: Make OpenTelemetry export opt-in

- **Status:** Proposed

## Context

Compatibility and persistence failures need correlated diagnostics. They can occur on requests carrying test keys and signed URLs. Useful observability must not require sending sensitive information or contacting a service that the operator did not choose.

## Decision and scope

Use OpenTelemetry for trace correlation and metrics, and structured logs with request IDs. Network exporters and the Prometheus endpoint are opt-in. Redact secrets before data reaches a log, span, metric, or exporter. Cover request handling, authentication, metadata and content operations, and copies. This governs product diagnostics, not explicitly invoked storage integrations.

## Alternatives and consequences

Plain-text access logs lack context for a multi-step request. Mandatory remote collection would add an external dependency, risk disclosure, and break offline development. Optional export needs local diagnostics and testing for multiple configurations, but does not require a collector to run the emulator.

## Verification criteria

- Default startup makes no telemetry network connections. A configured test collector receives correlated diagnostics on the selected exporter.
- Seeded synthetic credentials, signatures, and authorization headers are absent from captured logs, spans, metrics, and exported payloads.
