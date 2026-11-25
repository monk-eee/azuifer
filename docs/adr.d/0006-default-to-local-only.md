# ADR-0006: Keep the emulator local by default

- **Status:** Proposed

## Context

An emulator accepts development credentials and can contain test or copied data. A default network listener would expose it to peers that the local testing model does not trust.

## Decision and scope

Bind service and administrative endpoints to loopback unless the operator explicitly selects another interface. Provide TLS and validated bearer authentication. Treat reduced validation as an explicit controlled-local-test feature, not a deployment mode. Do not silently downgrade validation on errors. Keep the image unprivileged, constrain storage paths and input sizes, and document that untrusted network exposure is unsupported.

## Alternatives and consequences

Binding all interfaces by default would simplify some container setups but would also expose a fresh installation. Removing all test authentication affordances would make isolated tests harder. Default isolation preserves local usability; cross-interface access requires deliberate configuration.

## Verification criteria

- Fresh startup exposes service and admin listeners only on loopback; a non-loopback listener requires explicit configuration.
- Authentication tests demonstrate that invalid bearer credentials fail closed in validated mode, and that reduced validation is never the default or an implicit fallback.
- Container smoke tests verify an unprivileged runtime, and request tests verify enforced input and filesystem boundaries without exposed secrets.
