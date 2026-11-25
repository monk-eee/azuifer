# ADR-0005: Publish operation-level conformance

- **Status:** Proposed

## Context

A service-wide "supported" label cannot tell a client whether a particular operation, API version, or authentication mode behaves as expected. Success responses alone miss conditions, errors, and inconsistent state after the request.

## Decision and scope

Use one version-controlled manifest to classify the operation, version, authentication mode, and feature combinations described by the [compatibility contract](../specs/azuifer.md#4-compatibility-contract). Derive reports for docs, release notes, CLI, and test output from it. Pin versions per service, reject unknown newer versions in strict mode, and make recognized unsupported operations return stable Azure-shaped errors. Record material differences instead of flattening them into a success claim.

## Alternatives and consequences

A manually edited support table is quicker to start but drifts across releases and cannot drive test selection. Claiming parity based on a supported SDK's happy path misses wire and state differences. A manifest and differential evidence cost ongoing maintenance but make the boundary checkable.

## Verification criteria

- Schema and coverage checks detect unclassified recognized operations. The outputs agree with the manifest, including explicit unsupported cases and known differences.
- Version and protocol tests cover rejection, negotiated behavior where applicable, errors, and post-request state. A protected differential run links `exact` claims to evidence without exposing credentials or customer data.
