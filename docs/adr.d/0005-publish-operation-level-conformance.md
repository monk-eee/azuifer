# ADR-0005: Publish operation-level conformance

- **Status:** Proposed

## Context

A service-wide "supported" label cannot tell a client whether a particular operation, API version, or authentication mode behaves as expected. Success responses alone miss conditions, errors, and inconsistent state after the request.

## Decision and scope

Use one version-controlled manifest to classify the operation, version, authentication mode, and feature combinations described by the [compatibility contract](../specs/azuifer.md#4-compatibility-contract). Derive reports for docs, release notes, CLI, and test output from it. Pin versions per service, reject unknown newer versions in strict mode, and make recognized unsupported operations return stable Azure-shaped errors. Record material differences instead of flattening them into a success claim.

The opt-in `--skip-api-version-check` flag lets newer clients use the current baseline. Only a well-formed newer date is eligible: reject older, malformed, or missing versions. Verify the signature over the original request, return the version that actually ran, and log the requested and effective versions without logging credentials. The fallback does not implement newer operations.

Back each compatibility claim with a differential test against real Azure Storage and Azuifer. Compare observable responses and resulting state; normalize only inherently variable fields where the protocol permits it.

## Alternatives and consequences

A manually edited support table is quicker to start but drifts across releases and cannot drive test selection. Claiming parity based on a supported SDK's happy path misses wire and state differences. A manifest and differential evidence cost ongoing maintenance but make the boundary checkable.

## Verification criteria

- Schema and coverage checks detect unclassified recognized operations. The outputs agree with the manifest, including explicit unsupported cases and known differences.
- Version and protocol tests cover version rejection, negotiated behavior where applicable, status, headers, response bodies (including Azure error codes), and post-request state.
- The current pinned Azure CLI release and its three predecessors each run real Blob operations against the release image build in CI. Report per-version outcomes and the tested image IDs. Passing that workflow is client interoperability evidence, not Azure differential evidence.
- Each compatibility claim links to evidence from a protected differential run for the claimed operation, API version, authentication mode, and feature. No credentials or customer data appear in the evidence.
