# ADR-0021: Publish one conformance manifest per service

- **Status:** Proposed

## Context

[ADR-0005](0005-publish-operation-level-conformance.md) publishes operation-level conformance but the embedded manifest is Blob-only (`specs/conformance/blob.json`) and uses a flat list of implemented operations. With five services, a single file hides which operations are verified, which differ, and which return stable unsupported errors.

## Decision and scope

Keep one manifest per service under `specs/conformance/` (`blob`, `queue`, `table`, `dfs`, `file`). Each lists every recognized operation with the API version, authentication modes, and one state from the specification: `exact`, `compatible`, `known-difference`, `unsupported`, or `not-applicable`. A state is `exact` only when differential evidence against Azure exists; locally tested but undifferentiated operations are `compatible` or `known-difference` with a note. `conformance export` emits all manifests. Tests check that every operation a router handles appears in its manifest and that every unsupported operation returns the stable Azure-shaped error. Documentation and release notes are generated from the manifests so they cannot claim more than the data.

## Alternatives and consequences

A single combined manifest conflicts on every change and mixes API baselines. Hand-written support tables drift. Per-service manifests need a consistency test and a merge in the exporter.

## Verification criteria

- `conformance export` includes every service manifest and validates against a schema.
- A test fails when a handled operation is missing from, or an unsupported operation is marked implemented in, its manifest.
- No documentation claims `exact` for an operation lacking differential evidence.
