# ADR-0021: Publish one conformance manifest per service

- **Status:** Proposed

## Context

[ADR-0005](0005-publish-operation-level-conformance.md) publishes operation-level conformance but the embedded manifest is Blob-only (`specs/conformance/blob.json`) and uses a flat list of implemented operations. With five services, a single file hides which operations are verified, which differ, and which return stable unsupported errors.

## Decision and scope

Keep one manifest per service under `specs/conformance/` (`blob`, `queue`, `table`, `dfs`, `file`). Each lists every recognized operation with the API version, authentication modes, and one state from the specification: `exact`, `compatible`, `known-difference`, `unsupported`, or `not-applicable`. A state is `exact` only when differential evidence against Azure exists; locally tested but undifferentiated operations are `compatible` or `known-difference` with a note. `conformance export` emits all manifests. Tests check that every operation a router handles appears in its manifest and that every unsupported operation returns the stable Azure-shaped error. Documentation and release notes are generated from the manifests so they cannot claim more than the data.

Keep live evidence separate from those states. The recording-plan audit projects the full exchange target, reviewed cassette counts, recorded and matched exchanges, and explicit matched operation/auth credits into each manifest's `live_azure_evidence` field. It also counts the service's wire ledger entries and records unsupported-operation boundaries separately. `conformance export` embeds these audited projections, so a native binary or container can show the evidence without the repository, Git, or Azure access. A credit identifies a recorded scenario, which can be a rejection; it does not certify the operation, every auth mode, or unrecorded feature profiles. Pending and unmatched exchanges never count as matches.

## Alternatives and consequences

A single combined manifest conflicts on every change and mixes API baselines. Hand-written support tables drift. Per-service manifests need a consistency test and a merge in the exporter.

## Verification criteria

- `conformance export` includes every service manifest and validates against a schema.
- A test fails when a handled operation is missing from, or an unsupported operation is marked implemented in, its manifest.
- No documentation claims `exact` for an operation lacking differential evidence.
- The recording-plan audit rejects a missing or stale evidence projection. The JSON export keeps its existing fields, and both export formats show live Azure progress alongside the operation states.
