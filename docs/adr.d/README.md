# Architecture decision records

The [product specification](../specs/azuifer.md) describes the target. An ADR records why a bounded choice was proposed, what alternatives it rules out, and what would prove the implementation follows it.

| Record | Status |
| --- | --- |
| [ADR-0001: Record architecture decisions with verification criteria](0001-record-architecture-decisions.md) | Proposed |
| [ADR-0002: Build an independent Rust binary](0002-build-an-independent-rust-binary.md) | Proposed |
| [ADR-0003: Share the Blob and DFS namespace](0003-share-the-blob-and-dfs-namespace.md) | Proposed |
| [ADR-0004: Commit only durable content references](0004-commit-durable-content-references.md) | Proposed |
| [ADR-0005: Publish operation-level conformance](0005-publish-operation-level-conformance.md) | Proposed |
| [ADR-0006: Keep the emulator local by default](0006-default-to-local-only.md) | Proposed |
| [ADR-0007: Make OpenTelemetry export opt-in](0007-opt-in-opentelemetry.md) | Proposed |

Search the index before drafting a record. If a change needs a new decision, use the [template](template.md), pick the next four-digit number, and add the proposed record to the index. Keep separate decisions in separate records.

Maintainers record acceptance after review; publishing a proposal does not accept it. Acceptance records intent, not proof: link actual tests, fixtures, or results from the implementing change. Keep an accepted rationale in history and link a superseding ADR if the decision changes. This collection does not install a blocking check.
