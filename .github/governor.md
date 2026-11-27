# Azuifer Governor Rules

Repository-specific governance invariants loaded by the `multi-agent-governor` skill on top of its core 4 gates.

## 1. Conformance Honesty
- Never mark an operation `exact` in `specs/conformance/*.json` without a reviewed, passing live Azure cassette for that operation, API version, and auth mode.
- Any operation implemented from Microsoft Learn or SDK behavior without live Azure recordings stays `known-difference` (or `compatible` only where non-material differences are explicitly documented).
- Keep operation names synchronized across Rust `Operation::name()`, `specs/conformance/*.json`, and `docs/compatibility/azure-recording-plan.md`.

## 2. Anti-Fossilization
- Every new `known-difference` behavior or ADR section listing unverified/undocumented Azure behavior must have a corresponding pending row in `docs/compatibility/azure-recording-plan.md` naming the Azure profile required to verify it.
- Track verification debt (`matched / target`) per service on every cycle; call out any branch that expands unverified surface area without logging its recording rows.

## 3. Docs vs. SDK vs. Live-Wire Discrepancy Ledger
- Whenever a live Azure cassette, SDK test, or protocol survey reveals a concrete divergence between Microsoft Learn documentation, official Azure SDKs, and live Azure wire behavior, record it in `docs/compatibility/wire-discrepancies.json` with its evidence reference.
- Allowed categories:
  - `live_vs_docs` — live Azure wire behavior differs from Microsoft Learn docs.
  - `sdk_vs_docs` — official Azure SDK wire behavior differs from Microsoft Learn docs.
  - `live_vs_sdk` — live Azure wire behavior differs from an official SDK expectation.
  - `docs_inconsistency` — Microsoft Learn pages disagree with each other.
  - `undocumented_live` — live Azure behavior not documented in Microsoft Learn.
- Validate with `python scripts/audit-wire-discrepancies.py` (or `uv run scripts/audit-wire-discrepancies.py`).

## 4. Complexity Creep & Boundary Discipline
- Enforce `AGENTS.md`: one implementation per shared concept (Shared Key canonicalization, ETag/range parsing, XML error writing, continuation tokens, SAS validation, leases). Flag per-service re-implementations.
- Keep Blob and DFS on one shared object identity; keep FileREST in its own namespace.
- Flag files crossing 800 lines in active diffs for decomposition review rather than letting them grow unchecked across agent sessions.
- Require explicit justification for any new dependency in `Cargo.toml`.

## 5. Merge Order
- Prefer merging branches closest to `main` and scoped to a single service before branches touching shared core modules (`src/domain.rs`, `src/protocol.rs`, `src/respond.rs`, `src/server.rs`, `src/wire.rs`).
- Every branch must pass `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo test --workspace --all-features` after rebasing onto `main`.
