# Azuifer Governor Rules

Repository-specific governance invariants loaded by the `multi-agent-governor` skill on top of its core 4 gates. These extend the [conformance decision](../docs/adr.d/0021-publish-one-conformance-manifest-per-service.md); they do not add a new runtime contract.

## Running a cycle

Use `uv run ~/.copilot/skills/multi-agent-governor/scripts/audit_governance.py --repo .`
from this checkout, or invoke that script with an active virtualenv's Python.
The installed skill owns the reusable core. [governor.json](governor.json) loads
the ledger audit and category tally automatically; no core edits are needed.
Use the checkout being audited as `--repo`: unmerged extension files in another
worktree are not loaded.

The recording-plan audit is conditional until the cassette branch supplies
its script. A `skipped` result means evidence auditing is unavailable, **not a
passing conformance gate**. Once the script exists, its failures must be reported.
Missing or malformed ledger data must fail the mandatory ledger audit, even if
the core tally reader omits it. Core audit exit status alone is not a four-gate
pass: inspect extension results, merge conflicts, overlaps, and safety findings.

## 1. Conformance Honesty
- Never mark an operation `exact` in `specs/conformance/*.json` without a reviewed, passing live Azure cassette for that operation, API version, and auth mode.
- Any operation implemented from Microsoft Learn or SDK behavior without live Azure recordings stays `known-difference` (or `compatible` only where non-material differences are explicitly documented).
- Keep operation names synchronized across Rust `Operation::name()`, the [service manifests](../specs/conformance), and the recording plan when present.

## 2. Anti-Fossilization
- Every new `known-difference` behavior or ADR section listing unverified/undocumented Azure behavior must have a corresponding pending row in the recording plan naming the Azure profile required to verify it. Until that plan lands, explicitly report the missing tracking coverage rather than crediting it as verified.
- Track verification debt (`matched / target`) per service on every cycle; call out any branch that expands unverified surface area without logging its recording rows.

## 3. Docs vs. SDK vs. Live-Wire Discrepancy Ledger
- Record concrete divergences in the [wire ledger](../docs/compatibility/wire-discrepancies.json) with separate, pinned documentation/SDK sources and scoped live evidence where applicable.
- Allowed categories:
  - `live_vs_docs` — live Azure wire behavior differs from Microsoft Learn docs.
  - `sdk_vs_docs` — official Azure SDK wire behavior differs from Microsoft Learn docs.
  - `live_vs_sdk` — live Azure wire behavior differs from an official SDK expectation.
  - `docs_inconsistency` — Microsoft Learn claims disagree, within one page or across pages.
  - `undocumented_live` — live detail absent from the cited Learn pages; not proof that no documentation anywhere mentions it.
- Count `entries` only. Keep documented matches and unsubstantiated leads in `observations`, excluded from the discrepancy tally. Do not invent a disagreement to make a category non-zero.
- Live references use `commit:tests/contracts/cassettes/name.json#step`, `source=azure`, API version, and auth mode. The initial live references are on the unmerged cassette branch; their allowlisted findings are described in the ledger, but their fixtures are not available for replay on `main` yet. Do not advertise them as merged fixtures or new passing differential tests.
- `observed` means a source finding, not Azuifer alignment. NFS SDK/docs mismatches remain `awaiting_live_recording`; ledger validation checks structure and scope, not live parity.
- Initial IDs WD-005 through WD-008 are not counted: the prior draft did not establish a docs/SDK disagreement for those claims. Preserve the surviving IDs rather than renumbering history.
- Validate with `python scripts/audit-wire-discrepancies.py` (or `uv run scripts/audit-wire-discrepancies.py`).

## 4. Complexity Creep & Boundary Discipline
- Enforce [AGENTS.md](../AGENTS.md): one implementation per shared concept (Shared Key canonicalization, ETag/range parsing, XML error writing, continuation tokens, SAS validation, leases). Flag per-service re-implementations.
- Keep Blob and DFS on one shared object identity; keep FileREST in its own namespace.
- Flag files crossing 800 lines in active diffs for decomposition review rather than letting them grow unchecked across agent sessions.
- Require explicit justification for any new dependency in `Cargo.toml`.

## 5. Merge Order
- Prefer merging branches closest to `main` and scoped to a single service before branches touching shared core modules (`src/domain.rs`, `src/protocol.rs`, `src/respond.rs`, `src/server.rs`, `src/wire.rs`).
- Every branch must pass `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo test --workspace --all-features` after rebasing onto `main`.
