## Problem

<!-- What is wrong or missing, and how do you know? Link the issue, spec section or ADR. -->

## Change

<!-- What changed and why this approach. Name behavior you left unverified. -->

## Linked decisions

- Spec section or ADR (`docs/adr.d/`), or "none needed":

## Validation

<!-- Paste what you ran and what you saw. Delete lines that do not apply. -->

- [ ] A regression or behavior test that fails without this change
- [ ] `cargo fmt --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `python -m unittest discover -s scripts -p "test_*.py"` and the `scripts/audit-*.py` checks, for docs or evidence changes

## Conformance and docs

- [ ] The matching `specs/conformance/*.json` manifest is updated, or this change does not alter supported behavior
- [ ] No operation is marked `exact` without Azure differential evidence
- [ ] Docs, counts and links I touched still agree with the manifests (`python scripts/audit-docs.py`)
- [ ] No credentials, SAS tokens, raw Azure traffic or private references are included

## Sign-off

- [ ] Every commit has a `Signed-off-by` line (`git commit --signoff`) certifying the [Developer Certificate of Origin](https://developercertificate.org/)
