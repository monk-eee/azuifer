# Contributing to Azuifer

Start with the [onboarding guide](ONBOARDING.md) and [product and technical specification](docs/specs/azuifer.md). Discuss a material change to protocol behavior, storage, security, or distribution in a public GitHub issue before implementing it. For security reports, use the [private reporting path](SECURITY.md) instead.

## Design and review

- Check the [ADR index](docs/adr.d/README.md) for existing rationale. If no record covers a new architectural decision, draft a focused proposal with a falsifiable verification criterion. No new ADR is needed for an editorial fix.
- Open a focused pull request against `main`. Explain the problem, what changed, and how you checked it. Link the applicable spec, ADR, and tests or fixtures; identify behavior that remains unverified.
- Use `git commit --signoff` for contributions you can certify under the [Developer Certificate of Origin](https://developercertificate.org/). Submit only work you have the right to publish under the repository's [dual license](README.md).

## Validation

Run the [merge checks](AGENTS.md#ci-and-completion) and applicable build checks on the pinned toolchain. Follow the [testing rules](AGENTS.md#tests): write the regression before fixing a bug and cover the observable contract, not implementation calls. The [Blob HTTP tests](tests/blob_http.rs) start the built executable on ephemeral loopback ports and require no Azure credentials. For a persistence change, include restart or crash-recovery tests where applicable.

The [Azure CLI matrix](tests/azure_cli_matrix.py) runs actual `az storage` commands from four consecutive CLI releases against the Azure Linux image in [CI](.github/workflows/rust.yml), including the gate reused before releases. Keep it testing real data and error outcomes, not `--help` or mocked command output. Use `cargo llvm-cov --workspace --all-features --locked` with `cargo-llvm-cov` and the Rust LLVM tools component to inspect line and region coverage. Normal test subprocesses close stdin and exit cleanly so the report includes the server; the crash test still kills it on purpose.

Update the conformance manifest alongside changes to supported behavior. Link the differential evidence for any new or changed compatibility claim. Keep examples and fixtures synthetic, and do not put live test credentials or recordings into a pull request.

For docs-only changes, check that links resolve, ADRs are indexed, and public docs contain no credentials or private references.
