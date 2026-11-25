# Contributing to Azuifer

Start with the [onboarding guide](ONBOARDING.md) and [product and technical specification](docs/specs/azuifer.md). Discuss a material change to protocol behavior, storage, security, or distribution in a public GitHub issue before implementing it. For security reports, use the [private reporting path](SECURITY.md) instead.

## Design and review

- Check the [ADR index](docs/adr.d/README.md) for existing rationale. If no record covers a new architectural decision, draft a focused proposal with a falsifiable verification criterion. No new ADR is needed for an editorial fix.
- Open a focused pull request against `main`. Explain the problem, what changed, and how you checked it. Link the applicable spec, ADR, and tests or fixtures; identify behavior that remains unverified.
- Use `git commit --signoff` for contributions you can certify under the [Developer Certificate of Origin](https://developercertificate.org/). Submit only work you have the right to publish under the repository's [dual license](README.md).

## Validation

Today, check that Markdown links resolve, ADRs are indexed, and public docs contain no credentials or private references. There is no runnable Cargo target or CI gate yet.

When implementation lands, run the workspace's format, lint, test, and build checks on the pinned toolchain. Test changed behavior at the boundary it affects: wire status, headers, errors, and follow-up reads for a REST change; restart or crash recovery for a persistence change. Update the conformance manifest alongside changes to supported behavior. Keep examples and fixtures synthetic, and do not put live test credentials or recordings into a pull request.
