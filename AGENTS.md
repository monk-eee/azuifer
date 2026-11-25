# Working on Azuifer

Start with the [specification](docs/specs/azuifer.md) and [ADR index](docs/adr.d/README.md). The repository currently contains documentation only. Treat proposed behavior as a target, never as an implemented endpoint or a passing test.

## Before changing behavior

- Find the decision that covers the change. If the work introduces a new architectural choice or exceeds the existing scope, draft a bounded ADR before writing code. Link relevant records in the pull request. See [Contributing](CONTRIBUTING.md) for review and validation expectations.
- Keep HTTP and protocol mapping, authentication, domain rules, and persistence separate. Keep service code behind the metadata transaction interface. Do not duplicate Blob and DFS identity or force FileREST into that namespace.
- Prefer safe Rust, explicit errors, and bounded streaming. Do not turn unsupported requests or persistence failures into successful responses. Keep blocking database and filesystem work off async executor threads.
- Keep builds reproducible with public inputs and portable tooling. Do not add a private dependency or publish credentials, internal links, or real datasets.
- Keep wire behavior, tests, and conformance records in sync. Do not claim compatibility without evidence for the specific operation, API version, and authentication mode. Keep ordinary tests independent of Azure credentials.

For docs-only changes, check the Markdown links and consistency across the spec, decision records, and contributor docs. Report what you validated and what you could not run.
