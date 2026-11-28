# Security policy

## Private reporting

Use [GitHub's private vulnerability reporting form](https://github.com/monk-eee/azuifer/security/advisories/new) for suspected vulnerabilities in Azuifer. Do not disclose a security issue in a public issue or pull request. Describe the affected component or revision, the observed impact, and the minimum information needed to reproduce it with synthetic data. Remove keys, tokens, SAS query strings, and identifying data from attachments.

## Scope and support

Azuifer currently has no software releases. The proposed emulator is for local development and testing, not for direct exposure to an untrusted network. Report issues in other products to their respective maintainers.

## External copy sources

External copies are off by default. Allow only the sources your test needs; an exact address can grant access to a private service. Equivalent IPv6 spellings match the same address, but an explicit port must still match. The configured fetch timeout covers name resolution and the response transfer. See the [external copy decision](docs/adr.d/0024-fetch-external-copy-sources-only-from-allowlisted-hosts.md).

## Release verification

The [release workflow](.github/workflows/release.yml) checks that the SPDX SBOM includes every registry package and version pinned in `Cargo.lock` before creating `SHA256SUMS`. See the [release guide](docs/releases.md) for verifying checksums and signed build provenance. GitHub attestations are not operating-system code signatures.
