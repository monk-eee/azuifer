# Release Azuifer

The [release workflow](../.github/workflows/release.yml) packages Linux, macOS, and Windows on x64 and ARM64. Linux archives contain a standalone musl executable; they do not depend on a particular distribution's glibc. The workflow smoke-tests it on Debian 12, Ubuntu 22.04, Alpine 3.24, and Red Hat UBI 9. These are portable archives, not `.deb` or `.rpm` packages.

The same Linux build stage supplies the executable for the [Azure Linux image](../Dockerfile). The runtime is distroless, non-root, and can run with a read-only root filesystem.

## Preview and publish

1. Run **Release** manually from the intended branch to build a `release-preview` bundle without creating a GitHub release or publishing an image. The [checks workflow](../.github/workflows/rust.yml) runs first.
2. Confirm the source commit and version in [Cargo.toml](../Cargo.toml) and the lockfile. Only tag a reviewed, tested commit. Restrict who can create `v*` tags on the public repository.
3. Push a tag matching the package version, such as `v0.1.0`. A version mismatch or a missing archive fails the workflow. The tag publishes the six native archives, `SHA256SUMS`, a Cargo workspace SPDX SBOM, and signed GitHub build provenance. A `0.x` or prerelease version is marked as a prerelease.

Verify a downloaded archive from the public repo with `gh attestation verify <archive> --repo monk-eee/azuifer`. Attestations are not Windows Authenticode signatures or macOS notarization. Verify the checksum against `SHA256SUMS` before extracting.

## Opt in to Docker Hub

Create a public Docker Hub repository in your namespace. In GitHub Actions settings, set these repository variables:

| Variable | Value |
| --- | --- |
| `DOCKERHUB_IMAGE` | The Docker Hub `namespace/repository` to publish to, without a tag |
| `DOCKERHUB_USERNAME` | The Docker Hub account authorized to write to that repository |

Set `DOCKERHUB_TOKEN` as a secret in the `dockerhub` GitHub environment. Use a scoped access token with write access to the chosen repository. Do not put it in a workflow, a command-line example, or version control. Add a deployment approval to the environment if you want to review the image publish separately.

With the destination configured, the tag workflow publishes `linux/amd64` and `linux/arm64` under one version tag after the GitHub release succeeds. Buildx attaches image SBOM and provenance; GitHub also attests the published image digest. The workflow does not overwrite a `latest` tag. Without a Docker Hub destination, only the GitHub release is published.
