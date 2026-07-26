---
title: Cutting a Release
---

# Cutting a Release

Releases are tag-driven: pushing a version tag publishes every artifact automatically, with no manual build steps.

## Versioning Policy

- plexd uses semantic versioning with major version `0`: a minor bump signals a breaking change, a patch bump signals fixes.
- The `0.1.x` series carries the current MVP control-plane contract — the contract exercised by the bundled mock API server (`test/e2e/mockapi`). Adoption of the real Plexsphere control-plane v1 API lands as `0.2.0`.
- While the major version is `0`, the `0` and `latest` image tags track the newest release and are published deliberately — do not add the docker/metadata-action major-zero `enable` guard to suppress the `{{major}}` tag. Consumers wanting stability should pin `0.1` or an exact version.
- Release image tags are mutable while the major version is `0`. Re-running the Container workflow for an existing tag rebuilds the image and moves `vX.Y.Z` and `X.Y.Z` to the new manifest, so an exact-version pin identifies a release, not a fixed set of bytes — a consumer holding a cached image cannot tell it has gone stale. Anyone needing a reference that can never move should pin by digest (`ghcr.io/plexsphere/plexd@sha256:…`), which `docker buildx imagetools inspect` reports for any tag.

## Prerequisites

- Tag-push permission on `plexsphere/plexd`.
- CI is green on the `main` commit being released.

## Steps

Releases use lightweight tags, the same convention documented in the [Release Workflow](../reference/development/release-workflow.md) reference. The example below uses `v0.1.0`; substitute any `vX.Y.Z`.

1. Switch to `main` and pull the commit being released:

   ```bash
   git switch main && git pull
   ```

2. Create the lightweight version tag:

   ```bash
   git tag v0.1.0
   ```

3. Push the tag to trigger the automation:

   ```bash
   git push origin v0.1.0
   ```

4. Watch the **Release** and **Container** workflow runs in GitHub Actions until both complete.

## What the Automation Publishes

- A GitHub release with `plexd-linux-{amd64,arm64,mipsle}` binaries, a combined `checksums.sha256`, and auto-generated release notes.
- Multi-arch (linux/amd64, linux/arm64) container images `ghcr.io/plexsphere/plexd:{vX.Y.Z, X.Y.Z, X.Y, X, latest}` — for `v0.1.0` that is `v0.1.0`, `0.1.0`, `0.1`, `0`, and `latest`. The `v`-prefixed and bare forms of the full version are aliases for the same manifest, published so the release version resolves as an image reference without a consumer having to strip the prefix.

## Verify the Release

- The release page carries the three binaries plus `checksums.sha256`. Spot-check a binary against the checksums file to catch a truncated or corrupted upload:

  ```bash
  sha256sum --ignore-missing --check checksums.sha256
  ```

  ::: warning This is an integrity check, not an authenticity check
  The release job generates `checksums.sha256` from the same binaries it uploads, so the checksums share a trust root with the artifacts they describe. Anyone able to publish to the release can replace a binary and regenerate the checksums to match. plexd does not yet sign release artifacts or publish build provenance, so a consumer currently has no way to prove a downloaded binary came from this repository's CI — this check only tells you the bytes survived the round trip.
  :::

- Confirm the image pulls anonymously — the ghcr package is public:

  ```bash
  docker pull ghcr.io/plexsphere/plexd:0.1.0
  ```

  If the pull requires authentication, fix the package visibility in the GitHub package settings — a one-time action.

- Confirm both spellings of the version resolve to the same manifest:

  ```bash
  docker buildx imagetools inspect ghcr.io/plexsphere/plexd:v0.1.0 --format '{{.Manifest.Digest}}'
  docker buildx imagetools inspect ghcr.io/plexsphere/plexd:0.1.0  --format '{{.Manifest.Digest}}'
  ```

  The two digests must match, and each must name a manifest list covering `linux/amd64` and `linux/arm64` — drop the `--format` flag to see the platform entries.

- Confirm the stamped version:

  ```bash
  docker run --rm ghcr.io/plexsphere/plexd:0.1.0 --version
  ```

  This prints `plexd version v0.1.0` — the tag name including the `v` prefix, which is also the `v0.1.0` image tag and the form the agent sends in its API `User-Agent` header as `plexd/v0.1.0`. The bare `0.1.0` tag is the same image under its parsed-semver spelling.

## See Also

- [Release Workflow](../reference/development/release-workflow.md) — Binary build matrix, checksums, and release job internals.
- [Container Workflow](../reference/development/container-workflow.md) — Multi-arch image build and semver tag generation.
