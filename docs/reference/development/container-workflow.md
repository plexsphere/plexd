---
title: Container Workflow
package: .github/workflows
feature: PXD-0036
---

# Container Workflow

The `.github/workflows/container.yml` workflow builds a multi-arch container image and pushes it to `ghcr.io/plexsphere/plexd` when a version tag is pushed or code is merged to `main`. It uses Docker Buildx to produce a single manifest list covering `linux/amd64` and `linux/arm64` in one invocation.

## Trigger Events

| Event  | Filter             | Description                                         |
|--------|--------------------|-----------------------------------------------------|
| `push` | `tags: ['v*']`     | Runs when a tag matching `v*` is pushed             |
| `push` | `branches: [main]` | Runs on every push to the `main` branch             |

The workflow does not trigger on pull requests or tags that do not match the `v*` pattern.

## Permissions

The workflow declares a minimal permissions block:

| Scope      | Access  | Reason                                           |
|------------|---------|--------------------------------------------------|
| `packages` | `write` | Required for pushing container images to ghcr.io |
| `contents` | `read`  | Required for repository checkout                 |

No other permission scopes are granted. The workflow uses `GITHUB_TOKEN` (not personal access tokens).

## Job: build-and-push

Single job on `ubuntu-latest` with `timeout-minutes: 30`. No matrix strategy — Buildx handles multi-platform builds natively.

| Step               | Action / Command                         | Purpose                                          |
|--------------------|------------------------------------------|--------------------------------------------------|
| Checkout           | `actions/checkout@v4`                    | Clone repository at the triggered commit         |
| Setup Buildx       | `docker/setup-buildx-action@v3`          | Install Docker Buildx for multi-platform builds  |
| Login to ghcr.io   | `docker/login-action@v3`                 | Authenticate to GitHub Container Registry        |
| Extract metadata   | `docker/metadata-action@v5`              | Generate image tags and labels from git context  |
| Build and push     | `docker/build-push-action@v6`            | Build multi-arch image and push to registry      |

### Login

::: v-pre
Authenticates to `ghcr.io` using:

- **registry:** `ghcr.io`
- **username:** `${{ github.actor }}`
- **password:** `${{ secrets.GITHUB_TOKEN }}`
:::

### Metadata

The metadata step (id: `meta`) configures image name and tag rules:

- **images:** `ghcr.io/plexsphere/plexd`

### Build and Push

::: v-pre
- **context:** `.` (repository root)
- **file:** `deploy/docker/Dockerfile`
- **platforms:** `linux/amd64,linux/arm64`
- **push:** `true`
- **tags:** `${{ steps.meta.outputs.tags }}`
- **labels:** `${{ steps.meta.outputs.labels }}`
:::

## Image Tagging Strategy

::: v-pre
| Trigger            | Tag Rule                                  | Example Input | Example Tags                  |
|--------------------|-------------------------------------------|---------------|-------------------------------|
| Tag push `v1.2.3`  | `type=semver,pattern={{version}}`          | `v1.2.3`      | `1.2.3`                       |
| Tag push `v1.2.3`  | `type=semver,pattern=v{{version}}`         | `v1.2.3`      | `v1.2.3`                      |
| Tag push `v1.2.3`  | `type=semver,pattern={{major}}.{{minor}}`  | `v1.2.3`      | `1.2`                         |
| Tag push `v1.2.3`  | `type=semver,pattern={{major}}`            | `v1.2.3`      | `1`                           |
| Tag push `v1.2.3`  | (automatic)                               | `v1.2.3`      | `latest`                      |
| Main push          | `type=raw,value=dev,enable={{is_default_branch}}` | (any)  | `dev`                         |

For non-prerelease semver tags, `metadata-action` automatically adds a `latest` tag (default behavior). Main-branch pushes produce only the `dev` tag — no semver tags and no `latest`.

The `{{version}}` placeholder emits the *parsed* semantic version, which drops the leading `v` by definition, so `v{{version}}` is spelled out separately to publish the release version verbatim. Both patterns resolve to the same manifest — the git tag, the GitHub release name, and `ghcr.io/plexsphere/plexd:v1.2.3` are one spelling, and a consumer that records the release version and builds an image reference from it gets a pullable one. The bare-semver forms are unaffected; this is an alias, not a replacement.
:::

## Build Arguments

::: v-pre
The build step passes version metadata as Docker build arguments, matching the `ARG` declarations in `deploy/docker/Dockerfile`:

| Build Arg  | Source                                                                       | Dockerfile Default |
|------------|------------------------------------------------------------------------------|--------------------|
| `VERSION`  | `${{ github.ref_name }}` (tag name on tag push, `main` on branch push)      | `dev`              |
| `COMMIT`   | `${{ github.sha }}`                                                          | `none`             |
| `DATE`     | `${{ github.event.head_commit.timestamp \|\| github.event.repository.updated_at }}` | `unknown`   |

These are injected into the binary via `-ldflags` targeting `main.version`, `main.commit`, and `main.date`.
:::

## Platforms

The image is built as a multi-arch manifest covering:

- `linux/amd64`
- `linux/arm64`

Docker Buildx sets `TARGETOS` and `TARGETARCH` automatically for each platform. The Dockerfile uses these to cross-compile the Go binary without modification.

## Dockerfile

The workflow builds from `deploy/docker/Dockerfile`, a multi-stage image:

1. **Builder stage** (`golang:1.26-alpine`): downloads modules, cross-compiles the `plexd` binary with version ldflags
2. **Runtime stage** (`gcr.io/distroless/static-debian12`): copies the binary to `/usr/local/bin/plexd`, runs as non-root (UID 65534)

## DaemonSet Relationship

The Kubernetes DaemonSet at `deploy/kubernetes/daemonset.yaml` references:

```yaml
image: ghcr.io/plexsphere/plexd:latest
```

The `metadata-action` `images` field is set to `ghcr.io/plexsphere/plexd`, matching this reference. The `latest` tag points to the most recent non-prerelease semver tag, ensuring the DaemonSet pulls release builds. The multi-arch manifest allows scheduling on both amd64 and arm64 nodes without image name changes.

## Action Versions

All actions are pinned to full SHA hashes for supply-chain hardening. The `checkout` pin matches `ci.yml`.

| Action                         | Version   | SHA                                          | Purpose                              |
|--------------------------------|-----------|----------------------------------------------|--------------------------------------|
| `actions/checkout`             | `v4.3.1`  | `34e114876b0b11c390a56381ad16ebd13914f8d5`   | Repository checkout                  |
| `docker/setup-buildx-action`   | `v3.12.0` | `8d2750c68a42422c14e847fe6c8ac0403b4cbd6f`   | Install Docker Buildx                |
| `docker/login-action`          | `v3.7.0`  | `c94ce9fb468520275223c153574b00df6fe4bcc9`   | Authenticate to container registry   |
| `docker/metadata-action`       | `v5.10.0` | `c299e40c65443455700f0fdfc63efafe5b349051`   | Generate tags and labels from git    |
| `docker/build-push-action`     | `v6.19.2` | `10e90e3645eae34f1e60eeb005ba3a3d33f178e8`   | Build and push multi-platform image  |
