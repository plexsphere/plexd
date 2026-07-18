---
title: Release Workflow
package: .github/workflows
feature: PXD-0035
---

# Release Workflow

The `.github/workflows/release.yml` workflow builds cross-compiled static binaries for linux/amd64, linux/arm64, and linux/mipsle, generates a combined SHA-256 checksums file, and publishes them as a GitHub Release when a version tag is pushed.

## Trigger Events

| Event  | Filter          | Description                                      |
|--------|-----------------|--------------------------------------------------|
| `push` | `tags: ['v*']`  | Runs when a tag matching `v*` is pushed          |

The workflow does not trigger on branch pushes, pull requests, or tags that do not match the `v*` pattern.

## Permissions

The workflow declares a minimal permissions block:

| Scope      | Access  | Reason                                  |
|------------|---------|----------------------------------------|
| `contents` | `write` | Required for creating releases and uploading assets |

No other permission scopes are granted. The workflow uses `GITHUB_TOKEN` (not personal access tokens).

## Jobs

The workflow has two jobs: `build` runs once per architecture via a matrix strategy, and `release` runs after all matrix builds complete.

### build

Cross-compiles a static binary for each target architecture and uploads it with its checksum as a GitHub Actions artifact.

| Step              | Command / Action                                           | Purpose                                        |
|-------------------|------------------------------------------------------------|------------------------------------------------|
| Checkout          | `actions/checkout@v4`                                      | Clone repository at the tagged commit          |
| Setup Go          | `actions/setup-go@v5` (`go-version: '1.26'`)              | Install Go with module caching                 |
| Build binary      | `go build -ldflags "..." -o plexd-linux-$GOARCH ./cmd/plexd` | Cross-compile static binary                  |
| Generate checksum | `sha256sum plexd-linux-$GOARCH > plexd-linux-$GOARCH.sha256` | Create per-artifact checksum file            |
| Upload artifact   | `actions/upload-artifact@v4`                               | Upload binary and checksum for release job     |

The build step sets `CGO_ENABLED=0`, `GOOS=linux`, and `GOARCH` from the matrix, producing a fully static binary with no shared library dependencies.

**Matrix strategy:**

| `goarch`  | `gomips`     |
|-----------|--------------|
| `amd64`   | (unset)      |
| `arm64`   | (unset)      |
| `mipsle`  | `softfloat`  |

The matrix uses an `include` list so each entry can set its own parameters. The `mipsle` build sets `GOMIPS=softfloat` for OpenWRT hardware without an FPU.

Each matrix entry produces one artifact named `plexd-linux-{arch}` containing both the binary and its `.sha256` checksum file.

### release

Downloads all build artifacts and creates a GitHub Release with auto-generated notes.

| Step                   | Command / Action                         | Purpose                                    |
|------------------------|------------------------------------------|--------------------------------------------|
| Download artifacts     | `actions/download-artifact@v4` (`merge-multiple: true`) | Download all matrix artifacts into one directory |
| Generate combined checksums | `cat plexd-linux-*.sha256 > checksums.sha256` | Combine per-binary checksums into single file |
| Create GitHub Release  | `softprops/action-gh-release@v2` (`generate_release_notes: true`) | Create release and upload assets |

The release job has `needs: build`, ensuring it only runs after all matrix builds succeed. The `merge-multiple: true` option on `download-artifact` merges all artifacts into a single flat directory.

## Build Arguments and Ldflags

The build step injects version metadata via Go linker flags matching the pattern used in the Dockerfile:

```
-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}
```

| Flag                  | Source                          | Example Value              |
|-----------------------|---------------------------------|----------------------------|
| `-s -w`               | (static flags)                  | Strips debug info and DWARF symbols |
| `-X main.version=...` | `GITHUB_REF_NAME`               | `v1.2.3`                   |
| `-X main.commit=...`  | `GITHUB_SHA` (first 8 chars)    | `a1b2c3d4`                 |
| `-X main.date=...`    | `date -u +%Y-%m-%dT%H:%M:%SZ`  | `2025-01-15T12:00:00Z`     |

## Release Assets

| File                         | Description                      |
|------------------------------|----------------------------------|
| `plexd-linux-amd64`          | Static binary for x86_64         |
| `plexd-linux-arm64`          | Static binary for ARM64          |
| `plexd-linux-mipsle`         | Static binary for MIPS little-endian (softfloat) |
| `checksums.sha256`           | Combined SHA-256 checksums for all binaries |

Binary names follow the `plexd-linux-{arch}` convention expected by `install.sh`.

## Checksum Format

The `checksums.sha256` file contains one line per binary in standard `sha256sum` output format:

```
<64-char hex hash>  plexd-linux-amd64
<64-char hex hash>  plexd-linux-arm64
<64-char hex hash>  plexd-linux-mipsle
```

Two spaces separate the hash from the filename. This format is compatible with `sha256sum --check` for verification and with `install.sh`, which downloads `checksums.sha256` and greps for the target binary name.

## Action Versions

All actions are pinned to full SHA hashes for supply-chain hardening. The `checkout` and `setup-go` pins match those in `ci.yml`.

| Action                         | Version  | SHA                                          | Purpose                            |
|--------------------------------|----------|----------------------------------------------|------------------------------------|
| `actions/checkout`             | `v4.3.1` | `34e114876b0b11c390a56381ad16ebd13914f8d5`   | Repository checkout                |
| `actions/setup-go`             | `v5.6.0` | `40f1582b2485089dde7abd97c1529aa768e1baff`   | Go installation and module cache   |
| `actions/upload-artifact`      | `v4.6.2` | `ea165f8d65b6e75b540449e92b4886f43607fa02`   | Upload build artifacts             |
| `actions/download-artifact`    | `v4.3.0` | `d3f86a106a0bac45b974a628896c90dbdf5c8093`   | Download artifacts in release job  |
| `softprops/action-gh-release`  | `v2.5.0` | `a06a81a03ee405af7f2048a818ed3f03bbf83c7b`   | Create GitHub Release with assets  |

## Creating a Release

See [Cutting a Release](../../how-to/cutting-a-release.md) for the tag-driven release procedure and the versioning policy.
