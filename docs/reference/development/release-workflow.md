---
title: Release Workflow
package: .github/workflows
feature: PXD-0035
---

# Release Workflow

The `.github/workflows/release.yml` workflow builds cross-compiled static binaries for linux/amd64, linux/arm64, linux/mipsle, windows/amd64, windows/arm64, darwin/amd64 and darwin/arm64, generates a combined SHA-256 checksums file, signs every binary with cosign, and publishes them as a GitHub Release when a version tag is pushed.

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

The workflow has two jobs: `build` runs once per target via a matrix strategy, and `release` runs after all matrix builds complete.

### build

Cross-compiles a static binary for each target and uploads it with its checksum as a GitHub Actions artifact.

| Step              | Command / Action                                           | Purpose                                        |
|-------------------|------------------------------------------------------------|------------------------------------------------|
| Checkout          | `actions/checkout@v4`                                      | Clone repository at the tagged commit          |
| Setup Go          | `actions/setup-go@v5` (`go-version: '1.26'`)              | Install Go with module caching                 |
| Build binary      | `go build -ldflags "..." -o plexd-$GOOS-$GOARCH$EXT ./cmd/plexd` | Cross-compile static binary               |
| Generate checksum | `sha256sum plexd-$GOOS-$GOARCH$EXT > plexd-$GOOS-$GOARCH$EXT.sha256` | Create per-artifact checksum file     |
| Upload artifact   | `actions/upload-artifact@v4`                               | Upload binary and checksum for release job     |

The build step sets `CGO_ENABLED=0` and takes `GOOS`, `GOARCH` and `GOMIPS` from the matrix, producing a fully static binary with no shared library dependencies. Every target cross-compiles on `ubuntu-latest`; no Windows or macOS runner is involved.

**Matrix strategy:**

| `goos`    | `goarch`  | `gomips`     | `ext`   |
|-----------|-----------|--------------|---------|
| `linux`   | `amd64`   | (unset)      | (unset) |
| `linux`   | `arm64`   | (unset)      | (unset) |
| `linux`   | `mipsle`  | `softfloat`  | (unset) |
| `windows` | `amd64`   | (unset)      | `.exe`  |
| `windows` | `arm64`   | (unset)      | `.exe`  |
| `darwin`  | `amd64`   | (unset)      | (unset) |
| `darwin`  | `arm64`   | (unset)      | (unset) |

The matrix uses an `include` list so each entry can set its own parameters. The `mipsle` build sets `GOMIPS=softfloat` for OpenWRT hardware without an FPU. `ext` is the binary's file extension and expands to the empty string on every entry that omits it, which is what keeps the Linux asset names unchanged.

Each matrix entry produces one artifact named `plexd-{goos}-{goarch}` containing both the binary and its `.sha256` checksum file.

`.github/workflows/build.yml` carries the same matrix and runs on every pull request. `internal/cicheck` fails if the two drift apart, so a target is added to both files or neither.

### release

Downloads all build artifacts and creates a GitHub Release with auto-generated notes.

| Step                   | Command / Action                         | Purpose                                    |
|------------------------|------------------------------------------|--------------------------------------------|
| Download artifacts     | `actions/download-artifact@v4` (`merge-multiple: true`) | Download all matrix artifacts into one directory |
| Generate combined checksums | `cat plexd-*.sha256 > checksums.sha256` | Combine per-binary checksums into single file |
| Install cosign         | `sigstore/cosign-installer@v4`           | Provide the cosign binary                  |
| Sign release binaries  | `cosign sign-blob --bundle <binary>.sigstore.json <binary>` | Sign each binary, keyless |
| Create GitHub Release  | `softprops/action-gh-release@v2` (`generate_release_notes: true`) | Create release and upload assets |

The release job has `needs: build`, ensuring it only runs after all matrix builds succeed. The `merge-multiple: true` option on `download-artifact` merges all artifacts into a single flat directory.

The signing step is keyless, which is why the job requests `id-token: write` in addition to `contents: write`. The bundle's name is the binary's file name plus `.sigstore.json`, `.exe` included, so `plexd-windows-amd64.exe` is signed into `plexd-windows-amd64.exe.sigstore.json`. `internal/upgrade` derives the bundle name the same way.

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
| `plexd-linux-amd64`          | Static binary for Linux x86_64   |
| `plexd-linux-arm64`          | Static binary for Linux ARM64    |
| `plexd-linux-mipsle`         | Static binary for MIPS little-endian (softfloat) |
| `plexd-windows-amd64.exe`    | Static binary for Windows x86_64 |
| `plexd-windows-arm64.exe`    | Static binary for Windows ARM64  |
| `plexd-darwin-amd64`         | Static binary for macOS Intel    |
| `plexd-darwin-arm64`         | Static binary for macOS Apple silicon |
| `<binary>.sigstore.json`     | Sigstore bundle for each of the seven binaries |
| `checksums.sha256`           | Combined SHA-256 checksums for all binaries |

Binary names follow the `plexd-{goos}-{goarch}` convention, with a `.exe` suffix on Windows. The three Linux names are the ones `deploy/install.sh` and `internal/upgrade/fetcher.go` resolve, so they cannot change.

The per-binary `.sha256` files are build artifacts only. They are folded into `checksums.sha256` and are not published as release assets.

## Checksum Format

The `checksums.sha256` file contains one line per binary in standard `sha256sum` output format:

```
<64-char hex hash>  plexd-linux-amd64
<64-char hex hash>  plexd-linux-arm64
<64-char hex hash>  plexd-linux-mipsle
<64-char hex hash>  plexd-windows-amd64.exe
<64-char hex hash>  plexd-windows-arm64.exe
<64-char hex hash>  plexd-darwin-amd64
<64-char hex hash>  plexd-darwin-arm64
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
| `sigstore/cosign-installer`    | `v4.1.2` | `6f9f17788090df1f26f669e9d70d6ae9567deba6`   | Install cosign for keyless signing |
| `softprops/action-gh-release`  | `v2.5.0` | `a06a81a03ee405af7f2048a818ed3f03bbf83c7b`   | Create GitHub Release with assets  |

## Creating a Release

See [Cutting a Release](../../how-to/cutting-a-release.md) for the tag-driven release procedure and the versioning policy.
