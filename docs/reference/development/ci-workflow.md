---
title: CI Workflow
package: .github/workflows
feature: PXD-0023
---

# CI Workflow

The `.github/workflows/ci.yml` workflow runs lint checks, unit tests, and integration tests on every pull request. All jobs run in parallel with no inter-job dependencies. `lint` and `integration-test` run on `ubuntu-latest`; `unit-test` runs on Linux, Windows and macOS.

## Trigger Events

| Event               | Filter | Description                                    |
|---------------------|--------|------------------------------------------------|
| `pull_request`      | (all)  | Runs on opened, synchronized, and reopened PRs |
| `workflow_dispatch` | —      | Manual run against any branch                  |

The workflow does not run on pushes to `main`. A `pull_request` run checks out the merge result rather than the branch head, so the commit that lands on `main` is the commit CI already tested; repeating the run after the merge tests it a second time. Use `workflow_dispatch` to verify `main` on demand — after a merge whose base had moved since the PR run, for example.

A branch without an open PR does not trigger the workflow on push.

## Jobs

All jobs use `actions/checkout@v4` and `actions/setup-go@v5` with Go 1.26, pinned to full SHA hashes for supply-chain hardening. Each job sets `timeout-minutes` to prevent runaway CI from consuming unlimited minutes. Module caching is handled automatically by `setup-go@v5` using `go.sum` as the cache key.

### lint

Static analysis and dependency verification.

| Step                   | Command / Action                                           | Purpose                              |
|------------------------|------------------------------------------------------------|--------------------------------------|
| Checkout               | `actions/checkout@v4`                                      | Clone repository                     |
| Setup Go               | `actions/setup-go@v5` (`go-version: '1.26'`)              | Install Go with module caching       |
| Verify dependencies    | `go mod verify`                                            | Validate checksums against `go.sum`  |
| Run go vet             | `go vet ./...`                                             | Built-in static analysis             |
| Install staticcheck    | `go install honnef.co/go/tools/cmd/staticcheck@latest`     | Install advanced static analyzer     |
| Run staticcheck        | `staticcheck ./...`                                        | Detect bugs and deprecated patterns  |
| Run golangci-lint      | `golangci/golangci-lint-action@v9` (`version: v2.12.2`)    | Aggregated linter suite              |

The `golangci-lint` action runs golangci-lint v2 (pinned via the `version` input), configured by `.golangci.yml` in the repository root. The config restores the default exclusions that golangci-lint v1 applied implicitly, since v2 dropped them. golangci-lint v2 is required because v1 binaries are built with Go 1.24 and refuse to run against the `go 1.26.0` directive in `go.mod`.

### unit-test

Runs all tests with race detection and cache disabled, once per platform.

| Step           | Command / Action                            | Purpose                                  |
|----------------|---------------------------------------------|------------------------------------------|
| Checkout       | `actions/checkout@v4`                       | Clone repository                         |
| Setup Go       | `actions/setup-go@v5` (`go-version: '1.26'`)| Install Go with module caching          |
| Run unit tests | `go test -race -count=1 ./...`              | Execute all tests, detect data races     |

The `-count=1` flag disables test caching to ensure every CI run exercises all tests. The `-race` flag enables the Go race detector.

::: v-pre
**Matrix strategy:** the job sets `runs-on: ${{ matrix.os }}` over three labels, producing the jobs `unit-test (ubuntu-latest)`, `unit-test (windows-latest)` and `unit-test (macos-latest)`.
:::

| Label            | Image                | Architecture |
|------------------|----------------------|--------------|
| `ubuntu-latest`  | Ubuntu               | x64          |
| `windows-latest` | Windows Server 2025  | x64          |
| `macos-latest`   | macOS 26             | arm64        |

`fail-fast: false` keeps a Windows failure from cancelling the Linux and macOS jobs, whose results are what tell you whether a failure is platform-specific. `timeout-minutes` is 30 rather than the usual 10: the Linux job takes about a minute and a half, and no measured Windows duration exists yet.

`-race` needs cgo everywhere except macOS, so the Windows job links against the C toolchain its runner image ships. The race detector supports windows/amd64 and both macOS architectures, which is what these three labels resolve to.

Tests that cannot run on a platform skip themselves rather than being excluded: see [Tests that cannot run everywhere](./getting-started.md#tests-that-cannot-run-everywhere).

### integration-test

Runs only test functions matching the `Integration` pattern.

| Step                   | Command / Action                                      | Purpose                                      |
|------------------------|-------------------------------------------------------|----------------------------------------------|
| Checkout               | `actions/checkout@v4`                                 | Clone repository                             |
| Setup Go               | `actions/setup-go@v5` (`go-version: '1.26'`)         | Install Go with module caching               |
| Run integration tests  | `go test -race -count=1 -run Integration ./...`       | Execute integration tests with race detection|

The `-run Integration` flag performs substring matching, selecting test functions such as `TestIntegration_*`, `TestRelayIntegration_*`, `TestBridgeReconcileIntegration_*`, and `TestUserAccessIntegration_*`. Packages with no matching tests are skipped gracefully.

## Go Version

All jobs pin Go 1.26 via `go-version: '1.26'` (not `1.26.0`), which resolves to the latest patch release. This matches the version specified in `go.mod`.

## Module Caching

`actions/setup-go@v5` automatically caches downloaded Go modules using `go.sum` as the cache key. No explicit cache configuration is needed. On cache hit, `go mod download` is skipped, reducing job duration.

## Adding a New Job

1. Add a new entry under `jobs:` in `.github/workflows/ci.yml`
2. Set `runs-on: ubuntu-latest`, or an `os` matrix with `runs-on` taken from it, when the job has to run on every platform, as `unit-test` does
3. Set `timeout-minutes` to an appropriate value (10 for standard jobs, 15 for integration tests, 30 for the cross-platform unit-test matrix)
4. Include `actions/checkout` and `actions/setup-go` pinned to full SHA hashes as the first two steps
5. Do not add a `needs:` key unless the job genuinely depends on another job's output
6. Add the job's run commands as subsequent steps

## Action Versions

All actions are pinned to full SHA hashes for supply-chain hardening. The version comment after each SHA indicates the corresponding release tag.

| Action                           | Version  | SHA                                          | Purpose                           |
|----------------------------------|----------|----------------------------------------------|-----------------------------------|
| `actions/checkout`               | `v4.3.1` | `34e114876b0b11c390a56381ad16ebd13914f8d5`   | Repository checkout               |
| `actions/setup-go`               | `v5.6.0` | `40f1582b2485089dde7abd97c1529aa768e1baff`   | Go installation and module cache  |
| `golangci/golangci-lint-action`  | `v9.2.1` | `82606bf257cbaff209d206a39f5134f0cfbfd2ee`   | golangci-lint installation and run|
