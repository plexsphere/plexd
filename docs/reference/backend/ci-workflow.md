---
title: CI Workflow
quadrant: backend
package: .github/workflows
feature: PXD-0023
---

# CI Workflow

The `.github/workflows/ci.yml` workflow runs lint checks, unit tests, and integration tests on every push to `main` and every pull request. All three jobs run in parallel on `ubuntu-latest` with no inter-job dependencies.

## Trigger Events

| Event          | Filter             | Description                                     |
|----------------|--------------------|-------------------------------------------------|
| `push`         | `branches: [main]` | Runs on every push to the `main` branch         |
| `pull_request` | (all)              | Runs on opened, synchronized, and reopened PRs  |

Pushes to non-main branches without an open PR do not trigger the workflow.

## Jobs

All jobs use `actions/checkout@v4` and `actions/setup-go@v5` with Go 1.24, pinned to full SHA hashes for supply-chain hardening. Each job sets `timeout-minutes` to prevent runaway CI from consuming unlimited minutes. Module caching is handled automatically by `setup-go@v5` using `go.sum` as the cache key.

### lint

Static analysis and dependency verification.

| Step                   | Command / Action                                           | Purpose                              |
|------------------------|------------------------------------------------------------|--------------------------------------|
| Checkout               | `actions/checkout@v4`                                      | Clone repository                     |
| Setup Go               | `actions/setup-go@v5` (`go-version: '1.24'`)              | Install Go with module caching       |
| Verify dependencies    | `go mod verify`                                            | Validate checksums against `go.sum`  |
| Run go vet             | `go vet ./...`                                             | Built-in static analysis             |
| Install staticcheck    | `go install honnef.co/go/tools/cmd/staticcheck@latest`     | Install advanced static analyzer     |
| Run staticcheck        | `staticcheck ./...`                                        | Detect bugs and deprecated patterns  |
| Run golangci-lint      | `golangci/golangci-lint-action@v6`                         | Aggregated linter suite              |

The `golangci-lint` action uses default linters when no `.golangci.yml` exists. Adding a `.golangci.yml` to the repository root will be picked up automatically without workflow changes.

### unit-test

Runs all tests with race detection and cache disabled.

| Step           | Command / Action                            | Purpose                                  |
|----------------|---------------------------------------------|------------------------------------------|
| Checkout       | `actions/checkout@v4`                       | Clone repository                         |
| Setup Go       | `actions/setup-go@v5` (`go-version: '1.24'`)| Install Go with module caching          |
| Run unit tests | `go test -race -count=1 ./...`              | Execute all tests, detect data races     |

The `-count=1` flag disables test caching to ensure every CI run exercises all tests. The `-race` flag enables the Go race detector.

### integration-test

Runs only test functions matching the `Integration` pattern.

| Step                   | Command / Action                                      | Purpose                                      |
|------------------------|-------------------------------------------------------|----------------------------------------------|
| Checkout               | `actions/checkout@v4`                                 | Clone repository                             |
| Setup Go               | `actions/setup-go@v5` (`go-version: '1.24'`)         | Install Go with module caching               |
| Run integration tests  | `go test -race -count=1 -run Integration ./...`       | Execute integration tests with race detection|

The `-run Integration` flag performs substring matching, selecting test functions such as `TestIntegration_*`, `TestRelayIntegration_*`, `TestBridgeReconcileIntegration_*`, and `TestUserAccessIntegration_*`. Packages with no matching tests are skipped gracefully.

## Go Version

All jobs pin Go 1.24 via `go-version: '1.24'` (not `1.24.0`), which resolves to the latest patch release. This matches the version specified in `go.mod`.

## Module Caching

`actions/setup-go@v5` automatically caches downloaded Go modules using `go.sum` as the cache key. No explicit cache configuration is needed. On cache hit, `go mod download` is skipped, reducing job duration.

## Adding a New Job

1. Add a new entry under `jobs:` in `.github/workflows/ci.yml`
2. Set `runs-on: ubuntu-latest`
3. Set `timeout-minutes` to an appropriate value (10 for standard jobs, 15 for integration tests)
4. Include `actions/checkout` and `actions/setup-go` pinned to full SHA hashes as the first two steps
5. Do not add a `needs:` key unless the job genuinely depends on another job's output
6. Add the job's run commands as subsequent steps

## Action Versions

All actions are pinned to full SHA hashes for supply-chain hardening. The version comment after each SHA indicates the corresponding release tag.

| Action                           | Version  | SHA                                          | Purpose                           |
|----------------------------------|----------|----------------------------------------------|-----------------------------------|
| `actions/checkout`               | `v4.3.1` | `34e114876b0b11c390a56381ad16ebd13914f8d5`   | Repository checkout               |
| `actions/setup-go`               | `v5.6.0` | `40f1582b2485089dde7abd97c1529aa768e1baff`   | Go installation and module cache  |
| `golangci/golangci-lint-action`  | `v6.5.2` | `55c2c1448f86e01eaae002a5a3a9624417608d84`   | golangci-lint installation and run|
