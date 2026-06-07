---
title: E2E Workflow
package: .github/workflows
feature: PXD-0041
---

# E2E Workflow

The `.github/workflows/e2e.yml` workflow runs all three E2E test suites — Docker, Kubernetes, and systemd — as parallel GitHub Actions jobs. It triggers on pushes to `main` and on pull requests when relevant source paths change.

## Trigger Configuration

The workflow uses path-filtered triggers on both `push` (branches: `main`) and `pull_request`:

| Path | Rationale |
|------|-----------|
| `cmd/**` | CLI and entrypoint changes |
| `internal/**` | Core agent logic |
| `deploy/**` | Dockerfiles, systemd units, Kubernetes manifests |
| `test/e2e/**` | E2E test scripts and fixtures |
| `Dockerfile` | Root Dockerfile (if present) |
| `.github/workflows/e2e.yml` | Self-trigger for workflow changes |

Changes to `docs/`, `README.md`, `.planwerk/`, or other non-runtime files do **not** trigger the workflow.

## Jobs

All three jobs run in parallel on `ubuntu-latest` with `timeout-minutes: 30`. No `needs:` dependencies exist between them.

### docker-e2e

Runs the Docker Compose-based E2E test.

| Step | Action |
|------|--------|
| Checkout | `actions/checkout` (pinned SHA) |
| Setup Go | `actions/setup-go` with `go-version: '1.26'` |
| Run tests | `make test-e2e-docker` |
| Capture logs | `docker compose logs` (on failure) |
| Upload artifact | `docker-e2e-logs` (on failure) |

### kubernetes-e2e

Runs the kind-based Kubernetes E2E test.

| Step | Action |
|------|--------|
| Checkout | `actions/checkout` (pinned SHA) |
| Setup Go | `actions/setup-go` with `go-version: '1.26'` |
| Install kind | `go install sigs.k8s.io/kind@v0.27.0` |
| Run tests | `make test-e2e-k8s` |
| Capture logs | `kubectl logs` + `kubectl describe` (on failure) |
| Upload artifact | `kubernetes-e2e-logs` (on failure) |

### systemd-e2e

Runs the systemd-in-Docker E2E test.

| Step | Action |
|------|--------|
| Checkout | `actions/checkout` (pinned SHA) |
| Setup Go | `actions/setup-go` with `go-version: '1.26'` |
| Run tests | `make test-e2e-systemd` |
| Capture logs | `docker logs` for both containers (on failure) |
| Upload artifact | `systemd-e2e-logs` (on failure) |

## Artifact Upload on Failure

Each job captures logs with `if: failure()` before uploading via `actions/upload-artifact`. Log capture uses `|| true` to handle cases where the test script's trap handler has already cleaned up resources.

| Job | Artifact name | Contents |
|-----|---------------|----------|
| docker-e2e | `docker-e2e-logs` | Docker Compose service logs |
| kubernetes-e2e | `kubernetes-e2e-logs` | plexd pod logs, mock-api logs, DaemonSet description, pod status |
| systemd-e2e | `systemd-e2e-logs` | mock-api container logs, systemd container logs |

To download artifacts from a failed run, navigate to the workflow run in the Actions tab and find the artifacts listed at the bottom of the run summary page.

## Action Versions

All actions use pinned SHAs matching the project convention:

| Action | SHA | Version |
|--------|-----|---------|
| `actions/checkout` | `34e114876b0b11c390a56381ad16ebd13914f8d5` | v4.3.1 |
| `actions/setup-go` | `40f1582b2485089dde7abd97c1529aa768e1baff` | v5.6.0 |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | v4.6.2 |

## Makefile Targets

| Target | Command |
|--------|---------|
| `test-e2e-docker` | `bash test/e2e/docker/test.sh` |
| `test-e2e-k8s` | `bash test/e2e/kubernetes/test.sh` |
| `test-e2e-systemd` | `bash test/e2e/systemd/test.sh` |

## See also

- [Docker E2E Test](docker-e2e-test.md) — Test implementation details
- [Kubernetes E2E Test](kubernetes-e2e-test.md) — kind cluster setup and manifests
- [Systemd E2E Test](systemd-e2e-test.md) — systemd container and service lifecycle
- [CI Workflow](ci-workflow.md) — Lint and unit test workflow
