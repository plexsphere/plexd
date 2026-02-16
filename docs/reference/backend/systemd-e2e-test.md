---
title: Systemd E2E Test
quadrant: backend
package: test/e2e/systemd
feature: PXD-0040
---

# Systemd E2E Test

Validates that plexd runs correctly as a systemd service by deploying it inside a privileged Ubuntu container with systemd as PID 1. The test installs the plexd binary and the production `plexd.service` unit file, starts the service via `systemctl`, polls the mock-api assertion endpoint to verify registration, heartbeat, state retrieval, capabilities reporting, drift detection, and observability forwarding (metrics, logs, audit), then verifies clean shutdown.

## Container Topology

```
┌──────────────┐       ┌─────────────────────────┐
│   mock-api   │◄──────│   systemd container     │
│  :8080       │       │  (Ubuntu 24.04)         │
│  /v1/ping    │       │  systemd PID 1          │
│              │       │  plexd.service managed   │
└──────────────┘       └─────────────────────────┘
        │                          │
        └──── plexd-systemd-e2e ───┘
              (Docker network)
```

| Container | Image | Source | Purpose |
|-----------|-------|--------|---------|
| `plexd-e2e-mockapi` | `mockapi:e2e-systemd` | `test/e2e/mockapi/Dockerfile` | Fixture-based mock Central API, tracks call counters |
| `plexd-e2e-systemd` | `plexd-systemd:e2e` | `test/e2e/systemd/Dockerfile` | Ubuntu 24.04 with systemd as PID 1, runs plexd as a real service |

## Test Phases

### 1. Pre-flight checks

Verifies that `docker`, `curl`, and `jq` are available on `$PATH`. Exits immediately if any tool is missing.

### 2. Pre-cleanup

Removes any leftover containers and network from a previous run (handles the case where a prior run was killed with SIGKILL and the trap did not fire).

### 3. Image build

Builds the mock-api image, the systemd container image, and cross-compiles the plexd binary using a Go Alpine container. The Go version is extracted from `go.mod`.

### 4. Network and container startup

Creates a Docker bridge network and starts both containers on it. The systemd container runs with `--privileged`, `--cgroupns=host`, and cgroup volume mounts for full systemd functionality.

### 5. Service installation

Copies the plexd binary and the production `deploy/systemd/plexd.service` unit file into the systemd container. Writes `config.yaml` pointing at the mock-api container and an environment file with the bootstrap token. Runs `systemctl daemon-reload` and `systemctl enable --now plexd`.

### 6. Assertion polling

Polls `GET http://localhost:18080/test/assertions` every 3 seconds for up to 60 seconds (configurable via `TIMEOUT`).

### 7. Shutdown verification

Stops the service with `systemctl stop plexd`, verifies `inactive` state and exit code 0, and checks `journalctl -u plexd` for absence of crash indicators (`core dumped`, `segfault`, `SIGABRT`, `SIGKILL`).

### 8. Cleanup

The `cleanup` function runs on `EXIT` trap (both success and failure). It prints diagnostics on failure, then removes both containers and the Docker network.

## Assertion Logic

The test polls `GET http://localhost:18080/test/assertions` which returns JSON counters:

```json
{
  "registration_count": 1,
  "heartbeat_count": 1,
  "state_count": 1,
  "capabilities_count": 1,
  "drift_count": 1,
  "metrics_count": 1,
  "logs_count": 1,
  "audit_count": 1
}
```

The test passes when all eight counters are >= 1:

| Counter | Meaning |
|---------|---------|
| `registration_count` | plexd called `POST /v1/register` |
| `heartbeat_count` | plexd called `POST /v1/nodes/{id}/heartbeat` |
| `state_count` | plexd called `GET /v1/nodes/{id}/state` |
| `capabilities_count` | plexd called `PUT /v1/nodes/{id}/capabilities` |
| `drift_count` | plexd called `POST /v1/nodes/{id}/drift` |
| `metrics_count` | plexd called `POST /v1/nodes/{id}/metrics` |
| `logs_count` | plexd called `POST /v1/nodes/{id}/logs` |
| `audit_count` | plexd called `POST /v1/nodes/{id}/audit` |

## plexd Configuration

The config is written directly into the container (not via the installer script):

```yaml
api:
  base_url: http://plexd-e2e-mockapi:8080
registration:
  data_dir: /var/lib/plexd
node_api:
  data_dir: /var/lib/plexd
heartbeat:
  node_id: e2e-systemd-node
```

The bootstrap token is set via the environment file at `/etc/plexd/environment` (`PLEXD_BOOTSTRAP_TOKEN=e2e-test-token`).

## Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TIMEOUT` | `60` | Assertion polling timeout in seconds |

## Usage

```bash
make test-e2e-systemd
```

Or directly:

```bash
bash test/e2e/systemd/test.sh
```

Override configuration:

```bash
TIMEOUT=120 make test-e2e-systemd
```

### Prerequisites

- Docker
- `curl` and `jq` on the host

## Debugging Failures

**systemd does not boot inside the container:**

The container requires `--privileged`, `--cgroupns=host`, and cgroup volume mounts. Verify the host supports cgroup v2:

```bash
mount | grep cgroup2
```

**plexd service fails to start:**

```bash
docker exec plexd-e2e-systemd journalctl -u plexd --no-pager
docker exec plexd-e2e-systemd systemctl status plexd
```

Common causes:
- Binary not executable — check that `chmod +x` was applied to `/usr/local/bin/plexd`.
- Config YAML parse error — field names must use snake_case YAML tags (e.g. `base_url`, not `baseurl`).
- Missing bootstrap token — the environment file must set `PLEXD_BOOTSTRAP_TOKEN`.

**Assertions not met (counters stay at 0):**

```bash
docker logs plexd-e2e-mockapi
docker exec plexd-e2e-systemd journalctl -u plexd --no-pager -n 100
```

Common causes:
- Network connectivity — both containers must be on the `plexd-systemd-e2e` bridge network.
- mock-api not ready — the script polls `/v1/ping` for readiness but the health timeout may be too short.

**Leftover containers from previous run:**

The script performs pre-cleanup, but if issues persist:

```bash
docker rm -f plexd-e2e-mockapi plexd-e2e-systemd
docker network rm plexd-systemd-e2e
```

## Diagnostics Output

On any failure, the `print_diagnostics` function outputs:

| Command | Purpose |
|---------|---------|
| `docker network inspect plexd-systemd-e2e` | Network state and connected containers |
| `docker logs plexd-e2e-mockapi` | Mock API server logs |
| `systemctl status plexd` | Service state and recent log lines |
| `journalctl -u plexd -n 100` | Recent plexd service logs |
| `journalctl -n 50` | Recent system-wide journal entries |
| `ps aux` | Process list inside systemd container |
| `ls -la /etc/plexd/` | Configuration files |
| `ls -la /usr/local/bin/plexd` | Binary presence and permissions |

## Key Files

| File | Purpose |
|------|---------|
| `test/e2e/systemd/Dockerfile` | Ubuntu 24.04 systemd container image |
| `test/e2e/systemd/test.sh` | Orchestration script (build, install, assert, shutdown, cleanup) |
| `test/e2e/systemd/.dockerignore` | Prevents unnecessary files in Docker context |
| `test/e2e/mockapi/Dockerfile` | Mock API image |
| `test/e2e/mockapi/mockapi.go` | Mock API server with `/test/assertions` endpoint |
| `deploy/systemd/plexd.service` | Production unit file (copied verbatim into container) |
| `Makefile` | `test-e2e-systemd` target |

## See also

- [Docker E2E Test](docker-e2e-test.md) — Docker Compose-based E2E test
- [Kubernetes E2E Test](kubernetes-e2e-test.md) — kind-based Kubernetes E2E test
