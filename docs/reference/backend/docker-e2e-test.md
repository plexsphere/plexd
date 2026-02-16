---
title: Docker E2E Test
quadrant: backend
package: test/e2e/docker
feature: PXD-0038
---

# Docker E2E Test

Validates that a containerised plexd agent successfully registers, sends heartbeats, retrieves state, reports capabilities, detects drift, and forwards metrics, logs, and audit events to the Central API. The test uses docker compose to orchestrate two services — `mock-api` (a fixture-based mock of the Central API) and `plexd` (the agent under test) — on an isolated bridge network.

## Service Topology

```
┌──────────────┐       ┌──────────────┐
│   mock-api   │◄──────│    plexd     │
│  :8080       │       │  (agent)     │
│  healthcheck │       │  depends_on  │
│  /v1/ping    │       │  mock-api    │
└──────────────┘       └──────────────┘
        │                      │
        └──────── e2e-net ─────┘
```

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `mock-api` | Built from `test/e2e/mockapi/Dockerfile` | 8080 (host: 18080) | Returns fixture responses, tracks call counters |
| `plexd` | Built from `deploy/docker/Dockerfile` | — | Agent under test, connects to mock-api |

### Startup Ordering

1. `mock-api` starts and exposes a healthcheck on `GET /v1/ping`.
2. docker compose waits for `mock-api` to become healthy (2s interval, 10 retries).
3. `plexd` starts with `depends_on: mock-api (service_healthy)`.

## Assertion Logic

The test script polls `GET http://localhost:18080/test/assertions` every 2 seconds for up to 30 seconds. The endpoint returns JSON counters:

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

The container receives configuration from three sources:

| Source | Value | Purpose |
|--------|-------|---------|
| Config file (`/etc/plexd/config.yaml`) | Bind-mounted from `test/e2e/docker/plexd-e2e.yaml` | Sets `api.base_url`, `registration.data_dir`, `node_api.data_dir`, `heartbeat.node_id` |
| CLI flag `--api` | `http://mock-api:8080` | Overrides API base URL (redundant with config, belt-and-suspenders) |
| Env var `PLEXD_BOOTSTRAP_TOKEN` | `e2e-test-token` | Bootstrap token for registration |

A `tmpfs` mount at `/var/lib/plexd` provides a writable data directory.

## Usage

```bash
make test-e2e-docker
```

Or directly:

```bash
bash test/e2e/docker/test.sh
```

### Prerequisites

- Docker with compose v2 plugin
- `curl` and `jq` on the host (for assertion polling)

## Debugging Failures

**mock-api never becomes healthy:**

```bash
docker compose -f test/e2e/docker-compose.yml -p plexd-e2e logs mock-api
```

Check that the mock-api binary starts and the `wget` healthcheck binary is present in the distroless image.

**Assertions not met (counters stay at 0):**

```bash
docker compose -f test/e2e/docker-compose.yml -p plexd-e2e logs plexd
```

Common causes:
- Config file parse error — check YAML field names use snake_case tags (e.g. `base_url`, not `baseurl`).
- Network connectivity — both services must be on the `e2e-net` bridge network.
- Missing bootstrap token — `PLEXD_BOOTSTRAP_TOKEN` must be set in the plexd service environment.

**Cleanup stuck containers:**

```bash
docker compose -f test/e2e/docker-compose.yml -p plexd-e2e down -v
```

## Key Files

| File | Purpose |
|------|---------|
| `test/e2e/docker-compose.yml` | Service definitions, network, healthcheck |
| `test/e2e/docker/test.sh` | Orchestration script (build, wait, assert, cleanup) |
| `test/e2e/docker/plexd-e2e.yaml` | Minimal plexd config for the E2E test |
| `test/e2e/mockapi/Dockerfile` | Mock API image (includes wget for healthcheck) |
| `deploy/docker/Dockerfile` | plexd production image |
| `Makefile` | `test-e2e-docker` target |
