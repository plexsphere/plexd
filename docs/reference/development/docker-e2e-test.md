---
title: Docker E2E Test
package: test/e2e/docker
feature: PXD-0038
---

# Docker E2E Test

Validates that a containerised plexd agent successfully registers, sends heartbeats, retrieves state, reports capabilities, converges to desired state, and forwards metrics, logs, and audit events to the Central API. The test uses docker compose to orchestrate two services — `mock-api` (a fixture-based mock of the Central API) and `plexd` (the agent under test) — on an isolated bridge network.

The test runs fourteen phases:

1. **Initial assertions** — all 7 counters >= 1 (agent started and contacted all endpoints)
2. **Request body validation** — verifies registration token, heartbeat structure, capabilities payload, and metrics data
3. **Periodic loop verification** — heartbeat and metrics counters >= 2 (self-generating loops run continuously)
4. **Log injection** — injects a log file via `docker cp`, verifies logs_count increases (FileSource pipeline works)
5. **Agent restart for audit** — restarts the plexd container and verifies `local_audit_count` increases (ProcessSource fires per-process). The platform leg carries nothing: plexd's own `process` source is outside the ingest contract's closed enum (`auditd`, `k8s`), so `audit_count` must stay at 0.
6. **SSE event injection** — injects a `node_state_updated` event and verifies state_count increases (proves SSE stream is connected)
7. **Session lifecycle from the state pull** — splices a `tcp` entry into the snapshot's `sessions` block and verifies a `session_started` activity row carrying `listener_endpoint`, then re-posts the snapshot **without** the entry and verifies the drain produces a `session_ended` row with `plexd_close` and numeric byte counters; a second entry carrying `idle_timeout_seconds` verifies the idle window closes a session on its own with `idle_timeout`
8. **Session events as pull triggers** — injects `session_setup` and `session_revoked` envelopes with opaque payloads, verifies each advances `state_count` while leaving `session_activity_count` unchanged
9. **Convergence cycle** — posts a mutated `NodeStateSnapshot` envelope via `/test/configure-state`, verifies `state_count` advances AND a reconcile cycle reports `policy` drift
10. **Policy fingerprint no-op** — re-posts the envelope with only `revision_id` bumped (same fingerprint), verifies `state_count` advances but no cycle reports `policy` drift (the differ's fingerprint short-circuit holds)
11. **Local endpoint delivery** — all 3 local endpoint counters >= 1 (dual delivery to HTTPS local endpoint works)
12. **Local endpoint body validation** — verifies non-empty JSON arrays received at each local endpoint
13. **Dual delivery verification** — both platform and local counters >= 1 simultaneously (proves parallel delivery)
14. **Graceful shutdown** — stops plexd container, verifies exit code 0 and no crash indicators in logs

## Service Topology

```
┌──────────────┐       ┌──────────────┐
│   mock-api   │◄──────│    plexd     │
│  :8080 (HTTP)│       │  (agent)     │
│  :8443 (TLS) │       │  depends_on  │
│  /v1/health  │       │  mock-api    │
└──────────────┘       └──────────────┘
        │                      │
        └──────── e2e-net ─────┘
```

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `mock-api` | Built from `test/e2e/mockapi/Dockerfile` | 8080 (host: 18080), 8443 (host: 18443) | Returns fixture responses, tracks call counters, TLS local endpoint |
| `plexd` | Built from `deploy/docker/Dockerfile` | — | Agent under test, connects to mock-api |

### Startup Ordering

1. `mock-api` starts and exposes a healthcheck on `GET /v1/health`.
2. docker compose waits for `mock-api` to become healthy (2s interval, 10 retries).
3. `plexd` starts with `depends_on: mock-api (service_healthy)`.

## Assertion Logic

### Phase 1: Counter Polling

The test script polls `GET http://localhost:18080/test/assertions` every 2 seconds for up to 30 seconds. The endpoint returns JSON counters:

```json
{
  "registration_count": 1,
  "heartbeat_count": 1,
  "state_count": 1,
  "capabilities_count": 1,
  "metrics_count": 1,
  "logs_count": 1,
  "audit_count": 0,
  "local_metrics_count": 1,
  "local_logs_count": 1,
  "local_audit_count": 1
}
```

Phase 1 passes when all seven platform counters are >= 1. Local endpoint counters are verified separately in Phases 9-11:

| Counter | Meaning |
|---------|---------|
| `registration_count` | plexd called `POST /v1/register` |
| `heartbeat_count` | plexd called `POST /v1/nodes/{id}/heartbeat` |
| `state_count` | plexd called `GET /v1/nodes/{id}/state` |
| `capabilities_count` | plexd called `PUT /v1/nodes/{id}/capabilities` |
| `metrics_count` | plexd called `POST /v1/nodes/{id}/metrics` |
| `logs_count` | plexd called `POST /v1/nodes/{id}/logs` |
| `audit_count` | plexd called `POST /v1/nodes/{id}/audit` — 0 while no contract-legal audit source is wired |
| `local_metrics_count` | plexd sent metrics to `POST /local/metrics` (TLS) |
| `local_logs_count` | plexd sent logs to `POST /local/logs` (TLS) |
| `local_audit_count` | plexd sent audit to `POST /local/audit` (TLS) |

### Phase 2: Request Body Validation

Uses `GET /test/last-request/{endpoint}` to verify the content of request payloads:

| Endpoint | Validated Fields |
|----------|-----------------|
| `register` | `token` (non-empty), `hostname` (non-empty), `public_key` (non-empty) |
| `heartbeat` | Valid JSON with `timestamp` field (node_id is in URL path, not body) |
| `capabilities` | `binary_version` (non-empty), `binary_checksum` (32-byte base64 digest), and no field the handler rejects as unknown |
| `metrics` | Array with >= 1 data point |

### Phase 3: Periodic Loop Verification

Waits up to 60 seconds for `heartbeat_count` and `metrics_count` to reach >= 2. These are self-generating periodic loops. Logs and audit are tested separately via injection and restart.

### Phase 4: Log Injection

Injects a log file into the plexd container via `docker cp` (the container is distroless with no shell). The `FileSource` discovers the new file via glob, reads it, and the forwarder reports it to the API. Verifies `logs_count` increases.

### Phase 5: Agent Restart for Audit

The `ProcessSource` uses `sync.Once` to emit a single `process_start` audit entry per process lifetime. Restarting the plexd container creates a new process with a fresh `ProcessSource`, verifying `local_audit_count` increases.

That entry travels to the local endpoint only. Its source is plexd's own `process`, which is not in the audit ingest contract's closed enum (`auditd`, `k8s`), and a record naming a value outside that set refuses the whole batch with `400 ingest_batch_malformed`. The reporter therefore skips it, and the phase also asserts `audit_count == 0`: with no contract-legal audit source wired, the platform leg carries nothing. If the agent grows an auditd or Kubernetes audit reader, that assertion is the thing to update.

### Phase 6: SSE Event Injection

Injects a `node_state_updated` event via `POST /test/inject-event` and verifies that `state_count` increases, proving the SSE stream is connected and event-driven reconciliation works.

### Phase 7: Session Lifecycle from the State Pull

Drives the whole mediated-access lifecycle through the `sessions` block (script phase `8e`). Splicing a `tcp` entry with a future `expires_at` into that block provisions a listener: the test polls `session_activity_count` to +1 and asserts the captured row carries `tcp.phase = session_started`, the configured `target_host` / `target_port`, and a non-empty `host:port` `listener_endpoint` — the address the listener actually bound. Re-posting the snapshot with an empty `sessions` array is the teardown signal: `session_activity_count` reaches +2 and the captured row is `session_ended` with `terminated_by = plexd_close` and `bytes_in` / `bytes_out` present as numbers — the node cannot tell a revocation from a control plane that failed to serve the block, so it never claims `operator_revoke`. There is no revocation endpoint and no teardown event; the drain is the whole mechanism.

Script phase `8i` covers the other way a session ends on the node's own initiative: an entry carrying `idle_timeout_seconds: 1` provisions a listener nothing ever connects to, so the window runs out from the bind. `session_activity_count` reaches +2 with no drain at all, and the captured row is `session_ended` with `terminated_by = idle_timeout` — the entry is still standing in the block when its session ends, and it is not provisioned again.

### Phase 8: Session Events as Pull Triggers

Proves that `session_setup` and `session_revoked` are reconcile triggers rather than delivery channels (script phase `8h`). Each is injected with an opaque `"{}"` payload. The test asserts `state_count` advances within a window deliberately shorter than the ~30s heartbeat reconcile cadence — what is proven is that the pull happens *now* — and that `session_activity_count` is unchanged afterwards: the resulting pull found no session in the block, so nothing was provisioned or torn down.

### Phase 9: Convergence Cycle

Posts a full mutated `NodeStateSnapshot` envelope to `POST /test/configure-state` (a new policy fingerprint and new state values), then polls until **both** hard conditions hold: `state_count` advances (the agent re-fetched the snapshot) and the count of `"reconciliation cycle completed"` lines whose `drift` summary contains `policy` increases (the differ reported `PolicyChanged`, so the policy handler ran). Both fixture peers are surfaced and asserted through the node API `GET /v1/peers`.

The assertion deliberately gates on the reconciler drift summary rather than on `"policy ruleset applied"`. The test container's kernel exposes no nftables backend, so policy enforcement stays disabled there and no rule can reach the kernel; the applied-log is emitted only on a real apply and would never fire. Proving rule installation requires an environment with a working nftables backend.

`POST /test/configure-state` replaces the **whole** snapshot fixture, which is also how the action phases drive execution: they queue a dispatch by reading the live snapshot, splicing an entry into its `executions` array, and posting the result back, then inject a `node_state_updated` envelope so the agent pulls immediately instead of waiting out the reconcile cadence. Because the fetch leg is a real `GET` on the state endpoint, it increments `state_count` — a phase gating on that counter must take its baseline **after** configuring the block. Action dispatches never ride an SSE payload, so `action_request` can only be used the same way: as a nudge that pulls the next reconcile forward.

The session phases drive the `sessions` array through the same splice, via the `session_entry` and `configure_sessions` helpers. The one difference is what a re-post means: `executions` is a delivery queue that drains when the node settles an entry, while `sessions` is desired state, so dropping an entry from the array *is* the revocation — the node tears the listener down on the pull that no longer carries it. `session_setup` and `session_revoked` are nudges exactly like `action_request`, carrying neither a session nor a teardown of their own.

### Phase 10: Policy Fingerprint No-Op

Re-posts the envelope with only `revision_id` bumped and a metadata value changed — the policy `fingerprint` stays identical. The test asserts `state_count` advances (the no-op envelope was fetched) but the policy-drift cycle count is **unchanged**, exercising the differ's fingerprint short-circuit: a revision-only bump must not report `PolicyChanged`.

### Phase 11: Local Endpoint Delivery

Polls `GET /test/assertions` until `local_metrics_count`, `local_logs_count`, and `local_audit_count` are all >= 1 (timeout: 60s). This validates the full local endpoint credential chain: registration (32-byte NSK) → secret fetch → AES-256-GCM decryption → Bearer token → HTTPS POST to mock-api's TLS listener on `:8443`.

### Phase 12: Local Endpoint Body Validation

Uses `GET /test/last-request/local_{metrics,logs,audit}` to verify each local endpoint received a non-empty JSON array payload.

### Phase 13: Dual Delivery Verification

Asserts that both platform counters (`metrics_count`, `logs_count`, `audit_count`) and local counters (`local_metrics_count`, `local_logs_count`, `local_audit_count`) are all >= 1, proving parallel delivery to both the central API and the local endpoint.

### Phase 20: Bearer Envelope on Every Authenticated Call

Every phase above runs through the mock's bearer-envelope gate, so this one states the outcome: `unauthorized_count` is 0 across the whole run, and the agent log carries no `heartbeat auth failure`. Both halves matter — an agent that registers successfully and is then refused on every later call looks healthy while delivering nothing, which is how the defect in issue #60 reached two releases. A phase that drives an authenticated route itself presents the same envelope, fetched once from `GET /test/bearer`.

### Phase 14: Graceful Shutdown

Stops the plexd container via `docker compose stop` (sends SIGTERM) and verifies:
- Exit code is 0
- No crash indicators in logs (`panic:`, `fatal error:`, `SIGABRT`, `SIGKILL`, `runtime error:`)
- Shutdown message is logged

## plexd Configuration

The container receives configuration from three sources:

| Source | Value | Purpose |
|--------|-------|---------|
| Config file (`/etc/plexd/config.yaml`) | Bind-mounted from `test/e2e/docker/plexd-e2e.yaml` | Sets `api.base_url`, `registration.data_dir`, `node_api.data_dir`, `heartbeat.node_id`, `local_endpoint` blocks for metrics/log_fwd/audit_fwd |
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
