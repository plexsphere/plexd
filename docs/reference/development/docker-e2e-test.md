---
title: Docker E2E Test
package: test/e2e/docker
feature: PXD-0038
---

# Docker E2E Test

Validates that a containerised plexd agent successfully registers, sends heartbeats, retrieves state, reports capabilities, converges to desired state, and forwards metrics, logs, and audit events to the Central API. The test uses docker compose to orchestrate two services — `mock-api` (a fixture-based mock of the Central API) and `plexd` (the agent under test) — on an isolated bridge network.

The test runs fourteen phases:

1. **Initial assertions** — all 7 counters >= 1 (agent started and contacted all endpoints)
2. **Request body validation** — verifies registration token, heartbeat structure, capabilities payload, and metrics data, then that the capability manifest follows the hooks directory while the agent runs and that a failed PUT is retried (script step `10f`)
3. **Periodic loop verification** — heartbeat and metrics counters >= 2 (self-generating loops run continuously), then a handshake report and a `tunnel_health` sample for a fixture peer when WireGuard came up in the container (script phase `4b`), an edge PSK fetch for each fixture peer under the same condition (script phase `4c`), an endpoint candidates report, an endpoint selection switch on a fixture peer and its move to a new relay fallback under the same condition (script phase `4d`), and a mesh MTU sized by the uplink probe and held by the device under the same condition (script phase `4e`)
4. **Log injection** — injects a log file via `docker cp`, verifies logs_count increases (FileSource pipeline works)
5. **Agent restart for audit** — restarts the plexd container and verifies `local_audit_count` increases (ProcessSource fires per-process). The platform leg carries nothing: plexd's own `process` source is outside the ingest contract's closed enum (`auditd`, `k8s`), so `audit_count` must stay at 0.
6. **SSE event injection** — injects a `node_state_updated` event and verifies state_count increases (proves SSE stream is connected), then switches the mock to a new signing key and verifies that a pull installs it, that an event signed with it is dispatched, and that plexd starts from the persisted key after a restart (script phase `7c`)
7. **Session lifecycle from the state pull** — splices a `tcp` entry into the snapshot's `sessions` block and verifies a `session_started` activity row carrying `listener_endpoint`, then re-posts the snapshot **without** the entry: the `session_ended` row the drain produces is accepted, so the test verifies `session_activity_count` advances by 2 over the phase's baseline while `session_activity_rejected_count` stays unchanged, and that the captured row carries `plexd_close` and numeric byte counters; a second entry carrying `idle_timeout_seconds` verifies the idle window closes a session on its own with `idle_timeout`; a third entry is closed by a signed `session_revoked` event while it still stands in the block, and its ending row reports `operator_revoke` (script phase `8j`); bytes sent through a fourth entry's listener are reported as `session_active` rows, at most one per interval, and a quiet tunnel posts none (script phase `8k`)
8. **Session events as pull triggers** — injects a `session_setup` envelope with an opaque payload and a `session_revoked` envelope whose payload plexd refuses as malformed, verifies each advances `state_count` while leaving `session_activity_count` unchanged, then verifies that the pull's `secrets` block fills, changes, and empties the local node API's secret index, and that `node_secrets_updated` triggers the pull for the change (script phase `12c`)
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
| `plexd` | Built from `test/e2e/docker/Dockerfile.plexd` | — | Agent under test, connects to mock-api |

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
| `capabilities` | `binary_version` (non-empty), `binary_checksum` (32-byte base64 digest), `builtin_actions` equal to the eleven builtins sorted by name, each with a description, `service.upgrade` declaring `version` then `checksum` as required; `declared_hooks` exactly `e2e-bigout` with the SHA-256 of `test/e2e/docker/hooks/e2e-bigout`, where an absent list fails; `capabilities_count` exactly 1, so these checks read the first manifest and a broken boot order cannot pass through a later send; `plexd_hooks`, `binary`, and `hooks` absent |
| `metrics` | Array with >= 1 data point |

### Phase 2 (cont.): Capability Manifest Kept Current

Runs as script step `10f`, the last step of script phase `10`, after step `10c` has required `declared_hooks` to hold `e2e-bigout` again late in the run, once the agent has restarted. It changes the hooks directory of the running container and reads each change back from the mock through `GET /test/last-request/capabilities`. Each change waits for its PUT, so no count catches the PUT of the change before it. Writes and removals touch only the step's own hook, `e2e-live`, and every check fails the suite.

1. **The watch runs.** It requires no `hook watcher stopped` line in the plexd log. The watch needs an inotify instance, and those are scarce on a host that runs kind clusters, so without this check every poll below would time out with nothing to say why.
2. **Add.** It writes `e2e-live` into the container over stdin and polls for up to 10 seconds until `declared_hooks` is exactly `e2e-bigout` and `e2e-live`, with the digest of the bytes it wrote.
3. **Change.** It rewrites `e2e-live` and polls the same way for the new digest.
4. **Remove.** It removes `e2e-live` and polls until `declared_hooks` is `e2e-bigout` alone.
5. **No-op control.** It reads `capabilities_count`, runs `touch` on `e2e-bigout`, waits 5 seconds, and requires the count unchanged. The watcher fires, but the manifest equals the one last accepted, so no PUT follows.
6. **Reload.** It writes `e2e-live` again and runs `plexd hooks reload` in one `sh -c`, so the reload answers inside the watcher's 200 ms debounce and only a scan of the directory can count the file. It parses the `Hooks:` field, which the CLI prints with two spaces, and requires it to equal the two entries on disk. It then waits for the PUT that carries `e2e-live` with its digest, removes the file, and waits for the PUT the removal causes. Removing the file before the first PUT lands would put the manifest back to the accepted one and send nothing.
7. **Failed PUT.** It counts the `agent: capability report: send failed` lines as a baseline, arms `{"fail_next": 2}` through [`POST /test/configure-capabilities`](mock-api-server.md#post-test-configure-capabilities), and runs `dc restart plexd`. The boot PUT and the first retry meet a `500`, and the second retry lands. It polls for up to 30 seconds until `capabilities_count` grows, which the mock moves only on delivery and which also proves the agent is back for script phase `12`. It then requires exactly two new `send failed` lines and a delivered manifest of `e2e-bigout` alone, since the container layer survives the restart.

Inside the container every applet except `sh`, `head`, and `tr` runs as `/bin/busybox <applet>`, because the image links only those three.

### Phase 3: Periodic Loop Verification

Waits up to 60 seconds for `heartbeat_count` and `metrics_count` to reach >= 2. These are self-generating periodic loops. Logs and audit are tested separately via injection and restart.

### Phase 3 (cont.): Handshake Report and Tunnel Health

Runs as script phase `4b`, directly after the periodic-loop phase in `test.sh`, and checks the two channels that read the WireGuard device: the [handshake report](../core/heartbeat-service.md#handshake-reporter) and the `tunnel_health` metrics group.

plexd starts both only when its WireGuard interface came up, so the phase first reads the plexd container's log into a variable (`dc logs plexd`) and looks for `wireguard interface configured` with a `case` statement. It does not use `grep -q` in a pipeline: under `pipefail`, `grep -q` exits at the first match, the writer upstream can fail on the closed pipe, and the pipeline then reports a present line as missing. Without the line the phase prints:

```text
SKIP: handshake report and tunnel_health (WireGuard did not come up in this container)
```

With the line it checks three things:

1. **A report arrived.** Polls `GET /test/assertions` for up to 90 seconds until `handshake_report_count` >= 1. The e2e config keeps the default 30s `heartbeat.interval`, and the reporter sends its first report one interval after it starts.
2. **The body is an empty report.** Reads `GET /test/last-request/handshakes` and asserts with `jq` that the body has exactly the keys `observed_at` and `peers`, and that `peers` is an array of length 0. The fixture peers never complete a handshake, and the reporter omits a peer without one.
3. **Tunnel metrics name a fixture peer.** Polls `GET /test/last-request/metrics` for up to 30 seconds for at least one `tunnel_health` sample whose `labels.peer_id` is one of the two fixture node IDs (`0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1`, `0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2`). The tunnel collector keeps peers with no handshake, so the samples exist without one.

This phase is the only run anywhere that reads a kernel WireGuard device through `NetlinkController.PeerStats`, so it must not be weakened to the skip path.

### Phase 3 (cont.): Edge PSKs

Runs as script phase `4c`, directly after phase `4b`, and checks that plexd fetches and opens the [edge PSK](../../guide/security.md#pre-shared-keys-psk) of each fixture peer from the mock's [PSK route](mock-api-server.md#get-v1-nodes-id-peers-peer-node-id-psk). The e2e config leaves `wireguard.edge_psk` unset, which reads as enabled.

plexd fetches edge PSKs only when its WireGuard interface came up, so the phase reuses phase `4b`'s check for `wireguard interface configured`. Without the line it prints:

```text
SKIP: edge psk (WireGuard did not come up in this container)
```

With the line it checks two things:

1. Polls `GET /test/assertions` for up to 60 seconds until `edge_psk_count` >= 2, which shows the mock served both envelopes. plexd syncs its edge PSKs on every pull, before the WireGuard handler adds the peers, so the first pull after start fetches the PSK of both fixture peers.
2. For each fixture node ID, polls `dc logs plexd` for up to 30 seconds for an `edge psk fetched` line naming that peer, which shows plexd opened its envelope. plexd writes the line only after the envelope opened under the NSK with the edge's additional authenticated data. The line names the peer and the epoch, never the key. The log is read line by line and matched with `case`, for the same `pipefail` reason as in phase `4b`.

### Phase 3 (cont.): Endpoint Candidates and Endpoint Selection

Runs as script phase `4d`, directly after phase `4c`, and checks the two halves of endpoint candidates: the [candidate publisher](../networking/nat-traversal.md#local-endpoint-candidates) reporting this container's addresses to the mock's [candidates route](mock-api-server.md#put-v1-nodes-id-endpoint-candidates), and [endpoint selection](../networking/wireguard.md#endpoint-selection) moving a fixture peer along its dial order and to a new relay fallback. The e2e config leaves `wireguard.persistent_keepalive` and `nat.local_candidates` unset, which read as 25s and enabled.

plexd publishes candidates and runs endpoint selection only when its WireGuard interface came up, so the phase reuses phase `4b`'s check for `wireguard interface configured`. Without the line it prints:

```text
SKIP: endpoint candidates and endpoint selection (WireGuard did not come up in this container)
```

With the line it checks four things:

1. Polls `GET /test/assertions` every 3 seconds for up to 30 seconds until `endpoint_candidates_count` >= 1. The publisher reports once when it starts, so the report has usually landed by the time the phase runs.
2. Reads `GET /test/last-request/endpoint-candidates` and asserts with `jq` that the body has exactly the keys `candidates` and `reported_at`, that `candidates` is an array of 1 to 8 entries, that every entry ends in `:51820` (the `wireguard.listen_port` in `plexd-e2e.yaml`), and that no entry starts with `10.99.0.`, the mock's mesh prefix. Each `jq` expression answers `true` only when its check holds, so a `jq` error fails the check rather than passing it.
3. Polls `dc logs plexd` every 3 seconds for up to 75 seconds for a line that contains both `trying next endpoint candidate` and the fixture node ID `0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1`. That peer's dial order is its candidate `192.0.2.10:51820`, then its fallback `203.0.113.1:51820`. No node holds its key, so no handshake completes, and endpoint selection switches to the fallback once the first entry has gone 30 seconds without one (the 25s keepalive plus 5s). The 75 seconds cover that timeout, counted from the pull that programmed the peer, with room for the 5-second selection tick and a slow start. The log is read line by line and matched with `case`, as in phase `4b`.
4. Waits up to 80 seconds for the next `trying next endpoint candidate` line for that peer naming `203.0.113.1:51820`. The fallback is held for 30 seconds too, and each switch lands on a 5-second tick, so one cycle of the order takes up to 70 seconds. While plexd holds the peer on that relay, the phase splices `fallback_endpoint` `203.0.113.2:51820` into the peer of the live snapshot with `POST /test/configure-state` and injects a `node_state_updated` nudge. It then polls every 2 seconds for up to 24 seconds for a line that contains `relay fallback changed, moving to the new relay`, the node ID, `203.0.113.1:51820` and `203.0.113.2:51820`, and fails if a new `endpoint switch failed` line names the peer. The [move](../networking/wireguard.md#endpoint-selection) removes the peer from the kernel device and adds it again. Last, it splices `203.0.113.1:51820` back with a second nudge, which it does not wait for, so later phases see the fixture as it was. Each splice reads the live snapshot with a real `GET` on the state endpoint, which increments `state_count`.

This phase is the only run anywhere that switches an endpoint on a real device, so it must not be weakened to the skip path.

### Phase 3 (cont.): Mesh MTU

Runs as script phase `4e`, directly after phase `4d`, and checks [mesh MTU detection](../networking/wireguard.md#mtu-detection): plexd measures the uplink with the [path MTU probe](../networking/nat-traversal.md#path-mtu-probe), sizes its WireGuard interface to the result, and starts the 10-minute re-probe loop. The e2e config leaves `wireguard.mtu` unset and sets `nat.enabled: true`, so `Setup` probes the STUN servers before it creates the interface.

There is a mesh MTU to check only when the WireGuard interface came up, so the phase reuses phase `4b`'s check for `wireguard interface configured`. Without the line it prints:

```text
SKIP: mesh mtu (WireGuard did not come up in this container)
```

With the line, the phase reads `dc logs plexd` into a variable once and takes the first `wireguard interface configured` line. No restart has happened yet, so that is the line `Setup` wrote at start. It reads the values of `mtu_source=` and `mtu=` with parameter expansion, matching each key with a space in front of it so that `path_mtu=` does not match. Lines are matched with `case`, for the same `pipefail` reason as in phase `4b`. It then checks four things:

1. **The probe chose the MTU.** `mtu_source` must be `probe`. When it is `default`, the startup probe heard no STUN server, and the phase fails with a message that points at the `wireguard: mtu probe inconclusive, using the default mtu` warning in the plexd log. Any other value fails too.
2. **The MTU is in range.** `mtu` must be a number from 1280 to 1420. The phase checks a range, not a value, because the uplink decides it: a 1500-byte path gives 1420, a 1492-byte PPPoE path 1412, and a 1452-byte path of DS-Lite over PPPoE 1372.
3. **The device holds the logged MTU.** Reads `/sys/class/net/wg-plexd/mtu` with `dc exec -T plexd head -c 16`, strips the newline on the host, and requires the same number as the log line. `wg-plexd` is the `wireguard.interface_name` in `plexd-e2e.yaml`, and `head` is the busybox applet in the e2e image. The re-probe loop's first round comes 10 minutes after start, after the phase has run, so the device still holds what `Setup` programmed.
4. **The re-probe loop started.** Requires a line that contains both `wireguard: mtu probe started` and `interval=10m0s`. `RunMTUProbe` logs it first thing when step 17c of `plexd up` starts the loop, next to the endpoint selection that phase `4d` has already seen at work.

An inconclusive probe fails the phase instead of skipping it. The suite's endpoint report check already needs outbound UDP to `stun.l.google.com` and `stun.cloudflare.com`, so a probe that heard neither server is broken. The unit tests probe a loopback fake server. This phase is the only run anywhere that probes real STUN servers across a real uplink and programs the result on a kernel device, so it must not be weakened to the skip path.

### Phase 4: Log Injection

Injects a log file into the plexd container via `docker cp` (the container is distroless with no shell). The `FileSource` discovers the new file via glob, reads it, and the forwarder reports it to the API. Verifies `logs_count` increases.

### Phase 5: Agent Restart for Audit

The `ProcessSource` uses `sync.Once` to emit a single `process_start` audit entry per process lifetime. Restarting the plexd container creates a new process with a fresh `ProcessSource`, verifying `local_audit_count` increases.

That entry travels to the local endpoint only. Its source is plexd's own `process`, which is not in the audit ingest contract's closed enum (`auditd`, `k8s`), and a record naming a value outside that set refuses the whole batch with `400 ingest_batch_malformed`. The reporter therefore skips it, and the phase also asserts `audit_count == 0`: with no contract-legal audit source wired, the platform leg carries nothing. If the agent grows an auditd or Kubernetes audit reader, that assertion is the thing to update.

### Phase 6: SSE Event Injection

Injects a `node_state_updated` event via `POST /test/inject-event` and verifies that `state_count` increases, proving the SSE stream is connected and event-driven reconciliation works.

### Phase 6 (cont.): Signing Key from the State Pull

Runs as script phase `7c` and covers a node that holds a signing key its Domain no longer signs with, which learns the Domain key only from the state pull's `signing_key` block (see [Key from the state pull](../core/event-verification.md#key-from-the-state-pull)). Every check fails the suite; none is a soft warning.

1. `POST /test/rotate-signing-key` switches the mock to a fresh key and answers with its `key_id`. From then on the mock signs every envelope with that key and every pull carries it; plexd still holds the key it registered with.
2. The phase posts the mock's default heartbeat response, `{"reconcile":true,"rotate_keys":false}`, so the next heartbeat triggers a pull, and leaves it in place for the later phases. It then polls the plexd log for up to 60 seconds for an `installed signing key from state pull` line naming the new key id.
3. It injects `node_state_updated` event `evt-e2e-sigkey-001`, signed with the new key, and requires `state_count` to rise within 15 seconds with no `event verification failed` line naming the event.
4. It reads `/var/lib/plexd/identity.json` from the container with `head` and requires `"signing_key_id"` to hold the new key id: plexd persisted the key.
5. It restarts the plexd container and waits up to 60 seconds until `events_request_count` has risen, so the restarted agent opened its event stream, and `state_count` has risen after that. It requires that `registration_count` did not move and that the log gained an `existing identity loaded` line: the restarted agent resumed the identity it persisted, since a new registration would hand it the mock's current key and prove nothing. It then injects `evt-e2e-sigkey-002` and requires the same rise and no verification failure, and requires that the log still holds exactly one `installed signing key from state pull` line for the key: the restarted process started from the persisted key and had nothing to install.

Like phase `4b`, the phase reads the plexd log into a variable and matches lines with `case`, never with `grep -q` in a pipeline.

### Phase 7: Session Lifecycle from the State Pull

Drives the whole mediated-access lifecycle through the `sessions` block (script phase `8e`). Splicing a `tcp` entry with a future `expires_at` into that block provisions a listener: the test polls `session_activity_count` to +1 and asserts the captured row carries `tcp.phase = session_started`, the configured `target_host` / `target_port`, and a non-empty `host:port` `listener_endpoint` — the address the listener actually bound. Re-posting the snapshot with an empty `sessions` array is the teardown signal. This phase sends no `session_revoked` event, so the drain alone closes the session. The `session_ended` row is posted for a session the mock holds as revoked, and the mock, like the control plane, records the ending row of such a session once, so the row is accepted: the leg polls `session_activity_count` to +2 over the phase's baseline and asserts `session_activity_rejected_count` did not move. The captured row is `session_ended` with `terminated_by = plexd_close` and `bytes_in` / `bytes_out` present as numbers. With no `session_revoked` event, the node cannot tell a revocation from a control plane that failed to serve the block, so it does not claim `operator_revoke`. There is no revocation endpoint: without the event, the drain is the whole mechanism (the next section covers the event).

Script phase `8i` covers the other way a session ends on the node's own initiative: an entry carrying `idle_timeout_seconds: 1` provisions a listener nothing ever connects to, so the window runs out from the bind. `session_activity_count` reaches +2 with no drain at all, and the captured row is `session_ended` with `terminated_by = idle_timeout` — the entry is still standing in the block when its session ends, and it is not provisioned again.

### Phase 7 (cont.): A Signed session_revoked Closes the Session It Names

Runs as script phase `8j`, after phase `8i`, and covers a revocation the control plane announces in a verified `session_revoked` event: plexd closes the session the payload names at once and reports the `terminated_by` the payload's `revoke_reason` maps to (see [Secure Access Tunneling](../networking/secure-access-tunneling.md)). Every check fails the suite.

1. It configures `tcp` session `sess-e2e-revoke-001` (target `127.0.0.1:8080`, `expires_at` 5 minutes ahead, no `idle_timeout_seconds`), polls `session_activity_count` for up to 30 seconds to +1 over the phase's baseline, and requires the captured row to be `tcp.phase = session_started`.
2. While the entry still stands in the block, it injects `session_revoked` event `evt-e2e-sess-revoke-001` and requires `204`. The payload is an object carrying `session_id` and `jti` (both `sess-e2e-revoke-001`), `revoked_at` (the current time) and `revoke_reason` `operator_request`.
3. It polls `session_activity_count` every second for up to 15 seconds for +1 over the started row, and requires `session_activity_rejected_count` unchanged. The entry still stands, and the session has no idle window and a 5-minute expiry, so only the event can produce that row inside the window. The mock still holds the session as live, so it records the row. The captured row must be `tcp.phase = session_ended` with `tcp.terminated_by = operator_revoke` (plexd maps `operator_request` to it) and `bytes_in` / `bytes_out` present as numbers.
4. It drains the entry, takes the `state_count` baseline after `configure_sessions` (which counts on `state_count` itself), waits up to 30 seconds for a pull and 5 seconds more for that pull's dispatch, then requires both activity counters unchanged: the session is already closed, so the drain finds no live session and posts no second ending row.

### Phase 7 (cont.): Tunnel Traffic Reported as Session Activity

Runs as script phase `8k`, after phase `8j` and before phase `8h`, and covers the `session_active` rows a tcp tunnel posts while it forwards bytes, which keep the control plane's idle sweeper away from a tunnel in use (see [Activity Reports](../networking/secure-access-tunneling.md#activity-reports)). The mock counts these rows on `session_active_count` alone (see [the session activity route](mock-api-server.md#post-v1-nodes-id-sessions-sid)), so the `session_activity_count` arithmetic of phases `8e`, `8i` and `8j` does not move. Every check fails the suite.

1. It reads the baselines of `session_activity_count` and `session_active_count`, and sets `expires_at` 5 minutes ahead, as phase `8j` does.
2. It configures `tcp` session `sess-e2e-active` (target `mock-api:8080`, `idle_timeout_seconds` 24). The 24-second window gives a 6-second interval. It polls `session_activity_count` for up to 30 seconds to +1 over the baseline, reads `tcp.listener_endpoint` from `GET /test/last-request/session_activity`, and splits it into host and port. It requires `session_active_count` still at its baseline: no byte has crossed yet.
3. It sends two requests through the listener from inside the plexd container with the busybox `nc` applet, the second straight after the first, and requires exit status 0 from each. The tunnel forwards to the mock's own health route. The first request, `dc exec -T plexd /bin/busybox sh -c "{ printf 'GET /v1/health HTTP/1.0\r\n\r\n'; /bin/busybox sleep 1; } | /bin/busybox nc -w 3 <host> <port>"`, keeps `nc`'s stdin open for a second so the mock's answer comes back before `nc` half-closes its socket, since the tunnel ends both halves as soon as either direction ends. The answer has to start with an `HTTP/1.x` status line, so bytes crossed in both directions. The second request only sends. plexd's nftables chain hooks `forward` only, so a connection from inside the container to its own mesh address is not filtered.
4. It requires both requests to have taken at most 3 seconds, counted in whole seconds, which keeps them well inside the first 6-second interval; a slower host fails the phase with that reason. It then reads `session_active_count` once and requires exactly +1: the first bytes posted a row at once, and the bytes after them, the answer and the second request, wait for the interval's end. It requires the captured `session_activity` body, compacted with `jq -c .`, to equal `{"tcp":{"phase":"session_active"}}`.
5. It polls for up to 10 seconds for `session_active_count` at +2: the row at the end of the first interval, which covers the answer and the second request.
6. It sleeps 13 seconds, more than two intervals, with no traffic, and requires `session_active_count` still at +2: a quiet tunnel posts nothing.
7. It drains the entry with an empty `sessions` block, so the session does not reach a later phase, and polls `session_activity_count` for up to 30 seconds to +2 over the baseline: the one `session_ended` row, from the drain or from the 24-second idle window. Waiting for it keeps that row out of phase `8h`'s baseline. From the same response it then requires `session_activity_count` exactly at +2 and `session_active_count` exactly at +2, so the `session_active` rows moved only their own counter and closing the session posted no further one.

### Phase 8: Session Events as Pull Triggers

Proves that `session_setup` is a reconcile trigger rather than a delivery channel, and that a `session_revoked` plexd cannot decode closes nothing and still pulls (script phase `8h`). Each is injected with the JSON string `"{}"` where the payload object belongs. plexd never parses `session_setup`'s payload. It does parse `session_revoked`'s (phase `8j`), but a string does not decode into it, so the handler closes nothing, triggers the reconcile, and returns the error, which the event dispatcher logs at Error as `event handler failed`. The test asserts `state_count` advances within a window deliberately shorter than the ~30s heartbeat reconcile cadence — what is proven is that the pull happens *now* — and that `session_activity_count` is unchanged afterwards: the resulting pull found no session in the block, so nothing was provisioned or torn down.

### Phase 8 (cont.): Secret Index from the Inventory

Runs as script phase `12c`, between phases `12b` and `13`, and checks that the state pull's `secrets` block feeds the local node API's secret index, and that `node_secrets_updated` is a pull trigger rather than a delivery channel. The phase polls [`GET /v1/state/secrets`](../core/nodeapi.md#get-v1-state-secrets) on the node API's TCP listener, with its bearer token, every 2 seconds until the compact JSON (`jq -c`) equals the expected list. Each entry's `name` appears in the listing as `key`, with its `version`, in pull order.

The `configure_secrets` helper drives the block. Like `configure_sessions`, it reads the live snapshot, splices `.secrets` into it with `jq`, and posts the result to `POST /test/configure-state`. Given a nudge type, it then injects an envelope of that type so plexd pulls right away; without one, the caller decides what makes plexd pull. Reading the live snapshot is a real `GET` on the state endpoint, so a check that gates on `state_count` takes its baseline after the helper.

The phase checks three things:

1. **The pull fills the index.** It configures `[{"name":"api-token","version":1},{"name":"db-password","version":2}]` with a `node_state_updated` nudge, then polls for up to 30 seconds for the listing `[{"key":"api-token","version":1},{"key":"db-password","version":2}]`.
2. **The event pulls a changed inventory.** It first sets the heartbeat fixture to `{"reconcile":false,"rotate_keys":false}` through `POST /test/configure-heartbeat`, because a window shorter than the ~30s heartbeat cadence does not keep a heartbeat-driven pull out of it. The only other pull that nothing triggers is the 60s reconcile ticker, which the first step's nudge reset moments earlier. It then configures `[{"name":"db-password","version":3}]` with no nudge, takes the `state_count` baseline after the splice, and injects `node_secrets_updated` event `evt-e2e-secrets-001`, whose payload carries the contract's `event_id`, `occurred_at`, `node_id`, and `secrets`. It requires `state_count` to advance within 15 seconds and then polls for up to 15 seconds for the listing `[{"key":"db-password","version":3}]`. plexd treats the payload as opaque, so the new version reaches the index only through the pull the event triggers. Finally it sets the heartbeat fixture back to `{"reconcile":true,"rotate_keys":false}` for the later phases.
3. **An empty inventory empties the index.** It configures `[]`, which says the node may read nothing, with a `node_state_updated` nudge, and requires the listing `[]` within 30 seconds.

### Phase 9: Convergence Cycle

Posts a full mutated `NodeStateSnapshot` envelope to `POST /test/configure-state` (a new policy fingerprint and new state values), then polls until **both** hard conditions hold: `state_count` advances (the agent re-fetched the snapshot) and the count of `"reconciliation cycle completed"` lines whose `drift` summary contains `policy` increases (the differ reported `PolicyChanged`, so the policy handler ran). Both fixture peers are surfaced and asserted through the node API `GET /v1/peers`.

The assertion deliberately gates on the reconciler drift summary rather than on `"policy ruleset applied"`. The test container's kernel exposes no nftables backend, so policy enforcement stays disabled there and no rule can reach the kernel; the applied-log is emitted only on a real apply and would never fire. Proving rule installation requires an environment with a working nftables backend.

`POST /test/configure-state` replaces the **whole** snapshot fixture, which is also how the action phases drive execution: they queue a dispatch by reading the live snapshot, splicing an entry into its `executions` array, and posting the result back, then inject a `node_state_updated` envelope so the agent pulls immediately instead of waiting out the reconcile cadence. Because the fetch leg is a real `GET` on the state endpoint, it increments `state_count` — a phase gating on that counter must take its baseline **after** configuring the block. Action dispatches never ride an SSE payload, so `action_request` can only be used the same way: as a nudge that pulls the next reconcile forward.

The session phases drive the `sessions` array through the same splice, via the `session_entry` and `configure_sessions` helpers. The one difference is what a re-post means: `executions` is a delivery queue that drains when the node settles an entry, while `sessions` is desired state, so dropping an entry from the array *is* the revocation — the node tears the listener down on the pull that no longer carries it, unless a signed `session_revoked` event closed it first (phase `8j`). `session_setup` is a nudge exactly like `action_request`, carrying no session of its own. `session_revoked` is parsed: a payload that names a live session closes it before the pull, and one plexd cannot decode, like phase `8h`'s, closes nothing and still pulls.

### Phase 10: Policy Fingerprint No-Op

Re-posts the envelope with only `revision_id` bumped and a metadata value changed — the policy `fingerprint` stays identical. The test asserts `state_count` advances (the no-op envelope was fetched) but the policy-drift cycle count is **unchanged**, exercising the differ's fingerprint short-circuit: a revision-only bump must not report `PolicyChanged`.

### Phase 11: Local Endpoint Delivery

Polls `GET /test/assertions` until `local_metrics_count`, `local_logs_count`, and `local_audit_count` are all >= 1 (timeout: 60s). This validates the full local endpoint credential chain: registration (32-byte NSK) → secret fetch → AES-256-GCM decryption → Bearer token → HTTPS POST to mock-api's TLS listener on `:8443`.

### Phase 12: Local Endpoint Body Validation

Uses `GET /test/last-request/local_{metrics,logs,audit}` to verify each local endpoint received a non-empty JSON array payload.

### Phase 13: Dual Delivery Verification

Asserts that both platform counters (`metrics_count`, `logs_count`, `audit_count`) and local counters (`local_metrics_count`, `local_logs_count`, `local_audit_count`) are all >= 1, proving parallel delivery to both the central API and the local endpoint.

### Phase 20: Bearer Envelope on Every Authenticated Call

Every phase above runs through the mock's bearer-envelope gate, so this one states the outcome: `unauthorized_count` is 0 across the whole run, and the agent log carries no `credential refused` line, which the heartbeat logs as a Warn on the first two `401`s in a row and as an Error when the third parks the agent. Both halves matter — an agent that registers successfully and is then refused on every later call looks healthy while delivering nothing, which is how the defect in issue #60 reached two releases. A phase that drives an authenticated route itself presents the same envelope, fetched once from `GET /test/bearer`.

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

An anonymous volume at `/var/lib/plexd` provides a writable data directory that survives `dc restart plexd`, as the data directory of a real node survives a reboot: a restarted agent resumes the identity it persisted rather than registering again. `dc down -v` removes the volume. `/var/run/plexd` is a `tmpfs` mount.

The hook fixture ships in the image: the final stage of `test/e2e/docker/Dockerfile.plexd` copies `test/e2e/docker/hooks/` to `/etc/plexd/hooks/`, and no bind mount covers that path. Step `10f` adds hooks while the agent runs, so the directory has to be writable. The container layer takes those writes and survives `dc restart plexd`, and files the suite creates never land root-owned in the repository.

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
| `test/e2e/docker/Dockerfile.plexd` | E2E plexd image: the production runtime plus a static busybox shell and the hook fixture |
| `test/e2e/docker/hooks/` | Hook fixture copied into the image (`e2e-bigout`) |
| `test/e2e/mockapi/Dockerfile` | Mock API image (includes wget for healthcheck) |
| `deploy/docker/Dockerfile` | plexd production image |
| `Makefile` | `test-e2e-docker` target |
