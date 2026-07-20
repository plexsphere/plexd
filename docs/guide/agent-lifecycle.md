---
title: Agent Lifecycle
---

# Agent Lifecycle

> For architecture diagrams and platform support, see [Architecture](/guide/architecture). For a visual overview of communication channels, see [Platform Communication & Mesh](/guide/platform-communication).

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                                                                               │
│   ┌─────────┐    ┌──────────┐    ┌───────────┐    ┌─────────────┐             │
│   │  Start  │    │          │    │ Configure │    │     NAT     │             │
│   │ Binary  ├───▶│ Register ├───▶│  Tunnels  ├───▶│  Discovery  │             │
│   │ Checksum│    │          │    │           │    │   (STUN)    │             │
│   │ Hook    │    └──────────┘    └───────────┘    └──────┬──────┘             │
│   │ Scan    │                                            │                    │
│   └─────────┘                                            ▼                    │
│                                                                               │
│   ┌────────────┐                 ┌─────────────────────────────────────┐      │
│   │            │  On shutdown    │            Connected                │      │
│   │ Deregister │◀── or command ──┤                                     │      │
│   │            │                 │  ┌─────────────┐ ┌───────────────┐  │      │
│   └────────────┘                 │  │ Heartbeat   │ │ Reconcile     │  │      │
│                                  │  │ NAT Refresh │ │ SSE Stream    │  │      │
│   • Notify control plane         │  └─────────────┘ └───────────────┘  │      │
│   • Tear down tunnels            │  ┌─────────────┐ ┌───────────────┐  │      │
│   • Wait for in-flight           │  │ Policy      │ │ Observe       │  │      │
│     action executions            │  │ Enforce     │ │ Logs, Audit   │  │      │
│   • Clean up local state         │  └─────────────┘ └───────────────┘  │      │
│                                  │  ┌─────────────┐ ┌───────────────┐  │      │
│                                  │  │ Access      │ │ Action        │  │      │
│                                  │  │ Proxy       │ │ Dispatcher    │  │      │
│                                  │  └─────────────┘ └───────────────┘  │      │
│                                  │  ┌─────────────┐ ┌───────────────┐  │      │
│                                  │  │ Hook File   │ │ Node API      │  │      │
│                                  │  │ Watcher     │ │ Server        │  │      │
│                                  │  └─────────────┘ └───────────────┘  │      │
│                                  └─────────────────────────────────────┘      │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

1. **Start** - Read config, locate bootstrap token, compute binary SHA-256 checksum, scan and checksum all declared hooks.
2. **Register** - POST token to control plane, receive node identity, keys, and initial peer list. Include capabilities (binary info, available actions, hooks with checksums).
3. **Configure Tunnels** - Set up mesh interfaces and establish tunnels to all authorized peers.
4. **NAT Discovery** - Determine public endpoint via STUN and report it to the control plane, which returns a freshness deadline (`stale_after`) that schedules the next report. Peer endpoints arrive separately via SSE.
5. **Connected** - Enter steady state: send heartbeats, stream peer/policy/action/state updates via SSE, report observability data, forward logs, collect audit data, serve access requests, dispatch actions, watch hook files for changes, serve node API, refresh STUN endpoints, reconcile periodically.
6. **Deregister** - On shutdown or explicit command: graceful shutdown with cleanup (see details below).

## Steady State

### Heartbeat Protocol

plexd sends a heartbeat to the control plane at `heartbeat.interval` (default 30s) via `POST /v1/nodes/{node_id}/heartbeat`.

Heartbeat payload:

```json
{
  "client_now": "2026-07-19T19:32:35Z",
  "binary_checksum": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "binary_version": "1.2.3",
  "nat_summary": { "endpoint": "203.0.113.10:51820", "nat_type": "full_cone" }
}
```

`nat_summary` is always a JSON object — `{}` before NAT discovery has a result. The control plane responds with `accepted_at` (its receive time, used to estimate clock skew) plus the directive flags below:

| Response | Meaning |
|---|---|
| `200 OK` | Heartbeat acknowledged, no action required |
| `200 OK` + `{ "reconcile": true }` | Trigger immediate reconciliation (out-of-band hint) |
| `200 OK` + `{ "rotate_keys": true }` | Trigger key rotation (redundant with SSE, serves as fallback) |
| `400 Bad Request` + `{ "code": "clock_skew" }` | `client_now` drifted more than 60s from the control plane; sync the system clock via NTP |
| `401 Unauthorized` | Node identity invalid, re-register |

If a node misses **3 consecutive heartbeats** (i.e. no heartbeat received for `3 x heartbeat.interval`), the control plane marks the node as `unreachable` and notifies peer nodes. After **10 consecutive missed heartbeats**, the node is marked `offline` and its peers remove it from their active tunnel configuration. The node re-establishes tunnels automatically when it comes back online and resumes heartbeats.

### SSE Reconnection

The SSE stream is the primary channel for real-time updates. When the connection drops:

1. plexd detects the disconnect and begins reconnection with **exponential backoff**: 1s, 2s, 4s, 8s, ... up to a maximum of 60s.
2. **Jitter** of +/-25% is applied to each backoff interval to prevent thundering herd effects when many nodes reconnect simultaneously (e.g. after a control plane restart).
3. On reconnection, plexd sends the `Last-Event-ID` header (from the last successfully processed SSE event) so the control plane can replay missed events.
4. After a successful reconnect, plexd triggers an **immediate reconciliation** to catch any updates that may have been missed during the disconnect window.
5. If the SSE stream cannot be re-established after 5 minutes, plexd falls back to polling the full state at `reconcile.interval` until the SSE stream recovers.

## Deregistration

When plexd receives a shutdown signal (`SIGTERM`, `SIGINT`) or the `plexd deregister` command is run:

1. **Stop accepting new work** - Stop accepting new action requests and SSE events.
2. **Drain in-flight executions** - Wait for all running action/hook executions to complete (up to 30s grace period). After the grace period, running executions are cancelled and reported as `cancelled` to the control plane.
3. **Notify control plane** - Send `POST /v1/nodes/{node_id}/deregister` to inform the control plane. The control plane removes the node from peer lists and pushes `peer_removed` events to all peers.
4. **Tear down tunnels** - Remove all WireGuard peers from the `plexd0` interface and delete the interface.
5. **Stop subsystems** - Stop log forwarding, audit collection, observability reporting, access proxy, and heartbeat.
6. **Clean up local state** - Optionally (when `--purge` is passed) remove all data from `data_dir`, including private keys and cached state. Without `--purge`, state is preserved for potential re-registration.

On `plexd deregister --purge`, the bootstrap token file is also removed if it still exists, and the systemd unit is disabled.

## Operational Behavior

### Offline Behavior

plexd is designed to remain functional when the control plane is temporarily unreachable:

- **Mesh connectivity persists:** Established WireGuard tunnels continue to operate independently of the control plane. Peers can communicate as long as the tunnels are up.
- **Configuration is cached:** The last known peer list, policies, and signing keys are persisted to `data_dir`. On restart without control plane connectivity, plexd restores the cached state and establishes tunnels to known peers.
- **Buffered telemetry:** Log, audit, and observability data are buffered in local ringbuffers and drained when connectivity is restored.
- **No new peers:** New peers cannot be added while offline, as peer key exchange requires the control plane. Existing peers continue to work.
- **Heartbeat failure:** After 3 missed heartbeats, the control plane marks the node as `unreachable`. This does not affect the node's local operation.
- **Actions are unavailable:** SSE-triggered actions cannot be received while offline. Local actions via `plexd actions run --local` remain available.
- **Secrets are unavailable:** Secret values are fetched in real-time from the control plane and never cached in plaintext. When the control plane is unreachable, secret read requests return `503 Service Unavailable`. Metadata and data entries remain available from the local cache.

### Upgrade Process

plexd supports in-place upgrades triggered by the control plane via the `service.upgrade` built-in action:

1. Control plane sends `action_request` with `action: service.upgrade`, including the target `version` and expected binary `checksum`.
2. plexd downloads the new binary from the control plane's artifact store, verifies the SHA-256 checksum, and places it alongside the current binary.
3. plexd signals the systemd service to restart (or re-execs in non-systemd environments).
4. On startup, the new binary computes its own checksum and reports it in the registration/heartbeat. The control plane verifies the upgrade succeeded.
5. If the new binary fails to start (crash loop), systemd's `RestartSec` and `StartLimitBurst` prevent excessive restarts. Manual intervention or rollback via the control plane is required.

Rollback is a new `service.upgrade` action pointing to the previous version.

### Mesh IP Allocation

Each node receives a unique mesh IP from the `10.100.0.0/16` range during registration. IPs are assigned by the control plane and are stable for the lifetime of the node's registration.

- **Format:** `10.100.x.y/32` (single host address per node)
- **Uniqueness:** Guaranteed by the control plane within a tenant
- **Persistence:** The mesh IP is stored in `data_dir` and reused across restarts
- **Deregistration:** When a node deregisters, its mesh IP is returned to the pool after a cooldown period (to avoid conflicts with cached peer configurations on other nodes)
- **Bridge nodes:** Typically assigned from a reserved range (e.g. `10.100.255.x`) by convention, but this is a control plane policy, not enforced by plexd

### Reconciliation

The reconciliation loop (`reconcile.interval`, default 60s) ensures that the local state matches the control plane's desired state. It acts as a consistency fallback for the real-time SSE event stream.

Each reconciliation cycle:

1. **Pull the state snapshot** from `GET /v1/nodes/{node_id}/state` — the `NodeStateSnapshot` envelope with its always-present blocks (`peers`, `reachability`, `policy`, `bridge`, `state`, `reports`). A `null` block means "not populated".
2. **Diff** the snapshot against the local snapshot by presence: peer add/remove/update, and per-block change flags for policy, bridge, and the state/reports buckets.
3. **Apply corrections** for any detected drift:
   - Add/remove WireGuard peers (membership comes from the `peers` block; AllowedIPs derived as `mesh_ip/32`, no PSK)
   - Rebuild nftables rules from the merged `policy` block, but only when its fingerprint changed
   - Reconcile the bridge subtrees (relay, user access, ingress, site-to-site)
   - Feed the node state cache from the `state` block

The pull is one-way — plexd does not report drift back to the control plane. Applied-correction visibility will return as node-authored state reports (issue #23). Reconciliation is also triggered immediately after SSE reconnection (see [SSE Reconnection](#sse-reconnection)).

## See Also

- [Architecture](/guide/architecture) — Platform support, architecture diagrams, mesh topology
- [Platform Communication & Mesh](/guide/platform-communication) — Visual overview of communication channels
- [Agent Internals](/concepts) — Subsystem details, startup/shutdown sequences, SSE event types
