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
│   │  Shutdown  │◀── or command ──┤                                     │      │
│   │            │                 │  ┌─────────────┐ ┌───────────────┐  │      │
│   └────────────┘                 │  │ Heartbeat   │ │ Reconcile     │  │      │
│                                  │  │ NAT Refresh │ │ SSE Stream    │  │      │
│   • Stop accepting new work      │  └─────────────┘ └───────────────┘  │      │
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
6. **Shutdown** - On a shutdown signal or explicit command: graceful local shutdown with cleanup (see details below).

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
| `200 OK` + `{ "rotate_keys": true }` | Trigger the mesh-key rotation flow: generate, stage, submit, swap (redundant with SSE, serves as fallback) |
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

## Shutdown and Deregistration

### Graceful shutdown

When the running agent (`plexd up`) receives a shutdown signal (`SIGTERM`,
`SIGINT`) it performs a graceful **local** shutdown. It sends **no** deregister
call to the control plane — removing a node from the platform is operator-driven.

1. **Stop accepting new work** - Stop accepting new action requests and SSE events.
2. **Drain in-flight executions** - Wait for all running action/hook executions to complete (up to the 30s drain timeout). After the grace period, running executions are cancelled and reported as `cancelled` to the control plane.
3. **Tear down tunnels** - Remove all WireGuard peers from the `plexd0` interface and delete the interface.
4. **Stop subsystems** - Stop log forwarding, audit collection, observability reporting, access proxy, and heartbeat.

The local identity is left in place, so the agent re-attaches on its next start.
Once the node stops sending heartbeats the control plane marks it `unreachable`,
then `offline`, and its peers drop it from their tunnel configuration (see
[Heartbeat Protocol](#heartbeat-protocol)).

### `plexd deregister`

`plexd deregister` is a separate, **local-only** cleanup command; it makes no
request to the control plane. It removes the node's `identity.json` from
`data_dir` and prints that platform-side removal is operator-driven. With
`--purge` it additionally removes the whole `data_dir` (all identity and key
files, cached state) and the registration token file. `--purge` does **not**
disable the systemd unit — use `plexd uninstall` to remove the service. See the
[CLI Reference](/reference/core/cli#plexd-deregister) for the exact output and
exit codes.

## Operational Behavior

### Offline Behavior

plexd is designed to remain functional when the control plane is temporarily unreachable:

- **Mesh connectivity persists:** Established WireGuard tunnels continue to operate independently of the control plane. Peers can communicate as long as the tunnels are up.
- **Configuration is cached:** The last known peer list, policies, and signing keys are persisted to `data_dir`. On restart without control plane connectivity, plexd restores the cached state and establishes tunnels to known peers.
- **Buffered telemetry:** Log, audit, and observability data are buffered in local ringbuffers and drained when connectivity is restored.
- **No new peers:** New peers cannot be added while offline, as peer key exchange requires the control plane. Existing peers continue to work.
- **Heartbeat failure:** After 3 missed heartbeats, the control plane marks the node as `unreachable`. This does not affect the node's local operation.
- **Actions are unavailable while the control plane is unreachable:** Action dispatches arrive in the `executions` block of the state pull, so they need the control plane, not the event stream. A node whose SSE stream is descoped or disconnected but whose pull still succeeds keeps executing dispatches — just at the reconciliation cadence instead of within milliseconds, because `action_request` only pulls the next reconcile forward. Local actions via `plexd actions run --local` remain available regardless.
- **Secrets are unavailable:** Secret values are fetched in real-time from the control plane and never cached in plaintext. When the control plane is unreachable, secret read requests return `503 Service Unavailable`. Metadata and data entries remain available from the local cache.

### Upgrade Process

plexd supports in-place upgrades triggered by the control plane via the `service.upgrade` built-in action. The binary comes from the release channel, and every upgrade is gated on both a dispatched checksum and an offline Sigstore signature check — a release the platform did not sign is refused.

1. The control plane queues an execution for `action: service.upgrade` in the `executions` block of the state pull, with the target `version` and expected binary `checksum` among its `parameters`.
2. plexd downloads the release binary from the configured release channel (`{upgrade.release_base_url}/{tag}/plexd-linux-{arch}`, with `{tag}` the `v`-prefixed version) into a temporary file, computing its SHA-256 as it streams. Upgrades are Linux-only; a non-Linux node refuses. plexd never fetches the binary from the control plane.
3. plexd compares the download's SHA-256 to the dispatched `checksum`. A mismatch ends the action with the terminal status `checksum_mismatch` (exit 1) and the running binary is untouched.
4. plexd downloads the release's Sigstore bundle (`plexd-linux-{arch}.sigstore.json`) and verifies it **offline** against the embedded Sigstore public-good trusted root: the signing certificate's issuer and SAN must match `upgrade.signing_issuer` / `upgrade.signing_identity_regexp`, and the signed artifact digest must match the downloaded binary. A release with no bundle asset fails the bundle download and is refused; a bundle that fails verification ends the action with the terminal status `bundle_verification_failed` (exit 1) and the temporary file is removed. In both cases the running binary is untouched.
5. Once both checks pass, plexd makes the new binary executable (`chmod 0755`), atomically renames it over the current binary, and triggers `systemctl restart plexd.service`. The terminal status is `upgraded` on a successful restart, `upgraded_restart_pending` when `systemctl` is unavailable, or `upgraded_restart_failed` when the restart command errors.
6. If the new binary fails to start (crash loop), systemd's `RestartSec` and `StartLimitBurst` prevent excessive restarts. Manual intervention or a follow-up upgrade is required.

Rollback is a new `service.upgrade` action pointing to a previous version (a version published without a Sigstore bundle is refused by the signature check).

**Sigstore root rotation.** Verification chains to the Sigstore public-good trusted root vendored into the binary, so it needs no network access — but that embedded copy can go stale. If Sigstore rotates its public-good root, releases signed under the new keys no longer chain for an already-deployed node, and every upgrade to such a release is refused with `bundle_verification_failed` while the running binary is left untouched. Because the refreshed root normally ships inside a plexd release, the upgrade path itself is blocked and must be repaired out of band: point `upgrade.trusted_root_path` at a current `trusted_root.json` (or reinstall the package), then re-issue the upgrade.

### Mesh IP Allocation

Each node receives a unique mesh IP from the `10.100.0.0/16` range during registration. IPs are assigned by the control plane and are stable for the lifetime of the node's registration.

- **Format:** `10.100.x.y/32` (single host address per node)
- **Uniqueness:** Guaranteed by the control plane within a tenant
- **Persistence:** The mesh IP is stored in `data_dir` and reused across restarts
- **Decommission:** When a node is removed from the platform (operator-driven), its mesh IP is returned to the pool after a cooldown period (to avoid conflicts with cached peer configurations on other nodes)
- **Bridge nodes:** Typically assigned from a reserved range (e.g. `10.100.255.x`) by convention, but this is a control plane policy, not enforced by plexd

### Reconciliation

The reconciliation loop (`reconcile.interval`, default 60s) ensures that the local state matches the control plane's desired state. It acts as a consistency fallback for the real-time SSE event stream.

Each reconciliation cycle:

1. **Pull the state snapshot** from `GET /v1/nodes/{node_id}/state` — the `NodeStateSnapshot` envelope with its always-present blocks (`peers`, `reachability`, `policy`, `bridge`, `state`, `reports`, `executions`). A `null` block means "not populated".
2. **Dispatch** the delivery-queue blocks. Today that is `executions`, the channel through which the control plane delivers action dispatches. This step runs on **every** successful pull, before the diff, so a queued action executes even when nothing has drifted.
3. **Diff** the snapshot against the local snapshot by presence: peer add/remove/update, and per-block change flags for policy, bridge, and the state/reports buckets. `executions` is a queue rather than desired state, so it is neither stored nor diffed.
4. **Apply corrections** for any detected drift:
   - Add/remove WireGuard peers (membership comes from the `peers` block; AllowedIPs derived as `mesh_ip/32`, no PSK)
   - Rebuild nftables rules from the merged `policy` block, but only when its fingerprint changed
   - Reconcile the bridge subtrees (relay, user access, ingress, site-to-site)
   - Feed the node state cache from the `state` block

The pull is one-way — plexd does not report drift back to the control plane. Applied-correction visibility will return as node-authored state reports (issue #23). Reconciliation is also triggered immediately after SSE reconnection (see [SSE Reconnection](#sse-reconnection)).

## See Also

- [Architecture](/guide/architecture) — Platform support, architecture diagrams, mesh topology
- [Platform Communication & Mesh](/guide/platform-communication) — Visual overview of communication channels
- [Agent Internals](/concepts) — Subsystem details, startup/shutdown sequences, SSE event types
