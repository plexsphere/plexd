# Architecture and Concepts

## What plexd Does

plexd is the Plexsphere node agent — a lightweight daemon that runs on every managed node. It handles:

- **Registration** — self-registers with the control plane using a bootstrap token
- **State Reconciliation** — periodically fetches desired state and applies drift corrections
- **Remote Actions** — executes built-in and hook-based actions requested via SSE events
- **Observability** — collects and forwards metrics, logs, and audit events to the control plane
- **Integrity** — verifies checksums of the plexd binary and hook scripts

## Operating Modes

| Mode | Status | Description |
|------|--------|-------------|
| `node` | **Active** | Default mode. Runs all active subsystems listed below. |
| `bridge` | Inactive | Config value is parsed and validated, but bridge-specific code is not started by `plexd up`. |

## Active Subsystems

These subsystems are initialized and started by `plexd up`:

| Subsystem | Package | Reference |
|-----------|---------|-----------|
| Control Plane Client | `internal/api` | [Control Plane Client](reference/core/control-plane-client.md) |
| Registration | `internal/registration` | [Registration](reference/core/registration.md) |
| Event Verification | `internal/api` (Ed25519Verifier) | [Event Verification](reference/core/event-verification.md) |
| SSE Manager | `internal/api` (SSEManager) | [Control Plane Client](reference/core/control-plane-client.md) |
| Reconciler | `internal/reconcile` | [Configuration Reconciliation](reference/core/reconciliation.md) |
| Heartbeat | `internal/agent` (HeartbeatService) | [Heartbeat Service](reference/core/heartbeat-service.md) |
| Integrity | `internal/integrity` | [Integrity Verification](reference/actions/integrity-verification.md) |
| Actions | `internal/actions` | [Remote Actions and Hooks](reference/actions/remote-actions-hooks.md) |
| Node API | `internal/nodeapi` | [Local Node API](reference/core/nodeapi.md) |
| Metrics | `internal/metrics` | [Metrics Collection & Reporting](reference/observability/metrics-collection.md) |
| Log Forwarding | `internal/logfwd` | [Log Forwarding](reference/observability/log-forwarding.md) |
| Audit Forwarding | `internal/auditfwd` | [Audit Forwarding](reference/observability/audit-forwarding.md) |

## Inactive Subsystems

The following subsystems have code in the repository and their configuration sections are parsed and validated on startup, but they are **not started** by `plexd up`. Configuring these sections has no runtime effect.

| Subsystem | Package | Config Key | Reference |
|-----------|---------|------------|-----------|
| WireGuard | `internal/wireguard` | `wireguard` | [WireGuard Tunnel Management](reference/networking/wireguard.md) |
| NAT Traversal | `internal/nat` | `nat` | [NAT Traversal via STUN](reference/networking/nat-traversal.md) |
| Peer Exchange | `internal/peerexchange` | `peer_exchange` | [Peer Endpoint Exchange](reference/networking/peer-endpoint-exchange.md) |
| Network Policy | `internal/policy` | `policy` | [Network Policy Enforcement](reference/networking/network-policy.md) |
| Secure Tunneling | `internal/tunnel` | `tunnel` | [Secure Access Tunneling](reference/networking/secure-access-tunneling.md) |
| Bridge | `internal/bridge` | `bridge` | [Bridge Mode](reference/bridge/bridge-mode.md) |

## Startup Sequence (`plexd up`)

The `runUp` function in `cmd/plexd/cmd/up.go` performs 15 initialization steps before entering steady state:

**Initialization:**

1. **Parse config** — read YAML, apply CLI flag overrides, apply `PLEXD_*` env overrides
2. **Set up logger** — structured `slog` logger with configured level
3. **Create control plane client** — `api.NewControlPlane()` with API config and build version
4. **Register** — `registrar.Register()` loads or creates node identity (fatal on failure)
5. **Create Ed25519 verifier** — decode the control plane's signing public key from identity
6. **Create SSE manager** — `api.NewSSEManager()` with `signing_key_rotated` handler to update verifier keys
7. **Create reconciler** — `reconcile.NewReconciler()` with configured interval
8. **Create heartbeat service** — `agent.NewHeartbeatService()` with auth-failure callback (triggers re-registration) and key-rotation callback (triggers reconcile)
9. **Create integrity store + verifier** — `integrity.NewStore()` and `integrity.NewVerifier()` for hook checksums
10. **Create action executor** — `actions.NewExecutor()`, register 11 built-in actions, register `action_request` SSE handler, report capabilities to control plane
11. **Create hook watcher** — `actions.NewHookWatcher()` for filesystem hook scanning
12. **Create node API server** — `nodeapi.NewServer()`, wire action provider, hook reloader, and reconcile handler
13. **Create metrics collectors + manager** — system collector, agent stats collector, `metrics.NewManager()`
14. **Create log sources + forwarder** — journald source, file sources from `file_patterns`, `logfwd.NewForwarder()`
15. **Create audit sources + forwarder** — process source, `auditfwd.NewForwarder()`

**Goroutines (8):**

After initialization, 8 goroutines are started via a `sync.WaitGroup`:

1. **SSE Manager** — `sseMgr.Start()` — event stream connection
2. **Heartbeat** — `heartbeat.Run()` — periodic heartbeats
3. **Reconciler** — `reconciler.Run()` — periodic state reconciliation
4. **Node API** — `nodeAPISrv.Start()` — Unix socket + optional HTTP server
5. **Hook Watcher** — `hookWatcher.Watch()` — filesystem watching for hook changes
6. **Metrics Manager** — `metricsMgr.Run()` — collect and report metrics
7. **Log Forwarder** — `logForwarder.Run()` — collect and forward logs
8. **Audit Forwarder** — `auditForwarder.Run()` — collect and forward audit events

## Shutdown Sequence

On SIGTERM or SIGINT:

1. **Context cancel** — the signal-notify context is cancelled, which signals all goroutines to stop
2. **`sseMgr.Shutdown()`** — close the SSE connection
3. **`executor.Shutdown()`** — drain running actions
4. **`wg.Wait()` with 30s timeout** — wait for all 8 goroutines to exit; force exit if timeout exceeded

## Authentication Flow

1. **Bootstrap** — node registers using a bootstrap token (file, env var, or metadata service)
2. **Node Secret Key** — registration returns a `NodeSecretKey` used for all subsequent API authentication
3. **Heartbeat Auth** — each heartbeat uses the node secret key; on 401 Unauthorized, the `onAuthFailure` callback triggers re-registration
4. **Key Rotation** — on `signing_key_rotated` SSE events or heartbeat `RotateKeys` flag, the Ed25519 verifier keys are updated

## SSE Event Types

The SSE manager processes these event types in the current release:

| Event | Handler | Description |
|-------|---------|-------------|
| `signing_key_rotated` | Updates Ed25519 verifier keys | Fired when the control plane rotates its signing key pair |
| `action_request` | Dispatches to action executor | Requests execution of a built-in action or hook |

Other event types for inactive subsystems (e.g. peer configuration, tunnel updates) exist in the API types but are not registered as handlers by `plexd up`.

## See Also

- [Configuration Reference](reference/core/configuration.md) — Full YAML configuration schema
- [CLI Reference](reference/core/cli.md) — Command-line interface and subcommands
- [Environment Variables Reference](reference/core/environment-variables.md) — All `PLEXD_*` overrides
- [README](../README.md) — Project overview and quick start
