---
title: Secure Access Tunneling
package: internal/tunnel
feature: PXD-0009
---

# Secure Access Tunneling

The `internal/tunnel` package enables platform-mediated SSH access to mesh nodes through WireGuard tunnels without exposing services to the public internet. The control plane orchestrates session lifecycle via SSE events; the node agent opens a local TCP listener bound to the mesh IP, forwards connections to the target host, and reports status back to the control plane.

## Data Flow

```
Control Plane
      │
      │ SSE: ssh_session_setup
      ▼
┌──────────────┐     ┌─────────────────┐
│ EventDispatcher│───▶│ HandleSSHSession │
│  (internal/api)│    │    Setup         │
└──────────────┘     └───────┬──────────┘
                             │
                             ▼
                     ┌───────────────┐
                     │ SessionManager │
                     │  CreateSession │
                     └───────┬───────┘
                             │
                     ┌───────┴───────┐
                     │    Session     │
                     │               │
                     │ ┌───────────┐ │
                     │ │  Listener  │ │  ← bound to meshIP:0
                     │ │ (TCP)     │ │
                     │ └─────┬─────┘ │
                     │       │       │
                     │ ┌─────┴─────┐ │
                     │ │ Forwarder  │ │  ← bidirectional io.Copy
                     │ └─────┬─────┘ │
                     └───────┼───────┘
                             │
                             ▼
                      Target Host
                      (e.g. sshd)
```

### Event Sequence

1. Control plane sends `ssh_session_setup` SSE event with session parameters
2. `HandleSSHSessionSetup` parses the payload and calls `SessionManager.CreateSession`
3. `SessionManager` creates a `Session`, which opens a TCP listener on `meshIP:0`
4. `SessionActivityReporter.ReportSessionStarted` posts a `tcp` `session_started` row with the target host and port
5. Client connects through the mesh to the listener; `Session` forwards to the target
6. Session ends by expiry (`time.AfterFunc`), revocation (`session_revoked` SSE), or shutdown
7. The `SessionManager`'s on-closed callback fires `SessionActivityReporter.ReportSessionEnded`, posting a `tcp` `session_ended` row with byte counters and a `terminated_by` reason — for every close reason, `Shutdown` included

## Config

`Config` holds secure access tunneling parameters passed to the `SessionManager` constructor.

| Field            | Type            | Default | Description                                    |
|------------------|-----------------|---------|------------------------------------------------|
| `Enabled`        | `bool`          | `true`  | Whether tunneling is active                    |
| `MaxSessions`    | `int`           | `10`    | Maximum concurrent tunnel sessions             |
| `DefaultTimeout` | `time.Duration` | `30m`   | Default/maximum session timeout                |
| `SSHListenAddr`  | `string`        | —       | SSH mesh server listen address (empty = no SSH server) |
| `HostKeyDir`     | `string`        | —       | Directory for SSH host key (empty = transient key)     |

```go
cfg := tunnel.Config{
    MaxSessions: 5,
}
cfg.ApplyDefaults() // Enabled=true, DefaultTimeout=30m, MaxSessions stays 5
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

### Default Heuristic

`ApplyDefaults` uses zero-value detection: on a fully zero-valued `Config`, `MaxSessions == 0` triggers all defaults including `Enabled = true`. If `MaxSessions` is already set (indicating explicit construction), `Enabled` is left as-is. This allows `Config{Enabled: false}` to disable tunneling after `ApplyDefaults`.

### Validation Rules

| Field            | Rule                      | Error Message                                                 |
|------------------|---------------------------|---------------------------------------------------------------|
| `MaxSessions`    | Must be > 0 when enabled  | `tunnel: config: MaxSessions must be positive when enabled`   |
| `DefaultTimeout` | Must be >= 1m when enabled| `tunnel: config: DefaultTimeout must be at least 1m when enabled` |

Validation is skipped entirely when `Enabled` is `false`.

## Session

Represents an active tunnel session with a local TCP listener that forwards connections to a target host through the mesh.

### Fields

| Field        | Type              | Description                              |
|--------------|-------------------|------------------------------------------|
| `SessionID`  | `string`          | Unique session identifier                |
| `TargetHost` | `string`          | Target host to forward connections to    |
| `TargetPort` | `int`             | Target port                              |
| `MeshIP`     | `string`          | Mesh IP to bind the listener to          |

### Constructor

```go
func NewSession(sessionID, targetHost string, targetPort int, meshIP string, expiresAt time.Time, logger *slog.Logger) *Session
```

### Methods

| Method       | Signature                                  | Description                                              |
|--------------|--------------------------------------------|----------------------------------------------------------|
| `Start`      | `(ctx context.Context) (string, error)`    | Opens TCP listener on meshIP:0, starts accept loop       |
| `Close`      | `() error`                                 | Idempotent shutdown: cancels context, closes listener and connection, then waits (bounded) for the forwarding goroutines so the byte counters are complete |
| `ListenAddr` | `() string`                                | Returns listener address or empty string if not started  |

### Connection Lifecycle

1. `Start` binds a TCP listener to `meshIP:0` (ephemeral port, mesh-only interface)
2. `acceptLoop` runs in a goroutine, accepting one connection at a time
3. Single-connection enforcement: if a connection is already active, new connections are rejected
4. `forward` dials the target, sets the active connection under mutex, and runs bidirectional `io.Copy` with `sync.Once` cleanup and `sync.WaitGroup` for completion
5. `Close` is idempotent via `sync.Mutex` + `closed` flag; cancels context, closes listener and active connection

### Security

- Listener binds to mesh IP only, never `0.0.0.0` or `localhost`
- At most one active forwarded connection per session
- Context cancellation propagates to listener and active connection

## SessionManager

Central coordinator for tunnel session lifecycle.

### Constructor

```go
func NewSessionManager(cfg Config, meshIP string, logger *slog.Logger) *SessionManager
```

- Applies config defaults via `cfg.ApplyDefaults()`
- Logger is tagged with `component=tunnel`

### Methods

| Method         | Signature                                                        | Description                                              |
|----------------|------------------------------------------------------------------|----------------------------------------------------------|
| `CreateSession`| `(ctx context.Context, setup api.SSHSessionSetup) (string, error)` | Validates, creates, and starts a tunnel session          |
| `CloseSession` | `(sessionID string, reason string) *ClosedSessionInfo`           | Closes and removes a session by ID; returns session info |
| `Shutdown`     | `()`                                                             | Closes all active sessions, reporting each through the on-closed callback |
| `ActiveCount`  | `() int`                                                         | Returns number of active sessions                        |

### CreateSession Validation

| Check                  | Condition                           | Error                                              |
|------------------------|-------------------------------------|-----------------------------------------------------|
| Tunneling disabled     | `cfg.Enabled == false`              | `tunnel: tunneling is disabled`                     |
| Missing fields         | Empty ID, host, or port <= 0        | `tunnel: invalid session setup: ...`                |
| Already expired        | `ExpiresAt` in the past             | `tunnel: session already expired`                   |
| Duplicate ID           | Session ID already exists           | `tunnel: duplicate session ID: {id}`                |
| Capacity               | `len(sessions) >= MaxSessions`      | `tunnel: max sessions reached ({n})`                |

### Expiry

- `ExpiresAt` is capped at `DefaultTimeout` from now (never exceeds maximum)
- `time.AfterFunc` schedules automatic `CloseSession("expired")` at the capped expiry time

### Lifecycle

```go
logger := slog.Default()

mgr := tunnel.NewSessionManager(tunnel.Config{}, "10.0.0.1", logger)

// Create session from SSE event payload
addr, err := mgr.CreateSession(ctx, api.SSHSessionSetup{
    SessionID:  "sess-abc",
    TargetHost: "127.0.0.1",
    TargetPort: 22,
    ExpiresAt:  time.Now().Add(10 * time.Minute),
})

// Close specific session
mgr.CloseSession("sess-abc", "revoked")

// Graceful shutdown (closes all sessions)
mgr.Shutdown()
```

## SSE Event Handlers

Factory functions returning `api.EventHandler` for tunnel lifecycle events. Each parses the `Envelope.Payload` and calls the appropriate `SessionManager` method.

| Factory                  | Event Type           | Payload Type                        | Action                                     |
|--------------------------|----------------------|-------------------------------------|--------------------------------------------|
| `HandleSSHSessionSetup`  | `ssh_session_setup`  | `api.SSHSessionSetup`               | `CreateSession` + `ReportSessionStarted`   |
| `HandleSessionRevoked`   | `session_revoked`    | `{"session_id": "..."}`             | `CloseSession("revoked")` (on-closed callback emits the `session_ended` row) |

- Malformed payloads are logged at error level and return an error
- `HandleSessionRevoked` is a no-op if the session ID is not found (logged at debug level)

### Registration

```go
mgr := tunnel.NewSessionManager(tunnel.Config{}, meshIP, logger)

dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register("ssh_session_setup", tunnel.HandleSSHSessionSetup(mgr, reporter))
dispatcher.Register("session_revoked", tunnel.HandleSessionRevoked(mgr))
```

## SessionActivityReporter

Interface for reporting `tcp`-phase session activity rows to the control plane. Abstracted for testability.

```go
type SessionActivityReporter interface {
    ReportSessionStarted(ctx context.Context, sessionID, targetHost string, targetPort int)
    ReportSessionEnded(ctx context.Context, sessionID, targetHost string, targetPort int, bytesIn, bytesOut int64, terminatedBy string)
}
```

A production implementation posts an `api.SessionActivityRequest` carrying a `tcp` `api.TCPActivity` to `api.ControlPlane.ReportSessionActivity` (`POST /v1/nodes/{node_id}/sessions/{session_id}`). `ReportSessionStarted` emits a `session_started` row; `ReportSessionEnded` emits a `session_ended` row with the byte counters and a `terminated_by` reason.

## API Types

Types defined in `internal/api` for tunnel communication with the control plane.

### SSHSessionSetup

Payload of the `ssh_session_setup` SSE event.

```go
type SSHSessionSetup struct {
    SessionID     string    `json:"session_id"`
    TargetHost    string    `json:"target_host"`
    TargetPort    int       `json:"target_port"`
    AuthorizedKey string    `json:"authorized_key"`
    ExpiresAt     time.Time `json:"expires_at"`
}
```

### SessionActivityRequest

Posted by the node agent per session event. Exactly one of `SSH`, `K8s`, or `TCP`
is set, selecting the session kind. The tunnel subsystem is an opaque TCP
forwarder, so it always sets `TCP`; the `SSH` and `K8s` variants are carried by
the type and accepted by the control plane but not emitted by any current session
type.

```go
type SessionActivityRequest struct {
    SSH *SSHActivity `json:"ssh,omitempty"`
    K8s *K8sActivity `json:"k8s,omitempty"`
    TCP *TCPActivity `json:"tcp,omitempty"`
}
```

**Endpoint**: `POST /v1/nodes/{node_id}/sessions/{session_id}` (success: `204 No Content`)

### TCPActivity

The `tcp` member: a session lifecycle row. `Phase` is `session_started` or
`session_ended`. `BytesIn` (operator→target) and `BytesOut` (target→operator) are
pointers so a `session_ended` row carries explicit zeros while a `session_started`
row omits the byte counters. `TerminatedBy`, when set, is one of the
`TerminatedBy*` values.

```go
type TCPActivity struct {
    Phase        string `json:"phase"`
    TargetHost   string `json:"target_host,omitempty"`
    TargetPort   int    `json:"target_port,omitempty"`
    BytesIn      *int64 `json:"bytes_in,omitempty"`
    BytesOut     *int64 `json:"bytes_out,omitempty"`
    TerminatedBy string `json:"terminated_by,omitempty"`
}
```

#### terminated_by mapping

`TerminatedByFromReason` maps the internal session close reason to the wire
`terminated_by` value reported on a `session_ended` row:

| Close reason   | Wire value (`terminated_by`) |
|----------------|------------------------------|
| `expired`      | `ttl_expired`                |
| `revoked`      | `operator_revoke`            |
| any other      | `plexd_close`                |
| _(reserved)_   | `idle_timeout`               |

`idle_timeout` is reserved and never produced — the tunnel subsystem has no idle
timer. The `session_ended` row is emitted by the `SessionManager`'s on-closed
callback for **every** close reason: TTL expiry, operator revocation, and node
shutdown alike. The row is the only carrier of a session's byte counters and
`terminated_by`, so skipping it on shutdown would leave the control plane's
audit record for every live session truncated — the node going offline says the
session ended, but not how much traffic it carried.

## Integration Points

### SSE Event Stream (`internal/api`)

The tunnel package consumes two SSE event types via `api.EventDispatcher`:

| Event Type           | Handler                  | Trigger                               |
|----------------------|--------------------------|---------------------------------------|
| `ssh_session_setup`  | `HandleSSHSessionSetup`  | Control plane initiates SSH access    |
| `session_revoked`    | `HandleSessionRevoked`   | Control plane revokes SSH session     |

### Control Plane API (`internal/api`)

The node agent reports session activity via a single endpoint on `api.ControlPlane`:

| Method                  | Endpoint                             | When Called                                                            |
|-------------------------|--------------------------------------|------------------------------------------------------------------------|
| `ReportSessionActivity` | `POST /v1/nodes/{id}/sessions/{sid}` | Listener ready (`session_started`) and session close (`session_ended`) |

### WireGuard Mesh (`internal/wireguard`)

Tunnel listeners bind to the mesh IP assigned by the WireGuard interface. Connections arrive through the encrypted mesh — no ports are exposed on the public network. The `meshIP` parameter in `NewSessionManager` comes from `registration.NodeIdentity.MeshIP`.

### Graceful Shutdown

Call `SessionManager.Shutdown()` on context cancellation to close all active sessions:

```go
<-ctx.Done()
mgr.Shutdown()
```

## Access Flows

### SSH Access Flow

1. User requests SSH access through the platform UI/CLI.
2. Control plane verifies RBAC permissions and issues a session JWT scoped to the target node and allowed actions.
3. Control plane sends an `ssh_session_setup` event via SSE to the target node, including the session token.
4. plexd opens a TCP listener on the mesh interface and tunnels the SSH connection through the encrypted mesh.
5. The SSH session uses the node's managed host key (stored in `host_key_dir`). If the key file does not exist, plexd generates an Ed25519 host key on first use and reports its fingerprint to the control plane.
6. Session environment is injected with `PLEXD_SESSION_TOKEN` for local action authorization.
7. On disconnect or `default_timeout`, plexd tears down the session and notifies the control plane.

### Kubernetes API Proxy Flow

1. User requests kubectl access through the platform.
2. Control plane issues a scoped kubeconfig with a short-lived token.
3. plexd proxies the Kubernetes API request through the mesh to the target cluster's API server (auto-discovered via kubelet config or configured explicitly).
4. The proxy terminates on `default_timeout` if no requests are received.

## Logging

All log entries use `component=tunnel`. Session-scoped entries add `session_id`.

| Level   | Event                          | Keys                                        |
|---------|--------------------------------|---------------------------------------------|
| `Info`  | Session started                | `listen_addr`, `target`                     |
| `Info`  | Session created                | `session_id`, `listen_addr`, `expires_at`   |
| `Info`  | Session closed                 | `session_id`, `reason`, `duration`          |
| `Info`  | All tunnel sessions closed     | —                                           |
| `Debug` | Connection rejected (duplicate)| —                                           |
| `Debug` | Session not found for close    | `session_id`                                |
| `Debug` | Revoked session not found      | `session_id`                                |
| `Error` | Payload parse failed           | `event_id`, `error`                         |
| `Error` | Failed to dial target          | `target`, `error`                           |
