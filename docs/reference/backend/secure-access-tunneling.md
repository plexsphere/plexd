---
title: Secure Access Tunneling
quadrant: backend
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
4. `TunnelReporter.ReportReady` notifies the control plane with the listen address
5. Client connects through the mesh to the listener; `Session` forwards to the target
6. Session ends by expiry (`time.AfterFunc`), revocation (`session_revoked` SSE), or shutdown
7. `TunnelReporter.ReportClosed` notifies the control plane with reason and duration

## Config

`Config` holds secure access tunneling parameters passed to the `SessionManager` constructor.

| Field            | Type            | Default | Description                                    |
|------------------|-----------------|---------|------------------------------------------------|
| `Enabled`        | `bool`          | `true`  | Whether tunneling is active                    |
| `MaxSessions`    | `int`           | `10`    | Maximum concurrent tunnel sessions             |
| `DefaultTimeout` | `time.Duration` | `30m`   | Default/maximum session timeout                |

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
| `Close`      | `() error`                                 | Idempotent shutdown: cancels context, closes listener and connection |
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
| `CloseSession` | `(sessionID string, reason string)`                              | Closes and removes a session by ID                       |
| `Shutdown`     | `()`                                                             | Closes all active sessions                               |
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

Factory functions returning `api.EventHandler` for tunnel lifecycle events. Each parses the `SignedEnvelope.Payload` and calls the appropriate `SessionManager` method.

| Factory                  | Event Type           | Payload Type                        | Action                                     |
|--------------------------|----------------------|-------------------------------------|--------------------------------------------|
| `HandleSSHSessionSetup`  | `ssh_session_setup`  | `api.SSHSessionSetup`               | `CreateSession` + `ReportReady`            |
| `HandleSessionRevoked`   | `session_revoked`    | `{"session_id": "..."}`             | `CloseSession("revoked")` + `ReportClosed` |

- Malformed payloads are logged at error level and return an error
- `HandleSessionRevoked` is a no-op if the session ID is not found (logged at debug level)

### Registration

```go
mgr := tunnel.NewSessionManager(tunnel.Config{}, meshIP, logger)

dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register("ssh_session_setup", tunnel.HandleSSHSessionSetup(mgr, reporter))
dispatcher.Register("session_revoked", tunnel.HandleSessionRevoked(mgr, reporter))
```

## TunnelReporter

Interface for reporting tunnel session lifecycle events to the control plane. Abstracted for testability.

```go
type TunnelReporter interface {
    ReportReady(ctx context.Context, sessionID, listenAddr string)
    ReportClosed(ctx context.Context, sessionID, reason string, duration time.Duration)
}
```

A production implementation would use `api.ControlPlane.TunnelReady` and `api.ControlPlane.TunnelClosed`.

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

### TunnelReadyRequest

Sent by the node agent when a tunnel listener is ready.

```go
type TunnelReadyRequest struct {
    ListenAddr string    `json:"listen_addr"`
    Timestamp  time.Time `json:"timestamp"`
}
```

**Endpoint**: `POST /v1/nodes/{node_id}/tunnels/{session_id}/ready`

### TunnelClosedRequest

Sent by the node agent when a tunnel session closes.

```go
type TunnelClosedRequest struct {
    Reason    string    `json:"reason"`
    Duration  string    `json:"duration"`
    Timestamp time.Time `json:"timestamp"`
}
```

**Endpoint**: `POST /v1/nodes/{node_id}/tunnels/{session_id}/closed`

## Integration Points

### SSE Event Stream (`internal/api`)

The tunnel package consumes two SSE event types via `api.EventDispatcher`:

| Event Type           | Handler                  | Trigger                               |
|----------------------|--------------------------|---------------------------------------|
| `ssh_session_setup`  | `HandleSSHSessionSetup`  | Control plane initiates SSH access    |
| `session_revoked`    | `HandleSessionRevoked`   | Control plane revokes SSH session     |

### Control Plane API (`internal/api`)

The node agent reports tunnel status via two endpoints on `api.ControlPlane`:

| Method         | Endpoint                                          | When Called               |
|----------------|---------------------------------------------------|---------------------------|
| `TunnelReady`  | `POST /v1/nodes/{id}/tunnels/{sid}/ready`         | Listener is ready         |
| `TunnelClosed` | `POST /v1/nodes/{id}/tunnels/{sid}/closed`        | Session closed            |

### WireGuard Mesh (`internal/wireguard`)

Tunnel listeners bind to the mesh IP assigned by the WireGuard interface. Connections arrive through the encrypted mesh — no ports are exposed on the public network. The `meshIP` parameter in `NewSessionManager` comes from `registration.NodeIdentity.MeshIP`.

### Graceful Shutdown

Call `SessionManager.Shutdown()` on context cancellation to close all active sessions:

```go
<-ctx.Done()
mgr.Shutdown()
```

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
