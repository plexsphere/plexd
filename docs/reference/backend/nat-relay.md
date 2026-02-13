---
title: NAT Relay
quadrant: backend
package: internal/bridge
feature: PXD-0012
---

# NAT Relay

The NAT relay functionality extends bridge mode (`internal/bridge`) to forward UDP packets between peers that cannot establish direct peer-to-peer WireGuard tunnels. A bridge node configured as a relay opens a UDP listener and relays packets between assigned peer pairs based on session assignments from the control plane.

## Data Flow

```
Peer A                                                      Peer B
(behind NAT)                                                (behind NAT)
    │                                                           ▲
    │  UDP packet                                  UDP packet   │
    ▼                                                           │
┌──────────────────────────────────────────────────────────────────┐
│                     Bridge Node (Relay)                          │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────────┐      │
│  │  UDP Listener │───▶│  addrIndex   │───▶│ RelaySession  │      │
│  │  (port 51821) │    │  O(1) lookup │    │  Forward()    │      │
│  └──────────────┘    └──────────────┘    └───────────────┘      │
│         ▲                                        │               │
│         │              dispatchLoop              │               │
│         │         (pre-allocated 64KB buf)        ▼               │
│         └────────────────────────────────────────┘               │
│                                                                  │
│  Control Plane ──SSE──▶ HandleRelaySessionAssigned               │
│                ──SSE──▶ HandleRelaySessionRevoked                │
│                ──Rec──▶ RelayReconcileHandler                    │
└──────────────────────────────────────────────────────────────────┘
```

The relay uses a single shared UDP socket. Incoming packets are dispatched to sessions via an `addrIndex` map keyed by `net.UDPAddr.String()` for O(1) lookup. Each `RelaySession` knows both peer addresses and forwards packets to the opposite peer.

## Config

Relay fields extend the existing bridge `Config` struct. Relay requires bridge mode to be enabled (`Enabled=true`).

| Field              | Type            | Default       | Description                                          |
|--------------------|-----------------|---------------|------------------------------------------------------|
| `RelayEnabled`     | `bool`          | `false`       | Whether the bridge node serves as a relay            |
| `RelayListenPort`  | `int`           | `51821`       | UDP port for relay traffic                           |
| `MaxRelaySessions` | `int`           | `100`         | Maximum concurrent relay sessions                    |
| `SessionTTL`       | `time.Duration` | `5m`          | Time-to-live for relay sessions                      |

```go
cfg := bridge.Config{
    Enabled:         true,
    AccessInterface: "eth1",
    AccessSubnets:   []string{"10.0.0.0/24"},
    RelayEnabled:    true,
    RelayListenPort: 51821,
}
cfg.ApplyDefaults() // sets MaxRelaySessions=100, SessionTTL=5m if zero
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

### Defaults

`ApplyDefaults()` sets zero-valued relay fields:

| Field              | Zero Value | Default Applied       |
|--------------------|------------|-----------------------|
| `RelayListenPort`  | `0`        | `DefaultRelayListenPort` (51821)  |
| `MaxRelaySessions` | `0`        | `DefaultMaxRelaySessions` (100)   |
| `SessionTTL`       | `0`        | `DefaultSessionTTL` (5 minutes)   |

### Validation Rules

Relay validation is skipped when `RelayEnabled` is `false`. When enabled:

| Field              | Rule                                 | Error Message                                                        |
|--------------------|--------------------------------------|----------------------------------------------------------------------|
| `RelayEnabled`     | Requires `Enabled=true`              | `bridge: config: relay requires bridge mode to be enabled`           |
| `RelayListenPort`  | Must be 1-65535                      | `bridge: config: RelayListenPort must be between 1 and 65535`        |
| `MaxRelaySessions` | Must be > 0                          | `bridge: config: MaxRelaySessions must be positive when relay is enabled` |
| `SessionTTL`       | Must be >= 30s                       | `bridge: config: SessionTTL must be at least 30s`                    |

## Relay

`Relay` manages a UDP listener and relay sessions. Created by `NewRelay` and integrated into the `Manager`.

### Constructor

```go
func NewRelay(listenPort, maxSessions int, sessionTTL time.Duration, logger *slog.Logger) *Relay
```

### Methods

| Method         | Signature                                          | Description                                               |
|----------------|----------------------------------------------------|-----------------------------------------------------------|
| `Start`        | `(ctx context.Context) error`                      | Opens UDP socket, starts dispatch loop goroutine          |
| `Stop`         | `() error`                                         | Closes all sessions and UDP listener; idempotent          |
| `AddSession`   | `(assignment api.RelaySessionAssignment) error`    | Creates and registers a new relay session                 |
| `RemoveSession`| `(sessionID string)`                               | Closes and removes a session by ID; no-op if not found    |
| `ActiveCount`  | `() int`                                           | Returns the number of active relay sessions               |
| `SessionIDs`   | `() []string`                                      | Returns the IDs of all active sessions                    |
| `ListenAddr`   | `() net.Addr`                                      | Returns the local address of the UDP listener; nil if not started |

### Lifecycle

```go
relay := bridge.NewRelay(51821, 100, 5*time.Minute, logger)

// Start listening
if err := relay.Start(ctx); err != nil {
    log.Fatal(err)
}

// Add a session (typically driven by SSE handler or reconciliation)
err := relay.AddSession(api.RelaySessionAssignment{
    SessionID:     "sess-1",
    PeerAEndpoint: "203.0.113.1:51820",
    PeerBEndpoint: "198.51.100.1:51820",
    ExpiresAt:     time.Now().Add(5 * time.Minute),
})

// Remove a session
relay.RemoveSession("sess-1")

// Graceful shutdown
relay.Stop()
```

### AddSession

1. Resolves `PeerAEndpoint` and `PeerBEndpoint` via `net.ResolveUDPAddr`
2. Rejects duplicate session IDs and sessions beyond `maxSessions`
3. Creates a `RelaySession` with the shared UDP connection
4. Registers both peer addresses in `addrIndex` for O(1) dispatch
5. Starts a TTL timer — uses `min(sessionTTL, time.Until(ExpiresAt))`

### Dispatch Loop

The `dispatchLoop` goroutine reads from the shared UDP socket using a pre-allocated 65535-byte buffer (no per-packet allocation):

1. Read packet from UDP socket
2. Copy data to a new slice (buffer reuse)
3. Look up session by source address in `addrIndex` (O(1) via `RLock`)
4. If found, call `session.Forward(srcAddr, data)`
5. If not found, log at debug level and continue

Context cancellation closes the UDP connection, causing `ReadFromUDP` to return an error and the loop to exit.

### Concurrency

- `Relay.mu` (`sync.RWMutex`) protects `sessions`, `addrIndex`, `timers`, `conn`, `active`
- `RelaySession.mu` (`sync.Mutex`) protects the `closed` flag
- `dispatchLoop` receives the `conn` as a parameter to avoid racing with `Stop()` which sets `r.conn = nil`
- TTL timer callbacks call `RemoveSession` which acquires the write lock

## RelaySession

Represents a single relay session forwarding UDP packets between two peers.

```go
type RelaySession struct {
    SessionID string
    PeerAAddr *net.UDPAddr
    PeerBAddr *net.UDPAddr
}
```

### Forward

`Forward(srcAddr *net.UDPAddr, data []byte)` determines the destination by matching the source address:

| Source matches | Destination |
|----------------|-------------|
| `PeerAAddr`    | `PeerBAddr` |
| `PeerBAddr`    | `PeerAAddr` |
| Neither        | Dropped (logged at debug) |

### Close

`Close()` is idempotent — calling it multiple times returns `nil`.

## SSE Event Handlers

### HandleRelaySessionAssigned

```go
func HandleRelaySessionAssigned(relay *Relay, logger *slog.Logger) api.EventHandler
```

Handles `relay_session_assigned` events. Parses `api.RelaySessionAssignment` from the envelope payload and calls `relay.AddSession(assignment)`.

- On parse error: logs and returns wrapped error
- On `AddSession` error: returns wrapped error

### HandleRelaySessionRevoked

```go
func HandleRelaySessionRevoked(relay *Relay, logger *slog.Logger) api.EventHandler
```

Handles `relay_session_revoked` events. Parses `session_id` from the envelope payload and calls `relay.RemoveSession(sessionID)`.

- On parse error: logs and returns wrapped error
- `RemoveSession` is a no-op if the session does not exist

### Registration

```go
dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventRelaySessionAssigned,
    bridge.HandleRelaySessionAssigned(mgr.Relay(), logger))
dispatcher.Register(api.EventRelaySessionRevoked,
    bridge.HandleRelaySessionRevoked(mgr.Relay(), logger))
```

## RelayReconcileHandler

```go
func RelayReconcileHandler(relay *Relay, logger *slog.Logger) reconcile.ReconcileHandler
```

Returns a `reconcile.ReconcileHandler` that synchronizes relay sessions to match the desired `RelayConfig`:

1. If `desired.RelayConfig` is nil, returns nil (no-op)
2. Builds a desired set from `desired.RelayConfig.Sessions` keyed by `SessionID`
3. Removes stale sessions: current IDs not in the desired set
4. Adds missing sessions: desired sessions not in the current set
5. Aggregates `AddSession` errors via `errors.Join`

### Registration

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.ReconcileHandler(bridgeMgr))
r.RegisterHandler(bridge.RelayReconcileHandler(bridgeMgr.Relay(), logger))
```

## Manager Integration

The `Manager` creates and manages the `Relay` when `Config.RelayEnabled` is `true`.

### Manager Relay Methods

| Method         | Signature                              | Description                                         |
|----------------|----------------------------------------|-----------------------------------------------------|
| `Relay`        | `() *Relay`                            | Returns the relay instance; nil if not configured   |
| `StartRelay`   | `(ctx context.Context) error`          | Starts the relay UDP listener; no-op if nil         |
| `StopRelay`    | `() error`                             | Stops the relay; no-op if nil                       |

`Teardown()` automatically calls `relay.Stop()` as part of bridge teardown. Errors are aggregated with other teardown errors.

### BridgeStatus with Relay

When relay is configured, `BridgeStatus()` includes relay fields:

```go
info := mgr.BridgeStatus()
// info.RelayEnabled = true
// info.ActiveRelaySessions = relay.ActiveCount()
```

### BridgeCapabilities with Relay

When relay is enabled, `BridgeCapabilities()` includes:

```go
caps := mgr.BridgeCapabilities()
// caps["relay"] = "true"
// caps["relay_listen_port"] = "51821"
```

### Full Lifecycle

```go
mgr := bridge.NewManager(ctrl, bridge.Config{
    Enabled:         true,
    AccessInterface: "eth1",
    AccessSubnets:   []string{"10.0.0.0/24"},
    RelayEnabled:    true,
}, logger)

// Setup bridge routing
mgr.Setup("plexd0")

// Start relay UDP listener
mgr.StartRelay(ctx)

// Register handlers
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.ReconcileHandler(mgr))
r.RegisterHandler(bridge.RelayReconcileHandler(mgr.Relay(), logger))

dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventRelaySessionAssigned,
    bridge.HandleRelaySessionAssigned(mgr.Relay(), logger))
dispatcher.Register(api.EventRelaySessionRevoked,
    bridge.HandleRelaySessionRevoked(mgr.Relay(), logger))
dispatcher.Register(api.EventBridgeConfigUpdated,
    bridge.HandleBridgeConfigUpdated(r))

// Run reconciler
go r.Run(ctx, nodeID)

// Graceful shutdown
<-ctx.Done()
mgr.Teardown() // stops relay, removes routes, disables forwarding
```

## API Types

### RelayConfig

Pushed from the control plane in `api.StateResponse.RelayConfig`.

```go
type RelayConfig struct {
    Sessions []RelaySessionAssignment `json:"sessions"`
}
```

### RelaySessionAssignment

Represents a single relay session assignment.

```go
type RelaySessionAssignment struct {
    SessionID     string    `json:"session_id"`
    PeerAID       string    `json:"peer_a_id"`
    PeerAEndpoint string    `json:"peer_a_endpoint"`
    PeerBID       string    `json:"peer_b_id"`
    PeerBEndpoint string    `json:"peer_b_endpoint"`
    ExpiresAt     time.Time `json:"expires_at"`
}
```

| Field           | Description                                      |
|-----------------|--------------------------------------------------|
| `SessionID`     | Unique identifier for the relay session          |
| `PeerAID`       | Node ID of peer A                                |
| `PeerAEndpoint` | UDP endpoint of peer A (`host:port`)             |
| `PeerBID`       | Node ID of peer B                                |
| `PeerBEndpoint` | UDP endpoint of peer B (`host:port`)             |
| `ExpiresAt`     | Absolute expiry time for the session             |

### BridgeInfo Relay Fields

Reported in heartbeats via `api.BridgeInfo`:

| Field                 | Type   | Description                              |
|-----------------------|--------|------------------------------------------|
| `RelayEnabled`        | `bool` | Whether relay is active on this node     |
| `ActiveRelaySessions` | `int`  | Number of currently active relay sessions|

### SSE Event Constants

| Constant                       | Value                       |
|--------------------------------|-----------------------------|
| `api.EventRelaySessionAssigned`| `"relay_session_assigned"`  |
| `api.EventRelaySessionRevoked` | `"relay_session_revoked"`   |

## Error Prefixes

| Source                       | Prefix                                      |
|------------------------------|---------------------------------------------|
| `Relay.Start`                | `bridge: relay: listen on :<port>: `        |
| `Relay.AddSession` (resolve) | `bridge: relay: resolve peer A/B endpoint`  |
| `Relay.AddSession` (dup)     | `bridge: relay: duplicate session ID: `     |
| `Relay.AddSession` (max)     | `bridge: relay: max sessions reached`       |
| `HandleRelaySessionAssigned` | `bridge: relay_session_assigned: `          |
| `HandleRelaySessionRevoked`  | `bridge: relay_session_revoked: `           |

## Logging

All relay log entries use `component=bridge`.

| Level   | Event                          | Keys                                           |
|---------|--------------------------------|------------------------------------------------|
| `Info`  | Relay started                  | `listen_port`                                  |
| `Info`  | Relay stopped                  | —                                              |
| `Info`  | Relay session added            | `session_id`, `peer_a`, `peer_b`, `ttl`        |
| `Info`  | Relay session closed           | `session_id`                                   |
| `Debug` | Packet from unregistered addr  | `source`                                       |
| `Debug` | Dropping packet (unknown src)  | `session_id`, `source`                         |
| `Error` | Forward failed                 | `session_id`, `dst`, `error`                   |
| `Error` | Relay reconcile: add failed    | `session_id`, `error`                          |
| `Error` | SSE parse payload failed       | `event_id`, `error`                            |
