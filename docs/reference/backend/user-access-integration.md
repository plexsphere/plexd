---
title: User Access Integration
quadrant: backend
package: internal/bridge
feature: PXD-0013
---

# User Access Integration

The user access integration extends bridge mode (`internal/bridge`) to allow external VPN clients (Tailscale, Netbird, WireGuard) to connect to the mesh network via a dedicated WireGuard interface on the bridge node. The control plane manages peer assignments; the bridge node creates the interface, configures peers, and forwards traffic into the mesh.

## Data Flow

```
External VPN Clients
(Tailscale / Netbird / WireGuard)
        │
        │  WireGuard tunnel
        ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Bridge Node                              │
│                                                                 │
│  ┌───────────────────┐         ┌───────────────────┐           │
│  │  Access WireGuard │  IP fwd │  Mesh WireGuard   │           │
│  │  Interface        │────────▶│  Interface        │           │
│  │  (wg-access)      │         │  (wg0)            │           │
│  │  port 51822       │         │                   │           │
│  └───────────────────┘         └─────────┬─────────┘           │
│         ▲                                │                     │
│         │                                ▼                     │
│  ┌──────┴──────────┐            ┌──────────────────┐           │
│  │ AccessController│            │  Mesh Peers      │           │
│  │ (WG operations) │            │  10.42.0.0/16    │           │
│  └─────────────────┘            └──────────────────┘           │
│                                                                 │
│  Control Plane ──SSE──▶ HandleUserAccessPeerAssigned            │
│                ──SSE──▶ HandleUserAccessPeerRevoked              │
│                ──SSE──▶ HandleUserAccessConfigUpdated            │
│                ──Rec──▶ UserAccessReconcileHandler               │
└─────────────────────────────────────────────────────────────────┘
```

Traffic from external VPN clients arrives on the access WireGuard interface (`wg-access`), is forwarded via IP forwarding to the mesh WireGuard interface (`wg0`), and reaches mesh peers. The `RouteController` manages forwarding rules; the `AccessController` manages the WireGuard interface and peer configuration.

## Config

User access fields extend the existing bridge `Config` struct. User access requires bridge mode to be enabled (`Enabled=true`).

| Field                     | Type   | Default      | Description                                              |
|---------------------------|--------|--------------|----------------------------------------------------------|
| `UserAccessEnabled`       | `bool` | `false`      | Whether user access integration is active                |
| `UserAccessInterfaceName` | `string` | `"wg-access"` | WireGuard interface name for user access               |
| `UserAccessListenPort`    | `int`  | `51822`      | UDP port for the user access WireGuard interface         |
| `MaxAccessPeers`          | `int`  | `50`         | Maximum number of concurrent user access peers           |

```go
cfg := bridge.Config{
    Enabled:           true,
    AccessInterface:   "eth1",
    AccessSubnets:     []string{"10.0.0.0/24"},
    UserAccessEnabled: true,
}
cfg.ApplyDefaults() // sets UserAccessInterfaceName, UserAccessListenPort, MaxAccessPeers
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

### Defaults

`ApplyDefaults()` sets zero-valued user access fields:

| Field                     | Zero Value | Default Applied                              |
|---------------------------|------------|----------------------------------------------|
| `UserAccessInterfaceName` | `""`       | `DefaultUserAccessInterfaceName` (`"wg-access"`) |
| `UserAccessListenPort`    | `0`        | `DefaultUserAccessListenPort` (`51822`)      |
| `MaxAccessPeers`          | `0`        | `DefaultMaxAccessPeers` (`50`)               |

### Validation Rules

User access validation is skipped when `UserAccessEnabled` is `false`. When enabled:

| Field                     | Rule                        | Error Message                                                                  |
|---------------------------|-----------------------------|--------------------------------------------------------------------------------|
| `UserAccessEnabled`       | Requires `Enabled=true`     | `bridge: config: user access requires bridge mode to be enabled`               |
| `UserAccessListenPort`    | Must be 1-65535             | `bridge: config: UserAccessListenPort must be between 1 and 65535`             |
| `UserAccessInterfaceName` | Must not be empty           | `bridge: config: UserAccessInterfaceName is required when user access is enabled` |
| `MaxAccessPeers`          | Must be > 0                 | `bridge: config: MaxAccessPeers must be positive when user access is enabled`  |

## AccessController

Interface abstracting WireGuard interface operations for user access. The production implementation is provided externally; this package defines and consumes the interface.

```go
type AccessController interface {
    CreateInterface(name string, listenPort int) error
    RemoveInterface(name string) error
    ConfigurePeer(iface string, publicKey string, allowedIPs []string, psk string) error
    RemovePeer(iface string, publicKey string) error
}
```

| Method            | Description                                                    |
|-------------------|----------------------------------------------------------------|
| `CreateInterface` | Creates a WireGuard interface with the given name and port     |
| `RemoveInterface` | Removes the WireGuard interface by name                        |
| `ConfigurePeer`   | Adds or updates a peer on the WireGuard interface              |
| `RemovePeer`      | Removes a peer from the WireGuard interface by public key      |

All methods must be idempotent: repeating an already-applied operation returns `nil`.

## UserAccessManager

Central coordinator for user access lifecycle. Concurrent-safe via `sync.Mutex` — SSE event handlers and the reconcile loop may invoke methods concurrently.

### Constructor

```go
func NewUserAccessManager(ctrl AccessController, routes RouteController, cfg Config, logger *slog.Logger) *UserAccessManager
```

### Methods

| Method                  | Signature                                  | Description                                                      |
|-------------------------|--------------------------------------------|------------------------------------------------------------------|
| `Setup`                 | `() error`                                 | Creates WG interface, enables forwarding; no-op when disabled    |
| `Teardown`              | `() error`                                 | Removes peers, forwarding, interface; aggregates errors          |
| `AddPeer`               | `(peer api.UserAccessPeer) error`          | Adds a peer; rejects duplicates and max-peers overflow           |
| `RemovePeer`            | `(publicKey string)`                       | Removes a peer by public key; no-op if not found                 |
| `PeerPublicKeys`        | `() []string`                              | Returns public keys of all active peers                          |
| `UserAccessStatus`      | `() *api.UserAccessInfo`                   | Returns status for heartbeat; nil when inactive                  |
| `UserAccessCapabilities`| `() map[string]string`                     | Returns capability metadata for registration; nil when disabled  |

### Lifecycle

```go
mgr := bridge.NewUserAccessManager(accessCtrl, routeCtrl, cfg, logger)

// Setup — creates interface, enables forwarding
if err := mgr.Setup(); err != nil {
    log.Fatal(err)
}

// Add a peer (driven by SSE handler or reconciliation)
err := mgr.AddPeer(api.UserAccessPeer{
    PublicKey:  "pk-abc123",
    AllowedIPs: []string{"10.99.0.1/32"},
    PSK:       "optional-psk",
    Label:     "alice-laptop",
})

// Remove a peer
mgr.RemovePeer("pk-abc123")

// Report status in heartbeat
status := mgr.UserAccessStatus()

// Capabilities for registration
caps := mgr.UserAccessCapabilities()
// {"user_access": "true", "access_listen_port": "51822"}

// Graceful shutdown
if err := mgr.Teardown(); err != nil {
    logger.Warn("teardown failed", "error", err)
}
```

### Setup Sequence

1. `AccessController.CreateInterface(interfaceName, listenPort)` — create WireGuard interface
2. `RouteController.EnableForwarding(interfaceName, accessInterface)` — enable IP forwarding

When `UserAccessEnabled` is `false`, `Setup` is a no-op.

### Setup Rollback

If `EnableForwarding` fails after `CreateInterface` succeeds, the interface is rolled back via `RemoveInterface`.

### Teardown

Teardown removes all state regardless of individual failures:

1. Remove all tracked peers individually via `AccessController.RemovePeer`
2. Disable forwarding via `RouteController.DisableForwarding`
3. Remove interface via `AccessController.RemoveInterface`

Errors are aggregated via `errors.Join` — cleanup continues even when individual operations fail. Calling `Teardown` when the manager is inactive is a no-op.

### AddPeer

1. Rejects duplicate public keys (`peer already exists`)
2. Rejects if `MaxAccessPeers` limit is reached (`max peers reached`)
3. Calls `AccessController.ConfigurePeer` to apply the WireGuard peer
4. Tracks the public key in the internal `activePeers` set

### RemovePeer

1. If the public key is not tracked, returns immediately (no-op)
2. Calls `AccessController.RemovePeer` to remove the WireGuard peer
3. On success, removes the key from internal tracking

## SSE Event Handlers

### HandleUserAccessPeerAssigned

```go
func HandleUserAccessPeerAssigned(mgr *UserAccessManager, logger *slog.Logger) api.EventHandler
```

Handles `user_access_peer_assigned` events. Parses `api.UserAccessPeer` from the envelope payload and calls `mgr.AddPeer(peer)`.

- On parse error: logs and returns wrapped error
- On `AddPeer` error: returns wrapped error

### HandleUserAccessPeerRevoked

```go
func HandleUserAccessPeerRevoked(mgr *UserAccessManager, logger *slog.Logger) api.EventHandler
```

Handles `user_access_peer_revoked` events. Parses `public_key` from the envelope payload and calls `mgr.RemovePeer(publicKey)`.

- On parse error: logs and returns wrapped error
- `RemovePeer` is a no-op if the peer does not exist

### HandleUserAccessConfigUpdated

```go
func HandleUserAccessConfigUpdated(trigger ReconcileTrigger) api.EventHandler
```

Handles `user_access_config_updated` events. Calls `trigger.TriggerReconcile()` to request an immediate reconciliation cycle. The event payload is not parsed — any config update triggers a full reconcile.

### Registration

```go
dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventUserAccessPeerAssigned,
    bridge.HandleUserAccessPeerAssigned(accessMgr, logger))
dispatcher.Register(api.EventUserAccessPeerRevoked,
    bridge.HandleUserAccessPeerRevoked(accessMgr, logger))
dispatcher.Register(api.EventUserAccessConfigUpdated,
    bridge.HandleUserAccessConfigUpdated(reconciler))
```

## UserAccessReconcileHandler

```go
func UserAccessReconcileHandler(mgr *UserAccessManager, logger *slog.Logger) reconcile.ReconcileHandler
```

Returns a `reconcile.ReconcileHandler` that synchronizes user access peers to match the desired `UserAccessConfig`:

1. If `desired.UserAccessConfig` is nil, returns nil (no-op)
2. Builds a desired set from `desired.UserAccessConfig.Peers` keyed by `PublicKey`
3. Removes stale peers: current keys not in the desired set
4. Adds missing peers: desired peers not in the current set
5. Aggregates `AddPeer` errors via `errors.Join`

### Registration

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.ReconcileHandler(bridgeMgr))
r.RegisterHandler(bridge.UserAccessReconcileHandler(accessMgr, logger))
```

## API Types

### UserAccessConfig

Pushed from the control plane in `api.StateResponse.UserAccessConfig`.

```go
type UserAccessConfig struct {
    Enabled       bool             `json:"enabled"`
    InterfaceName string           `json:"interface_name"`
    ListenPort    int              `json:"listen_port"`
    Peers         []UserAccessPeer `json:"peers"`
}
```

### UserAccessPeer

Represents a single user access peer (external VPN client).

```go
type UserAccessPeer struct {
    PublicKey  string   `json:"public_key"`
    AllowedIPs []string `json:"allowed_ips"`
    PSK       string   `json:"psk,omitempty"`
    Label     string   `json:"label"`
}
```

| Field        | Description                                              |
|--------------|----------------------------------------------------------|
| `PublicKey`  | WireGuard public key of the external client              |
| `AllowedIPs` | CIDR subnets the peer is allowed to route               |
| `PSK`       | Optional pre-shared key for additional security          |
| `Label`     | Human-readable label for the peer                        |

### UserAccessInfo

Reported in heartbeats via `api.HeartbeatRequest.UserAccess`.

```go
type UserAccessInfo struct {
    Enabled       bool   `json:"enabled"`
    InterfaceName string `json:"interface_name"`
    PeerCount     int    `json:"peer_count"`
    ListenPort    int    `json:"listen_port"`
}
```

### SSE Event Constants

| Constant                             | Value                            |
|--------------------------------------|----------------------------------|
| `api.EventUserAccessConfigUpdated`   | `"user_access_config_updated"`   |
| `api.EventUserAccessPeerAssigned`    | `"user_access_peer_assigned"`    |
| `api.EventUserAccessPeerRevoked`     | `"user_access_peer_revoked"`     |

## Plan Deviations

The implementation deviates from the original plan in two areas:

1. **UserAccessInfo placement**: Plan task 1.1 specifies `BridgeInfo.UserAccess *UserAccessInfo`, but the implementation places it as `HeartbeatRequest.UserAccess *UserAccessInfo` instead. User access is a separate capability from bridge status, and placing it at the top level of `HeartbeatRequest` alongside `Bridge *BridgeInfo` keeps concerns cleanly separated.

2. **AccessSubnets reuse**: Plan task 1.2 mentions a `UserAccessSubnets []string` config field, but the implementation reuses the existing `AccessSubnets` field since user access shares the same bridge access interface and exposes the same mesh CIDRs to VPN clients. Adding a separate `UserAccessSubnets` field would duplicate configuration with no behavioral difference.

## Error Prefixes

| Source                              | Prefix                                             |
|-------------------------------------|-----------------------------------------------------|
| `UserAccessManager.Setup` (create)  | `bridge: user access: create interface: `           |
| `UserAccessManager.Setup` (fwd)     | `bridge: user access: enable forwarding: `          |
| `UserAccessManager.AddPeer` (dup)   | `bridge: user access: peer already exists: `        |
| `UserAccessManager.AddPeer` (max)   | `bridge: user access: max peers reached (`          |
| `UserAccessManager.AddPeer` (ctrl)  | `bridge: user access: configure peer: `             |
| `HandleUserAccessPeerAssigned`      | `bridge: user_access_peer_assigned: `               |
| `HandleUserAccessPeerRevoked`       | `bridge: user_access_peer_revoked: `                |

## Logging

All user access log entries use `component=bridge`.

| Level   | Event                            | Keys                                        |
|---------|----------------------------------|---------------------------------------------|
| `Info`  | User access interface created    | `interface`, `listen_port`                  |
| `Info`  | User access interface removed    | `interface`                                 |
| `Error` | Remove peer failed               | `public_key`, `error`                       |
| `Error` | Reconcile: add peer failed       | `public_key`, `error`                       |
| `Error` | SSE parse payload failed         | `event_id`, `error`                         |

## Integration Points

### Reconciliation Loop

The user access reconcile handler plugs into `internal/reconcile` alongside existing handlers:

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(wireguard.ReconcileHandler(wgMgr))
r.RegisterHandler(policy.ReconcileHandler(enforcer, wgMgr, nodeID, meshIP, "wg0"))
r.RegisterHandler(bridge.ReconcileHandler(bridgeMgr))
r.RegisterHandler(bridge.RelayReconcileHandler(bridgeMgr.Relay(), logger))
r.RegisterHandler(bridge.UserAccessReconcileHandler(accessMgr, logger))
```

### SSE Real-Time Updates

Peer-level events (`peer_assigned`/`peer_revoked`) enable immediate response to individual peer changes. The `config_updated` event triggers a full reconcile for bulk changes.

### Control Plane Types

| Type                                   | Package        | Usage                                           |
|----------------------------------------|----------------|-------------------------------------------------|
| `api.UserAccessConfig`                 | `internal/api` | Desired user access config from control plane   |
| `api.UserAccessPeer`                   | `internal/api` | Individual peer definition                      |
| `api.UserAccessInfo`                   | `internal/api` | User access status in heartbeats                |
| `api.StateResponse`                    | `internal/api` | Desired state (contains `UserAccessConfig`)     |
| `api.HeartbeatRequest`                 | `internal/api` | Heartbeat payload (contains `UserAccessInfo`)   |
| `api.SignedEnvelope`                   | `internal/api` | SSE event wrapper                               |
| `api.EventUserAccessConfigUpdated`     | `internal/api` | Event type `"user_access_config_updated"`       |
| `api.EventUserAccessPeerAssigned`      | `internal/api` | Event type `"user_access_peer_assigned"`        |
| `api.EventUserAccessPeerRevoked`       | `internal/api` | Event type `"user_access_peer_revoked"`         |

### Heartbeat Reporting

```go
heartbeat := api.HeartbeatRequest{
    UserAccess: accessMgr.UserAccessStatus(), // nil when inactive
}
```

### Registration Capabilities

```go
caps := accessMgr.UserAccessCapabilities()
// {"user_access": "true", "access_listen_port": "51822"}
// nil when user access is disabled
```

### Graceful Shutdown

```go
<-ctx.Done()
if err := accessMgr.Teardown(); err != nil {
    logger.Warn("user access teardown failed", "error", err)
}
```

## Full Lifecycle

```go
cfg := bridge.Config{
    Enabled:           true,
    AccessInterface:   "eth1",
    AccessSubnets:     []string{"10.0.0.0/24"},
    UserAccessEnabled: true,
}
cfg.ApplyDefaults()

accessMgr := bridge.NewUserAccessManager(accessCtrl, routeCtrl, cfg, logger)

// Setup user access interface and forwarding
accessMgr.Setup()

// Register SSE handlers
dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventUserAccessPeerAssigned,
    bridge.HandleUserAccessPeerAssigned(accessMgr, logger))
dispatcher.Register(api.EventUserAccessPeerRevoked,
    bridge.HandleUserAccessPeerRevoked(accessMgr, logger))
dispatcher.Register(api.EventUserAccessConfigUpdated,
    bridge.HandleUserAccessConfigUpdated(reconciler))

// Register reconcile handler
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.UserAccessReconcileHandler(accessMgr, logger))

// Run reconciler
go r.Run(ctx, nodeID)

// Graceful shutdown
<-ctx.Done()
accessMgr.Teardown()
```
