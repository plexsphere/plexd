---
title: Bridge Mode
quadrant: backend
package: internal/bridge
feature: PXD-0011
---

# Bridge Mode

The `internal/bridge` package manages bridge mode routing between a WireGuard mesh interface and an access-side network interface. A bridge node acts as a gateway, forwarding traffic from the mesh to external subnets reachable via the access interface.

All OS-level routing and forwarding operations go through a `RouteController` interface, enabling full unit testing without root privileges or kernel configuration.

## Data Flow

```
Mesh Peers
    │
    ▼
┌──────────────┐     ┌───────────┐     ┌──────────────────┐
│  WireGuard   │────▶│  Bridge   │────▶│  Access-Side     │
│  Interface   │     │  Manager  │     │  Interface       │
│  (plexd0)    │     └─────┬─────┘     │  (eth1)          │
└──────────────┘           │           └────────┬─────────┘
                           │                    │
                    ┌──────┴───────┐             ▼
                    │              │      ┌──────────────┐
                    ▼              ▼      │  External    │
              ┌──────────┐  ┌─────────┐  │  Network     │
              │ IP Fwd   │  │  NAT    │  │  Subnets     │
              │ (sysctl) │  │ (ipt)   │  └──────────────┘
              └──────────┘  └─────────┘
```

The control plane pushes `BridgeConfig` via `api.StateResponse`. The `ReconcileHandler` feeds desired subnets to the `Manager`, which diffs against currently active routes and calls `RouteController` to add/remove routes. `HandleBridgeConfigUpdated` triggers immediate reconciliation on SSE events.

## Config

`Config` holds bridge mode parameters passed to the `Manager` constructor.

| Field             | Type       | Default | Description                                         |
|-------------------|------------|---------|-----------------------------------------------------|
| `Enabled`         | `bool`     | `false` | Whether bridge mode is active                       |
| `AccessInterface` | `string`   | —       | Access-side network interface name                  |
| `AccessSubnets`   | `[]string` | —       | CIDR subnets reachable via the access interface     |
| `EnableNAT`       | `*bool`    | `true`  | Whether NAT masquerading is applied on the access interface (nil = true) |

```go
cfg := bridge.Config{
    Enabled:         true,
    AccessInterface: "eth1",
    AccessSubnets:   []string{"10.0.0.0/24", "192.168.1.0/24"},
}
cfg.ApplyDefaults() // EnableNAT nil defaults to true via natEnabled()
if err := cfg.Validate(); err != nil {
    log.Fatal(err) // rejects empty interface, empty subnets, invalid CIDR
}
```

### Validation Rules

Validation is skipped entirely when `Enabled` is `false`.

| Field             | Rule                             | Error Message                                                    |
|-------------------|----------------------------------|------------------------------------------------------------------|
| `AccessInterface` | Must not be empty when enabled   | `bridge: config: AccessInterface is required when enabled`       |
| `AccessSubnets`   | At least one required when enabled | `bridge: config: at least one AccessSubnet is required when enabled` |
| `AccessSubnets`   | Each must be valid CIDR          | `bridge: config: invalid CIDR "...": ...`                        |

## RouteController

Interface abstracting OS-level routing and forwarding operations. The production implementation (netlink/sysctl/iptables) is provided externally; this package defines and consumes the interface.

```go
type RouteController interface {
    EnableForwarding(meshIface, accessIface string) error
    DisableForwarding(meshIface, accessIface string) error
    AddRoute(subnet, iface string) error
    RemoveRoute(subnet, iface string) error
    AddNATMasquerade(iface string) error
    RemoveNATMasquerade(iface string) error
}
```

| Method               | Description                                                |
|----------------------|------------------------------------------------------------|
| `EnableForwarding`   | Enables IP forwarding between mesh and access interfaces   |
| `DisableForwarding`  | Reverses the forwarding setup                              |
| `AddRoute`           | Adds a route for a CIDR subnet via the given interface     |
| `RemoveRoute`        | Removes the route for a CIDR subnet                        |
| `AddNATMasquerade`   | Configures NAT masquerading on the given interface         |
| `RemoveNATMasquerade`| Removes NAT masquerading from the given interface          |

All methods must be idempotent: repeating an already-applied operation returns `nil`.

## Manager

Central coordinator for bridge mode routing lifecycle.

### Constructor

```go
func NewManager(ctrl RouteController, cfg Config, logger *slog.Logger) *Manager
```

- Applies config defaults via `cfg.ApplyDefaults()`
- Initializes an empty `activeRoutes` map

### Methods

| Method              | Signature                             | Description                                                    |
|---------------------|---------------------------------------|----------------------------------------------------------------|
| `Setup`             | `(meshIface string) error`            | Enables forwarding, adds routes, configures NAT               |
| `Teardown`          | `() error`                            | Removes all routes, NAT, and forwarding; aggregates errors    |
| `UpdateRoutes`      | `(subnets []string) error`            | Diffs desired vs active routes; adds/removes incrementally    |
| `BridgeStatus`      | `() *api.BridgeInfo`                  | Returns status for heartbeat; nil when inactive               |
| `BridgeCapabilities`| `() map[string]string`                | Returns capability metadata for registration; nil when disabled |

### Lifecycle

```go
logger := slog.Default()

// Create manager with a RouteController implementation
mgr := bridge.NewManager(ctrl, bridge.Config{
    Enabled:         true,
    AccessInterface: "eth1",
    AccessSubnets:   []string{"10.0.0.0/24"},
    EnableNAT:       bridge.BoolPtr(true), // nil defaults to true
}, logger)

// Setup bridge routing
if err := mgr.Setup("plexd0"); err != nil {
    log.Fatal(err)
}

// Report bridge status in heartbeats
status := mgr.BridgeStatus() // &api.BridgeInfo{Enabled: true, ...}

// Route updates driven by reconciliation
mgr.UpdateRoutes([]string{"10.0.0.0/24", "192.168.1.0/24"}) // adds new subnet
mgr.UpdateRoutes([]string{"192.168.1.0/24"})                 // removes old subnet

// Graceful shutdown
if err := mgr.Teardown(); err != nil {
    logger.Warn("bridge teardown failed", "error", err)
}
```

### Setup Sequence

1. `EnableForwarding(meshIface, accessIface)` — enable IP forwarding between interfaces
2. `AddRoute(subnet, accessIface)` — for each configured subnet
3. `AddNATMasquerade(accessIface)` — only if `Config.EnableNAT` is not explicitly `false`

When `Config.Enabled` is `false`, `Setup` is a no-op.

### Setup Rollback

If a route addition or NAT configuration fails during `Setup`:

1. All previously added routes are removed
2. Forwarding is disabled
3. Active routes are cleared
4. The original error is returned, wrapped with `bridge: setup:` prefix

This ensures no partial configuration is left behind on failure.

### Teardown

Teardown removes all bridge state regardless of individual failures:

1. Remove all active routes
2. Remove NAT masquerade (if configured)
3. Disable forwarding

Errors are aggregated via `errors.Join` — cleanup continues even when individual operations fail. Calling `Teardown` when the bridge is inactive is a no-op.

### UpdateRoutes

Incrementally updates routes by diffing desired subnets against the active set:

1. **Remove stale routes** — subnets in `activeRoutes` but not in the desired set
2. **Add new routes** — subnets in the desired set but not in `activeRoutes`

Unchanged routes are not touched. Errors are aggregated via `errors.Join`. On failure, the route is left in its current state (stale route stays active, new route stays absent) and the error is returned.

### Error Prefixes

| Method        | Prefix                              |
|---------------|-------------------------------------|
| `Setup`       | `bridge: setup: `                   |
| `Teardown`    | (aggregated, no prefix)             |
| `UpdateRoutes`| (aggregated, no prefix)             |

### Logging

All log entries use `component=bridge`.

| Level   | Event                      | Keys                                                   |
|---------|----------------------------|--------------------------------------------------------|
| `Info`  | Bridge mode configured     | `mesh_iface`, `access_iface`, `subnets`, `nat`        |
| `Error` | Route add/remove failed    | `subnet`, `error`                                      |
| `Error` | NAT masquerade failed      | `error`                                                |
| `Error` | Forwarding operation failed| `error`                                                |

## ReconcileHandler

Factory function returning a `reconcile.ReconcileHandler` that updates bridge routes when the desired `BridgeConfig` changes.

```go
func ReconcileHandler(mgr *Manager) reconcile.ReconcileHandler
```

The returned handler:

1. Checks if `desired.BridgeConfig` is non-nil
2. If nil, returns `nil` (no-op)
3. If present, calls `mgr.UpdateRoutes(desired.BridgeConfig.AccessSubnets)`

The handler does **not** inspect `StateDiff` — it relies on being invoked whenever any drift is detected by the reconciler (peers, policies, metadata, etc.) and internally diffs the desired subnets against the Manager's tracked active routes.

### Registration

```go
mgr := bridge.NewManager(ctrl, bridge.Config{...}, logger)

r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.ReconcileHandler(mgr))
```

## HandleBridgeConfigUpdated

Factory function returning an `api.EventHandler` for real-time bridge configuration updates via SSE.

```go
func HandleBridgeConfigUpdated(trigger ReconcileTrigger) api.EventHandler
```

When a `bridge_config_updated` SSE event is received, the handler calls `trigger.TriggerReconcile()` to request an immediate reconciliation cycle. The event payload is not parsed — any bridge config update triggers a full reconcile.

### ReconcileTrigger

```go
type ReconcileTrigger interface {
    TriggerReconcile()
}
```

Satisfied by `*reconcile.Reconciler`. Extracted as an interface for testability.

### Registration

```go
dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventBridgeConfigUpdated, bridge.HandleBridgeConfigUpdated(reconciler))
```

## Integration Points

### Reconciliation Loop

The bridge reconcile handler plugs into `internal/reconcile` alongside the WireGuard and policy handlers:

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(wireguard.ReconcileHandler(wgMgr))
r.RegisterHandler(policy.ReconcileHandler(enforcer, wgMgr, nodeID, meshIP, "plexd0"))
r.RegisterHandler(bridge.ReconcileHandler(bridgeMgr))
```

### SSE Real-Time Updates

`HandleBridgeConfigUpdated` triggers reconciliation when the control plane pushes a `bridge_config_updated` event. The reconciliation cycle then fetches fresh state and re-evaluates the bridge configuration.

### Control Plane Types

| Type                           | Package        | Usage                                           |
|--------------------------------|----------------|-------------------------------------------------|
| `api.BridgeConfig`             | `internal/api` | Desired bridge config from control plane        |
| `api.BridgeInfo`               | `internal/api` | Bridge status reported in heartbeats            |
| `api.StateResponse`            | `internal/api` | Desired state (contains `BridgeConfig`)         |
| `api.HeartbeatRequest`         | `internal/api` | Heartbeat payload (contains `BridgeInfo`)       |
| `api.SignedEnvelope`           | `internal/api` | SSE event wrapper                               |
| `api.EventBridgeConfigUpdated` | `internal/api` | Event type constant `"bridge_config_updated"`   |

### Heartbeat Reporting

Use `BridgeStatus()` to include bridge state in heartbeats:

```go
heartbeat := api.HeartbeatRequest{
    Bridge: bridgeMgr.BridgeStatus(), // nil when inactive
}
```

### Registration Capabilities

Use `BridgeCapabilities()` to advertise bridge support during node registration:

```go
caps := bridgeMgr.BridgeCapabilities()
// Returns map: {"bridge": "true", "access_interface": "eth1", "access_subnet_0": "10.0.0.0/24"}
// Returns nil when bridge mode is disabled
```

### Graceful Shutdown

Call `Teardown()` on context cancellation to remove all bridge routing:

```go
<-ctx.Done()
if err := bridgeMgr.Teardown(); err != nil {
    logger.Warn("bridge teardown failed", "error", err)
}
```
