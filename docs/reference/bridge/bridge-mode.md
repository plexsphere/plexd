---
title: Bridge Mode
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

Access-subnet routes come from **local YAML config** (`Config.AccessSubnets`), programmed by the `Manager` at bridge setup via `RouteController`. The old `bridge_config` block (`access_subnets`/`enable_nat`/`enable_forwarding`) no longer rides the state snapshot, and the top-level bridge routes reconcile handler has been removed. The snapshot's `bridge` subtree carries only the four feature children (`relay`, `user_access`, `ingress`, `site_to_site`), each reconciled by its own handler. `HandleBridgeConfigUpdated` still triggers an immediate reconciliation on `bridge_config_updated` SSE events.

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

Interface abstracting OS-level routing and forwarding operations. The package has three production implementations: [`NetlinkRouteController`](./netlink-route-controller.md) on Linux (`route_linux.go`), and `DarwinRouteController` and `WindowsRouteController` on macOS and Windows (`route_darwin.go`, `route_windows.go`, described in [macOS & Windows Route Controllers](./route-controllers-macos-windows.md)).

```go
type RouteController interface {
    EnableForwarding(meshIface, accessIface string) error
    DisableForwarding(meshIface, accessIface string) error
    AddRoute(subnet, iface string) error
    RemoveRoute(subnet, iface string) error

    NATController
}

type NATController interface {
    AddNATMasquerade(iface string) error
    RemoveNATMasquerade(iface string) error
}
```

The NAT methods are a separate interface because the macOS and Windows controllers do not implement them: pf and the Windows Filtering Platform own those rules, so both delegate to a backend passed to their constructor.

| Method               | Description                                                |
|----------------------|------------------------------------------------------------|
| `EnableForwarding`   | Enables IP forwarding between mesh and access interfaces   |
| `DisableForwarding`  | Reverses the forwarding setup                              |
| `AddRoute`           | Adds a route for a CIDR subnet via the given interface     |
| `RemoveRoute`        | Removes the route for a CIDR subnet                        |
| `AddNATMasquerade`   | Configures NAT masquerading for bridge egress               |
| `RemoveNATMasquerade`| Removes NAT masquerading from the given interface          |

All methods must be idempotent: repeating an already-applied operation returns `nil`.

`AddNATMasquerade` returns an error wrapping `ErrNATUnavailable` on a controller built without a NAT backend. `cmd/plexd/cmd/up_darwin.go` and `up_windows.go` supply one — the pf and WFP firewall controllers — so NAT works on all three platforms; see [pf & WFP Firewall Controllers](../networking/pf-wfp-firewall.md#nat). Linux and macOS scope the translation to the given interface; Windows scopes it by the mesh source prefix and ignores the name.

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

## Access-Subnet Routes

Access-subnet routes are **not** reconciled from the control plane. The `Manager`
programs them once from local `Config.AccessSubnets` when `Setup(meshIface)` runs,
adding each subnet via `RouteController` (with rollback on partial failure) and
tracking them as active routes. The former top-level `bridge.ReconcileHandler`
that fed `desired.BridgeConfig.AccessSubnets` into `Manager.UpdateRoutes` has been
removed together with the `bridge_config` block. `Manager.UpdateRoutes` remains
available for programmatic route changes but is no longer wired into the
reconciliation loop.

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

The bridge feature sub-handlers plug into `internal/reconcile` alongside the WireGuard and policy handlers. There is no longer a top-level bridge handler:

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(wireguard.ReconcileHandler(wgMgr))
r.RegisterHandler(policy.ReconcileHandler(enforcer, "plexd0"))
r.RegisterHandler(bridge.RelayReconcileHandler(relay, logger))
r.RegisterHandler(bridge.UserAccessReconcileHandler(uaMgr, logger))
r.RegisterHandler(bridge.IngressReconcileHandler(ingressMgr, logger))
r.RegisterHandler(bridge.SiteToSiteReconcileHandler(s2sMgr, logger))
```

### SSE Real-Time Updates

`HandleBridgeConfigUpdated` triggers reconciliation when the control plane pushes a `bridge_config_updated` event. The reconciliation cycle then pulls fresh state and re-evaluates the four bridge subtrees.

### Control Plane Types

| Type                           | Package        | Usage                                                     |
|--------------------------------|----------------|-----------------------------------------------------------|
| `api.BridgeSnapshot`           | `internal/api` | The snapshot `bridge` subtree (`relay`, `user_access`, `ingress`, `site_to_site`) |
| `api.BridgeInfo`               | `internal/api` | Bridge status reported in heartbeats                      |
| `api.NodeStateSnapshot`        | `internal/api` | Desired-state envelope (contains `Bridge`)                |
| `api.HeartbeatRequest`         | `internal/api` | Heartbeat payload (contains `BridgeInfo`)                 |
| `api.Envelope`                 | `internal/api` | SSE event wrapper                                         |
| `api.EventBridgeConfigUpdated` | `internal/api` | Event type constant `"bridge_config_updated"`             |

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
