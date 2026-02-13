---
title: Site-to-Site VPN
quadrant: backend
package: internal/bridge
feature: PXD-0015
---

# Site-to-Site VPN

The site-to-site VPN feature extends bridge mode (`internal/bridge`) to establish WireGuard tunnels between a bridge node and external networks. Each tunnel creates a dedicated WireGuard interface, configures a remote peer, and installs OS-level routes for the remote subnets. The bridge node acts as a gateway between the mesh network and the external site.

## Data Flow

```
External Network
(remote site)
      |
      |  WireGuard tunnel (UDP)
      v
+---------------------------------------------------------------+
|                        Bridge Node                              |
|                                                                 |
|  +-------------------+         +-------------------+           |
|  |  S2S WireGuard    |  route  |  Mesh WireGuard   |           |
|  |  Interfaces       |-------->|  Interface        |           |
|  |  (wg-s2s-{id})    |         |  (plexd0)         |           |
|  |  :51823, ...      |         |                   |           |
|  +-------------------+         +---------+---------+           |
|         ^                                |                     |
|         |                                v                     |
|  +------+------------+            +------------------+           |
|  | VPNController     |            |  Mesh Peers      |           |
|  | (WireGuard ops)   |            |  10.42.0.0/16    |           |
|  +---------+---------+            +------------------+           |
|            |                                                     |
|  +------+-------------+                                          |
|  | RouteController    |                                          |
|  | (OS routing ops)   |                                          |
|  +--------------------+                                          |
|                                                                 |
|  Control Plane --SSE--> HandleSiteToSiteTunnelAssigned           |
|                --SSE--> HandleSiteToSiteTunnelRevoked             |
|                --SSE--> HandleSiteToSiteConfigUpdated             |
|                --Rec--> SiteToSiteReconcileHandler                |
+-----------------------------------------------------------------+
```

Traffic between the external site and mesh peers flows through per-tunnel WireGuard interfaces (`wg-s2s-{id}`). The `VPNController` manages WireGuard interface and peer operations. The `RouteController` manages OS-level routes for remote subnets. The control plane pushes tunnel definitions via `SiteToSiteConfig` in `api.StateResponse`.

## Config

Site-to-site fields extend the existing bridge `Config` struct. Site-to-site requires bridge mode to be enabled (`Enabled=true`).

| Field                        | Type     | Default      | Description                                               |
|------------------------------|----------|--------------|-----------------------------------------------------------|
| `SiteToSiteEnabled`         | `bool`   | `false`      | Whether site-to-site VPN connectivity is active           |
| `SiteToSiteInterfacePrefix` | `string` | `"wg-s2s-"`  | Prefix for WireGuard interfaces used by tunnels           |
| `SiteToSiteListenPort`      | `int`    | `51823`      | Base UDP port for site-to-site WireGuard interfaces       |
| `MaxSiteToSiteTunnels`      | `int`    | `10`         | Maximum number of concurrent site-to-site tunnels         |

```go
cfg := bridge.Config{
    Enabled:           true,
    AccessInterface:   "eth1",
    AccessSubnets:     []string{"10.0.0.0/24"},
    SiteToSiteEnabled: true,
}
cfg.ApplyDefaults() // sets SiteToSiteInterfacePrefix, SiteToSiteListenPort, MaxSiteToSiteTunnels
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

### Defaults

`ApplyDefaults()` sets zero-valued site-to-site fields:

| Field                        | Zero Value | Default Applied                                          |
|------------------------------|------------|----------------------------------------------------------|
| `SiteToSiteInterfacePrefix` | `""`       | `DefaultSiteToSiteInterfacePrefix` (`"wg-s2s-"`)        |
| `SiteToSiteListenPort`      | `0`        | `DefaultSiteToSiteListenPort` (`51823`)                  |
| `MaxSiteToSiteTunnels`      | `0`        | `DefaultMaxSiteToSiteTunnels` (`10`)                     |

### Validation Rules

Site-to-site validation is skipped when `SiteToSiteEnabled` is `false`. When enabled:

| Field                        | Rule                         | Error Message                                                                          |
|------------------------------|------------------------------|----------------------------------------------------------------------------------------|
| `SiteToSiteEnabled`         | Requires `Enabled=true`      | `bridge: config: site-to-site requires bridge mode to be enabled`                      |
| `SiteToSiteListenPort`      | Must be between 1 and 65535  | `bridge: config: SiteToSiteListenPort must be between 1 and 65535`                     |
| `SiteToSiteInterfacePrefix` | Must not be empty            | `bridge: config: SiteToSiteInterfacePrefix is required when site-to-site is enabled`   |
| `MaxSiteToSiteTunnels`      | Must be > 0                  | `bridge: config: MaxSiteToSiteTunnels must be positive when site-to-site is enabled`   |

## VPNController

Interface abstracting OS-level WireGuard tunnel operations for testability. The production implementation is provided externally; this package defines and consumes the interface. All methods must be idempotent.

```go
type VPNController interface {
    CreateTunnelInterface(name string, listenPort int) error
    RemoveTunnelInterface(name string) error
    ConfigureTunnelPeer(iface string, publicKey string, allowedIPs []string, endpoint string, psk string) error
    RemoveTunnelPeer(iface string, publicKey string) error
}
```

| Method                   | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| `CreateTunnelInterface`  | Creates a WireGuard interface with the given name and UDP listen port       |
| `RemoveTunnelInterface`  | Removes the WireGuard interface; idempotent for non-existent interfaces    |
| `ConfigureTunnelPeer`    | Configures the remote peer (public key, allowed IPs, endpoint, optional PSK) |
| `RemoveTunnelPeer`       | Removes the remote peer from the interface; idempotent                     |

## SiteToSiteManager

Central coordinator for site-to-site VPN lifecycle. Concurrent-safe via `sync.Mutex` — SSE event handlers and the reconcile loop may invoke methods concurrently.

### Constructor

```go
func NewSiteToSiteManager(ctrl VPNController, routes RouteController, cfg Config, logger *slog.Logger) *SiteToSiteManager
```

### Methods

| Method                       | Signature                                       | Description                                                     |
|------------------------------|--------------------------------------------------|-----------------------------------------------------------------|
| `Setup`                      | `() error`                                       | Marks manager active; no-op when disabled                       |
| `Teardown`                   | `() error`                                       | Removes all tunnels, routes, interfaces; aggregates errors      |
| `AddTunnel`                  | `(tunnel api.SiteToSiteTunnel) error`            | Creates interface, configures peer, adds routes; full rollback  |
| `RemoveTunnel`               | `(tunnelID string)`                              | Removes routes, peer, interface; no-op if not found             |
| `GetTunnel`                  | `(tunnelID string) (api.SiteToSiteTunnel, bool)` | Returns tunnel config and true if exists, zero value and false otherwise |
| `TunnelIDs`                  | `() []string`                                    | Returns IDs of all active tunnels                               |
| `SiteToSiteStatus`           | `() *api.SiteToSiteInfo`                         | Returns status for heartbeat; nil when inactive                 |
| `SiteToSiteCapabilities`     | `() map[string]string`                           | Returns capability metadata for registration; nil when disabled |

### Lifecycle

```go
mgr := bridge.NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, logger)

// Setup — marks manager active
if err := mgr.Setup(); err != nil {
    log.Fatal(err)
}

// Add a tunnel (driven by SSE handler or reconciliation)
err := mgr.AddTunnel(api.SiteToSiteTunnel{
    TunnelID:        "site-hq",
    RemoteEndpoint:  "203.0.113.1:51820",
    RemotePublicKey: "base64-encoded-key",
    LocalSubnets:    []string{"10.0.0.0/24"},
    RemoteSubnets:   []string{"192.168.1.0/24"},
    InterfaceName:   "wg-s2s-site-hq",
    ListenPort:      51823,
})

// Remove a tunnel
mgr.RemoveTunnel("site-hq")

// Report status in heartbeat
status := mgr.SiteToSiteStatus()

// Capabilities for registration
caps := mgr.SiteToSiteCapabilities()
// {"site_to_site": "true", "max_site_to_site_tunnels": "10"}

// Graceful shutdown
if err := mgr.Teardown(); err != nil {
    logger.Warn("teardown failed", "error", err)
}
```

### Setup

When `SiteToSiteEnabled` is `false`, `Setup` is a no-op. When enabled, it marks the manager as active and logs the configuration.

### Teardown

Teardown removes all active tunnels, their routes, and interfaces:

1. Remove routes for each tunnel's remote subnets via `RouteController.RemoveRoute`
2. Remove each tunnel's WireGuard interface via `VPNController.RemoveTunnelInterface`
3. Mark manager as inactive and clear the tunnel map

Errors are aggregated via `errors.Join` — cleanup continues even when individual operations fail. Calling `Teardown` when the manager is inactive is a no-op (idempotent).

### AddTunnel

1. Rejects if the manager is inactive (`manager is not active`)
2. Rejects duplicate tunnel IDs (`tunnel already exists`)
3. Rejects if `MaxSiteToSiteTunnels` limit is reached (`max tunnels reached`)
4. Creates WireGuard interface via `VPNController.CreateTunnelInterface`
5. Configures remote peer via `VPNController.ConfigureTunnelPeer`
6. Adds routes for each remote subnet via `RouteController.AddRoute`
7. Tracks the tunnel in the internal `activeTunnels` map

On failure at any step, AddTunnel performs full rollback of all completed operations (routes, peer, interface) before returning the error.

### RemoveTunnel

1. If the manager is inactive or the tunnel ID is not tracked, returns immediately (no-op)
2. Removes routes for each remote subnet via `RouteController.RemoveRoute`
3. Removes the remote peer via `VPNController.RemoveTunnelPeer`
4. Removes the WireGuard interface via `VPNController.RemoveTunnelInterface`
5. Deletes the tunnel from the internal map

Errors during removal are logged but do not prevent cleanup of remaining resources.

## SSE Event Handlers

### HandleSiteToSiteTunnelAssigned

```go
func HandleSiteToSiteTunnelAssigned(mgr *SiteToSiteManager, logger *slog.Logger) api.EventHandler
```

Handles `site_to_site_tunnel_assigned` events. Parses `api.SiteToSiteTunnel` from the envelope payload and calls `mgr.AddTunnel(tunnel)`.

- On parse error: logs and returns wrapped error
- On `AddTunnel` error: returns wrapped error

### HandleSiteToSiteTunnelRevoked

```go
func HandleSiteToSiteTunnelRevoked(mgr *SiteToSiteManager, logger *slog.Logger) api.EventHandler
```

Handles `site_to_site_tunnel_revoked` events. Parses `tunnel_id` from the envelope payload and calls `mgr.RemoveTunnel(tunnelID)`.

- On parse error: logs and returns wrapped error
- `RemoveTunnel` is a no-op if the tunnel does not exist

### HandleSiteToSiteConfigUpdated

```go
func HandleSiteToSiteConfigUpdated(trigger ReconcileTrigger) api.EventHandler
```

Handles `site_to_site_config_updated` events. Calls `trigger.TriggerReconcile()` to request an immediate reconciliation cycle. The event payload is not parsed — any config update triggers a full reconcile.

### Registration

```go
dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventSiteToSiteTunnelAssigned,
    bridge.HandleSiteToSiteTunnelAssigned(s2sMgr, logger))
dispatcher.Register(api.EventSiteToSiteTunnelRevoked,
    bridge.HandleSiteToSiteTunnelRevoked(s2sMgr, logger))
dispatcher.Register(api.EventSiteToSiteConfigUpdated,
    bridge.HandleSiteToSiteConfigUpdated(reconciler))
```

## SiteToSiteReconcileHandler

```go
func SiteToSiteReconcileHandler(mgr *SiteToSiteManager, logger *slog.Logger) reconcile.ReconcileHandler
```

Returns a `reconcile.ReconcileHandler` that synchronizes tunnels to match the desired `SiteToSiteConfig`:

1. If `desired.SiteToSiteConfig` is nil, returns nil (no-op)
2. Builds a desired set from `desired.SiteToSiteConfig.Tunnels` keyed by `TunnelID`
3. Removes stale tunnels: current tunnel IDs not in the desired set
4. Detects changed tunnels: same tunnel ID but different config (uses `reflect.DeepEqual`) — removes and re-adds
5. Adds missing tunnels: desired tunnels not in the current set
6. Aggregates `AddTunnel` errors via `errors.Join`

### Registration

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.ReconcileHandler(bridgeMgr))
r.RegisterHandler(bridge.RelayReconcileHandler(bridgeMgr.Relay(), logger))
r.RegisterHandler(bridge.UserAccessReconcileHandler(accessMgr, logger))
r.RegisterHandler(bridge.IngressReconcileHandler(ingressMgr, logger))
r.RegisterHandler(bridge.SiteToSiteReconcileHandler(s2sMgr, logger))
```

## API Types

### SiteToSiteConfig

Pushed from the control plane in `api.StateResponse.SiteToSiteConfig`.

```go
type SiteToSiteConfig struct {
    Enabled bool               `json:"enabled"`
    Tunnels []SiteToSiteTunnel `json:"tunnels"`
}
```

### SiteToSiteTunnel

Represents a single site-to-site VPN tunnel definition.

```go
type SiteToSiteTunnel struct {
    TunnelID        string   `json:"tunnel_id"`
    RemoteEndpoint  string   `json:"remote_endpoint"`
    RemotePublicKey string   `json:"remote_public_key"`
    LocalSubnets    []string `json:"local_subnets"`
    RemoteSubnets   []string `json:"remote_subnets"`
    PSK             string   `json:"psk,omitempty"`
    InterfaceName   string   `json:"interface_name"`
    ListenPort      int      `json:"listen_port"`
}
```

| Field              | Description                                                          |
|--------------------|----------------------------------------------------------------------|
| `TunnelID`         | Unique identifier for the tunnel                                    |
| `RemoteEndpoint`   | Remote WireGuard endpoint (host:port)                               |
| `RemotePublicKey`  | Base64-encoded public key of the remote peer                        |
| `LocalSubnets`     | CIDR subnets on the local side                                      |
| `RemoteSubnets`    | CIDR subnets on the remote side (used for routing and allowed IPs)  |
| `PSK`              | Optional pre-shared key for additional security                     |
| `InterfaceName`    | WireGuard interface name for this tunnel                            |
| `ListenPort`       | UDP listen port for this tunnel's WireGuard interface               |

### SiteToSiteInfo

Reported in heartbeats via `api.HeartbeatRequest.SiteToSite`.

```go
type SiteToSiteInfo struct {
    Enabled     bool `json:"enabled"`
    TunnelCount int  `json:"tunnel_count"`
}
```

### SSE Event Constants

| Constant                                | Value                              |
|-----------------------------------------|------------------------------------|
| `api.EventSiteToSiteConfigUpdated`      | `"site_to_site_config_updated"`    |
| `api.EventSiteToSiteTunnelAssigned`     | `"site_to_site_tunnel_assigned"`   |
| `api.EventSiteToSiteTunnelRevoked`      | `"site_to_site_tunnel_revoked"`    |

## Error Prefixes

| Source                                           | Prefix                                                           |
|--------------------------------------------------|------------------------------------------------------------------|
| `SiteToSiteManager.AddTunnel` (inactive)         | `bridge: site-to-site: manager is not active`                    |
| `SiteToSiteManager.AddTunnel` (duplicate)        | `bridge: site-to-site: tunnel already exists: `                  |
| `SiteToSiteManager.AddTunnel` (max)              | `bridge: site-to-site: max tunnels reached (`                    |
| `SiteToSiteManager.AddTunnel` (create iface)     | `bridge: site-to-site: create interface for tunnel <id>: `       |
| `SiteToSiteManager.AddTunnel` (configure peer)   | `bridge: site-to-site: configure peer for tunnel <id>: `         |
| `SiteToSiteManager.AddTunnel` (add route)        | `bridge: site-to-site: add route <subnet> for tunnel <id>: `    |
| `SiteToSiteManager.Teardown` (remove route)      | `bridge: site-to-site: remove route <subnet> for tunnel <id>: ` |
| `SiteToSiteManager.Teardown` (remove iface)      | `bridge: site-to-site: remove interface for tunnel <id>: `       |
| `HandleSiteToSiteTunnelAssigned`                  | `bridge: site_to_site_tunnel_assigned: `                         |
| `HandleSiteToSiteTunnelRevoked`                   | `bridge: site_to_site_tunnel_revoked: `                          |

## Logging

All site-to-site log entries use `component=bridge`.

| Level   | Event                           | Keys                                                 |
|---------|---------------------------------|------------------------------------------------------|
| `Info`  | Site-to-site manager started    | `max_tunnels`, `interface_prefix`                    |
| `Info`  | Site-to-site manager stopped    | (none)                                               |
| `Info`  | Site-to-site tunnel added       | `tunnel_id`, `interface`, `remote_endpoint`, `remote_subnets` |
| `Info`  | Site-to-site tunnel removed     | `tunnel_id`                                          |
| `Error` | Remove route failed             | `tunnel_id`, `subnet`, `error`                       |
| `Error` | Remove peer failed              | `tunnel_id`, `error`                                 |
| `Error` | Remove interface failed         | `tunnel_id`, `error`                                 |
| `Error` | SSE parse payload failed        | `event_id`, `error`                                  |
| `Error` | Reconcile: add tunnel failed    | `tunnel_id`, `error`                                 |

## Integration Points

### Reconciliation Loop

The site-to-site reconcile handler plugs into `internal/reconcile` alongside existing handlers:

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(wireguard.ReconcileHandler(wgMgr))
r.RegisterHandler(policy.ReconcileHandler(enforcer, wgMgr, nodeID, meshIP, "plexd0"))
r.RegisterHandler(bridge.ReconcileHandler(bridgeMgr))
r.RegisterHandler(bridge.RelayReconcileHandler(bridgeMgr.Relay(), logger))
r.RegisterHandler(bridge.UserAccessReconcileHandler(accessMgr, logger))
r.RegisterHandler(bridge.IngressReconcileHandler(ingressMgr, logger))
r.RegisterHandler(bridge.SiteToSiteReconcileHandler(s2sMgr, logger))
```

### SSE Real-Time Updates

Tunnel-level events (`tunnel_assigned`/`tunnel_revoked`) enable immediate response to individual tunnel changes. The `config_updated` event triggers a full reconcile for bulk changes.

### Control Plane Types

| Type                                      | Package        | Usage                                           |
|-------------------------------------------|----------------|-------------------------------------------------|
| `api.SiteToSiteConfig`                    | `internal/api` | Desired site-to-site config from control plane  |
| `api.SiteToSiteTunnel`                    | `internal/api` | Individual tunnel definition                    |
| `api.SiteToSiteInfo`                      | `internal/api` | Site-to-site status in heartbeats               |
| `api.StateResponse`                       | `internal/api` | Desired state (contains `SiteToSiteConfig`)     |
| `api.HeartbeatRequest`                    | `internal/api` | Heartbeat payload (contains `SiteToSiteInfo`)   |
| `api.SignedEnvelope`                      | `internal/api` | SSE event wrapper                               |
| `api.EventSiteToSiteConfigUpdated`        | `internal/api` | Event type `"site_to_site_config_updated"`      |
| `api.EventSiteToSiteTunnelAssigned`       | `internal/api` | Event type `"site_to_site_tunnel_assigned"`     |
| `api.EventSiteToSiteTunnelRevoked`        | `internal/api` | Event type `"site_to_site_tunnel_revoked"`      |

### Heartbeat Reporting

```go
heartbeat := api.HeartbeatRequest{
    SiteToSite: s2sMgr.SiteToSiteStatus(), // nil when inactive
}
```

### Registration Capabilities

```go
caps := s2sMgr.SiteToSiteCapabilities()
// {"site_to_site": "true", "max_site_to_site_tunnels": "10"}
// nil when site-to-site is disabled
```

### Graceful Shutdown

```go
<-ctx.Done()
if err := s2sMgr.Teardown(); err != nil {
    logger.Warn("site-to-site teardown failed", "error", err)
}
```

## Full Lifecycle

```go
cfg := bridge.Config{
    Enabled:           true,
    AccessInterface:   "eth1",
    AccessSubnets:     []string{"10.0.0.0/24"},
    SiteToSiteEnabled: true,
}
cfg.ApplyDefaults()

s2sMgr := bridge.NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, logger)

// Setup site-to-site manager
s2sMgr.Setup()

// Register SSE handlers
dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventSiteToSiteTunnelAssigned,
    bridge.HandleSiteToSiteTunnelAssigned(s2sMgr, logger))
dispatcher.Register(api.EventSiteToSiteTunnelRevoked,
    bridge.HandleSiteToSiteTunnelRevoked(s2sMgr, logger))
dispatcher.Register(api.EventSiteToSiteConfigUpdated,
    bridge.HandleSiteToSiteConfigUpdated(reconciler))

// Register reconcile handler
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.SiteToSiteReconcileHandler(s2sMgr, logger))

// Run reconciler
go r.Run(ctx, nodeID)

// Graceful shutdown
<-ctx.Done()
s2sMgr.Teardown()
```
