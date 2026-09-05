---
title: Site-to-Site VPN
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
|  Control Plane --SSE--> bridge_config_updated --> reconcile      |
|                --Rec--> SiteToSiteReconcileHandler                |
+-----------------------------------------------------------------+
```

Traffic between the external site and mesh peers flows through per-tunnel WireGuard interfaces (`wg-s2s-{id}`). The `VPNController` manages WireGuard interface and peer operations. The `RouteController` manages OS-level routes for remote subnets. The control plane pushes tunnel definitions via the snapshot `bridge.site_to_site` subtree (`api.BridgeSnapshot.SiteToSite`).

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

Interface abstracting OS-level WireGuard tunnel operations for testability. Two implementations exist. `NetlinkVPNController` (`vpn_controller_linux.go`) drives the Linux kernel through netlink and `wgctrl`. `WGVPNController` (`vpn_controller_wg.go`) covers macOS and Windows by wrapping the platform `WGController`: `DarwinController` on a utun device, `WindowsController` on a Wintun adapter, both running on the [userspace backend](../networking/wireguard.md#userspace-backend). Every method except `CreateTunnelInterface` must be idempotent; no implementation makes the create idempotent, and the interface says so.

Every platform generates a fresh private key per tunnel interface. On macOS `plexd up` builds the controller with the node's mesh IP as a `/32`, because `route(8)` refuses a route over a utun that carries no IPv4 address and answers `Network is unreachable`. Each tunnel utun therefore holds the mesh IP as an alias (`ifconfig utunN inet <meshIP>/32 <meshIP> alias`; a host prefix needs no on-link route, so none is added). That is the unnumbered-interface idiom: traffic the node originates towards the remote site leaves with the mesh IP as its source, which the remote site routes back through the tunnel. An identity without a mesh IP leaves the utun unnumbered. On Windows and Linux the tunnel interface stays unnumbered, since the route to a remote subnet is installed by adapter LUID there and through netlink on Linux, neither of which needs an address on the device.

macOS requires root and Windows Administrator, which the LocalSystem service satisfies. Each tunnel interface answers the WireGuard UAPI, so `wg show wg-s2s-0` works through `/var/run/wireguard/wg-s2s-0.sock` on macOS and through the named pipe `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\wg-s2s-0` on Windows. A second `CreateTunnelInterface` for a name that already exists fails with an error wrapping `os.ErrExist` on macOS and Windows, which is what `EEXIST` is on Linux. WinNAT is scoped to the mesh prefix, so a site-to-site source is not translated on Windows; see [pf & WFP Firewall Controllers](../networking/pf-wfp-firewall.md#nat).

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
| `CreateTunnelInterface`  | Creates a WireGuard interface with the given name and UDP listen port; not idempotent, a name in use fails with `os.ErrExist` |
| `RemoveTunnelInterface`  | Removes the WireGuard interface; idempotent for non-existent interfaces    |
| `ConfigureTunnelPeer`    | Configures the remote peer (public key, allowed IPs, endpoint, optional PSK) |
| `RemoveTunnelPeer`       | Removes the remote peer from the interface; idempotent                     |

## SiteToSiteManager

Central coordinator for site-to-site VPN lifecycle. Concurrent-safe via `sync.Mutex` — the reconcile handler and status readers may invoke methods concurrently.

Once `CreateTunnelInterface` succeeds, the manager asks the controller for `wireguard.OSInterfaceNamer`. A controller that implements it and reports a mapping supplies the name the operating system knows the interface by, which the manager stores as the tunnel's `osIface` and passes to every `RouteController` call: `EnableForwarding(osIface, meshIface)`, `AddRoute(subnet, osIface)`, `RemoveRoute(subnet, osIface)` and `DisableForwarding(osIface, meshIface)`, in `AddTunnel`, in its rollback, in `RemoveTunnel` and in `Teardown`. The `VPNController` calls keep the configured name. A controller that is no namer, or one that reports no mapping, leaves the configured name in both places, which is what Linux needs. `WGVPNController` is a namer on every platform: it answers the configured name where the wrapped controller keeps it, as `WindowsController` does, because that name is the one the operating system knows the adapter by. Reporting no mapping there would tell a caller reading the `wireguard.OSInterfaceNamer` contract that a live adapter does not exist. `WGVPNController` over `DarwinController` maps `wg-s2s-0` to `utunN`, and the manager logs the pairing at `Debug` when the two names differ:

```
tunnel interface resolved  component=bridge tunnel_id=t-1 interface=wg-s2s-0 os_interface=utun9
```

### Constructor

```go
func NewSiteToSiteManager(ctrl VPNController, routes RouteController, cfg Config, logger *slog.Logger, tunnelProviders map[string]TunnelProvider) *SiteToSiteManager
```

### Methods

| Method                       | Signature                                       | Description                                                     |
|------------------------------|--------------------------------------------------|-----------------------------------------------------------------|
| `Setup`                      | `(meshIface string) error`                       | Marks manager active; no-op when disabled                       |
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

// Add a tunnel (driven by the reconcile handler)
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

1. Disable forwarding for each WireGuard tunnel via `VPNController.DisableForwarding`
2. Remove routes for each tunnel's remote subnets via `RouteController.RemoveRoute`
3. Remove each tunnel's WireGuard interface via `VPNController.RemoveTunnelInterface`
4. Stop all registered tunnel providers via `provider.Stop()`
5. Mark manager as inactive and clear the tunnel map

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

## SSE Event Handling

There are no site-to-site-specific SSE handlers. The control plane emits a single
`bridge_config_updated` event with an opaque payload; `bridge.HandleBridgeConfigUpdated`
dispatches it to `TriggerReconcile()`, and the `SiteToSiteReconcileHandler` below
applies the desired site-to-site subtree from the authoritative state snapshot.

```go
dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventBridgeConfigUpdated,
    bridge.HandleBridgeConfigUpdated(reconciler))
```

## SiteToSiteReconcileHandler

```go
func SiteToSiteReconcileHandler(mgr *SiteToSiteManager, logger *slog.Logger) reconcile.ReconcileHandler
```

Returns a `reconcile.ReconcileHandler` that synchronizes tunnels to match the desired bridge site-to-site subtree. The handler is **presence-aware**: a `null` `Bridge` or `null` `SiteToSite` child means "not populated", so it reconciles against an empty desired set and tears down stale tunnels.

1. Reads tunnels from `desired.Bridge.SiteToSite.Tunnels` (empty when `Bridge` or `SiteToSite` is nil)
2. Builds a desired set keyed by `TunnelID`
3. Removes stale tunnels: current tunnel IDs not in the desired set
4. Detects changed tunnels: same tunnel ID but different config (uses `reflect.DeepEqual`) — removes and re-adds
5. Adds missing tunnels: desired tunnels not in the current set
6. Aggregates `AddTunnel` errors via `errors.Join`

### Registration

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.RelayReconcileHandler(bridgeMgr.Relay(), logger))
r.RegisterHandler(bridge.UserAccessReconcileHandler(accessMgr, logger))
r.RegisterHandler(bridge.IngressReconcileHandler(ingressMgr, logger))
r.RegisterHandler(bridge.SiteToSiteReconcileHandler(s2sMgr, logger))
```

## API Types

### SiteToSiteConfig

Pushed from the control plane in the snapshot `bridge.site_to_site` subtree (`api.BridgeSnapshot.SiteToSite`), present-but-nullable — a `null` value tears down active tunnels.

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

Site-to-site changes are delivered through the single bridge event constant; the
fine-grained `site_to_site_*` constants have been removed.

| Constant                        | Value                     |
|---------------------------------|---------------------------|
| `api.EventBridgeConfigUpdated`  | `"bridge_config_updated"` |

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

The controller behind those calls carries prefixes of its own:

| Step                       | Prefix                                    |
|----------------------------|-------------------------------------------|
| Private key generation     | `bridge: vpn: generate key:`              |
| Interface creation         | `bridge: vpn: create interface <name>:`   |
| Address assignment         | `bridge: vpn: configure address <cidr>:`  |
| Bringing the interface up  | `bridge: vpn: set interface up:`          |
| Interface removal          | `bridge: vpn: remove interface:`          |
| Peer public key decode     | `bridge: vpn: decode public key:`         |
| Peer public key parse      | `bridge: vpn: parse public key:`          |
| Endpoint resolution        | `bridge: vpn: resolve endpoint:`          |
| Allowed IP parse           | `bridge: vpn: parse allowed IP "<cidr>":` |
| PSK decode                 | `bridge: vpn: decode psk:`                |
| PSK parse                  | `bridge: vpn: parse psk:`                 |
| Peer programming           | `bridge: vpn: configure peer:`            |
| Peer removal               | `bridge: vpn: remove peer:`               |

Both implementations use these prefixes, so a rejected peer reads the same on every platform. `NetlinkVPNController` adds `bridge: vpn: open wgctrl:` and `bridge: vpn: configure device:` for the two steps only it has. On macOS and Windows the text after the prefix is the `wireguard:` controller's own message.

## Logging

All site-to-site log entries use `component=bridge`.

| Level   | Event                           | Keys                                                 |
|---------|---------------------------------|------------------------------------------------------|
| `Info`  | Site-to-site manager started    | `max_tunnels`, `interface_prefix`                    |
| `Info`  | Site-to-site manager stopped    | (none)                                               |
| `Info`  | Site-to-site tunnel added       | `tunnel_id`, `interface`, `remote_endpoint`, `remote_subnets` |
| `Info`  | Site-to-site tunnel removed     | `tunnel_id`                                          |
| `Debug` | Tunnel interface resolved       | `tunnel_id`, `interface`, `os_interface`             |
| `Info`  | Tunnel interface created        | `interface`, `listen_port`                           |
| `Info`  | Tunnel interface removed        | `interface`                                          |
| `Debug` | Tunnel interface addressed      | `interface`, `address`                               |
| `Debug` | Tunnel peer configured          | `interface`                                          |
| `Debug` | Tunnel peer removed             | `interface`                                          |
| `Error` | Remove route failed             | `tunnel_id`, `subnet`, `error`                       |
| `Error` | Remove peer failed              | `tunnel_id`, `error`                                 |
| `Error` | Remove interface failed         | `tunnel_id`, `error`                                 |
| `Error` | Reconcile: add tunnel failed    | `tunnel_id`, `error`                                 |

The four controller lines `tunnel interface created`, `tunnel interface removed`, `tunnel peer configured` and `tunnel peer removed` are the same on Linux, macOS and Windows. `tunnel interface addressed` comes from the WireGuard-backed controller and appears only when it is built with an address, which `plexd up` does on macOS.

## Integration Points

### Reconciliation Loop

The site-to-site reconcile handler plugs into `internal/reconcile` alongside existing handlers:

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(wireguard.ReconcileHandler(wgMgr))
r.RegisterHandler(policy.ReconcileHandler(enforcer, "plexd0"))
r.RegisterHandler(bridge.RelayReconcileHandler(bridgeMgr.Relay(), logger))
r.RegisterHandler(bridge.UserAccessReconcileHandler(accessMgr, logger))
r.RegisterHandler(bridge.IngressReconcileHandler(ingressMgr, logger))
r.RegisterHandler(bridge.SiteToSiteReconcileHandler(s2sMgr, logger))
```

### SSE Real-Time Updates

The `bridge_config_updated` event triggers a full reconcile; the
`SiteToSiteReconcileHandler` then applies the desired tunnel set from the state
snapshot. There are no per-tunnel events.

### Control Plane Types

| Type                                      | Package        | Usage                                           |
|-------------------------------------------|----------------|-------------------------------------------------|
| `api.SiteToSiteConfig`                    | `internal/api` | Desired site-to-site config from control plane  |
| `api.SiteToSiteTunnel`                    | `internal/api` | Individual tunnel definition                    |
| `api.SiteToSiteInfo`                      | `internal/api` | Site-to-site status in heartbeats               |
| `api.BridgeSnapshot`                      | `internal/api` | Snapshot `bridge` subtree (contains `SiteToSite`) |
| `api.HeartbeatRequest`                    | `internal/api` | Heartbeat payload (contains `SiteToSiteInfo`)   |
| `api.Envelope`                            | `internal/api` | SSE event wrapper                               |
| `api.EventBridgeConfigUpdated`            | `internal/api` | Event type `"bridge_config_updated"`            |

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

// Register the bridge SSE handler
dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventBridgeConfigUpdated,
    bridge.HandleBridgeConfigUpdated(reconciler))

// Register reconcile handler
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.SiteToSiteReconcileHandler(s2sMgr, logger))

// Run reconciler
go r.Run(ctx, nodeID)

// Graceful shutdown
<-ctx.Done()
s2sMgr.Teardown()
```
