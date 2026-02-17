---
title: Tunnel Providers
package: internal/bridge
feature: PXD-0028
---

# Tunnel Providers

> **Note: This subsystem is not active in the current release.** The code in `internal/bridge` is implemented and its configuration section (`bridge`) is parsed and validated on startup, but the subsystem is not started by `plexd up`. Configuring this section has no runtime effect. See [Architecture and Concepts](../../concepts.md) for the list of active subsystems.

The tunnel providers feature extends site-to-site VPN connectivity (`internal/bridge`) to support non-WireGuard tunnel technologies (IPsec, OpenVPN). A `TunnelProvider` interface abstracts lifecycle management of external tunnel daemons, enabling heterogeneous site-to-site connectivity alongside the existing WireGuard-based approach. The `SiteToSiteManager` delegates to the appropriate provider based on the `ProviderType` field of each tunnel definition.

## Data Flow

```
External Network
(remote site)
      |
      |  IPsec / OpenVPN tunnel
      v
+---------------------------------------------------------------+
|                        Bridge Node                              |
|                                                                 |
|  +-------------------+         +-------------------+           |
|  |  IPsec / OpenVPN  |  route  |  Mesh WireGuard   |           |
|  |  Tunnels          |-------->|  Interface        |           |
|  |  (ipsec-{id},     |         |  (plexd0)         |           |
|  |   tun-{id})       |         |                   |           |
|  +-------------------+         +---------+---------+           |
|         ^                                |                     |
|         |                                v                     |
|  +------+------------+            +------------------+           |
|  | TunnelProvider    |            |  Mesh Peers      |           |
|  | (IPsec/OpenVPN)   |            |  10.42.0.0/16    |           |
|  +---------+---------+            +------------------+           |
|            |                                                     |
|  +------+-------------+                                          |
|  | CommandExecutor    |                                          |
|  | (CLI invocation)   |                                          |
|  +------+-------------+                                          |
|            |                                                     |
|  +------+-------------+                                          |
|  | RouteController    |                                          |
|  | (OS routing ops)   |                                          |
|  +--------------------+                                          |
|                                                                 |
|  SiteToSiteManager delegates to TunnelProvider                  |
|    when tunnel.ProviderType != "" && != "wireguard"             |
+-----------------------------------------------------------------+
```

Traffic between the external site and mesh peers flows through provider-managed tunnel interfaces (`ipsec-{id}` for IPsec, `tun-{id}` for OpenVPN). The `TunnelProvider` wraps the tunnel daemon CLI, managing config generation, process lifecycle, and route installation via `RouteController`. The `SiteToSiteManager` tracks provider-managed tunnels alongside WireGuard tunnels in a unified `activeTunnels` map.

## TunnelProvider Interface

Abstracts lifecycle management of non-WireGuard tunnel technologies. Implementations invoke the tunnel daemon/CLI to establish encrypted tunnels to external networks. All methods must be safe for concurrent use.

```go
type TunnelProvider interface {
    Name() string
    CreateTunnel(ctx context.Context, cfg TunnelConfig) error
    RemoveTunnel(tunnelID string) error
    TunnelStatus(tunnelID string) TunnelStatus
    ActiveTunnels() []string
    Stop() error
}
```

| Method          | Description                                                                     |
|-----------------|---------------------------------------------------------------------------------|
| `Name`          | Returns the provider identifier (e.g. `"ipsec"`, `"openvpn"`)                  |
| `CreateTunnel`  | Establishes a tunnel with the given configuration; returns error if it already exists |
| `RemoveTunnel`  | Tears down the tunnel with the given ID; idempotent for non-existent tunnels   |
| `TunnelStatus`  | Returns the status of the tunnel; zero-value with `Running=false` if not found |
| `ActiveTunnels` | Returns sorted IDs of all active tunnels                                        |
| `Stop`          | Gracefully shuts down all tunnels managed by this provider; idempotent         |

## TunnelConfig

Holds the configuration for creating a tunnel via a `TunnelProvider`.

```go
type TunnelConfig struct {
    TunnelID       string            `json:"tunnel_id"`
    LocalSubnets   []string          `json:"local_subnets"`
    RemoteSubnets  []string          `json:"remote_subnets"`
    RemoteEndpoint string            `json:"remote_endpoint"`
    PSK            string            `json:"psk"`
    Extra          map[string]string `json:"extra,omitempty"`
}
```

| Field            | Description                                                  |
|------------------|--------------------------------------------------------------|
| `TunnelID`       | Unique identifier for this tunnel                           |
| `LocalSubnets`   | Local CIDR subnets to expose through the tunnel             |
| `RemoteSubnets`  | Remote CIDR subnets reachable through the tunnel            |
| `RemoteEndpoint` | Remote tunnel peer address (host:port or IP)                |
| `PSK`            | Pre-shared key for tunnel authentication                    |
| `Extra`          | Provider-specific configuration parameters (optional)       |

## TunnelStatus

Represents the current status of a tunnel managed by a `TunnelProvider`.

```go
type TunnelStatus struct {
    TunnelID      string `json:"tunnel_id"`
    Running       bool   `json:"running"`
    InterfaceName string `json:"interface_name,omitempty"`
    Error         string `json:"error,omitempty"`
}
```

| Field           | Description                                            |
|-----------------|--------------------------------------------------------|
| `TunnelID`      | Unique identifier for this tunnel                     |
| `Running`       | Whether the tunnel is active                          |
| `InterfaceName` | Network interface used by the tunnel (if running)     |
| `Error`         | Last error message, if any                            |

## CommandExecutor

Shared interface abstracting command execution for testability. Defined in `internal/bridge/exec.go`.

```go
type CommandExecutor interface {
    Run(ctx context.Context, name string, args ...string) ([]byte, error)
    Start(ctx context.Context, name string, args ...string) (CommandHandle, error)
}

type CommandHandle interface {
    Stop() error
}
```

| Method               | Description                                                           |
|----------------------|-----------------------------------------------------------------------|
| `Run`                | Executes a command synchronously and returns its combined output      |
| `Start`              | Starts a long-running command; returns a `CommandHandle` to stop it   |
| `CommandHandle.Stop` | Terminates the running process                                        |

`Run` is used by `IPsecProvider` for short-lived swanctl commands. `Start` is used by `OpenVPNProvider` for the long-running OpenVPN process.

## IPsecProvider

Concrete `TunnelProvider` implementation wrapping strongSwan (swanctl) CLI. File: `internal/bridge/ipsec.go`.

### Constructor

```go
func NewIPsecProvider(exec CommandExecutor, routes RouteController, logger *slog.Logger) *IPsecProvider
```

- Initializes an empty `tunnels` map
- Concurrent-safe via `sync.Mutex`

### Name

Returns `"ipsec"`.

### CreateTunnel

1. Rejects duplicate tunnel IDs (`bridge: ipsec: tunnel "..." already exists`)
2. Generates swanctl config file at `/run/plexd/tunnels/plexd-ipsec-{id}.conf` (PSK auth, `local_ts`/`remote_ts` from subnets)
3. Runs `swanctl --load-conns --file {confPath}` to load the connection configuration
4. Runs `swanctl --initiate --child {id}` to establish the tunnel
5. Adds routes for each remote subnet via `RouteController.AddRoute` with interface name `ipsec-{id}`
6. Tracks the tunnel in the internal map

On failure at any step, CreateTunnel performs full rollback of all completed operations:

- Route addition failure: rolls back previously added routes, terminates the child, removes config file
- Initiate failure: terminates the child, removes config file
- Load conns failure: removes config file
- Config write failure: returns error immediately

### RemoveTunnel

Idempotent. For a non-existent tunnel, returns `nil`.

1. Terminates the connection via `swanctl --terminate --child {id}`
2. Removes routes for each remote subnet via `RouteController.RemoveRoute`
3. Removes the config file at `/run/plexd/tunnels/plexd-ipsec-{id}.conf`
4. Deletes the tunnel from the internal map

Errors during removal are logged but do not prevent cleanup of remaining resources.

### Stop

Calls `removeTunnelLocked` for all active tunnels. Idempotent.

### ActiveTunnels

Returns sorted IDs of all active tunnels.

### Generated Config Format

```
connections {
    {tunnel_id} {
        remote_addrs = {remote_endpoint}
        local {
            auth = psk
        }
        remote {
            auth = psk
        }
        children {
            {tunnel_id} {
                local_ts = {local_subnets joined by comma}
                remote_ts = {remote_subnets joined by comma}
            }
        }
    }
}
secrets {
    ike-{tunnel_id} {
        secret = {psk}
    }
}
```

## OpenVPNProvider

Concrete `TunnelProvider` implementation wrapping the OpenVPN CLI. File: `internal/bridge/openvpn.go`.

### Constructor

```go
func NewOpenVPNProvider(exec CommandExecutor, routes RouteController, logger *slog.Logger) *OpenVPNProvider
```

- Initializes an empty `tunnels` map
- Concurrent-safe via `sync.Mutex`

### Name

Returns `"openvpn"`.

### CreateTunnel

1. Rejects duplicate tunnel IDs (`bridge: openvpn: tunnel "..." already exists`)
2. Generates OpenVPN config at `/run/plexd/tunnels/plexd-openvpn-{id}.conf` (client mode, static key inline)
3. Starts the OpenVPN process via `exec.Start("openvpn", "--config", confPath)` (long-running, returns `CommandHandle`)
4. Adds routes for each remote subnet via `RouteController.AddRoute` with interface name `tun-{id}`
5. Tracks the tunnel (including `CommandHandle`) in the internal map

On failure at any step, CreateTunnel performs full rollback of all completed operations:

- Route addition failure: rolls back previously added routes, stops the process via `handle.Stop()`, removes config file
- Process start failure: removes config file
- Config write failure: returns error immediately

### RemoveTunnel

Idempotent. For a non-existent tunnel, returns `nil`.

1. Stops the OpenVPN process via `handle.Stop()`
2. Removes routes for each remote subnet via `RouteController.RemoveRoute`
3. Removes the config file at `/run/plexd/tunnels/plexd-openvpn-{id}.conf`
4. Deletes the tunnel from the internal map

Errors during removal are logged but do not prevent cleanup of remaining resources.

### Stop

Calls `removeTunnelLocked` for all active tunnels. Idempotent.

### ActiveTunnels

Returns sorted IDs of all active tunnels.

### Generated Config Format

```
client
remote {host} {port}
dev {tun-id}
dev-type tun
secret [inline]
<secret>
{psk}
</secret>
```

The remote endpoint is split into host and port at the last `:` delimiter. If no port is present, `1194` is used as the default.

## Config Fields

Tunnel provider configuration is part of the bridge `Config` struct.

| Field              | Type       | Default | Description                                                           |
|--------------------|------------|---------|-----------------------------------------------------------------------|
| `TunnelProviders`  | `[]string` | `nil`   | Tunnel provider types to enable. Supported: `"ipsec"`, `"openvpn"`. Empty = WireGuard-only. |

```go
cfg := bridge.Config{
    Enabled:           true,
    AccessInterface:   "eth1",
    AccessSubnets:     []string{"10.0.0.0/24"},
    SiteToSiteEnabled: true,
    TunnelProviders:   []string{"ipsec", "openvpn"},
}
cfg.ApplyDefaults()
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

### Validation Rules

| Field             | Rule                                       | Error Message                                           |
|-------------------|--------------------------------------------|---------------------------------------------------------|
| `TunnelProviders` | Each entry must be `"ipsec"` or `"openvpn"` | `bridge: config: unsupported TunnelProvider "..."`      |

Validation iterates over all entries in `TunnelProviders`. Any value other than `"ipsec"` or `"openvpn"` causes a validation error. An empty slice is valid and means WireGuard-only mode.

## Integration with SiteToSiteManager

The `SiteToSiteManager` accepts an optional map of `TunnelProvider` instances and delegates tunnel lifecycle to the appropriate provider based on the `ProviderType` field of each `api.SiteToSiteTunnel`.

### Constructor

```go
func NewSiteToSiteManager(
    ctrl VPNController,
    routes RouteController,
    cfg Config,
    logger *slog.Logger,
    tunnelProviders map[string]TunnelProvider,
) *SiteToSiteManager
```

- `tunnelProviders` can be `nil` (WireGuard-only mode); internally normalized to an empty map
- Provider map is keyed by provider name (e.g. `"ipsec"`, `"openvpn"`)

### AddTunnel — Provider Delegation

When `tunnel.ProviderType` is non-empty and not `"wireguard"`, `AddTunnel` delegates to the matching `TunnelProvider`:

1. Looks up the provider by `tunnel.ProviderType` in the `tunnelProviders` map
2. Returns `bridge: site-to-site: unsupported provider type: ...` if not found
3. Builds a `TunnelConfig` from the `api.SiteToSiteTunnel` fields:
   - `TunnelID` from `tunnel.TunnelID`
   - `LocalSubnets` from `tunnel.LocalSubnets`
   - `RemoteSubnets` from `tunnel.RemoteSubnets`
   - `RemoteEndpoint` from `tunnel.RemoteEndpoint`
   - `PSK` from `tunnel.PSK`
4. Calls `provider.CreateTunnel(ctx, cfg)`
5. Tracks the tunnel in `activeTunnels` with `providerName` set to `tunnel.ProviderType`

When `tunnel.ProviderType` is empty or `"wireguard"`, the existing WireGuard path is used (VPNController).

### RemoveTunnel — Provider Delegation

For provider-managed tunnels (where `activeTunnel.providerName` is non-empty):

1. Looks up the provider by `providerName` in the `tunnelProviders` map
2. Calls `provider.RemoveTunnel(tunnelID)`
3. Deletes the tunnel from `activeTunnels`

Errors during provider removal are logged but do not prevent the tunnel from being untracked.

### Teardown

Teardown handles both WireGuard and provider-managed tunnels:

1. For each active tunnel:
   - If `providerName` is set: delegates to `provider.RemoveTunnel(id)`
   - If WireGuard: removes routes, disables forwarding, removes interface
2. Calls `provider.Stop()` on all registered tunnel providers
3. Marks manager as inactive and clears the tunnel map

Errors are aggregated via `errors.Join`.

### SiteToSiteStatus

Populates `TunnelProviderNames` in the returned `api.SiteToSiteInfo`:

```go
info := &api.SiteToSiteInfo{
    Enabled:             true,
    TunnelCount:         len(m.activeTunnels),
    TunnelProviderNames: providerNames, // sorted alphabetically
}
```

### API Type Extensions

The `api.SiteToSiteTunnel` type includes the `ProviderType` field:

```go
type SiteToSiteTunnel struct {
    // ... existing fields ...
    ProviderType string `json:"provider_type,omitempty"`
}
```

| Field          | Description                                                                         |
|----------------|-------------------------------------------------------------------------------------|
| `ProviderType` | Which tunnel provider to use. Empty or `"wireguard"` = default WireGuard. Other values (e.g. `"ipsec"`, `"openvpn"`) delegate to the corresponding `TunnelProvider`. |

The `api.SiteToSiteInfo` type includes the `TunnelProviderNames` field:

```go
type SiteToSiteInfo struct {
    Enabled             bool     `json:"enabled"`
    TunnelCount         int      `json:"tunnel_count"`
    TunnelProviderNames []string `json:"tunnel_provider_names,omitempty"`
}
```

| Field                 | Description                                                  |
|-----------------------|--------------------------------------------------------------|
| `TunnelProviderNames` | Sorted list of registered tunnel provider names (e.g. `["ipsec", "openvpn"]`) |

## Error Prefixes

| Source                                                         | Prefix                                                                   |
|----------------------------------------------------------------|--------------------------------------------------------------------------|
| `IPsecProvider.CreateTunnel` (duplicate)                       | `bridge: ipsec: tunnel "..." already exists`                             |
| `IPsecProvider.CreateTunnel` (write config)                    | `bridge: ipsec: write config for "...": `                                |
| `IPsecProvider.CreateTunnel` (load conns)                      | `bridge: ipsec: load conns for "...": `                                  |
| `IPsecProvider.CreateTunnel` (initiate)                        | `bridge: ipsec: initiate "...": `                                        |
| `IPsecProvider.CreateTunnel` (add route)                       | `bridge: ipsec: add route "..." for "...": `                             |
| `IPsecProvider.Stop` (stop tunnel)                             | `bridge: ipsec: stop tunnel "...": `                                     |
| `OpenVPNProvider.CreateTunnel` (duplicate)                     | `bridge: openvpn: tunnel "..." already exists`                           |
| `OpenVPNProvider.CreateTunnel` (write config)                  | `bridge: openvpn: write config for "...": `                              |
| `OpenVPNProvider.CreateTunnel` (start)                         | `bridge: openvpn: start "...": `                                         |
| `OpenVPNProvider.CreateTunnel` (add route)                     | `bridge: openvpn: add route "..." for "...": `                           |
| `OpenVPNProvider.Stop` (stop tunnel)                           | `bridge: openvpn: stop tunnel "...": `                                   |
| `SiteToSiteManager.AddTunnel` (unsupported provider)           | `bridge: site-to-site: unsupported provider type: `                      |
| `SiteToSiteManager.AddTunnel` (provider create)                | `bridge: site-to-site: provider {name} create tunnel {id}: `            |
| `SiteToSiteManager.Teardown` (provider remove)                 | `bridge: site-to-site: provider {name} remove tunnel {id}: `            |
| `SiteToSiteManager.Teardown` (provider stop)                   | `bridge: site-to-site: stop provider {name}: `                           |
| `Config.Validate` (unsupported provider)                       | `bridge: config: unsupported TunnelProvider "..."`                       |

## Logging

All tunnel provider log entries use `component=bridge` with an additional `provider` key.

| Level   | Event                              | Keys                                                  |
|---------|------------------------------------|-------------------------------------------------------|
| `Info`  | Tunnel created (IPsec)            | `component=bridge`, `provider=ipsec`, `tunnel_id`, `interface`   |
| `Info`  | Tunnel removed (IPsec)            | `component=bridge`, `provider=ipsec`, `tunnel_id`                |
| `Warn`  | Terminate tunnel failed (IPsec)   | `component=bridge`, `provider=ipsec`, `tunnel_id`, `error`       |
| `Warn`  | Remove route failed (IPsec)       | `component=bridge`, `provider=ipsec`, `tunnel_id`, `subnet`, `error` |
| `Info`  | Tunnel created (OpenVPN)          | `component=bridge`, `provider=openvpn`, `tunnel_id`, `interface` |
| `Info`  | Tunnel removed (OpenVPN)          | `component=bridge`, `provider=openvpn`, `tunnel_id`              |
| `Warn`  | Stop process failed (OpenVPN)     | `component=bridge`, `provider=openvpn`, `tunnel_id`, `error`     |
| `Warn`  | Remove route failed (OpenVPN)     | `component=bridge`, `provider=openvpn`, `tunnel_id`, `subnet`, `error` |
| `Info`  | Tunnel added via provider (S2S)   | `tunnel_id`, `provider`, `remote_endpoint`, `remote_subnets`     |
| `Info`  | Tunnel removed via provider (S2S) | `tunnel_id`, `provider`                                          |
| `Error` | Provider remove tunnel failed (S2S) | `tunnel_id`, `provider`, `error`                               |

## Full Lifecycle

```go
cfg := bridge.Config{
    Enabled:           true,
    AccessInterface:   "eth1",
    AccessSubnets:     []string{"10.0.0.0/24"},
    SiteToSiteEnabled: true,
    TunnelProviders:   []string{"ipsec", "openvpn"},
}
cfg.ApplyDefaults()

// Create tunnel providers
exec := newSystemExecutor() // production CommandExecutor
ipsecProv := bridge.NewIPsecProvider(exec, routeCtrl, logger)
openvpnProv := bridge.NewOpenVPNProvider(exec, routeCtrl, logger)

providers := map[string]bridge.TunnelProvider{
    "ipsec":   ipsecProv,
    "openvpn": openvpnProv,
}

// Create the site-to-site manager with providers
s2sMgr := bridge.NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, logger, providers)

// Setup site-to-site manager
s2sMgr.Setup("plexd0")

// Add a WireGuard tunnel (default path)
s2sMgr.AddTunnel(api.SiteToSiteTunnel{
    TunnelID:        "site-hq",
    RemoteEndpoint:  "203.0.113.1:51820",
    RemotePublicKey: "base64-encoded-key",
    LocalSubnets:    []string{"10.0.0.0/24"},
    RemoteSubnets:   []string{"192.168.1.0/24"},
    InterfaceName:   "wg-s2s-site-hq",
    ListenPort:      51823,
})

// Add an IPsec tunnel (provider delegation)
s2sMgr.AddTunnel(api.SiteToSiteTunnel{
    TunnelID:       "site-branch",
    RemoteEndpoint: "198.51.100.1",
    LocalSubnets:   []string{"10.0.0.0/24"},
    RemoteSubnets:  []string{"172.16.0.0/24"},
    PSK:            "shared-secret-key",
    ProviderType:   "ipsec",
})

// Add an OpenVPN tunnel (provider delegation)
s2sMgr.AddTunnel(api.SiteToSiteTunnel{
    TunnelID:       "site-remote",
    RemoteEndpoint: "203.0.113.5:1194",
    LocalSubnets:   []string{"10.0.0.0/24"},
    RemoteSubnets:  []string{"10.99.0.0/24"},
    PSK:            "openvpn-static-key",
    ProviderType:   "openvpn",
})

// Report status in heartbeat — includes provider names
status := s2sMgr.SiteToSiteStatus()
// &api.SiteToSiteInfo{
//     Enabled: true,
//     TunnelCount: 3,
//     TunnelProviderNames: ["ipsec", "openvpn"],
// }

// Remove individual tunnels
s2sMgr.RemoveTunnel("site-branch") // delegates to IPsecProvider
s2sMgr.RemoveTunnel("site-hq")     // uses WireGuard path

// Graceful shutdown — removes all tunnels, stops all providers
<-ctx.Done()
if err := s2sMgr.Teardown(); err != nil {
    logger.Warn("site-to-site teardown failed", "error", err)
}
```

## Integration Points

### SiteToSiteManager Constructor

The `tunnelProviders` parameter is optional. Passing `nil` produces WireGuard-only behavior identical to the pre-PXD-0028 implementation:

```go
// WireGuard-only (no providers)
s2sMgr := bridge.NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, logger, nil)

// With providers
s2sMgr := bridge.NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, logger, providers)
```

### Heartbeat Reporting

```go
heartbeat := api.HeartbeatRequest{
    SiteToSite: s2sMgr.SiteToSiteStatus(), // includes TunnelProviderNames
}
```

### Graceful Shutdown

```go
<-ctx.Done()
if err := s2sMgr.Teardown(); err != nil {
    logger.Warn("site-to-site teardown failed", "error", err)
}
```
