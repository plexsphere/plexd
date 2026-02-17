---
title: VPN Providers
package: internal/bridge
feature: PXD-0028
---

# VPN Providers

> **Note: This subsystem is not active in the current release.** The code in `internal/bridge` is implemented and its configuration section (`bridge`) is parsed and validated on startup, but the subsystem is not started by `plexd up`. Configuring this section has no runtime effect. See [Architecture and Concepts](../../concepts.md) for the list of active subsystems.

The VPN providers feature extends user access integration (`internal/bridge`) with a `UserAccessProvider` interface for external VPN provider integration. Concrete implementations for Tailscale and Netbird enable external VPN users to access mesh resources through the bridge node via their provider's overlay network.

## Data Flow

```
External VPN Users
(Tailscale / Netbird)
        |
        |  Provider overlay network
        v
+---------------------------------------------------------------+
|                        Bridge Node                              |
|                                                                 |
|  +-------------------+         +-------------------+           |
|  |  Provider         |  IP fwd |  Mesh WireGuard   |           |
|  |  Interface        |-------->|  Interface        |           |
|  |  (tailscale0 /    |         |  (plexd0)         |           |
|  |   wt0 / etc.)     |         |                   |           |
|  +-------------------+         +---------+---------+           |
|         ^                                |                     |
|         |                                v                     |
|  +------+------------+            +------------------+         |
|  | UserAccessProvider |            |  Mesh Peers      |         |
|  | (Tailscale/Netbird)|            |  10.42.0.0/16    |         |
|  +---------+----------+            +------------------+         |
|            |                                                    |
|  +---------+---------+                                          |
|  | CommandExecutor   |                                          |
|  | (CLI invocations) |                                          |
|  +-------------------+                                          |
|                                                                 |
|  UserAccessManager -----> provider.Start() / provider.Stop()    |
+-----------------------------------------------------------------+
```

Traffic from external VPN users arrives on the provider's network interface, is forwarded via IP forwarding to the mesh WireGuard interface (`plexd0`), and reaches mesh peers. The `UserAccessProvider` manages the provider daemon lifecycle. The `CommandExecutor` abstracts CLI invocations for testability.

## UserAccessProvider Interface

Interface abstracting lifecycle management of external VPN providers (Tailscale, Netbird) used for user access into the mesh via a bridge node. Implementations invoke the provider's CLI or daemon to join an overlay network, then report status so the bridge can route traffic between the provider's interface and the mesh.

```go
type UserAccessProvider interface {
    Name() string
    Start(ctx context.Context) error
    Stop() error
    Status() ProviderStatus
}
```

| Method   | Description                                                                |
|----------|----------------------------------------------------------------------------|
| `Name`   | Returns the provider identifier (e.g. `"tailscale"`, `"netbird"`)         |
| `Start`  | Launches the provider daemon/process; reads auth credentials from the environment |
| `Stop`   | Gracefully shuts down the provider; idempotent when not running            |
| `Status` | Returns the current provider status                                        |

All methods must be safe for concurrent use.

## ProviderStatus

Represents the current status of a user access VPN provider.

```go
type ProviderStatus struct {
    Running       bool   `json:"running"`
    InterfaceName string `json:"interface_name,omitempty"`
    IP            string `json:"ip,omitempty"`
    Error         string `json:"error,omitempty"`
}
```

| Field           | Description                                             |
|-----------------|---------------------------------------------------------|
| `Running`       | Whether the provider process is active                  |
| `InterfaceName` | Network interface created by the provider               |
| `IP`            | IP address assigned by the provider                     |
| `Error`         | Last error message, if any                              |

## CommandExecutor Interface

Shared abstraction for CLI command execution, enabling full unit testing without invoking real binaries.

```go
type CommandExecutor interface {
    Run(ctx context.Context, name string, args ...string) ([]byte, error)
    Start(ctx context.Context, name string, args ...string) (CommandHandle, error)
}
```

| Method  | Description                                                                  |
|---------|------------------------------------------------------------------------------|
| `Run`   | Executes a command synchronously and returns its combined output             |
| `Start` | Starts a command without waiting for completion; returns a handle to stop it |

### CommandHandle

```go
type CommandHandle interface {
    Stop() error
}
```

| Method | Description                |
|--------|----------------------------|
| `Stop` | Terminates the process     |

## TailscaleProvider

Concrete `UserAccessProvider` implementation wrapping the Tailscale CLI (`tailscale`/`tailscaled`). Joins a Tailscale network on a bridge node, enabling Tailscale users to access mesh resources.

- **File**: `internal/bridge/tailscale.go`
- **Name**: `"tailscale"`
- **Interface name**: `"tailscale0"` (hardcoded)
- **Auth key env var**: `PLEXD_TAILSCALE_AUTH_KEY`
- **Concurrency**: `sync.Mutex` protects `running`, `ip`, `ifaceName`, `daemonHandle`

### Constructor

```go
func NewTailscaleProvider(exec CommandExecutor, logger *slog.Logger) *TailscaleProvider
```

### Start Sequence

1. Read auth key from `PLEXD_TAILSCALE_AUTH_KEY` environment variable
2. Start `tailscaled --state=mem:` via `CommandExecutor.Start` (long-running daemon)
3. Run `tailscale up --authkey=<key> --accept-routes` via `CommandExecutor.Run`
4. Run `tailscale status --json` via `CommandExecutor.Run` to discover the assigned IP
5. Parse `TailscaleIPs[0]` from the JSON response as the provider IP
6. Set interface name to `"tailscale0"`, mark as running

Full rollback on failure at any step:

| Failure Point            | Rollback Actions                                              |
|--------------------------|---------------------------------------------------------------|
| `tailscale up` fails     | Stop daemon handle                                            |
| `tailscale status` fails | Run `tailscale down`, stop daemon handle                      |
| JSON parse fails         | Run `tailscale down`, stop daemon handle                      |

### Stop Sequence

1. Run `tailscale down` (disconnect from network)
2. Stop daemon handle via `CommandHandle.Stop`
3. Clear `running`, `ip`, `ifaceName`

Idempotent: calling `Stop` when not running returns `nil`.

### Usage

```go
exec := &prodCommandExecutor{} // production CommandExecutor
provider := bridge.NewTailscaleProvider(exec, logger)

// Start — joins Tailscale network
if err := provider.Start(ctx); err != nil {
    log.Fatal(err) // e.g. "bridge: tailscale: PLEXD_TAILSCALE_AUTH_KEY is not set"
}

// Query status
status := provider.Status()
// ProviderStatus{Running: true, InterfaceName: "tailscale0", IP: "100.64.0.1"}

// Graceful shutdown
provider.Stop()
```

## NetbirdProvider

Concrete `UserAccessProvider` implementation wrapping the Netbird CLI (`netbird`). Joins a Netbird network using a setup key, enabling Netbird users to access mesh resources through the bridge node.

- **File**: `internal/bridge/netbird.go`
- **Name**: `"netbird"`
- **Interface name**: discovered from `netbird status --json` (e.g. `"wt0"`)
- **Setup key env var**: `PLEXD_NETBIRD_SETUP_KEY`
- **Concurrency**: `sync.Mutex` protects `status`

### Constructor

```go
func NewNetbirdProvider(exec CommandExecutor, logger *slog.Logger) *NetbirdProvider
```

### Start Sequence

1. Read setup key from `PLEXD_NETBIRD_SETUP_KEY` environment variable
2. Run `netbird up --setup-key <key>` via `CommandExecutor.Run`
3. Run `netbird status --json` via `CommandExecutor.Run` to discover IP and interface
4. Parse IP and interface name from the JSON response
5. Strip CIDR prefix from IP if present (e.g. `"100.119.0.1/16"` becomes `"100.119.0.1"`)
6. Mark as running

### Stop Sequence

1. Run `netbird down` via `CommandExecutor.Run`
2. Clear status to zero value

Idempotent: calling `Stop` when not running returns `nil`.

### Usage

```go
exec := &prodCommandExecutor{} // production CommandExecutor
provider := bridge.NewNetbirdProvider(exec, logger)

// Start — joins Netbird network
if err := provider.Start(ctx); err != nil {
    log.Fatal(err) // e.g. "bridge: netbird: PLEXD_NETBIRD_SETUP_KEY environment variable is not set"
}

// Query status
status := provider.Status()
// ProviderStatus{Running: true, InterfaceName: "wt0", IP: "100.119.0.1"}

// Graceful shutdown
provider.Stop()
```

## Config Fields

The following fields on the bridge `Config` struct control VPN provider selection.

| Field                      | Type     | Default | Description                                              |
|----------------------------|----------|---------|----------------------------------------------------------|
| `UserAccessProviderType`   | `string` | `""`    | External VPN provider: `"tailscale"`, `"netbird"`, or `""` (disabled) |
| `AuthKeyEnv`               | `string` | —       | Env var name for the auth key (e.g. `"PLEXD_TAILSCALE_AUTH_KEY"`) |
| `SetupKeyEnv`              | `string` | —       | Env var name for the setup key (e.g. `"PLEXD_NETBIRD_SETUP_KEY"`) |

```go
cfg := bridge.Config{
    Enabled:                true,
    AccessInterface:        "eth1",
    AccessSubnets:          []string{"10.0.0.0/24"},
    UserAccessEnabled:      true,
    UserAccessProviderType: "tailscale",
    AuthKeyEnv:             "PLEXD_TAILSCALE_AUTH_KEY",
}
cfg.ApplyDefaults()
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

### Validation Rules

Provider validation runs when `UserAccessProviderType` is non-empty, regardless of other flags.

| Field                      | Rule                                         | Error Message                                                      |
|----------------------------|----------------------------------------------|--------------------------------------------------------------------|
| `UserAccessProviderType`   | Must be `"tailscale"`, `"netbird"`, or `""`  | `bridge: config: unsupported UserAccessProviderType "<value>"`     |

## Integration with UserAccessManager

The `UserAccessProvider` integrates into the existing `UserAccessManager` as an optional dependency.

### Constructor

```go
func NewUserAccessManager(ctrl AccessController, routes RouteController, cfg Config, logger *slog.Logger, provider UserAccessProvider) *UserAccessManager
```

The `provider` parameter is optional -- pass `nil` when no external VPN provider is used.

### Setup

When a provider is configured, `Setup` calls `provider.Start()` after the WireGuard interface and forwarding are established:

1. `AccessController.CreateInterface(interfaceName, listenPort)` -- create WG interface
2. `RouteController.EnableForwarding(interfaceName, accessInterface)` -- enable IP forwarding
3. `provider.Start(ctx)` -- launch the VPN provider (only when provider is non-nil)

If `provider.Start()` fails, full rollback is performed: forwarding is disabled and the interface is removed.

### Teardown

When a provider is configured, `Teardown` calls `provider.Stop()` first, before removing peers and interfaces:

1. `provider.Stop()` -- stop the VPN provider (only when provider is non-nil)
2. Remove all tracked peers via `AccessController.RemovePeer`
3. Disable forwarding via `RouteController.DisableForwarding`
4. Remove interface via `AccessController.RemoveInterface`

Errors are aggregated via `errors.Join` -- cleanup continues even when individual operations fail.

### UserAccessStatus

When a provider is configured, `UserAccessStatus()` includes provider information in the returned `api.UserAccessInfo`:

| Field            | Source                    | Values                                   |
|------------------|---------------------------|------------------------------------------|
| `ProviderName`   | `provider.Name()`         | `"tailscale"`, `"netbird"`               |
| `ProviderStatus` | Derived from `provider.Status()` | `"running"`, `"error"`, `"stopped"` |

Status derivation logic:

- `status.Running == true` => `"running"`
- `status.Error != ""` => `"error"`
- Otherwise => `"stopped"`

### UserAccessInfo API Type

```go
type UserAccessInfo struct {
    Enabled        bool   `json:"enabled"`
    InterfaceName  string `json:"interface_name"`
    PeerCount      int    `json:"peer_count"`
    ListenPort     int    `json:"listen_port"`
    ProviderName   string `json:"provider_name,omitempty"`
    ProviderStatus string `json:"provider_status,omitempty"`
}
```

| Field            | Description                                                          |
|------------------|----------------------------------------------------------------------|
| `ProviderName`   | Provider identifier; empty when no provider is configured            |
| `ProviderStatus` | Provider state: `"running"`, `"error"`, or `"stopped"`; empty when no provider |

## Error Prefixes

| Source                                            | Prefix                                                         |
|---------------------------------------------------|----------------------------------------------------------------|
| `TailscaleProvider.Start` (no key)                | `bridge: tailscale: PLEXD_TAILSCALE_AUTH_KEY is not set`       |
| `TailscaleProvider.Start` (daemon)                | `bridge: tailscale: start tailscaled: `                        |
| `TailscaleProvider.Start` (up)                    | `bridge: tailscale: tailscale up: `                            |
| `TailscaleProvider.Start` (status)                | `bridge: tailscale: tailscale status: `                        |
| `TailscaleProvider.Start` (parse)                 | `bridge: tailscale: parse status: `                            |
| `NetbirdProvider.Start` (no key)                  | `bridge: netbird: PLEXD_NETBIRD_SETUP_KEY environment variable is not set` |
| `NetbirdProvider.Start` (up)                      | `bridge: netbird: up failed: `                                 |
| `NetbirdProvider.Start` (status)                  | `bridge: netbird: status failed: `                             |
| `NetbirdProvider.Start` (parse)                   | `bridge: netbird: failed to parse status JSON: `               |
| `NetbirdProvider.Stop` (down)                     | `bridge: netbird: down failed: `                               |
| `UserAccessManager.Setup` (provider)              | `bridge: user access: start provider: `                        |
| `UserAccessManager.Teardown` (provider)           | `bridge: user access: stop provider: `                         |

## Logging

All log entries use `component=bridge`.

| Level   | Event                              | Keys                              |
|---------|------------------------------------|-----------------------------------|
| `Info`  | Tailscale provider started         | `ip`, `interface`                 |
| `Info`  | Tailscale provider stopped         | (none)                            |
| `Error` | Tailscale down failed              | `error`                           |
| `Error` | Stop tailscaled failed             | `error`                           |
| `Info`  | Starting netbird provider          | `setup_key_len`                   |
| `Info`  | Netbird up completed               | `output`                          |
| `Info`  | Netbird provider started           | `ip`, `interface`                 |
| `Info`  | Stopping netbird provider          | (none)                            |
| `Info`  | Netbird down completed             | `output`                          |
| `Info`  | User access provider started       | `provider`                        |

## Lifecycle Without Provider

```go
cfg := bridge.Config{
    Enabled:           true,
    AccessInterface:   "eth1",
    AccessSubnets:     []string{"10.0.0.0/24"},
    UserAccessEnabled: true,
}
cfg.ApplyDefaults()

// No provider — pass nil
accessMgr := bridge.NewUserAccessManager(accessCtrl, routeCtrl, cfg, logger, nil)

// Setup — creates WG interface, enables forwarding (no provider step)
if err := accessMgr.Setup(); err != nil {
    log.Fatal(err)
}

// Report status in heartbeat — no provider fields populated
status := accessMgr.UserAccessStatus()
// &api.UserAccessInfo{Enabled: true, InterfaceName: "wg-access", PeerCount: 0, ListenPort: 51822}

// Graceful shutdown
<-ctx.Done()
if err := accessMgr.Teardown(); err != nil {
    logger.Warn("user access teardown failed", "error", err)
}
```

## Lifecycle With Provider

```go
cfg := bridge.Config{
    Enabled:                true,
    AccessInterface:        "eth1",
    AccessSubnets:          []string{"10.0.0.0/24"},
    UserAccessEnabled:      true,
    UserAccessProviderType: "tailscale",
}
cfg.ApplyDefaults()

// Create provider based on config
var provider bridge.UserAccessProvider
switch cfg.UserAccessProviderType {
case "tailscale":
    provider = bridge.NewTailscaleProvider(exec, logger)
case "netbird":
    provider = bridge.NewNetbirdProvider(exec, logger)
}

accessMgr := bridge.NewUserAccessManager(accessCtrl, routeCtrl, cfg, logger, provider)

// Setup — creates WG interface, enables forwarding, starts provider
if err := accessMgr.Setup(); err != nil {
    log.Fatal(err)
}

// Report status in heartbeat — includes provider fields
status := accessMgr.UserAccessStatus()
// &api.UserAccessInfo{
//     Enabled: true, InterfaceName: "wg-access", PeerCount: 0,
//     ListenPort: 51822, ProviderName: "tailscale", ProviderStatus: "running",
// }

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

// Graceful shutdown — stops provider first, then tears down WG interface
<-ctx.Done()
if err := accessMgr.Teardown(); err != nil {
    logger.Warn("user access teardown failed", "error", err)
}
```

## Heartbeat Reporting

```go
heartbeat := api.HeartbeatRequest{
    UserAccess: accessMgr.UserAccessStatus(), // includes ProviderName, ProviderStatus
}
```

## Registration Capabilities

```go
caps := accessMgr.UserAccessCapabilities()
// {"user_access": "true", "access_listen_port": "51822"}
// nil when user access is disabled
```
