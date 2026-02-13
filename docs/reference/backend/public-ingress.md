---
title: Public Ingress
quadrant: backend
package: internal/bridge
feature: PXD-0014
---

# Public Ingress

The public ingress feature extends bridge mode (`internal/bridge`) to expose mesh-internal services to public internet traffic through the bridge node. The bridge node accepts TCP connections on configured public ports and proxies them to target mesh peers. TLS can be terminated at the bridge or passed through transparently.

## Data Flow

```
Public Internet Clients
(HTTP / HTTPS / TCP)
        |
        |  TCP connection
        v
+---------------------------------------------------------------+
|                        Bridge Node                              |
|                                                                 |
|  +-------------------+         +-------------------+           |
|  |  TCP Listeners    |  proxy  |  Mesh WireGuard   |           |
|  |  (per ingress     |-------->|  Interface        |           |
|  |   rule)           |         |  (plexd0)         |           |
|  |  :8080, :443, ... |         |                   |           |
|  +-------------------+         +---------+---------+           |
|         ^                                |                     |
|         |                                v                     |
|  +------+------------+            +------------------+           |
|  | IngressController |            |  Mesh Peers      |           |
|  | (TCP operations)  |            |  10.42.0.0/16    |           |
|  +---------+---------+            +------------------+           |
|            |                                                     |
|    TLS terminate:                                                |
|    tls.NewListener                                               |
|    TLS passthrough:                                              |
|    raw TCP forward                                               |
|                                                                 |
|  Control Plane --SSE--> HandleIngressRuleAssigned                |
|                --SSE--> HandleIngressRuleRevoked                  |
|                --SSE--> HandleIngressConfigUpdated                |
|                --Rec--> IngressReconcileHandler                   |
+-----------------------------------------------------------------+
```

Traffic from public internet clients arrives on per-rule TCP listeners, is proxied via bidirectional `io.Copy` relay to the target mesh peer address, and reaches mesh-internal services. For TLS terminate mode, the bridge decrypts TLS before forwarding plaintext. For passthrough mode, raw TCP bytes are forwarded without decryption.

## Config

Ingress fields extend the existing bridge `Config` struct. Ingress requires bridge mode to be enabled (`Enabled=true`).

| Field                | Type            | Default | Description                                      |
|----------------------|-----------------|---------|--------------------------------------------------|
| `IngressEnabled`     | `bool`          | `false` | Whether public ingress is active                 |
| `MaxIngressRules`    | `int`           | `20`    | Maximum number of concurrent ingress rules       |
| `IngressDialTimeout` | `time.Duration` | `10s`   | Timeout for dialing target mesh peers            |

```go
cfg := bridge.Config{
    Enabled:        true,
    AccessInterface: "eth1",
    AccessSubnets:  []string{"10.0.0.0/24"},
    IngressEnabled: true,
}
cfg.ApplyDefaults() // sets MaxIngressRules, IngressDialTimeout
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

### Defaults

`ApplyDefaults()` sets zero-valued ingress fields:

| Field                | Zero Value | Default Applied                                   |
|----------------------|------------|---------------------------------------------------|
| `MaxIngressRules`    | `0`        | `DefaultMaxIngressRules` (`20`)                   |
| `IngressDialTimeout` | `0`        | `DefaultIngressDialTimeout` (`10s`)               |

### Validation Rules

Ingress validation is skipped when `IngressEnabled` is `false`. When enabled:

| Field                | Rule                    | Error Message                                                               |
|----------------------|-------------------------|-----------------------------------------------------------------------------|
| `IngressEnabled`     | Requires `Enabled=true` | `bridge: config: ingress requires bridge mode to be enabled`                |
| `MaxIngressRules`    | Must be > 0             | `bridge: config: MaxIngressRules must be positive when ingress is enabled`  |
| `IngressDialTimeout` | Must be >= 1s           | `bridge: config: IngressDialTimeout must be at least 1s`                    |

## IngressController

Interface abstracting TCP listener operations for ingress testability. The production implementation is provided externally; this package defines and consumes the interface.

```go
type IngressController interface {
    Listen(addr string, tlsCfg *tls.Config) (net.Listener, error)
    Close(listener net.Listener) error
}
```

| Method   | Description                                                              |
|----------|--------------------------------------------------------------------------|
| `Listen` | Creates a TCP listener; wraps with `tls.NewListener` if `tlsCfg` is set |
| `Close`  | Closes the given listener; idempotent                                    |

## IngressManager

Central coordinator for public ingress lifecycle. Concurrent-safe via `sync.Mutex` — SSE event handlers and the reconcile loop may invoke methods concurrently. Active proxy connections are tracked via `atomic.Int64` for lock-free counting.

### Constructor

```go
func NewIngressManager(ctrl IngressController, cfg Config, logger *slog.Logger) *IngressManager
```

### Methods

| Method                 | Signature                            | Description                                                      |
|------------------------|--------------------------------------|------------------------------------------------------------------|
| `Setup`                | `() error`                           | Marks manager active; no-op when disabled                        |
| `Teardown`             | `() error`                           | Closes all listeners, cancels connections; aggregates errors     |
| `AddRule`              | `(rule api.IngressRule) error`       | Starts listener, spawns accept loop; rejects duplicates/max      |
| `RemoveRule`           | `(ruleID string)`                    | Stops listener, waits for goroutine exit; no-op if not found     |
| `RuleIDs`              | `() []string`                        | Returns IDs of all active rules                                  |
| `IngressStatus`        | `() *api.IngressInfo`                | Returns status for heartbeat; nil when inactive                  |
| `IngressCapabilities`  | `() map[string]string`               | Returns capability metadata for registration; nil when disabled  |

### Lifecycle

```go
mgr := bridge.NewIngressManager(ingressCtrl, cfg, logger)

// Setup — marks manager active
if err := mgr.Setup(); err != nil {
    log.Fatal(err)
}

// Add a rule (driven by SSE handler or reconciliation)
err := mgr.AddRule(api.IngressRule{
    RuleID:     "web-https",
    ListenPort: 443,
    TargetAddr: "10.42.0.5:8080",
    Mode:       "terminate",
    CertPEM:    certPEM,
    KeyPEM:     keyPEM,
})

// Remove a rule
mgr.RemoveRule("web-https")

// Report status in heartbeat
status := mgr.IngressStatus()

// Capabilities for registration
caps := mgr.IngressCapabilities()
// {"ingress": "true", "max_ingress_rules": "20"}

// Graceful shutdown
if err := mgr.Teardown(); err != nil {
    logger.Warn("teardown failed", "error", err)
}
```

### Setup

When `IngressEnabled` is `false`, `Setup` is a no-op. When enabled, it marks the manager as active and logs the configuration.

### Teardown

Teardown closes all active listeners and cancels proxy connections:

1. Cancel all accept loop contexts
2. Close all listeners via `IngressController.Close`
3. Release the mutex
4. Wait for all accept loop goroutines to exit (via `done` channels)

Errors are aggregated via `errors.Join` — cleanup continues even when individual operations fail. Calling `Teardown` when the manager is inactive is a no-op.

### AddRule

1. Rejects duplicate rule IDs (`rule already exists`)
2. Rejects if `MaxIngressRules` limit is reached (`max rules reached`)
3. For TLS terminate mode: parses `CertPEM`/`KeyPEM` via `tls.X509KeyPair`, builds `tls.Config` with `MinVersion: tls.VersionTLS12`
4. Calls `IngressController.Listen` to create the TCP listener
5. Spawns an `acceptLoop` goroutine with a cancellable context
6. Tracks the rule in the internal `activeRules` map

### RemoveRule

1. If the rule ID is not tracked, returns immediately (no-op)
2. Cancels the accept loop context
3. Closes the listener via `IngressController.Close`
4. Waits for the accept loop goroutine to exit (via `done` channel)

### TCP Proxy

Each accepted connection spawns a `proxyConnection` goroutine:

1. Increments the atomic connection counter
2. Dials the target address with `IngressDialTimeout`
3. Runs two `io.Copy` goroutines for bidirectional relay
4. On context cancellation or either copy finishing, closes both connections
5. Decrements the connection counter on exit

### TLS Modes

| Mode          | Behavior                                                                           |
|---------------|------------------------------------------------------------------------------------|
| `passthrough` | Raw TCP bytes forwarded without decryption; no certificates required               |
| `terminate`   | Bridge performs TLS handshake with `tls.Config`; plaintext forwarded to target     |

TLS terminate mode enforces minimum TLS 1.2 via `tls.Config.MinVersion`.

## SSE Event Handlers

### HandleIngressRuleAssigned

```go
func HandleIngressRuleAssigned(mgr *IngressManager, logger *slog.Logger) api.EventHandler
```

Handles `ingress_rule_assigned` events. Parses `api.IngressRule` from the envelope payload and calls `mgr.AddRule(rule)`.

- On parse error: logs and returns wrapped error
- On `AddRule` error: returns wrapped error

### HandleIngressRuleRevoked

```go
func HandleIngressRuleRevoked(mgr *IngressManager, logger *slog.Logger) api.EventHandler
```

Handles `ingress_rule_revoked` events. Parses `rule_id` from the envelope payload and calls `mgr.RemoveRule(ruleID)`.

- On parse error: logs and returns wrapped error
- `RemoveRule` is a no-op if the rule does not exist

### HandleIngressConfigUpdated

```go
func HandleIngressConfigUpdated(trigger ReconcileTrigger) api.EventHandler
```

Handles `ingress_config_updated` events. Calls `trigger.TriggerReconcile()` to request an immediate reconciliation cycle. The event payload is not parsed — any config update triggers a full reconcile.

### Registration

```go
dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventIngressRuleAssigned,
    bridge.HandleIngressRuleAssigned(ingressMgr, logger))
dispatcher.Register(api.EventIngressRuleRevoked,
    bridge.HandleIngressRuleRevoked(ingressMgr, logger))
dispatcher.Register(api.EventIngressConfigUpdated,
    bridge.HandleIngressConfigUpdated(reconciler))
```

## IngressReconcileHandler

```go
func IngressReconcileHandler(mgr *IngressManager, logger *slog.Logger) reconcile.ReconcileHandler
```

Returns a `reconcile.ReconcileHandler` that synchronizes ingress rules to match the desired `IngressConfig`:

1. If `desired.IngressConfig` is nil, returns nil (no-op)
2. Builds a desired set from `desired.IngressConfig.Rules` keyed by `RuleID`
3. Removes stale rules: current rule IDs not in the desired set
4. Adds missing rules: desired rules not in the current set
5. Aggregates `AddRule` errors via `errors.Join`

### Registration

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.ReconcileHandler(bridgeMgr))
r.RegisterHandler(bridge.RelayReconcileHandler(bridgeMgr.Relay(), logger))
r.RegisterHandler(bridge.UserAccessReconcileHandler(accessMgr, logger))
r.RegisterHandler(bridge.IngressReconcileHandler(ingressMgr, logger))
```

## API Types

### IngressConfig

Pushed from the control plane in `api.StateResponse.IngressConfig`.

```go
type IngressConfig struct {
    Enabled bool          `json:"enabled"`
    Rules   []IngressRule `json:"rules"`
}
```

### IngressRule

Represents a single public ingress rule.

```go
type IngressRule struct {
    RuleID     string `json:"rule_id"`
    ListenPort int    `json:"listen_port"`
    TargetAddr string `json:"target_addr"`
    Mode       string `json:"mode"`
    CertPEM    string `json:"cert_pem,omitempty"`
    KeyPEM     string `json:"key_pem,omitempty"`
}
```

| Field        | Description                                                              |
|--------------|--------------------------------------------------------------------------|
| `RuleID`     | Unique identifier for the rule                                          |
| `ListenPort` | Public TCP port to listen on                                            |
| `TargetAddr` | Mesh peer address to proxy traffic to (host:port)                       |
| `Mode`       | TLS mode: `passthrough` (raw TCP) or `terminate` (TLS at bridge)        |
| `CertPEM`    | PEM-encoded certificate for terminate mode (optional for passthrough)   |
| `KeyPEM`     | PEM-encoded private key for terminate mode (optional for passthrough)   |

### IngressInfo

Reported in heartbeats via `api.HeartbeatRequest.Ingress`.

```go
type IngressInfo struct {
    Enabled         bool `json:"enabled"`
    RuleCount       int  `json:"rule_count"`
    ConnectionCount int  `json:"connection_count"`
}
```

### SSE Event Constants

| Constant                           | Value                          |
|------------------------------------|--------------------------------|
| `api.EventIngressConfigUpdated`    | `"ingress_config_updated"`     |
| `api.EventIngressRuleAssigned`     | `"ingress_rule_assigned"`      |
| `api.EventIngressRuleRevoked`      | `"ingress_rule_revoked"`       |

## Error Prefixes

| Source                             | Prefix                                              |
|------------------------------------|------------------------------------------------------|
| `IngressManager.AddRule` (dup)     | `bridge: ingress: rule already exists: `             |
| `IngressManager.AddRule` (max)     | `bridge: ingress: max rules reached (`               |
| `IngressManager.AddRule` (TLS)     | `bridge: ingress: rule <id>: load TLS certificate: ` |
| `IngressManager.AddRule` (listen)  | `bridge: ingress: rule <id>: listen on <addr>: `     |
| `IngressManager.Teardown` (close)  | `bridge: ingress: close rule <id>: `                 |
| `HandleIngressRuleAssigned`        | `bridge: ingress_rule_assigned: `                    |
| `HandleIngressRuleRevoked`         | `bridge: ingress_rule_revoked: `                     |

## Logging

All ingress log entries use `component=bridge`.

| Level   | Event                          | Keys                                        |
|---------|--------------------------------|---------------------------------------------|
| `Info`  | Ingress manager started        | `max_rules`, `dial_timeout`                 |
| `Info`  | Ingress manager stopped        | (none)                                      |
| `Info`  | Ingress rule added             | `rule_id`, `listen_port`, `target`, `mode`  |
| `Info`  | Ingress rule removed           | `rule_id`                                   |
| `Error` | Dial target failed             | `rule_id`, `target`, `error`                |
| `Error` | Close rule failed              | `rule_id`, `error`                          |
| `Error` | SSE parse payload failed       | `event_id`, `error`                         |
| `Error` | Reconcile: add rule failed     | `rule_id`, `error`                          |

## Integration Points

### Reconciliation Loop

The ingress reconcile handler plugs into `internal/reconcile` alongside existing handlers:

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(wireguard.ReconcileHandler(wgMgr))
r.RegisterHandler(policy.ReconcileHandler(enforcer, wgMgr, nodeID, meshIP, "plexd0"))
r.RegisterHandler(bridge.ReconcileHandler(bridgeMgr))
r.RegisterHandler(bridge.RelayReconcileHandler(bridgeMgr.Relay(), logger))
r.RegisterHandler(bridge.UserAccessReconcileHandler(accessMgr, logger))
r.RegisterHandler(bridge.IngressReconcileHandler(ingressMgr, logger))
```

### SSE Real-Time Updates

Rule-level events (`rule_assigned`/`rule_revoked`) enable immediate response to individual rule changes. The `config_updated` event triggers a full reconcile for bulk changes.

### Control Plane Types

| Type                                 | Package        | Usage                                         |
|--------------------------------------|----------------|-----------------------------------------------|
| `api.IngressConfig`                  | `internal/api` | Desired ingress config from control plane     |
| `api.IngressRule`                    | `internal/api` | Individual ingress rule definition            |
| `api.IngressInfo`                    | `internal/api` | Ingress status in heartbeats                  |
| `api.StateResponse`                  | `internal/api` | Desired state (contains `IngressConfig`)      |
| `api.HeartbeatRequest`               | `internal/api` | Heartbeat payload (contains `IngressInfo`)    |
| `api.SignedEnvelope`                 | `internal/api` | SSE event wrapper                             |
| `api.EventIngressConfigUpdated`      | `internal/api` | Event type `"ingress_config_updated"`         |
| `api.EventIngressRuleAssigned`       | `internal/api` | Event type `"ingress_rule_assigned"`          |
| `api.EventIngressRuleRevoked`        | `internal/api` | Event type `"ingress_rule_revoked"`           |

### Heartbeat Reporting

```go
heartbeat := api.HeartbeatRequest{
    Ingress: ingressMgr.IngressStatus(), // nil when inactive
}
```

### Registration Capabilities

```go
caps := ingressMgr.IngressCapabilities()
// {"ingress": "true", "max_ingress_rules": "20"}
// nil when ingress is disabled
```

### Graceful Shutdown

```go
<-ctx.Done()
if err := ingressMgr.Teardown(); err != nil {
    logger.Warn("ingress teardown failed", "error", err)
}
```

## Full Lifecycle

```go
cfg := bridge.Config{
    Enabled:        true,
    AccessInterface: "eth1",
    AccessSubnets:  []string{"10.0.0.0/24"},
    IngressEnabled: true,
}
cfg.ApplyDefaults()

ingressMgr := bridge.NewIngressManager(ingressCtrl, cfg, logger)

// Setup ingress manager
ingressMgr.Setup()

// Register SSE handlers
dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventIngressRuleAssigned,
    bridge.HandleIngressRuleAssigned(ingressMgr, logger))
dispatcher.Register(api.EventIngressRuleRevoked,
    bridge.HandleIngressRuleRevoked(ingressMgr, logger))
dispatcher.Register(api.EventIngressConfigUpdated,
    bridge.HandleIngressConfigUpdated(reconciler))

// Register reconcile handler
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.IngressReconcileHandler(ingressMgr, logger))

// Run reconciler
go r.Run(ctx, nodeID)

// Graceful shutdown
<-ctx.Done()
ingressMgr.Teardown()
```
