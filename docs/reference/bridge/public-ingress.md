---
title: Public Ingress
package: internal/bridge
feature: PXD-0014
---

# Public Ingress

Public ingress lets a bridge node publish services that run on nodes of its Domain. A client outside the mesh connects to a public TCP port of the bridge, and the bridge forwards the connection over the mesh to a port on the target node. Each published service is a rule of the `bridge.ingress` block of the bridge's state pull, which an operator authors on the bridge Resource in the control plane.

The bridge opens one TCP listener per distinct listen port. A port with a rule that names no `sni_host` forwards every connection without reading it. On a port whose rules name hosts, the bridge reads the server name of each connection's TLS ClientHello and routes by it, so several HTTPS services share port 443.

## Data Flow

```
Public Internet Clients
        |
        |  TCP to <bridge>:<listen_port>
        v
+------------------------------------------------------------------+
|                          Bridge Node                             |
|                                                                  |
|  one listener per listen port                                    |
|  +-------------------+     plain port: forward without reading   |
|  | :2222  (plain)    |-------------------------------+           |
|  +-------------------+                               |           |
|  +-------------------+     SNI port: peek the        v           |
|  | :443   (SNI)      |---> ClientHello, match --> dial target    |
|  +-------------------+     the server name        over plexd0    |
|           ^                                          |           |
|           | ingressTable per port, swapped in place  |           |
|  IngressReconcileHandler --> IngressManager.Apply    |           |
+------------------------------------------------------|-----------+
                                                       v
                                         Target node <target_address>:<target_port>
```

The control plane delivers the block in the state pull and announces a change with a `bridge_config_updated` event, which only triggers a pull (see [SSE event handling](#sse-event-handling)). `IngressReconcileHandler` hands the block to `IngressManager.Apply`, which plans the rules, opens and closes listeners, and swaps each port's routing table.

The bridge's dial to a target is traffic the bridge itself sends over the mesh, which its compiled policy governs (see [What the rules govern](../networking/pf-wfp-firewall.md#what-the-rules-govern)). A rule grants no allow of its own: the policy needs a rule that allows TCP from the bridge's mesh IP to the target's address and port. A Project's allow-all policy covers every mesh address. Without such a rule the dial fails, and the bridge logs `bridge: ingress: dial target failed`.

## The bridge.ingress Block

The block is the control plane's `NodeStateBridgeIngress`, and each rule a `NodeStateBridgeIngressRule`. The agent contract's `## Public ingress` section in plexsphere's `docs/reference/api/plexd-agent-contract.md` defines it. The pull lists the rules by `slug` ascending:

```json
"bridge": {
  "ingress": {
    "rules": [
      {
        "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f2",
        "slug": "apps",
        "listen_port": 443,
        "mode": "passthrough",
        "sni_host": "*.apps.example.com",
        "target_node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2",
        "target_address": "10.42.0.8",
        "target_port": 443
      },
      {
        "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f4",
        "slug": "ssh",
        "listen_port": 2222,
        "mode": "passthrough",
        "target_node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2",
        "target_address": "10.42.0.8",
        "target_port": 22
      }
    ]
  }
}
```

| Field | Type | Description |
|---|---|---|
| `id` | string | The rule's id. The bridge tells rules apart by it |
| `slug` | string | The rule's name within the bridge Resource; logs and listener conflicts name it |
| `listen_port` | int | The public TCP port, 1 to 65535, on all of the node's addresses |
| `mode` | string | `passthrough`, `terminate` or `acme` (see [Modes](#modes)) |
| `sni_host` | string, optional | The server name the rule matches, in lowercase: an exact name, or `*.` and a suffix for one label in place of the `*`. A rule without it is the only rule on its port |
| `target_node_id` | string | The target node. It is not dialed |
| `target_address` | string | The target node's mesh address, IPv4 or IPv6, without brackets |
| `target_port` | int | The port the bridge dials on the target, 1 to 65535 |

The block is whole: a rule missing from a later pull is removed, and a port no rule names any more is closed. An `ingress` child that is absent or `null` closes every public listener. An `ingress` child with an empty or `null` rule list does the same.

## Activation

The bridge serves the block only in bridge mode with the local `bridge.ingress_enabled: true` (default `false`); `cmd/plexd/cmd/up.go` builds the ingress manager only then. Without it, the block is ignored. The block carries no `enabled` member.

| Field                | Type            | Default | Description                                      |
|----------------------|-----------------|---------|--------------------------------------------------|
| `IngressEnabled`     | `bool`          | `false` | `bridge.ingress_enabled`: the local switch for public ingress |
| `MaxIngressRules`    | `int`           | `20`    | `bridge.max_ingress_rules`: the most rules the bridge holds |
| `IngressDialTimeout` | `time.Duration` | `10s`   | `bridge.ingress_dial_timeout`: the timeout for dialing a target |

Ingress validation is skipped when `IngressEnabled` is `false`. When enabled:

| Field                | Rule                    | Error Message                                                               |
|----------------------|-------------------------|-----------------------------------------------------------------------------|
| `IngressEnabled`     | Requires `Enabled=true` | `bridge: config: ingress requires bridge mode to be enabled`                |
| `MaxIngressRules`    | Must be > 0             | `bridge: config: MaxIngressRules must be positive when ingress is enabled`  |
| `IngressDialTimeout` | Must be >= 1s           | `bridge: config: IngressDialTimeout must be at least 1s`                    |

## Modes

| Mode | Behavior |
|---|---|
| `passthrough` | Served. The bridge forwards the bytes unchanged, the TLS handshake included, so the target ends TLS |
| `terminate` | Held and not served |
| `acme` | Held and not served |

`terminate` and `acme` end TLS at the bridge, and the block does not name yet where their certificate comes from, so the bridge serves neither mode. A `terminate` or `acme` rule is held: it keeps its `(listen_port, sni_host)` slot, so no other rule takes its host, not even a wildcard `passthrough` rule that covers it, and a connection for its host is closed. Its state reads `mode_not_served`. The local ACME settings (`bridge.acme_*`, see [ACME & SNI Routing](acme-sni.md)) serve no rule.

## The Listener Plan

`planIngress` walks the rules in the order the pull lists them and gives each the first reason that applies:

| Order | Check | Reason | Detail |
| --- | --- | --- | --- |
| 1 | `id` is empty | `invalid_rule` | `id` |
| 2 | an earlier rule has the same `id` | `duplicate_id` | |
| 3 | `mode` is none of the three modes | `invalid_rule` | `mode` |
| 4 | `listen_port` outside 1 to 65535 | `invalid_rule` | `listen_port` |
| 5 | `sni_host`, lowercased: longer than 253 bytes, an empty label, or a `*` anywhere but as the whole first label of at least two; or empty on `terminate` or `acme` | `invalid_rule` | `sni_host` |
| 6 | `target_address` is not an IP address, or carries a port, brackets or a zone | `invalid_rule` | `target_address` |
| 7 | `target_port` outside 1 to 65535 | `invalid_rule` | `target_port` |
| 8 | a held rule has the same port and the same host, or one of the two has no host | `listener_conflict` | slug of the holder |
| 9 | `max_ingress_rules` rules are held already | `max_rules` | |
| 10 | held; `mode` is `terminate` or `acme` | `mode_not_served` | |

A rule that passes check 9 is held. A held `passthrough` rule is served once its port is bound. When the bind fails, the port's rules read `listen_failed`. Only a port with a held `passthrough` rule gets a listener.

The control plane refuses a rule set a bridge could not serve: a second rule on a listener another rule holds answers `409 bridge_port_conflict`, and a `terminate` or `acme` rule without `sni_host` answers `400 ingress_rule_invalid`. A rule the bridge skips is therefore a defect report, not a routine path. The bridge serves the rest of the block and logs `ingress rule not served` for the rule.

`target_address` is checked for syntax only. The pull is the node's authenticated configuration, and the control plane resolves the address from the target node.

The reasons are the exported constants `IngressReasonInvalid`, `IngressReasonDuplicateID`, `IngressReasonListenerConflict`, `IngressReasonMaxRules`, `IngressReasonModeNotServed` and `IngressReasonListenFailed`.

## Routing a Connection

The accept loop of a port loads the port's routing table for each connection:

- **A plain port.** The rule without `sni_host` takes every connection. The bridge reads nothing and dials the target, so a protocol whose server speaks first, such as SSH or SMTP, works as well as TLS.
- **An SNI port.** `peekClientHello` reads the TLS ClientHello without answering it: `crypto/tls` parses it, so a hello that spans several reads or records, or that orders the server name behind a large key share, is read in full. The peek reads at most 16 KiB and waits at most 5 s. The server name is then compared with the rules' hosts case-insensitively. An exact host wins over a wildcard, and `*.example.com` matches exactly one label in place of the `*`: it matches `a.example.com` and neither `example.com` nor `a.b.example.com`. The bridge dials the matching rule's target and replays the bytes it peeked to it first.

A connection that matches no served rule is closed without a byte from any target and logged at Debug, with one of these reasons:

| Reason | Cause |
|---|---|
| `no_client_hello` | The client sent no ClientHello within 5 s or 16 KiB, closed the connection, or sent bytes that are not TLS |
| `no_server_name` | The ClientHello carries no server name |
| `no_matching_rule` | No rule's host matches the server name |
| `rule_not_served` | The matching rule is a held `terminate` or `acme` rule |

The level is Debug because a public port draws scanners: a line per connection at Warn would let any client fill the log and the log forwarder.

The bridge dials `target_address:target_port` with `ingress_dial_timeout` and copies both ways until one side ends or the rule is removed or changed. A failed dial closes the client connection and logs `bridge: ingress: dial target failed`.

## Applying the Block

`Apply` makes the manager serve exactly the rules it is given:

1. It returns `bridge: ingress: manager is not active` before `Setup` or after `Teardown`.
2. It plans the rules.
3. A route whose rule is unchanged keeps its context and its established connections. Every other planned route gets a new context. Every route of the last `Apply` that is not carried over is cancelled, which closes its connections. Other rules on the port keep theirs.
4. For a port in the plan without a listener, it calls `IngressController.Listen(":<port>", nil)`. On an error it marks the port's rules `listen_failed`, goes on with the other ports, and adds `bridge: ingress: listen on :<port>: <error>` to the result.
5. For a port with a listener, it stores the new routing table. The listener is not rebound, also when the port changes between a plain rule and SNI rules.
6. It closes the listener of a port that left the plan and waits for its accept loop.
7. It returns the listen errors joined, or nil.

`Apply` is idempotent: a second call with the same rules binds nothing and cancels nothing, and logs nothing again. A failed bind fails the reconcile cycle, so the reconciler keeps its snapshot, and the next pull tries the bind again.

## Ports Below 1024

A listen port below 1024, such as 443 or 80, needs `CAP_NET_BIND_SERVICE`. The systemd unit `plexd install` writes and `deploy/systemd/plexd.service` grant it (see [Bare-Metal Packaging](../deployment/bare-metal-packaging.md)). When the bind fails with a permission error on such a port, `bridge: ingress: listen failed` carries `hint="ports below 1024 need CAP_NET_BIND_SERVICE"`.

A unit an earlier release wrote keeps `CAP_NET_ADMIN CAP_NET_RAW` until `plexd install` writes it again. Until then, this drop-in adds the capability, because systemd merges repeated capability lines:

```ini
# /etc/systemd/system/plexd.service.d/bind-service.conf
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

Run `systemctl daemon-reload` and `systemctl restart plexd` after adding it. A host firewall plexd does not manage must open the listen ports too.

## IngressController

Interface abstracting TCP listener operations for ingress testability.

```go
type IngressController interface {
    Listen(addr string, tlsCfg *tls.Config) (net.Listener, error)
    Close(listener net.Listener) error
}
```

| Method   | Description |
|----------|-------------|
| `Listen` | Creates a TCP listener on `addr`. The manager always passes a nil `tlsCfg` |
| `Close`  | Closes the given listener; idempotent |

`StdIngressController` implements it with `net.Listen`.

## IngressManager

```go
func NewIngressManager(ctrl IngressController, cfg Config, logger *slog.Logger, acme *ACMEManager) *IngressManager
```

Concurrent-safe via `sync.Mutex`. The connection counter is an `atomic.Int64`.

| Method                | Signature                                 | Description |
|-----------------------|-------------------------------------------|-------------|
| `Setup`               | `() error`                                | Marks the manager active; a no-op when `IngressEnabled` is `false` |
| `Apply`               | `(rules []api.IngressRule) error`         | Serves exactly these rules (see [Applying the Block](#applying-the-block)) |
| `RuleStates`          | `() []IngressRuleState`                   | The outcome of the last `Apply`, one entry per rule, in block order |
| `Teardown`            | `() error`                                | Cancels every route, which closes every connection, and closes every listener; joins close errors; a no-op when inactive |
| `IngressStatus`       | `() *api.IngressInfo`                     | The `status.ingress` report entry; nil when inactive |
| `IngressCapabilities` | `() map[string]string`                    | `{"ingress": "true", "max_ingress_rules": "<n>"}`; nil when disabled |

```go
type IngressRuleState struct {
    Rule   api.IngressRule
    Served bool
    Reason string // empty when served
    Detail string // the field of an invalid rule, or the slug of the rule that holds the listener
}
```

`IngressStatus().RuleCount` counts the served rules, and `ConnectionCount` the connections from accept to close.

## IngressReconcileHandler

```go
func IngressReconcileHandler(mgr *IngressManager, logger *slog.Logger) reconcile.ReconcileHandler
```

The handler returns nil for a nil snapshot. Otherwise it takes the rules of `desired.Bridge.Ingress`, none when `Bridge` or `Ingress` is nil, calls `mgr.Apply`, and on an error logs `ingress reconcile: apply failed` and returns it. `cmd/plexd/cmd/up.go` registers it when the ingress manager exists.

## SSE Event Handling

There are no ingress-specific SSE handlers. The control plane emits a single `bridge_config_updated` event with an opaque payload; `bridge.HandleBridgeConfigUpdated` dispatches it to `TriggerReconcile()`, and `IngressReconcileHandler` applies the block from the authoritative state snapshot.

## API Types

### IngressConfig

`api.BridgeSnapshot.Ingress`, present-but-nullable.

```go
type IngressConfig struct {
    Rules []IngressRule `json:"rules"`
}
```

### IngressRule

```go
type IngressRule struct {
    ID            string `json:"id"`
    Slug          string `json:"slug"`
    ListenPort    int    `json:"listen_port"`
    Mode          string `json:"mode"`
    SNIHost       string `json:"sni_host,omitempty"`
    TargetNodeID  string `json:"target_node_id"`
    TargetAddress string `json:"target_address"`
    TargetPort    int    `json:"target_port"`
}

const (
    IngressModePassthrough = "passthrough"
    IngressModeTerminate   = "terminate"
    IngressModeACME        = "acme"
)
```

`IngressRule` is comparable with `==`, which is how `Apply` tells an unchanged rule from a changed one.

### IngressInfo

Published as the `status.ingress` report entry.

```go
type IngressInfo struct {
    Enabled         bool `json:"enabled"`
    RuleCount       int  `json:"rule_count"`
    ConnectionCount int  `json:"connection_count"`
    ACMEEnabled     bool `json:"acme_enabled"`
}
```

## Error Prefixes

| Source                            | Prefix                                         |
|-----------------------------------|------------------------------------------------|
| `IngressManager.Apply` (inactive) | `bridge: ingress: manager is not active`       |
| `IngressManager.Apply` (listen)   | `bridge: ingress: listen on :<port>: `         |
| `IngressManager.Teardown` (close) | `bridge: ingress: close listener <port>: `     |

## Logging

All ingress log entries use `component=bridge`.

| Level   | Message                                  | Keys |
|---------|------------------------------------------|------|
| `Info`  | `ingress manager started`                | `max_rules`, `dial_timeout` |
| `Info`  | `ingress manager stopped`                | (none) |
| `Info`  | `ingress listener opened`                | `listen_port` |
| `Info`  | `ingress listener closed`                | `listen_port` |
| `Info`  | `ingress rule added`                     | `rule_id`, `slug`, `listen_port`, `mode`, `sni_host`, `target` |
| `Info`  | `ingress rule updated`                   | the same; an id held before with another value |
| `Info`  | `ingress rule removed`                   | the same |
| `Warn`  | `ingress rule not served`                | `rule_id`, `slug`, `listen_port`, `reason`, `detail`; once per rule value and reason |
| `Debug` | `ingress connection closed`              | `listen_port`, `remote`, `server_name`, `reason` |
| `Error` | `bridge: ingress: listen failed`         | `listen_port`, `error`, and `hint` for a permission error below port 1024 |
| `Error` | `bridge: ingress: close listener failed` | `listen_port`, `error` |
| `Error` | `bridge: ingress: dial target failed`    | `rule_id`, `slug`, `target`, `error` |
| `Error` | `ingress reconcile: apply failed`        | `error` |

A rule logs `ingress rule not served` once: an `Apply` that leaves its value and reason unchanged logs nothing for it.

## Limits

The bridge sets no connection limit and no idle timeout on a public listener. It bounds only the ClientHello peek, to 16 KiB and 5 s per connection.
