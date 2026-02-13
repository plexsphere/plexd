---
title: Network Policy Enforcement
quadrant: backend
package: internal/policy
feature: PXD-0008
---

# Network Policy Enforcement

The `internal/policy` package enforces network policies on mesh nodes. It evaluates policies from the control plane to determine peer visibility (which peers a node can communicate with) and generates iptables firewall rules for packet-level enforcement.

The package integrates with `internal/reconcile` for periodic convergence and with `internal/api` for real-time SSE-driven policy updates.

## Data Flow

```
Control Plane
      │
      ▼
┌─────────────┐     ┌──────────────┐
│ StateResponse│────▶│ PolicyEngine │
│  .Policies   │     └──────┬───────┘
│  .Peers      │            │
└─────────────┘     ┌───────┴────────┐
                    │                │
                    ▼                ▼
            ┌────────────┐   ┌────────────────┐
            │ FilterPeers│   │BuildFirewallRules│
            └─────┬──────┘   └───────┬─────────┘
                  │                  │
                  ▼                  ▼
            ┌──────────┐     ┌──────────────────┐
            │ WireGuard│     │FirewallController │
            │ Manager  │     │  (iptables/nft)   │
            └──────────┘     └──────────────────┘
```

Policies flow from the control plane via `api.StateResponse`. The `PolicyEngine` evaluates them to produce two outputs: a filtered peer list (fed to `wireguard.Manager`) and firewall rules (applied via `FirewallController`). The `Enforcer` orchestrates both paths, and `ReconcileHandler` wires it into the reconciliation loop.

## Config

`Config` holds policy enforcement parameters.

| Field       | Type     | Default          | Description                              |
|-------------|----------|------------------|------------------------------------------|
| `Enabled`   | `bool`   | `true`           | Whether policy enforcement is active     |
| `ChainName` | `string` | `plexd-mesh`   | iptables chain name for firewall rules   |

```go
cfg := policy.Config{}
cfg.ApplyDefaults() // Enabled=true, ChainName="plexd-mesh"
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

### Default Heuristic

`ApplyDefaults` uses zero-value detection: on a fully zero-valued `Config`, `Enabled` is set to `true`. If `ChainName` is already set (indicating explicit construction), `Enabled` is left as-is. This allows `Config{Enabled: false}` to disable enforcement after `ApplyDefaults`.

### Validation Rules

| Field       | Rule                              | Error Message                                              |
|-------------|-----------------------------------|------------------------------------------------------------|
| `ChainName` | Must not be empty when `Enabled`  | `policy: config: ChainName must not be empty when enabled` |

Validation is skipped entirely when `Enabled` is `false`.

## FirewallRule

Describes a single iptables-style packet filter rule.

```go
type FirewallRule struct {
    Interface string // network interface name
    SrcIP     string // source IP (CIDR or single IP)
    DstIP     string // destination IP (CIDR or single IP)
    Port      int    // destination port (0 = any)
    Protocol  string // "tcp", "udp", or "" (any)
    Action    string // "allow" or "deny"
}
```

### Validation Rules

| Field      | Rule                                 | Error Message                                      |
|------------|--------------------------------------|----------------------------------------------------|
| `Action`   | Must be `"allow"` or `"deny"`        | `policy: firewall rule: invalid action "..."`      |
| `Port`     | Must be 0–65535                      | `policy: firewall rule: invalid port N`            |
| `Protocol` | Must be `""`, `"tcp"`, or `"udp"`    | `policy: firewall rule: invalid protocol "..."`    |
| `Port`     | Requires protocol if > 0            | `policy: firewall rule: port N requires a protocol`|

## FirewallController

Interface abstracting OS-level iptables operations. The production implementation is provided externally; this package defines and consumes the interface.

```go
type FirewallController interface {
    EnsureChain(chain string) error
    ApplyRules(chain string, rules []FirewallRule) error
    FlushChain(chain string) error
    DeleteChain(chain string) error
}
```

| Method        | Description                                              |
|---------------|----------------------------------------------------------|
| `EnsureChain` | Creates the named chain if it does not already exist     |
| `ApplyRules`  | Replaces all rules in the named chain atomically         |
| `FlushChain`  | Removes all rules from the named chain                   |
| `DeleteChain` | Deletes the named chain; idempotent on non-existent chain|

## PolicyEngine

Evaluates network policies to determine peer visibility and generate firewall rules.

### Constructor

```go
func NewPolicyEngine(logger *slog.Logger) *PolicyEngine
```

Logger is tagged with `component=policy`.

### FilterPeers

```go
func (e *PolicyEngine) FilterPeers(peers []api.Peer, policies []api.Policy, localNodeID string) []api.Peer
```

Returns the subset of peers the local node is allowed to communicate with.

| Scenario           | Behavior                                                    |
|--------------------|-------------------------------------------------------------|
| No policies        | No peers returned (deny-by-default)                         |
| Allow rules exist  | Only peers matching a bidirectional allow rule are returned  |
| Deny-only rules    | No peers returned (deny does not grant visibility)          |
| Wildcard `"*"`     | Matches any node ID in src or dst position                  |

**Bidirectional matching**: A peer is visible if any allow rule references both the local node and the peer in either `Src`/`Dst` direction. This means `{Src: "node-A", Dst: "node-B", Action: "allow"}` allows communication in both directions.

### BuildFirewallRules

```go
func (e *PolicyEngine) BuildFirewallRules(
    policies []api.Policy,
    localNodeID string,
    iface string,
    peersByID map[string]string,
) []FirewallRule
```

Converts `api.PolicyRule` entries into concrete `FirewallRule` entries for the local node.

- `peersByID` maps peer IDs to mesh IPs for address resolution
- Only rules where `Src` or `Dst` matches `localNodeID` (or `"*"`) are included
- Wildcard `"*"` resolves to `"0.0.0.0/0"` in the generated firewall rule
- Rules with invalid protocols (not `""`, `"tcp"`, or `"udp"`) are skipped with a warning log
- A default-deny rule dropping all traffic on the interface is appended as the last rule
- Rules referencing unknown peer IDs produce rules with empty IP fields

## Enforcer

Combines a `PolicyEngine` with a `FirewallController` to enforce policies on the local node.

### Constructor

```go
func NewEnforcer(
    engine *PolicyEngine,
    firewall FirewallController,
    cfg Config,
    logger *slog.Logger,
) *Enforcer
```

- Applies config defaults via `cfg.ApplyDefaults()`
- `firewall` may be `nil` — only peer filtering is functional in that case

### Methods

| Method              | Signature                                                                                  | Description                                             |
|---------------------|--------------------------------------------------------------------------------------------|---------------------------------------------------------|
| `FilterPeers`       | `(peers []api.Peer, policies []api.Policy, localNodeID string) []api.Peer`                | Filters peers; passthrough when disabled                |
| `ApplyFirewallRules` | `(policies []api.Policy, localNodeID string, iface string, peersByID map[string]string) error` | Builds and applies rules; no-op when disabled or nil firewall |
| `Teardown`          | `() error`                                                                                 | Flushes and deletes firewall chain; safe with nil firewall |

### Behavior by State

| `Enabled` | `firewall` | `FilterPeers`        | `ApplyFirewallRules` | `Teardown`  |
|-----------|------------|----------------------|----------------------|-------------|
| `true`    | non-nil    | Engine-filtered      | Rules applied        | Chain removed |
| `true`    | `nil`      | Engine-filtered      | No-op (warn logged)  | No-op       |
| `false`   | any        | All peers returned   | No-op                | No-op/chain removed |

### Error Prefixes

| Method              | Prefix              |
|---------------------|---------------------|
| `ApplyFirewallRules`| `policy: enforce: ` |
| `Teardown`          | `policy: teardown: `|

## ReconcileHandler

Factory function returning a `reconcile.ReconcileHandler` that enforces policies during reconciliation cycles.

```go
func ReconcileHandler(
    enforcer *Enforcer,
    wgMgr *wireguard.Manager,
    localNodeID, localMeshIP, iface string,
) reconcile.ReconcileHandler
```

The returned handler maintains an internal `allowedPeers` map (closure state) that tracks which peers are currently added to WireGuard, enabling incremental add/remove across cycles.

### Processing Order

1. **Skip check** — if `StateDiff` contains no policy or peer changes, return `nil`
2. **Filter peers** — evaluate policies via `Enforcer.FilterPeers`
3. **Apply firewall rules** — via `Enforcer.ApplyFirewallRules`
4. **Remove revoked peers** — peers in `allowedPeers` but not in the new filtered set are removed via `wgMgr.RemovePeerByID`
5. **Add new peers** — peers in the new filtered set but not in `allowedPeers` are added via `wgMgr.AddPeer`
6. **Update state** — `allowedPeers` is replaced with the new set

### Drift Detection

The handler checks `StateDiff` for any of:

| Field              | Triggers Handler |
|--------------------|-----------------|
| `PeersToAdd`       | Yes             |
| `PeersToRemove`    | Yes             |
| `PeersToUpdate`    | Yes             |
| `PoliciesToAdd`    | Yes             |
| `PoliciesToRemove` | Yes             |

If none of these fields are populated, the handler is a no-op.

### Error Handling

Individual failures (firewall apply, peer remove, peer add) are collected and returned as an aggregated error via `errors.Join`. This ensures the reconciler marks the cycle as failed and retries.

### Registration

```go
enforcer := policy.NewEnforcer(engine, fwCtrl, policy.Config{}, logger)
mgr := wireguard.NewManager(ctrl, wireguard.Config{}, logger)

r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(policy.ReconcileHandler(enforcer, mgr, nodeID, meshIP, "plexd0"))
```

## HandlePolicyUpdated

Factory function returning an `api.EventHandler` for real-time policy updates via SSE.

```go
func HandlePolicyUpdated(trigger ReconcileTrigger) api.EventHandler
```

When a `policy_updated` SSE event is received, the handler calls `trigger.TriggerReconcile()` to request an immediate reconciliation cycle. The event payload is not parsed — any policy update triggers a full reconcile.

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
dispatcher.Register(api.EventPolicyUpdated, policy.HandlePolicyUpdated(reconciler))
```

## Integration Points

### Reconciliation Loop

The policy reconcile handler plugs into `internal/reconcile` alongside the WireGuard handler. Both are invoked sequentially on each cycle:

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(wireguard.ReconcileHandler(mgr))
r.RegisterHandler(policy.ReconcileHandler(enforcer, mgr, nodeID, meshIP, "plexd0"))
```

### SSE Real-Time Updates

`HandlePolicyUpdated` triggers reconciliation when the control plane pushes a `policy_updated` event. The reconciliation cycle then fetches fresh state and re-evaluates all policies.

### WireGuard Manager

The policy handler uses `wireguard.Manager` to add and remove peers:

| Manager Method    | Used When                                |
|-------------------|------------------------------------------|
| `AddPeer`         | A peer becomes allowed by policy change  |
| `RemovePeerByID`  | A peer is revoked by policy change       |

### Control Plane Types

| Type             | Package        | Usage                              |
|------------------|----------------|------------------------------------|
| `api.Peer`       | `internal/api` | Peer identity and WireGuard config |
| `api.Policy`     | `internal/api` | Policy with ID and rules           |
| `api.PolicyRule` | `internal/api` | Src, Dst, Port, Protocol, Action   |
| `api.StateResponse` | `internal/api` | Desired state from control plane |
| `api.SignedEnvelope` | `internal/api` | SSE event wrapper                |
| `api.EventPolicyUpdated` | `internal/api` | Event type constant `"policy_updated"` |

### Graceful Shutdown

Call `Enforcer.Teardown()` to clean up firewall chains:

```go
<-ctx.Done()
if err := enforcer.Teardown(); err != nil {
    logger.Warn("policy teardown failed", "error", err)
}
```
