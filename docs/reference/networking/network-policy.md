---
title: Network Policy Enforcement
package: internal/policy
feature: PXD-0008
---

# Network Policy Enforcement

The `internal/policy` package enforces network policies on mesh nodes. It translates the control plane's merged policy — a single `{revision_id, fingerprint, rules[]}` block on the `NodeStateSnapshot` envelope — into concrete nftables firewall rules for packet-level enforcement.

The package integrates with `internal/reconcile` for periodic convergence and with `internal/api` for real-time SSE-driven policy updates.

> **Peer membership is not a policy concern.** WireGuard peer visibility comes solely from the snapshot `peers` block, applied by `wireguard.ReconcileHandler`. The policy package no longer filters peers: node-ID rule matching and `FilterPeers` have been removed, and policy rules are CIDR-scoped rather than node-ID-scoped.

## Data Flow

```
Control Plane
      │
      ▼
┌──────────────────┐     ┌──────────────┐
│ NodeStateSnapshot│────▶│ PolicyEngine │
│  .Policy         │     └──────┬───────┘
│  (merged block)  │            │
└──────────────────┘            ▼
                        ┌──────────────────┐
                        │BuildFirewallRules│
                        └───────┬──────────┘
                                ▼
                        ┌──────────────────┐
                        │FirewallController │
                        │      (nft)        │
                        └──────────────────┘
```

The merged policy flows from the control plane via `NodeStateSnapshot.Policy`. The `PolicyEngine` converts its five-tuple rules into `FirewallRule` entries, and the `Enforcer` applies them via the `FirewallController`. `ReconcileHandler` wires it into the reconciliation loop, rebuilding the ruleset only when the policy fingerprint changes.

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
    PortTo    int    // inclusive end of a destination port range, 0 means single-Port match
    Protocol  string // "tcp", "udp", "icmp", or "" (any)
    Action    string // "allow" or "deny"
}
```

`PortTo` carries the inclusive end of a destination port range, mapping to an nftables range match; `0` means a single-port match on `Port`.

### Validation Rules

| Field      | Rule                                          | Error Message                                                    |
|------------|-----------------------------------------------|------------------------------------------------------------------|
| `Action`   | Must be `"allow"` or `"deny"`                 | `policy: firewall rule: invalid action "..."`                    |
| `Port`     | Must be 0–65535                               | `policy: firewall rule: invalid port N`                          |
| `Protocol` | Must be `""`, `"tcp"`, `"udp"`, or `"icmp"`   | `policy: firewall rule: invalid protocol "..."`                  |
| `Port`     | Requires `tcp`/`udp` if > 0                   | `policy: firewall rule: port N requires protocol tcp or udp`     |
| `PortTo`   | Requires a start port and `Port ≤ PortTo ≤ 65535` | `policy: firewall rule: port range end N requires a start port` / `... invalid port range end N` |

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

Translates the merged policy's rules into concrete firewall rules for the local node.

### Constructor

```go
func NewPolicyEngine(logger *slog.Logger) *PolicyEngine
```

Logger is tagged with `component=policy`.

### BuildFirewallRules

```go
func (e *PolicyEngine) BuildFirewallRules(rules []api.PolicyRule, iface string) []FirewallRule
```

Converts the merged policy's five-tuple `api.PolicyRule` entries into concrete `FirewallRule` entries for the local node. Each `PolicyRule` carries `{action, protocol, source_cidr, destination_cidr, ports?}`; the CIDR fields map directly to `SrcIP`/`DstIP`, and the `{from, to}` port range maps to `Port`/`PortTo` (a single port when `from == to`).

- **Action** — `allow` and `deny` are kept. A `log` action is observational only: nftables has no log verdict and skipping it cannot change the accept/drop outcome, so `log` rules are **skipped with a warning**. Unknown actions are also skipped.
- **Protocol** — `tcp`, `udp`, and `icmp` are kept; `any` maps to `""` (match all); unknown protocols are skipped with a warning.
- **Ports** — valid only for `tcp`/`udp`. A rule that sets `ports` on a portless protocol (`icmp`/`any`) violates the contract and is skipped with a warning.
- A default-deny rule dropping all traffic on the interface is always appended as the last rule — including when `rules` is empty or `nil` — giving a deny-by-default posture.

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
- `firewall` may be `nil` — `ApplyFirewallRules` is a no-op in that case

### Methods

| Method              | Signature                                                     | Description                                                        |
|---------------------|---------------------------------------------------------------|-------------------------------------------------------------------|
| `ApplyFirewallRules` | `(policy *api.PolicySnapshot, iface string) (bool, error)`   | Builds and applies rules; no-op when disabled or nil firewall. A `nil` policy yields the default-deny-only ruleset. The `bool` reports whether the ruleset actually reached the kernel |
| `Teardown`          | `() error`                                                    | Flushes and deletes firewall chain; safe with nil firewall        |

The `bool` exists so callers cannot log an enforcement that never happened: both no-op paths return `(false, nil)`, which is indistinguishable from a successful apply on the error value alone.

### Behavior by State

| `Enabled` | `firewall` | `ApplyFirewallRules` | `Teardown`          |
|-----------|------------|----------------------|---------------------|
| `true`    | non-nil    | Rules applied, `(true, nil)`  | Chain removed       |
| `true`    | `nil`      | No-op, `(false, nil)`         | No-op               |
| `false`   | any        | No-op, `(false, nil)`         | No-op/chain removed |

### Error Prefixes

| Method              | Prefix              |
|---------------------|---------------------|
| `ApplyFirewallRules`| `policy: enforce: ` |
| `Teardown`          | `policy: teardown: `|

A ruleset the engine refuses to translate is additionally wrapped in the sentinel `ErrInvalidRuleset`, so callers can distinguish a permanently broken revision (`errors.Is(err, policy.ErrInvalidRuleset)`) from a transient netlink failure. The backend is never touched in that case — the previously installed chain stays in place.

## ReconcileHandler

Factory function returning a `reconcile.ReconcileHandler` that rebuilds the firewall ruleset during reconciliation cycles.

```go
func ReconcileHandler(enforcer *Enforcer, iface string) reconcile.ReconcileHandler
```

The handler does not touch WireGuard peers — peer membership is owned by `wireguard.ReconcileHandler`. It only rebuilds nftables rules from the merged policy.

### Processing Order

1. **Skip check** — if `!diff.PolicyChanged`, return `nil`
2. **Fingerprint check** — a populated policy block with an empty `fingerprint` logs a warning: the differ treats it as always-changed, so the ruleset is rebuilt every cycle
3. **Apply firewall rules** — call `Enforcer.ApplyFirewallRules(desired.Policy, iface)`
4. **Log** — emit `"policy ruleset applied"` with `revision_id`, `fingerprint`, and rule count, but **only** when the enforcer reports the ruleset reached the kernel. A disabled config or a missing firewall backend logs at debug level instead, so the applied-log never claims an enforcement that did not happen

### Fingerprint Short-Circuit

`diff.PolicyChanged` is set by the differ, which compares the policy `Fingerprint` byte-for-byte and **never re-derives it from the rules**. A revision-only bump (same fingerprint) leaves `PolicyChanged` false, so this handler — and its `"policy ruleset applied"` log — does not fire and the ruleset is not rebuilt. Only a genuine fingerprint change reapplies rules.

### Error Handling

Transient `ApplyFirewallRules` failures (netlink, chain creation) propagate so the reconciler holds the snapshot back and retries the ruleset next cycle.

`ErrInvalidRuleset` does **not** propagate. Rules the engine cannot translate are a permanent property of the revision, so returning the error would hold the snapshot back and re-run every handler at the reconcile interval forever, with no chance of the same rules parsing on a later attempt. The handler logs `"policy revision rejected, keeping previous ruleset"` at error level and returns `nil` so the rest of the snapshot converges. The firewall keeps the last successfully applied ruleset, which is fail-closed; the rejected revision is retried only when the control plane publishes a new fingerprint.

### Registration

```go
enforcer := policy.NewEnforcer(engine, fwCtrl, policy.Config{}, logger)

r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(policy.ReconcileHandler(enforcer, "plexd0"))
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

## Enforcement Behavior

> **Note:** The policy enforcement model is under active development. The behavior described here reflects the current design and may change in future versions.

- Policy changes are signalled by the control plane via the `policy_updated` SSE event, which triggers a reconcile; the merged policy itself is pulled in the `NodeStateSnapshot` envelope.
- Filtering operates at **L3/L4** (CIDR, port, protocol) on the `plexd0` mesh interface using **nftables** rules.
- The default stance is **deny-all**: the ruleset always ends with a default-deny rule, and a `null` policy applies the default-deny-only ruleset.
- Peer membership is **not** governed by policy — it comes from the snapshot `peers` block via `wireguard.ReconcileHandler`. Policy rules are CIDR-scoped five-tuples, not node-ID references.
- On a genuine policy change (fingerprint mismatch), plexd rebuilds the nftables ruleset from the merged policy. Revision-only bumps short-circuit and leave the ruleset untouched.

## Integration Points

### Reconciliation Loop

The policy reconcile handler plugs into `internal/reconcile` alongside the WireGuard handler. Both are invoked sequentially on each cycle:

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(wireguard.ReconcileHandler(mgr))
r.RegisterHandler(policy.ReconcileHandler(enforcer, "plexd0"))
```

### SSE Real-Time Updates

`HandlePolicyUpdated` triggers reconciliation when the control plane pushes a `policy_updated` event. The reconciliation cycle then pulls a fresh snapshot and re-applies the merged policy if its fingerprint changed.

### Control Plane Types

| Type             | Package        | Usage                                                     |
|------------------|----------------|-----------------------------------------------------------|
| `api.PolicySnapshot` | `internal/api` | Merged policy block `{revision_id, fingerprint, rules[]}` |
| `api.PolicyRule` | `internal/api` | Five-tuple: `action`, `protocol`, `source_cidr`, `destination_cidr`, `ports?` |
| `api.PortRange`  | `internal/api` | Inclusive destination port range `{from, to}`             |
| `api.NodeStateSnapshot` | `internal/api` | Desired-state envelope from the control plane        |
| `api.Envelope` | `internal/api` | SSE event wrapper                                     |
| `api.EventPolicyUpdated` | `internal/api` | Event type constant `"policy_updated"`            |

### Graceful Shutdown

Call `Enforcer.Teardown()` to clean up firewall chains:

```go
<-ctx.Done()
if err := enforcer.Teardown(); err != nil {
    logger.Warn("policy teardown failed", "error", err)
}
```
