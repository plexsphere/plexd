---
title: Network Policy Enforcement
package: internal/policy
feature: PXD-0008
---

# Network Policy Enforcement

The `internal/policy` package enforces network policies on mesh nodes. It translates the control plane's merged policy — a single `{revision_id, fingerprint, rules[]}` block on the `NodeStateSnapshot` envelope — into concrete firewall rules (nftables on Linux, pf on macOS, the Windows Filtering Platform on Windows) for packet-level enforcement.

The package integrates with `internal/reconcile` for periodic convergence and with `internal/api` for real-time SSE-driven policy updates and the [policy status report](#policy-status-report) it sends back to the control plane.

> **Peer membership is not a policy concern.** WireGuard peer visibility comes solely from the snapshot `peers` block, applied by `wireguard.ReconcileHandler`. The policy package no longer filters peers: node-ID rule matching and `FilterPeers` have been removed, and policy rules are CIDR-scoped rather than node-ID-scoped.

## Data Flow

```
Control Plane ◀─────── PUT /v1/nodes/{node_id}/policy-status ────────┐
      │                                                              │
      ▼                                                              │
┌──────────────────┐   ┌─────────────────┐   ┌───────────────┐   ┌───┴────────────┐
│ NodeStateSnapshot│──▶│ DispatchHandler │──▶│ Enforcer.Sync │──▶│ StatusReporter │
│  .Policy         │   └─────────────────┘   └───────┬───────┘   └────────────────┘
│  (merged block)  │                                 │
└──────────────────┘                                 ▼
                                            ┌──────────────────┐
                                            │   PolicyEngine   │
                                            │BuildFirewallRules│
                                            └────────┬─────────┘
                                                     ▼
                                            ┌──────────────────┐
                                            │FirewallController│
                                            │  (nft, pf, WFP)  │
                                            └──────────────────┘
```

The merged policy flows from the control plane via `NodeStateSnapshot.Policy`. [`DispatchHandler`](#dispatchhandler) hands the block of every successful pull to [`Enforcer.Sync`](#sync), which compares it with its record of what the firewall holds and applies it when it is not the installed ruleset: the `PolicyEngine` converts its allow rules into `FirewallRule` entries, and the `Enforcer` applies them via the `FirewallController`. `Sync` records the outcome in the Enforcer's [`Status`](#status-and-changed): what it enforces, the block it applied, and the block its latest apply failed on, with the reason. A block it could not apply is applied again on the next pull. The [`StatusReporter`](#policy-status-report) sends that record, with the drop counters of the default deny, to the control plane, and the node API serves it as [`GET /v1/policies`](../core/nodeapi.md#get-v1-policies).

## Config

`Config` holds policy enforcement parameters.

| Field       | Type     | Default          | Description                              |
|-------------|----------|------------------|------------------------------------------|
| `Enabled`   | `*bool`  | `true` (nil)     | Whether policy enforcement is active     |
| `ChainName` | `string` | `plexd-mesh`     | Prefix of the three Linux base chains, `<ChainName>-input`, `<ChainName>-forward` and `<ChainName>-output`; the chain's comment line in the pf anchor on macOS, the prefix of the WFP filter names on Windows |

```go
cfg := policy.Config{}
cfg.ApplyDefaults()  // ChainName="plexd-mesh"; Enabled stays nil
cfg.IsEnabled()      // true
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

### Enabled Is a Pointer

`Enabled` is a `*bool` and `ApplyDefaults` never writes to it: `nil` means unset, which `IsEnabled()` reads as enabled. Read the effective setting through `IsEnabled()`, never through the field.

The pointer is what keeps an operator's `enabled: false` distinguishable from an omitted key. Enforcement is the deny-by-default posture and a node that cannot install it aborts startup, so `enabled: false` is the only way to run a node without it — and defaulting a `false` back to `true` would swallow exactly that instruction.

### Validation Rules

| Field       | Rule                                | Error Message                                              |
|-------------|-------------------------------------|------------------------------------------------------------|
| `ChainName` | Must not be empty when `IsEnabled()`| `policy: config: ChainName must not be empty when enabled` |

Validation is skipped entirely when enforcement is disabled.

## FirewallRule

Describes a single iptables-style packet filter rule.

```go
type FirewallRule struct {
    Interface string // network interface name
    SrcIP     string // source IP (CIDR or single IP); "" matches every address
    DstIP     string // destination IP (CIDR or single IP); "" matches every address
    Port      int    // destination port (0 = any)
    PortTo    int    // inclusive end of a destination port range, 0 means single-Port match
    Protocol  string // "tcp", "udp", "icmp", or "" (any)
    Action    string // "allow" or "deny"
    LogTag    string // when set, the backend reports the connections the rule admits
}
```

`PortTo` carries the inclusive end of a destination port range, mapping to an nftables range match; `0` means a single-port match on `Port`.

An address field holds a prefix or a single address, IPv4 or IPv6. The two fields of a rule name one family, and a rule with both empty matches both families. `0.0.0.0/0` and `::/0` match every address of their family and nothing of the other. The engine builds `allow` rules and one `deny`, the default deny, which carries no address.

`LogTag`, when set, asks the backend to report each connection the rule admits, carrying the tag; see [Connection logging](#connection-logging). Only an allow carries one. The engine sets none: the `Enforcer` tags the rules with `log: true` when it applies them; see [Log tags and rule order](#log-tags-and-rule-order).

A backend applies each rule in both directions: to what arrives on `Interface`, delivered to the node or forwarded through it, and to what the node's own sockets send over `Interface`. A rule matches by its addresses. The control plane compiles every authored rule for both ends (plexsphere/plexsphere#1056): the destination node gets a copy that names the source as sender, and the source node gets one that names itself. Each copy therefore matches one direction. `FirewallRule` has no direction field. The engine would need the node's own mesh address to tag a rule inbound or outbound, and it does not receive that address.

### Validation Rules

| Field      | Rule                                          | Error Message                                                    |
|------------|-----------------------------------------------|------------------------------------------------------------------|
| `Action`   | Must be `"allow"` or `"deny"`                 | `policy: firewall rule: invalid action "..."`                    |
| `Port`     | Must be 0–65535                               | `policy: firewall rule: invalid port N`                          |
| `Protocol` | Must be `""`, `"tcp"`, `"udp"`, or `"icmp"`   | `policy: firewall rule: invalid protocol "..."`                  |
| `Port`     | Requires `tcp`/`udp` if > 0                   | `policy: firewall rule: port N requires protocol tcp or udp`     |
| `PortTo`   | Requires a start port and `Port ≤ PortTo ≤ 65535` | `policy: firewall rule: port range end N requires a start port` / `... invalid port range end N` |
| `SrcIP`, `DstIP` | Empty, or a prefix or address without a zone | `policy: firewall rule: invalid IP address "..."`          |
| `SrcIP`, `DstIP` | Not an IPv4-mapped IPv6 address such as `::ffff:10.0.0.1` | `policy: firewall rule: IPv4-mapped IPv6 address "..."` |
| `SrcIP`, `DstIP` | Both of one family when both are set  | `policy: firewall rule: source "..." and destination "..." differ in address family` |
| `Protocol` | `icmp` needs an address, which chooses between ICMP and ICMPv6 | `policy: firewall rule: protocol icmp needs an address to choose between ICMP and ICMPv6` |
| `LogTag`   | Only on an `allow`                            | `policy: firewall rule: log tag on a "deny" rule`                |
| `LogTag`   | At most 64 bytes, which keeps it inside the 127-byte prefix of an nftables log expression | `policy: firewall rule: log tag "..." longer than 64 bytes` |

Every backend parses the addresses with the same function, `parseRuleAddr`, so a rejected address reads the same on Linux, macOS and Windows.

## FirewallController

Interface abstracting OS-level packet filter operations. The package has three implementations, one per platform: [`NftablesController`](./nftables-firewall.md) on Linux, and [`PFController` and `WFPController`](./pf-wfp-firewall.md) on macOS and Windows.

```go
type FirewallController interface {
    Probe() error
    EnsureChain(chain string) error
    ApplyRules(chain string, rules []FirewallRule) error
    FlushChain(chain string) error
    DeleteChain(chain string) error
}
```

| Method        | Description                                              |
|---------------|----------------------------------------------------------|
| `Probe`       | Reports whether the backend is usable, without changing kernel state |
| `EnsureChain` | Creates the named chain if it does not already exist     |
| `ApplyRules`  | Replaces all rules in the named chain atomically, for traffic in both directions: what arrives on a rule's interface and what the node itself sends over it |
| `FlushChain`  | Removes all rules from the named chain                   |
| `DeleteChain` | Deletes the named chain; idempotent on non-existent chain|

### ConnReporter

A backend that can report the connections its logged rules admit also implements `ConnReporter`. The Linux and macOS backends do; the Windows one does not, see [Logged rules on Windows](./pf-wfp-firewall.md#logged-rules-on-windows). `NewEnforcer` hands such a backend the Enforcer's `ConnLogger` as its sink, and the backend's reader hands the sink one `ConnEvent` per connection.

```go
type ConnReporter interface {
    SetConnSink(sink ConnSink)
}

type ConnSink interface {
    Event(ev ConnEvent)
    Lost(n int) // records the reader knows it missed
}

type ConnEvent struct {
    Tag              string  // the LogTag of the rule that admitted the connection
    Dir              ConnDir // ConnIn, ConnOut or ConnForward
    Src, Dst         netip.Addr
    Protocol         uint8   // the IP protocol number
    SrcPort, DstPort uint16  // 0 unless Protocol is TCP or UDP
}
```

`ConnDir.String()` returns `in`, `out` and `forward`. When a reader cannot start, the backend installs the rules without their tags; see [When logging is unavailable](#when-logging-is-unavailable).

`RelayProbePort` is 9, the UDP port of plexd's [relay liveness probe](./wireguard.md#relay-liveness-probe). Every backend lets the node send UDP to this port over the mesh interface without a rule, ahead of the policy rules. Any local process can do so, to any address the mesh routes, and the receiving node's inbound rules still apply. Without the exemption a narrow policy would fail every probe send, and plexd would notice a dead relay only once the handshake went stale.

### DropCounter

A backend that counts what its default deny drops also implements `DropCounter`. The Enforcer reads the counts through it for the [policy status report](#policy-status-report).

```go
type DropCounter interface {
    DropCounts(chain string) (packets, bytes uint64, err error)
}
```

`DropCounts` returns the packets and bytes the deny rules of `chain` dropped since the chain was last loaded. The engine's only deny is the default deny, so that is what the default deny dropped. Every apply loads the chain anew, so the counts start from 0 at every install.

| Platform | Backend | Counts |
|---|---|---|
| Linux | `NftablesController` | The counters of every rule ending in a drop verdict in the input, forward and output chain; see [DropCounts](./nftables-firewall.md#dropcounts) |
| macOS | `PFController` | The packets and bytes `pfctl -a com.apple/plexd -sl` prints for the label `plexd-default-deny`, which every `block` line carries; see [Drop counters](./pf-wfp-firewall.md#drop-counters) |
| Windows | `WFPController` | Does not implement `DropCounter`: WFP keeps no per-filter counters, and its drop events carry no byte count. A Windows node reports no drops; see [Drop counters on Windows](./pf-wfp-firewall.md#drop-counters-on-windows) |

## PolicyEngine

Translates the merged policy's rules into concrete firewall rules for the local node.

### Constructor

```go
func NewPolicyEngine(logger *slog.Logger) *PolicyEngine
```

Logger is tagged with `component=policy`.

### BuildFirewallRules

```go
func (e *PolicyEngine) BuildFirewallRules(rules []api.PolicyRule, iface string) ([]FirewallRule, error)
```

Converts the merged policy's `api.PolicyRule` entries into concrete `FirewallRule` entries for the local node. A rule is `{protocol, source_cidr, destination_cidr, ports?, log?}`:

```json
{ "protocol": "tcp", "source_cidr": "10.99.0.2/32", "destination_cidr": "10.99.0.1/32", "ports": { "from": 5432, "to": 5432 }, "log": true }
```

Every rule is an allow, and rule order carries no meaning: a packet passes when any rule allows it, and the default deny appended last drops the rest. The CIDR fields map directly to `SrcIP`/`DstIP`, the `{from, to}` port range maps to `Port`/`PortTo` (a single port when `from == to`), and every rule becomes a `FirewallRule` with `Action: "allow"`.

- **Legacy `action`**: the key is not part of the format. A rule without it, or with `action: "allow"`, passes. Any other value, `""` included, returns `policy: rule <i>: unsupported action "<value>"`. Since plexsphere/plexsphere#1056 the control plane sends `action: "allow"` on every rule, so a node on this release works against it, and a control plane older than that cannot have a deny enforced as an allow.
- **Protocol**: `tcp`, `udp`, and `icmp` are kept; `any` maps to `""` (match all); any other value returns `policy: rule <i>: unsupported protocol "<value>"`. `icmp` in an IPv6 rule means ICMPv6.
- **Addresses**: `source_cidr` and `destination_cidr` are both required, in prefix notation, IPv4 or IPv6, and of one family. `0.0.0.0/0` is every IPv4 address and `::/0` every IPv6 address. The engine rejects an empty value with `address is empty`, a value that is not a prefix, such as `10.0.0.1` without a prefix length, with `invalid address "<value>": <parse error>`, and an IPv4-mapped IPv6 prefix such as `::ffff:10.0.0.1/128` with `IPv4-mapped IPv6 address "<value>"`. Each reads `policy: rule <i>: source_cidr: policy: firewall rule: <text>`, or the same with `destination_cidr`. Two families return `policy: rule <i>: source_cidr "<value>" and destination_cidr "<value>" differ in address family`.
- **Ports**: valid only for `tcp`/`udp`. `ports` on `icmp` or `any` returns `policy: rule <i>: ports set on portless protocol "<value>"`, and a range outside 1–65535 or with `to < from` returns `policy: rule <i>: port range <from>-<to> out of bounds`.
- **Log**: `log: true` asks for the rule's traffic to be logged. Absent and `false` mean the same. The engine translates a logged rule like any other and sets no `LogTag`. The `Enforcer` tags the rule when it applies the ruleset, and plexd then writes one line for each connection the rule allows; see [Connection logging](#connection-logging).
- **Default deny**: `FirewallRule{Interface: iface, Action: "deny"}` with both addresses empty is always appended as the last rule, including when `rules` is empty or `nil`. Without addresses it covers IPv4 and IPv6, on every backend.

One untranslatable rule rejects the whole revision. The engine returns the error, `ApplyFirewallRules` wraps it in `ErrInvalidRuleset`, and the node keeps the ruleset it enforces, reports the revision as rejected, and tries it again on every pull (see [Error Handling](#error-handling)). Skipping only that rule would merely narrow an allow-only ruleset, but the node would then enforce a ruleset that matches no revision, and a revision is either applied or rejected (plexsphere/plexd#177).

A plexd before this release rejects every rule of this format with `unsupported action ""` and keeps its previous ruleset.

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
- `firewall` may be `nil` — `ApplyFirewallRules` is a no-op in that case, and `Sync` records the enforcement `unavailable`
- Builds the Enforcer's `ConnLogger` from `logger`. When `firewall` implements [`ConnReporter`](#connreporter), it calls `SetConnSink` with that logger once

### Methods

| Method              | Signature                                                     | Description                                                        |
|---------------------|---------------------------------------------------------------|-------------------------------------------------------------------|
| `Preflight`         | `() error`                                                    | Probes the firewall backend without changing kernel state; no-op when disabled or nil firewall |
| `ApplyFirewallRules` | `(policy *api.PolicySnapshot, iface string) (bool, error)`   | Builds and applies rules; no-op when disabled or nil firewall. A `nil` policy yields the default-deny-only ruleset. The `bool` reports whether the ruleset actually reached the kernel. On success it records `policy` as the ruleset the backend holds |
| `Sync`              | `(desired *api.PolicySnapshot, iface string)`                 | Brings the firewall to the policy block of a pull and records the outcome; see [Sync](#sync) |
| `Status`            | `() Status`                                                   | A deep copy of the Enforcer's record; the zero `Status` before the first `Sync`; see [Status and Changed](#status-and-changed) |
| `Changed`           | `() <-chan struct{}`                                          | A channel of capacity 1 that `Sync` signals when the reported state moves |
| `DropCounts`        | `() (packets, bytes uint64, ok bool)`                         | What the installed ruleset's default deny dropped since it was installed; see [DropCounts](#dropcounts) |
| `Teardown`          | `() error`                                                    | Flushes and deletes firewall chain; safe with nil firewall. Clears the record of the installed and the applied ruleset, and closes the Enforcer: a later `Sync` or `ApplyFirewallRules` touches the backend no more |
| `ConnLogger`        | `() *ConnLogger`                                              | The logger that writes a line for each connection a logged rule admits; see [Connection logging](#connection-logging) |

The `bool` exists so callers cannot log an enforcement that never happened: both no-op paths return `(false, nil)`, which is indistinguishable from a successful apply on the error value alone.

Before the backend gets the rules, `ApplyFirewallRules` tags the logged ones and moves them ahead of the others; see [Log tags and rule order](#log-tags-and-rule-order).

`Sync`, `ApplyFirewallRules`, `Teardown` and `DropCounts` hold one lock across their backend calls, so the record always describes what the backend holds, and `Status` reads it under the same lock.

### Preflight

`plexd up` calls `Preflight` before it registers, and aborts startup on an error.

The check exists because the baseline install is fatal but happens *after* registration, which spends a one-shot bootstrap token and persists the identity the control plane hands back. Without it, a node that can never install a chain claims an identity it will never use and then crash-loops on the same step; where `data_dir` is ephemeral, the restart has neither an identity to reload nor an unspent token to register with.

`Preflight` mirrors the no-op paths of `ApplyFirewallRules` exactly — with enforcement disabled or no backend compiled in there is no enforcement to be unable to perform — and it never mutates kernel state, so a node that goes on to fail startup for another reason leaves nothing behind.

### Sync

```go
func (e *Enforcer) Sync(desired *api.PolicySnapshot, iface string)
```

[`DispatchHandler`](#dispatchhandler) calls `Sync` with the policy block of every successful pull, `nil` for a pull with `policy: null`. `Sync` brings the firewall to that block and records the outcome. It compares the block with the policy the backend holds, which `ApplyFirewallRules` records on every successful apply, `nil` standing for the default deny alone. It decides in this order:

1. It stores a copy of `desired` as `Received` and sets `Synced`.
2. With enforcement disabled (`policy.enabled: false`) it records the enforcement `disabled`, and without a firewall backend `unavailable`. Either way it clears the applied and the rejected block and touches nothing else. Otherwise the enforcement is `enforcing`.
3. When a ruleset is installed and `desired` is the same block, both `nil` or both with the same non-empty fingerprint, it makes no kernel call. It records `desired` as applied and clears the rejection. This is how a first pull with `policy: null` is recorded as applied over the startup baseline, and how a pull that changes only `revision_id` or `revisions` under an unchanged fingerprint is adopted. The `ConnLogger` is not told, so connection lines keep the `revision_id` of the install they came from.
4. When nothing is installed and `desired` is `nil`, it does nothing. That is the node whose startup skipped the baseline because no interface carried the mesh address under the mesh name.
5. Otherwise it calls `ApplyFirewallRules(desired, iface)`. A block without a fingerprint is never the installed one, so it reaches this step on every pull and logs `policy snapshot carries no fingerprint, ruleset rebuilds every cycle` at Warn with `revision_id`.
6. On success it records `desired` as applied, clears the rejection, and logs `policy ruleset applied` at Info with `revision_id`, `fingerprint` and `rules`, the rule count.
7. On failure the applied block stays: every backend replaces its chains whole or leaves them as they were. A block with a fingerprint becomes `Rejected`, with `rejectionReason(err)` as `Reason`. `Attempts` counts up while the fingerprint and the reason repeat, and restarts at 1 otherwise. A `nil` block or one without a fingerprint cannot be named in the policy status report, so its failure clears `Rejected` instead.

A ruleset the engine refuses and a failure of the backend are both recorded as a rejection, with plexd's error text as the reason. The first failure of a fingerprint and reason logs at Error, and every repeat logs `policy revision still rejected` at Debug; see [Error Handling](#error-handling).

DECISION: the retry is the next pull. `Sync` runs on every successful pull, every `reconcile.interval` (60 s by default) and on every trigger, and a block that is not installed is applied again each time. There is no backoff: a ruleset the engine refuses costs one pass over its rules and no kernel call, and a backend failure was retried every cycle when the apply ran as a reconcile handler.

`rejectionReason(err)` makes the error text fit the report's `reason`, which the contract bounds to 1 to 1024 bytes of UTF-8 without control characters. Invalid UTF-8 becomes U+FFFD, every rune from U+0000 to U+001F and U+007F becomes a space, the text is trimmed and cut to at most 1024 bytes on a rune boundary, and an error that leaves nothing reads `apply failed`.

### Status and Changed

```go
type Status struct {
    Enforcement string              // api.PolicyEnforcementEnforcing, ...Disabled or ...Unavailable
    Synced      bool                // Sync ran at least once
    HasApplied  bool                // a pull's block is applied
    Applied     *api.PolicySnapshot // that block; nil when the applied pull carried policy: null
    Received    *api.PolicySnapshot // the block of the latest pull; nil for policy: null
    Rejected    *api.PolicySnapshot // the block the latest apply failed on; nil when it did not fail
    Reason      string              // why, as rejectionReason renders the error; "" without Rejected
    Attempts    int                 // applies of Rejected that failed in a row with the same reason; 0 without Rejected
}
```

`Status()` returns a copy whose blocks share no memory with the Enforcer's. Before the first `Sync` it is the zero `Status`. The startup baseline, `ApplyFirewallRules(nil, iface)`, records an installed default deny without setting `HasApplied`, because it is no ruleset of the control plane's. `Teardown` clears `HasApplied`, `Applied` and the rejection, so `Status` no longer claims a ruleset the backend dropped.

`Changed()` returns a channel of capacity 1. `Sync` signals it, without blocking, when it ran for the first time, or when the enforcement, `HasApplied`, the fingerprint or revisions of `Applied`, or the fingerprint, revisions or `Reason` of `Rejected` changed. `Attempts` and `Received` alone signal nothing. Several changes before the reader wakes collapse into one signal, and the reader then reads the latest `Status`.

### DropCounts

```go
func (e *Enforcer) DropCounts() (packets, bytes uint64, ok bool)
```

Returns what the installed ruleset's default deny dropped since it was installed. `ok` is false while enforcement is disabled, while nothing is installed, and for a backend that does not implement [`DropCounter`](#dropcounter), a `nil` backend and the Windows one included. Otherwise it reads the counts of `cfg.ChainName` from the backend and remembers them with the install they belong to. An install is an apply the backend accepted: a failed apply leaves the chain and its counters as they were, so the counts it remembered stay those of the install still in place.

A failed read returns the counts remembered for the same install, or `ok == false` when there are none, and logs `policy drop counters unavailable` at Warn with `chain` and `error`, once per run of failures. Returning the remembered counts keeps `drops` in every report of one install: the control plane counts the whole value of a report that follows one without counters, so a gap would count the same drops twice. A new install starts without remembered counts.

The read holds the Enforcer's lock, so the counts always belong to the install it remembers them for. It costs one dump of three chains on Linux and one `pfctl` run on macOS.

### Behavior by State

| `IsEnabled()` | `firewall` | `Preflight`                  | `ApplyFirewallRules`          | `Sync`                                         | `Teardown`          |
|---------------|------------|------------------------------|-------------------------------|------------------------------------------------|---------------------|
| `true`        | non-nil    | Backend probed               | Rules applied, `(true, nil)`  | Records `enforcing`; applies the block when it is not the installed one | Chain removed       |
| `true`        | `nil`      | No-op, `nil`                 | No-op, `(false, nil)`         | Records `unavailable`; no backend call         | No-op               |
| `false`       | any        | No-op, `nil`                 | No-op, `(false, nil)`         | Records `disabled`; no backend call            | No-op/chain removed |

### Error Prefixes

| Method              | Prefix               |
|---------------------|----------------------|
| `Preflight`         | `policy: preflight: `|
| `ApplyFirewallRules`| `policy: enforce: `  |
| `Teardown`          | `policy: teardown: ` |

A ruleset the engine refuses to translate is additionally wrapped in the sentinel `ErrInvalidRuleset`, so callers can distinguish a permanently broken revision (`errors.Is(err, policy.ErrInvalidRuleset)`) from a transient netlink failure. The backend is never touched in that case — the previously installed chain stays in place. `Sync` records both kinds as a rejection and uses the sentinel only to choose its Error line.

## DispatchHandler

Factory function returning a `reconcile.DispatchHandler` that hands the policy block of every successful pull to `Enforcer.Sync`.

```go
func DispatchHandler(enforcer *Enforcer, iface string) reconcile.DispatchHandler
```

The handler calls `enforcer.Sync(desired.Policy, iface)` and ignores a `nil` snapshot. [`Sync`](#sync) applies the block when it is not the installed ruleset and records the outcome for the [policy status report](#policy-status-report) and the node API. The handler does not touch WireGuard peers: `wireguard.ReconcileHandler` owns peer membership.

### Why the Dispatch Seam

DECISION: the apply runs on the dispatch seam, on every pull, rather than as a reconcile handler behind the differ's `PolicyChanged`. A reconcile handler could not retry a rejected revision: the reconciler stores the pulled block once the cycle completes, and the differ never offers its fingerprint again. Returning the error instead would hold back every other block of the snapshot. On the dispatch seam a failed apply holds nothing back, and `Sync` compares the pull with what is installed itself, so a rejected block is applied again on the next pull, and a pull with `policy: null` can be recorded as applied over the startup baseline.

The differ still compares the policy block and sets `StateDiff.PolicyChanged`, so a new fingerprint shows as `drift=policy` in the cycle log, but no reconcile handler acts on the flag. Dispatch handlers run before the reconcile handlers, so a new ruleset is installed before the WireGuard handler changes peers in the same cycle. The default deny stands throughout either way.

### Retry

`Sync` runs on every successful pull, every `reconcile.interval` (60 s by default) and on every trigger, such as a `policy_updated` event. A block that is not installed is applied again each time, without a backoff, until it succeeds or the control plane serves another block. While the retry fails, the node enforces the ruleset it applied before, and `Status` names the rejected block, its reason and the attempts in a row.

### Fingerprint Short-Circuit

`Sync` compares the pulled `fingerprint` with the installed ruleset's byte for byte and **never re-derives it from the rules**. A revision-only bump (same fingerprint) makes no kernel call and logs no `policy ruleset applied`. `Sync` records the block as applied all the same, so the policy status report and `GET /v1/policies` name its `revision_id` and `revisions`. A block without a fingerprint has no comparison key and is applied on every pull.

### Error Handling

No apply failure reaches the reconciler: a dispatch handler returns nothing, so the rest of the snapshot converges while the Enforcer retries on its own. The firewall keeps the last successfully applied ruleset, which is fail-closed.

`Sync` records a failed apply of a block with a fingerprint as `Rejected` and applies it again on every pull. The first failure of a fingerprint and reason logs at Error, with `revision_id`, `fingerprint` and `error`:

- `policy revision rejected, keeping previous ruleset` for a ruleset the engine refuses (`ErrInvalidRuleset`). Its rules are a permanent property of the revision, so the same block fails on every pull until the control plane serves another.
- `reconcile: apply firewall rules failed` for a failure of the backend, such as a netlink error.

Every repeat of the same fingerprint and reason logs `policy revision still rejected` at Debug with `revision_id`, `fingerprint` and `attempts`, so a revision stuck behind the retry does not repeat its Error every minute. A successful apply resets this, and the next failure logs at Error again. A failure with another reason logs at Error and restarts `attempts` at 1.

### Registration

```go
enforcer := policy.NewEnforcer(engine, fwCtrl, policy.Config{}, logger)

r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterDispatchHandler(policy.DispatchHandler(enforcer, "plexd0"))
```

`plexd up` registers it on every node, after every other dispatch handler and so ahead of every reconcile handler.

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
- Filtering operates at **L3/L4** (CIDR, port, protocol) on the mesh interface: an nftables input chain, forward chain and output chain on `plexd0` on Linux, pf rules on the kernel's `utunN` on macOS, WFP filters on the Wintun adapter on Windows.
- On all three platforms the rules govern mesh traffic addressed to the node itself, the mesh traffic it forwards, and what the node's own sockets send over the mesh. A node therefore rejects unsolicited mesh traffic to its own addresses until a rule allows it, and it drops what it sends to a mesh address until a rule allows that too; see [What the rules govern](./pf-wfp-firewall.md#what-the-rules-govern). On Linux the replies to a connection the node, or a host behind it, opened pass through connection tracking without a rule of their own, and so do the replies the node sends to a connection the policy let in; see [Connection Tracking](./nftables-firewall.md#connection-tracking). On macOS only TCP keeps state: the node's own TCP connections keep their replies, and the replies to what a rule lets in leave through stateless mirror lines. On Windows those replies leave through the ALE flow the inbound accept authorized.
- What the node forwards into the mesh is not filtered on its way out: traffic from a user-access client, a site-to-site peer or a host behind a bridge, and on Linux a container or Pod masqueraded onto the node's mesh address. On Linux the output chain also lets out unfiltered what leaves the mesh interface from a source that is not one of its addresses, such as a Pod's packet IPVS sends to a Service endpoint behind the mesh; see [Connection Tracking](./nftables-firewall.md#connection-tracking).
- plexd's relay liveness probe, UDP to port 9 (`RelayProbePort`), leaves the mesh interface without a rule on every platform; see [Relay liveness probe](./wireguard.md#relay-liveness-probe).
- A rule with `log: true` makes plexd log each connection it allows, at a bounded rate, on Linux and macOS; Windows enforces it without logging; see [Connection logging](#connection-logging).
- Every rule is an allow and rule order carries no meaning. The default stance is **deny-all**: the ruleset always ends with a default-deny rule that covers IPv4 and IPv6, and a `null` policy applies the default-deny-only ruleset.
- Rules may name IPv4 or IPv6 prefixes on Linux, macOS and Windows. A peer's allowed IPs are its IPv4 mesh address alone today, so an IPv6 rule governs IPv6 traffic only once the mesh carries it.
- Peer membership is **not** governed by policy — it comes from the snapshot `peers` block via `wireguard.ReconcileHandler`. Policy rules are CIDR-scoped, not node-ID references.
- On every successful pull plexd compares the block's fingerprint with the installed ruleset's and rebuilds the ruleset only when they differ. Revision-only bumps short-circuit and leave the ruleset untouched. A block plexd could not apply is applied again on every pull, and the node keeps the ruleset it applied before in the meantime.
- plexd reports what it enforces, the ruleset it applied, the one its latest apply failed on and the drop counters of its default deny to the control plane; see [Policy status report](#policy-status-report).

## Connection logging

A rule with `log: true` makes plexd write one line to its own log for each connection the rule allows, on Linux and macOS:

```text
time=2026-11-12T10:00:00.000Z level=INFO msg="policy rule allowed connection" component=policy revision_id=0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c4 rule=0 direction=in protocol=tcp src=10.99.0.3 dst=10.99.0.1 dst_port=7001
```

The keys come in this order:

| Key | Value |
|---|---|
| `revision_id` | The `revision_id` of the policy block the rule came from |
| `rule` | The rule's index in that block's `rules` array, counted from 0. The format carries no rule id, and plexsphere/plexsphere#1060 shows the ruleset of a revision |
| `direction` | `in` for traffic addressed to the node, `out` for what the node's own sockets send, `forward` for traffic routed through the node |
| `protocol` | `tcp`, `udp`, `icmp` (IP protocol 1), `icmpv6` (58), or the protocol number in decimal |
| `src`, `dst` | The source and the destination address |
| `dst_port` | The destination port, for `tcp` and `udp` only |

The line carries no source port. A connection that several logged rules allow is named after the first of them in the block's order.

### Log tags and rule order

After `BuildFirewallRules` succeeds, `Enforcer.ApplyFirewallRules`:

1. increments a generation counter, which counts the applies that got past the engine since plexd started;
2. gives every rule with `log: true` the `LogTag` `"<generation>/<index>"`, the index being the rule's position in the policy's `rules`;
3. moves the tagged rules ahead of the untagged ones and keeps the order within each group, so the default deny stays last;
4. hands the rules and the policy's `revision_id` to `ConnLogger.SetRuleset` before the backend gets them, so an event the kernel produces right after the apply finds its rule;
5. calls `EnsureChain` and `ApplyRules`. When either fails, it calls `ConnLogger.Revert`, so repeated failures never push the tags of the installed ruleset out of the logger.

With enforcement disabled or no backend it returns before step 1. The generation changes with every apply, so a tag from one ruleset never names a rule of another. The backend hands the tag back with each event, and the `ConnLogger` turns it into the line's `revision_id` and `rule`, so the line never shows it.

DECISION: the logged rules go ahead of the unlogged ones. Every rule is an allow and rule order carries no verdict, so the move changes nothing that passes or drops. It makes every backend's first match a logged rule whenever one allows the connection, so a narrow logged rule still logs behind a Project's allow-all policy. A connection that several logged rules allow is named after the first of them in the policy's order. The backends get the reordered list, so a pf line's position follows it, while a connection line's `rule` stays the index in the policy.

### Per platform

Each backend reads its kernel's own report and hands one `ConnEvent` per match to the `ConnLogger`:

| | Linux | macOS |
|---|---|---|
| Kernel source | nftables `log group 28772` in front of each logged rule, read over NFLOG | `log` on pf lines, read from `pflog0` through `/dev/bpf` |
| First packet only | `ct state new`; an unanswered flow's later packets are still new | TCP: a `flags S/SA` line in, `keep state` out; UDP, ICMP and other protocols: every packet |
| Directions | `in`, `forward`, `out` from the NFLOG hook | `out` from pf's direction; `in`, or `forward` when the destination is no address of the Mac |

On macOS a UDP, ICMP or other non-TCP flow yields one line per packet, and on Linux a flow yields one line per packet until its first reply, both within the rate limit below. The backend pages describe each reader: [nftables Firewall Controller](./nftables-firewall.md#connection-logging) and [pflog](./pf-wfp-firewall.md#pflog).

Windows enforces a logged rule like any other and logs none of its connections. Every apply that holds a logged rule logs the line under [When logging is unavailable](#when-logging-is-unavailable), with the `error` `policy: wfp: connection logging is not available on Windows`; see [Logged rules on Windows](./pf-wfp-firewall.md#logged-rules-on-windows).

### Rate limit

plexd writes at most 5 connection lines a second, with a burst of 50. At the default `log_fwd.report_interval` of 30 s that is at most 200 lines a batch, half of the forwarder's buffer of twice `batch_size`. A line beyond the limit is dropped and counted as rate limited. A record a reader knows it missed, through a full NFLOG socket on Linux or a BPF drop on macOS, is counted as lost. Once a minute, when either count is above 0, plexd logs at Warn

```text
level=WARN msg="policy connection lines dropped" component=policy rate_limited=10 lost=3
```

and resets both counts to 0. No setting changes the rate: the control plane's `log` property decides what is logged, and `policy.enabled: false` stays the node's way out.

### When logging is unavailable

Logging never blocks enforcement. A backend whose reader cannot start installs the ruleset without its log tags and logs, once per apply that holds a logged rule:

```text
level=WARN msg="policy connection logging unavailable, logged rules are enforced without it" component=policy error="..."
```

The rules still pass and drop the same traffic, and no line names them. The `error` names the cause, such as another process bound to NFLOG group 28772 on Linux or no free BPF device on macOS. On Windows it is `policy: wfp: connection logging is not available on Windows`, for every apply that holds a logged rule. On Linux and macOS a reader that started and then fails logs `policy connection log reader stopped` at Warn with `error`, and the next apply with a logged rule opens a new one.

The `ConnLogger` drops an event it cannot attribute and logs it at Debug with `tag`: `policy connection event names no logged rule` when the tag belongs to neither the ruleset applied last nor the one before, and `policy connection event does not match its rule` when the rule's addresses, protocol and port do not match the event.

### Where the lines go

A connection line is a record of plexd's own log, so it lands where plexd's other lines do: the journal on Linux and `/Library/Logs/plexd/plexd.log` on macOS. Log forwarding carries it to the control plane from there, as it carries every other plexd line.

On Linux without `journalctl`, as in the Docker image, the Kubernetes DaemonSet and OpenWRT, plexd has no source for its own output. There, with `log_fwd.enabled`, `plexd up` creates a [`QueueSource`](../observability/log-forwarding.md#queuesource) and passes its `Add` to `ConnLogger.ForwardTo`, so the connection lines and the minute summary reach the control plane. plexd's other lines stay on stderr there, as before. On every platform `plexd up` runs `ConnLogger.Run` beside the log forwarder.

### ConnLogger

```go
func NewConnLogger(logger *slog.Logger) *ConnLogger
```

`ConnLogger` implements `ConnSink`. Its logger is tagged with `component=policy`, and all its methods are safe for concurrent use.

| Method | Description |
|---|---|
| `SetRuleset(revisionID string, rules []FirewallRule)` | Records the revision and index of every tagged rule of a ruleset about to be applied, by tag. The ruleset it held becomes the previous one, and the one before that is forgotten |
| `Revert()` | Makes the previous ruleset current again after a failed apply. Does nothing without a previous ruleset |
| `Event(ev ConnEvent)` | Looks the tag up in the current, then the previous ruleset, checks that the rule admits the event, takes a token from the bucket and logs the line |
| `Lost(n int)` | Adds `n` to the lost count |
| `Run(ctx context.Context)` | Logs `policy connection lines dropped` once a minute when either count is above 0, and resets both. Returns when `ctx` ends |
| `ForwardTo(fn func(ts time.Time, severity, message string))` | Also hands every line and summary to `fn`, with severity `info` or `warning` and the record as `slog.TextHandler` renders it, without the trailing newline. A nil `fn` stops forwarding |

## Policy status report

`StatusReporter` sends the Enforcer's record to the control plane as [`PUT /v1/nodes/{node_id}/policy-status`](../core/api-endpoints.md#policy-status): what the node enforces, the ruleset it applied, the ruleset its latest apply failed on and why, and how many packets and bytes its default deny dropped. Without the report the control plane cannot tell a ruleset the node applied from one it refused. The control plane derives the node's policy status from it, `applied`, `pending`, `rejected` or `not_enforced`, and logs every change of what the node enforces.

```go
type StatusClient interface {
    ReportPolicyStatus(ctx context.Context, nodeID string, req api.PolicyStatusRequest) (*api.PolicyStatusResponse, error)
}

func NewStatusReporter(interval time.Duration, nodeID string, client StatusClient, enforcer *Enforcer, logger *slog.Logger) *StatusReporter
func (r *StatusReporter) Run(ctx context.Context) error
```

`*api.ControlPlane` satisfies `StatusClient`. A non-positive interval becomes 30 s, the default heartbeat interval. `plexd up` starts the reporter on every node, after the relay status reporter, at `heartbeat.interval`. No configuration key turns it on or off: a node with `policy.enabled: false` reports `disabled`. Its log lines carry `component=policy`, and `Run` logs `policy status: reporter started` at Info with `interval` when it starts.

### What a report carries

`buildPolicyStatusRequest` builds every report from the Enforcer's [`Status`](#status-and-changed) and its [`DropCounts`](#dropcounts):

| Member | Content |
|---|---|
| `enforcement` | `Status.Enforcement`: `enforcing`, `disabled` or `unavailable` |
| `applied` | Set while `HasApplied` is: `{"revisions": []}`, without a fingerprint, for an applied pull with `policy: null`, and the block's `fingerprint` and `revisions` for a block with a fingerprint. Left out for an applied block without a fingerprint, which cannot be echoed, and while no pull's block is applied |
| `rejected` | Set while `Rejected` is: its `fingerprint` and `revisions`, and `Reason` as `reason` |
| `drops` | Set when `DropCounts` returns `ok`: `packets` and `bytes`, each capped at `math.MaxInt64` |

`revisions` go out as the pull listed them. A block from a control plane that sends none goes out with `[]`, because the contract refuses `null`. For a node that applied one block and rejected the next:

```json
{
  "enforcement": "enforcing",
  "applied": {
    "fingerprint": "j7Hn2mF0oQ9rXcV8yZ1aB4cD6eF8gH0iJ2kL4mN6oM0=",
    "revisions": [
      { "policy_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d1", "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1" }
    ]
  },
  "rejected": {
    "fingerprint": "q7vZ4Zx0d8nU1m3oW5bJk2pQ9rT6yH4sL0aE8cV1fG4=",
    "revisions": [
      { "policy_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d1", "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c2" }
    ],
    "reason": "policy: enforce: policy: invalid ruleset: policy: rule 0: unsupported action \"deny\""
  },
  "drops": { "packets": 5, "bytes": 500 }
}
```

### When a report is sent

- On every signal of `Enforcer.Changed()`: after the first `Sync`, and on every change of the enforcement, of the applied block, or of the rejected block or its reason. The interval restarts after such a send.
- On a tick of the interval, only when no report of the current state was accepted yet, which is the case after a failed send, or when the drop counters differ from the ones the control plane accepted last. A quiet node sends nothing, so the age of its last report is no liveness signal.
- Nothing before the Enforcer's first `Sync`: until then plexd has seen no pull and could only report the startup baseline, which is no ruleset of the control plane's.
- Nothing at shutdown: the contract defines no such report, and the control plane keeps the last one. `Run` returns `nil` when its context ends.

A change of `Attempts` alone sends nothing. Every send and every tick reads the drop counters once, so a quiet node costs one dump of three chains on Linux, or one `pfctl` run on macOS, per heartbeat interval.

DECISION: the reporter sends from a goroutine of its own, one report at a time, never from inside the dispatch handler, so a slow control plane never delays a reconcile cycle. This follows the [relay status reporter](../bridge/nat-relay.md#relay-status-report).

### Answers

| Answer | Log line | Level | Then |
|---|---|---|---|
| `200` | `policy status: reported`, with `enforcement`, `status` (the answer's), `applied_fingerprint` and `rejected_fingerprint` | Info for the first accepted report and when what the node applied, rejected or enforces changed since the last one; Debug when only the counters did | The report counts as accepted |
| `200` after a `501 policy_status_not_provisioned` | `policy status: control plane accepts policy status reports`, ahead of the line above | Info | As for any `200` |
| `404` with any code but `policy_status_node_gone`, which `api.IsPolicyStatusNotServed` classifies | `policy status: control plane does not accept policy status reports, not reporting until restart`, with `status` and `code` | Info, once | No further report until plexd restarts, as the contract asks |
| `501 policy_status_not_provisioned`, which `api.IsPolicyStatusNotProvisioned` classifies | `policy status: control plane has not provisioned policy status reports, retrying every interval`, with `status` and `code` | Info, once until a report is accepted | Every tick sends again |
| `api.ErrCredentialRefused` | `policy status: send failed`, with `error` | Debug, because the heartbeat names the cause when it parks the agent | The next tick sends again |
| `404 policy_status_node_gone` | `policy status: rejected, this node was removed`, with `code` | Warn, on every send | The next tick sends again |
| Any other failure: `400`, `401`, `403`, `413`, `500`, `503`, a `501` with another code, a transport error or a timeout | `policy status: send failed`, with `error` | Warn | The next tick sends again |

An error that arrives once the reporter's context is done is the shutdown itself and is not logged.

### Drop counters

Linux and macOS send `drops`. Windows never does: WFP keeps no per-filter counters and its drop events carry no byte count, so the contract's required `bytes` could not be filled. [DropCounter](#dropcounter) lists what each backend counts. On every platform `drops` is left out while enforcement is disabled or unavailable and while nothing is installed.

The counters start from 0 at every install, and the control plane reads a value below the previous one as a restart of the count. Within one install a failed read sends the counts read last; see [DropCounts](#dropcounts).

## Integration Points

### Reconciliation Loop

The policy dispatch handler plugs into `internal/reconcile` on the dispatch seam, so it runs on every successful pull, ahead of the WireGuard reconcile handler and every other reconcile handler:

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterDispatchHandler(policy.DispatchHandler(enforcer, "plexd0"))
r.RegisterHandler(wireguard.ReconcileHandler(mgr))
```

### SSE Real-Time Updates

`HandlePolicyUpdated` triggers reconciliation when the control plane pushes a `policy_updated` event. The reconciliation cycle then pulls a fresh snapshot, and the dispatch handler hands its policy block to `Sync`, which applies it when it is not the installed ruleset.

### Status Reporter

`plexd up` runs the [`StatusReporter`](#policy-status-report) on its own goroutine beside the reconciler. It reads the Enforcer's `Status` on every `Changed` signal and on every tick, and sends through the shared control plane client.

### Node API

`GET /v1/policies` serves the same record as the report: the applied block, the enforcement, the latest pull's block, and whether the two are the same block (`in_sync`). `plexd policies` prints it; see [`GET /v1/policies`](../core/nodeapi.md#get-v1-policies) and [`plexd policies`](../core/cli.md#plexd-policies).

### Control Plane Types

| Type             | Package        | Usage                                                     |
|------------------|----------------|-----------------------------------------------------------|
| `api.PolicySnapshot` | `internal/api` | Merged policy block `{revision_id, fingerprint, rules[], revisions[]}`; `Clone` deep-copies it |
| `api.PolicyRevisionRef` | `internal/api` | One `{policy_id, revision_id}` pair of the block's `revisions`, echoed in the report |
| `api.PolicyRule` | `internal/api` | Allow rule: `protocol`, `source_cidr`, `destination_cidr`, `ports?`, `log?`; a legacy `action` key lands in `LegacyAction` |
| `api.PortRange`  | `internal/api` | Inclusive destination port range `{from, to}`             |
| `api.NodeStateSnapshot` | `internal/api` | Desired-state envelope from the control plane        |
| `api.PolicyStatusRequest` | `internal/api` | The policy status report: `enforcement`, `applied?`, `rejected?`, `drops?` |
| `api.PolicyStatusResponse` | `internal/api` | The report's `200` body: `accepted_at`, `status` |
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

`Teardown` also clears the Enforcer's record of the installed and the applied ruleset, so `Status` no longer claims a ruleset the backend dropped, and it closes the Enforcer. `plexd up` tears the chain down before it waits for the reconciler, which can still be inside a cycle whose pull it fetched before the shutdown; a closed Enforcer makes the `Sync` of that pull, and any `ApplyFirewallRules`, a no-op, so the chain is not installed again. The status reporter sends no report at shutdown: `Run` returns `nil` when its context ends, and the control plane keeps the last report.
