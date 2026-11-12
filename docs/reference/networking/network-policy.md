---
title: Network Policy Enforcement
package: internal/policy
feature: PXD-0008
---

# Network Policy Enforcement

The `internal/policy` package enforces network policies on mesh nodes. It translates the control plane's merged policy — a single `{revision_id, fingerprint, rules[]}` block on the `NodeStateSnapshot` envelope — into concrete firewall rules (nftables on Linux, pf on macOS, the Windows Filtering Platform on Windows) for packet-level enforcement.

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

The merged policy flows from the control plane via `NodeStateSnapshot.Policy`. The `PolicyEngine` converts its allow rules into `FirewallRule` entries, and the `Enforcer` applies them via the `FirewallController`. `ReconcileHandler` wires it into the reconciliation loop, rebuilding the ruleset only when the policy fingerprint changes.

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

One untranslatable rule rejects the whole revision. The engine returns the error, `ApplyFirewallRules` wraps it in `ErrInvalidRuleset`, and the node keeps the ruleset it enforces (see [Error Handling](#error-handling)). Skipping only that rule would merely narrow an allow-only ruleset, but the node would then enforce a ruleset that matches no revision, and a revision is either applied or rejected (plexsphere/plexd#177).

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
- `firewall` may be `nil` — `ApplyFirewallRules` is a no-op in that case
- Builds the Enforcer's `ConnLogger` from `logger`. When `firewall` implements [`ConnReporter`](#connreporter), it calls `SetConnSink` with that logger once

### Methods

| Method              | Signature                                                     | Description                                                        |
|---------------------|---------------------------------------------------------------|-------------------------------------------------------------------|
| `Preflight`         | `() error`                                                    | Probes the firewall backend without changing kernel state; no-op when disabled or nil firewall |
| `ApplyFirewallRules` | `(policy *api.PolicySnapshot, iface string) (bool, error)`   | Builds and applies rules; no-op when disabled or nil firewall. A `nil` policy yields the default-deny-only ruleset. The `bool` reports whether the ruleset actually reached the kernel |
| `Teardown`          | `() error`                                                    | Flushes and deletes firewall chain; safe with nil firewall        |
| `ConnLogger`        | `() *ConnLogger`                                              | The logger that writes a line for each connection a logged rule admits; see [Connection logging](#connection-logging) |

The `bool` exists so callers cannot log an enforcement that never happened: both no-op paths return `(false, nil)`, which is indistinguishable from a successful apply on the error value alone.

Before the backend gets the rules, `ApplyFirewallRules` tags the logged ones and moves them ahead of the others; see [Log tags and rule order](#log-tags-and-rule-order).

### Preflight

`plexd up` calls `Preflight` before it registers, and aborts startup on an error.

The check exists because the baseline install is fatal but happens *after* registration, which spends a one-shot bootstrap token and persists the identity the control plane hands back. Without it, a node that can never install a chain claims an identity it will never use and then crash-loops on the same step; where `data_dir` is ephemeral, the restart has neither an identity to reload nor an unspent token to register with.

`Preflight` mirrors the no-op paths of `ApplyFirewallRules` exactly — with enforcement disabled or no backend compiled in there is no enforcement to be unable to perform — and it never mutates kernel state, so a node that goes on to fail startup for another reason leaves nothing behind.

### Behavior by State

| `IsEnabled()` | `firewall` | `Preflight`                  | `ApplyFirewallRules`          | `Teardown`          |
|---------------|------------|------------------------------|-------------------------------|---------------------|
| `true`        | non-nil    | Backend probed               | Rules applied, `(true, nil)`  | Chain removed       |
| `true`        | `nil`      | No-op, `nil`                 | No-op, `(false, nil)`         | No-op               |
| `false`       | any        | No-op, `nil`                 | No-op, `(false, nil)`         | No-op/chain removed |

### Error Prefixes

| Method              | Prefix               |
|---------------------|----------------------|
| `Preflight`         | `policy: preflight: `|
| `ApplyFirewallRules`| `policy: enforce: `  |
| `Teardown`          | `policy: teardown: ` |

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
- Filtering operates at **L3/L4** (CIDR, port, protocol) on the mesh interface: an nftables input chain, forward chain and output chain on `plexd0` on Linux, pf rules on the kernel's `utunN` on macOS, WFP filters on the Wintun adapter on Windows.
- On all three platforms the rules govern mesh traffic addressed to the node itself, the mesh traffic it forwards, and what the node's own sockets send over the mesh. A node therefore rejects unsolicited mesh traffic to its own addresses until a rule allows it, and it drops what it sends to a mesh address until a rule allows that too; see [What the rules govern](./pf-wfp-firewall.md#what-the-rules-govern). On Linux the replies to a connection the node, or a host behind it, opened pass through connection tracking without a rule of their own, and so do the replies the node sends to a connection the policy let in; see [Connection Tracking](./nftables-firewall.md#connection-tracking). On macOS only TCP keeps state: the node's own TCP connections keep their replies, and the replies to what a rule lets in leave through stateless mirror lines. On Windows those replies leave through the ALE flow the inbound accept authorized.
- What the node forwards into the mesh is not filtered on its way out: traffic from a user-access client, a site-to-site peer or a host behind a bridge, and on Linux a container or Pod masqueraded onto the node's mesh address. On Linux the output chain also lets out unfiltered what leaves the mesh interface from a source that is not one of its addresses, such as a Pod's packet IPVS sends to a Service endpoint behind the mesh; see [Connection Tracking](./nftables-firewall.md#connection-tracking).
- plexd's relay liveness probe, UDP to port 9 (`RelayProbePort`), leaves the mesh interface without a rule on every platform; see [Relay liveness probe](./wireguard.md#relay-liveness-probe).
- A rule with `log: true` makes plexd log each connection it allows, at a bounded rate, on Linux and macOS; Windows enforces it without logging; see [Connection logging](#connection-logging).
- Every rule is an allow and rule order carries no meaning. The default stance is **deny-all**: the ruleset always ends with a default-deny rule that covers IPv4 and IPv6, and a `null` policy applies the default-deny-only ruleset.
- Rules may name IPv4 or IPv6 prefixes on Linux, macOS and Windows. A peer's allowed IPs are its IPv4 mesh address alone today, so an IPv6 rule governs IPv6 traffic only once the mesh carries it.
- Peer membership is **not** governed by policy — it comes from the snapshot `peers` block via `wireguard.ReconcileHandler`. Policy rules are CIDR-scoped, not node-ID references.
- On a genuine policy change (fingerprint mismatch), plexd rebuilds the nftables ruleset from the merged policy. Revision-only bumps short-circuit and leave the ruleset untouched.

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
| `api.PolicyRule` | `internal/api` | Allow rule: `protocol`, `source_cidr`, `destination_cidr`, `ports?`, `log?`; a legacy `action` key lands in `LegacyAction` |
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
