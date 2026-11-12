---
title: nftables Firewall Controller
package: internal/policy
feature: PXD-0027
---

# nftables Firewall Controller

`NftablesController` is the Linux production implementation of the `FirewallController` interface defined in `internal/policy`. It translates `FirewallRule` entries into nftables expressions and manages them via the `github.com/google/nftables` netlink library. The macOS and Windows implementations are described in [pf & WFP Firewall Controllers](./pf-wfp-firewall.md).

The controller works in the table `plexd` of the `inet` family (`nftables.TableFamilyINet`), which sees IPv4 and IPv6 packets alike. For a configured chain name it creates two base chains, `<chain>-input` on the input hook and `<chain>-forward` on the forward hook, both `ChainTypeFilter` at `ChainPriorityFilter` with policy accept. The input chain governs mesh traffic addressed to the node itself, the forward chain the mesh traffic the node forwards. It requires `CAP_NET_ADMIN` and the `//go:build linux` constraint.

## Architecture

```
PolicyEngine
     │
     ▼
┌──────────────┐     ┌────────────────────┐
│ FirewallRule  │────▶│ NftablesController │
│   (slice)    │     └────────┬───────────┘
└──────────────┘              │
                              ▼
                    ┌──────────────────────────┐
                    │  nftables (nfnl)         │
                    │  table: plexd            │
                    │  family: inet            │
                    │  chains: <chain>-input   │
                    │          <chain>-forward │
                    └──────────────────────────┘
```

The `Enforcer` calls `NftablesController` methods during policy reconciliation. Each method opens a fresh netlink connection, batches operations, and commits atomically via `Flush()`.

## Constructor

```go
func NewNftablesController(logger *slog.Logger) *NftablesController
```

Logger entries use `component=policy`.

## Interface Implementation

`NftablesController` implements `FirewallController`. `chainNames(chain)` derives the two chain names from the configured one, and every method acts on both.

| Method        | nftables Operation                                                    |
|---------------|-----------------------------------------------------------------------|
| `Probe`       | `ListTablesOfFamily(INet)`, read-only                                 |
| `EnsureChain` | `ListTablesOfFamily(IPv4)`, then in one batch `DelTable` of `ip plexd` if listed, `AddTable` and `AddChain` for both chains, `Flush` |
| `ApplyRules`  | `AddTable` + `AddChain` and `FlushChain` for both chains + `AddRule` per rule into each + `Flush` |
| `FlushChain`  | `AddTable` + `FlushChain` for both chains + `Flush`                   |
| `DeleteChain` | `ListChainsOfTableFamily(INet)` → `DelChain` for each chain found + `Flush` |

### Probe

Dumps the `inet` table list and discards the result. nfnetlink gates every message on `CAP_NET_ADMIN`, dumps included, so a dropped capability or a kernel that does not offer the `nf_tables` subsystem fails here exactly as it would on the first `EnsureChain`, but without adding a table to a batch first.

`Enforcer.Preflight` calls this before `plexd up` registers, so a node that cannot enforce policy exits before it spends a bootstrap token. The read-only shape is deliberate: a node that goes on to fail startup for another reason must not leave a table behind.

### EnsureChain

Builds one batch. It first lists the tables of the `ip` family. When that listing names `plexd`, the batch deletes that table: a plexd before this release kept its chain there, on the forward hook alone, and leaves the table behind, after a crash with the chain and its final drop still in it. That drop would still drop what the new chains accept. The batch then adds the `inet plexd` table and both base chains. Adding a table or a chain that already exists is a no-op in nftables.

A failed listing returns `policy: nftables: ensure chain: list tables: <error>`. Without `CAP_NET_ADMIN` that is where `EnsureChain` fails.

### ApplyRules

Atomically replaces the rules of both chains with the same list:

1. Ensures the table and both chains exist
2. Flushes both chains
3. Validates each `FirewallRule` and converts it into nftables expressions
4. Writes, into each chain, the two [connection tracking rules](#connection-tracking) once per distinct `Interface` among the rules, in order of first appearance, and then one rule per `FirewallRule` in the order given
5. Commits everything in one batch via `Flush()`

If validation or expression building fails for any rule (an invalid address, mixed families, an unsupported protocol or action), the whole operation is aborted before `Flush()`, and the chains keep the rules they had.

The kernel holds the list twice. For n policy rules on one interface that is 2 × (n + 3) rules: the n rules, the two connection tracking rules and the default deny, in each chain. A packet is evaluated only by the chain whose hook it takes. plexd sets no cap of its own on n; the control plane's compile bounds it.

### FlushChain and DeleteChain

`FlushChain` empties both chains. `DeleteChain` lists the chains of the `inet` family and deletes the two that belong to the configured name in table `plexd`. It returns `nil` when neither exists, so a second call is a no-op. The empty `inet plexd` table stays.

## Connection Tracking

Each chain starts with two rules per interface:

```
iifname "plexd0" ct state established ct direction reply counter accept
iifname "plexd0" ct state related counter accept
```

`connTrackExprs(iface)` builds them. The first passes a packet in the reply direction of a connection the kernel tracks: the replies to a connection the node opened over the mesh, or that a host behind the node opened through it. Neither needs a policy rule of its own. The second passes a packet the kernel relates to a tracked connection, such as an ICMP error about it, in either direction.

Only the reply direction bypasses the rules. A packet in a connection's original direction is matched against the rules every time, so a revoked rule cuts an established inbound or forwarded connection at its next packet, as the stateless chain of earlier releases did. Accepting every established packet instead would keep a revoked connection alive until conntrack forgets it. For the same reason plexd flushes no conntrack entry when a ruleset changes.

What the node sends is not filtered: the chains match the arrival interface, and plexd has no output chain. Filtering outbound mesh traffic is plexsphere/plexd#178.

## Rule Translation

Each `FirewallRule` is converted to a sequence of nftables expressions. Every address goes through `parseRuleAddr`, which the three backends share, so a rejected address reads the same on every platform.

| FirewallRule Field | nftables Expression                                       | Condition            |
|--------------------|-----------------------------------------------------------|----------------------|
| `Interface`        | `Meta(IIFNAME)` + `Cmp`                                  | Non-empty            |
| (family)           | `Meta(NFPROTO)` + `Cmp` against `ipv4` or `ipv6`          | At least one address |
| `SrcIP`            | `Payload(NetworkHeader)` + `Cmp`, or + `Bitwise` + `Cmp`  | Prefix length above 0 |
| `DstIP`            | `Payload(NetworkHeader)` + `Cmp`, or + `Bitwise` + `Cmp`  | Prefix length above 0 |
| `Protocol`         | `Meta(L4PROTO)` + `Cmp`                                  | Non-empty            |
| `Port`, `PortTo`   | `Payload(TransportHeader, offset=2)` + `Cmp`, or two `Cmp` for a range | `Port > 0` |
| (always)           | `Counter`                                                 | Always appended      |
| `Action`           | `Verdict(Accept)` or `Verdict(Drop)`                     | `"allow"` or `"deny"`|

### IP Address Matching

| Input Format              | Family match        | Address match                                            |
|---------------------------|---------------------|----------------------------------------------------------|
| `10.0.0.1`, `10.0.0.1/32` | `meta nfproto ipv4` | 4 bytes at offset 12 (source) or 16 (destination), exact |
| `10.0.0.0/24`             | `meta nfproto ipv4` | The same 4 bytes through a mask, compared with the network address |
| `0.0.0.0/0`               | `meta nfproto ipv4` | None                                                     |
| `fd00::1`, `fd00::1/128`  | `meta nfproto ipv6` | 16 bytes at offset 8 (source) or 24 (destination), exact |
| `fd00::/64`               | `meta nfproto ipv6` | The same 16 bytes through a mask, compared with the network address |
| `::/0`                    | `meta nfproto ipv6` | None                                                     |
| Both fields empty         | None                | None, so the rule covers both families                   |

A zero-length prefix is every address of its family: the rule still matches that family alone. Both addresses of a rule name one family. An IPv4-mapped IPv6 address such as `::ffff:10.0.0.1`, an address with a zone, and two addresses of different families are rejected.

### Protocol Mapping

| String   | Family | IP Protocol Number    |
|----------|--------|-----------------------|
| `"tcp"`  | either | `6` (IPPROTO_TCP)     |
| `"udp"`  | either | `17` (IPPROTO_UDP)    |
| `"icmp"` | IPv4   | `1` (IPPROTO_ICMP)    |
| `"icmp"` | IPv6   | `58` (IPPROTO_ICMPV6) |

`protocolNumber(proto, family)` does the mapping. A rule with protocol `icmp` and no address names neither family, so `Validate` rejects it. Unsupported protocols cause `ApplyRules` to return an error.

## nftables Table Layout

For the chain name `plexd-mesh` on `plexd0`, with one IPv4 and one IPv6 rule, in nft syntax:

```
table inet plexd {
    chain plexd-mesh-input {
        type filter hook input priority filter; policy accept;
        iifname "plexd0" ct state established ct direction reply counter accept
        iifname "plexd0" ct state related counter accept
        iifname "plexd0" meta nfproto ipv4 ip saddr 10.99.0.0/24 ip daddr 10.99.0.1 meta l4proto tcp th dport 443 counter accept
        iifname "plexd0" meta nfproto ipv6 ip6 saddr fd00:99::/64 ip6 daddr fd00:99::1 meta l4proto tcp th dport 443 counter accept
        iifname "plexd0" counter drop
    }
    chain plexd-mesh-forward {
        type filter hook forward priority filter; policy accept;
        # the same five rules
    }
}
```

The last rule is the default deny. It carries no address, so it drops IPv4 and IPv6 alike. The table name `plexd` is a package-level constant. The chain names come from `Config.ChainName` (default: `plexd-mesh`).

Inspect the chains with:

```bash
sudo nft list table inet plexd
```

nft prints the rules in its own form, which can leave out a match the next one implies. Every rule carries a counter, so the listing shows the packets and bytes each rule matched, and the counter of the final `drop` is what the policy dropped on that hook.

## Host Requirements

- `nf_tables` with the `inet` family.
- Connection tracking: `nf_conntrack` and `nft_ct`. The kernel loads them itself when the first `ct` rule arrives, and from then on it tracks every connection on the host, mesh or not. A kernel that cannot load `nft_ct` fails the batch: `ApplyRules` returns `policy: nftables: apply rules to chain "<chain>": <error>`, and the deny-by-default baseline in `plexd up` aborts startup, as it does for any refused chain.
- `CAP_NET_ADMIN`, as before. Neither the systemd unit nor the Kubernetes manifests change: `plexd.service` already grants the capability, and a module load the kernel requests itself is not one a unit's `ProtectKernelModules=` would block.

Traffic the node sends to its own mesh address arrives on `lo`, which the chains do not match. A local client of a service bound to the mesh IP, such as the [mesh DNS resolver](./mesh-dns.md) or a tcp tunnel listener, is therefore not filtered. A mesh peer's traffic to the same service is, and needs a rule.

## Downgrade

A plexd before this release knows only the `ip plexd` table. After a clean stop this release has deleted its two chains, and the empty `inet plexd` table it leaves drops nothing. After a crash both chains stay in place with their default deny, and an earlier binary neither sees nor removes them. An operator who downgrades after a crash removes them with:

```bash
sudo nft delete table inet plexd
```

## Error Prefixes

| Method        | Prefix                                           |
|---------------|--------------------------------------------------|
| `Probe`       | `policy: nftables: probe`                        |
| `EnsureChain` | `policy: nftables: ensure chain`, and `policy: nftables: ensure chain: list tables` when the `ip` table listing fails |
| `ApplyRules`  | `policy: nftables: apply rules`                  |
| `FlushChain`  | `policy: nftables: flush chain`                  |
| `DeleteChain` | `policy: nftables: delete chain`                 |

## Dependencies

| Package                        | Usage                          |
|--------------------------------|--------------------------------|
| `github.com/google/nftables`  | Netlink-based nftables control |
| `github.com/google/nftables/expr` | Rule expression types      |
| `golang.org/x/sys/unix`       | Protocol number constants      |

## Privileges

All methods require `CAP_NET_ADMIN`. When running without privileges, methods return permission errors wrapped with the appropriate error prefix. Tests that need the privilege to succeed skip with `t.Skipf` when it is missing.

## Tests

Every test in `nftables_linux_test.go` that calls the controller runs through `inTestNetns(t, fn)`, which runs `fn` on the test's own goroutine, locked to a thread moved into a fresh network namespace. Run as root, those tests therefore never change the host's tables, and `EnsureChain` never deletes the `ip plexd` table of a live older plexd. A process that may not create a namespace and lacks `CAP_NET_ADMIN` runs `fn` in place, where every nftables call fails with the permission error the unprivileged assertions expect. A process that holds `CAP_NET_ADMIN` but may not create a namespace, such as a container granted `NET_ADMIN` alone, skips the test rather than change its ruleset.

`TestNftablesController_Real` (`nftables_real_linux_test.go`) drives the real kernel. It runs only with `PLEXD_TEST_REAL_NFTABLES=1` and an effective uid of 0. It builds three network namespaces with `github.com/vishvananda/netlink` and `github.com/vishvananda/netns`: a peer P, joined by a veth pair to the node N's `plexd0` (10.99.0.2/24 and fd00:99::2/64 on P, 10.99.0.1/24 and fd00:99::1/64 on N), and an external host E behind N's `lan0` (192.0.2.1/24 on N, 192.0.2.2/24 on E). N forwards IPv4. Every link is created inside the test's namespaces, never in the host's, which may run a live `plexd0`, and the controller runs on a goroutine locked to N. The test shows that:

- P connects to 10.99.0.1:7001 and [fd00:99::1]:7001, which rules allow, and times out within 2 s on 7002 over both families while listeners run there.
- P connects through N to E at 192.0.2.2:8001, which a rule allows, and times out on 8002.
- N connects to a listener on P at 10.99.0.2:9001, and E connects through N to P at 10.99.0.2:9002, with no rule naming either direction, and N reaches its own 10.99.0.1:7002 under the default-deny-only ruleset.
- After `ApplyRules` drops the 7001 rule, bytes P writes on an already established 7001 connection do not reach N within 2 s.
- With a table `ip plexd` created first, holding a forward chain that drops everything from `plexd0`, `EnsureChain` removes it, and P reaches E on 8001.
- After `DeleteChain`, P connects to 10.99.0.1:7002 again, and a second `DeleteChain` returns `nil`.

Locally:

```bash
sudo PLEXD_TEST_REAL_NFTABLES=1 go test -run TestNftablesController_Real ./internal/policy/
```

CI runs it in the step "Run privileged Linux tests"; see [CI Workflow](../development/ci-workflow.md).

## Usage

```go
logger := slog.Default()
ctrl := policy.NewNftablesController(logger)

enforcer := policy.NewEnforcer(engine, ctrl, policy.Config{}, logger)
```
