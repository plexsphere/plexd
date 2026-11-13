---
title: nftables Firewall Controller
package: internal/policy
feature: PXD-0027
---

# nftables Firewall Controller

`NftablesController` is the Linux production implementation of the `FirewallController` interface defined in `internal/policy`. It translates `FirewallRule` entries into nftables expressions and manages them via the `github.com/google/nftables` netlink library. The macOS and Windows implementations are described in [pf & WFP Firewall Controllers](./pf-wfp-firewall.md).

The controller works in the table `plexd` of the `inet` family (`nftables.TableFamilyINet`), which sees IPv4 and IPv6 packets alike. For a configured chain name it creates three base chains, `<chain>-input` on the input hook, `<chain>-forward` on the forward hook and `<chain>-output` on the output hook, all `ChainTypeFilter` at `ChainPriorityFilter` with policy accept. The input chain governs mesh traffic addressed to the node itself, the forward chain the mesh traffic the node forwards, and the output chain what the node's own sockets send over the mesh. It requires `CAP_NET_ADMIN` and the `//go:build linux` constraint.

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
                    │          <chain>-output  │
                    └──────────────────────────┘
```

The `Enforcer` calls `NftablesController` methods during policy reconciliation. Each method opens a fresh netlink connection, batches operations, and commits atomically via `Flush()`. The only state the controller keeps is the sink for [connection logging](#connection-logging) and the NFLOG reader that feeds it.

## Constructor

```go
func NewNftablesController(logger *slog.Logger) *NftablesController
```

Logger entries use `component=policy`.

## Interface Implementation

`NftablesController` implements `FirewallController`, `ConnReporter` through `SetConnSink`, which stores the sink its [NFLOG reader](#connection-logging) hands events to, and `DropCounter` through [`DropCounts`](#dropcounts). `chainNames(chain)` derives the three chain names from the configured one, and every method acts on all three.

| Method        | nftables Operation                                                    |
|---------------|-----------------------------------------------------------------------|
| `Probe`       | `ListTablesOfFamily(INet)`, read-only                                 |
| `EnsureChain` | `ListTablesOfFamily(IPv4)`, then in one batch `DelTable` of `ip plexd` if listed, `AddTable` and `AddChain` for all three chains, `Flush` |
| `ApplyRules`  | `chainRuleExprs` for both lists, then on a socket sized by `applyBufferBytes`: `AddTable` + `AddChain` and `FlushChain` for all three chains + `AddRule` per rule of the input list into the input and forward chains and of the output list into the output chain + `Flush` |
| `FlushChain`  | `ListChainsOfTableFamily(INet)` → `FlushChain` for each chain found + `Flush` |
| `DeleteChain` | `ListChainsOfTableFamily(INet)` → `DelChain` for each chain found + `Flush`; closes the NFLOG reader, also when no chain exists |
| `DropCounts`  | `GetRules` for each of the three chains, read-only, then `sumDropCounters` over the rules |

### Probe

Dumps the `inet` table list and discards the result. nfnetlink gates every message on `CAP_NET_ADMIN`, dumps included, so a dropped capability or a kernel that does not offer the `nf_tables` subsystem fails here exactly as it would on the first `EnsureChain`, but without adding a table to a batch first.

`Enforcer.Preflight` calls this before `plexd up` registers, so a node that cannot enforce policy exits before it spends a bootstrap token. The read-only shape is deliberate: a node that goes on to fail startup for another reason must not leave a table behind.

### EnsureChain

Builds one batch. It first lists the tables of the `ip` family. When that listing names `plexd`, the batch deletes that table: a plexd before this release kept its chain there, on the forward hook alone, and leaves the table behind, after a crash with the chain and its final drop still in it. That drop would still drop what the new chains accept. The batch then adds the `inet plexd` table and all three base chains. Adding a table or a chain that already exists is a no-op in nftables.

A failed listing returns `policy: nftables: ensure chain: list tables: <error>`. Without `CAP_NET_ADMIN` that is where `EnsureChain` fails.

### ApplyRules

Atomically replaces the rules of all three chains. It builds two lists from the same rules before it touches the batch. The input list matches the interface a packet arrives on (`meta iifname`), and the output list the interface a packet leaves through (`meta oifname`):

1. Validates each `FirewallRule` and converts it into nftables expressions, once for each list: `chainRuleExprs(rules, dirIn)` and `chainRuleExprs(rules, dirOut)`
2. Opens each list with the two [connection tracking rules](#connection-tracking) once per distinct `Interface` among the rules, in order of first appearance. The output list follows them with that interface's foreign-source rule and relay probe rule. One rule per `FirewallRule` follows, in the order given, and a rule with a `LogTag` has its [log rule](#log-rules) directly in front of it
3. Ensures the table and all three chains exist
4. Flushes all three chains
5. Writes the input list into the input and forward chains, and the output list into the output chain
6. Commits everything in one batch via `Flush()`, so the three chains change together or not at all

If validation or expression building fails for any rule (an invalid address, mixed families, an unsupported protocol or action), the whole operation is aborted before `Flush()`, and the chains keep the rules they had. The error texts are the same for both lists.

When a rule carries a `LogTag` and no NFLOG reader runs, `ApplyRules` opens one. If no sink is set or the reader does not open, it writes the rules without their tags, so no log rule reaches the kernel, and on a failed open it logs `policy connection logging unavailable, logged rules are enforced without it` at Warn with `error`. See [Connection Logging](#connection-logging).

For n policy rules on one interface the kernel holds 3n + 11 rules: n + 3 in each of the input and forward chains (the n rules, the two connection tracking rules and the default deny), and n + 5 in the output chain, which adds the foreign-source rule and the relay probe rule. Each logged rule adds its log rule to all three chains, so m logged rules make it 3(n + m) + 11. A packet is evaluated only by the chain whose hook it takes. plexd sets no cap of its own on n; the control plane's compile bounds it.

The kernel echoes every rule add back on the batch's netlink socket, and the echoes queue there until the batch is acknowledged. With the default socket buffers a batch failed with `ENOBUFS` or `EMSGSIZE` from about 55 policy rules with two chains, and from about 40 with three, measured on Linux 6.8. `ApplyRules` therefore sizes the socket to the batch. `applyBufferBytes` returns 1 MiB plus 8 KiB per rule the batch adds, counting the input list twice and the output list once. `sizeSocketBuffers` sets the send and receive buffers to that size with `SO_SNDBUFFORCE` and `SO_RCVBUFFORCE`, which go past the host's `net.core.wmem_max` and `net.core.rmem_max` and need `CAP_NET_ADMIN`. Without the capability it falls back to `SO_SNDBUF` and `SO_RCVBUF`, which the host caps. The option never returns an error, because google/nftables v0.3.0 leaves the netlink socket open when one does. A batch that still does not fit fails on its own, with the kernel's `ENOBUFS` or `EMSGSIZE` in the error `ApplyRules` returns. `TestNftablesController_Real` applies 1000 policy rules in one batch.

### FlushChain and DeleteChain

`FlushChain` lists the chains of the `inet` family and empties those of the three that exist in table `plexd`, skipping the others, and returns `nil` when none exists. So `Enforcer.Teardown` reaches `DeleteChain` also where only some exist, such as the two chains of a plexd before the output chain. `DeleteChain` lists the chains the same way and deletes those of the three that belong to the configured name in table `plexd`. It returns `nil` when none exists, so a second call is a no-op. The empty `inet plexd` table stays.

### DropCounts

`DropCounts(chain)` returns the packets and bytes the default deny dropped, which the Enforcer sends as `drops` in the [policy status report](./network-policy.md#policy-status-report). It opens a netlink connection, calls `GetRules` for `<chain>-input`, `<chain>-forward` and `<chain>-output` in table `inet plexd`, and returns `sumDropCounters` over the rules of all three: the sum of the `expr.Counter` of every rule whose last expression is an `expr.Verdict` of kind `VerdictDrop`. Every rule but a log rule ends in a counter and a verdict, and the default deny is the only rule with a drop verdict, so the sum is what the default deny dropped on the three hooks. Rules that end in accept are not counted. The read changes nothing.

`ApplyRules` flushes the three chains and adds every rule anew, so the counters restart from 0 whenever it replaces the chains. The control plane reads a count below the previous one as such a restart. A failed read returns `policy: nftables: drop counts: <cause>`, and the Enforcer logs it as `policy drop counters unavailable`; see [DropCounts](./network-policy.md#dropcounts).

## Connection Tracking

Each chain starts with two rules per interface. The input and forward chains match the interface a packet arrives on:

```
iifname "plexd0" ct state established ct direction reply counter accept
iifname "plexd0" ct state related counter accept
```

The output chain matches the interface a packet leaves through, and follows the two rules with the foreign-source rule and the relay probe rule:

```
oifname "plexd0" ct state established ct direction reply counter accept
oifname "plexd0" ct state related counter accept
oifname "plexd0" fib saddr . oif type != local counter accept
oifname "plexd0" meta l4proto udp th dport 9 counter accept
```

`connTrackExprs(iface, dir)` builds the first two. The first passes a packet in the reply direction of a connection the kernel tracks. In the input and forward chains those are the replies to a connection the node opened over the mesh, or that a host behind the node opened through it. In the output chain they are the replies the node sends to a connection the policy let in. None needs a policy rule of its own. The second passes a packet the kernel relates to a tracked connection, such as an ICMP error about it, in either direction.

Only the reply direction bypasses the rules. A packet in a connection's original direction is matched against the rules every time, so a revoked rule cuts an established inbound or forwarded connection at its next packet, as the stateless chain of earlier releases did. The output chain does the same for a connection the node's own sockets opened. Accepting every established packet instead would keep a revoked connection alive until conntrack forgets it. For the same reason plexd flushes no conntrack entry when a ruleset changes.

The third rule, built by `foreignSourceExprs(iface)`, lets a packet out unfiltered when its source is not an address of the mesh interface. `fib saddr . oif type` asks the routing table for the type of the source address on the outgoing interface, which is `local` only for an address assigned to that interface, so the node's mesh address is filtered and any other source is not. IPVS sends a Pod's packet to a Service endpoint behind the mesh through the output hook with the Pod's address as source, and a socket can bind another address of the node. Masquerade gives such a packet the mesh address only at postrouting, after the output chain, so no rule could match it. It leaves as forwarded traffic leaves, and a packet that still carries a foreign source when it leaves is dropped by the receiving peer's WireGuard, which accepts from a peer only the addresses it allows for that peer. kube-proxy's DNAT of a host-network connection to a Service never meets the output chain as `plexd0` traffic: the filter chains of the output hook see the interface of the route the connection started on.

The fourth rule is the relay probe exemption, built from `relayProbeRule(iface)`: UDP to port 9, `RelayProbePort`, with no address, so it covers IPv4 and IPv6. It lets plexd's [relay liveness probe](./wireguard.md#relay-liveness-probe) out ahead of the policy rules. Any local process can send to that port, to any address the mesh routes, and the receiving node's inbound rules still apply.

The output chain filters only what the node itself sends from an address of the mesh interface: the packets of its own sockets, and the ICMP errors and TCP resets its kernel generates, which pass as related or reply traffic. A packet the node forwards into the mesh takes the forward hook instead, whose chain matches the interface the packet arrived on. Traffic forwarded out through the mesh is therefore not filtered on its way out, whether it comes from a user-access client, a site-to-site peer, a host behind a bridge, or a container or Pod masqueraded onto the node's mesh address.

A drop in the output chain reaches the local program. A blocked UDP or ICMP send fails with `operation not permitted` (`EPERM`). A blocked TCP connect does not fail at once: the kernel retransmits the SYN until the connect times out. The counter of the chain's final `drop` shows what the policy dropped:

```bash
sudo nft list chain inet plexd plexd-mesh-output
```

## Rule Translation

Each `FirewallRule` is converted to a sequence of nftables expressions. Every address goes through `parseRuleAddr`, which the three backends share, so a rejected address reads the same on every platform.

| FirewallRule Field | nftables Expression                                       | Condition            |
|--------------------|-----------------------------------------------------------|----------------------|
| `Interface`        | `Meta(IIFNAME)` + `Cmp` in the input list, `Meta(OIFNAME)` + `Cmp` in the output list | Non-empty |
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

### Log Rules

A rule with a `LogTag` gets a log rule directly in front of it, in both lists. `logRuleExprs(rule, dir)` builds it from the rule's own matches, without the counter and the verdict, and appends:

| Expression | Meaning |
|---|---|
| `Ct(STATE)` + `Bitwise` + `Cmp` on the new bit | Only a packet of a connection conntrack has not yet seen answered |
| `Log{Group: 28772, Data: <LogTag>}` | Hands the packet to NFLOG group 28772, `nflogGroup` (ASCII `pd`), with the tag as its prefix |

The log rule carries no verdict, so evaluation goes on to the rule itself, which accepts the packet. A logged rule therefore logs the first packet of each connection it admits, and every later packet of a flow that has not been answered yet. The connection tracking rules ahead of it pass the replies before they reach it.

## nftables Table Layout

For the chain name `plexd-mesh` on `plexd0`, with one IPv4 and one IPv6 rule, the IPv4 one logged with the tag `1/0`, in nft syntax:

```
table inet plexd {
    chain plexd-mesh-input {
        type filter hook input priority filter; policy accept;
        iifname "plexd0" ct state established ct direction reply counter accept
        iifname "plexd0" ct state related counter accept
        iifname "plexd0" meta nfproto ipv4 ip saddr 10.99.0.0/24 ip daddr 10.99.0.1 meta l4proto tcp th dport 443 ct state new log prefix "1/0" group 28772
        iifname "plexd0" meta nfproto ipv4 ip saddr 10.99.0.0/24 ip daddr 10.99.0.1 meta l4proto tcp th dport 443 counter accept
        iifname "plexd0" meta nfproto ipv6 ip6 saddr fd00:99::/64 ip6 daddr fd00:99::1 meta l4proto tcp th dport 443 counter accept
        iifname "plexd0" counter drop
    }
    chain plexd-mesh-forward {
        type filter hook forward priority filter; policy accept;
        # the same six rules
    }
    chain plexd-mesh-output {
        type filter hook output priority filter; policy accept;
        oifname "plexd0" ct state established ct direction reply counter accept
        oifname "plexd0" ct state related counter accept
        oifname "plexd0" fib saddr . oif type != local counter accept
        oifname "plexd0" meta l4proto udp th dport 9 counter accept
        oifname "plexd0" meta nfproto ipv4 ip saddr 10.99.0.0/24 ip daddr 10.99.0.1 meta l4proto tcp th dport 443 ct state new log prefix "1/0" group 28772
        oifname "plexd0" meta nfproto ipv4 ip saddr 10.99.0.0/24 ip daddr 10.99.0.1 meta l4proto tcp th dport 443 counter accept
        oifname "plexd0" meta nfproto ipv6 ip6 saddr fd00:99::/64 ip6 daddr fd00:99::1 meta l4proto tcp th dport 443 counter accept
        oifname "plexd0" counter drop
    }
}
```

The last rule is the default deny. It carries no address, so it drops IPv4 and IPv6 alike. The table name `plexd` is a package-level constant. The chain names come from `Config.ChainName` (default: `plexd-mesh`).

The output chain holds the same policy rules as the other two. A rule matches by its addresses, so the rules above, whose destination is the node, match nothing there. The node's own copy of a rule names the node as the source, and that copy is the one that matches there.

The `Enforcer` puts the logged rules ahead of the unlogged ones (see [Log tags and rule order](./network-policy.md#log-tags-and-rule-order)), so a logged rule and its log rule come first among the policy rules.

Inspect the chains with:

```bash
sudo nft list table inet plexd
```

nft prints the rules in its own form, which can leave out a match the next one implies. Every rule but a log rule carries a counter, so the listing shows the packets and bytes each rule matched, and the counter of the final `drop` is what the policy dropped on that hook. [`DropCounts`](#dropcounts) sums the three final `drop` counters for the policy status report.

## Connection Logging

The controller reports the connections its logged rules admit over NFLOG; see [Connection logging](./network-policy.md#connection-logging) for the line plexd writes. `nflog_linux.go` holds the reader, with the constants of the kernel's `linux/netfilter/nfnetlink_log.h`, which `golang.org/x/sys/unix` lacks.

`openNflog` dials `NETLINK_NETFILTER` on `github.com/mdlayher/netlink` in the caller's network namespace and raises the socket's read buffer to 1 MiB. It sends two acknowledged config messages to group 28772: `NFULA_CFG_CMD` with `BIND`, then `NFULA_CFG_MODE` with a copy range of 128 bytes and the mode `COPY_PACKET`. The kernel then sends the reader the first 128 bytes of each logged packet, enough for the IP header and the ports behind it. A failed open returns `policy: nftables: nflog: bind group 28772: <error>`, with the kernel's `operation not permitted` (`EPERM`) when another process holds the group. The reader then starts on its own goroutine.

For each packet message, `parseNflogPacket` takes:

| Attribute | What it gives |
|---|---|
| `NFULA_PACKET_HDR`, its hook byte | The direction: hook 1 (input) is `in`, 2 (forward) is `forward`, 3 (output) is `out`. Any other hook is dropped |
| `NFULA_PREFIX` | The tag, up to its NUL |
| `NFULA_PAYLOAD` | The addresses, the protocol and the ports, read by `parseIPTuple` |

A message of another type, one without one of the three attributes, or a payload `parseIPTuple` refuses is dropped. An overrun of the socket, `ENOBUFS`, counts one lost record in the [minute summary](./network-policy.md#rate-limit), and the reader goes on. Any other read error logs `policy connection log reader stopped` at Warn with `error` and ends the reader, and the next apply with a logged rule opens a new one. `DeleteChain` closes the reader, also when no chain existed.

## Host Requirements

- `nf_tables` with the `inet` family.
- Connection tracking: `nf_conntrack` and `nft_ct`. The kernel loads them itself when the first `ct` rule arrives, and from then on it tracks every connection on the host, mesh or not. A kernel that cannot load `nft_ct` fails the batch: `ApplyRules` returns `policy: nftables: apply rules to chain "<chain>": <error>`, and the deny-by-default baseline in `plexd up` aborts startup, as it does for any refused chain.
- `CAP_NET_ADMIN`, as before. Neither the systemd unit nor the Kubernetes manifests change: `plexd.service` already grants the capability, and a module load the kernel requests itself is not one a unit's `ProtectKernelModules=` would block. The same capability lets `ApplyRules` raise its netlink socket buffers past the host's limits.
- The routing table lookup of the foreign-source rule: `nft_fib` and `nft_fib_inet`. The kernel loads them itself when the first `fib` rule arrives. A kernel that cannot load them fails the batch the same way a kernel without `nft_ct` does.
- For [connection logging](#connection-logging): `nfnetlink_log` and NFLOG group 28772. The kernel loads `nfnetlink_log` itself when plexd binds the group, and `nft_log` when the first log rule arrives. The bind needs `CAP_NET_ADMIN`, which plexd already holds. A kernel that cannot load `nfnetlink_log` fails the reader's open, not the batch. Only one process can bind a group: when another process, such as ulogd, holds group 28772, the bind fails with `operation not permitted` (`EPERM`), and plexd's connection logging is off. plexd then logs `policy connection logging unavailable, logged rules are enforced without it` at Warn on every apply that holds a logged rule, and writes the rules without their log rules, so the other process never receives plexd's records.

Traffic the node sends to its own mesh address leaves through and arrives on `lo`, which the chains do not match. A local client of a service bound to the mesh IP, such as the [mesh DNS resolver](./mesh-dns.md) or a tcp tunnel listener, is therefore not filtered. A mesh peer's traffic to the same service is, and needs a rule.

## Downgrade

A plexd before the `inet` table knows only the `ip plexd` table, and a plexd before the output chain knows only the input and forward chains. After a clean stop this release has deleted its three chains, and the empty `inet plexd` table it leaves drops nothing. After a crash all three chains stay in place with their default deny. A binary before the `inet` table neither sees nor removes them. A binary before the output chain rewrites and deletes the input and forward chains, but leaves the output chain and its default deny in place, so the node keeps dropping what it sends that the last ruleset of this release did not allow. An operator who downgrades after a crash removes them with:

```bash
sudo nft delete table inet plexd
```

The command deletes the whole table, so it also removes the output chain an older plexd does not know.

## Error Prefixes

| Method        | Prefix                                           |
|---------------|--------------------------------------------------|
| `Probe`       | `policy: nftables: probe`                        |
| `EnsureChain` | `policy: nftables: ensure chain`, and `policy: nftables: ensure chain: list tables` when the `ip` table listing fails |
| `ApplyRules`  | `policy: nftables: apply rules`                  |
| `FlushChain`  | `policy: nftables: flush chain`                  |
| `DeleteChain` | `policy: nftables: delete chain`                 |
| `DropCounts`  | `policy: nftables: drop counts`                  |

The NFLOG reader's open fails with `policy: nftables: nflog: bind group 28772: <error>`. `ApplyRules` does not return it: it logs it as the `error` of `policy connection logging unavailable, logged rules are enforced without it` and applies the rules.

## Dependencies

| Package                        | Usage                          |
|--------------------------------|--------------------------------|
| `github.com/google/nftables`  | Netlink-based nftables control |
| `github.com/google/nftables/expr` | Rule expression types      |
| `github.com/mdlayher/netlink` | The netlink socket `sizeSocketBuffers` sizes, and the NFLOG reader's socket |
| `golang.org/x/sys/unix`       | Protocol number constants and socket options |

## Privileges

All methods require `CAP_NET_ADMIN`. When running without privileges, methods return permission errors wrapped with the appropriate error prefix. Tests that need the privilege to succeed skip with `t.Skipf` when it is missing.

## Tests

Every test in `nftables_linux_test.go` that calls the controller runs through `inTestNetns(t, fn)`, which runs `fn` on the test's own goroutine, locked to a thread moved into a fresh network namespace. Run as root, those tests therefore never change the host's tables, and `EnsureChain` never deletes the `ip plexd` table of a live older plexd. A process that may not create a namespace and lacks `CAP_NET_ADMIN` runs `fn` in place, where every nftables call fails with the permission error the unprivileged assertions expect. A process that holds `CAP_NET_ADMIN` but may not create a namespace, such as a container granted `NET_ADMIN` alone, skips the test rather than change its ruleset.

`TestSumDropCounters` needs no privilege either. It checks that `sumDropCounters` sums the counters of the rules that end in a drop verdict, ignores the rules that end in accept, and returns 0 packets and 0 bytes for an empty and for a nil rule list.

The connection logging tests need no privilege. `nftables_linux_test.go` checks that `chainRuleExprs` puts the log rule, ending in the new-state match and the log expression for group 28772 with the tag, directly in front of a tagged rule in both lists, and that an untagged ruleset yields the lists it yielded before. Through the `openLog` seam it checks that a reader that fails to open with `EBUSY`, and a controller without a sink, both make `ApplyRules` write the rules without their log rules, and that only the first logs the Warn line. `nflog_linux_test.go` pins the bytes of the two config messages, the hooks, tags and attributes `parseNflogPacket` accepts and refuses, and the read loop, fed a `receive` that returns `ENOBUFS` and then a packet, or another error.

`TestNftablesController_Real` (`nftables_real_linux_test.go`) drives the real kernel. It runs only with `PLEXD_TEST_REAL_NFTABLES=1` and an effective uid of 0. It builds three network namespaces with `github.com/vishvananda/netlink` and `github.com/vishvananda/netns`: a peer P, joined by a veth pair to the node N's `plexd0` (10.99.0.2/24 and fd00:99::2/64 on P, 10.99.0.1/24 and fd00:99::1/64 on N), and an external host E behind N's `lan0` (192.0.2.1/24 on N, 192.0.2.2/24 on E). N forwards IPv4. Every link is created inside the test's namespaces, never in the host's, which may run a live `plexd0`, and the controller runs on a goroutine locked to N. The rules include `allowOut9001`, N's own copy of a rule from N (10.99.0.1/32) to P (10.99.0.2/32) on TCP 9001, the copy the control plane compiles for the source node. The test shows that:

- P connects to 10.99.0.1:7001 and [fd00:99::1]:7001, which rules allow, and times out within 2 s on 7002 over both families while listeners run there. N's replies on 7001 leave through the output chain.
- P connects through N to E at 192.0.2.2:8001, which a rule allows, and times out on 8002. That rule, `allow8001`, carries the tag `9/0`, and the test's recording sink receives an event with that tag, direction forward, source 10.99.0.2, destination 192.0.2.2, protocol 6 and destination port 8001, which proves the forward hook's NFLOG records.
- N connects to P at 10.99.0.2:9001, which `allowOut9001` allows, and is blocked on 9003 while P listens there: the dial times out within 2 s or fails with `EPERM`, and is never refused.
- E connects through N to P at 10.99.0.2:9002 with no rule naming that direction, so what N forwards out of `plexd0` is not filtered on its way out.
- With no rule naming UDP, a byte N sends to P's UDP port 9, the relay probe's, arrives within 2 s, and a byte sent to UDP port 10 does not. A send error on port 10 is accepted.
- After `ApplyRules` drops the 7001 rule, bytes P writes on an already established 7001 connection do not reach N within 2 s.
- After `ApplyRules` drops `allowOut9001`, bytes N writes on its established 9001 connection do not reach P within 2 s.
- With a nat table in N that DNATs 10.96.0.10:9003 onto P's 9003, as kube-proxy does for a Service, and masquerades what leaves `plexd0`, N connects to 10.96.0.10:9003, and a socket bound to N's `lan0` address 192.0.2.1 connects to P's 9003 straight through `plexd0`, as IPVS sends a Pod's packet. No rule allows 9003: the foreign-source rule lets the second connection out, and without it the dial times out.
- A ruleset of 1000 policy rules, with the 7001 rule and the default deny, applies in one batch and is enforced: P connects to 7001 and times out on 7002.
- N reaches its own 10.99.0.1:7002 under the default-deny-only ruleset.
- With a table `ip plexd` created first, holding a forward chain that drops everything from `plexd0`, `EnsureChain` removes it, and P reaches E on 8001. After `EnsureChain` the three chains exist, `<chain>-output` on the output hook.
- After `FlushChain`, P connects to 10.99.0.1:7002 and through N to E at 8002 again, and N connects to P at 9003.
- After `DeleteChain`, none of the three chains remains, P connects to 10.99.0.1:7002 again, N connects to P at 9003, and a second `DeleteChain` returns `nil`.
- With only the input and forward chains in table `inet plexd`, as a plexd before the output chain leaves them, `FlushChain` and `DeleteChain` return `nil` and no chain remains, and `FlushChain` of a chain name that does not exist returns `nil`.

`TestNftablesController_RealTraffic` (`tuntraffic_linux_test.go`) runs the traffic checks the macOS and Windows backends run, described under [Tests](./pf-wfp-firewall.md#tests), through a TUN device. It has the same gate. It creates a fresh network namespace N, creates the TUN device `plexdtun0` there with 10.255.247.1/30, and hands `runTunTrafficChecks` the controller, the device, an offset of 16, which leaves room for the 10-byte virtio header wireguard-go's Linux device writes in front of each packet, and N's `do`, so N's sockets and the controller's calls run inside N. The device, its address and every rule stay in N, never in the host's namespace. Among the checks is the drop check: `DropCounts` before and after one injected packet that no rule allows must differ by at least 1 packet and at least that packet's length in bytes, which proves on the real kernel that the sum reads the default deny's counters.

`TestNftablesController_RealConnLog` (`tuntraffic_linux_test.go`) has the same gate and builds the same namespace and device through `newTunTestHarness`, which the traffic test calls too. It runs the connection logging checks the macOS test runs too, `runTunConnLogChecks`, described under [Tests](./pf-wfp-firewall.md#tests). The NFLOG reader opens inside N, so it binds group 28772 in N's namespace, not in the host's.

`TestTunPacketRoundTrip` (`tunpacket_test.go`) carries no build tag and needs no privilege, so it runs on every platform. It checks the packet builders and the parser the traffic tests share. It pins each builder's IPv4 header and transport checksums against values computed independently, checks that the parser reads each packet back, and checks that it refuses every truncated prefix of a packet and an IPv6 header. A packet with a wrong checksum would be dropped by the host before any filter saw it, and a traffic test would read that as a drop.

Locally:

```bash
sudo PLEXD_TEST_REAL_NFTABLES=1 go test -run '^TestNftablesController_Real(Traffic|ConnLog)?$' ./internal/policy/
```

CI runs all three in the step "Run privileged Linux tests", which fails unless its log holds the `--- PASS` line of each; see [CI Workflow](../development/ci-workflow.md).

## Usage

```go
logger := slog.Default()
ctrl := policy.NewNftablesController(logger)

enforcer := policy.NewEnforcer(engine, ctrl, policy.Config{}, logger)
```
