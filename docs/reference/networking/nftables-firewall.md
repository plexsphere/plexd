---
title: nftables Firewall Controller
package: internal/policy
feature: PXD-0027
---

# nftables Firewall Controller

`NftablesController` is the Linux production implementation of the `FirewallController` interface defined in `internal/policy`. It translates `FirewallRule` entries into nftables expressions and manages them via the `github.com/google/nftables` netlink library. The macOS and Windows implementations are described in [pf & WFP Firewall Controllers](./pf-wfp-firewall.md).

The controller works in the table `plexd` of the `inet` family (`nftables.TableFamilyINet`), which sees IPv4 and IPv6 packets alike. For a configured chain name it creates three base chains, `<chain>-input` on the input hook, `<chain>-forward` on the forward hook and `<chain>-output` on the output hook, all `ChainTypeFilter` at `ChainPriorityFilter` with policy accept. The input chain governs mesh traffic addressed to the node itself, the forward chain the mesh traffic the node forwards, and the output chain what the node's own sockets send over the mesh. It requires `CAP_NET_ADMIN` and the `//go:build linux` constraint.

When every rule names an interface, each chain opens with a [guard](#connection-tracking) that accepts a packet on any other interface, so traffic outside the policy's interfaces passes one rule instead of all of them. The unlogged allows that name an address go into nftables [sets](#rule-sets), so a mesh packet costs a fixed number of lookups instead of a walk of the rule list. A kernel that refuses the sets gets the rules as a list behind the same guard.

## Architecture

![The PolicyEngine produces a slice of FirewallRule values, which goes to the NftablesController. The controller writes to nftables over nfnl: the table plexd of the family inet, with three chains named after the configured chain name with the suffixes -input, -forward and -output.](../../diagrams/networking-nftables-architecture.svg)

The `Enforcer` calls `NftablesController` methods during policy reconciliation. Each method opens a fresh netlink connection, batches operations, and commits atomically via `Flush()`. The only state the controller keeps is the sink for [connection logging](#connection-logging), the NFLOG reader that feeds it, and `listOnly`, which records that the kernel refused the [rule sets](#rule-sets) once.

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
| `ApplyRules`  | `segmentRules` once and `chainRuleExprs` for the three lists, then `writeChains` on a socket sized by `applyBufferBytes`: `AddTable` + `AddChain` and `FlushChain` for all three chains + per set rule `AddSet` with the first 256 elements and `SetAddElements` for every further 256 + `AddRule` per entry of each list into its own chain + `Flush`; once more without sets when a write with sets fails |
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

Atomically replaces the rules of all three chains. It builds one list for each chain from the same rules before it touches the batch. The input and forward lists match the interface a packet arrives on (`meta iifname`), and the output list the interface a packet leaves through (`meta oifname`):

1. Validates every `FirewallRule` and cuts the rules into segments, once for all three lists: `segmentRules(rules, sets)`. Each run of consecutive unlogged allows that name an address and share an `Interface` becomes [set rules](#rule-sets), and every other rule is a segment of its own. `sets` is false once the kernel has refused the sets (`listOnly`), and then every rule is a segment of its own
2. Builds one list per chain from the segments: `chainRuleExprs(segments, hookInput)`, `chainRuleExprs(segments, hookForward)` and `chainRuleExprs(segments, hookOutput)`. When every rule names an interface, each list opens with the [guard](#connection-tracking), built by `guardExprs`, which accepts a packet on any interface no rule names
3. Goes on with the two [connection tracking rules](#connection-tracking) once per distinct `Interface` among the rules, in order of first appearance. The input list follows them with that interface's round-trip probe rule, and the output list with its foreign-source rule, relay probe rule and round-trip probe rule. The forward list adds none, so nothing the node forwards passes an exemption. The segments follow in the order given: a rule, with its [log rule](#log-rules) directly in front of it when it carries a `LogTag`, or the set rules of a run, one per set
4. Hands the three lists to `writeChains`, which opens a netlink socket sized by `applyBufferBytes`, ensures the table and all three chains exist, and flushes all three chains, which removes the sets of their old rules
5. Writes each list into its own chain, each set rule behind its set, which `AddSet` and `SetAddElements` add
6. Commits everything in one batch via `Flush()`, so the three chains change together or not at all

If validation or expression building fails for any rule (an invalid address, mixed families, an unsupported protocol or action), the whole operation is aborted before `Flush()`, and the chains keep the rules they had. The error texts are the same for all three lists.

When a rule carries a `LogTag` and no NFLOG reader runs, `ApplyRules` opens one. If no sink is set or the reader does not open, it writes the rules without their tags, so no log rule reaches the kernel, and on a failed open it logs `policy connection logging unavailable, logged rules are enforced without it` at Warn with `error`. See [Connection Logging](#connection-logging).

A kernel that refuses the sets gets the rule list behind the same guard. When a write whose lists hold a set fails, `ApplyRules` builds the lists again without sets, so every rule is a segment of its own, and writes once more. When that write succeeds, it sets `listOnly`, logs `policy rule sets unavailable, rules are installed as a list` at Warn with `component`, `chain` and `error`, the first write's error, and returns `nil`. From then on every apply writes the list, until the process ends. When the list fails too, `ApplyRules` returns the list's error and logs no Warn line, and the next apply tries the sets again. `ApplyRules` does not retry a failed write of lists without a set. Each write is one atomic batch, so a failed one leaves the chains as they were. The retry is tied to no error number: the sets need interval concatenations, in mainline since Linux 5.6, and what an older kernel answers was not measured. `ApplyRules` writes through the controller's `write` field, which `NewNftablesController` sets to `writeChains` and tests replace.

For n unlogged policy rules that name an address, m logged ones and s set rules per chain on one interface the kernel holds 3(2m + s) + 16 rules. Each chain holds the guard, the two connection tracking rules, the m log rules and the m logged rules, the s set rules and the default deny. The input chain adds the round-trip probe rule, and the output chain the foreign-source rule, the relay probe rule and the round-trip probe rule. n drops out, because the n rules are elements of the sets: s counts one set rule per family, shape and layer of each run, so 3,000 IPv4 rules of one shape that do not cross take one. An unlogged rule without an address, or another deny, adds one rule to each chain. Written as a list, the n rules take the place of the s set rules, and the kernel holds 3(2m + n) + 16. A packet is evaluated only by the chain whose hook it takes. plexd sets no cap of its own on n; the control plane's compile bounds it.

The kernel echoes every rule add back on the batch's netlink socket, and the echoes queue there until the batch is acknowledged. With the default socket buffers a batch failed with `ENOBUFS` or `EMSGSIZE` from about 55 policy rules with two chains, and from about 40 with three, measured on Linux 6.8. `ApplyRules` therefore sizes the socket to the batch. `applyBufferBytes` returns 1 MiB plus 8 KiB per rule and 256 bytes per set element the batch adds, counting each of the three lists once. A batch of 3 × 15,003 elements failed with `EMSGSIZE` on 1 MiB buffers and passed with 1 MiB plus 256 bytes per element, and it applied in 0.55 s. `sizeSocketBuffers` sets the send and receive buffers to that size with `SO_SNDBUFFORCE` and `SO_RCVBUFFORCE`, which go past the host's `net.core.wmem_max` and `net.core.rmem_max` and need `CAP_NET_ADMIN`. Without the capability it falls back to `SO_SNDBUF` and `SO_RCVBUF`, which the host caps. The option never returns an error, because google/nftables v0.3.0 leaves the netlink socket open when one does. A batch that still does not fit fails on its own, with the kernel's `ENOBUFS` or `EMSGSIZE` in the error `ApplyRules` returns. `TestNftablesController_Real` applies 3,000 policy rules in one batch, as one set of 3,002 elements per chain.

### FlushChain and DeleteChain

`FlushChain` lists the chains of the `inet` family and empties those of the three that exist in table `plexd`, skipping the others, and returns `nil` when none exists. So `Enforcer.Teardown` reaches `DeleteChain` also where only some exist, such as the two chains of a plexd before the output chain. `DeleteChain` lists the chains the same way and deletes those of the three that belong to the configured name in table `plexd`. It returns `nil` when none exists, so a second call is a no-op. The empty `inet plexd` table stays.

### DropCounts

`DropCounts(chain)` returns the packets and bytes the default deny dropped, which the Enforcer sends as `drops` in the [policy status report](./network-policy.md#policy-status-report). It opens a netlink connection, calls `GetRules` for `<chain>-input`, `<chain>-forward` and `<chain>-output` in table `inet plexd`, and returns `sumDropCounters` over the rules of all three: the sum of the `expr.Counter` of every rule whose last expression is an `expr.Verdict` of kind `VerdictDrop`. Every rule but the guard and a log rule ends in a counter and a verdict, and the default deny is the only rule with a drop verdict, so the sum is what the default deny dropped on the three hooks. Rules that end in accept are not counted, among them the guard, which carries no counter, and the set rules. The read changes nothing.

`ApplyRules` flushes the three chains and adds every rule anew, so the counters restart from 0 whenever it replaces the chains. The control plane reads a count below the previous one as such a restart. A failed read returns `policy: nftables: drop counts: <cause>`, and the Enforcer logs it as `policy drop counters unavailable`; see [DropCounts](./network-policy.md#dropcounts).

## Connection Tracking

Each chain starts with the guard when every rule names an interface, and then with two rules per interface. The input and forward chains match the interface a packet arrives on, and the input chain follows the two rules with the round-trip probe rule. `plexd up` applies its rules to one interface, `plexd0` here, and the input chain opens with the following rules. The listings on this page leave out the packet and byte values nft prints after each `counter`.

```
iifname != "plexd0" accept
ct state established ct direction reply counter accept
ct state related counter accept
udp dport 7911 counter accept
```

The forward chain holds the guard and the two connection tracking rules alone. The output chain matches the interface a packet leaves through, and follows the two rules with the foreign-source rule, the relay probe rule and the round-trip probe rule:

```
oifname != "plexd0" accept
ct state established ct direction reply counter accept
ct state related counter accept
fib saddr . oif type != local counter accept
udp dport 9 counter accept
udp dport 7911 counter accept
```

`guardExprs(ifaces, dir)` builds the guard when every rule names an interface: `meta iifname` in the input and forward chains or `meta oifname` in the output chain, compared with `!=` against each interface the rules name, in order of first appearance, then accept. A packet on any other interface leaves the chain at the guard, so the chain tests the interface once per packet instead of once per rule. An accept in a base chain ends that chain only, as falling off the end of a policy-accept chain does, so no verdict changes: none of the rules behind the guard matches a packet on another interface. The guard carries no counter, so traffic that leaves at it moves no counter. With one interface `chainRuleExprs` builds every rule behind the guard without an interface match (`dirNone`), because what reaches it is on that interface already, and nft lists no `iifname` or `oifname` behind the guard. A rule whose `Interface` is empty matches every interface, so a ruleset that holds one gets no guard, and every rule carries the interface match of its own rule, none for the empty one.

With rules on two or more interfaces the guard names all of them, and every rule behind it keeps its own interface match. The input chain of a ruleset with an allow and a default deny on `plexd0` and on `wg1` reads:

```
iifname != "plexd0" iifname != "wg1" accept
iifname "plexd0" ct state established ct direction reply counter accept
iifname "plexd0" ct state related counter accept
iifname "plexd0" udp dport 7911 counter accept
iifname "wg1" ct state established ct direction reply counter accept
iifname "wg1" ct state related counter accept
iifname "wg1" udp dport 7911 counter accept
iifname "plexd0" ip saddr . ip daddr . meta l4proto . th dport { 10.99.0.0/24 . 10.99.0.1 . tcp . 443 } counter accept
iifname "plexd0" counter drop
iifname "wg1" ip saddr . ip daddr . meta l4proto . th dport { 10.98.0.0/24 . 10.98.0.1 . tcp . 22 } counter accept
iifname "wg1" counter drop
```

`connTrackExprs(iface, dir)` builds the two connection tracking rules. The first passes a packet in the reply direction of a connection the kernel tracks. In the input and forward chains those are the replies to a connection the node opened over the mesh, or that a host behind the node opened through it. In the output chain they are the replies the node sends to a connection the policy let in. None needs a policy rule of its own. The second passes a packet the kernel relates to a tracked connection, such as an ICMP error about it, in either direction.

Only the reply direction bypasses the rules. A packet in a connection's original direction is matched against the rules every time, so a revoked rule cuts an established inbound or forwarded connection at its next packet, as the stateless chain of earlier releases did. The output chain does the same for a connection the node's own sockets opened. Accepting every established packet instead would keep a revoked connection alive until conntrack forgets it. For the same reason plexd flushes no conntrack entry when a ruleset changes.

The rule that follows the connection tracking rules in the output chain, built by `foreignSourceExprs(iface, dir)`, lets a packet out unfiltered when its source is not an address of the mesh interface. `fib saddr . oif type` asks the routing table for the type of the source address on the outgoing interface, which is `local` only for an address assigned to that interface, so the node's mesh address is filtered and any other source is not. IPVS sends a Pod's packet to a Service endpoint behind the mesh through the output hook with the Pod's address as source, and a socket can bind another address of the node. Masquerade gives such a packet the mesh address only at postrouting, after the output chain, so no rule could match it. It leaves as forwarded traffic leaves, and a packet that still carries a foreign source when it leaves is dropped by the receiving peer's WireGuard, which accepts from a peer only the addresses it allows for that peer. kube-proxy's DNAT of a host-network connection to a Service never meets the output chain as `plexd0` traffic: the filter chains of the output hook see the interface of the route the connection started on.

The next rule of the output chain is the relay probe exemption, built from `relayProbeRule(iface)`: UDP to port 9, `RelayProbePort`, with no address, so it covers IPv4 and IPv6. It lets plexd's [relay liveness probe](./wireguard.md#relay-liveness-probe) out ahead of the policy rules. Any local process can send to that port, to any address the mesh routes, and the receiving node's inbound rules still apply.

The round-trip probe exemption, built from `rttProbeRule(iface)`, follows the connection tracking rules in the input chain and the relay probe rule in the output chain: UDP to port 7911, `RTTProbePort`, with no address, so it covers IPv4 and IPv6. It passes plexd's [round-trip probe](./wireguard.md#round-trip-probe) ahead of the policy rules in both directions: the input chain passes what arrives for the node on the port, and the output chain what the node sends to it. The forward chain does not hold it, so nothing the node forwards passes it. The `DECISION` at `RTTProbePort` (`firewall.go`) records why: one socket on port 7911 of the mesh address sends plexd's probes and answers the peers' probes, so a probe and its answer both travel from port 7911 to port 7911, and one rule shape, UDP to port 7911 on the mesh interface, covers both directions, on a backend that keeps no state too. Any local process on a peer can therefore send UDP to port 7911 of the node, where it reaches the socket that holds the port on the mesh address, which is plexd's.

The output chain filters only what the node itself sends from an address of the mesh interface: the packets of its own sockets, and the ICMP errors and TCP resets its kernel generates, which pass as related or reply traffic. A packet the node forwards into the mesh takes the forward hook instead, whose chain matches the interface the packet arrived on. Traffic forwarded out through the mesh is therefore not filtered on its way out, whether it comes from a user-access client, a site-to-site peer, a host behind a bridge, or a container or Pod masqueraded onto the node's mesh address.

A drop in the output chain reaches the local program. A blocked UDP or ICMP send fails with `operation not permitted` (`EPERM`). A blocked TCP connect does not fail at once: the kernel retransmits the SYN until the connect times out. The counter of the chain's final `drop` shows what the policy dropped:

```bash
sudo nft list chain inet plexd plexd-mesh-output
```

## Rule Translation

Each `FirewallRule` is converted to a sequence of nftables expressions. A rule that joins a run becomes an element of a set instead; see [Rule Sets](#rule-sets). The tables below describe the rules that stay rules: logged rules, denies, rules without an address, and every rule of a controller that fell back to the list. Every address goes through `parseRuleAddr`, which the three backends share, so a rejected address reads the same on every platform.

| FirewallRule Field | nftables Expression                                       | Condition            |
|--------------------|-----------------------------------------------------------|----------------------|
| `Interface`        | `Meta(IIFNAME)` + `Cmp` in the input and forward lists, `Meta(OIFNAME)` + `Cmp` in the output list | Non-empty, except behind the [guard](#connection-tracking) of a single interface |
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

A rule with a `LogTag` gets a log rule directly in front of it, in all three lists. `logRuleExprs(rule, dir)` builds it from the rule's own matches, without the counter and the verdict, and appends:

| Expression | Meaning |
|---|---|
| `Ct(STATE)` + `Bitwise` + `Cmp` on the new bit | Only a packet of a connection conntrack has not yet seen answered |
| `Log{Group: 28772, Data: <LogTag>}` | Hands the packet to NFLOG group 28772, `nflogGroup` (ASCII `pd`), with the tag as its prefix |

The log rule carries no verdict, so evaluation goes on to the rule itself, which accepts the packet. A logged rule therefore logs the first packet of each connection it admits, and every later packet of a flow that has not been answered yet. The connection tracking rules ahead of it pass the replies before they reach it.

A logged rule stays a rule of its own and never joins a [run](#rule-sets): it ends the run in front of it, and the unlogged allows behind it start a new one. The `Enforcer` puts the logged rules first, so they and their log rules come ahead of the set rules.

### Rule Sets

`segmentRules(rules, sets)` cuts the rules into segments before `chainRuleExprs` builds the lists. A rule joins a run when it is an allow, carries no `LogTag` and names an address, so that it has an address family. A run is a maximal sequence of consecutive such rules with the same `Interface`. A logged rule, a deny and a rule without an address stay rules of their own and end the run before them: a log rule needs its rule's own match, and a deny or a rule without an address has no place in an accept set. Consecutive allows commute, so plexd can reorder and merge the rules of a run without changing a verdict. Nothing moves across a logged rule or a deny.

Each rule of a run is a box, which `boxOf` returns: a source prefix, a destination prefix, a protocol number and an inclusive range of destination ports. An absent address is the zero-length prefix of the rule's family, `0.0.0.0/0` or `::/0`. The range runs from `Port` to `PortTo` when `PortTo` is above `Port`, and is `Port` alone otherwise. The rule's fields decide the shape of its box, which decides the key of its set and the fields the set rule loads:

| Shape | Rule | Key types | nft form |
|---|---|---|---|
| `shapeAddrs` | No `Protocol` | `ipv4_addr` or `ipv6_addr` twice | `ip saddr . ip daddr` |
| `shapeProto` | A `Protocol` and no `Port` | The address type twice, `inet_proto` | `ip saddr . ip daddr . meta l4proto` |
| `shapePort` | `Port > 0` | The address type twice, `inet_proto`, `inet_service` | `ip saddr . ip daddr . meta l4proto . th dport` |

`setKeyType(family, shape)` concatenates the key types with `nftables.MustConcatSetType`. An IPv6 set rule reads `ip6 saddr . ip6 daddr` in place of `ip saddr . ip daddr`. A set rule loads only the fields of its shape, so an any-protocol rule still matches a packet without a readable transport header, as the same rule written alone does. The set rules of a run come in the order IPv4 `shapeAddrs`, `shapeProto`, `shapePort`, then IPv6 the same, one set rule per layer, whatever order the rules of the run had.

#### Layers

The kernel refuses an element whose first or last point lies inside an element its set already holds, and fails the whole batch with `EEXIST` (`file exists`). Two crossing port ranges on equal addresses fail in either order, and so does a box followed by a box it contains. `layerBoxes` therefore places the boxes of each family and shape of a run into layers of pairwise disjoint boxes:

1. It sorts the boxes stably by source prefix length ascending, destination prefix length ascending and port range width descending, so a box that contains another comes first.
2. It drops a box that a placed box contains (both prefixes inside those of the placed box, the same protocol, the port range inside), since it admits nothing more. Identical rules so end up as one element.
3. It places every other box in the first layer none of whose boxes it intersects (both prefixes overlap, the protocols are equal and the port ranges overlap), and opens a new layer when none fits.

Each layer becomes one set and one set rule. `TestNftablesController_Real` applies tcp rules from 10.99.0.0/24 to 10.99.0.1/32 for ports 7010-7020 and 7015-7025, one from 10.0.0.0/8 for port 7030 and one from 10.99.0.2/32 for port 7030. The 7015-7025 rule crosses the 7010-7020 rule and takes a second layer, the 10.99.0.2/32 rule lies inside the 10.0.0.0/8 rule and `layerBoxes` drops it, and the input chain holds two set rules whose sets hold three elements together.

The comparison is pairwise, so its cost grows with the square of the rules of one family and shape. For pairwise disjoint boxes it took 11 ms for 1,000 rules, 95 ms for 3,000 and 1.1 s for 10,000, once per apply. A ruleset of pairwise crossing boxes ends with one set per rule, and a mesh packet then pays what the list costs.

#### Elements and Registers

`ruleBox.element(shape)` writes a box as a set element. `Key` concatenates the first source address and the first destination address, for `shapeProto` and `shapePort` the protocol padded to 4 bytes, and for `shapePort` the port in network byte order padded to 4 bytes. `KeyEnd` holds the same with the last address of each prefix and the last port of the range. The rule from 10.99.0.0/24 to 10.99.0.1/32 on tcp 5201 gives:

|          | Source     | Destination | Protocol   | Port       |
|----------|------------|-------------|------------|------------|
| `Key`    | `0a630000` | `0a630001`  | `06000000` | `14510000` |
| `KeyEnd` | `0a6300ff` | `0a630001`  | `06000000` | `14510000` |

The padding follows the kernel's 4-byte registers. `setLookupExprs` builds the set rule: the interface match where the list keeps one, `meta nfproto` for the family, then the fields of the key, loaded into the registers from `NFT_REG32_00`, register number 8, on. `regConcat` holds that number, which `golang.org/x/sys/unix` does not define. The lookup reads the concatenation from register 8, and a counter and accept follow.

| Field | IPv4 registers | IPv6 registers |
|---|---|---|
| Source address | 8 | 8 to 11 |
| Destination address | 9 | 12 to 15 |
| Protocol (`meta l4proto`) | 10 | 16 |
| Destination port (`th dport`) | 11 | 17 |

#### Sets in the Batch

Each set is an `nftables.Set` whose `Anonymous`, `Constant`, `Interval` and `Concatenation` fields are true, and each set rule in each chain has its own, so each chain holds its own copy of the elements. An anonymous set lives and dies with its rule: the flush at the start of every apply and `FlushChain` remove it, so it needs no delete step of its own. `writeChains` adds a set with `AddSet`, which carries the first 256 elements (`setElemsPerMessage`), and every further chunk of 256 (`elementChunks`) with `SetAddElements` on a copy of the set whose `Anonymous` is false. The library refuses to add to an anonymous set (`anonymous sets cannot be updated`), and the copy keeps the name, ID and table that address the same set inside the batch. The set rule gets a copy of its lookup that names the set.

The chunks exist because `AddSet` and `SetAddElements` put all elements of a call into one netlink attribute, whose length field has 16 bits. On Linux 6.8, 1,203 elements of the IPv4 port shape arrived whole and 1,303 arrived as 42, and neither the call nor `Flush` returned an error. 256 elements per message arrive whole.

nft lists a set rule with its elements inline. Two rules of the IPv4 port shape in one set read:

```
ip saddr . ip daddr . meta l4proto . th dport { 10.99.0.0/24 . 10.99.0.1 . tcp . 7010-7020, 10.99.0.0/24 . 10.99.0.1 . tcp . 443 } counter accept
```

A set rule carries one counter for every packet its set admits. There are no per-element counters, so the unlogged rules of a run have no counters of their own.

## nftables Table Layout

Take the chain name `plexd-mesh`, a connection sink, and five rules on `plexd0`: an allow from 10.99.0.0/24 to 10.99.0.1/32 on tcp 443, logged with the tag `1/0`; an allow from 10.99.0.0/24 to 10.99.0.1/32 on tcp 7010-7020; an allow from 10.99.0.2/32 to 10.99.0.1/32 on udp; an allow from fd00:99::/64 to fd00:99::1/128 on tcp 443; and the default deny. `nft list table inet plexd` prints them on Linux 6.8 with nftables 1.1.3 as follows, with the counter values left out as elsewhere on this page:

```
table inet plexd {
    chain plexd-mesh-input {
        type filter hook input priority filter; policy accept;
        iifname != "plexd0" accept
        ct state established ct direction reply counter accept
        ct state related counter accept
        udp dport 7911 counter accept
        ip saddr 10.99.0.0/24 ip daddr 10.99.0.1 tcp dport 443 ct state new log prefix "1/0" group 28772
        ip saddr 10.99.0.0/24 ip daddr 10.99.0.1 tcp dport 443 counter accept
        ip saddr . ip daddr . meta l4proto { 10.99.0.2 . 10.99.0.1 . udp } counter accept
        ip saddr . ip daddr . meta l4proto . th dport { 10.99.0.0/24 . 10.99.0.1 . tcp . 7010-7020 } counter accept
        ip6 saddr . ip6 daddr . meta l4proto . th dport { fd00:99::/64 . fd00:99::1 . tcp . 443 } counter accept
        counter drop
    }

    chain plexd-mesh-forward {
        type filter hook forward priority filter; policy accept;
        iifname != "plexd0" accept
        ct state established ct direction reply counter accept
        ct state related counter accept
        ip saddr 10.99.0.0/24 ip daddr 10.99.0.1 tcp dport 443 ct state new log prefix "1/0" group 28772
        ip saddr 10.99.0.0/24 ip daddr 10.99.0.1 tcp dport 443 counter accept
        ip saddr . ip daddr . meta l4proto { 10.99.0.2 . 10.99.0.1 . udp } counter accept
        ip saddr . ip daddr . meta l4proto . th dport { 10.99.0.0/24 . 10.99.0.1 . tcp . 7010-7020 } counter accept
        ip6 saddr . ip6 daddr . meta l4proto . th dport { fd00:99::/64 . fd00:99::1 . tcp . 443 } counter accept
        counter drop
    }

    chain plexd-mesh-output {
        type filter hook output priority filter; policy accept;
        oifname != "plexd0" accept
        ct state established ct direction reply counter accept
        ct state related counter accept
        fib saddr . oif type != local counter accept
        udp dport 9 counter accept
        udp dport 7911 counter accept
        ip saddr 10.99.0.0/24 ip daddr 10.99.0.1 tcp dport 443 ct state new log prefix "1/0" group 28772
        ip saddr 10.99.0.0/24 ip daddr 10.99.0.1 tcp dport 443 counter accept
        ip saddr . ip daddr . meta l4proto { 10.99.0.2 . 10.99.0.1 . udp } counter accept
        ip saddr . ip daddr . meta l4proto . th dport { 10.99.0.0/24 . 10.99.0.1 . tcp . 7010-7020 } counter accept
        ip6 saddr . ip6 daddr . meta l4proto . th dport { fd00:99::/64 . fd00:99::1 . tcp . 443 } counter accept
        counter drop
    }
}
```

Each chain opens with the guard, and no rule behind it names `plexd0`. The logged rule stays a rule behind its log rule. The three unlogged allows behind it form one run, written as three set rules in the order of their shapes: the udp rule as the IPv4 protocol shape, the 7010-7020 rule as the IPv4 port shape, and the IPv6 rule as the IPv6 port shape. The last rule is the default deny. It carries no address, so it drops IPv4 and IPv6 alike. The table name `plexd` is a package-level constant. The chain names come from `Config.ChainName` (default: `plexd-mesh`).

The output chain holds the same policy rules as the other two. A rule matches by its addresses, so the rules above, whose destination is the node, match nothing there. The node's own copy of a rule names the node as the source, and that copy is the one that matches there.

The `Enforcer` puts the logged rules ahead of the unlogged ones (see [Log tags and rule order](./network-policy.md#log-tags-and-rule-order)), so a logged rule and its log rule come first among the policy rules.

Inspect the chains with:

```bash
sudo nft list table inet plexd
```

nft prints the rules in its own form, which can leave out a match the next one implies, such as the `meta nfproto` match in front of `ip saddr`. Every rule but the guard and a log rule carries a counter, so the listing shows the packets and bytes each rule matched, and a set rule's counter covers every element of its set. The counter of the final `drop` is what the policy dropped on that hook. [`DropCounts`](#dropcounts) sums the three final `drop` counters for the policy status report.

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
- For the [rule sets](#rule-sets): interval concatenations, the `nft_set_pipapo` set back end, in mainline since Linux 5.6. A kernel that refuses a batch with sets gets the rules as a list behind the same guard, and plexd logs `policy rule sets unavailable, rules are installed as a list` at Warn; see [ApplyRules](#applyrules). What a kernel before 5.6 answers was not measured, so the fallback is tied to no error number.
- For [connection logging](#connection-logging): `nfnetlink_log` and NFLOG group 28772. The kernel loads `nfnetlink_log` itself when plexd binds the group, and `nft_log` when the first log rule arrives. The bind needs `CAP_NET_ADMIN`, which plexd already holds. A kernel that cannot load `nfnetlink_log` fails the reader's open, not the batch. Only one process can bind a group: when another process, such as ulogd, holds group 28772, the bind fails with `operation not permitted` (`EPERM`), and plexd's connection logging is off. plexd then logs `policy connection logging unavailable, logged rules are enforced without it` at Warn on every apply that holds a logged rule, and writes the rules without their log rules, so the other process never receives plexd's records.

Traffic the node sends to its own mesh address leaves through and arrives on `lo`, which the chains do not match. A local client of a service bound to the mesh IP, such as the [mesh DNS resolver](./mesh-dns.md) or a tcp tunnel listener, is therefore not filtered. A mesh peer's traffic to the same service is, and needs a rule.

## Downgrade

An earlier plexd that writes the three chains, but neither the guard nor the rule sets, flushes and rewrites the three chains on its first apply. The anonymous sets of this release go with the flush, so nothing of this release stays, after a crash too.

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
| `ApplyRules`  | `policy: nftables: apply rules`, and `policy: nftables: apply rules to chain "<chain>"` when the batch fails |
| `FlushChain`  | `policy: nftables: flush chain`                  |
| `DeleteChain` | `policy: nftables: delete chain`                 |
| `DropCounts`  | `policy: nftables: drop counts`                  |

The NFLOG reader's open fails with `policy: nftables: nflog: bind group 28772: <error>`. `ApplyRules` does not return it: it logs it as the `error` of `policy connection logging unavailable, logged rules are enforced without it` and applies the rules.

`writeChains` fails with `policy: nftables: apply rules: add set: <error>` when `AddSet` or `SetAddElements` fails. It calls them only for lists that hold a set, so `ApplyRules` never returns that error: it writes the list instead. When a write with sets fails and the list succeeds, `ApplyRules` returns `nil` and logs `policy rule sets unavailable, rules are installed as a list` at Warn with `component`, `chain` and `error`, the error of the write with sets, which can be the add set error. When the list fails too, it returns the list's error.

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

The list tests need no privilege either. `TestGuardExprs` pins the guard: `meta iifname` or `meta oifname` into register 1, one `!=` per interface in the order given, and accept. `TestChainRuleExprs`, `TestChainRuleExprsForward` and `TestChainRuleExprsOut` build the lists of a ruleset on one interface without sets and see the guard first, then the opening of each list without interface matches: the connection tracking pair and the round-trip probe rule in the input list, the pair alone in the forward list, and the pair, the foreign-source rule, the relay probe rule and the round-trip probe rule in the output list. No entry behind the guard matches an interface. `TestChainRuleExprsTwoInterfaces` sees one guard with `wg0` and `wg1`, and every other entry keep its interface match. `TestChainRuleExprsWithoutInterface` sees a ruleset with a rule whose `Interface` is empty get no guard and the lists plexd wrote before the guard. `TestChainRuleExprsEmpty` sees a nil and an empty ruleset give an empty list for all three hooks, with no guard and no set. `TestRTTProbeRule` checks that `rttProbeRule` is UDP to port 7911 on the interface and passes `Validate`.

The set tests need no privilege. `TestSegmentRules` cuts an allow, an allow, a logged allow, an allow, a deny and an allow without an address into a run of two, a rule, a run of one and two rules. Without sets it sees six rules, two consecutive allows on different interfaces give two runs, and a nil and an empty ruleset give no segment. `TestSegmentRulesRejectsInvalidRule` sees an invalid source address, in a logged and an unlogged rule, with and without sets, fail with an error that starts `policy: nftables: apply rules: policy: firewall rule:`. `TestBoxOf` pins the family, shape and box of a tcp rule with a port and with a port range, a udp rule without a port, an icmp rule in IPv4 (protocol 1) and IPv6 (protocol 58), an any-protocol rule, a rule with only a source and a zero-length prefix. `TestLayerBoxes` sees disjoint boxes share a layer, a contained box dropped in either input order, identical boxes kept once, port ranges 80-90 and 85-95 on equal addresses take two layers, and a box take the first layer it fits. `TestRuleBoxElement` pins the key and end bytes of each shape, the example under [Elements and Registers](#elements-and-registers) among them, and checks that `setKeyType` is as long as the key. `TestSetLookupExprs` pins the set rule of each shape in both families, with the registers above, with and without the interface match. `TestElementChunks` sees 0, 256, 257 and 1,000 elements cut into no chunk, one, two and four, none longer than 256. `TestApplyBufferBytes` checks that `applyBufferBytes` adds the allowance per rule and the allowance per element to the base. `TestChainRuleExprsSets` sees each list hold, behind the guard and its opening, a log rule, the logged rule, one IPv4 port-shape set rule with two elements, one IPv6 address-shape set rule with one element, and the deny. `TestChainRuleExprsLogged` sees a logged rule stay a rule behind its log rule, ahead of the set rule of the unlogged run that follows it.

The fallback tests replace `writeChains` through the `write` seam. `TestNftablesController_SetsUnavailable` answers a write whose lists hold a set with `EOPNOTSUPP` and sees `ApplyRules` return `nil`, the second write hold no set, one Warn line `policy rule sets unavailable, rules are installed as a list` with that error, and the next `ApplyRules` write once, without a set and without a second Warn line. `TestNftablesController_SetsAndListFail` answers every write with `EPERM` and sees `ApplyRules` return an error that wraps it, no Warn line, and the next `ApplyRules` try the sets again. `TestNftablesController_ListWriteNotRetried` sees a failing write of the default deny alone made once.

The connection logging tests need no privilege. `nftables_linux_test.go` checks that `chainRuleExprs` puts the log rule, ending in the new-state match and the log expression for group 28772 with the tag, directly in front of a tagged rule in all three lists, behind the guard and the rules each list opens with, and that an untagged ruleset yields the lists it yielded before. Through the `openLog` seam it checks that a reader that fails to open with `EBUSY`, and a controller without a sink, both make `ApplyRules` write the rules without their log rules, and that only the first logs the Warn line. `nflog_linux_test.go` pins the bytes of the two config messages, the hooks, tags and attributes `parseNflogPacket` accepts and refuses, and the read loop, fed a `receive` that returns `ENOBUFS` and then a packet, or another error.

`TestNftablesController_Real` (`nftables_real_linux_test.go`) drives the real kernel. It runs only with `PLEXD_TEST_REAL_NFTABLES=1` and an effective uid of 0. It builds three network namespaces with `github.com/vishvananda/netlink` and `github.com/vishvananda/netns`: a peer P, joined by a veth pair to the node N's `plexd0` (10.99.0.2/24 and fd00:99::2/64 on P, 10.99.0.1/24 and fd00:99::1/64 on N), and an external host E behind N's `lan0` (192.0.2.1/24 on N, 192.0.2.2/24 on E). N forwards IPv4. Every link is created inside the test's namespaces, never in the host's, which may run a live `plexd0`, and the controller runs on a goroutine locked to N. The rules include `allowOut9001`, N's own copy of a rule from N (10.99.0.1/32) to P (10.99.0.2/32) on TCP 9001, the copy the control plane compiles for the source node. The test shows that:

- After the first apply each of the three chains, read back with `GetRules`, opens with the guard for `plexd0` without a counter, and no rule behind the guard matches an interface. `GetSets` returns anonymous sets, and each chain holds a rule with a lookup.
- P connects to 10.99.0.1:7001 and [fd00:99::1]:7001, which rules allow, and times out within 2 s on 7002 over both families while listeners run there. N's replies on 7001 leave through the output chain.
- P connects through N to E at 192.0.2.2:8001, which a rule allows, and times out on 8002. That rule, `allow8001`, carries the tag `9/0`, and the test's recording sink receives an event with that tag, direction forward, source 10.99.0.2, destination 192.0.2.2, protocol 6 and destination port 8001, which proves the forward hook's NFLOG records.
- N connects to P at 10.99.0.2:9001, which `allowOut9001` allows, and is blocked on 9003 while P listens there: the dial times out within 2 s or fails with `EPERM`, and is never refused.
- E connects through N to P at 10.99.0.2:9002 with no rule naming that direction, so what N forwards out of `plexd0` is not filtered on its way out.
- With no rule naming UDP, a byte N sends to P's UDP port 9, the relay probe's, arrives within 2 s, and so does one sent to P's UDP port 7911, the round-trip probe's. A byte sent to UDP port 10 does not arrive. A send error on port 10 is accepted.
- A byte P sends to UDP port 7911 of E, which N forwards, does not arrive within 2 s: the forward chain holds no round-trip probe exemption.
- After `ApplyRules` drops the 7001 rule, bytes P writes on an already established 7001 connection do not reach N within 2 s.
- After `ApplyRules` drops `allowOut9001`, bytes N writes on its established 9001 connection do not reach P within 2 s.
- With a nat table in N that DNATs 10.96.0.10:9003 onto P's 9003, as kube-proxy does for a Service, and masquerades what leaves `plexd0`, N connects to 10.96.0.10:9003, and a socket bound to N's `lan0` address 192.0.2.1 connects to P's 9003 straight through `plexd0`, as IPVS sends a Pod's packet. No rule allows 9003: the foreign-source rule lets the second connection out, and without it the dial times out.
- Under an allow and a default deny that name `plexd9`, an interface N does not have, P connects to 10.99.0.1:7002, and every counter of the three chains reads 0 packets.
- Under a default deny on `plexd0`, an allow from 192.0.2.0/24 to 192.0.2.1/32 on tcp 7002 and a default deny on `lan0`, E connects to 192.0.2.1:7002, E times out on 192.0.2.1:7001, and P times out on 10.99.0.1:7002.
- An any-protocol rule from 10.99.0.2/32 to 10.99.0.1/32, a set of the address shape, lets P connect to 10.99.0.1:7002. A udp rule without a port for the same addresses, a set of the protocol shape, lets P's datagram reach N's UDP port 7050, which it does not reach under the default deny alone.
- Four tcp rules to 10.99.0.1/32 apply: from 10.99.0.0/24 for ports 7010-7020 and for 7015-7025, from 10.0.0.0/8 for port 7030, and from 10.99.0.2/32 for port 7030. P connects to 7012, 7022 and 7030 and times out on 7026, and the input chain holds two set rules whose sets hold three elements together.
- A controller whose `listOnly` is set applies the first ruleset as a list: no rule holds a lookup, and the guard leads each chain. P connects to 10.99.0.1:7001 and [fd00:99::1]:7001 and times out on 7002 over both families, P reaches E on 8001 and not on 8002, and N reaches P on 9001 and not on 9003.
- A ruleset of 3,000 policy rules, with the 7001 rule, a rule from 10.99.0.2/32 to 10.99.0.1/32 on tcp 7003 and the default deny, applies in one batch, and the set of each chain holds 3,002 elements, counted with `GetSetElements`. The kernel enforces it: P connects to 7001 and 7003 and times out on 7002.
- N reaches its own 10.99.0.1:7002 under the default-deny-only ruleset.
- With a table `ip plexd` created first, holding a forward chain that drops everything from `plexd0`, `EnsureChain` removes it, and P reaches E on 8001. After `EnsureChain` the three chains exist, `<chain>-output` on the output hook.
- After `FlushChain`, `GetSets` returns no set of table `plexd`, P connects to 10.99.0.1:7002 and through N to E at 8002 again, and N connects to P at 9003.
- After `DeleteChain`, none of the three chains remains, P connects to 10.99.0.1:7002 again, N connects to P at 9003, and a second `DeleteChain` returns `nil`.
- With only the input and forward chains in table `inet plexd`, as a plexd before the output chain leaves them, `FlushChain` and `DeleteChain` return `nil` and no chain remains, and `FlushChain` of a chain name that does not exist returns `nil`.

`TestNftablesController_RealTraffic` (`tuntraffic_linux_test.go`) runs the traffic checks the macOS and Windows backends run, described under [Tests](./pf-wfp-firewall.md#tests), through a TUN device. It has the same gate. It creates a fresh network namespace N, creates the TUN device `plexdtun0` there with 10.255.247.1/30, and hands `runTunTrafficChecks` the controller, the device, an offset of 16, which leaves room for the 10-byte virtio header wireguard-go's Linux device writes in front of each packet, and N's `do`, so N's sockets and the controller's calls run inside N. The device, its address and every rule stay in N, never in the host's namespace. With no rule naming port 7911, the checks see N's round-trip probe to P's port 7911 leave through the output chain, P's probe from its port 7911 reach an echo on N's port 7911 through the input chain, and the echo's answer to P's port 7911 leave. Among the checks is the drop check: `DropCounts` before and after one injected packet that no rule allows must differ by at least 1 packet and at least that packet's length in bytes, which proves on the real kernel that the sum reads the default deny's counters.

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
