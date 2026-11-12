---
title: pf & WFP Firewall Controllers
package: internal/policy
---

# pf & WFP Firewall Controllers

`PFController` (`pf_darwin.go`) and `WFPController` (`wfp_windows.go`, `netnat_windows.go`) are the non-Linux implementations of the `FirewallController` interface defined in `internal/policy`. macOS programs its rules with `pfctl(8)` and needs root. Windows programs the Windows Filtering Platform through `github.com/tailscale/wf` and WinNAT through PowerShell, both of which need Administrator, which the LocalSystem service satisfies.

Both controllers also implement `bridge.NATController`, so one instance carries the policy rules and the bridge's masquerade rule; see [NAT](#nat).

The Linux implementation is [`NftablesController`](./nftables-firewall.md).

## What the rules govern

On all three platforms the rules govern everything that arrives on the mesh interface, whether the packet is delivered to the node itself or forwarded through it, and everything the node's own sockets send over it. A rule matches by its addresses. The control plane compiles every rule for both ends: the destination node's copy names the peer as the source, and the source node's copy names the node itself, so each copy matches one direction. A node rejects unsolicited mesh traffic to its own addresses until a rule allows it, and drops what it sends to a mesh address until a rule allows that too, because the ruleset ends in a default deny. Replies to a connection the policy let in leave without a policy rule of their own on Linux and Windows, and on macOS for tcp, udp and icmp; see below.

What the node forwards into the mesh is not filtered on its way out, on any platform. On Linux such a packet takes the forward hook, whose chain matches the interface it arrived on. On macOS the default deny's `block out` line names the interface's own addresses as the source, which a forwarded packet does not carry. On Windows forwarded traffic never reaches `ALE_AUTH_CONNECT`.

On every platform the node can send UDP to port 9, `RelayProbePort`, over the mesh interface without a rule, ahead of the policy rules. That is plexd's [relay liveness probe](./wireguard.md#relay-liveness-probe). Any local process can use the exemption, to any address the mesh routes, and the receiving node's inbound rules still apply.

Every rule may name IPv4 or IPv6 prefixes. The default deny names no address and covers both families.

On Linux `NftablesController` installs the same rules in an input chain, a forward chain and an output chain, and connection tracking passes a packet in the reply direction of a tracked connection without a rule; see [nftables Firewall Controller](./nftables-firewall.md#connection-tracking).

On macOS one line precedes the policy rules of every chain, once per interface the chain mentions, in order of first appearance:

```text
pass out quick on utun4 proto udp from (utun4) to any port 9 no state
```

It is the relay probe exemption. It names no address family, so it covers IPv4 and IPv6, and it keeps no state, so it lets nothing back in. `(utun4)` is the interface's own addresses as the kernel tracks them, not a snapshot taken when the anchor was loaded, so a mesh address assigned after the load needs no reload. Each policy rule then renders its own lines; see [The rendered anchor](#the-rendered-anchor).

The node's own TCP connections keep state. An allow that names `tcp`, or no protocol, renders a `pass out ... proto tcp ... keep state` line, and the state entry matches the reply before the default deny is reached. A revoked rule therefore stops a Mac's established outbound TCP connection only when that connection ends.

Only TCP keeps state. pf consults the state table ahead of the ruleset and a state entry is bidirectional, so a stateful rule covering every protocol would keep an inbound-initiated UDP or ICMP flow alive after the rule that allowed it was revoked: the node's own reply creates the entry, and every further packet of that flow matches it instead of the ruleset. pf's idle timeouts refresh on each packet, so an active flow would never expire. TCP is not affected, because the implicit `flags S/SA` pfctl puts on a stateful TCP pass rule means an outbound SYN-ACK creates no state. The node's own UDP and ICMP flows stop at their next packet once their rule is revoked.

The cost is that a Mac's own UDP and ICMP flows over the mesh get no automatic return path: a reply arriving on the mesh interface is subject to the policy like any other inbound packet, so the policy has to allow it. This is the fail-closed side of the trade: a revoked rule cuts what arrives at once, on every protocol.

Replies to what a rule lets in leave through stateless mirror lines, with the rule's source and destination swapped. The inbound lines stay stateless so that a revoked rule cuts inbound traffic at once, which means pf can tell a reply from a new flow only by its shape. A TCP mirror carries `flags A/A`, which keeps the Mac from opening a TCP connection through it, and an ICMP mirror carries only replies and errors. A UDP mirror, however, lets the Mac send from the rule's port, or from any port for a rule without ports, to a peer that may reach it. Linux and Windows allow no such thing.

The mirrors also carry less than Linux's connection tracking does. A reply in a protocol other than tcp, udp and icmp matches no mirror. Neither does an ICMP error the Mac sends from its own address about traffic it forwards, such as a time exceeded for a traceroute through it. Both meet the default deny unless a rule allows them from the node's own address.

On Windows the node's own traffic is filtered at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `FWPM_LAYER_ALE_AUTH_CONNECT_V6`, which authorize the node's own outbound connections and the first packet of its other flows. Replies leave through the ALE flow the inbound accept authorized and need no outbound filter; see [Layers and conditions](#layers-and-conditions).

On Windows the forward path is narrower than the local one. `FWPM_LAYER_IPFORWARD_V4` and `FWPM_LAYER_IPFORWARD_V6` carry interfaces and addresses, but neither a protocol nor a port: the layers have no `IP_PROTOCOL` field and no port field, and `github.com/tailscale/wf` refuses a condition on a field the layer does not have. `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6` carry the full five-tuple. The two connect layers carry the protocol and the remote port as well.

A rule left out of the forward layer is not narrowed to nothing: the traffic it covered is decided by the filters that remain, which end in the default deny. An **allow** that names a protocol or a port cannot be narrowed onto a layer without those fields, so it gets no forward filter, and the traffic it covered is dropped unless another rule allows it. Only an allow that names neither, one that matches on addresses alone, reaches the forward path. This fails closed, and an operator notices it: on a bridge or relay node, transit traffic such a rule allows is dropped. `ApplyRules` logs one `Warn` line per apply naming how many rules that affects, so the effect is not mistaken for a routing fault. The controller would install a **deny** that names a protocol or a port on the forward layer without them, which blocks every protocol and port between its addresses, a superset of what it asked for, and log a second `Warn` line counting such rules. The engine builds no such rule: its only deny is the default deny, which names neither.

One more Windows difference: the ALE receive-accept layers classify a TCP connection once, at accept, so a revoked allow does not cut an already accepted inbound connection, which pf `no state` and the nftables chains both do.

## macOS: pf

### The anchor

plexd's rules live in the pf anchor `com.apple/plexd`. Apple's `/etc/pf.conf` references `anchor "com.apple/*"` and `nat-anchor "com.apple/*"`, so the kernel evaluates every child of `com.apple` for filter rules and for translation rules without a change to the main ruleset. That file's own header says system services rewrite it dynamically, which is why plexd stays out of it.

`pfctl -f` replaces an anchor's rules wholesale, and there is no way to add a single rule to one, so the controller keeps the desired state itself and renders the whole anchor on every change. The rendered text opens with a header line, so an operator reading the loaded ruleset knows who owns it and that local edits do not survive.

### The rendered anchor

Seven allow rules and the default deny render as:

```text
# plexd policy anchor. Managed by plexd; edits are overwritten.
# chain plexd-mesh
pass out quick on utun4 proto udp from (utun4) to any port 9 no state
pass in quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 no state
pass out quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 keep state
pass out quick on utun4 inet proto tcp from 10.1.0.5 port 443 to 10.0.0.0/24 flags A/A no state
pass out quick on utun4 inet proto icmp from 10.1.0.5 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state
pass in quick on utun4 inet proto udp from 10.0.0.0/24 to 10.1.0.0/24 port 53:60 no state
pass out quick on utun4 inet proto udp from 10.0.0.0/24 to 10.1.0.0/24 port 53:60 no state
pass out quick on utun4 inet proto udp from 10.1.0.0/24 port 53:60 to 10.0.0.0/24 no state
pass out quick on utun4 inet proto icmp from 10.1.0.0/24 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state
pass in quick on utun4 inet proto icmp from 10.0.0.0/24 to 10.1.0.0/24 no state
pass out quick on utun4 inet proto icmp from 10.0.0.0/24 to 10.1.0.0/24 no state
pass out quick on utun4 inet proto icmp from 10.1.0.0/24 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state
pass in quick on utun4 inet from 10.0.0.9 to 10.1.0.0/24 no state
pass out quick on utun4 inet proto tcp from 10.0.0.9 to 10.1.0.0/24 keep state
pass out quick on utun4 inet from 10.0.0.9 to 10.1.0.0/24 no state
pass out quick on utun4 inet proto tcp from 10.1.0.0/24 to 10.0.0.9 flags A/A no state
pass out quick on utun4 inet proto udp from 10.1.0.0/24 to 10.0.0.9 no state
pass out quick on utun4 inet proto icmp from 10.1.0.0/24 to 10.0.0.9 icmp-type { echorep, unreach, timex, paramprob } no state
pass in quick on utun4 inet proto tcp from 10.0.0.0/24 to any port 22 no state
pass out quick on utun4 inet proto tcp from 10.0.0.0/24 to any port 22 keep state
pass out quick on utun4 inet proto tcp from any port 22 to 10.0.0.0/24 flags A/A no state
pass out quick on utun4 inet proto icmp from any to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state
pass in quick on utun4 inet6 proto tcp from fd00::/64 to fd00::1 port 443 no state
pass out quick on utun4 inet6 proto tcp from fd00::/64 to fd00::1 port 443 keep state
pass out quick on utun4 inet6 proto tcp from fd00::1 port 443 to fd00::/64 flags A/A no state
pass out quick on utun4 inet6 proto icmp6 from fd00::1 to fd00::/64 icmp6-type { echorep, unreach, toobig, timex, paramprob } no state
pass in quick on utun4 inet6 proto icmp6 from fd00::/64 to fd00::/64 no state
pass out quick on utun4 inet6 proto icmp6 from fd00::/64 to fd00::/64 no state
pass out quick on utun4 inet6 proto icmp6 from fd00::/64 to fd00::/64 icmp6-type { echorep, unreach, toobig, timex, paramprob } no state
block in quick on utun4 from any to any
block out quick on utun4 from (utun4) to any
```

`render` opens the chain with the relay probe line. `renderRule` returns every line of one rule. An allow renders, in this order:

1. A `pass in` line, which lets in what the rule allows.
2. `pass out` lines for the node's own traffic: `tcp` with `keep state`, `udp` and `icmp` with `no state`. A rule without a protocol renders the `tcp` line and then a `no state` line for every protocol.
3. Reply mirrors, with source and destination swapped: a `tcp` mirror with `flags A/A` for a rule that names `tcp` or no protocol, a `udp` mirror for one that names `udp` or no protocol, and for every allow the ICMP replies and errors of its family. A rule without addresses gets the ICMP mirror of both families.

A deny renders a `block in` line and a `block out` line. The `block out` line names the interface's own addresses, `(utun4)`, in place of an empty source, so the default deny drops what the node sends and leaves alone what the Mac forwards out of the interface. The engine puts the default deny last, so its two `block` lines follow every `pass` line.

| Element | Meaning |
|---|---|
| `# chain plexd-mesh` | pf has no user chains, so the chain is a comment. The name is what `ApplyRules`, `FlushChain` and `DeleteChain` address |
| `quick` | The first matching rule is final, the first-match semantics the nftables backend has |
| `no state` | Every packet stays subject to the current rules, so a revoked rule takes effect at once instead of after the last flow expires. Every `pass in` line, every mirror, the relay probe line and the node's own `udp`, `icmp` and protocol-less `pass out` lines carry it |
| `keep state` | The node's own TCP connections. pfctl adds `flags S/SA`, so only the node's own SYN creates a state entry, never its SYN-ACK to an inbound connection. A revoked rule stops such a connection only when it ends |
| `flags A/A` | A TCP mirror matches only a segment with ACK set, so the Mac cannot open a TCP connection through it |
| `icmp-type { ... }`, `icmp6-type { ... }` | What an ICMP mirror lets the node send: the echo reply and the errors a host sends about a packet it received. IPv4 reports a packet too big for the path as a code of `unreach`, IPv6 as the type `toobig` |
| `(utun4)` | The interface's own addresses as the kernel tracks them. The relay probe line and the default deny's `block out` line use it, so both match what the node sends and not what the Mac forwards |
| `inet`, `inet6` | The family of the rule's addresses. A rule without addresses, the default deny, carries neither and matches both, as does the relay probe line. An ICMP mirror names its own family |
| `icmp6` | Protocol `icmp` in an IPv6 rule, which means ICMPv6 |
| `block in`, `block out` | The default deny, the only deny rule the engine builds. pf's default block policy is drop, what the nftables backend expresses as `VerdictDrop` |
| `any` | An empty address field, `0.0.0.0/0` or `::/0`. Under `0.0.0.0/0` or `::/0` the family keyword stays, so the rule still matches only its own family |

Chains are rendered in name order, so the same desired state always yields the same text. A `nat` rule, when one is configured, is rendered ahead of the chains, because pf requires translation rules before filter rules in a file.

### pfctl invocations

| Command | When | What it does |
|---|---|---|
| `pfctl -s rules` | `Probe` | Prints the main ruleset, checked for the `anchor "com.apple/*"` line |
| `pfctl -s nat` | `Probe` | Prints the main translation rules, checked for the `nat-anchor "com.apple/*"` line |
| `pfctl -a com.apple/plexd -f -` | Every change | Loads the rendered anchor from stdin, replacing what it held |
| `pfctl -E` | After the first load | Enables pf and prints a reference token |
| `pfctl -a com.apple/plexd -F all` | Last chain gone, no NAT | Flushes the anchor |
| `pfctl -X <token>` | After that flush | Gives plexd's reference back |

The binary is addressed as `/sbin/pfctl`, absolutely, because launchd starts the daemon with a minimal environment in which `pfctl` is not guaranteed to be on `PATH`. Every invocation runs under a 10 second timeout, so a wedged host cannot stall policy enforcement. The anchor is loaded before pf is enabled, so pf never runs with an empty plexd anchor in between.

### The enable reference

`pfctl -E` enables pf and prints a token:

```text
pf enabled
Token : 13971906727590307623
```

The token is one reference. pf stays enabled while any reference is held, and `pfctl -X <token>` releases the one it names. plexd takes exactly one, on the first successful load, and gives it back when its last chain is deleted and no NAT rule is left, so plexd does not keep pf switched on for a host that had it off. On a host where another holder keeps pf enabled, pf stays enabled. `pfctl -s References` lists the holders.

The controller forgets the token even when `-X` failed. A leaked reference only means pf stays enabled, and a retry with the same token could not release it either.

### Probe

`Probe` reads and changes nothing. It runs `pfctl -s rules` and `pfctl -s nat`, which need the same access to `/dev/pf` every mutating call takes, and checks that the main ruleset still references the wildcard anchors Apple ships. Without them the kernel never evaluates `com.apple/plexd`, and plexd would load rules that enforce nothing. The check runs per line, because `pfctl` prints a `scrub-anchor` line for the same wildcard that carries the filter form as a substring.

Two failures are its own:

```text
policy: pf: probe: the main ruleset does not reference anchor "com.apple/*"; restore /etc/pf.conf and run pfctl -f /etc/pf.conf
policy: pf: probe: the main ruleset does not reference nat-anchor "com.apple/*"; restore /etc/pf.conf and run pfctl -f /etc/pf.conf
```

`Enforcer.Preflight` calls `Probe` before `plexd up` registers, so a node that cannot enforce exits before it spends its one-shot bootstrap token. `AddNATMasquerade` calls it too, on its first use. `Preflight` returns early with `policy.enabled: false` — the configuration an operator picks who wants bridge routing without enforcement — and without that second call a missing `nat-anchor` line would leave the bridge loading a `nat` rule the kernel never evaluates, with every `pfctl` invocation reporting success and mesh traffic still leaving the Mac untranslated.

### Interface names

A pf rule without `on <iface>` applies to every interface of the host, so a rule with an empty interface name is rejected: a default deny among them would cut the Mac off its own networks.

The name has to be the kernel's. `plexd up` hands the enforcer `Manager.OSInterfaceName()`, which on macOS is the `utunN` the WireGuard controller created rather than the configured `plexd0`, so the rendered rules carry `utunN`; see [The utunN name](./wireguard.md#the-utunn-name).

### Inspecting the anchor

```bash
sudo pfctl -a com.apple/plexd -s rules   # the filter rules plexd loaded
sudo pfctl -a com.apple/plexd -s nat     # the masquerade rule, if one is configured
sudo pfctl -s References                 # every holder keeping pf enabled, plexd among them
```

`pfctl` prints its own normalised form rather than the text plexd loaded: a `block` reads `block drop`, a single port reads `port = 443`, and a dynamic address pool carries a trailing `round-robin`. A `keep state` line reads `flags S/SA keep state`, `from any to any` without ports reads `all`, `icmp6` reads `ipv6-icmp`, and an `icmp-type` or `icmp6-type` list loads as one rule per type. The relay probe's port 9 may read `discard`, its `/etc/services` name.

## Windows: WFP

The binding is `github.com/tailscale/wf`, the BSD-3 licensed package tailscaled drives WFP with, pinned to commit `6fbb0a674ee6`. It is imported from `//go:build windows` files only, so no other target pulls it into a build.

### The session and the sublayer

The controller opens one dynamic WFP session, named `plexd` with the description `plexd policy enforcement`, for the first chain, and closes it when the last chain is deleted. Everything added through a dynamic session goes when the session closes or the process dies, so a crashed plexd leaves no filter behind that an operator would have to hunt down. The Wintun adapter goes with the process too, so nothing arrives that those filters could have governed.

Every filter is filed into one sublayer:

| Field | Value |
|---|---|
| Name | `plexd policy` |
| Description | `plexd network policy filters` |
| Weight | `0xFFFE` |
| ID | A fixed GUID, the first 16 bytes of the SHA-256 of `plexd wfp: plexd policy sublayer` |

The weight is one below the maximum, which wireguard-windows claims for its kill switch, so a tunnel app's block-all still wins over a plexd permit. The ID is fixed rather than random, so plexd's objects carry the same identifier on every host and every run and an operator can recognise them in the filter engine's own tools.

`Probe` opens and closes such a session and leaves nothing behind: it needs the same access to the engine every mutating call takes, and a dynamic session with no objects in it drops nothing on close.

### Layers and conditions

An IPv4 rule yields one filter at the local-delivery layer `LayerALEAuthRecvAcceptV4`, named `plexd <chain> #<i> inbound`, a second at the connect layer `LayerALEAuthConnectV4`, named `plexd <chain> #<i> outbound`, and a third at the forward layer `LayerIPForwardV4`, named `plexd <chain> #<i> forward`. An IPv6 rule goes to `LayerALEAuthRecvAcceptV6`, `LayerALEAuthConnectV6` and `LayerIPForwardV6` instead, under names ending in ` v6`: `plexd <chain> #<i> inbound v6`, `plexd <chain> #<i> outbound v6` and `plexd <chain> #<i> forward v6`. A rule without addresses, the default deny, goes to all six layers. Only an `allow` that names a protocol or a port has no forward filter; see [What the rules govern](#what-the-rules-govern).

| Rule field | `LayerALEAuthRecvAcceptV4`, `LayerALEAuthRecvAcceptV6` (inbound) | `LayerALEAuthConnectV4`, `LayerALEAuthConnectV6` (outbound) | `LayerIPForwardV4`, `LayerIPForwardV6` (forward) |
|---|---|---|---|
| `Interface` | `FieldIPLocalInterface` equals the LUID | `FieldIPLocalInterface` equals the LUID | `FieldSourceInterfaceIndex` equals the index |
| `SrcIP` | `FieldIPRemoteAddress` | `FieldIPLocalAddress` | `FieldIPSourceAddress` |
| `DstIP` | `FieldIPLocalAddress` | `FieldIPRemoteAddress` | `FieldIPDestinationAddress` |
| `Protocol` | `FieldIPProtocol`; `icmp` is `IPProtoICMP` at the V4 layers and `IPProtoICMPV6` at the V6 layers | `FieldIPProtocol`, as inbound | The layer has no such field: dropped on a `deny`, and an `allow` gets no forward filter |
| `Port`, `PortTo` | `FieldIPLocalPort`, an equality or a `wf.Range` | `FieldIPRemotePort`, an equality or a `wf.Range` | The layer has no such field: dropped on a `deny`, and an `allow` gets no forward filter |
| `Action` | `wf.ActionPermit` or `wf.ActionBlock` | The same | The same |

Windows delivers a packet locally only when its destination is an address of the arrival interface, so the local interface is the arrival interface, the `iifname` the Linux chain matches. Windows sends a packet only from an address of the interface it leaves through, so at the connect layers the local interface is the outgoing interface, the `oifname` the Linux output chain matches. There the rule's source is the node's side of the flow and its destination the remote side. `wfpPrefix` parses every address with `parseRuleAddr`, which the three backends share. An empty address field, `0.0.0.0/0` or `::/0` yields no address condition; the layer alone selects the family. An IPv4 address is matched as an address and mask. An IPv6 address is matched as the range from its prefix's first to its last address, which matches the same packets: `github.com/tailscale/wf` builds a filter in an allocator that never aligns, and the 17-byte IPv6 address-and-mask struct would leave the rest of the filter on an odd address, which the race detector's pointer checks reject. `netsh wfp show filters` therefore lists IPv6 addresses as ranges. A rule with an empty interface name is rejected: a filter without an interface condition would govern every adapter of the host.

`ALE_AUTH_CONNECT` authorizes the node's own outbound connections and the first packet of its other flows. Replies need no outbound filter: once `ALE_AUTH_RECV_ACCEPT` authorizes a flow, its packets pass in both directions without another classification, and ICMP error messages never reach the ALE layers. Microsoft describes both in [ALE Stateful Filtering](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-stateful-filtering). Forwarded traffic never reaches `ALE_AUTH_CONNECT`, so what the node forwards into the mesh is not filtered on its way out.

Ahead of the rule filters, every interface the rules name gets two relay probe permits, once: `plexd <chain> relay probe` at `LayerALEAuthConnectV4` and `plexd <chain> relay probe v6` at `LayerALEAuthConnectV6`. Their conditions are `FieldIPLocalInterface` equal to the LUID, `FieldIPProtocol` equal to `wf.IPProtoUDP` and `FieldIPRemotePort` equal to `RelayProbePort`, 9. They name no address, since the probe goes to whichever peer is relayed. Their weight is above rule 0's, so no rule of the chain decides the probe; see [Weights and the epoch](#weights-and-the-epoch).

### Weights and the epoch

Within a sublayer WFP evaluates the heaviest filter first and the first terminating action wins, which is the first-match order the other two backends have. Filter `i` of `n` in epoch `e` gets:

```go
weight := uint64(e)<<32 | uint64(n-i)
```

Here `i` is the index of the rule, and all filters of one rule share its weight. The relay probe permits take `i = -1`, `wfpWeight(e, n, -1)`, which outweighs rule 0. Rule 0 is the heaviest of its own apply, and the epoch in the high half makes every filter of a newer apply outweigh every filter of an older one. `ApplyRules` builds its filters in `epoch+1` and installs them all before it deletes the ones the chain held, so the chain is never unfiltered in between and the new decisions win while both sets are installed. The weight stays below 2^60 for 2^28 applies, which is what a `FWP_UINT64` weight accepts.

Every rule is translated before the first filter is installed, so a rule the engine would reject fails without leaving half a ruleset behind. When an `AddRule` fails anyway, every filter that call installed is deleted again and the chain keeps the ones it had.

### Interface resolution

A rule carries the friendly name, the name the configuration holds and the one a Wintun adapter is created under. `net.InterfaceByName` resolves it to an interface index and `winipcfg.LUIDFromIndex` turns that index into the LUID. The forward layer matches the index, the local-delivery and connect layers the LUID. Each name is resolved once per apply, because most rules of a chain name the same interface and every lookup is a syscall.

### Soft permits

`HardAction` stays false on every filter, so a plexd permit is a soft one that the Windows Firewall's own sublayer may still block, while a plexd block is final. plexd's rules cannot open a port the host firewall closes.

### Inspecting the filters

```powershell
netsh wfp show filters file=-
```

The dump lists every filter in the engine. plexd's carry the names `plexd <chain> #<i> inbound`, `plexd <chain> #<i> outbound`, `plexd <chain> #<i> forward` and `plexd <chain> relay probe`, with ` v6` appended at the IPv6 layers, and sit in the sublayer `plexd policy`. Without `file=-` the command writes the same XML to `filters.xml` in the working directory.

## NAT

`RouteController` embeds `bridge.NATController`, and on both platforms the firewall controller is the backend the route controller delegates to. `cmd/plexd/cmd/up_darwin.go` and `up_windows.go` build one controller and hand the same instance to the enforcer and to the route controller; see [macOS & Windows Route Controllers](../bridge/route-controllers-macos-windows.md#nat).

On macOS the masquerade is a `nat` rule in the same anchor as the policy rules:

```text
nat on <access_interface> inet from any to any -> (<access_interface>)
```

Everything leaving the access interface is translated, the host's own traffic included, which is what `oifname masquerade` does on Linux. The parenthesised form is the interface's current address as the kernel tracks it, so a renewed lease needs no reload. The controller holds one such rule at a time; `RemoveNATMasquerade` logs the interface it is given rather than comparing it, as the Linux backend deletes its whole NAT table regardless of the name.

WFP cannot rewrite addresses without a callout driver of its own, and Internet Connection Sharing reassigns the private adapter's address, so the Windows translation is a WinNAT object driven through PowerShell:

```powershell
New-NetNat -Name plexd -InternalIPInterfaceAddressPrefix 10.42.0.0/16 | Out-Null

$ErrorActionPreference = 'Stop'; try { (Get-NetNat -Name plexd).InternalIPInterfaceAddressPrefix } catch { if ($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*') { throw } }; exit 0

$ErrorActionPreference = 'Stop'; try { Remove-NetNat -Name plexd -Confirm:$false } catch { if ($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*') { throw } }; exit 0
```

Both the read and the delete are wrapped, so a name no object carries is a success with no output while every other failure still terminates and reaches the controller. The marker is the error id `CmdletizationQuery_NotFound`, which every CDXML query cmdlet raises for a missing object — not the message that carries it, which is localized and would make the match miss on every non-English Windows install. `$ErrorActionPreference = 'Stop'` is what turns the cmdlet's non-terminating error into a catchable one, and the trailing `exit 0` is what makes the swallowed miss a success: `-Command` derives the process exit code from `$?` after the last statement, and a caught error leaves `$?` false, so without it the miss exits 1 with no output. A rethrow terminates the script before the exit is reached and still exits 1.

`Remove-NetNat` prompts for confirmation by default and a service has no console to answer with, hence `-Confirm:$false`. Every cmdlet is built from one `netNatName` constant, so the name plexd creates and the name plexd reports cannot drift apart. PowerShell is addressed absolutely under the directory `GetSystemDirectory` returns, not under `%SystemRoot%`: an elevated process inherits the environment block of whoever started it, so resolving the binary through that variable would run an unprivileged user's choice of `powershell.exe` as Administrator. Every invocation runs under a 30 second timeout, since PowerShell takes seconds to start on a cold host.

The prefix is the mesh adapter's own: the controller reads the mesh interface's IPv4 address and its on-link prefix length, which is the mesh CIDR the address was assigned with. WinNAT is scoped by source prefix, not by outgoing interface, so only traffic sourced from the mesh is translated. A user-access or site-to-site source outside the mesh prefix is not translated on Windows. The interface name reaches the call only to be logged — `bridge.NATController` documents that divergence, because `bridge.Manager` calls the same method on all three platforms.

`AddNATMasquerade` is idempotent: an object that already translates the mesh prefix is left alone, and one that translates another prefix is removed and rebuilt, because the mesh moved and the host has no room for a second object. Client editions of Windows hold one NetNat object per host, which is why plexd keeps exactly this one.

Inspect the object with:

```powershell
Get-NetNat -Name plexd
```

## Error prefixes

Every policy failure reads `policy: pf: <op>:` or `policy: wfp: <op>:`, with `<op>` one of `probe`, `ensure chain`, `apply rules`, `flush chain` and `delete chain`. NAT failures carry the bridge prefixes instead, so a log line reads the same as the Linux one and the route controller's.

| Failure | Prefix |
|---|---|
| Any `pfctl` invocation | `policy: pf: <op>: <command line>:` followed by the error and pfctl's own output |
| An empty chain name | `policy: pf: ensure chain: chain name is empty`, `policy: pf: apply rules: chain name is empty` |
| A rule that does not render | `policy: pf: apply rules: rule <i>:` |
| A wildcard anchor missing from the main ruleset | `policy: pf: probe: the main ruleset does not reference anchor "com.apple/*"`, and the same for `nat-anchor` |
| `pfctl -E` without a token line | `policy: pf: <op>: pfctl -E printed no token: "<output>"` |
| Opening the filter engine | `policy: wfp: probe:`, `policy: wfp: <op>: open session:` |
| Adding the sublayer | `policy: wfp: <op>: add sublayer:` |
| An empty chain name | `policy: wfp: ensure chain: chain name is empty`, `policy: wfp: apply rules: chain name is empty` |
| A rule that does not translate | `policy: wfp: apply rules: rule <i>:` |
| Installing a filter | `policy: wfp: apply rules: add filter "<name>":`, with the filter's name, such as `plexd <chain> #<i> inbound` or `plexd <chain> relay probe` |
| Deleting a chain's filters | `policy: wfp: apply rules: delete stale filters:`, `policy: wfp: flush chain "<chain>":`, `policy: wfp: delete chain "<chain>":` |
| Closing the session | `policy: wfp: probe: close session:`, `policy: wfp: delete chain: close session:` |

| NAT failure | Prefix |
|---|---|
| Any leg of the macOS masquerade | `bridge: add NAT masquerade on "<iface>":`, `bridge: remove NAT masquerade on "<iface>":` |
| An empty interface name on macOS | `bridge: add NAT masquerade on "": interface name is empty` |
| Resolving the mesh prefix on Windows | `bridge: add NAT masquerade on "<iface>": resolve mesh prefix for "<mesh iface>":` |
| Any PowerShell command | `bridge: <op>: powershell -Command "<script>":` followed by the error and PowerShell's output |

A privilege failure carries a hint, because the tool's own message does not name the privilege it wanted. macOS appends ` (policy enforcement on macOS requires root)` when pfctl's output holds `Permission denied`; Windows appends ` (policy enforcement on Windows requires Administrator)` on `ERROR_ACCESS_DENIED`. A pf failure also carries the command line and pfctl's output, since `exit status 1` alone is not actionable:

```text
policy: pf: apply rules: /sbin/pfctl -a com.apple/plexd -f -: <error>: <pfctl output> (policy enforcement on macOS requires root)
```

The two failures `plexd up` aborts on, the pre-flight probe and the deny-by-default baseline, wrap these with a per-platform hint naming the opt-out; see [policy](../core/configuration.md#policy).

## Logging

All entries carry `component=policy` for the filter operations and `component=bridge` for the NAT ones. All are at `Debug` except the two `Warn` lines and the one `Error` line.

| Message (`component=policy`) | Keys |
|---|---|
| `pf backend probed` | `anchor` |
| `pf enabled` | `anchor`, `token` |
| `pf anchor flushed and reference released` | `anchor` |
| `pf chain ensured` | `chain`, `anchor` |
| `pf chain already present` | `chain` |
| `pf rules applied` | `chain`, `count` |
| `pf chain flushed`, `pf chain deleted` | `chain` |
| `pf chain not found, nothing to flush` | `chain` |
| `pf chain not found, nothing to delete` | `chain` |
| `wfp backend probed` | none |
| `wfp chain ensured`, `wfp chain already present` | `chain` |
| `wfp rules applied` | `chain`, `count`, `filters` |
| `wfp chain flushed`, `wfp chain deleted` | `chain` |
| `wfp chain not found, nothing to flush` | `chain` |
| `wfp chain not found, nothing to delete` | `chain` |
| `wfp forward path cannot enforce a protocol or port, allow rules narrowed away` (`Warn`) | `chain`, `count` |
| `wfp forward path cannot enforce a protocol or port, deny rules widened to every protocol and port` (`Warn`) | `chain`, `count` |
| `wfp rollback delete failed` (`Error`) | `filter`, `error` |

| Message (`component=bridge`) | Keys |
|---|---|
| `NAT masquerade configured` (macOS) | `interface`, `anchor` |
| `NAT masquerade configured` (Windows) | `interface`, `prefix`, `nat` |
| `NAT masquerade already configured` (Windows) | `interface`, `prefix` |
| `NAT masquerade removed` | `interface` |
| `NAT masquerade not configured, idempotent success` (macOS) | `interface` |

`count` is the number of rules the chain was given, `filters` the number of WFP filters they became, which is larger: every rule yields an inbound and an outbound filter per family, some a forward filter too, and every interface two relay probe permits. Three lines sit above `Debug`. `wfp forward path cannot enforce a protocol or port, allow rules narrowed away` names, per apply, how many `allow` rules the node does not enforce on the forward path because they name a protocol or a port. `wfp forward path cannot enforce a protocol or port, deny rules widened to every protocol and port` names how many `deny` rules went onto the forward path without their protocol and port; the engine's only deny names neither, so it does not appear with the rules plexd builds today. Each `count` is a subset of the chain's rules, not of its filters. `wfp rollback delete failed` reports an apply whose `AddRule` failed: it deletes the filters it already installed, and a deletion that fails there leaves a filter behind that only the session's close drops.

## Tests

Both controllers reach the operating system through seams, so every rendered rule and every idempotent case runs on an ordinary unprivileged runner. macOS wires the package's recording runner in place of `pfctl`, which captures each invocation's arguments and its stdin, so a test pins the whole anchor text a change renders. Windows wires a `wfpEngine` fake in place of the session, which records the sublayer, the filters in the order they were added and the deletions, and can be armed to fail a chosen `AddRule`; PowerShell goes through the same recording runner. The fake refuses a filter whose condition names a field its layer does not have, as the engine does, from a per-layer list of the fields plexd uses: a protocol or a port at a forward layer fails a unit test rather than the real one.

`TestPFController_RenderParses` runs the real `pfctl -n -q -a com.apple/plexd -f -` over the rendered text. `-n` parses without loading, which needs no access to `/dev/pf`, so the test proves the rendered syntax is pf's without root. The anchor it parses holds every line form: the relay probe line, `keep state` and `no state` outbound lines, a `flags A/A` mirror with a port range, both ICMP type lists, and `block out quick on <if> from (<if>) to any`.

Five tests drive the real host and are gated:

| Test | Gate | Locally |
|---|---|---|
| `TestPFController_Real` (`pf_darwin_test.go`) | `PLEXD_TEST_REAL_PF=1` and `os.Geteuid() == 0` | `sudo PLEXD_TEST_REAL_PF=1 go test -run '^TestPFController_Real$' ./internal/policy/` |
| `TestPFController_RealTraffic` (`tuntraffic_darwin_test.go`) | The same | `sudo PLEXD_TEST_REAL_PF=1 go test -run '^TestPFController_RealTraffic$' ./internal/policy/` |
| `TestWFPController_Real` (`wfp_windows_test.go`) | `PLEXD_TEST_REAL_WFP=1` and an elevated token | `$env:PLEXD_TEST_REAL_WFP='1'; go test -run '^TestWFPController_Real$' ./internal/policy/` from an elevated shell |
| `TestWFPController_RealNAT` (`netnat_windows_test.go`) | The same | `$env:PLEXD_TEST_REAL_WFP='1'; go test -run TestWFPController_RealNAT ./internal/policy/` from an elevated shell |
| `TestWFPController_RealTraffic` (`tuntraffic_windows_test.go`) | The same | `$env:PLEXD_TEST_REAL_WFP='1'; go test -run TestWFPController_RealTraffic ./internal/policy/` from an elevated shell, with every Windows Firewall profile off |

`TestPFController_Real` loads an anchor naming `plexd99`, an interface no host has, with an IPv6 rule and the default deny among its rules, takes the pf reference, reads the filter and nat rules back with `pfctl -a com.apple/plexd -s rules` and `-s nat`, and finds the `inet6` rule and a block rule without an address there. In pfctl's printed form it also finds a `keep state` outbound line, a `flags A/A` mirror, both ICMP mirrors, `block drop out quick on plexd99 from (plexd99) to any`, and the relay probe line as the only `pass out` line from `(plexd99)`. It then deletes the chain and asserts the anchor is empty and the token released. A host that had pf disabled is left disabled. The variable gates it in addition to the effective uid, so `sudo go test ./...` on a developer's Mac does not enable pf on their host.

`TestWFPController_Real` installs filters for prefixes no host carries, IPv6 rules among them, one of which names addresses alone, and the default deny, which shows that the filter engine accepts filters at the V6 layers, an IPv6 prefix at `FWPM_LAYER_IPFORWARD_V6` included. It enumerates plexd's filters through a session of its own, checks that the allows naming a protocol or a port got no forward filter, and pins `FWP_E_FILTER_NOT_FOUND` by deleting a filter that is not there. It finds a `#<i> outbound` filter at `LayerALEAuthConnectV4` for every IPv4 rule, a `#<i> outbound v6` filter at `LayerALEAuthConnectV6` for every IPv6 rule, and the two relay probe permits once, which shows that the engine takes plexd's conditions at the connect layers. It also checks that the outbound filters of its allow of everything are permits. It cannot read their weights back: `github.com/tailscale/wf` declares the union of `rawContext` and `providerContextKey` in `FWPM_FILTER0` as two fields, so it reads `effectiveWeight` 8 bytes off and reports 0 for every filter. That the allow outweighs the default deny rests on the unit tests, which pin every filter's weight through the fake engine, and on `TestWFPController_RealTraffic`, which shows on the real engine that a permit at `ALE_AUTH_CONNECT` outweighs the default deny. A run that fails with the default deny installed first replaces the ruleset with the allow of everything alone and then deletes the chain, so the deny never stands alone on the runner's interface. `TestWFPController_RealNAT` creates the NetNat object for `10.255.252.0/30`, reads the prefix back, and repeats both the add and the remove to prove they are idempotent — the second read after the removal is what proves the absent case is a success with no output rather than a localized error.

The two traffic tests and Linux's `TestNftablesController_RealTraffic` (see [nftables Firewall Controller](./nftables-firewall.md#tests)) run the same checks, `runTunTrafficChecks` in `tuntraffic_test.go`. Each test creates a TUN device, puts node N's address 10.255.247.1 on it, and hands the checks a `tunHarness`: the controller, the device, the offset the device needs in front of each packet, and the interface name the rules carry. The test plays peer P, 10.255.247.2, behind the device: a packet it writes into the device arrives at N from P, and what N sends to P comes out of the device for the test to read. No other test uses this prefix. `TestPFController_RealTraffic` creates a `utun` and runs `/sbin/ifconfig <utun> inet 10.255.247.1 10.255.247.2 up`, with an offset of 4 for the address family wireguard-go's utun writes in front of each packet. `TestWFPController_RealTraffic` writes `wintun.dll` beside the test binary with `wintundll.Ensure`, creates the adapter `plexd-fwtest`, and assigns 10.255.247.1/30 through `winipcfg`, with an offset of 0.

N listens on TCP 7001 and 7003 and echoes UDP on 7002. As a control, before any chain exists, a SYN from P to N:7001 must draw a SYN-ACK within 3 s. Otherwise the test fails with `the host answers nothing through the test device without plexd's filters`. The test then applies, in chain `plexd-test`:

```text
r0 tcp  10.255.247.2/32 → 10.255.247.1/32 port 7001
r1 udp  10.255.247.2/32 → 10.255.247.1/32 port 7002
r2 icmp 10.255.247.2/32 → 10.255.247.1/32
r3 udp  10.255.247.1/32 → 10.255.247.2/32 port 7005
r4 tcp  10.255.247.1/32 → 10.255.247.2/32 port 7006
r5 the default deny
```

and checks that:

- a SYN from P to N:7001 draws a SYN-ACK, and a SYN to N:7003, where N listens, draws no SYN-ACK within 2 s;
- a datagram from P to N:7002 comes back as N's echo;
- an echo request from P draws an echo reply with the same id and sequence;
- a datagram N sends to P:7005 comes out of the device, and one to P:7007 does not within 2 s;
- a dial from N to P:7006 puts a SYN on the device, and a dial to P:7008 does not within 2 s;
- a datagram N sends to P:9, which no rule names, comes out of the device.

The SYN-ACK, the echo and the echo reply are replies to what r0 to r2 let in, so the checks prove each platform's reply path: connection tracking on Linux, the mirrors on macOS and the ALE flow on Windows. When the test ends it closes the device, which ends its reader, before it deletes the chain. The Windows Firewall blocks the unsolicited packets the test injects on its own, so the CI step turns every firewall profile off first with `Set-NetFirewallProfile -All -Enabled False`. plexd's filters sit in a sublayer of their own and do not depend on the Windows Firewall.

CI runs all five; see [CI Workflow](../development/ci-workflow.md).
