---
title: pf & WFP Firewall Controllers
package: internal/policy
---

# pf & WFP Firewall Controllers

`PFController` (`pf_darwin.go`, `pflog_darwin.go`) and `WFPController` (`wfp_windows.go`, `netnat_windows.go`) are the non-Linux implementations of the `FirewallController` interface defined in `internal/policy`. macOS programs its rules with `pfctl(8)` and needs root. Windows programs the Windows Filtering Platform through `github.com/tailscale/wf` and WinNAT through PowerShell, both of which need Administrator, which the LocalSystem service satisfies.

Both controllers also implement `bridge.NATController`, so one instance carries the policy rules and the bridge's masquerade rule; see [NAT](#nat).

The Linux implementation is [`NftablesController`](./nftables-firewall.md).

## What the rules govern

On all three platforms the rules govern everything that arrives on the mesh interface, whether the packet is delivered to the node itself or forwarded through it, and everything the node's own sockets send over it. A rule matches by its addresses. The control plane compiles every rule for both ends: the destination node's copy names the peer as the source, and the source node's copy names the node itself, so each copy matches one direction. A node rejects unsolicited mesh traffic to its own addresses until a rule allows it, and drops what it sends to a mesh address until a rule allows that too, because the ruleset ends in a default deny. Replies to a connection the policy let in leave without a policy rule of their own on Linux and Windows, and on macOS for tcp, udp and icmp; see below.

What the node forwards into the mesh is not filtered on its way out, on any platform. On Linux such a packet takes the forward hook, whose chain matches the interface it arrived on. On macOS the default deny's `block out` line names the interface's own addresses as the source, which a forwarded packet does not carry. A packet a [mesh source rewrite](#mesh-source-rewrite) translates does carry the mesh interface's address, and the rewrite's `nat` line carries `pass`, which makes pf skip the filter rules for it, so a bridge's device and site traffic is not filtered on its way out either. On Windows forwarded traffic never reaches `ALE_AUTH_CONNECT`, and what a bridge's [in-process mesh source rewrite](./wireguard.md#in-process-mesh-source-rewrite) translates never reaches Windows at all.

On every platform the node can send UDP to port 9, `RelayProbePort`, over the mesh interface without a rule, ahead of the policy rules. That is plexd's [relay liveness probe](./wireguard.md#relay-liveness-probe). Any local process can use the exemption, to any address the mesh routes, and the receiving node's inbound rules still apply.

UDP to port 7911, `RTTProbePort`, passes the mesh interface without a rule in both directions on every platform, ahead of the policy rules: what the node sends to the port and what arrives for the node on it, never what the node forwards. That is plexd's [round-trip probe](./wireguard.md#round-trip-probe). Its socket sends from port 7911 and answers from port 7911, so a probe and its answer both go to port 7911, and the one exemption covers both. Any local process on a peer can send UDP to port 7911 of the node, where it reaches the socket that holds the port on the mesh address, which is plexd's.

Every rule may name IPv4 or IPv6 prefixes. The default deny names no address and covers both families.

On Linux `NftablesController` installs the same rules in an input chain, a forward chain and an output chain, and connection tracking passes a packet in the reply direction of a tracked connection without a rule; see [nftables Firewall Controller](./nftables-firewall.md#connection-tracking).

On macOS three lines precede the policy rules of every chain, once per interface the chain mentions, in order of first appearance:

```text
pass out quick on utun4 proto udp from (utun4) to any port 9 no state
pass out quick on utun4 proto udp from (utun4) to any port 7911 no state
pass in quick on utun4 proto udp from any to (utun4) port 7911 no state
```

The first is the relay probe exemption. It names no address family, so it covers IPv4 and IPv6, and it keeps no state, so it lets nothing back in. `(utun4)` is the interface's own addresses as the kernel tracks them, not a snapshot taken when the anchor was loaded, so a mesh address assigned after the load needs no reload. Each policy rule then renders its own lines; see [The rendered anchor](#the-rendered-anchor).

The other two are the round-trip probe exemption. The anchor keeps no state for UDP on a Mac (see below), so it needs both lines: the `pass out` line for the probes the node sends and its answers to its peers' probes, and the `pass in` line for the peers' probes and their answers to the node's. `(utun4)` is the source of the first and the destination of the second, so neither matches what the Mac forwards. Because neither line keeps state, an answer leaves a Mac only when it goes to port 7911, which the answer to a plexd probe does: plexd sends every probe from port 7911.

The node's own TCP connections keep state. An allow that names `tcp`, or no protocol, renders a `pass out ... proto tcp ... keep state` line, and the state entry matches the reply before the default deny is reached. A revoked rule therefore stops a Mac's established outbound TCP connection only when that connection ends.

Only TCP keeps state. pf consults the state table ahead of the ruleset and a state entry is bidirectional, so a stateful rule covering every protocol would keep an inbound-initiated UDP or ICMP flow alive after the rule that allowed it was revoked: the node's own reply creates the entry, and every further packet of that flow matches it instead of the ruleset. pf's idle timeouts refresh on each packet, so an active flow would never expire. TCP is not affected, because the implicit `flags S/SA` pfctl puts on a stateful TCP pass rule means an outbound SYN-ACK creates no state. The node's own UDP and ICMP flows stop at their next packet once their rule is revoked.

The cost is that a Mac's own UDP and ICMP flows over the mesh get no automatic return path: a reply arriving on the mesh interface is subject to the policy like any other inbound packet, so the policy has to allow it. This is the fail-closed side of the trade: a revoked rule cuts what arrives at once, on every protocol.

Replies to what a rule lets in leave through stateless mirror lines, with the rule's source and destination swapped. The inbound lines stay stateless so that a revoked rule cuts inbound traffic at once, which means pf can tell a reply from a new flow only by its shape. A TCP mirror carries `flags A/A`, which keeps the Mac from opening a TCP connection through it, and an ICMP mirror carries only replies and errors. A UDP mirror, however, lets the Mac send from the rule's port, or from any port for a rule without ports, to a peer that may reach it. Linux and Windows allow no such thing.

The mirrors also carry less than Linux's connection tracking does. A reply in a protocol other than tcp, udp and icmp matches no mirror. Neither does an ICMP error the Mac sends from its own address about traffic it forwards, such as a time exceeded for a traceroute through it. Both meet the default deny unless a rule allows them from the node's own address.

On Windows the node's own traffic is filtered at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `FWPM_LAYER_ALE_AUTH_CONNECT_V6`, which authorize the node's own outbound connections and the first packet of its other flows. Replies leave through the ALE flow the inbound accept authorized and need no outbound filter; see [Layers and conditions](#layers-and-conditions).

The round-trip probe's permits sit at the connect layers, for what the node sends to port 7911, and at the receive-accept layers, for what arrives for the node on it, and at no forward layer. They are soft, as every plexd permit is (see [Soft permits](#soft-permits)), so Windows Defender Firewall can still drop the inbound probe: a node needs the rule of step 4 of the [Windows installation guide](../../how-to/windows-installation.md#_4-allow-inbound-wireguard-traffic) to answer its peers' probes.

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
pass out quick on utun4 proto udp from (utun4) to any port 7911 no state
pass in quick on utun4 proto udp from any to (utun4) port 7911 no state
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
block in quick on utun4 from any to any label "plexd-default-deny"
block out quick on utun4 from (utun4) to any label "plexd-default-deny"
```

`render` opens the chain with the relay probe line and the two round-trip probe lines. `renderRule` returns every line of one rule. An allow renders, in this order:

1. A `pass in` line, which lets in what the rule allows.
2. `pass out` lines for the node's own traffic: `tcp` with `keep state`, `udp` and `icmp` with `no state`. A rule without a protocol renders the `tcp` line and then a `no state` line for every protocol.
3. Reply mirrors, with source and destination swapped: a `tcp` mirror with `flags A/A` for a rule that names `tcp` or no protocol, a `udp` mirror for one that names `udp` or no protocol, and for every allow the ICMP replies and errors of its family. A rule without addresses gets the ICMP mirror of both families.

A deny renders a `block in` line and a `block out` line. The `block out` line names the interface's own addresses, `(utun4)`, in place of an empty source, so the default deny drops what the node sends and leaves alone what the Mac forwards out of the interface. Both lines end in `label "plexd-default-deny"`, the constant `pfDropLabel`, under which pf counts what they drop; see [Drop counters](#drop-counters). No `pass` line carries a label. The engine puts the default deny last, so its two `block` lines follow every `pass` line.

| Element | Meaning |
|---|---|
| `# chain plexd-mesh` | pf has no user chains, so the chain is a comment. The name is what `ApplyRules`, `FlushChain` and `DeleteChain` address |
| `quick` | The first matching rule is final, the first-match semantics the nftables backend has |
| `no state` | Every packet stays subject to the current rules, so a revoked rule takes effect at once instead of after the last flow expires. Every `pass in` line, every mirror, the relay probe line, the round-trip probe lines, the node's own `udp`, `icmp` and protocol-less `pass out` lines, and the unlogged `tcp` `pass out` line of a logged rule without a protocol carry it |
| `keep state` | The node's own TCP connections. pfctl adds `flags S/SA`, so only the node's own SYN creates a state entry, never its SYN-ACK to an inbound connection. A revoked rule stops such a connection only when it ends |
| `flags A/A` | A TCP mirror matches only a segment with ACK set, so the Mac cannot open a TCP connection through it |
| `icmp-type { ... }`, `icmp6-type { ... }` | What an ICMP mirror lets the node send: the echo reply and the errors a host sends about a packet it received. IPv4 reports a packet too big for the path as a code of `unreach`, IPv6 as the type `toobig` |
| `(utun4)` | The interface's own addresses as the kernel tracks them. The relay probe line, the round-trip probe's `pass out` line and the default deny's `block out` line use it as the source, so they match what the node sends and not what the Mac forwards. The round-trip probe's `pass in` line uses it as the destination, so it matches what arrives for the node and not what the Mac forwards |
| `inet`, `inet6` | The family of the rule's addresses. A rule without addresses, the default deny, carries neither and matches both, as do the relay probe line and the round-trip probe lines. An ICMP mirror names its own family |
| `icmp6` | Protocol `icmp` in an IPv6 rule, which means ICMPv6 |
| `block in`, `block out` | The default deny, the only deny rule the engine builds. pf's default block policy is drop, what the nftables backend expresses as `VerdictDrop` |
| `label "plexd-default-deny"` | Makes pf keep the packets and bytes the `block` lines drop under one label, which `pfctl -sl` prints and `DropCounts` sums |
| `any` | An empty address field, `0.0.0.0/0` or `::/0`. Under `0.0.0.0/0` or `::/0` the family keyword stays, so the rule still matches only its own family |

Chains are rendered in name order, so the same desired state always yields the same text. The `nat` rules, the bridge NAT's and one per mesh interface the [mesh source rewrites](#mesh-source-rewrite) name, are rendered ahead of the chains, because pf requires translation rules before filter rules in a file. The two filter lines of each rewrite follow the last chain.

### Logged rules

A rule with a `LogTag` carries `log` right after `pass in` or `pass out` on the lines that let in or out what it admits. pf hands each packet such a line matches to `pflog0`, and on a `keep state` line only the packet that creates the state. With `F` the family keyword, `S` and `D` the rendered addresses and `P` the port clause:

- `tcp`: `pass in log quick on <if> F proto tcp from S to D P flags S/SA no state` in front of the unchanged `pass in` line, and `log` on the `keep state` line. The new line matches only a SYN, so an inbound connection logs once, and the line after it passes the rest of the connection without logging.
- `udp` and `icmp`: `log` on the `pass in` line and on the `pass out ... no state` line. Both keep no state, so every packet logs.
- No protocol: `pass in log quick on <if> F proto tcp from S to D flags S/SA no state`, then `pass in quick on <if> F proto tcp from S to D no state`, then the protocol-less `pass in` line with `log`. On the way out, `log` on the node's `keep state` line, then an unlogged `pass out quick on <if> F proto tcp from S to D no state`, then `log` on the node's protocol-less `pass out` line. The unlogged TCP lines keep the rest of a TCP connection, and the Mac's replies to an inbound one, away from the logged protocol-less lines, so a TCP connection logs once, whichever side opened it, and every packet of another protocol logs.
- Mirrors and `block` lines never carry `log`.

For `{utun4, 10.0.0.0/24 → 10.1.0.5, tcp 443, LogTag "3/0"}`, `renderRule` returns:

```text
pass in log quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 flags S/SA no state
pass in quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 no state
pass out log quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 keep state
pass out quick on utun4 inet proto tcp from 10.1.0.5 port 443 to 10.0.0.0/24 flags A/A no state
pass out quick on utun4 inet proto icmp from 10.1.0.5 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state
```

Without the tag the same rule renders the last four lines, none of them with `log`. The `Enforcer` puts the logged rules first (see [Log tags and rule order](./network-policy.md#log-tags-and-rule-order)), so their lines follow the relay probe line and the two round-trip probe lines.

pf reports a logged packet with the number of the line that matched it, so `render` also returns a map from line number to tag, for every line that starts `pass in log ` or `pass out log `. pf numbers the rules of an anchor from 0 in the order they load. The header, the `# chain` comments and the `nat` lines load none, the filter lines of the mesh source rewrites follow every chain, so they move no logged line's number, and every other line loads one rule, except a line with a brace list, which loads one rule per item: an IPv4 ICMP reply mirror loads four and an IPv6 one five. `render` counts the rules that way, and `TestPFController_RealConnLog` proves the numbering on the macOS runner. `ApplyRules` keeps the map of the anchor loaded last as the current one, and the one before as the previous one, and swaps them only after `pfctl -f` succeeds. See [pflog](#pflog) for how the records are read.

### pfctl invocations

| Command | When | What it does |
|---|---|---|
| `pfctl -s rules` | `Probe` | Prints the main ruleset, checked for the `anchor "com.apple/*"` line |
| `pfctl -s nat` | `Probe` | Prints the main translation rules, checked for the `nat-anchor "com.apple/*"` line |
| `pfctl -a com.apple/plexd -f -` | Every change | Loads the rendered anchor from stdin, replacing what it held |
| `pfctl -E` | After the first load | Enables pf and prints a reference token |
| `pfctl -a com.apple/plexd -F all` | Last chain gone, no NAT and no mesh source rewrite; `ResetMeshSourceRewrite` with nothing else held | Flushes the anchor |
| `pfctl -X <token>` | After that flush | Gives plexd's reference back |
| `pfctl -a com.apple/plexd -sl` | `DropCounts`, once per send or tick of the policy status report | Prints the anchor's labels with their counters, and changes nothing |

The binary is addressed as `/sbin/pfctl`, absolutely, because launchd starts the daemon with a minimal environment in which `pfctl` is not guaranteed to be on `PATH`. Every invocation runs under a 10 second timeout, so a wedged host cannot stall policy enforcement. The anchor is loaded before pf is enabled, so pf never runs with an empty plexd anchor in between.

### The enable reference

`pfctl -E` enables pf and prints a token:

```text
pf enabled
Token : 13971906727590307623
```

The token is one reference. pf stays enabled while any reference is held, and `pfctl -X <token>` releases the one it names. plexd takes exactly one, on the first successful load, and gives it back when its last chain is deleted and neither a NAT rule nor a mesh source rewrite is left, so plexd does not keep pf switched on for a host that had it off. A user access provider or a site-to-site tunnel that comes up on a bridge takes the reference too, so pf is switched on for a host that had it off, as a policy chain or the bridge NAT does. On a host where another holder keeps pf enabled, pf stays enabled. `pfctl -s References` lists the holders.

The controller forgets the token even when `-X` failed. A leaked reference only means pf stays enabled, and a retry with the same token could not release it either.

### Probe

`Probe` reads and changes nothing. It runs `pfctl -s rules` and `pfctl -s nat`, which need the same access to `/dev/pf` every mutating call takes, and checks that the main ruleset still references the wildcard anchors Apple ships. Without them the kernel never evaluates `com.apple/plexd`, and plexd would load rules that enforce nothing. The check runs per line, because `pfctl` prints a `scrub-anchor` line for the same wildcard that carries the filter form as a substring.

Two failures are its own:

```text
policy: pf: probe: the main ruleset does not reference anchor "com.apple/*"; restore /etc/pf.conf and run pfctl -f /etc/pf.conf
policy: pf: probe: the main ruleset does not reference nat-anchor "com.apple/*"; restore /etc/pf.conf and run pfctl -f /etc/pf.conf
```

`Enforcer.Preflight` calls `Probe` before `plexd up` registers, so a node that cannot enforce exits before it spends a redemption of its bootstrap token. `AddNATMasquerade` calls it too, on its first use, and so does the first `AddMeshSourceRewrite` on a controller that holds neither a rewrite nor the bridge NAT. `Preflight` returns early with `policy.enabled: false` — the configuration an operator picks who wants bridge routing without enforcement — and without that second call a missing `nat-anchor` line would leave the bridge loading a `nat` rule the kernel never evaluates, with every `pfctl` invocation reporting success and mesh traffic still leaving the Mac untranslated.

### Interface names

A pf rule without `on <iface>` applies to every interface of the host, so a rule with an empty interface name is rejected: a default deny among them would cut the Mac off its own networks.

The name has to be the kernel's. `plexd up` hands the enforcer `Manager.OSInterfaceName()`, which on macOS is the `utunN` the WireGuard controller created rather than the configured `plexd0`, so the rendered rules carry `utunN`; see [The utunN name](./wireguard.md#the-utunn-name).

### Inspecting the anchor

```bash
sudo pfctl -a com.apple/plexd -s rules   # the filter rules plexd loaded
sudo pfctl -a com.apple/plexd -s nat     # the masquerade rule, if one is configured
sudo pfctl -s References                 # every holder keeping pf enabled, plexd among them
sudo pfctl -a com.apple/plexd -sl        # the default deny's counters, which plexd reports
```

`pfctl` prints its own normalised form rather than the text plexd loaded: a `block` reads `block drop`, a single port reads `port = 443`, and a dynamic address pool carries a trailing `round-robin`. A `keep state` line reads `flags S/SA keep state`, `from any to any` without ports reads `all`, `icmp6` reads `ipv6-icmp`, and an `icmp-type` or `icmp6-type` list loads as one rule per type. The relay probe's port 9 may read `discard`, its `/etc/services` name. The round-trip probe's port 7911 has no such name and reads `port = 7911`.

### Drop counters

`PFController` implements `DropCounter`, so the Enforcer can send what the default deny dropped as `drops` in the [policy status report](./network-policy.md#policy-status-report). `DropCounts(chain)` returns an error for a chain the controller does not hold. Otherwise it runs `pfctl -a com.apple/plexd -sl`, which prints one line per labelled rule of the anchor:

```text
<label> <evaluations> <packets> <bytes> <per-direction counts...>
```

It sums fields 3 and 4, the packets and the bytes, of every line whose first field is `plexd-default-deny`, which covers the `block in` and the `block out` line, and ignores a line of any other label. A label line with fewer than four fields, a count that is not a number, an output without any `plexd-default-deny` line and a failed `pfctl` run are errors, each reading `policy: pf: drop counts: <cause>`. pf keeps one anchor for plexd, so the sum covers every chain in it; plexd keeps one policy chain.

The column order is taken from pfctl(8). `TestPFController_RealTraffic` on the `macos-latest` runner proves it: it reads the counts before and after one packet that no rule allows, and fails unless they grew by at least 1 packet and at least that packet's length in bytes. `pfctl -f` replaces the anchor's rules on every apply, so the counters restart from 0 at every install.

### pflog

`pflog_darwin.go` reads what the [logged lines](#logged-rules) hand to `pflog0` and reports each record as a `ConnEvent`; see [Connection logging](./network-policy.md#connection-logging) for the line plexd writes. `ApplyRules` opens the reader when the rules carry a tag and none runs, and `DeleteChain` closes it when it flushes the anchor.

XNU creates no pflog interface at boot (`bsd/net/if_pflog.c`), so when `pflog0` does not exist `openPflog` creates it with `/sbin/ifconfig pflog0 create`, through the same runner as `pfctl`. It then opens the first free device of `/dev/bpf0` to `/dev/bpf255`, attaches it to `pflog0` with `BIOCSETIF`, sets `BIOCIMMEDIATE`, checks with `BIOCGDLT` that the link type is `DLT_PFLOG`, and reads with a buffer of the size `BIOCGBLEN` reports. XNU logs only while a BPF reader is attached and does not check whether `pflog0` is up, so plexd leaves the interface's flags alone. Each BPF reader gets its own copy of every record, so `tcpdump -i pflog0` beside plexd takes nothing from it.

The reader splits each read into its BPF records and parses XNU's 64-byte `pfloghdr` (`bsd/net/if_pflog.h`) with `parsePflogRecord`. The packet starts at the header's `length` rounded up to a multiple of 4. A record counts when its `ruleset` is `plexd`, which is how XNU names the anchor `com.apple/plexd`, and its action is pass. Its `subrulenr`, the logged rule's number in the anchor, is looked up in the map of the anchor loaded last, then in the one before; see [Logged rules](#logged-rules). pf's direction out is `out`. pf's direction in is `in` when the destination is an address of the Mac, and `forward` otherwise, from `net.InterfaceAddrs`, cached for 5 s. After each read, `BIOCGSTATS` reports how many records BPF dropped, and the increase counts as lost in the [minute summary](./network-policy.md#rate-limit).

A read error other than `EINTR` logs `policy connection log reader stopped` at Warn with `error` and ends the reader, and the next apply with a logged rule opens a new one. Every error of the open starts `policy: pf: pflog: `, among them `policy: pf: pflog: no free bpf device` when all 256 devices are busy and `policy: pf: pflog: pflog0 has link type <n>, want <m>`. When the open fails, or no sink is set, `ApplyRules` loads the anchor from the rules without their tags, so no line carries `log`, and on a failed open it logs `policy connection logging unavailable, logged rules are enforced without it` at Warn with that error.

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

An IPv4 rule yields one filter at the local-delivery layer `LayerALEAuthRecvAcceptV4`, named `plexd <chain> #<i> inbound`, a second at the connect layer `LayerALEAuthConnectV4`, named `plexd <chain> #<i> outbound`, and a third at the forward layer `LayerIPForwardV4`, named `plexd <chain> #<i> forward`. An IPv6 rule goes to `LayerALEAuthRecvAcceptV6`, `LayerALEAuthConnectV6` and `LayerIPForwardV6` instead, under names ending in ` v6`: `plexd <chain> #<i> inbound v6`, `plexd <chain> #<i> outbound v6` and `plexd <chain> #<i> forward v6`. A rule without addresses, the default deny, goes to all six layers. Only an `allow` that names a protocol or a port has no forward filter; see [What the rules govern](#what-the-rules-govern). `<i>` is the rule's position in the list the controller gets, in which the `Enforcer` has put the logged rules first; see [Log tags and rule order](./network-policy.md#log-tags-and-rule-order).

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

`rttProbeFilters` then gives the same interface four round-trip probe permits, per family in the order of `wfpFamilies`, IPv4 first: one at the connect layer for what the node sends to port 7911, and one at the receive-accept layer for what arrives for the node on it.

| Name | Layer | Port condition |
|---|---|---|
| `plexd <chain> rtt probe` | `LayerALEAuthConnectV4` | `FieldIPRemotePort` equal to `RTTProbePort`, 7911 |
| `plexd <chain> rtt probe inbound` | `LayerALEAuthRecvAcceptV4` | `FieldIPLocalPort` equal to 7911 |
| `plexd <chain> rtt probe v6` | `LayerALEAuthConnectV6` | `FieldIPRemotePort` equal to 7911 |
| `plexd <chain> rtt probe inbound v6` | `LayerALEAuthRecvAcceptV6` | `FieldIPLocalPort` equal to 7911 |

Each also carries `FieldIPLocalInterface` equal to the LUID and `FieldIPProtocol` equal to `wf.IPProtoUDP`, and names no address, since the probe runs to and from every connected peer. None sits at a forward layer, so nothing the node forwards passes them. They take the relay probe permits' weight, `wfpWeight(epoch, n, -1)`. An interface's filters therefore open with its two relay probe permits and its four round-trip probe permits, and the rule filters follow.

### Weights and the epoch

Within a sublayer WFP evaluates the heaviest filter first and the first terminating action wins, which is the first-match order the other two backends have. Filter `i` of `n` in epoch `e` gets:

```go
weight := uint64(e)<<32 | uint64(n-i)
```

Here `i` is the index of the rule, and all filters of one rule share its weight. The relay probe and round-trip probe permits take `i = -1`, `wfpWeight(e, n, -1)`, which outweighs rule 0. Rule 0 is the heaviest of its own apply, and the epoch in the high half makes every filter of a newer apply outweigh every filter of an older one. `ApplyRules` builds its filters in `epoch+1` and installs them all before it deletes the ones the chain held, so the chain is never unfiltered in between and the new decisions win while both sets are installed. The weight stays below 2^60 for 2^28 applies, which is what a `FWP_UINT64` weight accepts.

Every rule is translated before the first filter is installed, so a rule the engine would reject fails without leaving half a ruleset behind. When an `AddRule` fails anyway, every filter that call installed is deleted again and the chain keeps the ones it had.

### Interface resolution

A rule carries the friendly name, the name the configuration holds and the one a Wintun adapter is created under. `net.InterfaceByName` resolves it to an interface index and `winipcfg.LUIDFromIndex` turns that index into the LUID. The forward layer matches the index, the local-delivery and connect layers the LUID. Each name is resolved once per apply, because most rules of a chain name the same interface and every lookup is a syscall.

### Soft permits

`HardAction` stays false on every filter, so a plexd permit is a soft one that the Windows Firewall's own sublayer may still block, while a plexd block is final. plexd's rules cannot open a port the host firewall closes.

### Inspecting the filters

```powershell
netsh wfp show filters file=-
```

The dump lists every filter in the engine. plexd's carry the names `plexd <chain> #<i> inbound`, `plexd <chain> #<i> outbound`, `plexd <chain> #<i> forward`, `plexd <chain> relay probe`, `plexd <chain> rtt probe` and `plexd <chain> rtt probe inbound`, with ` v6` appended at the IPv6 layers, and sit in the sublayer `plexd policy`. Without `file=-` the command writes the same XML to `filters.xml` in the working directory.

### Logged rules on Windows

A rule with `log: true` gets the filters an untagged rule gets, and plexd writes `policy rule allowed connection` for each connection it allows, as on Linux and macOS; see [Connection logging](./network-policy.md#connection-logging). The filter engine reports each connection it permits as a classify-allow net event that names the filter that permitted it. `netevents_windows.go` reads these events through a `FwpmNetEventSubscribe4` subscription and hands each one that names a logged filter to the sink as a `ConnEvent`. `WFPController` implements `ConnReporter`, so `NewEnforcer` hands it the `ConnLogger` as that sink. Without a sink the controller reports nothing, changes no engine option and logs no Warn line, as the Linux backend does.

Logging never blocks enforcement. When plexd cannot read the filter ids, set the engine options or subscribe, every filter stays installed, the failure does not change what `ApplyRules` returns, and plexd logs `policy connection logging unavailable, logged rules are enforced without it` at Warn with `chain` and the `error`; see [Error prefixes](#error-prefixes).

#### The logged filters and their ids

`buildFilters` returns, beside the filters, a map of the logged ones. For every rule with a `LogTag` it holds the rule's inbound filter, `plexd <chain> #<i> inbound`, as `ConnIn` and its outbound filter, `plexd <chain> #<i> outbound`, as `ConnOut`, with ` v6` appended at the IPv6 layers, in each family the rule is installed for, so a tagged rule without addresses has four entries, two per family. Forward filters are never in the map: the forward layers are not ALE layers, so a forwarded flow has no authorization to report, and a Windows node logs `in` and `out` but no `forward` connection. The relay probe and round-trip probe permits are not in it either, since they belong to no rule.

An event names its filter by the runtime filter id the engine assigned when the filter was added. `github.com/tailscale/wf` does not give plexd that id. It declares the union of `rawContext` and `providerContextKey` in `FWPM_FILTER0` as two fields, so it reads every field behind the union 8 bytes off and reports a wrong `Rule.KernelID`, which run [43271551927](https://github.com/plexsphere/plexd/actions/runs/43271551927) measured. Its `AddRule` discards the id `FwpmFilterAdd0` returns. plexd therefore reads the ids through its own layout of `FWPM_FILTER0`. After an apply with a logged rule, `FilterIDs` opens a session of its own, enumerates every filter of the engine with `FwpmFilterEnum0`, 100 at a time, and returns each filter's id by its key. An error there reads `policy: wfp: list filters:`. A logged filter whose id is missing or 0 reads `policy: wfp: list filters: want a distinct runtime id for each of <n> logged filters, got <m>`. After either, the chain holds no logged filter.

The controller keeps two maps per chain, keyed by filter id: the one of the apply made last, and the one of the apply before, so an event that arrives just after an apply can still name a filter of the apply before. `FlushChain` makes the current map the previous one. An event is attributed to a rule by the filter it names, never by its addresses.

#### Reading the events

The subscription runs on the session plexd opens for the [engine options](#the-engine-options). It has no template, so it subscribes to every event, and its callback receives `FWPM_NET_EVENT5`. plexd keeps an IPv4 or IPv6 classify-allow event, type 6, and reads the filter id, the protocol, the addresses and the ports from it. An IPv4 address is a `UINT32` in host byte order, an IPv6 address 16 bytes in network order. For `ConnIn` the source is the remote side and `DstPort` the local port, for `ConnOut` the source is the local side and `DstPort` the remote port. Both ports are 0 unless the protocol is TCP or UDP. The engine reports one event per ALE authorization: one per TCP connection, and one per UDP or other flow, for its first datagram.

Run [43612480437](https://github.com/plexsphere/plexd/actions/runs/43612480437) on `windows-latest`, Windows Server 2025 build 26100, measured that `FwpmNetEventSubscribe4` delivers one classify-allow event per connection under plexd's own filter id, 2 to 126 ms after the event's time stamp, and that it delivered all 50,000 events of a burst of 50,000 UDP flows sent in 3.7 s. `FwpmNetEventSubscribe1`, `2` and `3` received only the drop events there. The engine's event buffer, which `FwpmNetEventEnum2` reads, kept about 1,500 of the 50,000, so plexd does not read it. The subscription reports no lost events, so the Windows backend never calls `ConnSink.Lost`.

plexd resolves the procedures of `fwpuclnt.dll` through `windows.NewLazySystemDLL`, and resolves every procedure a function needs before it calls the first one, so a missing one fails before a handle is open. On a `fwpuclnt.dll` without `FwpmNetEventSubscribe4`, connection logging is unavailable: the session for the [engine options](#the-engine-options) fails to open before any option changes, plexd logs the Warn line with an `error` that names the procedure, and the logged rules stay enforced. Microsoft's page for the function names no minimum Windows version.

After a filter change the engine reports every live flow again, with `reauthReason` 0x5, and under filter id 0 once plexd's filters are gone. Every apply replaces the filters, so plexd drops an event with a `reauthReason` other than 0, which would otherwise log every live connection again at each reconcile. It also drops an event with `isLoopback` set. A connection open before its rule was logged is therefore not reported. While a logged rule is applied, the engine calls plexd for every connection it permits on the host, not only on the mesh adapter. The callback makes two comparisons and two map reads per chain, in the current maps first and then in the previous ones, before it drops an event under a filter that is not a logged one of plexd's, and the `ConnLogger`'s [rate limit](./network-policy.md#rate-limit) bounds the lines.

#### The engine options

Windows records classify-allow events only while two options of the filter engine say so: `collect_net_events`, and `match_any_keywords` with the keyword `FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW`, 0x10. Both apply to the whole host, and the setting persists across reboots. While it is on, Windows records every connection it permits at an ALE layer on the host, not only the ones plexd's filters permit. plexd therefore sets the options only while the applied ruleset holds a logged rule, and puts the host's own values back when no logged rule is left.

plexd reads and sets the options with `FwpmEngineGetOption0` and `FwpmEngineSetOption0`, through a session it opens with `FwpmEngineOpen0` and no `FWPM_SESSION0`. That session is not dynamic, because the engine refuses `FwpmEngineSetOption0` inside a dynamic session. It adds no object, so the options are the only thing it leaves behind when the process ends.

After an apply that leaves a chain holding a logged filter, plexd:

1. reads both options;
2. when `wfp-allow-events.json` does not exist in `data_dir` (`%ProgramData%\plexd\data` by default; see [Platform defaults](../core/configuration.md#platform-defaults)), writes the values it read to that file, atomically and with mode `0600`, before it changes anything;
3. sets `collect_net_events` to 1 when it is 0, and adds the keyword bit to `match_any_keywords` when the bit is clear. When it changed either, it logs `wfp allow-event collection enabled` at Info with `previous_keywords`;
4. subscribes, unless it already has.

A host that holds `collect_net_events` 1 and `match_any_keywords` 0x1 gets this record, and its `match_any_keywords` becomes 0x11:

```json
{"collect_net_events":1,"match_any_keywords":1}
```

A record that already exists is kept as it is. It is the one an earlier apply of this run wrote, or one a run that crashed with the option set left behind, and either way it holds the host's setting. Without a state directory plexd sets nothing, and the `error` reads `policy: wfp: allow events: no state directory`. When one of the steps fails, plexd logs the Warn line and restores at once, so the host is not left recording events nobody reads.

The restore unsubscribes and reads the record. Without a record it changes nothing. Otherwise it clears the keyword bit when the record lacks it and the engine holds it, and sets `collect_net_events` to 0 when the record holds 0 and the engine does not. Every other bit of `match_any_keywords` stays as it is. It then closes its session, deletes the record and logs `wfp allow-event collection restored` at Info. The record goes last, so on any error it stays, and the next restore tries again. A record that is not valid JSON is logged at Warn as `policy: wfp: allow-event record unreadable` with `error`, and read as `collect_net_events` 1 and `match_any_keywords` 0: plexd clears the keyword it sets and leaves collection on. plexd writes a record only before it sets the keyword, so the keyword being plexd's is the likelier reading, and a record that never parses would otherwise keep the option set for good.

| When | How plexd restores |
|---|---|
| No logged rule is left | An apply after which no chain holds a logged filter restores, as does `DeleteChain` of the last chain that held one. With enforcement enabled, the baseline apply at start holds no logged rule, so it restores too |
| At shutdown | `Enforcer.Teardown` calls `FlushChain` and `DeleteChain`. `DeleteChain` restores for a chain it does not hold too, so a shutdown retries a restore that failed at start |
| At the next start | `plexd up` hands the controller `data_dir` through `SetStateDir` before it builds the `Enforcer`, and `SetStateDir` restores from a record it finds there. It does so with `policy.enabled: false` too, which applies no ruleset |
| After a failed enable | The restore runs at once |

A restore that fails, in any of these, is logged at Warn as `policy: wfp: restore allow-event collection` with `error`. `FlushChain` leaves the options alone.

A release before this one does not read the record. A node downgraded after a crash keeps the option set, and starting this release once restores it from the record, which the earlier release leaves in `data_dir`. `plexd uninstall` restores nothing itself. After a crash, `plexd uninstall --purge` deletes the record with `data_dir` and leaves the option set.

### Drop counters on Windows

`WFPController` does not implement `DropCounter`. WFP keeps no per-filter counters, and its drop net events carry no byte count, so the `bytes` the policy status report requires could not be filled. A Windows node's [policy status report](./network-policy.md#policy-status-report) therefore carries no `drops`. `TestWFPController_RealTraffic` checks that the controller is not a `DropCounter`.

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

The prefix is the mesh adapter's own: the controller reads the mesh interface's IPv4 address and its on-link prefix length, which is the mesh CIDR the address was assigned with. The mesh adapter carries an address in that prefix, so WinNAT translates what arrives on it to the address of the adapter it leaves through, and nothing that arrives on any other adapter (see [What WinNAT does, measured](#what-winnat-does-measured)). WinNAT takes no part in the mesh source rewrite of a user access provider or a site-to-site tunnel: a Windows bridge rewrites inside the plexd process (see [In-process mesh source rewrite](./wireguard.md#in-process-mesh-source-rewrite)) and exempts a tunnel's adapter from the bridge NAT (see [The NAT exemption of a tunnel](#the-nat-exemption-of-a-tunnel)). The interface name reaches the call only to be logged — `bridge.NATController` documents that divergence, because `bridge.Manager` calls the same method on all three platforms.

`AddNATMasquerade` is idempotent: an object that already translates the mesh prefix is left alone, and one that translates another prefix is removed and rebuilt, because the mesh moved. Microsoft documents one NAT network per host, and Server 2025 held three objects at once (measured); plexd still keeps one object for the mesh prefix, and beside it only the objects that exempt the adapters of tunnels.

Inspect the object with:

```powershell
Get-NetNat -Name plexd
```

### What WinNAT does, measured

Measured on 2026-11-22 on the CI's Windows runner (Windows Server 2025 Datacenter, build 26100, Hyper-V installed) with Wintun adapters, from a throwaway branch whose runs are [45061062531](https://github.com/plexsphere/plexd/actions/runs/45061062531), [45061594586](https://github.com/plexsphere/plexd/actions/runs/45061594586), [45062607015](https://github.com/plexsphere/plexd/actions/runs/45062607015), [45062991268](https://github.com/plexsphere/plexd/actions/runs/45062991268) and [45063283780](https://github.com/plexsphere/plexd/actions/runs/45063283780):

| Measured | Result |
|---|---|
| Forwarding between two Wintun adapters | Works, with the Windows Firewall profiles on and off. The flag that counts is the arrival adapter's. Windows routes over an adapter that carries no address |
| A NetNat object for a prefix an adapter carries an address in | Translates what arrives on that adapter to the departure adapter's address (UDP, TCP, ICMP echo). Replies return, also under plexd's default deny |
| The same object beside one for the mesh prefix, which `bridge.enable_nat` (default on) creates | Translates nothing into the mesh: WinNAT does not translate between two adapters that each carry a NetNat prefix |
| WFP forward filters against a flow WinNAT translates | No effect, by arrival adapter, departure adapter or source address. A device behind a pool object reaches every network the host routes, as the host |
| A NetNat object for a tunnel adapter's own prefix, without one for the mesh prefix | Also translates the site's replies to connections a mesh node opened, which breaks them |
| The mesh-prefix object and a tunnel adapter without an address | What a mesh node sends to the site leaves with the adapter's 169.254 autoconfiguration address as its source |
| The mesh-prefix object, the tunnel adapter with `169.254.214.1/30` and a NetNat object for that /30 | Nothing between the mesh and the tunnel adapter is translated, in both directions, UDP, TCP and ICMP, and plexd's default deny and an allow rule on the mesh adapter apply to it |
| Number of NetNat objects | Server 2025 held three at once. No client edition was measured |

Three things follow for a Windows bridge. WinNAT cannot carry the mesh source rewrite of user access and site-to-site tunnels: it translates into the mesh only without the bridge NAT, and a device on it could not be kept inside the mesh, so plexd rewrites in process (see [In-process mesh source rewrite](./wireguard.md#in-process-mesh-source-rewrite)). A tunnel's adapter needs an exemption while the object for the mesh prefix exists, or the site sees a 169.254 address as the source of everything a mesh node sends it (see [The NAT exemption of a tunnel](#the-nat-exemption-of-a-tunnel)). And what a Windows bridge forwards through its bridge NAT passes no WFP forward filter, so the bridge's policy does not filter what a mesh node sends to the access side through the NAT. That is a defect of bridge mode on Windows, independent of user access and tunnels, and [Platform Support](../../guide/platform-support.md#known-limitations) lists it.

### The NAT exemption of a tunnel

While a NetNat object covers the mesh prefix, a tunnel's adapter is exempted from the bridge NAT with a 169.254 /30 and a NetNat object of its own, the one arrangement of the table above that leaves traffic between the mesh and the tunnel's adapter untranslated and under plexd's policy. `WFPController` implements `bridge.NATExempter` in `natexempt_windows.go`, and `plexd up` hands it to the site-to-site manager, which exempts each `wireguard` tunnel's adapter as it comes up (see [Site-to-Site VPN](../bridge/site-to-site-vpn.md#routes-and-policy)):

```go
// NATExempter keeps the host's NAT from translating what is forwarded between
// the mesh interface and a tunnel's link. Windows needs it while a NetNat
// object covers the mesh prefix. All methods must be idempotent.
type NATExempter interface {
	ExemptFromNAT(iface string) error
	UnexemptFromNAT(iface string) error
	ResetNATExemptions() error
}
```

Its objects are named `plexd-exempt-<iface>`, after the constant `netNatExemptPrefix = "plexd-exempt-"`. The scripts, which list the objects, create one, remove one and remove them all:

```text
Get-NetNat | ForEach-Object { $_.Name + '|' + $_.InternalIPInterfaceAddressPrefix }
New-NetNat -Name plexd-exempt-<iface> -InternalIPInterfaceAddressPrefix <prefix> | Out-Null
Remove-NetNat -Name plexd-exempt-<iface> -Confirm:$false
Get-NetNat | Where-Object { $_.Name -like 'plexd-exempt-*' } | Remove-NetNat -Confirm:$false
```

The removal by name is wrapped as the masquerade's read and delete are, so an absent object is a success. The address work goes through three seams of the controller, so the unit tests need no Administrator: `addAddress` and `removeAddress` (`func(luid uint64, prefix netip.Prefix) error`, in production `winipcfg.LUID.AddIPAddress` and `DeleteIPAddress`) and `hostPrefixes func() ([]netip.Prefix, error)`, in production the rows of `winipcfg.GetUnicastIPAddressTable(windows.AF_INET)`.

`ExemptFromNAT(iface)` runs under the controller's mutex:

1. `iface` must match `^[A-Za-z0-9_.-]{1,15}$`, because it becomes PowerShell text. Otherwise it returns `bridge: exempt "<iface>" from NAT: invalid interface name` and runs nothing.
2. It resolves the mesh prefix. A failure returns `bridge: exempt "<iface>" from NAT: resolve mesh prefix for "<mesh>": <cause>`.
3. It lists the objects. A failure returns the error of the PowerShell run, whose operation is `exempt "<iface>" from NAT`.
4. When the list holds `plexd-exempt-<iface>`, it returns nil.
5. When no listed object outside `plexd-exempt-*` has a prefix that overlaps the mesh prefix, it returns nil and creates nothing. That is the case on a bridge without bridge NAT. The check is not optional: measured, the object without a mesh-prefix object breaks the replies to connections a mesh node opened.
6. It picks a /30 from the 16,128 blocks `169.254.(1+n/64).(4*(n mod 64))/30`, n from 0 to 16127, starting at the 32-bit FNV-1a hash of `iface` modulo 16128, going on in a circle, and taking the first block that overlaps no listed object's prefix and that no address of `hostPrefixes` rules out. A listed object whose prefix does not parse overlaps nothing. `hostPrefixes` gives each host address with its on-link prefix length, and such a prefix rules out every block it overlaps, with one exception: an address whose on-link prefix is exactly `169.254.0.0/16`, an IPv4 autoconfiguration address such as the one an unnumbered tunnel adapter carries, rules out only the block that holds that address. Without the exception every real exemption would fail, because that /16 overlaps all 16,128 blocks. The price is that a neighbour on another link whose autoconfiguration address falls inside the chosen /30 is routed to the tunnel's adapter, and the host no longer reaches it. A failed `hostPrefixes` returns `bridge: exempt "<iface>" from NAT: read the host's addresses: <cause>`, no free block `bridge: exempt "<iface>" from NAT: no free 169.254 /30`.
7. It adds the block's first host address with length 30 to the adapter. A failed lookup or add returns `bridge: exempt "<iface>" from NAT: add <address>: <cause>`.
8. It creates the object. A failure removes the address again and returns the PowerShell error followed by ` (a NetNat object covers the mesh prefix <prefix> and this host took no further one; bridge.enable_nat: false serves tunnels without bridge NAT)`. When the removal fails too, `bridge: exempt "<iface>" from NAT: remove <address>: <cause>` is joined to it on a line of its own.
9. It logs at Info `tunnel exempted from NAT` with `interface`, `prefix` (the /30) and `nat` (the object's name), and `component=bridge`.

`UnexemptFromNAT` checks the name as step 1 does, with `bridge: unexempt "<iface>" from NAT: invalid interface name`, and runs the removal by name. The address goes with the adapter. `ResetNATExemptions` runs the fourth script. Both log at Debug, `NAT exemption removed` and `NAT exemptions reset`, and return the error of the PowerShell run with the operation `unexempt "<iface>" from NAT` or `reset NAT exemptions`.

A bring-up on a bridge with bridge NAT runs PowerShell twice under the site-to-site manager's mutex, a few seconds, as `AddNATMasquerade` does under the bridge manager's at start, and a status read waits that long. An exemption object outlives a killed process, and the next start's `CleanupSiteToSite` removes it through `ResetNATExemptions`. One that a later downgrade leaves behind translates nothing, because no adapter carries its prefix any more (measured). A host that takes no further NetNat object puts the tunnel down with `setup_failed` and the error of step 8; Microsoft documents one NAT network per host on client editions, none of which was measured, so a tunnel there is expected to need `bridge.enable_nat: false`.

Inspect the exemptions with:

```powershell
Get-NetNat | Where-Object { $_.Name -like 'plexd-exempt-*' }
```

### Mesh source rewrite

On Windows the rewrite is neither WFP's nor WinNAT's: plexd rewrites inside its own process, between its wireguard-go devices (see [In-process mesh source rewrite](./wireguard.md#in-process-mesh-source-rewrite)).

On macOS `PFController` implements `bridge.MeshSourceRewriter` in the same anchor. The [user access](../bridge/user-access-integration.md) and [site-to-site](../bridge/site-to-site-vpn.md) managers call it for each provider's interface and each tunnel's link, with the kernel's `utunN` names. A rewrite from `utun7` onto the mesh interface `utun4`, beside a chain that holds the default deny alone, renders:

```text
# plexd policy anchor. Managed by plexd; edits are overwritten.
nat pass on utun4 inet from any to any tagged plexd-mesh-rewrite -> (utun4)
# chain plexd-mesh
pass out quick on utun4 proto udp from (utun4) to any port 9 no state
pass out quick on utun4 proto udp from (utun4) to any port 7911 no state
pass in quick on utun4 proto udp from any to (utun4) port 7911 no state
block in quick on utun4 from any to any label "plexd-default-deny"
block out quick on utun4 from (utun4) to any label "plexd-default-deny"
pass out on utun7 inet all keep state
pass in on utun7 inet all keep state tag plexd-mesh-rewrite
```

| Line | Why |
|---|---|
| `nat pass on <mesh> ... tagged plexd-mesh-rewrite -> (<mesh>)` | One per mesh interface the rewrites name, after the bridge NAT line, in name order. It translates the source of what leaves the mesh interface carrying the tag to that interface's address, the bridge's mesh address, which is the only source a mesh node accepts from the bridge. `pass` makes pf skip the filter rules for the translated packet, which carries the mesh interface's own address and would otherwise meet the default deny's `block out ... from (<mesh>)` line, so the bridge would filter device and site traffic that Linux lets through. The destination node filters it under its rules for the bridge's mesh address |
| `pass in on <from> inet all keep state tag plexd-mesh-rewrite` | pf has no way to match the interface a packet arrived on in a `nat` rule, so this line tags what arrives on the source interface, and the `nat` line matches the tag on the way out of the mesh interface. The tag is the constant `pfMeshRewriteTag` |
| `pass out on <from> inet all keep state` | What a mesh node sends to a device or a site leaves through the source interface and creates its state here. The reply returns on that state, is never tagged, and keeps its own source, as Linux's connection tracking masquerades new connections only. The mesh node's packet was filtered by the chain when it arrived on the mesh interface |

Both filter lines follow the last chain, so the numbers of the [logged lines](#logged-rules) do not move, and neither is `quick`, so a host's own rules for the interface still decide. Only IPv4 is rewritten, as on Linux.

`AddMeshSourceRewrite` refuses a name that does not match `^[A-Za-z0-9_.-]{1,15}$`, in either argument, before anything is rendered: a vendor client reports the name of its interface, and the name becomes pf rule text. A rewrite that exists for the source interface is left alone and runs no `pfctl`, whatever mesh interface the call names. The first rewrite on a controller that holds neither a rewrite nor the bridge NAT runs [Probe](#probe) first, since nothing else on the bridge path checks that the kernel evaluates the anchor. `RemoveMeshSourceRewrite` reloads the anchor without the lines, or flushes it and releases the [enable reference](#the-enable-reference) when nothing else is left, and runs no `pfctl` for an interface it holds no rewrite for. A failed probe or load leaves the controller's rewrites as they were.

`ResetMeshSourceRewrite` forgets every rewrite and writes the anchor once, whatever the controller holds: it loads the rendered text while a chain or the bridge NAT is left, and otherwise runs `pfctl -a com.apple/plexd -F all`, also when it holds no enable reference, and releases the reference when it holds one. `plexd up` resets once at start, through `bridge.CleanupUserAccess`, on every macOS bridge, also with `policy.enabled: false` and `bridge.enable_nat: false`. The reset flushes unconditionally because a pf anchor outlives the process that loaded it and a utun does not: the kernel hands a freed `utunN` to the next device that asks, so the lines a killed process left would tag another interface's traffic.

Every change reloads the anchor, which restarts the [drop counters](#drop-counters), as a NAT change does. The states a removed rewrite created stay until they expire; the interface they name is gone with its provider or tunnel. `TestPFController_RealMeshSourceRewrite` proves the lines with packets on the macOS runner (see [Tests](#tests)).

## Error prefixes

Every policy failure reads `policy: pf: <op>:` or `policy: wfp: <op>:`, with `<op>` one of `probe`, `ensure chain`, `apply rules`, `flush chain` and `delete chain`, and on macOS also `drop counts`. NAT and mesh source rewrite failures carry the bridge prefixes instead, so a log line reads the same as the Linux one and the route controller's. They wrap the `pfctl` failure, whose `<op>` names the method, such as `add NAT masquerade` or `add mesh source rewrite`.

| Failure | Prefix |
|---|---|
| Any `pfctl` invocation | `policy: pf: <op>: <command line>:` followed by the error and pfctl's own output |
| An empty chain name | `policy: pf: ensure chain: chain name is empty`, `policy: pf: apply rules: chain name is empty` |
| A rule that does not render | `policy: pf: apply rules: rule <i>:` |
| A wildcard anchor missing from the main ruleset | `policy: pf: probe: the main ruleset does not reference anchor "com.apple/*"`, and the same for `nat-anchor` |
| `pfctl -E` without a token line | `policy: pf: <op>: pfctl -E printed no token: "<output>"` |
| Reading the drop counters | `policy: pf: drop counts:`, for a chain the controller does not hold, a failed `pfctl -sl`, a label line it cannot read, or no `plexd-default-deny` line |
| Opening the filter engine | `policy: wfp: probe:`, `policy: wfp: <op>: open session:` |
| Adding the sublayer | `policy: wfp: <op>: add sublayer:` |
| An empty chain name | `policy: wfp: ensure chain: chain name is empty`, `policy: wfp: apply rules: chain name is empty` |
| A rule that does not translate | `policy: wfp: apply rules: rule <i>:` |
| Installing a filter | `policy: wfp: apply rules: add filter "<name>":`, with the filter's name, such as `plexd <chain> #<i> inbound`, `plexd <chain> relay probe` or `plexd <chain> rtt probe inbound` |
| Deleting a chain's filters | `policy: wfp: apply rules: delete stale filters:`, `policy: wfp: flush chain "<chain>":`, `policy: wfp: delete chain "<chain>":` |
| Closing the session | `policy: wfp: probe: close session:`, `policy: wfp: delete chain: close session:` |

The connection logging failures are logged, never returned, so they do not change what `ApplyRules` returns. An open of the [pflog](#pflog) reader fails with `policy: pf: pflog:`. On Windows, reading the filter ids fails with `policy: wfp: list filters:`, and setting the engine options or subscribing fails with `policy: wfp: allow events:`. Each is the `error` of `policy connection logging unavailable, logged rules are enforced without it`. A failed restore of the engine options also reads `policy: wfp: allow events:`, as the `error` of `policy: wfp: restore allow-event collection`; see [Logged rules on Windows](#logged-rules-on-windows).

| Logged failure on Windows | Prefix |
|---|---|
| Reading the filter ids | `policy: wfp: list filters:`, and `policy: wfp: list filters: want a distinct runtime id for each of <n> logged filters, got <m>` for a logged filter without an id or with the id 0 |
| No state directory | `policy: wfp: allow events: no state directory` |
| Opening the session for the engine options | `policy: wfp: allow events: open session:` |
| Reading an option | `policy: wfp: allow events: read collect_net_events:`, `policy: wfp: allow events: read match_any_keywords:` |
| Setting an option | `policy: wfp: allow events: set collect_net_events:`, `policy: wfp: allow events: set match_any_keywords:` |
| Writing, reading and deleting the record | `policy: wfp: allow events: record options:`, `policy: wfp: allow events: read record:`, `policy: wfp: allow events: delete record:` |
| The subscription | `policy: wfp: allow events: subscribe:`, `policy: wfp: allow events: unsubscribe:` |
| Closing the session | `policy: wfp: allow events: close session:` |

Inside these, a failed call of the filter engine reads `<procedure>: <error>`, such as `FwpmNetEventSubscribe4: <error>`. A call that reads or sets an engine option also names the option's number, 0 for `collect_net_events` and 1 for `match_any_keywords`, as in `FwpmEngineSetOption0(1): <error>`.

| NAT failure | Prefix |
|---|---|
| Any leg of the macOS masquerade | `bridge: add NAT masquerade on "<iface>":`, `bridge: remove NAT masquerade on "<iface>":` |
| An empty interface name on macOS | `bridge: add NAT masquerade on "": interface name is empty` |
| Any leg of a mesh source rewrite on macOS, its probe included | `bridge: add mesh source rewrite from "<from>" to "<mesh>":`, `bridge: remove mesh source rewrite from "<from>":`, `bridge: reset mesh source rewrite:` |
| A name the rewrite's check refuses | `bridge: add mesh source rewrite: invalid interface name "<name>"` |
| Resolving the mesh prefix on Windows | `bridge: add NAT masquerade on "<iface>": resolve mesh prefix for "<mesh iface>":` |
| Any PowerShell command | `bridge: <op>: powershell -Command "<script>":` followed by the error and PowerShell's output |
| A tunnel's NAT exemption on Windows | `bridge: exempt "<iface>" from NAT: invalid interface name`, `bridge: unexempt "<iface>" from NAT: invalid interface name`, and `bridge: exempt "<iface>" from NAT:` followed by `resolve mesh prefix for "<mesh iface>":`, `read the host's addresses:`, `no free 169.254 /30`, `add <address>:` or, after a failed `New-NetNat`, `remove <address>:` |
| A `New-NetNat` of an exemption that fails | The PowerShell error followed by ` (a NetNat object covers the mesh prefix <prefix> and this host took no further one; bridge.enable_nat: false serves tunnels without bridge NAT)` |
| Adding a mesh source rewrite on Windows | `bridge: add mesh source rewrite from "<from>" to "<mesh>":` followed by `the mesh interface is no device of this process` or `address of the mesh interface:`; see [In-process mesh source rewrite](./wireguard.md#adding-and-removing-a-rewrite) |

The PowerShell operations of the exemption are `exempt "<iface>" from NAT`, `unexempt "<iface>" from NAT` and `reset NAT exemptions`, so a failing list script reads `bridge: exempt "wg-s2s-a0a0a0e1" from NAT: powershell -Command "<script>":`.

A privilege failure carries a hint, because the tool's own message does not name the privilege it wanted. macOS appends ` (policy enforcement on macOS requires root)` when pfctl's output holds `Permission denied`; Windows appends ` (policy enforcement on Windows requires Administrator)` on `ERROR_ACCESS_DENIED`. A pf failure also carries the command line and pfctl's output, since `exit status 1` alone is not actionable:

```text
policy: pf: apply rules: /sbin/pfctl -a com.apple/plexd -f -: <error>: <pfctl output> (policy enforcement on macOS requires root)
```

The two failures `plexd up` aborts on, the pre-flight probe and the deny-by-default baseline, wrap these with a per-platform hint naming the opt-out; see [policy](../core/configuration.md#policy).

## Logging

All entries carry `component=policy` for the filter operations and `component=bridge` for the NAT and mesh source rewrite ones. All are at `Debug` except the lines the table marks with another level.

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
| `policy connection logging unavailable, logged rules are enforced without it` (`Warn`, pf and WFP) | `error`, and `chain` on WFP |
| `policy connection log reader stopped` (`Warn`, pf) | `error` |
| `wfp allow-event collection enabled` (`Info`) | `previous_keywords` |
| `wfp allow-event collection restored` (`Info`) | none |
| `policy: wfp: restore allow-event collection` (`Warn`) | `error` |
| `policy: wfp: allow-event record unreadable` (`Warn`) | `error` |

| Message (`component=bridge`) | Keys |
|---|---|
| `NAT masquerade configured` (macOS) | `interface`, `anchor` |
| `NAT masquerade configured` (Windows) | `interface`, `prefix`, `nat` |
| `NAT masquerade already configured` (Windows) | `interface`, `prefix` |
| `NAT masquerade removed` | `interface` |
| `NAT masquerade not configured, idempotent success` (macOS) | `interface` |
| `mesh source rewrite added`, `mesh source rewrite removed` (macOS) | `from_iface`, `mesh_iface`, `anchor` |
| `mesh source rewrite already present, idempotent success`, `mesh source rewrite not found, idempotent success` (macOS) | `from_iface`, `mesh_iface`, `anchor` |
| `mesh source rewrites reset` (macOS) | `anchor` |
| `tunnel exempted from NAT` (`Info`, Windows) | `interface`, `prefix`, `nat` |
| `NAT exemption removed` (Windows) | `interface`, `nat` |
| `NAT exemptions reset` (Windows) | none |

The in-process mesh source rewrite of Windows logs the lines of [Drops and log lines](./wireguard.md#drops-and-log-lines), with `component=bridge` too.

`count` is the number of rules the chain was given, `filters` the number of WFP filters they became, which is larger: every rule yields an inbound and an outbound filter per family, some a forward filter too, and every interface two relay probe permits and four round-trip probe permits. Three of the lines above `Debug` concern the forward path and the rollback. `wfp forward path cannot enforce a protocol or port, allow rules narrowed away` names, per apply, how many `allow` rules the node does not enforce on the forward path because they name a protocol or a port. `wfp forward path cannot enforce a protocol or port, deny rules widened to every protocol and port` names how many `deny` rules went onto the forward path without their protocol and port; the engine's only deny names neither, so it does not appear with the rules plexd builds today. Each `count` is a subset of the chain's rules, not of its filters. `wfp rollback delete failed` reports an apply whose `AddRule` failed: it deletes the filters it already installed, and a deletion that fails there leaves a filter behind that only the session's close drops.

The other six concern [connection logging](./network-policy.md#connection-logging). `policy connection logging unavailable, logged rules are enforced without it` is the line all three backends share, logged once per apply with a logged rule when the backend cannot report its connections. On Windows that is an apply whose filter ids plexd cannot read, or whose engine options or subscription it cannot set up, such as on a node without a state directory or with a `fwpuclnt.dll` that lacks `FwpmNetEventSubscribe4`. `policy connection log reader stopped` reports a pflog reader that ended on a read error. `wfp allow-event collection enabled` reports that plexd changed the filter engine's options, with `previous_keywords`, the `match_any_keywords` it found, and `wfp allow-event collection restored` that it put the recorded values back and deleted `wfp-allow-events.json`. `policy: wfp: restore allow-event collection` reports a restore that failed, which keeps the record for the next try, and `policy: wfp: allow-event record unreadable` a record that is not valid JSON, which plexd reads as `collect_net_events` 1 and `match_any_keywords` 0; see [Logged rules on Windows](#logged-rules-on-windows). The connection lines themselves, and the minute summary, come from the `ConnLogger`.

## Tests

Both controllers reach the operating system through seams, so every rendered rule and every idempotent case runs on an ordinary unprivileged runner. macOS wires the package's recording runner in place of `pfctl`, which captures each invocation's arguments and its stdin, so a test pins the whole anchor text a change renders. Windows wires a `wfpEngine` fake in place of the session, which records the sublayer, the filters in the order they were added and the deletions, and can be armed to fail a chosen `AddRule`; PowerShell goes through the same recording runner. The fake refuses a filter whose condition names a field its layer does not have, as the engine does, from a per-layer list of the fields plexd uses: a protocol or a port at a forward layer fails a unit test rather than the real one.

`TestPFController_RenderParses` runs the real `pfctl -n -q -a com.apple/plexd -f -` over the rendered text. `-n` parses without loading, which needs no access to `/dev/pf`, so the test proves the rendered syntax is pf's without root. The anchor it parses holds every line form: the relay probe line, the two round-trip probe lines, `keep state` and `no state` outbound lines, a `flags A/A` mirror with a port range, both ICMP type lists, `block out quick on <if> from (<if>) to any label "plexd-default-deny"`, the logged forms `pass in log ... flags S/SA no state`, `pass out log ... keep state` and `pass in log ... no state`, and the three lines of a mesh source rewrite.

The mesh source rewrite has unit tests on macOS too. They pin the anchor a rewrite beside a chain loads, one `nat pass` line for two rewrites onto one mesh interface, the probe before the first rewrite and none beside the bridge NAT, the repeat that runs no `pfctl`, the refused names (empty, 16 characters, one with a newline, in either argument), the error prefixes of a failed probe and a failed load with no line left for the interface afterwards, the removal that flushes and releases, the reset that loads, flushes without a reference, and restores the rewrites on a failure, and in `TestPFController_RenderLogTags` that a rewrite leaves the map of logged lines as it was.

The NAT exemption has unit tests on Windows, over the recording runner and fakes of `addAddress`, `removeAddress` and `hostPrefixes`. They pin that an empty list, a list whose only object is `nat|172.20.0.0/16` beside the mesh prefix `10.42.0.0/16`, and one where only an exemption object covers the mesh prefix, run the list script alone and add no address; that with `plexd|10.42.0.0/16` listed, or an object of another name that covers the mesh prefix, the first host address of a `169.254` /30 goes onto the adapter's LUID with length 30 before `New-NetNat` names that block, pinned as a literal for `wg-s2s-a0a0a0e1`, `169.254.243.96/30`, and that a listed object, a host address or an autoconfiguration address inside the block moves the choice to the next one, `169.254.243.100/30`; that an autoconfiguration address in `169.254.0.0/16` outside the block leaves the block free; that the search goes on from the last block to the first, and that a listed `169.254.0.0/16` leaves no free block; that a listed `plexd-exempt-wg-s2s-a0a0a0e1` adds nothing; that an empty name, a name of 16 characters and the name `x'; Remove-Item C:\` are refused before any PowerShell runs; the error prefixes of a failing list script, `meshPrefix`, `hostPrefixes`, the adapter's lookup and `addAddress`, after which no `New-NetNat` runs; that a failing `New-NetNat` removes the address it added and names `bridge.enable_nat: false` and the mesh prefix, and a removal that fails as well is joined after it; and the scripts and error operations of the removal and the reset.

The drop counters have unit tests on macOS too. `TestPFController_RenderRuleLines` checks that both `block` lines end in `label "plexd-default-deny"` and that no `pass` line carries a label. `TestPFController_DropCounts` feeds the recording runner `pfctl -sl` output: it sums fields 3 and 4 of two label lines, ignores a line of another label, and returns an error containing `policy: pf: drop counts` for a label line with three fields, a non-numeric count, an output without a label line, a `pfctl` exit status 1, and a chain the controller does not hold.

The connection logging code has unit tests of its own. On macOS they pin the lines `renderRule` returns for a tagged rule of each protocol, the line numbers `render` maps to tags, `parsePflogRecord` over a hand-built `pfloghdr`, and that a reader which fails to open makes `ApplyRules` load the anchor without `log` and log the Warn line. On Windows the fake engine also implements `FilterIDs`: it gives each filter it adds a distinct id and can be armed to fail through `filterIDsErr`. No unit test opens a real net event session on the elevated runner: `newTestWFPController` replaces `openNetEvents`, and the tests of the engine options wire a `fakeNetEvents`, which holds both options in memory and records every `setOption`. With them:

- `TestWFPController_BuildFilters_LoggedMap` checks that `buildFilters` maps the inbound filter of each logged rule as `ConnIn` and its outbound filter as `ConnOut`, in each family the rule is installed in, that it leaves the forward filters, the relay and round-trip probe permits and every filter of an untagged rule out, and that a ruleset without a tag yields an empty map and the filters it yields untagged.
- `TestWFPController_ApplyRules_LogFilters` checks that after an apply the controller knows each logged filter by the id `FilterIDs` returned, that a `FilterIDs` error or an id of 0 logs the Warn line while every filter stays installed, and that without a sink the controller neither lists the filters nor opens a session and logs no Warn line.
- `TestWFPController_EnableAllowEvents` checks that the first enable writes the record before it sets anything and then sets only what is off, that a second call writes, sets and logs nothing and does not subscribe again, and that a record already there is kept byte for byte. `TestWFPController_RestoreAllowEvents` checks that the restore clears the keyword only when the record holds it clear, turns collection off only when the record holds it off, leaves the bits others set, deletes the record and closes the session, and that it reads a record that is not valid JSON as collection on and the keyword clear. `TestWFPController_SetStateDir_RestoresCrashRecord` checks that `SetStateDir` on a new controller restores from a crash record, and that a directory without a record opens no session.
- `TestNetEventLayouts` pins the sizes and offsets of plexd's own layouts on a 64-bit build, among them `fwpmFilter0` at 200 bytes with `FilterID` at 176 and `fwpmNetEvent5` at 152 bytes with `Type` at 136 and `ClassifyAllow` at 144. `TestParseNetEvent` reads an IPv4 and an IPv6 event and refuses an event of another type, one without its classify-allow part and one of neither family. `TestOnNetEvent_DispatchesByKey` checks that the callback finds the handler by the context the subscription named and returns 0 each time. `TestWFPController_AllowEventConversion` checks the `ConnEvent` an event under an inbound or an outbound filter becomes, and that a reauthorization, a loopback event and an event under a filter that is not a logged one of plexd's are dropped.

Nine tests drive the real host and are gated:

| Test | Gate | Locally |
|---|---|---|
| `TestPFController_Real` (`pf_darwin_test.go`) | `PLEXD_TEST_REAL_PF=1` and `os.Geteuid() == 0` | `sudo PLEXD_TEST_REAL_PF=1 go test -run '^TestPFController_Real$' ./internal/policy/` |
| `TestPFController_RealTraffic` (`tuntraffic_darwin_test.go`) | The same | `sudo PLEXD_TEST_REAL_PF=1 go test -run '^TestPFController_RealTraffic$' ./internal/policy/` |
| `TestPFController_RealConnLog` (`tuntraffic_darwin_test.go`) | The same | `sudo PLEXD_TEST_REAL_PF=1 go test -run '^TestPFController_RealConnLog$' ./internal/policy/` |
| `TestPFController_RealMeshSourceRewrite` (`meshrewrite_darwin_test.go`) | The same | `sudo PLEXD_TEST_REAL_PF=1 go test -run '^TestPFController_RealMeshSourceRewrite$' ./internal/policy/` |
| `TestWFPController_Real` (`wfp_windows_test.go`) | `PLEXD_TEST_REAL_WFP=1` and an elevated token | `$env:PLEXD_TEST_REAL_WFP='1'; go test -run '^TestWFPController_Real$' ./internal/policy/` from an elevated shell |
| `TestWFPController_RealNAT` (`netnat_windows_test.go`) | The same | `$env:PLEXD_TEST_REAL_WFP='1'; go test -run '^TestWFPController_RealNAT$' ./internal/policy/` from an elevated shell |
| `TestWFPController_RealNATExemption` (`natexempt_windows_test.go`) | The same | `$env:PLEXD_TEST_REAL_WFP='1'; go test -run '^TestWFPController_RealNATExemption$' ./internal/policy/` from an elevated shell |
| `TestWFPController_RealTraffic` (`tuntraffic_windows_test.go`) | The same | `$env:PLEXD_TEST_REAL_WFP='1'; go test -run TestWFPController_RealTraffic ./internal/policy/` from an elevated shell, with every Windows Firewall profile off |
| `TestWFPController_RealConnLog` (`tuntraffic_windows_test.go`) | The same | `$env:PLEXD_TEST_REAL_WFP='1'; go test -run TestWFPController_RealConnLog ./internal/policy/` from an elevated shell, with every Windows Firewall profile off |

`TestPFController_Real` loads an anchor naming `plexd99`, an interface no host has, with an IPv6 rule and the default deny among its rules, takes the pf reference, reads the filter and nat rules back with `pfctl -a com.apple/plexd -s rules` and `-s nat`, and finds the `inet6` rule and a block rule without an address there. In pfctl's printed form it also finds a `keep state` outbound line, a `flags A/A` mirror, both ICMP mirrors, `block drop out quick on plexd99 from (plexd99) to any`, and three probe lines, each once, as the only `pass out` lines from `(plexd99)` and the only `pass in` line to it: the relay probe line, `pass out quick on plexd99 proto udp from (plexd99) to any port = 7911 no state` and `pass in quick on plexd99 proto udp from any to (plexd99) port = 7911 no state`. It then deletes the chain and asserts the anchor is empty and the token released. A host that had pf disabled is left disabled. The variable gates it in addition to the effective uid, so `sudo go test ./...` on a developer's Mac does not enable pf on their host.

`TestWFPController_Real` installs filters for prefixes no host carries, IPv6 rules among them, one of which names addresses alone, and the default deny, which shows that the filter engine accepts filters at the V6 layers, an IPv6 prefix at `FWPM_LAYER_IPFORWARD_V6` included. It enumerates plexd's filters through a session of its own, checks that the allows naming a protocol or a port got no forward filter, and pins `FWP_E_FILTER_NOT_FOUND` by deleting a filter that is not there. It finds a `#<i> outbound` filter at `LayerALEAuthConnectV4` for every IPv4 rule, a `#<i> outbound v6` filter at `LayerALEAuthConnectV6` for every IPv6 rule, the two relay probe permits once, and the four round-trip probe permits once, at the connect and the receive-accept layer of each family, which shows that the engine takes plexd's conditions at the connect layers. It also checks that the outbound filters of its allow of everything are permits. It cannot read their weights back: `github.com/tailscale/wf` declares the union of `rawContext` and `providerContextKey` in `FWPM_FILTER0` as two fields, so it reads `effectiveWeight` 8 bytes off and reports 0 for every filter. That the allow outweighs the default deny rests on the unit tests, which pin every filter's weight through the fake engine, and on `TestWFPController_RealTraffic`, which shows on the real engine that a permit at `ALE_AUTH_CONNECT` outweighs the default deny. A run that fails with the default deny installed first replaces the ruleset with the allow of everything alone and then deletes the chain, so the deny never stands alone on the runner's interface. `TestWFPController_RealNAT` creates the NetNat object for `10.255.252.0/30`, reads the prefix back, and repeats both the add and the remove to prove they are idempotent — the second read after the removal is what proves the absent case is a success with no output rather than a localized error.

`TestWFPController_RealNATExemption` fails before it creates anything when the host already holds an object named `plexd` or `plexd-exempt-*`, or one that covers its mesh prefix, since it removes the objects of those names when it ends. It creates two Wintun adapters of its own: one at `10.255.243.1/24`, which stands for the mesh adapter and is the controller's `meshIface`, and one without an address, which it exempts. Beside the object `AddNATMasquerade` created for `10.255.243.0/24`, `ExemptFromNAT` on the second adapter creates `plexd-exempt-<name>` for a `169.254` /30 the adapter then carries, and a second call leaves the list of objects unchanged. `UnexemptFromNAT` removes the object, and a second call returns nil. Without the object for `10.255.243.0/24`, `ExemptFromNAT` creates no object and adds no address. `ResetNATExemptions` removes an object named `plexd-exempt-leftover` the test created and leaves an object with another name in place. That traffic between the mesh and an exempted adapter stays untranslated and under the policy is `TestMeshSourceRewrite_RealWintun`'s to prove (see [In-process mesh source rewrite](./wireguard.md#tests)).

The two traffic tests and Linux's `TestNftablesController_RealTraffic` (see [nftables Firewall Controller](./nftables-firewall.md#tests)) run the same checks, `runTunTrafficChecks` in `tuntraffic_test.go`. Each test creates a TUN device, puts node N's address 10.255.247.1 on it, and hands the checks a `tunHarness`: the controller, the device, the offset the device needs in front of each packet, and the interface name the rules carry. The test plays peer P, 10.255.247.2, behind the device: a packet it writes into the device arrives at N from P, and what N sends to P comes out of the device for the test to read. No other test uses this prefix. `TestPFController_RealTraffic` creates a `utun` and runs `/sbin/ifconfig <utun> inet 10.255.247.1 10.255.247.2 up`, with an offset of 4 for the address family wireguard-go's utun writes in front of each packet. `TestWFPController_RealTraffic` writes `wintun.dll` beside the test binary with `wintundll.Ensure`, creates the adapter `plexd-fwtest`, and assigns 10.255.247.1/30 through `winipcfg`, with an offset of 0.

N listens on TCP 7001 and 7003 and echoes UDP on 7002 and on 7911, the round-trip probe port. As a control, before any chain exists, a SYN from P to N:7001 must draw a SYN-ACK within 3 s. Otherwise the test fails with `the host answers nothing through the test device without plexd's filters`. The test then applies, in chain `plexd-test`:

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
- a datagram N sends to P:9, which no rule names, comes out of the device;
- a datagram N sends to P:7911, which no rule names, comes out of the device;
- a datagram from P's port 7911 to N:7911, which no rule names, reaches N's echo, and the echo's answer from N:7911 to P:7911 comes out of the device;
- on Linux and macOS, `DropCounts("plexd-test")` before and after one packet from P that no rule allows differ by at least 1 packet and at least that packet's length in bytes. On Windows the checks assert instead that the controller is not a `DropCounter`.

The SYN-ACK, the echo and the echo reply are replies to what r0 to r2 let in, so the checks prove each platform's reply path: connection tracking on Linux, the mirrors on macOS and the ALE flow on Windows. The two round-trip probe checks prove that a probe and its answer pass in both directions under a ruleset that does not name the port: on macOS through the two stateless lines, on Windows through the connect and receive-accept permits. The drop check proves that `DropCounts` reads the default deny's counters on the real kernel, and on macOS it is the proof of the `pfctl -sl` column layout; see [Drop counters](#drop-counters). When the test ends it closes the device, which ends its reader, before it deletes the chain. The Windows Firewall blocks the unsolicited packets the test injects on its own, so the CI step turns every firewall profile off first with `Set-NetFirewallProfile -All -Enabled False`. plexd's filters sit in a sublayer of their own and do not depend on the Windows Firewall.

`TestPFController_RealConnLog`, `TestWFPController_RealConnLog` and Linux's `TestNftablesController_RealConnLog` build the same harness, through `newTunTestHarness`, and run `runTunConnLogChecks` (`tunconnlog_test.go`). It sets a recording sink through `ConnReporter`, so the events it checks come from the backend's reader as the kernel reported them, and applies, in chain `plexd-logtest`:

```text
r0 tcp 10.255.247.2/32 → 10.255.247.1/32 port 7001  LogTag "7/0"
r1 udp 10.255.247.2/32 → 10.255.247.1/32 port 7002  LogTag "7/1"
r2 tcp 10.255.247.1/32 → 10.255.247.2/32 port 7006  LogTag "7/2"
r3 tcp 10.255.247.2/32 → 10.255.247.1/32 port 7003
r4 the default deny
```

and checks that:

- a SYN from P:41001 to N:7001 draws a SYN-ACK and exactly one event `{"7/0", in, P, N, 6, 41001, 7001}` within 3 s, and no second event within 2 s;
- a SYN from P:41002 to N:7003, which the untagged r3 allows, draws a SYN-ACK and no event within 2 s;
- a datagram from P:41003 to N:7002 comes back and yields one event `{"7/1", in, P, N, 17, 41003, 7002}`. A second datagram on the same ports after the echo yields a second event on macOS, where `tunUDPLogsEveryPacket` holds, and none within 2 s on Linux and Windows;
- a dial from N to P:7006 puts a SYN on the device and yields at least one event `{"7/2", out, N, P, 6, <any port>, 7006}`, and no event with another tag;
- after a re-apply with r0 untagged, a SYN from P:41004 to N:7001 draws a SYN-ACK and no event within 2 s.

The checks end with `DeleteChain("plexd-logtest")`, and the cleanup deletes the chain only when a check failed before that. `TestPFController_RealConnLog` also finds `pflog0` after the first tagged apply, and its events prove the line numbers of [Logged rules](#logged-rules).

`TestPFController_RealMeshSourceRewrite` proves the [mesh source rewrite](#mesh-source-rewrite) with packets. It is the only measurement of the two kernel facts its lines rest on: that a tag a filter line sets on the way in is still on the packet when pf evaluates the `nat` rules on its way out of another interface, and that `nat pass` skips the filter rules. It creates three utuns with `tun.CreateTUN` and addresses and routes them the way the controllers do, `ifconfig <utun> inet <cidr> <address> alias`, `route -n add -inet <network> -interface <utun>` and `ifconfig <utun> up`:

| Device | Address | Route | Far end the test plays |
|---|---|---|---|
| M, the mesh interface | `10.255.245.1/24` | `10.255.245.0/24` | mesh node N, `10.255.245.2` |
| P, a provider's interface | `10.255.246.1/24` | `10.255.246.0/24` | device D, `10.255.246.2` |
| T, a tunnel's link | `10.255.245.1/32`, the mesh address, as plexd up's tunnel controller assigns it | `10.255.244.0/24` | site host S, `10.255.244.2` |

No other test uses these prefixes. The test reads `net.inet.ip.forwarding`, sets it to 1 and restores it in a cleanup, applies chain `plexd-test` on M with the default deny alone, and runs the checks once with P and D and once with T and S. A packet enters a device when the test writes it into the device and leaves when the test reads it from the device, and every check uses ports of its own, so none meets a state an earlier check left. With the rewrite from the source device onto M, it checks that:

- a UDP datagram from the far end to N:7001 enters the source device and leaves M with the source `10.255.245.1`;
- N's reply to the address and port the datagram left with enters M and leaves the source device to the far end's address and port, from N;
- a datagram from a host socket bound to `10.255.245.1` to N does not leave M within 2 s, and `DropCounts` grows;
- a datagram from N to the far end entering M does not leave the source device while the chain holds only the default deny;
- after an allow rule for udp and tcp from `10.255.245.2` to the far end, the same datagram leaves the source device from `10.255.245.2`, and the far end's reply leaves M with the far end's address as its source, not `10.255.245.1`;
- the same holds for a TCP SYN from N and the far end's SYN-ACK;
- after `RemoveMeshSourceRewrite`, a datagram of a new flow from the far end leaves M with its own source;
- after the rewrite is added again and found in `pfctl -a com.apple/plexd -s nat`, `ResetMeshSourceRewrite` on a second `PFController` that holds nothing leaves no line containing `plexd-mesh-rewrite` in `-s nat` and `-s rules`.

On Windows `tunUDPLogsEveryPacket` is false, because the engine authorizes a UDP flow once, and the events `TestWFPController_RealConnLog` checks prove the filter ids of [Logged rules on Windows](#logged-rules-on-windows). The engine options it turns on belong to the whole host and outlive the process. Before the checks the test reads both through a session of its own and stops when the keyword is already set, and a cleanup puts both back to those starting values whatever the test's result. The test hands the controller `t.TempDir()` through `SetStateDir` and wraps it in `wfpLoggedApplyHook`, which embeds the `*WFPController` and, after each successful `ApplyRules` with a tagged rule, checks that the keyword bit is set, that `collect_net_events` is not 0, and that `wfp-allow-events.json` holds the starting values. After the checks' `DeleteChain` it finds both options at their starting values and no record. It then sets the keyword and writes the record as a crashed run would, and checks that `SetStateDir` with the same directory on a new controller puts the starting values back and deletes the record.

CI runs all eight; see [CI Workflow](../development/ci-workflow.md).
