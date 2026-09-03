---
title: pf & WFP Firewall Controllers
package: internal/policy
---

# pf & WFP Firewall Controllers

`PFController` (`pf_darwin.go`) and `WFPController` (`wfp_windows.go`, `netnat_windows.go`) are the non-Linux implementations of the `FirewallController` interface defined in `internal/policy`. macOS programs its rules with `pfctl(8)` and needs root. Windows programs the Windows Filtering Platform through `github.com/tailscale/wf` and WinNAT through PowerShell, both of which need Administrator, which the LocalSystem service satisfies.

Both controllers also implement `bridge.NATController`, so one instance carries the policy rules and the bridge's masquerade rule; see [NAT](#nat).

The Linux implementation is [`NftablesController`](./nftables-firewall.md).

## What the rules govern

On macOS and Windows the rules govern everything that arrives on the mesh interface, whether the packet is delivered to the node itself or forwarded through it.

Linux differs. `NftablesController` creates its base chain with a forward hook (`internal/policy/nftables_linux.go`), so the kernel evaluates it for forwarded packets alone and a Linux node enforces nothing on traffic addressed to itself. A Mac or a Windows node rejects unsolicited mesh traffic to its own addresses until a rule allows it, because the ruleset ends in a default deny.

On macOS two lines precede the policy rules of every chain, once per interface the chain mentions:

```text
pass out quick on utun4 inet proto tcp from (utun4) to any keep state
pass out quick on utun4 inet from (utun4) to any no state
```

Replies to TCP connections the node itself opened over the mesh pass because of the first line. It keeps state for each outbound flow, and the state entry matches the reply before the default deny is reached. `(utun4)` is the interface's own addresses as the kernel tracks them, not a snapshot taken when the anchor was loaded, so a mesh address assigned after the load needs no reload.

Only TCP keeps state. pf consults the state table ahead of the ruleset and a state entry is bidirectional, so a stateful rule covering every protocol would keep an inbound-initiated UDP or ICMP flow alive after its rule turned into a deny: the node's own reply creates the entry, and every further packet of that flow matches it instead of the ruleset. pf's idle timeouts refresh on each packet, so an active flow would never expire. TCP is not affected, because the implicit `flags S/SA` pfctl puts on a stateful TCP pass rule means an outbound SYN-ACK creates no state.

The cost is that the node's own outbound UDP and ICMP flows get no automatic return path: a reply arriving on the mesh interface is subject to the policy like any other inbound packet, so the policy has to allow it. This is the fail-closed side of the trade — a revoked rule takes effect at once, on every protocol.

On Windows the forward path is narrower than the local one. `FWPM_LAYER_IPFORWARD_V4` carries interfaces, addresses and a protocol, but no port. `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` carries the full five-tuple.

The ruleset is ordered and first-match-terminating, so a rule left out of the forward layer is not narrowed to nothing: the traffic it covered is re-decided by whatever rule follows it. A port-scoped **deny** is therefore installed on the forward layer without the port condition, which blocks a superset of what the rule asked for. A port-scoped **allow** cannot be narrowed that way, so it gets no forward filter and the traffic it covered falls through to the rules below it — at worst the default deny. Both directions fail closed, and the second is the one an operator notices: on a bridge or relay node, transit traffic a port-scoped rule allows is dropped. `ApplyRules` logs one `Warn` line per apply naming how many rules that affects, so the effect is not mistaken for a routing fault.

One more Windows difference: `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` classifies a TCP connection once, at accept, so a newly applied deny does not cut an already accepted inbound connection, which pf `no state` and the nftables forward chain both do.

## macOS: pf

### The anchor

plexd's rules live in the pf anchor `com.apple/plexd`. Apple's `/etc/pf.conf` references `anchor "com.apple/*"` and `nat-anchor "com.apple/*"`, so the kernel evaluates every child of `com.apple` for filter rules and for translation rules without a change to the main ruleset. That file's own header says system services rewrite it dynamically, which is why plexd stays out of it.

`pfctl -f` replaces an anchor's rules wholesale, and there is no way to add a single rule to one, so the controller keeps the desired state itself and renders the whole anchor on every change. The rendered text opens with a header line, so an operator reading the loaded ruleset knows who owns it and that local edits do not survive.

### The rendered anchor

Six rules covering every field combination render as:

```text
# plexd policy anchor. Managed by plexd; edits are overwritten.
# chain plexd-mesh
pass out quick on utun4 inet proto tcp from (utun4) to any keep state
pass out quick on utun4 inet from (utun4) to any no state
pass in quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 no state
pass in quick on utun4 inet proto udp from 10.0.0.0/24 to 10.1.0.0/24 port 53:60 no state
pass in quick on utun4 inet proto icmp from 10.0.0.0/24 to 10.1.0.0/24 no state
pass in quick on utun4 inet from 10.0.0.9 to 10.1.0.0/24 no state
block in quick on utun4 inet from 10.0.0.9/32 to any
block in quick on utun4 inet from any to any
```

| Element | Meaning |
|---|---|
| `# chain plexd-mesh` | pf has no user chains, so the chain is a comment. The name is what `ApplyRules`, `FlushChain` and `DeleteChain` address |
| `quick` | The first matching rule is final, the first-match semantics the nftables backend has |
| `no state` | Every packet stays subject to the current rules, so a new deny takes effect at once instead of after the last flow expires. The `pass out` pair keeps this true for UDP and ICMP as well |
| `block` | A `deny` rule. pf's default block policy is drop, what the nftables backend expresses as `VerdictDrop` |
| `any` | An empty address field or `0.0.0.0/0`, the match the nftables backend leaves out of a rule |

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

`pfctl` prints its own normalised form rather than the text plexd loaded: a `block` reads `block drop`, a single port reads `port = 443`, and a dynamic address pool carries a trailing `round-robin`.

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

Each rule yields one filter at the local-delivery layer, named `plexd <chain> #<i> inbound`, and a second at the forward layer, named `plexd <chain> #<i> forward`. Only an `allow` that names a port has no forward filter; see [What the rules govern](#what-the-rules-govern).

| Rule field | `LayerALEAuthRecvAcceptV4` (inbound) | `LayerIPForwardV4` (forward) |
|---|---|---|
| `Interface` | `FieldIPLocalInterface` equals the LUID | `FieldSourceInterfaceIndex` equals the index |
| `SrcIP` | `FieldIPRemoteAddress` | `FieldIPSourceAddress` |
| `DstIP` | `FieldIPLocalAddress` | `FieldIPDestinationAddress` |
| `Protocol` | `FieldIPProtocol` | `FieldIPProtocol` |
| `Port`, `PortTo` | `FieldIPLocalPort`, an equality or a `wf.Range` | The layer has no such field: dropped on a `deny`, and an `allow` gets no forward filter |
| `Action` | `wf.ActionPermit` or `wf.ActionBlock` | The same |

Windows delivers a packet locally only when its destination is an address of the arrival interface, so the local interface is the arrival interface, the `iifname` the Linux chain matches. An empty address field or `0.0.0.0/0` yields no condition at all. A rule with an empty interface name is rejected: a filter without an interface condition would govern every adapter of the host.

### Weights and the epoch

Within a sublayer WFP evaluates the heaviest filter first and the first terminating action wins, which is the first-match order the other two backends have. Filter `i` of `n` in epoch `e` gets:

```go
weight := uint64(e)<<32 | uint64(n-i)
```

Rule 0 is the heaviest of its own apply, and the epoch in the high half makes every filter of a newer apply outweigh every filter of an older one. `ApplyRules` builds its filters in `epoch+1` and installs them all before it deletes the ones the chain held, so the chain is never unfiltered in between and the new decisions win while both sets are installed. The weight stays below 2^60 for 2^28 applies, which is what a `FWP_UINT64` weight accepts.

Every rule is translated before the first filter is installed, so a rule the engine would reject fails without leaving half a ruleset behind. When an `AddRule` fails anyway, every filter that call installed is deleted again and the chain keeps the ones it had.

### Interface resolution

A rule carries the friendly name, the name the configuration holds and the one a Wintun adapter is created under. `net.InterfaceByName` resolves it to an interface index and `winipcfg.LUIDFromIndex` turns that index into the LUID. The forward layer matches the index, the local-delivery layer the LUID. Each name is resolved once per apply, because most rules of a chain name the same interface and every lookup is a syscall.

### Soft permits

`HardAction` stays false on every filter, so a plexd permit is a soft one that the Windows Firewall's own sublayer may still block, while a plexd block is final. plexd's rules cannot open a port the host firewall closes.

### Inspecting the filters

```powershell
netsh wfp show filters file=-
```

The dump lists every filter in the engine. plexd's carry the names `plexd <chain> #<i> inbound` and `plexd <chain> #<i> forward` and sit in the sublayer `plexd policy`. Without `file=-` the command writes the same XML to `filters.xml` in the working directory.

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
| Installing a filter | `policy: wfp: apply rules: add filter "plexd <chain> #<i> inbound":` |
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

All entries carry `component=policy` for the filter operations and `component=bridge` for the NAT ones. All are at `Debug` except the one `Warn` and the one `Error` line.

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
| `wfp forward path cannot enforce a port, allow rules narrowed away` (`Warn`) | `chain`, `count` |
| `wfp rollback delete failed` (`Error`) | `filter`, `error` |

| Message (`component=bridge`) | Keys |
|---|---|
| `NAT masquerade configured` (macOS) | `interface`, `anchor` |
| `NAT masquerade configured` (Windows) | `interface`, `prefix`, `nat` |
| `NAT masquerade already configured` (Windows) | `interface`, `prefix` |
| `NAT masquerade removed` | `interface` |
| `NAT masquerade not configured, idempotent success` (macOS) | `interface` |

`count` is the number of rules the chain was given, `filters` the number of WFP filters they became, which is larger whenever a rule reaches the forward layer too. Two lines sit above `Debug`. `wfp forward path cannot enforce a port, allow rules narrowed away` names, per apply, how many `allow` rules the node does not enforce on the forward path; its `count` is a subset of the chain's rules, not of its filters. `wfp rollback delete failed` reports an apply whose `AddRule` failed: it deletes the filters it already installed, and a deletion that fails there leaves a filter behind that only the session's close drops.

## Tests

Both controllers reach the operating system through seams, so every rendered rule and every idempotent case runs on an ordinary unprivileged runner. macOS wires the package's recording runner in place of `pfctl`, which captures each invocation's arguments and its stdin, so a test pins the whole anchor text a change renders. Windows wires a `wfpEngine` fake in place of the session, which records the sublayer, the filters in the order they were added and the deletions, and can be armed to fail a chosen `AddRule`; PowerShell goes through the same recording runner.

`TestPFController_RenderParses` runs the real `pfctl -n -q -a com.apple/plexd -f -` over the rendered text. `-n` parses without loading, which needs no access to `/dev/pf`, so the test proves the rendered syntax is pf's without root.

Three tests drive the real host and are gated:

| Test | Gate | Locally |
|---|---|---|
| `TestPFController_Real` (`pf_darwin_test.go`) | `PLEXD_TEST_REAL_PF=1` and `os.Geteuid() == 0` | `sudo PLEXD_TEST_REAL_PF=1 go test -run TestPFController_Real ./internal/policy/` |
| `TestWFPController_Real` (`wfp_windows_test.go`) | `PLEXD_TEST_REAL_WFP=1` and an elevated token | `$env:PLEXD_TEST_REAL_WFP='1'; go test -run TestWFPController_Real ./internal/policy/` from an elevated shell |
| `TestWFPController_RealNAT` (`netnat_windows_test.go`) | The same | `$env:PLEXD_TEST_REAL_WFP='1'; go test -run TestWFPController_RealNAT ./internal/policy/` from an elevated shell |

`TestPFController_Real` loads an anchor naming `plexd99`, an interface no host has, takes the pf reference, reads the filter and nat rules back with `pfctl -a com.apple/plexd -s rules` and `-s nat`, then deletes the chain and asserts the anchor is empty and the token released. A host that had pf disabled is left disabled. The variable gates it in addition to the effective uid, so `sudo go test ./...` on a developer's Mac does not enable pf on their host.

`TestWFPController_Real` installs filters for prefixes no host carries and no blanket deny, so the runner's own traffic is untouched. It enumerates plexd's filters through a session of its own, checks that the `allow` naming a port got no forward filter, and pins `FWP_E_FILTER_NOT_FOUND` by deleting a filter that is not there. `TestWFPController_RealNAT` creates the NetNat object for `10.255.252.0/30`, reads the prefix back, and repeats both the add and the remove to prove they are idempotent — the second read after the removal is what proves the absent case is a success with no output rather than a localized error.

CI runs all three; see [CI Workflow](../development/ci-workflow.md).
