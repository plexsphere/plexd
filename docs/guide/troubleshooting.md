---
title: Troubleshooting
---

# Troubleshooting

This guide covers the most common issues encountered when running plexd and how to diagnose them.

## Reading the daemon log

Every section below asks you to read the agent's own log. `plexd logs` finds it on any platform:

```bash
plexd logs        # recent entries
plexd logs -f     # follow (not supported on Windows)
```

Where it reads from, and the native command if you would rather use it directly:

| Platform | Log | Native command |
|----------|-----|----------------|
| Linux    | journald | `journalctl -u plexd` |
| macOS    | `/Library/Logs/plexd/plexd.log` | `tail -f /Library/Logs/plexd/plexd.log` |
| Windows  | Application Event Log, source `plexd` | `Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='plexd'}` |

A `plexd up` started by hand writes to its own terminal rather than to any of these, so a host that never ran `plexd install` has nothing for the command to read. It says so instead of failing.

## Agent fails to register

```bash
plexd status   # Check current state
plexd logs     # View service logs
```

Verify that the bootstrap token has not expired and that the node can reach the control plane API (`PLEXD_API`).

Until registration completes the node API is not up, so `plexd status` reports that the agent is not running; the log and `/readyz` say what registration is doing.

A log line `registration rate limited by the bootstrap token policy, waiting` does not mean the enrolment is broken. The bootstrap token is valid, and the BootstrapToken policy it was issued under limits how often it is redeemed, for example once per hour for a fleet that shares one token. plexd waits until the `retry_at` time the line names and then registers again on its own, as often as the policy asks; no action is needed. Meanwhile `/readyz` on the health listener answers `not ready: registration rate limited` (`curl -s http://127.0.0.1:9101/readyz` with the default `health.listen`). When the Project administrator loosens the policy, restart plexd to ask again at once instead of waiting.

## Node removed from the control plane

```bash
plexd status
plexd logs | grep "credential refused"
```

When the Node is removed from the control plane, or its credential revoked, the control plane answers every heartbeat `401`. After three refused heartbeats with no accepted one between them, about 60s at the default interval, the agent parks: it stops calling the control plane and logs one Error line:

```
agent: heartbeat: node credential refused, the Node was removed from the control plane or its credential revoked; control-plane calls suspended
```

The line carries `node_id`, `code` (the problem code of the refusal, `nsk_invalid` for a removed Node), `consecutive`, `next_probe` and `enrol_again`. The two refused heartbeats before it log a Warn, `agent: heartbeat: credential refused`. While parked, the other loops log their refused calls at Debug, so the park line is the one to look for (see [Quiet Failure Logs](../reference/core/heartbeat-service.md#quiet-failure-logs)). A long park fills the buffers of the metrics, log and audit pipelines, which then keep only their newest entries; the log and audit forwarders log that overflow at Debug as well. `plexd status` prints the same cause after the counts:

```
The control plane refuses this node's credential: the Node was removed or its credential revoked.
To enrol again, run 'plexd deregister', provide a fresh bootstrap token, and restart plexd.
```

`/readyz` answers `503` with `not ready: node credential refused`. The WireGuard interface, the firewall, the mesh server and the local node API stay up.

To enrol the machine again:

1. Run `plexd deregister` to remove the old identity (see [`plexd deregister`](../reference/core/cli.md#plexd-deregister)).
2. Provide a fresh bootstrap token from the control plane (see [Source Priority](../reference/core/registration.md#source-priority) for where plexd reads it).
3. Restart plexd. It registers as a new Node.

A fault on the control plane side refuses the credential the same way and parks the agent with the same line. The agent keeps probing with the heartbeat, after 1, 3, 7, 15, 31 and 63 minutes at the default interval and hourly after that, and resumes on its own on the next accepted probe. It then logs `agent: heartbeat: node credential accepted again, control-plane calls resumed`. If the Node still exists on the control plane, wait for that probe instead of enrolling again.

## Every heartbeat refused after an agent upgrade

```bash
plexd logs | grep 'agent: heartbeat'   # The heartbeat's lines
```

A plexd release after v0.39.0 declares on its heartbeat what the node can do, in the member `features`. A control plane that predates the member decodes the heartbeat with unknown fields refused and answers every heartbeat that carries it with `400 malformed_heartbeat_request`. plexd logs one Error line per heartbeat:

```
agent: heartbeat: rejected as malformed, a control plane that predates the features member refuses it; upgrade the control plane
```

Its `error` starts with `api: HTTP 400 (malformed_heartbeat_request):`. The control plane records none of these heartbeats, so it shows the node as `unreachable` and then `offline` (see [Heartbeat Protocol](agent-lifecycle.md#heartbeat-protocol)), and the node receives no `reconcile` or `rotate_keys` hint from it. The refusal does not count toward the [credential park](#node-removed-from-the-control-plane), and plexd sends the next heartbeat unchanged.

plexd has no fallback: it does not detect such a control plane and does not leave the member off for it. Upgrade the control plane first, then the agents. Only a node that declares a feature is refused. plexd declares `mesh_readdress` when the node can follow a move to another mesh address: its WireGuard interface came up with the Domain mesh CIDR and its controller can replace an address. A node that declares nothing sends no `features` and is accepted. The same code on a heartbeat without the member logs `agent: heartbeat: send failed` instead, and points at another cause. No plexd release through v0.39.0 sends the member, so rolling the agent back to one also ends the refusals: it keeps the mesh address its `identity.json` holds and is not moved again. See [Upgrade order](../reference/core/heartbeat-service.md#upgrade-order).

## No peers connected

```bash
plexd peers                                # List peer status
plexd logs | grep "NAT translates ports"   # Check for a port-translating router
```

Common causes: firewall blocking UDP traffic, STUN servers unreachable, or the node has not yet received its peer list from the control plane.

A node behind a router that translates ports peers with every publicly reachable node but not with other nodes behind NAT. Its published endpoint carries the WireGuard listen port, and nothing forwards that port to the node, so peers behind NAT dial a port that never answers. The agent logs `NAT translates ports, the published endpoint assumes the WireGuard listen port is forwarded` when discovery first sees the router assign its own port, and reports `port_mapping` `translated` with every endpoint report. To fix it, forward the WireGuard listen port (UDP, `wireguard.listen_port`, 51820 by default) on the router to the node, or give the Domain a bridge that relays (see [NAT Relay](../reference/bridge/nat-relay.md)). Peers also receive the node's peer-observed endpoint, the mapping other nodes see in their handshakes with it, once at least two nodes of the Domain hold a direct handshake with it (see [Peer-observed endpoints](../reference/networking/peer-endpoint-exchange.md#peer-observed-endpoints)).

## Tunnel established but no traffic

```bash
plexd policies        # Check active policies
plexd logs | grep mtu # Check the mesh MTU
```

Network policies may be blocking traffic. Verify that the desired communication is allowed by the policies configured in the control plane.

`plexd policies` lists the ruleset the node applied, which is not always the one the control plane serves. When plexd could not apply the latest revision, the command says so ahead of the table:

```text
Received revision 0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c2 (fingerprint q7vZ4Zx0d8nU1m3oW5bJk2pQ9rT6yH4sL0aE8cV1fG4=) is not applied: policy: enforce: policy: invalid ruleset: policy: rule 0: unsupported action "deny" (tried 3 times).
Showing the ruleset applied before it.
```

The node enforces the rows that follow, the ruleset it applied before, and not the received revision. The text after `is not applied:` is plexd's error. One that holds `invalid ruleset`, as above, names a rule plexd cannot translate, and the revision fails the same way until the control plane serves another. Any other text is a failure of the node's firewall backend. plexd applies the revision again on every state pull and counts the attempts in `tried`. It logs the first failure at Error, as `policy revision rejected, keeping previous ruleset` or `reconcile: apply firewall rules failed`, and every repeat at Debug as `policy revision still rejected`. The control plane sees the revision as `rejected` from the node's [policy status report](../reference/networking/network-policy.md#policy-status-report). `Policy enforcement is disabled` or `is unavailable` means the node enforces no ruleset at all. See [`plexd policies`](../reference/core/cli.md#plexd-policies) for every state the command prints.

The policy filters both directions on the mesh interface: what arrives on it and what the node itself sends over it. A connection the node opens to a peer needs a rule from the node's mesh IP to the peer, and the peer's policy has to let it in. A Project's allow-all policy does both. UDP to port 9, plexd's relay liveness probe, passes without a rule, and so does UDP to port 7911, its round-trip probe, in both directions. To find a packet the node's own policy drops on its way out:

- On Linux a blocked UDP or ICMP send fails at once with `EPERM`, which a local program reports as `operation not permitted`. A blocked TCP connect times out instead. `sudo nft list chain inet plexd plexd-mesh-output` lists the output chain with its counters. The guard that opens the chain, `oifname != "plexd0" accept`, has none, and a set rule counts every packet its set admits, not each rule in the set. The counter of its last rule, the default deny, grows with every packet the chain drops.
- On macOS `sudo pfctl -a com.apple/plexd -vs rules` lists the anchor's rules with their counters. The counters of `block drop out quick on <utun> from (<utun>) to any label "plexd-default-deny"`, the default deny for what the Mac sends, grow with every packet it drops. `sudo pfctl -a com.apple/plexd -sl` prints the counters of both default deny lines under their label.
- On Windows `netsh wfp show filters file=-` lists plexd's outbound filters as `plexd <chain> #<i> outbound`, with ` v6` appended at the IPv6 layer. WFP keeps no per-filter counters, so a Windows node reports no drop counters to the control plane.

On Linux and macOS plexd sends the sum of the default deny's counters to the control plane as `drops` in its [policy status report](../reference/networking/network-policy.md#policy-status-report).

If pings and WireGuard handshakes pass but TCP connections over the mesh stall, the uplink may carry less than the mesh MTU plus WireGuard's 80 bytes of encapsulation. Small packets get through and full-size ones are lost without an error, so a connection hangs at its first full-size segment. SSH, for example, hangs in key exchange. A DS-Lite uplink over PPPoE carries 1452-byte packets, which fit a mesh MTU of at most 1372.

plexd sizes the interface to the uplink when it starts, and measures again every 10 minutes. The `wireguard interface configured` line shows what it chose:

```text
level=INFO msg="wireguard interface configured" component=wireguard interface=plexd0 listen_port=51820 mesh_ip=10.99.0.5 mtu=1372 mtu_source=probe path_mtu=1452
```

- `mtu` is the MTU the interface came up with, and `path_mtu` the largest IPv4 packet the probe got through to a STUN server.
- `mtu_source=probe` means the probe measured the uplink, and `config` that `wireguard.mtu` pins the MTU. `default` means the interface came up at 1420 unmeasured: either detection is off, which logs `mesh mtu detection disabled by nat.enabled`, or no STUN server answered, which logs `wireguard: mtu probe inconclusive, using the default mtu` with the error.
- A later change logs `wireguard: mesh mtu lowered` or `wireguard: mesh mtu raised` with `old_mtu`, `mtu` and `path_mtu`. A round without an answer logs `wireguard: mtu probe inconclusive, keeping the current mtu`, and an uplink too small even for the 1280-byte floor logs `wireguard: uplink carries less than the mesh minimum mtu`.

The probe measures only the outbound IPv4 path to the STUN servers. It cannot see a bottleneck on a path to a peer that the STUN traffic does not cross, and it gets no answer where UDP to the STUN servers is blocked. In those cases set `wireguard.mtu` to the path MTU minus 80, for example `1372` for a 1452-byte path, and restart plexd. A positive value pins the MTU and turns detection off. See [MTU detection](../reference/networking/wireguard.md#mtu-detection).

## A mesh edge shows no round-trip time

```bash
plexd logs | grep 'rtt probe'                          # The round-trip probe's lines
plexd logs | grep 'handshake report: send failed'      # Handshake reports the control plane refused
sudo wg show plexd0 latest-handshakes                  # Linux: the latest handshake with each peer
sudo ss -Hlunp 'sport = :7911'                         # Linux: the socket that holds UDP port 7911
```

plexd measures the round-trip time to each mesh peer with a UDP echo on port 7911 of the mesh address, once per heartbeat interval, and sends it as `rtt_microseconds` on the peer's entry in the [handshake report](../reference/core/heartbeat-service.md#handshake-reporter). The control plane ranks a pair's relays by it, and the Console prints it on the mesh edge. A peer that answers none of three probes in a row loses its value, about three heartbeat intervals after it stopped answering, and a change of the endpoint WireGuard uses for the peer clears the value until the next answer. A node reports a peer without a value as an entry with the handshake age and the endpoint alone. See [Round-trip probe](../reference/networking/wireguard.md#round-trip-probe).

Common causes: the peer runs no plexd with the probe, a host firewall drops UDP port 7911, the node holds no fresh handshake with the peer, the probe did not start or its socket did not open, the node's sends to the peer fail, or the control plane refuses the reports.

- A peer that runs a plexd release from before the probe, or a plain WireGuard peer without plexd, answers no probe, so the node reports it without a value. A pair measures each other only when both run a plexd with the probe.
- plexd's own policy passes UDP to port 7911 on the mesh interface without a rule on every platform, but plexd opens no port in a host firewall it does not manage, such as Windows Defender Firewall or the NixOS host firewall. A node behind such a firewall still measures its peers, since the answer to its own probe comes back, but answers none of their probes, so they report it without a value. The control plane takes either end's value for a node and a relay bridge, so the node's own measurement is enough for its relays' ranking. On Windows add the rule of step 4 of the [Windows installation guide](../how-to/windows-installation.md#_4-allow-inbound-wireguard-traffic). The NixOS rule belongs to plexsphere/plexsphere-node and is tracked in plexsphere/plexsphere-node#38.
- plexd probes only a peer whose latest handshake is younger than 180 seconds and whose mesh IP lies inside the Domain's mesh prefix. A peer without a fresh handshake gets no probe and has no value; see [No peers connected](#no-peers-connected). The value is the time through the tunnel as it runs now.
- No `wireguard: rtt probe started` line, with `interval` and `port=7911`, means the probe never started: the WireGuard interface did not come up. `wireguard: rtt probe unavailable, the controller cannot read peer stats` at Info means the WireGuard controller cannot read the device's peers, and the probe stopped.
- `wireguard: rtt probe listen failed` with `address` (`<mesh ip>:7911`) and `error` means the node could not bind its socket. On Linux the `error` ends in `bind: address already in use` when another program holds UDP port 7911 on the mesh address or on the wildcard address, in `bind: cannot assign requested address` when the mesh address is not yet assigned to the interface, and in `bind to interface <iface>: operation not permitted` on a kernel before Linux 5.7 when plexd runs without `CAP_NET_RAW`, which binding the socket to the mesh interface needs there. An `error` of `wireguard: rtt probe: mesh ip <ip> is not IPv4` means the registered mesh IP is no IPv4 address, and plexd never binds the wildcard address in its place. The line comes at Warn the first time and at Debug while the bind keeps failing. Meanwhile the node sends no probe and answers none, and every value it holds goes after three rounds. plexd tries the bind again on every round, so freeing the port is enough, without a restart.
- `wireguard: rtt probe send failed`, with `peer_id`, `mesh_ip` and `error`, names a peer the node could not send its probe to. It comes at Warn the first time for that peer and at Debug while the sends to it keep failing, and each failed send counts as an unanswered probe.
- A control plane older than plexsphere/plexsphere#1145 does not know the member. It decodes the report without unknown fields and refuses every report that carries the member with `400 malformed_handshake_report`, so it records nothing of that report, the handshake ages included. plexd logs `agent: handshake report: send failed` at Warn on every tick, with an `error` that starts `api: HTTP 400 (malformed_handshake_report):` and ends with the control plane's detail. plexd has no fallback: upgrade the control plane.

## A site stays on a dead bridge

```bash
plexd logs | grep 'shared subnet'                         # Assignments, moves and the two Warn lines
plexd logs | grep -E 'failure detection|endpoint selection'  # The time held, and whether endpoint selection runs
sudo wg show plexd0 allowed-ips                           # Linux: the bridge peer that carries the subnet
sudo wg show plexd0 latest-handshakes                     # Linux: the latest handshake with each bridge
```

When tunnels on several bridges of a Project list the same site subnet, the state pull names the bridges in `shared_subnets`, the carrier first, and plexd keeps the subnet on the allowed IPs of one bridge at a time. On a node that holds the Domain's failure-detection time, endpoint selection watches every bridge of the entry and moves the subnet to the next live bridge once the path to its bridge has been dead for that time, 14 to 15 s after the bridge's last packet at the default 15 s, and logs `wireguard: shared subnet moved` with `from`, `to` and `reason=bridge_dead`. `wg show plexd0 allowed-ips` lists the subnet beside exactly one peer, the bridge the node routes the site through. The node's handshake report names the subnet in the `shared_subnets` of that bridge's entry, which the control plane shows as the mesh edge's `shared_subnets`. See [Shared subnets](../reference/networking/wireguard.md#shared-subnets).

Common causes: no bridge of the entry is alive, the move's write failed, the bridge is judged against the 15-second floor, the node holds no failure-detection time or does not run endpoint selection, the node took no entry for the subnet, or the site answers through the dead bridge.

- `wireguard: shared subnet has no live bridge` at Warn, with `subnet`, `bridge`, `silent_for` and `window`, means the holder's path is dead and no other bridge of the entry answered within its window, so the subnet stays where it is. The line comes once until the holder changes or its path is alive again. Check the standbys' handshakes with `wg show`: a standby the node never completed a handshake with is never alive.
- `wireguard: shared subnet move failed` at Warn, with `subnet`, `from`, `to` and `error`, names a device write that failed. A failed write of the new holder changes nothing, endpoint selection logs `wireguard: endpoint selection pass failed` with the same error, and the next pass tries the move again. A failed write of the old holder leaves the subnet on the new holder.
- A bridge that answers no round-trip probe is judged against at least 15 seconds, whatever lower value the Domain sets: a bridge on a plexd release through v0.38.0, a plain WireGuard peer, and a bridge behind a host firewall that drops UDP port 7911. Its WireGuard answers the node's probe only within 10 seconds, so a shorter window would leave a healthy idle bridge, and the node waits 14 seconds on it. `rtt_microseconds` on the bridge's entry of the handshake report shows whether it answers; see [A mesh edge shows no round-trip time](#a-mesh-edge-shows-no-round-trip-time).
- No `wireguard: failure detection time set` line since the start means the node holds no failure-detection time, and then it moves no subnet on its own: it keeps the subnet where the pulls put it and leaves a dead bridge only when the control plane drops it from the entry. A node also moves nothing on its own while endpoint selection does not run: `wireguard: endpoint selection disabled, persistent_keepalive is 0s` means `wireguard.persistent_keepalive` is `0s`, and `wireguard: endpoint selection unavailable, the controller cannot read peer stats` that the WireGuard controller cannot read the device's peers.
- No `wireguard: shared subnet assigned` line for the subnet means the node took no entry for it. `wireguard: shared subnet not programmed` with `subnet` and `reason` names an entry it skipped: `no_bridge` when no bridge of the entry is a peer of the pull, and `invalid`, `overlaps_mesh`, `inside_local_network` or `duplicate` as for a routed subnet. A plexd release through v0.38.0 predates the block: it routes the subnet through its carrier and follows a carrier move with its next pull.
- A subnet that moved while the site still does not answer points at the return path. The remote site has to answer a flow through the tunnel it arrived on, or route the Domain mesh CIDR into the carrier's tunnel; see [Routes and Policy](../reference/bridge/site-to-site-vpn.md#routes-and-policy).

A restarted plexd starts every shared subnet on the first bridge of its entry again, since the holder lives in memory only, and moves it on once that bridge's window passes without an answer while a standby answers.

## A moved node does not follow its new mesh address

```bash
plexd logs | grep 'mesh address'                     # The moves and the steps that failed
ip -4 addr show plexd0                               # Linux: the address the mesh interface holds
sudo grep '"mesh_ip"' /var/lib/plexd/identity.json   # Linux: the address a restart starts from
```

The control plane can move a node to another mesh address, and does so only while the node's latest heartbeat declared `mesh_readdress`. Every state pull carries the address as `mesh_ip`, so the node follows a move with its next pull, at most one reconcile interval (60 s by default) later. Its peers learn the address with their own pulls, and a pair has no connectivity until both sides have pulled. plexd replaces the address on the mesh interface in place and logs `wireguard: mesh address replaced` with `interface`, `previous_mesh_ip` and `mesh_ip`, then `mesh address changed from state pull` with `previous_mesh_ip` and `mesh_ip`. The parts that hold the address follow, and plexd writes the address to `identity.json`. A restart logs `existing identity loaded` with the `mesh_ip` it starts from. See [Mesh Address Changes](agent-lifecycle.md#mesh-address-changes).

A move ends the tcp sessions that listened on the old address, which report `terminated_by: plexd_close`; their operators open new ones. ssh sessions stay.

A moved node on Linux whose mesh names, its own and its peers', stopped resolving through systemd-resolved while `resolvectl status plexd0` names the new server is covered under [A mesh name does not resolve](#a-mesh-name-does-not-resolve).

Common causes: a step of the move failed, the interface cannot change its address while plexd runs, the write to `identity.json` failed, or the pull named an address plexd does not apply.

- `mesh address not applied; retrying on the next pull` with `step`, `mesh_ip` and `error` names a step of the move that failed. It comes at Error the first time for an address and at Debug while the step keeps failing. plexd calls the failed step again on every pull, so once its cause is gone the next pull completes the move without a restart.
- With `step=interface` the replace on the mesh interface failed, and the `error` starts with `wireguard: readdress:`. plexd keeps using the old address, moves no other part and writes nothing to `identity.json`. The next pull repeats the replace with the same two addresses, which also completes a replace that stopped halfway.
- With `step=mesh-dns` the resolver could not move its listener to the new address, and the `error` starts with `meshdns: rebind <address>:<port>:`. This happens on Linux only: on macOS and Windows the resolver listens on `127.0.0.1` and does not move. The resolver keeps its sockets on the old address, and its registration with systemd-resolved keeps naming that address, which the interface no longer holds. An `error` that ends in `bind: address already in use` means another program holds the resolver's port (`dns.listen_port`, 5354 by default) on the new address or on the wildcard address; free the port. A failed `mesh-dns` step does not stop the steps after it, and plexd writes the address to `identity.json` once the interface took it, whatever a later step does.
- The steps `sessions`, `site-to-site` and `mesh-rewriter` report no error, so the line names only `step=interface` or `step=mesh-dns`. `sessions` ends the tcp sessions on the old address, and new ones listen on the new address. `site-to-site` builds the site-to-site tunnels of a macOS bridge again with the new address. `mesh-rewriter` moves the in-process source rewrite of a Windows bridge to it.
- `mesh address cannot be applied while plexd runs; restart plexd to use it` at Error, once per address, means the pull carried a new address while the interface cannot change its address in place: the WireGuard interface did not come up (`wireguard setup failed, continuing without WireGuard` at start), its controller cannot replace an address, or it carries a host `/32` because the identity holds no usable Domain mesh CIDR. Such a node declares no `mesh_readdress`, so the control plane moved it while the latest heartbeat came from an earlier run of plexd that declared the feature. plexd writes the new address to `identity.json` and keeps the old one on the interface and in every other part, so peers that pulled the move cannot reach the node. Restart plexd, which brings the interface up with the address `identity.json` holds. When the interface did not come up, first remove the cause that the setup line's `error` names.
- `mesh address not persisted; retrying on the next pull` at Warn means the write to `identity.json` failed. Its `error` starts with `registration: commit mesh ip:`, and plexd writes again on every pull. The node runs on the new address, or, when plexd also logged `mesh address cannot be applied while plexd runs` for the address, still on the old one. A restart before a write succeeds starts from the old address in both cases. A node that ran on the new address moves again with the first pull after the restart. For a node that could not apply the address, remove the cause of the failed write and check that `identity.json` holds the new address before you restart plexd.
- `mesh address from state pull refused` at Warn, with `mesh_ip` and `error`, once per address, means plexd applies nothing of the pulled address and writes nothing: it is no IP address, or an unspecified, loopback or multicast one, or the interface refused it as IPv6, link-local or outside its mesh prefix. A node moves only inside the prefix its interface came up with, the Domain mesh CIDR of its registration.
- No `mesh address changed from state pull` line after a move means the node did not see it yet, or the control plane sends no `mesh_ip`: one that predates the member never moves a node. With `PLEXD_LOG_LEVEL=debug`, plexd logs `state pull carried no mesh_ip; keeping the address` on every pull without the member.

## A mesh name does not resolve

```bash
resolvectl status plexd0                      # The link's server, domains and default-route flag
resolvectl query db-1.openstack.lab.internal  # Ask systemd-resolved directly
resolvectl query --type=SRV _postgres._tcp.openstack.lab.internal  # A record of another type
resolvectl query host.corp.example.com        # A name under a forward zone
plexd logs | grep -E 'mesh dns|component=meshdns|dns block|PLEXD_DNS_ENABLED|control plane name'  # The resolver's log lines
```

On Linux, plexd answers the mesh names of its Domain on the Node's own mesh IP, port 5354 by default, and registers the Domain's zones with systemd-resolved on the mesh interface (`wireguard.interface_name`, `plexd0` by default). `resolvectl status plexd0` should list the server `<mesh IP>:5354`, the search domain, each routing domain with a leading `~` (every other zone that no zone above it covers, every reverse zone, and every forward zone of the Node's forwarding setting), and `-DefaultRoute`. With a catch-all it shows `+DefaultRoute` instead, and the domains end in `~.`. A link without that server has no registration. `resolvectl query` names the link an answer came from, so a mesh name answered through the mesh interface shows `plexd0`. A bare host name resolves through the search domain, and a mesh IP resolves to its name when the Domain's reverse zones cover it.

`resolvectl status plexd0` should also read `Current Scopes: DNS`. `Current Scopes: none` beside the listed server means systemd-resolved holds no address or no carrier for the link, so it sends the mesh names to its other servers, which answer `not found`. On plexd v0.40.0 this follows every move of the node to another mesh address: the move ends with the delete of a `/32` of the new address, which systemd-resolved takes as the removal of the address (see [Replacing the address on each platform](../reference/networking/wireguard.md#replacing-the-address-on-each-platform)). `systemctl restart plexd` brings the scope back, and so does `ip addr change <mesh IP>/<prefix length> dev plexd0`, run as root, without a restart. A release after v0.40.0 keeps the scope across a move.

plexd also answers the records the Domain and its Projects define. `resolvectl query` asks for addresses unless `--type` names another type, such as `--type=SRV`, `--type=MX` or `--type=TXT`. With `--type` it prints each record as `<name> IN <type> <data>`, followed by `-- link: plexd0`. A name that exists without a record of the type prints `does not have any RR of the requested type`. A CNAME whose target lies outside the mesh zones is answered as the CNAME alone, for the system resolver to follow. systemd-resolved follows it through its other servers, so `resolvectl query` shows the address without the link `plexd0`, and the target in parentheses. See [Answer Table](../reference/networking/mesh-dns.md#answer-table).

On macOS, plexd answers on `127.0.0.1`, port 5354 by default, because a Mac cannot reach its own utun mesh IP, and registers the Domain's zones in configd's dynamic store, from which mDNSResponder takes its per-domain resolvers. `scutil --dns` should list resolvers for the search domain and the routing domains, each with `nameserver[0] : 127.0.0.1` and a `port` line naming 5354, and the search domain also as a `search domain` of the primary resolver. `dig @127.0.0.1 -p 5354 <name>` asks plexd directly. `printf 'open\nlist State:/Network/Service/plexd-meshdns-.*/DNS\nquit\n' | sudo scutil` lists the keys plexd holds: `plexd-meshdns-search`, `plexd-meshdns-match-0` and any further match keys, and with a catch-all `plexd-meshdns-default`. A Mac that lists none has no registration. `dscacheutil -q host -a name <name>` resolves a name through the system resolver as other programs do and prints `ip_address: <address>`, and `dscacheutil -q host -a ip_address <mesh IP>` prints the name of a mesh IP that the Domain's reverse zones cover. `dig` and `nslookup` on macOS ask the servers in `/etc/resolv.conf` and so never reach a supplemental entry: a mesh name they do not resolve says nothing about plexd. mDNSResponder caches an answer for its TTL of 10 seconds, while plexd flushes the cache whenever it changes the registration, so an answer cached before the change, such as a negative one for a mesh name, does not outlive it. See [Registration on macOS](../reference/networking/mesh-dns.md#registration-on-macos).

On Windows, plexd answers on `127.0.0.1`, port 53, the only port the Name Resolution Policy Table sends to, and registers the Domain's zones as rules of that table, from which the DNS Client (`Dnscache`) takes the server for the names under each rule, and the search domain as the mesh adapter's search list. In PowerShell, `Get-DnsClientNrptPolicy` should list the search domain and the routing domains, each with a leading dot and the name server `127.0.0.1`, and with a catch-all also `.local` without a name server and `.`. `reg query "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig" /s` lists the rule keys plexd holds: `plexd-meshdns-match-0` and any further match keys, and with a catch-all `plexd-meshdns-exempt-local` and `plexd-meshdns-default`. On a host whose Group Policy configures the table, `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig" /s` lists the same keys there, and elsewhere it prints an error, because the key does not exist. A host that lists none has no registration. `Resolve-DnsName <name>` resolves a name through the DNS Client as other programs do, and `Resolve-DnsName -Server 127.0.0.1 <name>` asks plexd directly. `nslookup` asks the adapter's DNS server itself and bypasses the table, so a mesh name it does not resolve says nothing about plexd. plexd empties the DNS Client's cache whenever it registers or removes a rule, except in the cleanup after a failed registration. On a host whose Group Policy configures the table, the DNS Client follows a change of plexd's rules only after a machine policy notification, which plexd sends when it runs as the service; on the CI runner, which is not domain-joined, the DNS Client followed one within 0.6 seconds, and how long it takes on a domain-joined host was not measured. See [Registration on Windows](../reference/networking/mesh-dns.md#registration-on-windows).

The log lines say why a name is missing:

- No `mesh dns listening` line means the resolver did not start. `mesh dns disabled by dns.enabled` means `dns.enabled` is `false`. `wireguard unavailable, mesh dns not started` means the WireGuard interface did not come up. After a crash or a kill on Linux, the setup fails on the `plexd0` the killed run left behind, and the stop of this run deletes it, so restart plexd once more. `mesh dns not started, the mesh ip does not parse` means the mesh IP that registration assigned is not an IP address; its `mesh_ip` key shows it. `mesh dns listener cannot bind, mesh names are not answered` means another program holds the port; set `dns.listen_port` to a free one and restart plexd. On Windows its `hint` reads `free port 53 on 127.0.0.1, the only port the Name Resolution Policy Table sends to, or set dns.enabled: false`: another port would bind but stay unregistered, so stop the program that holds port 53 on `127.0.0.1`, or turn mesh DNS off.
- `mesh dns not registered, systemd-resolved is not usable` means the host has no systemd-resolved, one older than 246, or no reachable system bus. Its `reason` says which. A stopped systemd-resolved counts as none, because plexd does not start it. On macOS the line reads `mesh dns not registered, configd is not usable` and means `/usr/sbin/scutil` is missing; its `reason` reads `meshdns: scutil: /usr/sbin/scutil is missing: meshdns: no usable system resolver`. On Windows the line reads `mesh dns not registered, Dnscache is not usable` and means `dns.listen_port` is set to a port other than 53, which the Name Resolution Policy Table cannot send to, because a rule names its server by address only; its `reason` reads `meshdns: nrpt: the Name Resolution Policy Table sends queries to port 53 only, and the resolver listens on 127.0.0.1:<port>: meshdns: no usable system resolver`. Remove `dns.listen_port`, or set it to 53, and restart plexd. The resolver still answers on the `listen` address; see [Hosts without systemd-resolved](../reference/networking/mesh-dns.md#hosts-without-systemd-resolved).
- `mesh dns registration failed` carries the error systemd-resolved returned. `org.freedesktop.resolve1.LinkBusy` means systemd-networkd manages the link, which then cannot take settings over D-Bus. On macOS it carries the error of a scutil run, `meshdns: scutil: <op>: ...` with `<op>` `list`, `apply` or `revert`: for example `meshdns: scutil: apply: <output>` when scutil printed anything but `No such key` for the script that writes the keys, or `meshdns: scutil: list: context deadline exceeded` when scutil did not finish within the 5 seconds plexd gives it. See [scutil Errors](../reference/networking/mesh-dns.md#scutil-errors) for every form. After a failed `apply` script plexd removes every plexd key once and flushes nothing. On Windows it carries an error of the registry or of the search list, `meshdns: nrpt: <step>: <cause>` with `<step>` one of `list <store>`, `read <store> <key>`, `write <store> <key>`, `delete <store> <key>`, `open policy store`, `delete policy store` and `search list <iface>`, and `<store>` `local` or `policy`: for example `meshdns: nrpt: write local plexd-meshdns-match-0: <cause>`, or `meshdns: nrpt: search list plexd0: no such adapter` when no adapter carries the interface name. See [NRPT Errors](../reference/networking/mesh-dns.md#nrpt-errors) for every form. After a failed registration plexd clears the search list, deletes every plexd rule and flushes nothing. plexd tries again on every pull.
- `state pull carries no dns block, keeping the names held` means the control plane sent no names. A control plane that predates the block never sends one.
- `mesh dns skipped invalid entries` names the entries of the block plexd refused, up to five. A skipped record reads `record "<fqdn>" of type "<type>" <reason>`, and the other names and records keep answering. See [Records](../reference/networking/mesh-dns.md#records) for the checks. A skipped forward zone reads `forward zone "<zone>" <reason>` and a skipped resolver `resolver "<value>" of <owner> <reason>`, after the sentences of the records. A forward zone that a mesh zone shadows is skipped, because the mesh zone answers its names. See [Forward Zones and Resolvers](../reference/networking/mesh-dns.md#forward-zones-and-resolvers).

A program resolves through systemd-resolved only when `/etc/resolv.conf` or `nsswitch.conf` sends it there: `/etc/resolv.conf` names the stub listener `127.0.0.53`, or the `hosts` line of `/etc/nsswitch.conf` lists `resolve`. `resolvectl query` always asks systemd-resolved, so a name that `resolvectl query` answers and a program does not points at the program's resolver configuration. On the Node itself, `dig @<mesh IP> -p 5354 <name>` asks plexd's resolver directly. A query from any other address gets no answer, so the same command run in a container or Pod network fails by design.

systemd-resolved caches every answer for its TTL of 10 seconds, so a renamed host answers under its new name at most 10 seconds after the pull that carried the change. See [Mesh DNS](../reference/networking/mesh-dns.md).

### A forwarded name does not resolve

A name under a forward zone, or with a catch-all any name no other link's domain matches, goes from systemd-resolved to plexd, and plexd passes it on to the resolvers of the Node's forwarding setting on port 53. `resolvectl query` names the link `plexd0` for such an answer. On macOS mDNSResponder sends such a name to plexd through plexd's match entries or its default-resolver entry, and `dscacheutil -q host -a name <name>` asks for it. On Windows the DNS Client sends such a name to plexd through plexd's match rules or its rule for `.`, and `Resolve-DnsName <name>` asks for it. The log lines say where it stops:

- `mesh dns forwarding updated` with `forward_zones` and `catch_all` shows how many forward zones and catch-all resolvers plexd accepted. No such line, or zero counts, means the Node forwards nothing: the Node's Domain or Project holds no forwarding setting, or the control plane does not send the `forwarding` member. `dns block carries no forwarding member, keeping the forwarding held` means the control plane sent a block without the member, and plexd forwards as before.
- `mesh dns resolver does not answer` names the `resolver` and the `zone` (`.` for the catch-all) of a resolver that sent no reply in time or refused the connection, with the `error`. plexd asks it after the other resolvers of its zone for 30 seconds. `mesh dns resolver answers again` says it came back. A query that no resolver answers gets `SERVFAIL`, and with `PLEXD_LOG_LEVEL=debug` logs `mesh dns forwarded query failed`. systemd-resolved asks three times before a lookup fails, `resolvectl query` included. Resolvers that send nothing back make plexd wait its 4 seconds each time, so such a lookup fails with `SERVFAIL` only after about 12 seconds. Resolvers that refuse the query, with an ICMP port unreachable or a TCP reset, make plexd answer `SERVFAIL` at once, so the lookup fails at once too, and the `error` of `mesh dns resolver does not answer` names the refused connection. The mesh names keep answering meanwhile. See [Asking the Resolvers](../reference/networking/mesh-dns.md#asking-the-resolvers).
- A name that fails with `SERVFAIL` while no resolver is reported down got that code from the resolver itself, which plexd relays as it relays every reply. plexd asks the next resolver after a `SERVFAIL` or `REFUSED` and passes the last one on when none answers otherwise.

A resolver behind a bridge is reached through the mesh, so the Domain's network policy has to allow UDP and TCP port 53 from the Node to it. Without that rule the resolver never answers, and plexd logs `mesh dns resolver does not answer` with `error="context deadline exceeded"`. The Node's own policy filters what the Node sends over the mesh as well, so on Linux it drops a UDP query before it leaves: the attempt fails at once, and the `error` ends in `operation not permitted` instead. A resolver the Node reaches outside the mesh needs a route and a firewall that pass port 53 the same way.

A catch-all takes only the names no other link claims: a name under a domain that another link holds, such as a DHCP search domain on `eth0`, still goes to that link. A program that does not resolve through systemd-resolved never asks plexd. See [The Catch-All as Default Route](../reference/networking/mesh-dns.md#the-catch-all-as-default-route).

### A catch-all that does not answer

systemd-resolved does not fall back to another server for the names a catch-all takes, so a catch-all whose resolvers are all down fails every lookup of the host outside the mesh zones and the other links' domains with `SERVFAIL`. The mesh names keep answering, and plexd keeps reaching its control plane: when the control plane's name stops resolving, it dials the address the name last resolved to and logs `control plane name does not resolve, dialing its last address` (see [Dial Fallback](../reference/core/control-plane-client.md#dial-fallback)). To recover:

1. Correct the setting on the control plane: point the catch-all at resolvers that answer, or remove it. The next pull brings the setting within one reconcile interval. New catch-all resolvers take over at once, with no call to systemd-resolved. A removed catch-all makes plexd register the link again, without `~.` and with `-DefaultRoute`.
2. When the Node must resolve other names before that pull, `resolvectl revert plexd0` clears the link by hand. The mesh names and the forward zones then no longer resolve through systemd-resolved either, and plexd does not apply the same registration again: the link stays cleared until the registration changes, as it does when the catch-all is removed, or plexd restarts. New catch-all resolvers leave the registration as it was, so restart plexd after that correction to register the link again.
3. To turn mesh DNS off on the Node altogether, set `dns.enabled: false`, or `PLEXD_DNS_ENABLED=false`, and restart plexd. The start reverts the link, and plexd answers no mesh name and forwards nothing until you turn it on again (see [Stop, Crash and Opt-Out](../reference/networking/mesh-dns.md#stop-crash-and-opt-out)).

After a crash or a kill of plexd with a catch-all, the link keeps `~.` and nothing answers on its server, so every such lookup fails until plexd starts again, which reverts the link.

On macOS the catch-all is plexd's default-resolver entry, and macOS keeps the primary network service's resolver as a second default resolver. Whether macOS ever asks that resolver for a name the catch-all should take, for example after plexd answers `SERVFAIL` for a dead catch-all resolver, was not measured, so a catch-all on macOS does not guarantee that the catch-all resolvers see every name. Steps 1 and 3 hold there: a removed catch-all makes plexd remove its key `plexd-meshdns-default`, and a start with `dns.enabled: false` removes every plexd key. After a crash or a kill, the utun goes with the process, but the keys stay in configd's dynamic store until the next start of plexd removes them or a reboot clears them, and every name the default entry takes fails meanwhile. To remove them by hand without starting plexd, run `sudo scutil` with `open`, a `remove <key>` line for each key the list command above names, and `quit`. See [Registration on macOS](../reference/networking/mesh-dns.md#registration-on-macos).

On Windows the catch-all is plexd's rule for `.`, and it is exclusive: it takes every name that no more specific rule of the Name Resolution Policy Table matches, the host's DHCP suffixes and the names of its Active Directory domain included. A host in an Active Directory domain therefore resolves its domain's names only when the catch-all resolvers answer them, or a forward zone covers the domain. `.local` stays with multicast DNS, because plexd writes an exemption rule for it. Steps 1 and 3 hold there: a removed catch-all makes plexd delete its keys `plexd-meshdns-default` and `plexd-meshdns-exempt-local`, and a start with `dns.enabled: false` deletes every plexd key. Step 2 does not hold for long: a key deleted by hand comes back at the next machine policy change, when plexd's Group Policy watcher writes the rules again. After a crash or a kill, the adapter goes with the process, but the rules stay in the registry until the next start of plexd removes them or a reboot clears them, because the keys are volatile, and every name fails meanwhile. To remove them by hand without starting plexd, run `reg delete "HKLM\<store path>\<key>" /f` from an elevated shell for each plexd key the `reg query` commands above list, then `ipconfig /flushdns`. See [The Catch-All on Windows](../reference/networking/mesh-dns.md#the-catch-all-on-windows).

## Hook execution fails with integrity violation

```bash
plexd hooks verify    # Check all hook checksums
plexd logs            # Look for integrity_violation events
```

A checksum mismatch means the hook script changed after plexd pinned its digest. For a hand-placed hook in `hooks_dir`, plexd pins the digest the first time a plexd process discovers the hook. `plexd hooks reload` does not clear the mismatch: a reload re-scans the directory and reports what it finds, and it moves no pin. An edited hook runs again after an agent restart, not after a reload. The control plane holds a baseline of its own, the first digest it received for the hook, so an edit also raises an integrity alert there and dispatch stays refused until it accepts the new digest. See [What an Edit Does](../how-to/custom-hook-scripts.md#what-an-edit-does). A hook the control plane rolled out is pinned to the checksum the control plane delivered instead, so a restart does not clear its mismatch; see [Hand-placed and Rolled-out Hooks](../how-to/custom-hook-scripts.md#hand-placed-and-rolled-out-hooks). If the mismatch is unexpected, investigate whether the file was modified by an unauthorized process.

::: warning
An unexpected checksum mismatch could indicate that a hook script was modified by an unauthorized process. Investigate before you restart the agent, because a restart pins whatever bytes are on disk at that moment.
:::

## SSE stream keeps disconnecting

```bash
plexd status          # Check SSE connection state and reconnect count
plexd log-status      # Check if log forwarding is buffering (indicates connectivity issues)
```

Frequent SSE disconnections are typically caused by network instability, an overloaded proxy between the node and the control plane, or TLS inspection appliances that terminate long-lived connections. Check for HTTP proxies or firewalls with idle timeout settings shorter than the heartbeat interval (30s). plexd reconnects automatically with exponential backoff.

::: tip
If you are behind a corporate proxy or firewall, ensure that idle timeout settings are longer than the 30-second heartbeat interval.
:::

## Node marked as unreachable but is running

```bash
plexd status   # Verify heartbeat is being sent
plexd logs | grep heartbeat
```

If plexd is running but the control plane shows the node as `unreachable`, the heartbeat POST may be failing. Common causes: DNS resolution failure for the control plane API, expired TLS certificate on an intermediate proxy, or network partition. Check that `PLEXD_API` is reachable with `curl -s -o /dev/null -w "%{http_code}" $PLEXD_API/health`. A control plane that predates the heartbeat's `features` member refuses every heartbeat that carries it; see [Every heartbeat refused after an agent upgrade](#every-heartbeat-refused-after-an-agent-upgrade).
