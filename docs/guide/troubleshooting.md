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

If pings and WireGuard handshakes pass but TCP connections over the mesh stall, the uplink may carry less than the mesh MTU plus WireGuard's 80 bytes of encapsulation. Small packets get through and full-size ones are lost without an error, so a connection hangs at its first full-size segment. SSH, for example, hangs in key exchange. A DS-Lite uplink over PPPoE carries 1452-byte packets, which fit a mesh MTU of at most 1372.

plexd sizes the interface to the uplink when it starts, and measures again every 10 minutes. The `wireguard interface configured` line shows what it chose:

```text
level=INFO msg="wireguard interface configured" component=wireguard interface=plexd0 listen_port=51820 mesh_ip=10.99.0.5 mtu=1372 mtu_source=probe path_mtu=1452
```

- `mtu` is the MTU the interface came up with, and `path_mtu` the largest IPv4 packet the probe got through to a STUN server.
- `mtu_source=probe` means the probe measured the uplink, and `config` that `wireguard.mtu` pins the MTU. `default` means the interface came up at 1420 unmeasured: either detection is off, which logs `mesh mtu detection disabled by nat.enabled`, or no STUN server answered, which logs `wireguard: mtu probe inconclusive, using the default mtu` with the error.
- A later change logs `wireguard: mesh mtu lowered` or `wireguard: mesh mtu raised` with `old_mtu`, `mtu` and `path_mtu`. A round without an answer logs `wireguard: mtu probe inconclusive, keeping the current mtu`, and an uplink too small even for the 1280-byte floor logs `wireguard: uplink carries less than the mesh minimum mtu`.

The probe measures only the outbound IPv4 path to the STUN servers. It cannot see a bottleneck on a path to a peer that the STUN traffic does not cross, and it gets no answer where UDP to the STUN servers is blocked. In those cases set `wireguard.mtu` to the path MTU minus 80, for example `1372` for a 1452-byte path, and restart plexd. A positive value pins the MTU and turns detection off. See [MTU detection](../reference/networking/wireguard.md#mtu-detection).

## A mesh name does not resolve

```bash
resolvectl status plexd0                      # The link's server, domains and default-route flag
resolvectl query db-1.openstack.lab.internal  # Ask systemd-resolved directly
resolvectl query --type=SRV _postgres._tcp.openstack.lab.internal  # A record of another type
resolvectl query host.corp.example.com        # A name under a forward zone
plexd logs | grep -E 'mesh dns|component=meshdns|dns block|PLEXD_DNS_ENABLED|control plane name'  # The resolver's log lines
```

On Linux, plexd answers the mesh names of its Domain on the Node's own mesh IP, port 5354 by default, and registers the Domain's zones with systemd-resolved on the mesh interface (`wireguard.interface_name`, `plexd0` by default). `resolvectl status plexd0` should list the server `<mesh IP>:5354`, the search domain, each routing domain with a leading `~` (every other zone that no zone above it covers, every reverse zone, and every forward zone of the Node's forwarding setting), and `-DefaultRoute`. With a catch-all it shows `+DefaultRoute` instead, and the domains end in `~.`. A link without that server has no registration. `resolvectl query` names the link an answer came from, so a mesh name answered through the mesh interface shows `plexd0`. A bare host name resolves through the search domain, and a mesh IP resolves to its name when the Domain's reverse zones cover it.

plexd also answers the records the Domain and its Projects define. `resolvectl query` asks for addresses unless `--type` names another type, such as `--type=SRV`, `--type=MX` or `--type=TXT`. With `--type` it prints each record as `<name> IN <type> <data>`, followed by `-- link: plexd0`. A name that exists without a record of the type prints `does not have any RR of the requested type`. A CNAME whose target lies outside the mesh zones is answered as the CNAME alone, for the system resolver to follow. systemd-resolved follows it through its other servers, so `resolvectl query` shows the address without the link `plexd0`, and the target in parentheses. See [Answer Table](../reference/networking/mesh-dns.md#answer-table).

The log lines say why a name is missing:

- No `mesh dns listening` line means the resolver did not start. `mesh dns disabled by dns.enabled` means `dns.enabled` is `false`. `wireguard unavailable, mesh dns not started` means the WireGuard interface did not come up. After a crash or a kill, the setup fails on the `plexd0` the killed run left behind, and the stop of this run deletes it, so restart plexd once more. `mesh dns not started, the mesh ip does not parse` means the mesh IP that registration assigned is not an IP address; its `mesh_ip` key shows it. `mesh dns listener cannot bind, mesh names are not answered` means another program holds the port; set `dns.listen_port` to a free one and restart plexd. macOS and Windows run no resolver and log none of these.
- `mesh dns not registered, systemd-resolved is not usable` means the host has no systemd-resolved, one older than 246, or no reachable system bus. Its `reason` says which. A stopped systemd-resolved counts as none, because plexd does not start it. The resolver still answers on the `listen` address; see [Hosts without systemd-resolved](../reference/networking/mesh-dns.md#hosts-without-systemd-resolved).
- `mesh dns registration failed` carries the error systemd-resolved returned. `org.freedesktop.resolve1.LinkBusy` means systemd-networkd manages the link, which then cannot take settings over D-Bus. plexd tries again on every pull.
- `state pull carries no dns block, keeping the names held` means the control plane sent no names. A control plane that predates the block never sends one.
- `mesh dns skipped invalid entries` names the entries of the block plexd refused, up to five. A skipped record reads `record "<fqdn>" of type "<type>" <reason>`, and the other names and records keep answering. See [Records](../reference/networking/mesh-dns.md#records) for the checks. A skipped forward zone reads `forward zone "<zone>" <reason>` and a skipped resolver `resolver "<value>" of <owner> <reason>`, after the sentences of the records. A forward zone that a mesh zone shadows is skipped, because the mesh zone answers its names. See [Forward Zones and Resolvers](../reference/networking/mesh-dns.md#forward-zones-and-resolvers).

A program resolves through systemd-resolved only when `/etc/resolv.conf` or `nsswitch.conf` sends it there: `/etc/resolv.conf` names the stub listener `127.0.0.53`, or the `hosts` line of `/etc/nsswitch.conf` lists `resolve`. `resolvectl query` always asks systemd-resolved, so a name that `resolvectl query` answers and a program does not points at the program's resolver configuration. On the Node itself, `dig @<mesh IP> -p 5354 <name>` asks plexd's resolver directly. A query from any other address gets no answer, so the same command run in a container or Pod network fails by design.

systemd-resolved caches every answer for its TTL of 10 seconds, so a renamed host answers under its new name at most 10 seconds after the pull that carried the change. See [Mesh DNS](../reference/networking/mesh-dns.md).

### A forwarded name does not resolve

A name under a forward zone, or with a catch-all any name no other link's domain matches, goes from systemd-resolved to plexd, and plexd passes it on to the resolvers of the Node's forwarding setting on port 53. `resolvectl query` names the link `plexd0` for such an answer. The log lines say where it stops:

- `mesh dns forwarding updated` with `forward_zones` and `catch_all` shows how many forward zones and catch-all resolvers plexd accepted. No such line, or zero counts, means the Node forwards nothing: the Node's Domain or Project holds no forwarding setting, or the control plane does not send the `forwarding` member. `dns block carries no forwarding member, keeping the forwarding held` means the control plane sent a block without the member, and plexd forwards as before.
- `mesh dns resolver does not answer` names the `resolver` and the `zone` (`.` for the catch-all) of a resolver that sent no reply in time or refused the connection, with the `error`. plexd asks it after the other resolvers of its zone for 30 seconds. `mesh dns resolver answers again` says it came back. A query that no resolver answers gets `SERVFAIL`, and with `PLEXD_LOG_LEVEL=debug` logs `mesh dns forwarded query failed`. systemd-resolved asks three times before a lookup fails, `resolvectl query` included. Resolvers that send nothing back make plexd wait its 4 seconds each time, so such a lookup fails with `SERVFAIL` only after about 12 seconds. Resolvers that refuse the query, with an ICMP port unreachable or a TCP reset, make plexd answer `SERVFAIL` at once, so the lookup fails at once too, and the `error` of `mesh dns resolver does not answer` names the refused connection. The mesh names keep answering meanwhile. See [Asking the Resolvers](../reference/networking/mesh-dns.md#asking-the-resolvers).
- A name that fails with `SERVFAIL` while no resolver is reported down got that code from the resolver itself, which plexd relays as it relays every reply. plexd asks the next resolver after a `SERVFAIL` or `REFUSED` and passes the last one on when none answers otherwise.

A resolver behind a bridge is reached through the mesh, so the Domain's network policy has to allow UDP and TCP port 53 from the Node to it. Without that rule the resolver never answers, and plexd logs `mesh dns resolver does not answer` with `error="context deadline exceeded"`. A resolver the Node reaches outside the mesh needs a route and a firewall that pass port 53 the same way.

A catch-all takes only the names no other link claims: a name under a domain that another link holds, such as a DHCP search domain on `eth0`, still goes to that link. A program that does not resolve through systemd-resolved never asks plexd. See [The Catch-All as Default Route](../reference/networking/mesh-dns.md#the-catch-all-as-default-route).

### A catch-all that does not answer

systemd-resolved does not fall back to another server for the names a catch-all takes, so a catch-all whose resolvers are all down fails every lookup of the host outside the mesh zones and the other links' domains with `SERVFAIL`. The mesh names keep answering, and plexd keeps reaching its control plane: when the control plane's name stops resolving, it dials the address the name last resolved to and logs `control plane name does not resolve, dialing its last address` (see [Dial Fallback](../reference/core/control-plane-client.md#dial-fallback)). To recover:

1. Correct the setting on the control plane: point the catch-all at resolvers that answer, or remove it. The next pull brings the setting within one reconcile interval. New catch-all resolvers take over at once, with no call to systemd-resolved. A removed catch-all makes plexd register the link again, without `~.` and with `-DefaultRoute`.
2. When the Node must resolve other names before that pull, `resolvectl revert plexd0` clears the link by hand. The mesh names and the forward zones then no longer resolve through systemd-resolved either, and plexd does not apply the same registration again: the link stays cleared until the registration changes, as it does when the catch-all is removed, or plexd restarts. New catch-all resolvers leave the registration as it was, so restart plexd after that correction to register the link again.
3. To turn mesh DNS off on the Node altogether, set `dns.enabled: false`, or `PLEXD_DNS_ENABLED=false`, and restart plexd. The start reverts the link, and plexd answers no mesh name and forwards nothing until you turn it on again (see [Stop, Crash and Opt-Out](../reference/networking/mesh-dns.md#stop-crash-and-opt-out)).

After a crash or a kill of plexd with a catch-all, the link keeps `~.` and nothing answers on its server, so every such lookup fails until plexd starts again, which reverts the link.

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

If plexd is running but the control plane shows the node as `unreachable`, the heartbeat POST may be failing. Common causes: DNS resolution failure for the control plane API, expired TLS certificate on an intermediate proxy, or network partition. Check that `PLEXD_API` is reachable with `curl -s -o /dev/null -w "%{http_code}" $PLEXD_API/health`.
