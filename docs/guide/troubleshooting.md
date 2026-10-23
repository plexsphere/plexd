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
```

Network policies may be blocking traffic. Verify that the desired communication is allowed by the policies configured in the control plane.

## Hook execution fails with integrity violation

```bash
plexd hooks verify    # Check all hook checksums
plexd logs            # Look for integrity_violation events
```

A checksum mismatch means the hook script was modified after plexd computed its initial checksum. This can happen if the file was updated manually without reloading hooks. Run `plexd hooks reload` to re-scan and recompute checksums, then retry. If the mismatch is unexpected, investigate whether the file was modified by an unauthorized process.

::: warning
An unexpected checksum mismatch could indicate that a hook script was modified by an unauthorized process. Investigate before simply reloading.
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
