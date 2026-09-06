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

## No peers connected

```bash
plexd peers           # List peer status
plexd status          # Check NAT traversal state
```

Common causes: firewall blocking UDP traffic, STUN servers unreachable, or the node has not yet received its peer list from the control plane.

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
