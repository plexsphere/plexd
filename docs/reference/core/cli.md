---
title: CLI Reference
package: cmd/plexd
feature: PXD-0025
---

# CLI Reference

The `plexd` binary is a single static executable providing node agent lifecycle management, local state queries, and administrative operations.

## Global Flags

| Flag          | Default                     | Description                                |
|---------------|-----------------------------|--------------------------------------------|
| `--config`    | `/etc/plexd/config.yaml`    | Path to the configuration file             |
| `--log-level` | `info`                      | Log level: `debug`, `info`, `warn`, `error`|
| `--api`       | —                           | Control plane API URL (overrides config)   |
| `--mode`      | —                           | Operating mode: `node` or `bridge`         |
| `--project-id` | —                          | Platform project UUID for registration (env `PLEXD_PROJECT_ID`; overrides config) |
| `--resource-handle` | —                     | Platform resource handle for registration (env `PLEXD_RESOURCE_HANDLE`; overrides config) |
| `--requested-resource-id` | —               | Resource ID override when substrate naming differs (env `PLEXD_REQUESTED_RESOURCE_ID`; overrides config) |
| `--version`   | —                           | Print version, commit hash, and build date |

## Build-Time Variables

The binary embeds version metadata via ldflags:

```
-ldflags "-X main.version=1.2.3 -X main.commit=abc123 -X main.date=2025-01-01"
```

## Commands

### `plexd up`

Start the agent daemon. Registers with the control plane, connects to the SSE event stream, starts the heartbeat service, reconciler, and local node API server.

```
plexd up [--config /path/to/config.yaml] [--log-level debug]
```

**Initialization:**

1. Parse config, apply CLI flag overrides, apply `PLEXD_*` env overrides
2. Set up structured logger
3. Create control plane client
4. Register (or load existing identity) — fatal on failure
5. Create Ed25519 verifier from the control plane's signing public key
5a. Initialize WireGuard — create interface, configure address, bring up
5b. Initialize NAT traversal and peer exchange
5c. Initialize network policy engine and enforcer
5d. Initialize tunnel mesh server with JWT verifier
5e. Initialize bridge subsystem (bridge mode only — ACME, ingress, user access, site-to-site)
6. Create SSE manager with handlers for signing keys, WireGuard peers, tunnel, policy, and bridge events
7. Create reconciler with handlers for WireGuard, policy, and bridge reconciliation
8. Create heartbeat service with subsystem status enrichment, auth-failure, and key-rotation callbacks
9. Create integrity store + verifier
10. Create action executor, register 11 built-in actions, register the action dispatcher on the reconciler, report capabilities
11. Create hook watcher
12. Create node API server, wire reconcile handler
13. Create metrics collectors + manager
14. Create log sources + forwarder
15. Create audit sources + forwarder

**Goroutines (10 node mode, 11 bridge mode):** SSE, Heartbeat, Reconciler, Node API, Hook Watcher, Metrics, Log Forwarder, Audit Forwarder, Peer Exchange, Mesh Server, Bridge Relay (bridge mode only).

**Shutdown:** On SIGTERM/SIGINT — cancel context, `sseMgr.Shutdown()`, `executor.Shutdown()`, mesh server shutdown, bridge teardowns (bridge mode), policy enforcer teardown, WireGuard teardown, wait for goroutines with 30s drain timeout.

For the full startup and shutdown sequence, see [Architecture and Concepts](../../concepts.md).

**Exit codes:** 0 on clean shutdown, 1 on error.

### `plexd join`

Register this node with the control plane and exit. Does not start the agent daemon.

```
plexd join [--token-file /path/to/token]
```

| Flag           | Default | Description                      |
|----------------|---------|----------------------------------|
| `--token-file` | —       | Path to bootstrap token file     |

**Output:** Prints `node_id` and `mesh_ip` to stdout.

**Exit codes:** 0 on success, 1 on error.

### `plexd install`

Install plexd as a systemd service. Requires root privileges.

```
plexd install [--api-url https://api.example.com] [--token TOKEN] [--token-file /path]
```

| Flag           | Default | Description                      |
|----------------|---------|----------------------------------|
| `--api-url`    | —       | Control plane API URL            |
| `--token`      | —       | Bootstrap token value            |
| `--token-file` | —       | Path to bootstrap token file     |

**Exit codes:** 0 on success, 1 on error.

### `plexd uninstall`

Remove the plexd systemd service. Requires root privileges.

```
plexd uninstall [--purge]
```

| Flag      | Default | Description                               |
|-----------|---------|-------------------------------------------|
| `--purge` | `false` | Also remove data and config directories   |

**Exit codes:** 0 on success, 1 on error.

### `plexd deregister`

Remove this node's local identity. This is a **local-only** cleanup: it makes no
request to the control plane. Removing the node from the control plane is
operator-driven and is done on the platform.

```
plexd deregister [--purge]
```

| Flag      | Default | Description                                                      |
|-----------|---------|------------------------------------------------------------------|
| `--purge` | `false` | Also remove `data_dir` and the registration token file          |

Plain `plexd deregister` removes `identity.json` from `data_dir` and prints:

```
local identity removed (/var/lib/plexd/identity.json)
node removal from the control plane is operator-driven on the platform
```

The command is idempotent: when no `identity.json` exists in the configured
`data_dir` it prints `no local identity found (nothing to do)` and exits `0`.
If the identity file exists but cannot be removed, it fails with
`plexd deregister: remove identity: <error>` and a non-zero exit.

With `--purge`, the command additionally removes the entire `data_dir` (all
identity and key files, cached state) and the registration token file, then
prints `local data purged`. `--purge` does **not** disable any systemd unit; use
[`plexd uninstall`](#plexd-uninstall) to remove the service.

`--purge` requires a config file: when none exists at the `--config` path it
fails with `plexd deregister: --purge needs a config file: ...` and removes
nothing. Without a file `data_dir` would be the built-in `/var/lib/plexd`, so a
mistyped `--config` would wipe an unrelated directory while leaving the node's
real key material — still valid against the control plane — in place.

Passing `--config` explicitly asserts that the file is there. When it is not,
the command fails with `plexd deregister: no config file at ...` and touches
nothing, because `data_dir` would silently fall back to `/var/lib/plexd`: a
mistyped path would otherwise remove an unrelated `identity.json` and report a
decommission, or report `nothing to do` for a node whose real identity is
elsewhere on disk. Without the flag the default path is the file-less
deployment, which stays idempotent and names the `data_dir` it used in the
warning it logs.

**Exit codes:** 0 on success, 1 on error.

### `plexd status`

Show node agent status by querying the local agent via Unix socket (`/var/run/plexd/api.sock`).

```
plexd status
```

Displays metadata entry count, data key count, secret key count, and report key count. If the agent is not running, prints an error.

### `plexd peers`

List mesh peers from the local agent.

```
plexd peers
```

### `plexd policies`

List network policies from the local agent.

```
plexd policies
```

### `plexd state`

Show a JSON summary of the local agent state.

```
plexd state
```

#### `plexd state get <type> <key>`

Fetch a specific state entry. Type must be `metadata`, `data`, or `report`.

```
plexd state get metadata node_id
plexd state get data config.yaml
plexd state get report health
```

**Exit codes:** 0 on success, 1 if not found or agent not running.

#### `plexd state report <key> --data <json>`

Write a report entry via the local agent.

```
plexd state report health --data '{"status":"ok"}'
```

| Flag     | Required | Description                           |
|----------|----------|---------------------------------------|
| `--data` | yes      | JSON payload for the report entry     |

### `plexd logs`

Stream agent logs from journald.

```
plexd logs [--follow]
```

| Flag       | Default | Description           |
|------------|---------|-----------------------|
| `-f`/`--follow` | `false` | Follow log output |

Falls back to a helpful message if journalctl is not available.

### `plexd log-status`

Show log forwarding configuration status.

```
plexd log-status
```

### `plexd audit`

Show audit log collection status.

```
plexd audit
```

### `plexd actions`

List available actions.

```
plexd actions
```

#### `plexd actions run <name>`

Dispatch an action to the local agent.

```
plexd actions run restart-service --param name=nginx --param force=true
```

| Flag      | Default | Description                         |
|-----------|---------|-------------------------------------|
| `--param` | —       | Action parameter in `key=value` format (repeatable) |

**Built-in actions:**

| Name | Description | Parameters |
|------|-------------|------------|
| `diagnostics.collect` | Collect system diagnostics (CPU, memory, disk, network) | `include_network`, `include_processes` |
| `diagnostics.ping_peer` | Ping a mesh peer and report latency | `peer_id` (required), `count` |
| `diagnostics.traceroute_peer` | Traceroute to a mesh peer | `peer_id` (required), `max_hops` |
| `service.restart` | Restart plexd via systemctl | — |
| `service.reload_config` | Send SIGHUP to reload config (Unix only; fails on Windows) | — |
| `service.upgrade` | Download a release binary, verify its checksum and Sigstore bundle, then swap and restart | `version` (required), `checksum` (required) |
| `system.info` | Report OS, kernel, hardware, and runtime info | — |
| `health.check` | Run all health checks and report status | `include_peers` |
| `mesh.reconnect` | Tear down and re-establish all mesh tunnels | — |
| `config.dump` | Return current effective configuration (secrets redacted) | — |
| `logs.snapshot` | Capture recent logs from ring buffer | `lines`, `since` |

### `plexd hooks`

Manage action hooks.

#### `plexd hooks list`

List all registered action hooks.

#### `plexd hooks verify`

Run integrity verification on all registered hooks.

#### `plexd hooks reload`

Trigger a re-scan of action hooks.

## Unix Socket Communication

Commands that query local agent state (`status`, `peers`, `policies`, `state`, `log-status`, `audit`, `actions`, `hooks`) connect to the agent via HTTP-over-Unix-socket at `/var/run/plexd/api.sock`. If the agent is not running, these commands return an error indicating the socket is unavailable.

## Configuration File

The default configuration file is `/etc/plexd/config.yaml`. For the full YAML schema, see [Configuration Reference](configuration.md). For environment variable overrides, see [Environment Variables](environment-variables.md).
