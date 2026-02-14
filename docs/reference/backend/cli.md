---
title: CLI Reference
quadrant: backend
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

**Lifecycle:**

1. Parse config and apply CLI flag overrides
2. Register (or load existing identity) with control plane
3. Create Ed25519 verifier from signing public key
4. Start SSE manager with signing key rotation handler
5. Start heartbeat service (30s default interval)
6. Start reconciler (60s default interval)
7. Start local node API server on Unix socket
8. Wait for SIGTERM/SIGINT, then graceful drain (30s timeout)

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

Deregister this node from the control plane.

```
plexd deregister [--purge]
```

| Flag      | Default | Description                                             |
|-----------|---------|---------------------------------------------------------|
| `--purge` | `false` | Remove data_dir, token file, and disable systemd unit   |

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

The default configuration file location is `/etc/plexd/config.yaml`. See `internal/agent/config.go` for the full `AgentConfig` schema and subsystem sections.
