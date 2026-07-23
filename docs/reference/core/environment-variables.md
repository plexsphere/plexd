---
title: Environment Variables Reference
package: cmd/plexd
feature: PXD-0025
---

# Environment Variables Reference

plexd supports environment variable overrides for configuration. Variables are applied at different stages during startup and follow a strict precedence order.

## Global Variables (all commands)

These variables are read via `envOrDefault()` in `cmd/plexd/cmd/root.go` and apply to all plexd commands.

| Variable | Default | Description |
|----------|---------|-------------|
| `PLEXD_CONFIG` | `/etc/plexd/config.yaml` | Path to the configuration file. Equivalent to `--config`. |
| `PLEXD_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error`. Equivalent to `--log-level`. |
| `PLEXD_API` | — | Control plane API URL. Equivalent to `--api`. |
| `PLEXD_MODE` | — | Operating mode: `node` or `bridge`. Equivalent to `--mode`. |
| `PLEXD_PROJECT_ID` | — | Platform project UUID for registration. Overrides `registration.project_id`. Equivalent to `--project-id`. |
| `PLEXD_RESOURCE_HANDLE` | — | Platform resource handle for registration. Overrides `registration.resource_handle`. Equivalent to `--resource-handle`. |
| `PLEXD_REQUESTED_RESOURCE_ID` | — | Resource ID override for registration. Overrides `registration.requested_resource_id`. Equivalent to `--requested-resource-id`. |

## plexd up Variables

These variables are read by `applyEnvOverrides()` in `cmd/plexd/cmd/up.go` and only apply to the `plexd up` command. They override YAML config values but are themselves overridden by CLI flags.

| Variable | Config field | Description |
|----------|-------------|-------------|
| `PLEXD_BOOTSTRAP_TOKEN_FILE` | `registration.token_file` | Path to the bootstrap token file |
| `PLEXD_ACTIONS_ENABLED` | `actions.enabled` | Enable/disable action execution. Values: `true`, `1` to enable; anything else to disable. |
| `PLEXD_HOOKS_ENABLED` | `integrity.watch_enabled` | Enable/disable inotify hook watching. Values: `true`, `1` to enable. |
| `PLEXD_HOOKS_DIR` | `actions.hooks_dir`, `integrity.hooks_dir` | Directory for hook scripts. Sets both `actions.hooks_dir` and `integrity.hooks_dir`. |
| `PLEXD_ACTIONS_MAX_CONCURRENT` | `actions.max_concurrent` | Maximum number of concurrent actions (integer) |
| `PLEXD_NODE_API_SOCKET` | `node_api.socket_path` | Path to the Unix domain socket |
| `PLEXD_NODE_API_HTTP_ENABLED` | `node_api.http_enabled` | Enable/disable the HTTP listener. Values: `true`, `1` to enable. |
| `PLEXD_NODE_API_HTTP_LISTEN` | `node_api.http_listen` | HTTP listen address, e.g. `127.0.0.1:9100` |

## Bootstrap Token Variable

| Variable | Config field | Description |
|----------|-------------|-------------|
| `PLEXD_BOOTSTRAP_TOKEN` | `registration.token_env` | The bootstrap token value. Read by the registration subsystem at runtime via the environment variable name configured in `registration.token_env` (default: `PLEXD_BOOTSTRAP_TOKEN`). |

This variable is not processed by `applyEnvOverrides()`. Instead, the registration subsystem reads it directly using `os.Getenv(config.TokenEnv)`.

## Precedence Order

From highest to lowest priority:

1. **CLI flags** — `--api`, `--mode`, `--log-level` (applied in `runUp` before `applyEnvOverrides`)
2. **`applyEnvOverrides()`** — `PLEXD_BOOTSTRAP_TOKEN_FILE`, `PLEXD_ACTIONS_ENABLED`, etc.
3. **Global env vars** — `PLEXD_CONFIG`, `PLEXD_LOG_LEVEL`, `PLEXD_API`, `PLEXD_MODE` (via `envOrDefault` in flag defaults)
4. **YAML config file** — values from `/etc/plexd/config.yaml` (or `--config` path)
5. **`ApplyDefaults()`** — built-in defaults for zero-valued fields

## Examples

**Override the bootstrap token file:**

```bash
PLEXD_BOOTSTRAP_TOKEN_FILE=/run/secrets/plexd-token plexd up
```

**Disable actions via environment:**

```bash
PLEXD_ACTIONS_ENABLED=false plexd up
```

**Enable HTTP node API on a custom address:**

```bash
PLEXD_NODE_API_HTTP_ENABLED=true PLEXD_NODE_API_HTTP_LISTEN=0.0.0.0:9200 plexd up
```

**Set log level and API URL globally:**

```bash
PLEXD_LOG_LEVEL=debug PLEXD_API=https://api.example.com plexd up
```

## Session Token Variable

| Variable | Description |
|----------|-------------|
| `PLEXD_SESSION_TOKEN` | JWT token injected by plexd into SSH sessions for action authorization. This token is set automatically when an SSH session is established via the access proxy. It is used by `plexd actions run` to authenticate and authorize action execution within the session. The JWT is signed with the control plane's Ed25519 key and contains claims for `sub` (user ID), `node_id`, `session_id`, `actions` (scoped action list), and `exp` (expiration). plexd validates this token locally without a control plane roundtrip. |

## See Also

- [Configuration Reference](configuration.md) — Full YAML configuration schema
- [CLI Reference](cli.md) — Command-line flags and commands
