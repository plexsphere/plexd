---
title: Environment Variables Reference
package: cmd/plexd
feature: PXD-0025
---

# Environment Variables Reference

plexd supports environment variable overrides for configuration. Variables are applied at different stages during startup and follow a strict precedence order. A config file is not required — flags and environment variables alone can run plexd, with defaults filling every field neither supplies (see [Running without a config file](configuration.md#running-without-a-config-file)).

## Global Variables (all commands)

These variables are read via `envOrDefault()` in `cmd/plexd/cmd/root.go` and apply to all plexd commands.

| Variable | Default | Description |
|----------|---------|-------------|
| `PLEXD_CONFIG` | `/etc/plexd/config.yaml` (Linux) | Path to the configuration file. Equivalent to `--config`. Per platform; see [Platform defaults](configuration.md#platform-defaults). |
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
| `PLEXD_ACTIONS_ENABLED` | `actions.enabled` | Enable/disable action execution. Parsed with Go's `strconv.ParseBool`: `1`, `t`, `T`, `true`, `TRUE`, `True` enable; `0`, `f`, `F`, `false`, `FALSE`, `False` disable. Any other value is ignored with a warning and leaves `actions.enabled` as the file or the default set it. Required to enable it on the file-less path, where `actions.enabled` defaults to `false`. |
| `PLEXD_HOOKS_ENABLED` | `integrity.watch_enabled` | Enable/disable inotify hook watching. Values: `true`, `1` to enable. |
| `PLEXD_HOOKS_DIR` | `actions.hooks_dir`, `integrity.hooks_dir` | Directory for hook scripts. Sets both `actions.hooks_dir` and `integrity.hooks_dir`. |
| `PLEXD_ACTIONS_MAX_CONCURRENT` | `actions.max_concurrent` | Maximum number of concurrent actions (integer) |
| `PLEXD_NODE_API_SOCKET` | `node_api.socket_path` | Path to the Unix domain socket |
| `PLEXD_NODE_API_HTTP_ENABLED` | `node_api.http_enabled` | Enable/disable the HTTP listener. Values: `true`, `1` to enable. |
| `PLEXD_NODE_API_HTTP_LISTEN` | `node_api.http_listen` | HTTP listen address, e.g. `127.0.0.1:9100` |
| `PLEXD_POLICY_ENABLED` | `policy.enabled` | Enable/disable network policy enforcement. Parsed with `strconv.ParseBool`, like `PLEXD_ACTIONS_ENABLED`; any other value is ignored with a warning and leaves `policy.enabled` as the file or the default set it. Setting it to `false` is how a container without `CAP_NET_ADMIN` gets past the firewall pre-flight without mounting a config file. |
| `PLEXD_HEALTH_ENABLED` | `health.enabled` | Enable/disable the health listener. Parsed with `strconv.ParseBool`; an unparseable value is ignored with a warning. Turning the listener off leaves the probe target unbound — remove the probes as well, or the kubelet restarts the container in a loop. |
| `PLEXD_HEALTH_LISTEN` | `health.listen` | Health listen address, e.g. `0.0.0.0:9101`. Applied verbatim: an address that cannot be bound fails at startup with the bind error, not a config-validation error. Needed by a Pod-network deployment, where the kubelet dials the Pod IP and the `127.0.0.1:9101` default answers nothing. The endpoints are unauthenticated, so widening the bind is a deliberate choice — see [health](configuration.md#health). |

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
4. **YAML config file** — values from `/etc/plexd/config.yaml` on Linux (or the `--config` path; see [Platform defaults](configuration.md#platform-defaults))
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

**Run without a config file on a restricted Pod-network deployment:**

```bash
PLEXD_API=https://api.example.com \
PLEXD_PROJECT_ID=... PLEXD_RESOURCE_HANDLE=... \
PLEXD_POLICY_ENABLED=false \
PLEXD_HEALTH_LISTEN=0.0.0.0:9101 \
plexd up
```

Without `PLEXD_POLICY_ENABLED=false` this pod aborts on the firewall pre-flight, because it holds no `CAP_NET_ADMIN`; without `PLEXD_HEALTH_LISTEN` its liveness probe never reaches the loopback-bound listener. Neither default changes — this run opts out of both explicitly.

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
