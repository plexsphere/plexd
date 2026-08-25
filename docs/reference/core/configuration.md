---
title: Configuration Reference
package: internal/agent
feature: PXD-0001
---

# Configuration Reference

plexd reads its configuration from a YAML file (default on Linux: `/etc/plexd/config.yaml`, overridable with `--config`; see [Platform defaults](#platform-defaults) for macOS and Windows). The file is optional: when no file exists at that path, plexd continues with an empty configuration — defaults apply, and CLI flags and environment variables supply the rest — and logs a single warn-level message naming the path it did not find, so a mistyped `--config` stays visible. A file that exists but cannot be read, a file that is empty, and a file that is not valid YAML, are startup errors that name the path. An empty file is rejected rather than treated as an absent one: a truncated write or a ConfigMap key that rendered to nothing is a broken configuration, not a decision to run without one.

The configuration a command runs on is assembled in four steps:

1. **Unmarshal** the YAML into an `AgentConfig` struct — or start from an empty struct when the file is absent (`ParseConfig()` in `internal/agent/config.go`)
2. **ApplyDefaults** for every zero-valued field
3. **Merge overrides** — CLI flag values, then the `PLEXD_*` environment overrides
4. **Validate** the merged configuration (returns the first error encountered)

Because validation runs on the merged result, a required value may come from any layer: `plexd up --api https://api.example.com` starts with no config file at all, and with a file that omits `api.base_url`.

**Precedence order** (highest to lowest):

1. CLI flags (`--api`, `--mode`, `--log-level`)
2. `applyEnvOverrides()` — `PLEXD_*` environment variables (see [Environment Variables](environment-variables.md))
3. Global env vars via `envOrDefault()` (`PLEXD_CONFIG`, `PLEXD_LOG_LEVEL`, `PLEXD_API`, `PLEXD_MODE`)
4. Values in the YAML config file
5. `ApplyDefaults()` for zero-valued fields

## Running without a config file

plexd can run entirely from flags and environment variables. For a fresh registration the file-less minimum is `PLEXD_API`, `PLEXD_PROJECT_ID`, `PLEXD_RESOURCE_HANDLE`, and `PLEXD_BOOTSTRAP_TOKEN` — or the equivalent `--api`, `--project-id`, and `--resource-handle` flags plus the token. Every other field falls back to its default.

Fields that have no flag or environment override remain reachable only through the file, which stays the primary configuration surface for host installs.

One default is inverted on this path: `actions.enabled` comes up `false` without a config file, where a file that omits the `actions` block leaves it `true`. `actions.enabled` is the only switch that stops the control plane from executing actions and hooks on the node, so a file that has gone missing — a deleted ConfigMap, a mistyped `--config`, a broken mount — must not silently enable it. A deliberately file-less deployment that wants action execution sets `PLEXD_ACTIONS_ENABLED=true`.

> For the full list of overrides, see [Environment Variables](environment-variables.md).

---

## Platform defaults

plexd resolves its configuration, data and runtime directories from the host it runs on. Every value below is a default: `--config`, `PLEXD_CONFIG`, the YAML keys and the `PLEXD_*` overrides replace it, and they take precedence on every platform.

| Path | Linux | macOS | Windows |
|------|-------|-------|---------|
| Configuration file (`--config`, `PLEXD_CONFIG`) | `/etc/plexd/config.yaml` | `/Library/Application Support/plexd/config.yaml` | `%ProgramData%\plexd\config.yaml` |
| `data_dir` | `/var/lib/plexd` | `/Library/Application Support/plexd/data` | `%ProgramData%\plexd\data` |
| `registration.token_file` | `/etc/plexd/bootstrap-token` | `/Library/Application Support/plexd/bootstrap-token` | `%ProgramData%\plexd\bootstrap-token` |
| `actions.hooks_dir` | `/etc/plexd/hooks` | `/Library/Application Support/plexd/hooks` | `%ProgramData%\plexd\hooks` |
| `node_api.socket_path` | `/var/run/plexd/api.sock` | `/var/run/plexd/api.sock` | `%ProgramData%\plexd\run\api.sock` |
| Runtime directory (`plexd install`) | `/var/run/plexd` | `/var/run/plexd` | `%ProgramData%\plexd\run` |
| Binary (`plexd install`) | `/usr/local/bin/plexd` | `/usr/local/bin/plexd` | `%ProgramFiles%\plexd\plexd.exe` |
| Service definition | `/etc/systemd/system/plexd.service` | `/Library/LaunchDaemons/com.plexsphere.plexd.plist` | SCM service `plexd` (no file) |
| Service log | journald | `/Library/Logs/plexd/plexd.log` | Application Event Log, source `plexd` |

`%ProgramData%` is the `ProgramData` environment variable, which Windows sets for every process including services. plexd falls back to `C:\ProgramData` when it is unset or empty. `%ProgramFiles%` is read the same way, with `C:\Program Files` as its fallback.

macOS resolves the system locations only, with no per-user fallback under `~/Library`. The CLI reaches the node API socket without knowing who started the daemon, so a per-user runtime directory would send `plexd status` looking for a socket a root daemon never created. An unprivileged macOS run sets `--config` and `data_dir` itself.

The sections below show the Linux value in their Default column.

---

## Top-Level Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `node` | Operating mode: `node` or `bridge`. Bridge mode enables bridge-specific subsystems when `bridge.enabled: true`. |
| `log_level` | string | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `data_dir` | string | `/var/lib/plexd` (Linux) | Directory for persistent agent data. Propagated to `registration.data_dir` and `node_api.data_dir` at runtime. Per platform; see [Platform defaults](#platform-defaults). |

---

## api

Control plane HTTP client configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `base_url` | string | — (required) | Control plane API base URL, e.g. `https://api.plexsphere.com`. Required in the merged configuration — the value may come from the file, `--api`, or `PLEXD_API`. |
| `tls_insecure_skip_verify` | bool | `false` | Disable TLS certificate verification. **WARNING:** Only for development/testing. |
| `connect_timeout` | duration | `10s` | Maximum time to wait for a TCP connection |
| `request_timeout` | duration | `30s` | Maximum time for a complete HTTP request/response cycle |
| `sse_idle_timeout` | duration | `90s` | Maximum idle time on the SSE stream before reconnecting |
| `sse_reprobe_interval` | duration | `10m` | How often pull-only delivery re-probes the SSE endpoint after the control plane descoped it. Must be at least `1s` when set. |

Source: `internal/api/config.go`

---

## registration

Node registration and bootstrap authentication.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `project_id` | string | — | Platform project UUID to register into. Required for fresh registration (validated at registration time, not config parse). |
| `resource_handle` | string | — | Platform Resource handle to bind to. Required for fresh registration. |
| `requested_resource_id` | string | — | Optional resource ID override used when substrate naming differs from the platform handle. |
| `token_file` | string | `/etc/plexd/bootstrap-token` (Linux) | Path to the bootstrap token file. Per platform; see [Platform defaults](#platform-defaults). |
| `token_env` | string | `PLEXD_BOOTSTRAP_TOKEN` | Environment variable name for the bootstrap token |
| `token_value` | string | — | Direct token value override |
| `use_metadata` | bool | `false` | Enable the cloud metadata service (IMDS) as a fallback source for registration inputs |
| `metadata_token_path` | string | `/plexd/bootstrap-token` | Metadata key path for the bootstrap token (e.g. IMDS) |
| `metadata_timeout` | duration | `2s` | Maximum time to wait for a metadata service response |
| `max_retry_duration` | duration | `5m` | Maximum duration to retry registration |

> `data_dir` is propagated from the top-level `data_dir` at runtime. It does not appear in the YAML.

Source: `internal/registration/config.go`

---

## heartbeat

Periodic heartbeat reporting to the control plane.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interval` | duration | `30s` | Heartbeat send interval |

> `node_id` is set at runtime from the registration identity. It does not appear in the YAML.

Source: `internal/agent/heartbeat.go`

---

## reconcile

State reconciliation loop.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interval` | duration | `60s` | Time between reconciliation cycles. Minimum: `1s`. |

Source: `internal/reconcile/config.go`

---

## node_api

Local node API server (Unix socket and optional HTTP).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `socket_path` | string | `/var/run/plexd/api.sock` (Linux) | Path to the Unix domain socket. Per platform; see [Platform defaults](#platform-defaults). |
| `http_enabled` | bool | `false` | Enable the optional HTTP listener |
| `http_listen` | string | `127.0.0.1:9100` | HTTP listen address |
| `http_token_file` | string | — | Path to the HTTP bearer token file |
| `debounce_period` | duration | `5s` | Debounce period for coalescing events |
| `shutdown_timeout` | duration | `5s` | Maximum time to wait for graceful shutdown |

> `data_dir` is propagated from the top-level `data_dir` by `ApplyDefaults()`; `secret_auth_enabled` is set at runtime by `plexd up`. Neither appears in the YAML.

Source: `internal/nodeapi/config.go`

---

## health

Dedicated listener for the unauthenticated Kubernetes probe endpoints `/healthz` and `/readyz`. It is independent of `node_api`, so a probe never needs a credential.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Run the health listener. `plexd up` starts it before registration begins, so a probe during a slow first registration gets an answer instead of a refused connection. On by default because the shipped DaemonSet probes both endpoints unconditionally: an omitted `health` block would leave the probe target unbound, and the resulting liveness failures restart the container in a loop that tears down the WireGuard interface and the firewall chain every time. Set it to `false` only when nothing probes the node. Also settable as [`PLEXD_HEALTH_ENABLED`](environment-variables.md#plexd-up-variables). |
| `listen` | string | `"127.0.0.1:9101"` | Listen address. The default binds loopback deliberately: the endpoints are unauthenticated, and under `hostNetwork: true` a wildcard bind answers on every node NIC and — once the mesh is up — to every WireGuard peer. The kubelet probes from the host network namespace, which is the namespace plexd listens in, so a probe with `host: 127.0.0.1` reaches a loopback-bound listener. Widening this to `":9101"` is an explicit opt-in; adjust the probes' `host` to match. Also settable as [`PLEXD_HEALTH_LISTEN`](environment-variables.md#plexd-up-variables), which is what a Pod-network deployment running without a config file uses — there the kubelet dials the Pod IP and a loopback-bound listener answers nothing. |

`/healthz` answers `200` for as long as the process serves requests — it reports liveness, not control-plane reachability. `/readyz` answers `200` once all readiness conditions hold; otherwise it answers `503` naming the first unmet one, in the order the agent establishes them:

| Condition | `503` body when unmet |
|-----------|-----------------------|
| The node holds a registered identity | `not ready: registration pending` |
| The WireGuard interface is up and the deny-by-default firewall baseline is installed | `not ready: data plane not configured` |
| The WireGuard interface is still present and up | `not ready: data plane lost` |
| Event delivery to the control plane is working | `not ready: event delivery stopped` or `not ready: event delivery degraded` |
| Every long-running subsystem is still running | `not ready: subsystem stopped` |

WireGuard setup failure is non-fatal — the agent logs a warning and keeps running — so the data-plane condition is what keeps such a node out of rotation instead of letting it report ready without a tunnel. On Kubernetes this also stops a DaemonSet rolling update from marching across the fleet when a kernel or capability regression breaks WireGuard everywhere.

The data plane is re-checked rather than latched at startup, so an interface deleted or brought down hours later takes the node out of rotation — and puts it back once the interface returns, without a restart. A background poller runs the check every 5 seconds and probes read its last verdict; the endpoints are unauthenticated, so running the check per request would let any caller that reaches the port drive one interface-table dump per `GET`. The check covers the interface only: a firewall baseline flushed by another actor on the node stays undetected.

`not ready: subsystem stopped` means a goroutine that should run for the life of the process exited before shutdown — the reconciler or the node API server. Nothing restarts them and `/healthz` stays `200` by design, so readiness is the only signal; the log line names which subsystem, the response body never does.

For the delivery condition, `streaming` and `pull_only` both count as a working path and `degraded_polling` does not. `not ready: event delivery stopped` is separate: it means the SSE goroutine exited for good — a permanent failure or a rejected node secret — which the delivery mode alone cannot express, because the reconnect engine returns without ever transitioning it.

Two consequences are worth knowing before you alert on readiness: the mode only turns to `degraded_polling` after the SSE polling-fallback window (default `5m`), so a node whose stream just broke still reports ready until the window elapses; and a node reports `200` in the short window between its data plane coming up and its first SSE connect. A restart that loads a persisted identity is ready without a fresh registration round-trip.

> For the delivery modes themselves, see [Reading a Node's Event Delivery Mode](../../how-to/delivery-modes.md).

Source: `internal/health/config.go`

---

## actions

Remote action execution and hook management.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable action execution. An omitted key leaves it `true`; an explicit `false` disables execution and survives defaulting. Without a config file it defaults to `false` — see [Running without a config file](#running-without-a-config-file). |
| `hooks_dir` | string | `/etc/plexd/hooks` (Linux) | Directory containing hook scripts. Per platform; see [Platform defaults](#platform-defaults). |
| `max_concurrent` | int | `5` | Maximum number of concurrent actions. Minimum: `1`. |
| `max_action_timeout` | duration | `10m` | Maximum duration for a single action. Minimum: `10s`. |
| `max_output_bytes` | int64 | `1048576` (1 MiB) | Maximum output size per action in bytes. Minimum: `1024`. |

::: warning Upgrading from a release that used the zero-value heuristic
Earlier releases derived `enabled` from the other fields: `ApplyDefaults()` set it to `true` only when `max_concurrent`, `max_action_timeout`, and `max_output_bytes` were all zero. A config file that set any one of them without an `enabled` key therefore ran with action execution **off**.

That heuristic is gone. `enabled` now means what it says, so a file of that shape comes up with action execution **on** after the upgrade, with no config change. If those nodes are meant to stay off, add an explicit `actions.enabled: false` before rolling the binary forward. `plexd up` reports the effective value as `actions_enabled` in its startup log line, and `config.dump` reports it under `actions.enabled`.
:::

Source: `internal/actions/config.go`

---

## upgrade

Release download and Sigstore bundle verification for the `service.upgrade` action.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `release_base_url` | string | `https://github.com/plexsphere/plexd/releases/download` | Base URL of the release download channel. Assets are fetched from `{release_base_url}/{tag}/{asset}`. Air-gapped setups point this at a mirror. |
| `signing_identity_regexp` | string | `^https://github\.com/plexsphere/plexd/\.github/workflows/release\.yml@refs/tags/v.+$` | Regexp the signing certificate's SAN must match. Compiled at validation; a malformed pattern fails with `upgrade: config: compile signing_identity_regexp: ...`. |
| `signing_issuer` | string | `https://token.actions.githubusercontent.com` | Exact OIDC issuer the signing certificate must carry. |
| `trusted_root_path` | string | — (empty) | Path to a Sigstore trusted root JSON file. Empty uses the embedded Sigstore public-good trusted root. |

Source: `internal/upgrade/config.go`

---

## integrity

Binary and hook integrity verification.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable integrity verification. Defaults to `true` when `verify_interval` is zero. |
| `binary_path` | string | — | Path to the plexd binary to verify |
| `hooks_dir` | string | — | Directory containing hook scripts to verify. When empty, mirrors `actions.hooks_dir`. |
| `verify_interval` | duration | `5m` | Interval between integrity verification runs. Minimum: `30s`. |
| `watch_enabled` | bool | `true` | Enable inotify file watching. When enabled, file changes in `hooks_dir` trigger immediate checksum recomputation. |

Source: `internal/integrity/config.go`

---

## metrics

System metrics collection and reporting.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable metrics collection. Defaults to `true` via zero-value heuristic. |
| `collect_interval` | duration | `15s` | Interval between collection cycles. Minimum: `5s`. |
| `report_interval` | duration | `60s` | Interval between reporting to the control plane. Minimum: `10s`. Must be >= `collect_interval`. |
| `batch_size` | int | `100` | Maximum number of metric points per report batch. Minimum: `1`. |
| `local_endpoint.url` | string | — | HTTPS URL for a local metrics endpoint. Must use `https://` scheme. Empty means not configured. |
| `local_endpoint.secret_key` | string | — | Authentication credential for the local endpoint. Required when `url` is set. Redacted in config dumps. |
| `local_endpoint.tls_insecure_skip_verify` | bool | `false` | Disable TLS certificate verification for the local endpoint. |

> For a step-by-step guide to configuring local endpoints, see [Setting Up Local Endpoint Delivery](../../how-to/local-endpoint-setup.md).

Source: `internal/metrics/config.go`

---

## log_fwd

Log collection and forwarding.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable log forwarding. Defaults to `true` via zero-value heuristic. |
| `collect_interval` | duration | `10s` | Interval between collection cycles. Minimum: `5s`. |
| `report_interval` | duration | `30s` | Interval between reporting to the control plane. Must be >= `collect_interval`. |
| `batch_size` | int | `200` | Maximum number of log entries per report batch. Minimum: `1`. |
| `file_patterns` | []string | — | Glob patterns for file-based log collection, e.g. `["/var/log/app/*.log"]` |
| `filter.min_severity` | string | — | Drop log entries below this severity level (syslog severities: `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`) |
| `filter.include_units` | []string | — | Only pass entries matching one of these unit names |
| `filter.exclude_units` | []string | — | Drop entries matching any of these unit names. Takes precedence over `include_units`. |
| `local_endpoint.url` | string | — | HTTPS URL for a local log forwarding endpoint. Must use `https://` scheme. Empty means not configured. |
| `local_endpoint.secret_key` | string | — | Authentication credential for the local endpoint. Required when `url` is set. Redacted in config dumps. |
| `local_endpoint.tls_insecure_skip_verify` | bool | `false` | Disable TLS certificate verification for the local endpoint. |

> For a step-by-step guide to configuring local endpoints, see [Setting Up Local Endpoint Delivery](../../how-to/local-endpoint-setup.md).

Source: `internal/logfwd/config.go`, `internal/logfwd/filter.go`

---

## audit_fwd

Audit event collection and forwarding.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable audit forwarding. Defaults to `true` via zero-value heuristic. |
| `collect_interval` | duration | `5s` | Interval between collection cycles. Minimum: `1s`. |
| `report_interval` | duration | `15s` | Interval between reporting to the control plane. Must be >= `collect_interval`. |
| `batch_size` | int | `500` | Maximum number of audit entries per report batch. Minimum: `1`. |
| `local_endpoint.url` | string | — | HTTPS URL for a local audit forwarding endpoint. Must use `https://` scheme. Empty means not configured. |
| `local_endpoint.secret_key` | string | — | Authentication credential for the local endpoint. Required when `url` is set. Redacted in config dumps. |
| `local_endpoint.tls_insecure_skip_verify` | bool | `false` | Disable TLS certificate verification for the local endpoint. |

> For a step-by-step guide to configuring local endpoints, see [Setting Up Local Endpoint Delivery](../../how-to/local-endpoint-setup.md).

Source: `internal/auditfwd/config.go`

---

## wireguard

WireGuard interface and peer management. See [WireGuard Tunnel Management](../networking/wireguard.md).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interface_name` | string | `plexd0` | Name of the WireGuard interface |
| `listen_port` | int | `51820` | UDP listen port for WireGuard |
| `mtu` | int | `0` | MTU for the WireGuard interface. `0` means use system default. |

Source: `internal/wireguard/config.go`

---

## nat

STUN-based NAT traversal. See [NAT Traversal via STUN](../networking/nat-traversal.md).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable NAT traversal |
| `stun_servers` | []string | (built-in list) | List of STUN server addresses (host:port) |
| `refresh_interval` | duration | `60s` | Interval between STUN binding refreshes. Minimum: `10s`. |
| `timeout` | duration | `5s` | Per-server STUN request timeout |
| `min_report_interval` | duration | `10s` | Floor on the endpoint report cadence derived from the control plane's `stale_after`. A short server-side deadline can otherwise drive STUN queries and endpoint reports above `refresh_interval`; raise this to bound how far the control plane may accelerate the loop. Must be positive. |

Source: `internal/nat/config.go`

---

## peer_exchange

Peer endpoint discovery and exchange. See [Peer Endpoint Exchange](../networking/peer-endpoint-exchange.md).

Embeds `nat.Config` — inherits all NAT fields.

Source: `internal/peerexchange/config.go`

---

## policy

Network policy enforcement and firewall rules. See [Network Policy Enforcement](../networking/network-policy.md).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable policy enforcement. An omitted key means enabled; an explicit `false` is preserved. Also settable as [`PLEXD_POLICY_ENABLED`](environment-variables.md#plexd-up-variables), which is how a deployment without a config file reaches the opt-out below. |
| `chain_name` | string | `plexd-mesh` | Name of the nftables chain for policy rules |

Policy enforcement needs `CAP_NET_ADMIN`. With enforcement on, `plexd up` probes the nftables backend **before it registers** and exits if the probe fails — a node that cannot install the deny-by-default baseline must not spend its one-shot bootstrap token first. The failure names the capability and this opt-out:

```
plexd up: firewall baseline pre-flight: policy enforcement needs CAP_NET_ADMIN,
grant it to the container or set policy.enabled: false to run this node without
enforcement: policy: preflight: policy: nftables: probe: netlink receive:
operation not permitted
```

Grant the capability (see [Kubernetes Deployment](../../how-to/kubernetes-deployment.md)) or set `enabled: false` — or, without a file to set it in, `PLEXD_POLICY_ENABLED=false`. There is no middle setting: a node told to enforce that cannot enforce fails closed rather than joining the mesh unfiltered.

> **Migration:** `enabled` was previously resolved by a zero-value heuristic that guessed intent from `chain_name`. A `policy` block naming a chain without an `enabled` key was read as *disabled* — such a node ran unenforced and now comes up enforcing, which on a host without `CAP_NET_ADMIN` means it fails the pre-flight instead of starting. A block setting only `enabled: false` was forced back on and now takes effect as written. Spell `enabled` out to be certain of either.

Source: `internal/policy/config.go`

---

## tunnel

Secure tunnel access for services. See [Secure Access Tunneling](../networking/secure-access-tunneling.md).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable secure access tunneling |
| `max_sessions` | int | `10` | Maximum concurrent tunnel sessions |
| `default_timeout` | duration | `30m` | Default session timeout |
| `ssh_listen_addr` | string | — | SSH server listen address. If empty, the SSH server is not started. |
| `host_key_dir` | string | — | Directory for the host key (defaults to `data_dir`) |

Source: `internal/tunnel/config.go`

---

## bridge

Gateway bridge mode operation. Active when `mode: bridge` and `bridge.enabled: true`. See [Bridge Mode](../bridge/bridge-mode.md).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable bridge mode |
| `access_interface` | string | `eth1` | Access-side network interface |
| `access_subnets` | []string | — | Subnets routable via the access interface |
| `enable_nat` | bool | `false` | Enable NAT masquerading on the access interface |
| `relay_enabled` | bool | `false` | Enable UDP relay for NAT traversal |
| `relay_listen_port` | int | `51821` | Relay UDP listen port |
| `max_relay_sessions` | int | `100` | Maximum concurrent relay sessions |
| `session_ttl` | duration | `5m` | Relay session TTL |
| `ingress_enabled` | bool | `false` | Enable public ingress |
| `max_ingress_rules` | int | `20` | Maximum ingress rules |
| `ingress_dial_timeout` | duration | `10s` | Timeout for dialing backend targets |
| `user_access_enabled` | bool | `false` | Enable user access VPN integration |
| `user_access_interface_name` | string | `wg-access` | WireGuard interface for user access |
| `user_access_listen_port` | int | `51822` | User access WireGuard listen port |
| `max_access_peers` | int | `50` | Maximum user access peers |
| `user_access_provider_type` | string | — | External VPN provider for user access: `tailscale`, `netbird`, or empty (disabled) |
| `auth_key_env` | string | — | Environment variable name containing the auth key for the user access provider (e.g. `PLEXD_TAILSCALE_AUTH_KEY`) |
| `site_to_site_enabled` | bool | `false` | Enable site-to-site VPN |
| `site_to_site_interface_prefix` | string | `wg-s2s-` | Prefix for site-to-site WireGuard interfaces |
| `site_to_site_listen_port` | int | `51823` | Base listen port for site-to-site tunnels |
| `max_site_to_site_tunnels` | int | `10` | Maximum site-to-site tunnels |
| `tunnel_providers` | []string | — | Tunnel provider types for site-to-site: `ipsec`, `openvpn`. Empty means WireGuard-only. |
| `acme_enabled` | bool | `false` | Enable ACME TLS certificate management |
| `acme_cache_dir` | string | — | Directory for ACME certificate caching |
| `acme_allowed_hosts` | []string | — | Hostnames allowed for ACME certificates |
| `acme_email` | string | — | ACME account contact email |
| `acme_directory_url` | string | — | Override ACME directory URL (default: Let's Encrypt production) |

Source: `internal/bridge/config.go`

---

## Complete Annotated Example

```yaml
# /etc/plexd/config.yaml — Complete example with all sections

mode: node          # "node" or "bridge" (default: node)
log_level: info     # debug | info | warn | error (default: info)
data_dir: /var/lib/plexd  # persistent data directory (default: /var/lib/plexd)

api:
  base_url: https://api.plexsphere.com  # required
  tls_insecure_skip_verify: false
  connect_timeout: 10s
  request_timeout: 30s
  sse_idle_timeout: 90s
  sse_reprobe_interval: 10m

registration:
  # project_id: ""            # platform project UUID (required for registration)
  # resource_handle: ""       # platform resource handle (required for registration)
  # requested_resource_id: "" # optional resource id override
  token_file: /etc/plexd/bootstrap-token
  token_env: PLEXD_BOOTSTRAP_TOKEN
  # token_value: ""          # direct token override
  use_metadata: false
  metadata_token_path: /plexd/bootstrap-token
  metadata_timeout: 2s
  max_retry_duration: 5m

heartbeat:
  interval: 30s

reconcile:
  interval: 60s              # min: 1s

node_api:
  socket_path: /var/run/plexd/api.sock
  http_enabled: false
  http_listen: 127.0.0.1:9100
  # http_token_file: ""
  debounce_period: 5s
  shutdown_timeout: 5s

health:
  enabled: true              # dedicated /healthz + /readyz listener (default: true)
  listen: "127.0.0.1:9101"   # loopback: the endpoints are unauthenticated

actions:
  enabled: true
  hooks_dir: /etc/plexd/hooks
  max_concurrent: 5          # min: 1
  max_action_timeout: 10m    # min: 10s
  max_output_bytes: 1048576  # min: 1024 (1 MiB)

upgrade:
  release_base_url: https://github.com/plexsphere/plexd/releases/download
  signing_identity_regexp: '^https://github\.com/plexsphere/plexd/\.github/workflows/release\.yml@refs/tags/v.+$'
  signing_issuer: https://token.actions.githubusercontent.com
  # trusted_root_path: ""    # empty = embedded Sigstore public-good root

integrity:
  enabled: true
  # binary_path: ""          # path to plexd binary
  # hooks_dir: ""            # empty = mirrors actions.hooks_dir
  verify_interval: 5m        # min: 30s
  watch_enabled: true

metrics:
  enabled: true
  collect_interval: 15s      # min: 5s
  report_interval: 60s       # min: 10s, >= collect_interval
  batch_size: 100            # min: 1
  # local_endpoint:
  #   url: https://metrics.local:9090/ingest
  #   secret_key: local-metrics-token
  #   tls_insecure_skip_verify: false

log_fwd:
  enabled: true
  collect_interval: 10s      # min: 5s
  report_interval: 30s       # >= collect_interval
  batch_size: 200            # min: 1
  # file_patterns:
  #   - /var/log/app/*.log
  # filter:
  #   min_severity: warning
  #   include_units:
  #     - sshd.service
  #   exclude_units:
  #     - cron.service
  # local_endpoint:
  #   url: https://logs.local:9090/ingest
  #   secret_key: local-logs-token
  #   tls_insecure_skip_verify: false

audit_fwd:
  enabled: true
  collect_interval: 5s       # min: 1s
  report_interval: 15s       # >= collect_interval
  batch_size: 500            # min: 1
  # local_endpoint:
  #   url: https://audit.local:9090/ingest
  #   secret_key: local-audit-token
  #   tls_insecure_skip_verify: false

wireguard:
  interface_name: plexd0
  listen_port: 51820
  # mtu: 0                  # 0 = system default

nat:
  enabled: true
  # stun_servers:            # default built-in list
  refresh_interval: 60s      # min: 10s
  timeout: 5s
  min_report_interval: 10s   # floor on the stale_after-driven cadence

peer_exchange:
  enabled: true
  refresh_interval: 60s
  timeout: 5s

policy:
  enabled: true              # needs CAP_NET_ADMIN; false to run unenforced
  chain_name: plexd-mesh

tunnel:
  enabled: true
  max_sessions: 10
  default_timeout: 30m
  # ssh_listen_addr: ""       # empty = SSH server not started
  # host_key_dir: ""         # defaults to data_dir

# bridge:                    # uncomment for bridge mode
#   enabled: true
#   access_interface: eth1
#   access_subnets:
#     - 10.0.0.0/24
#   enable_nat: false
#   relay_enabled: false
#   ingress_enabled: false
#   user_access_enabled: false
#   site_to_site_enabled: false
#   acme_enabled: false
```

## See Also

- [Environment Variables Reference](environment-variables.md) — All `PLEXD_*` environment variable overrides
- [CLI Reference](cli.md) — Command-line interface and global flags
- [Architecture and Concepts](../../concepts.md) — Subsystem map and startup lifecycle
