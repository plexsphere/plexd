---
title: Configuration Reference
package: internal/agent
feature: PXD-0001
---

# Configuration Reference

plexd reads its configuration from a YAML file (default: `/etc/plexd/config.yaml`). The file is parsed by `ParseConfig()` in `internal/agent/config.go`, which performs three steps:

1. **Unmarshal** the YAML into an `AgentConfig` struct
2. **ApplyDefaults** for every zero-valued field
3. **Validate** all sections (returns the first error encountered)

**Precedence order** (highest to lowest):

1. CLI flags (`--api`, `--mode`, `--log-level`)
2. `applyEnvOverrides()` — `PLEXD_*` environment variables (see [Environment Variables](environment-variables.md))
3. Global env vars via `envOrDefault()` (`PLEXD_CONFIG`, `PLEXD_LOG_LEVEL`, `PLEXD_API`, `PLEXD_MODE`)
4. Values in the YAML config file
5. `ApplyDefaults()` for zero-valued fields

## Top-Level Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `node` | Operating mode: `node` or `bridge`. Bridge mode enables bridge-specific subsystems when `bridge.enabled: true`. |
| `log_level` | string | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `data_dir` | string | `/var/lib/plexd` | Directory for persistent agent data. Propagated to `registration.data_dir` and `node_api.data_dir` at runtime. |

---

## api

Control plane HTTP client configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `base_url` | string | — (required) | Control plane API base URL, e.g. `https://api.plexsphere.com` |
| `tls_insecure_skip_verify` | bool | `false` | Disable TLS certificate verification. **WARNING:** Only for development/testing. |
| `connect_timeout` | duration | `10s` | Maximum time to wait for a TCP connection |
| `request_timeout` | duration | `30s` | Maximum time for a complete HTTP request/response cycle |
| `sse_idle_timeout` | duration | `90s` | Maximum idle time on the SSE stream before reconnecting |

Source: `internal/api/config.go`

---

## registration

Node registration and bootstrap authentication.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `project_id` | string | — | Platform project UUID to register into. Required for fresh registration (validated at registration time, not config parse). |
| `resource_handle` | string | — | Platform Resource handle to bind to. Required for fresh registration. |
| `requested_resource_id` | string | — | Optional resource ID override used when substrate naming differs from the platform handle. |
| `token_file` | string | `/etc/plexd/bootstrap-token` | Path to the bootstrap token file |
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
| `socket_path` | string | `/var/run/plexd/api.sock` | Path to the Unix domain socket |
| `http_enabled` | bool | `false` | Enable the optional HTTP listener |
| `http_listen` | string | `127.0.0.1:9100` | HTTP listen address |
| `http_token_file` | string | — | Path to the HTTP bearer token file |
| `debounce_period` | duration | `5s` | Debounce period for coalescing events |
| `shutdown_timeout` | duration | `5s` | Maximum time to wait for graceful shutdown |

> `data_dir` and `secret_auth_enabled` are set at runtime by `plexd up`. They do not appear in the YAML.

Source: `internal/nodeapi/config.go`

---

## actions

Remote action execution and hook management.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable action execution. Defaults to `true` via zero-value heuristic: if all numeric fields are zero, `Enabled` is set to `true` by `ApplyDefaults()`. |
| `hooks_dir` | string | `/etc/plexd/hooks` | Directory containing hook scripts |
| `max_concurrent` | int | `5` | Maximum number of concurrent actions. Minimum: `1`. |
| `max_action_timeout` | duration | `10m` | Maximum duration for a single action. Minimum: `10s`. |
| `max_output_bytes` | int64 | `1048576` (1 MiB) | Maximum output size per action in bytes. Minimum: `1024`. |

Source: `internal/actions/config.go`

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
| `enabled` | bool | `true` | Enable policy enforcement. Defaults to `true` when `chain_name` is empty (zero-value heuristic). |
| `chain_name` | string | `plexd-mesh` | Name of the nftables chain for policy rules |

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

actions:
  enabled: true
  hooks_dir: /etc/plexd/hooks
  max_concurrent: 5          # min: 1
  max_action_timeout: 10m    # min: 10s
  max_output_bytes: 1048576  # min: 1024 (1 MiB)

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
