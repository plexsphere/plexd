# plexd

plexd runs on every node in a Plexsphere-managed environment. It connects to the control plane, registers the node, establishes encrypted mesh tunnels to peers, enforces network policies, and continuously reconciles local state against the desired state.

## Key Capabilities

- **Self-Registration:** Authenticates with a one-time bootstrap token and enrolls the node with the control plane. Works for platform-provisioned resources (token injected via Cloud-Init / K8s Secret) and manually onboarded resources (token provided by the user).
- **Mesh Connectivity:** Establishes direct encrypted WireGuard tunnels to all authorized peers within the same tenant. No hub-and-spoke - nodes communicate directly.
- **NAT Traversal:** Discovers public endpoints via STUN and exchanges them through the control plane. Falls back to relaying traffic through bridge nodes when direct connectivity is not possible.
- **Policy Enforcement:** Receives network policies from the control plane and enforces them locally through peer visibility filtering and firewall rules.
- **Configuration Reconciliation:** Periodically compares local tunnel and policy state against the control plane's source of truth. Corrects drift automatically.
- **Bridge Mode:** Operates as a gateway between the mesh and external networks. Routes user access (e.g. via Tailscale, Netbird, WireGuard clients), exposes services to public traffic, connects to external VPNs for site-to-site connectivity, and serves as a relay for nodes that cannot establish direct P2P tunnels.
- **Observability:** Collects and reports node metrics, tunnel health, peer latency, and resource utilization.
- **Log Forwarding:** Streams system and application logs to the control plane for centralized monitoring and troubleshooting.
- **Audit:** Collects and forwards audit data from managed resources (e.g. Linux auditd, Kubernetes audit logs) for compliance and security analysis.
- **Remote Actions & Hooks:** Executes platform-triggered actions on nodes - both built-in operations (diagnostics, service management) and custom hook scripts. Integrity is ensured through SHA-256 checksums for hooks and the plexd binary itself.
- **Local Node API:** Exposes node state (metadata, configuration data, secrets) to local workloads and scripts via a Unix socket API (bare-metal/VM) or a PlexdNodeState CRD (Kubernetes). Supports bidirectional data exchange - downstream from the control plane and upstream reporting from the node.
- **Secure Access:** Enables platform-mediated access to managed resources - SSH sessions to servers/VMs and Kubernetes API access - tunneled through the mesh without exposing services directly.

## Supported Platforms

| Platform | Mode | Notes |
|---|---|---|
| Bare-metal servers | `node` | Systemd service, manual or automated enrollment |
| Virtual machines | `node` | Cloud-Init support for automated token injection |
| Kubernetes clusters | `node` | DaemonSet deployment, auto-detects K8s audit logs |
| Bridge / Gateway | `bridge` | User access, public ingress, site-to-site VPN, NAT relay |

**OS:** Linux (amd64, arm64)

## Architecture

### High-Level Overview

```
                              ┌───────────────────────┐
                              │  Plexsphere           │
                              │  Control Plane        │
                              └───────────┬───────────┘
                                          │
                            HTTPS + SSE (outbound only)
                                          │
       ┌──────────────┬───────────────────┼──────────────────┬──────────────┐
       ▼              ▼                   ▼                  ▼              ▼
┌────────────┐ ┌────────────┐      ┌────────────┐    ┌────────────┐ ┌────────────┐
│ Bare-Metal │ │     VM     │      │     VM     │    │    K8s     │ │  Bridge /  │
│            │ │            │      │            │    │  Cluster   │ │  Gateway   │
└─────┬──────┘ └─────┬──────┘      └─────┬──────┘    └─────┬──────┘ └──┬──────┬──┘
      │              │                   │                 │           │      │
      │◄════ Encrypted Mesh (direct P2P + NAT Traversal) ═════════════►│      │
      │              │                   │                 │           │      │
      └──────────────┴───────────────────┴─────────────────┘      ┌────┘      └────┐
                                                                  │                │
                                                                  ▼                ▼
                                                           ┌──────────┐     ┌────────────┐
                                                           │  User    │     │  External  │
                                                           │  Access  │     │  Traffic   │
                                                           │          │     │            │
                                                           │ Tailscale│     │ Public IPs │
                                                           │ Netbird  │     │ Site-to-   │
                                                           │ WireGuard│     │ Site VPN   │
                                                           └────┬─────┘     └──────┬─────┘
                                                                │                  │
                                                                ▼                  ▼
                                                          ┌───────────┐   ┌──────────────┐
                                                          │ Developers│   │ Public       │
                                                          │ Admins    │   │ Internet     │
                                                          │ On-Call   │   │ Partner Nets │
                                                          └───────────┘   └──────────────┘
```

### Detailed Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             Plexsphere Control Plane                             │
│                                                                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────┐  ┌────────────────┐    │
│  │ Registration   │  │ Key & Peer     │  │ Policy       │  │ Event Bus      │    │
│  │ API            │  │ Manager        │  │ Engine       │  │ (SSE)          │    │
│  └────────────────┘  └────────────────┘  └──────────────┘  └────────────────┘    │
│                                                                                  │
└─────────────────────────────────────┬────────────────────────────────────────────┘
                                      │
                            HTTPS + SSE (outbound only)
                                      │
         ┌────────────┬───────────────┼───────────────┬────────────────┐
         ▼            ▼               ▼               ▼                ▼
┌──────────────┐┌────────────┐┌────────────┐┌────────────┐  ┌───────────────────┐
│    plexd     ││   plexd    ││   plexd    ││   plexd    │  │   plexd (Bridge)  │
│ (Bare-Metal) ││   (VM)     ││   (VM)     ││   (K8s)    │  ├───────────────────┤
│              ││            ││            ││            │  │                   │
│  10.100.1.1  ││ 10.100.1.2 ││ 10.100.1.3 ││ 10.100.1.4 │  │ ┌───────────────┐ │
└──────┬───────┘└─────┬──────┘└─────┬──────┘└─────┬──────┘  │ │   Mesh side   │ │
       │              │             │             │         │ │  10.100.1.250 │ │
       │              │             │             │         │ │  NAT Relay    │ │
       │   ┌──────────┴─────────────┴─────────────┴──┐      │ └───────┬───────┘ │
       │   │                                         │      │         │         │
       └───┤  Encrypted WireGuard Mesh (Full Mesh)   ├──────┤         │         │
           │                                         │      │         │         │
           │  Every node ◄══ direct P2P ══► every    │      │ ┌───────┴───────┐ │
           │  node. Each peer uses STUN to discover  │      │ │  Access side  │ │
           │  its public endpoint for NAT traversal. │      │ │               │ │
           │  Falls back to relay via Bridge when    │      │ │ ┌───────────┐ │ │
           │  direct connectivity fails.             │      │ │ │ User      │ │ │
           │                                         │      │ │ │ Access    │ │ │
           └─────────────────────────────────────────┘      │ │ │ Tailscale │ │ │
                                                            │ │ │ Netbird   │ │ │
                                                            │ │ │ WireGuard │ │ │
                                                            │ │ └─────┬─────┘ │ │
                                                            │ │ ┌─────┴─────┐ │ │
                                                            │ │ │ Public    │ │ │
                                                            │ │ │ Ingress   │ │ │
                                                            │ │ └─────┬─────┘ │ │
                                                            │ │ ┌─────┴─────┐ │ │
                                                            │ │ │ Site-to-  │ │ │
                                                            │ │ │ Site VPN  │ │ │
                                                            │ │ └─────┬─────┘ │ │
                                                            │ └───────┼───────┘ │
                                                            └─────────┼─────────┘
                                                                      │
                                                        ┌─────────────┼─────────────┐
                                                        ▼             ▼             ▼
                                                   ┌─────────┐ ┌──────────┐ ┌───────────┐
                                                   │Developer│ │ Public   │ │ Partner / │
                                                   │Admin    │ │ Internet │ │ Customer  │
                                                   │On-Call  │ │ Traffic  │ │ Network   │
                                                   └─────────┘ └──────────┘ └───────────┘
```

plexd communicates outbound only - no inbound ports or public IPs required on the node side. Nodes behind NAT discover their public endpoints via STUN and exchange them through the control plane to establish direct peer-to-peer tunnels. When direct connectivity is not possible, traffic is relayed through bridge nodes. The control plane pushes peer updates via SSE; the agent pulls full state periodically as a consistency fallback.

## Installation

### Binary

```bash
curl -fsSL https://get.plexsphere.com/plexd | sh
```

### Container

```bash
docker pull ghcr.io/plexsphere/plexd:latest
```

### From Source

Requires Go 1.22+, WireGuard tools, and nftables.

```bash
git clone https://github.com/plexsphere/plexd.git
cd plexd
make build
```

## Quick Start

### Platform-Provisioned Node (Token via Cloud-Init)

No manual steps required - plexd reads the bootstrap token automatically:

```bash
plexd up
```

### Manual Enrollment

Generate a token in the Plexsphere UI or CLI, then:

```bash
# Interactive prompt (recommended - token never visible in shell history or process list)
plexd join

# From file
plexd join --token-file /etc/plexd/bootstrap-token

# From environment variable
PLEXD_BOOTSTRAP_TOKEN=plx_enroll_a8f3c7... plexd join
```

### Running as a Service

```bash
sudo plexd install   # Creates systemd unit
sudo systemctl enable --now plexd
```

### Kubernetes (DaemonSet)

> **Production:** Use [External Secrets Operator (ESO)](https://external-secrets.io) to provision the bootstrap token from your secrets manager (e.g. Vault, AWS Secrets Manager) instead of storing it as a plain Secret.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: plexd-bootstrap
  namespace: plexd-system
type: Opaque
stringData:
  token: "plx_enroll_a8f3c7..."
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: plexd
  namespace: plexd-system
spec:
  selector:
    matchLabels:
      app: plexd
  template:
    metadata:
      labels:
        app: plexd
    spec:
      hostNetwork: true
      serviceAccountName: plexd
      containers:
        - name: plexd
          image: ghcr.io/plexsphere/plexd:latest
          securityContext:
            capabilities:
              add:
                - NET_ADMIN
                - NET_RAW
          env:
            - name: PLEXD_API
              value: "https://api.plexsphere.com"
            - name: PLEXD_BOOTSTRAP_TOKEN
              valueFrom:
                secretKeyRef:
                  name: plexd-bootstrap
                  key: token
          volumeMounts:
            - name: plexd-data
              mountPath: /var/lib/plexd
      volumes:
        - name: plexd-data
          hostPath:
            path: /var/lib/plexd
            type: DirectoryOrCreate
```

### Docker (Bridge Mode)

```yaml
services:
  plexd:
    image: ghcr.io/plexsphere/plexd:latest
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - plexd-data:/var/lib/plexd
    environment:
      PLEXD_API: "https://api.plexsphere.com"
      PLEXD_BOOTSTRAP_TOKEN_FILE: /run/secrets/bootstrap-token
      PLEXD_MODE: bridge
    secrets:
      - bootstrap-token
    restart: unless-stopped

volumes:
  plexd-data:

secrets:
  bootstrap-token:
    file: ./bootstrap-token
```

## Usage

```
plexd <command> [flags]

Commands:
  up          Start the agent (register if needed, connect, reconcile)
  join        Register this node with a bootstrap token (interactive prompt, --token-file, or env)
  status      Show current node and mesh status
  peers       List connected peers
  policies    Show active network policies
  logs        Stream agent logs
  log-status  Show log forwarding status
  audit       Show audit collection status
  actions     List available actions (built-in and hooks)
  actions run Run an action locally (requires session token or --local)
  hooks list  List configured hooks and their status (script + CRD)
  hooks verify  Verify hook checksums (script: SHA-256, CRD: image digest)
  hooks reload  Re-scan hooks directory / CRD resources and update capabilities
  state       Show local node state summary (metadata, data entries, report entries)
  state get   Get a specific state entry (metadata, data, secret, report)
  state report  Write or delete a report entry (upstream to control plane)
  install     Install as a systemd service
  uninstall   Remove systemd service and clean up
  deregister  Unregister this node from the control plane

Flags:
  --config       Path to config file (default: /etc/plexd/config.yaml)
  --api          Control plane API URL
  --log-level    Log verbosity: debug, info, warn, error (default: info)
  --mode         Agent mode: node, bridge (default: node)
```

## Configuration

```yaml
# /etc/plexd/config.yaml

# --- Required ---
api: "https://api.plexsphere.com"

# --- Optional ---
log_level: info         # debug, info, warn, error
mode: node              # node | bridge
data_dir: /var/lib/plexd

# Mesh (WireGuard)
mesh:
  interface: plexd0     # WireGuard interface name
  listen_port: 51820    # UDP port for mesh traffic

# Token source (checked in order, first match wins)
token:
  file: /etc/plexd/bootstrap-token
  env: PLEXD_BOOTSTRAP_TOKEN
  metadata: true        # Read from cloud provider metadata service

# Reconciliation
reconcile:
  interval: 60s

# Policy enforcement
policy:
  default: deny          # deny | allow (default deny-all for mesh traffic)
  log_denied: true       # Log denied packets at debug level
```

**Policy enforcement behavior (preliminary - subject to change):**

> **Note:** The policy enforcement model is under active development. The behavior described here reflects the current design and may change in future versions.

- Policies are pushed by the control plane via the `policy_updated` SSE event. plexd does not poll for policy changes - they are applied as soon as received (and verified via signature).
- Filtering operates at **L3/L4** (IP, port, protocol) on the `plexd0` mesh interface using **nftables** rules.
- The default stance is **deny-all**: no mesh traffic is permitted unless explicitly allowed by a policy rule.
- **Peer visibility filtering:** In addition to firewall rules, plexd controls which peers are configured in the WireGuard interface. Peers not authorized by policy are not added to the interface, preventing even handshake-level communication.
- Policy rules are scoped to mesh IPs (10.100.x.x/32) and cannot reference external IPs or hostnames.
- On policy update, plexd computes a diff against the current nftables ruleset and applies only the changes (add/remove rules), minimizing disruption.

```yaml
# NAT Traversal
nat_traversal:
  enabled: true
  stun_servers:
    - stun.l.google.com:19302
    - stun.cloudflare.com:3478
  refresh_interval: 60s
  fallback: relay       # Route through bridge nodes when P2P fails

# Heartbeat
heartbeat:
  interval: 30s

# Observability
observe:
  enabled: true
  interval: 15s
  batch_interval: 10s
  batch_max_size: 500
  metrics:
    - node_resources    # CPU, memory, disk
    - tunnel_health     # Handshake status, packet loss
    - peer_latency      # RTT to each peer
    - agent_stats       # Goroutines, memory, uptime
```

**Observability behavior:**

plexd collects the following metric groups at the configured `interval`:

| Metric Group | Data Points |
|---|---|
| `node_resources` | CPU usage (%), memory used/total, disk used/total, load average |
| `tunnel_health` | Per-peer handshake age, TX/RX bytes, packet loss (%), last handshake timestamp |
| `peer_latency` | Per-peer RTT (ms) via ICMP echo over the mesh interface |
| `agent_stats` | plexd goroutine count, heap memory, GC stats, uptime, reconnect count |

Metrics are delivered to the control plane as **batch POST requests** (JSON array, gzip-compressed) at `batch_interval` (default 10s) or when `batch_max_size` (default 500 data points) is reached, whichever comes first. There is no local Prometheus or OpenTelemetry exposition endpoint - all metrics flow exclusively to the control plane.

```yaml
# Log forwarding
logs:
  enabled: true
  sources:
    - journald          # System journal
    - /var/log/syslog
  filters:
    - unit: plexd       # Always included
    - unit: sshd
    - path: /var/log/app/*.log
    - severity: warn     # Minimum severity (debug, info, warn, error)
  batch_interval: 10s    # Flush interval
  batch_max_size: 1000   # Max lines per batch
  buffer_size: 10000     # Ringbuffer entries when control plane is unreachable
  max_line_size: 16384   # 16 KiB, lines exceeding this are truncated
```

**Log forwarding behavior:**

Logs are collected from the configured sources and delivered to the control plane as **batch POST requests** using JSON Lines format, gzip-compressed. Batches are flushed at `batch_interval` (default 10s) or when `batch_max_size` (default 1000 lines) is reached.

Each log line is serialized as:

```json
{
  "timestamp": "2025-01-15T10:30:00.123Z",
  "source": "journald",
  "unit": "plexd",
  "message": "reconciliation completed, 0 drifts corrected",
  "severity": "info",
  "hostname": "web-01"
}
```

- **Max line size:** 16 KiB. Lines exceeding this limit are truncated with a `[truncated]` suffix.
- **Filtering:** Unit-based (systemd unit name), path-based (file glob), and severity-level filters are applied before batching. The `plexd` unit is always included regardless of filter configuration.
- **Offline buffering:** When the control plane is unreachable, log entries are buffered in a bounded ringbuffer (`buffer_size`, default 10000 entries). Oldest entries are evicted when the buffer is full. Buffered entries are drained on reconnection.

```yaml
# Audit
audit:
  enabled: true
  sources:
    - auditd            # Linux audit daemon
    - kubernetes        # Kubernetes audit logs (auto-detected on K8s nodes)
  batch_interval: 10s
  batch_max_size: 500
  buffer_size: 10000     # Ringbuffer entries when control plane is unreachable
```

**Audit collection behavior:**

- **auditd:** plexd opens a Netlink socket (`AF_AUDIT`) to receive real-time audit events from the Linux kernel. This avoids file-based polling and ensures no events are missed.
- **Kubernetes:** plexd tails the Kubernetes audit log file, auto-detected via the kubelet configuration (typically `/var/log/kubernetes/audit/audit.log`). The path can be overridden in the config.

All audit events are normalized into a unified JSON schema:

```json
{
  "timestamp": "2025-01-15T10:30:00.456Z",
  "source": "auditd",
  "event_type": "SYSCALL",
  "subject": { "uid": 1000, "pid": 4523, "comm": "sshd" },
  "object": { "path": "/etc/shadow" },
  "action": "open",
  "result": "denied",
  "hostname": "web-01",
  "raw": "..."
}
```

Delivery follows the same batch model as log forwarding: **batch POST** (JSON Lines, gzip-compressed) at `batch_interval` with its own independent ringbuffer for offline buffering.

```yaml
# Access proxy
access:
  ssh:
    enabled: true
    host_key_file: /var/lib/plexd/ssh_host_key
    idle_timeout: 30m    # Close session after inactivity
    max_sessions: 10     # Max concurrent SSH sessions per node
  kubernetes:
    enabled: false       # Auto-detected on K8s nodes
    api_server: ""       # Auto-discovered if empty
    idle_timeout: 15m
```

**Access proxy behavior:**

plexd provides platform-mediated access to managed resources without exposing services directly.

**SSH access flow:**

1. User requests SSH access through the platform UI/CLI.
2. Control plane verifies RBAC permissions and issues a session JWT scoped to the target node and allowed actions.
3. Control plane sends an `ssh_session_setup` event via SSE to the target node, including the session token.
4. plexd opens a TCP listener on the mesh interface and tunnels the SSH connection through the encrypted mesh.
5. The SSH session uses the node's managed host key (`host_key_file`). If the key file does not exist, plexd generates an Ed25519 host key on first use and reports its fingerprint to the control plane.
6. Session environment is injected with `PLEXD_SESSION_TOKEN` for local action authorization.
7. On disconnect or `idle_timeout`, plexd tears down the session and notifies the control plane.

**Kubernetes API proxy flow:**

1. User requests kubectl access through the platform.
2. Control plane issues a scoped kubeconfig with a short-lived token.
3. plexd proxies the Kubernetes API request through the mesh to the target cluster's API server (auto-discovered via kubelet config or configured explicitly).
4. The proxy terminates on `idle_timeout` (default 15m) if no requests are received.

```yaml
# Actions
actions:
  enabled: true
  max_concurrent: 5           # Max parallel action executions
  socket: /var/run/plexd.sock # Unix socket for local action requests
  local_auth:
    require_root: true        # --local flag requires root or plexd user

# Hooks
hooks:
  enabled: true
  dir: /etc/plexd/hooks.d
  definitions:
    - name: backup
      path: /etc/plexd/hooks.d/backup.sh
      description: "Run incremental backup"
      timeout: 300s
      user: backup-agent
      sandbox: namespaced

# Bridge-specific (only when mode: bridge)
bridge:
  # User access layer
  access:
    - type: tailscale
      auth_key_env: TS_AUTHKEY
    - type: netbird
      setup_key_env: NB_SETUP_KEY
    - type: wireguard
      listen_port: 51821

  # Public ingress
  ingress:
    enabled: false
    listen: 0.0.0.0:443

  # NAT relay for nodes that cannot establish direct P2P tunnels
  relay:
    enabled: true
    listen_port: 51820   # UDP relay port (shared with mesh listen_port)

  # Site-to-Site VPN peerings
  site_to_site:
    - name: partner-network
      type: wireguard   # wireguard, ipsec, openvpn
      remote_endpoint: vpn.partner.example:51820
      remote_subnets:
        - 172.16.0.0/16
```

**Bridge mode behavior:**

In bridge mode (`mode: bridge`), plexd acts as a gateway between the encrypted mesh and external networks. A bridge node participates in the mesh like any other node but additionally provides the following services:

**NAT relay:**

When two nodes cannot establish a direct P2P tunnel (e.g. both behind symmetric NAT), one or both fall back to relaying traffic through the bridge. The relay operates as a transparent UDP proxy - WireGuard handshakes and encrypted packets pass through without decryption. The bridge never has access to the plaintext traffic. Relay assignment is coordinated by the control plane, which instructs nodes to use the bridge's public endpoint as a fallback.

**User access:**

The bridge creates separate network interfaces for each configured access provider (Tailscale, Netbird, WireGuard client). User traffic arriving on these interfaces is routed into the mesh based on destination mesh IP. Routing rules ensure user traffic can only reach authorized mesh nodes, as determined by the control plane's policy.

**Public ingress:**

When `ingress.enabled` is `true`, the bridge runs a reverse proxy that terminates TLS and routes incoming traffic to mesh nodes. Routing is based on SNI (Server Name Indication) - each service is mapped to a mesh node/port combination configured in the control plane. The bridge requests TLS certificates automatically via ACME (Let's Encrypt).

**Site-to-site:**

The bridge establishes VPN tunnels to external networks (partner networks, cloud VPCs) using the configured protocol (WireGuard, IPsec, OpenVPN). Routing between the mesh and the remote subnets is bidirectional - mesh nodes can reach external subnets, and external hosts can reach authorized mesh IPs.

```yaml
# Local Node API
node_api:
  enabled: true
  socket: /var/run/plexd/api.sock   # Unix socket path
  http:
    enabled: false                   # Optional TCP listener
    listen: 127.0.0.1:9100
    token_file: /etc/plexd/node-api-token
```

**Node API behavior:**

The local Node API provides read/write access to node state for local workloads and scripts. When `node_api.enabled` is `true`, plexd opens a Unix socket at the configured path. The socket is created with group `plexd` ownership so that processes in the `plexd` group can access metadata and data entries. Secret access requires membership in the `plexd-secrets` group or root privileges.

When `node_api.http.enabled` is `true`, plexd additionally listens on the configured TCP address (default `127.0.0.1:9100`). TCP requests must include a `Authorization: Bearer <token>` header. The token is read from `token_file` at startup. This mode is intended for environments where Unix socket access is impractical (e.g. containers without socket mounts).

Metadata and data entries are cached locally in `data_dir/state/` and survive agent restarts. The cache is populated from the control plane on first connect and kept in sync via SSE events. Report entries written via the API are buffered locally and synced upstream with debounce (default 5s) and retry on failure.

Secret values are never cached in plaintext. Each secret read request is proxied to the control plane in real-time. The control plane delivers secrets encrypted with the node's AES-256-GCM secret key (NSK), and plexd decrypts on-the-fly before serving the response. This ensures the control plane remains the authoritative source and can enforce access policies in real-time.

On Kubernetes, plexd manages a `PlexdNodeState` custom resource for metadata, data, and reports. For secrets, plexd exposes a node-local decryption API (Kubernetes Secrets contain only NSK-encrypted ciphertext). See [Local Node API](#local-node-api) for details.

## Environment Variables

All configuration options can also be set via environment variables. These take precedence over the config file.

| Variable | Description | Default |
|---|---|---|
| `PLEXD_API` | Control plane API URL | - |
| `PLEXD_BOOTSTRAP_TOKEN` | Bootstrap token value | - |
| `PLEXD_BOOTSTRAP_TOKEN_FILE` | Path to file containing bootstrap token | - |
| `PLEXD_MODE` | Agent mode (`node`, `bridge`) | `node` |
| `PLEXD_LOG_LEVEL` | Log verbosity (`debug`, `info`, `warn`, `error`) | `info` |
| `PLEXD_CONFIG` | Path to config file | `/etc/plexd/config.yaml` |
| `PLEXD_ACTIONS_ENABLED` | Enable built-in actions | `true` |
| `PLEXD_HOOKS_ENABLED` | Enable custom hooks | `true` |
| `PLEXD_HOOKS_DIR` | Directory for hook scripts | `/etc/plexd/hooks.d` |
| `PLEXD_ACTIONS_MAX_CONCURRENT` | Max parallel action executions | `5` |
| `PLEXD_NODE_API_ENABLED` | Enable the local Node API | `true` |
| `PLEXD_NODE_API_SOCKET` | Unix socket path for the Node API | `/var/run/plexd/api.sock` |
| `PLEXD_NODE_API_HTTP_ENABLED` | Enable TCP listener for the Node API | `false` |
| `PLEXD_NODE_API_HTTP_LISTEN` | TCP listen address for the Node API | `127.0.0.1:9100` |
| `PLEXD_SESSION_TOKEN` | Session JWT for action authorization (injected by access proxy) | - |

## Agent Lifecycle

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                                                                               │
│   ┌─────────┐    ┌──────────┐    ┌───────────┐    ┌─────────────┐             │
│   │  Start  │    │          │    │ Configure │    │     NAT     │             │
│   │ Binary  ├───▶│ Register ├───▶│  Tunnels  ├───▶│  Discovery  │             │
│   │ Checksum│    │          │    │           │    │   (STUN)    │             │
│   │ Hook    │    └──────────┘    └───────────┘    └──────┬──────┘             │
│   │ Scan    │                                            │                    │
│   └─────────┘                                            ▼                    │
│                                                                               │
│   ┌────────────┐                 ┌─────────────────────────────────────┐      │
│   │            │  On shutdown    │            Connected                │      │
│   │ Deregister │◀── or command ──┤                                     │      │
│   │            │                 │  ┌─────────────┐ ┌───────────────┐  │      │
│   └────────────┘                 │  │ Heartbeat   │ │ Reconcile     │  │      │
│                                  │  │ NAT Refresh │ │ SSE Stream    │  │      │
│   • Notify control plane         │  └─────────────┘ └───────────────┘  │      │
│   • Tear down tunnels            │  ┌─────────────┐ ┌───────────────┐  │      │
│   • Wait for in-flight           │  │ Policy      │ │ Observe       │  │      │
│     action executions            │  │ Enforce     │ │ Logs, Audit   │  │      │
│   • Clean up local state         │  └─────────────┘ └───────────────┘  │      │
│                                  │  ┌─────────────┐ ┌───────────────┐  │      │
│                                  │  │ Access      │ │ Action        │  │      │
│                                  │  │ Proxy       │ │ Dispatcher    │  │      │
│                                  │  └─────────────┘ └───────────────┘  │      │
│                                  │  ┌─────────────┐ ┌───────────────┐  │      │
│                                  │  │ Hook File   │ │ Node API      │  │      │
│                                  │  │ Watcher     │ │ Server        │  │      │
│                                  │  └─────────────┘ └───────────────┘  │      │
│                                  └─────────────────────────────────────┘      │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

1. **Start** - Read config, locate bootstrap token, compute binary SHA-256 checksum, scan and checksum all declared hooks.
2. **Register** - POST token to control plane, receive node identity, keys, and initial peer list. Include capabilities (binary info, available actions, hooks with checksums).
3. **Configure Tunnels** - Set up mesh interfaces and establish tunnels to all authorized peers.
4. **NAT Discovery** - Determine public endpoint via STUN, report it to the control plane, receive NAT-discovered endpoints of peers.
5. **Connected** - Enter steady state: send heartbeats, stream peer/policy/action/state updates via SSE, report observability data, forward logs, collect audit data, serve access requests, dispatch actions, watch hook files for changes, serve node API, refresh STUN endpoints, reconcile periodically.
6. **Deregister** - On shutdown or explicit command: graceful shutdown with cleanup (see details below).

### Phase 3 Details: Steady State

**Heartbeat protocol:**

plexd sends a heartbeat to the control plane at `heartbeat.interval` (default 30s) via `POST /v1/nodes/{node_id}/heartbeat`.

Heartbeat payload:

```json
{
  "node_id": "n_abc123",
  "timestamp": "2025-01-15T10:30:00Z",
  "status": "healthy",
  "uptime": "72h15m",
  "binary_checksum": "sha256:a1b2c3d4e5f6...",
  "mesh": {
    "interface": "plexd0",
    "peer_count": 12,
    "listen_port": 51820
  },
  "nat": {
    "public_endpoint": "203.0.113.10:51820",
    "type": "full_cone"
  }
}
```

The control plane responds with one of:

| Response | Meaning |
|---|---|
| `200 OK` | Heartbeat acknowledged, no action required |
| `200 OK` + `{ "reconcile": true }` | Trigger immediate reconciliation (out-of-band hint) |
| `200 OK` + `{ "rotate_keys": true }` | Trigger key rotation (redundant with SSE, serves as fallback) |
| `401 Unauthorized` | Node identity invalid, re-register |

If a node misses **3 consecutive heartbeats** (i.e. no heartbeat received for `3 × heartbeat.interval`), the control plane marks the node as `unreachable` and notifies peer nodes. After **10 consecutive missed heartbeats**, the node is marked `offline` and its peers remove it from their active tunnel configuration. The node re-establishes tunnels automatically when it comes back online and resumes heartbeats.

**SSE reconnection:**

The SSE stream is the primary channel for real-time updates. When the connection drops:

1. plexd detects the disconnect and begins reconnection with **exponential backoff**: 1s, 2s, 4s, 8s, ... up to a maximum of 60s.
2. **Jitter** of ±25% is applied to each backoff interval to prevent thundering herd effects when many nodes reconnect simultaneously (e.g. after a control plane restart).
3. On reconnection, plexd sends the `Last-Event-ID` header (from the last successfully processed SSE event) so the control plane can replay missed events.
4. After a successful reconnect, plexd triggers an **immediate reconciliation** to catch any updates that may have been missed during the disconnect window.
5. If the SSE stream cannot be re-established after 5 minutes, plexd falls back to polling the full state at `reconcile.interval` until the SSE stream recovers.

### Deregistration Details

When plexd receives a shutdown signal (`SIGTERM`, `SIGINT`) or the `plexd deregister` command is run:

1. **Stop accepting new work** - Stop accepting new action requests and SSE events.
2. **Drain in-flight executions** - Wait for all running action/hook executions to complete (up to 30s grace period). After the grace period, running executions are cancelled and reported as `cancelled` to the control plane.
3. **Notify control plane** - Send `POST /v1/nodes/{node_id}/deregister` to inform the control plane. The control plane removes the node from peer lists and pushes `peer_removed` events to all peers.
4. **Tear down tunnels** - Remove all WireGuard peers from the `plexd0` interface and delete the interface.
5. **Stop subsystems** - Stop log forwarding, audit collection, observability reporting, access proxy, and heartbeat.
6. **Clean up local state** - Optionally (when `--purge` is passed) remove all data from `data_dir`, including private keys and cached state. Without `--purge`, state is preserved for potential re-registration.

On `plexd deregister --purge`, the bootstrap token file is also removed if it still exists, and the systemd unit is disabled.

## Actions & Hooks

### Overview

The platform can trigger actions on nodes by sending an `action_request` event over the authenticated SSE stream. plexd supports two types of actions:

- **Built-in Actions** - Operations compiled into the plexd binary (diagnostics, service management, system info).
- **Custom Hooks (script)** - User-defined scripts placed in `/etc/plexd/hooks.d/` and explicitly declared in the configuration. Used on bare-metal and VM nodes.
- **Custom Hooks (CRD)** - `PlexdHook` custom resources that define a Kubernetes Job template. On `action_request`, plexd creates a Job on the target node. Used when running as a DaemonSet in Kubernetes.

Actions can be triggered in two ways: remotely by the control plane via SSE, or locally by users in SSH sessions via the `plexd actions run` CLI. Local execution requires a session-scoped JWT token issued by the platform during SSH session setup (see [Session-Based Action Authorization](#session-based-action-authorization)).

Results are reported asynchronously via an HTTP POST callback to the control plane. Every hook script and the plexd binary itself are protected by SHA-256 checksums to ensure integrity.

### SSE Event: `action_request`

The control plane sends an `action_request` event over the existing SSE stream to trigger an action on a node. Like all SSE events, it is wrapped in a [signed envelope](#phase-3-steady-state) and verified before processing.

**Payload** (inside signed envelope):

```json
{
  "execution_id": "exec_a1b2c3d4",
  "action": "diagnostics.collect",
  "type": "builtin",
  "parameters": {
    "include_network": true,
    "include_processes": true
  },
  "timeout": "30s",
  "callback_url": "https://api.plexsphere.com/v1/nodes/n_abc123/executions/exec_a1b2c3d4"
}
```

| Field | Type | Description |
|---|---|---|
| `execution_id` | string | Unique identifier for this execution |
| `action` | string | Action name (e.g. `diagnostics.collect`, `hooks/backup`) |
| `type` | string | `builtin` or `hook` |
| `parameters` | object | Key-value parameters passed to the action |
| `timeout` | duration | Maximum execution time (default: 30s) |
| `callback_url` | string | URL for ACK/NACK and result delivery |

The `issued_at`, `nonce`, and `signature` fields are part of the signed event envelope (see [Phase 3: Steady State](#phase-3-steady-state)) and apply to all SSE events uniformly.

### Built-in Actions

Built-in actions are compiled into the plexd binary and always available.

| Action | Description | Parameters |
|---|---|---|
| `diagnostics.collect` | Collect system diagnostics (CPU, memory, disk, network) | `include_network`, `include_processes` |
| `diagnostics.ping_peer` | Ping a mesh peer and report latency | `peer_id`, `count` |
| `diagnostics.traceroute_peer` | Traceroute to a mesh peer | `peer_id`, `max_hops` |
| `service.restart` | Restart the plexd service | - |
| `service.reload_config` | Reload configuration without restart | - |
| `service.upgrade` | Upgrade plexd to a specified version | `version`, `checksum` |
| `system.info` | Report OS, kernel, hardware, and runtime info | - |
| `health.check` | Run all health checks and report status | `include_peers` |
| `mesh.reconnect` | Tear down and re-establish all mesh tunnels | - |
| `config.dump` | Return current effective configuration (secrets redacted) | - |
| `logs.snapshot` | Capture recent logs and return as compressed archive | `lines`, `since` |

### Custom Hooks (Bare-Metal / VM)

On bare-metal and VM nodes, custom hooks are user-defined scripts that extend plexd with site-specific operations. Hooks must be explicitly declared in the configuration - auto-discovery is not supported.

**Configuration:**

```yaml
# /etc/plexd/config.yaml

hooks:
  enabled: true
  dir: /etc/plexd/hooks.d

  definitions:
    - name: backup
      path: /etc/plexd/hooks.d/backup.sh
      description: "Run incremental backup of application data"
      parameters:
        - name: target
          type: string
          required: true
          description: "Backup target path"
        - name: compress
          type: bool
          default: "true"
      timeout: 300s
      user: backup-agent
      sandbox: namespaced
      resources:
        cpu: "1.0"
        memory: 512M

    - name: deploy
      path: /etc/plexd/hooks.d/deploy.sh
      description: "Deploy application version"
      parameters:
        - name: version
          type: string
          required: true
        - name: rollback_on_failure
          type: bool
          default: "true"
      timeout: 600s
      user: deploy
      sandbox: container
      resources:
        cpu: "2.0"
        memory: 1G
```

**Execution Model:**

Hooks are executed as subprocesses. Parameters are passed as environment variables with the `PLEXD_PARAM_` prefix:

```bash
#!/bin/bash
# /etc/plexd/hooks.d/backup.sh
# Parameters available as:
#   PLEXD_PARAM_TARGET   - Backup target path
#   PLEXD_PARAM_COMPRESS - Whether to compress (true/false)
#   PLEXD_EXECUTION_ID   - Unique execution ID
#   PLEXD_ACTION_NAME    - Hook name (backup)

set -euo pipefail
echo "Starting backup to ${PLEXD_PARAM_TARGET}"
# ... backup logic ...
```

### Kubernetes-Native Hooks (CRD)

When plexd runs as a DaemonSet in Kubernetes, hooks are defined as `PlexdHook` custom resources instead of script files. On `action_request`, plexd creates a Kubernetes Job on the target node - no intermediate scripts required.

**Custom Resource Definition:**

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: plexdhooks.plexd.plexsphere.com
spec:
  group: plexd.plexsphere.com
  names:
    kind: PlexdHook
    listKind: PlexdHookList
    plural: plexdhooks
    singular: plexdhook
    shortNames:
      - ph
  scope: Namespaced
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              required: [jobTemplate]
              properties:
                description:
                  type: string
                parameters:
                  type: array
                  items:
                    type: object
                    required: [name, type]
                    properties:
                      name:
                        type: string
                      type:
                        type: string
                        enum: [string, bool, int]
                      required:
                        type: boolean
                      default:
                        type: string
                      description:
                        type: string
                timeout:
                  type: string
                  default: "30s"
                privileged:
                  type: boolean
                  default: false
                jobTemplate:
                  type: object
                  x-kubernetes-preserve-unknown-fields: true
      additionalPrinterColumns:
        - name: Description
          type: string
          jsonPath: .spec.description
        - name: Timeout
          type: string
          jsonPath: .spec.timeout
        - name: Age
          type: date
          jsonPath: .metadata.creationTimestamp
```

**Hook Definition:**

```yaml
apiVersion: plexd.plexsphere.com/v1alpha1
kind: PlexdHook
metadata:
  name: db-backup
  namespace: plexd-system
spec:
  description: "PostgreSQL backup to S3"
  parameters:
    - name: bucket
      type: string
      required: true
      description: "S3 bucket URI"
    - name: compress
      type: bool
      default: "true"
  timeout: 600s
  jobTemplate:
    spec:
      containers:
        - name: backup
          image: registry.example.com/tools/pg-backup:2.1@sha256:abc123...
          command: ["/usr/local/bin/pg-backup.sh"]
          resources:
            limits:
              cpu: "1"
              memory: 512Mi
          volumeMounts:
            - name: pgdata
              mountPath: /var/lib/postgresql
              readOnly: true
      volumes:
        - name: pgdata
          hostPath:
            path: /var/lib/postgresql
      restartPolicy: Never
```

**Generated Job:**

When `action_request` arrives with `action: hooks/db-backup`, plexd creates:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: plexd-db-backup-exec-a1b2c3d4
  namespace: plexd-system
  labels:
    plexd.plexsphere.com/hook: db-backup
    plexd.plexsphere.com/execution-id: exec_a1b2c3d4
  ownerReferences:
    - apiVersion: plexd.plexsphere.com/v1alpha1
      kind: PlexdHook
      name: db-backup
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 600
  template:
    spec:
      nodeSelector:
        kubernetes.io/hostname: worker-03
      serviceAccountName: plexd-hook-runner
      containers:
        - name: backup
          image: registry.example.com/tools/pg-backup:2.1@sha256:abc123...
          command: ["/usr/local/bin/pg-backup.sh"]
          env:
            - name: PLEXD_PARAM_BUCKET
              value: "s3://backups/prod"
            - name: PLEXD_PARAM_COMPRESS
              value: "true"
            - name: PLEXD_EXECUTION_ID
              value: "exec_a1b2c3d4"
            - name: PLEXD_ACTION_NAME
              value: "db-backup"
          resources:
            limits:
              cpu: "1"
              memory: 512Mi
          volumeMounts:
            - name: pgdata
              mountPath: /var/lib/postgresql
              readOnly: true
      volumes:
        - name: pgdata
          hostPath:
            path: /var/lib/postgresql
      restartPolicy: Never
```

plexd pins the Job to the target node via `nodeSelector`, injects parameters as `PLEXD_PARAM_*` environment variables, and sets an `ownerReference` to the `PlexdHook` CR for garbage collection.

**Result Mapping:**

plexd watches the Job and maps its status to the action callback:

| Job Condition | Callback Status | Notes |
|---|---|---|
| Succeeded | `success` | Exit code 0 |
| Failed | `failure` | Exit code from container termination state |
| `activeDeadlineSeconds` exceeded | `timeout` | Job killed by Kubernetes |

Stdout and stderr are captured from the pod logs via the Kubernetes API.

**Privileged Hooks:**

Hooks that need host-level access (e.g. `hostPID`, `hostNetwork`) must set `privileged: true` in the `PlexdHook` spec. This is a declaration of intent - the platform can enforce approval policies before allowing privileged hooks to run.

```yaml
apiVersion: plexd.plexsphere.com/v1alpha1
kind: PlexdHook
metadata:
  name: network-diag
  namespace: plexd-system
spec:
  description: "Host-level network diagnostics"
  privileged: true
  timeout: 60s
  jobTemplate:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: diag
          image: registry.example.com/tools/net-diag:1.0@sha256:def456...
          command: ["/diag.sh"]
          securityContext:
            privileged: true
      restartPolicy: Never
```

**Comparison: Script Hooks vs. CRD Hooks**

| | Script Hooks (bare-metal/VM) | CRD Hooks (Kubernetes) |
|---|---|---|
| Definition | `config.yaml` + file in `hooks.d/` | `PlexdHook` custom resource |
| Isolation | Sandbox level (`none`/`namespaced`/`container`) | Always a separate Pod |
| Integrity | SHA-256 file checksum | Image digest (`@sha256:...`) |
| Cleanup | plexd kills process on timeout | Kubernetes GC via ownerReference + TTL |
| Observability | stdout/stderr capture | Native Pod logs + Events |
| Secrets | Environment variables from plexd | Native Kubernetes Secrets/ConfigMaps |
| Resource Limits | cgroup configuration | Native Kubernetes `resources` |
| Access Control | Unix user + file permissions | Kubernetes RBAC + ServiceAccount |
| Host Access | Sandbox options | `privileged: true` + securityContext |

**Required RBAC:**

The plexd DaemonSet ServiceAccount needs additional permissions for CRD-based hooks:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: plexd-hooks
rules:
  - apiGroups: ["plexd.plexsphere.com"]
    resources: ["plexdhooks"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list", "watch", "delete"]
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]
```

### Hook Checksums & Integrity

plexd computes SHA-256 checksums for all declared hook scripts to detect unauthorized modifications. On Kubernetes, image digests (`@sha256:...`) in the `PlexdHook` job template serve the same purpose - plexd reports the pinned digest as the hook checksum and rejects execution if the digest is missing or has been changed in the CR.

**Checksum Lifecycle:**

1. **Startup** - Compute SHA-256 for every declared hook file. Report checksums as part of capability announcement.
2. **Runtime Monitoring** - An inotify watcher monitors `/etc/plexd/hooks.d/` for file changes. On modification, checksums are recomputed and a capability update is sent to the control plane.
3. **Pre-Execution Verification** - Before every hook execution, plexd recomputes the file's SHA-256 and compares it against the last announced checksum. On mismatch, execution is refused and an integrity alert is sent to the control plane.

**Integrity Alert:**

If a checksum mismatch is detected, plexd:
- Refuses to execute the hook
- Reports an `integrity_violation` event to the control plane
- Logs the expected and actual checksums at `error` level

### Binary Integrity

plexd verifies its own binary integrity using SHA-256.

1. **Startup** - Compute SHA-256 of `/proc/self/exe`.
2. **Registration** - Include the binary checksum in the `POST /v1/register` payload.
3. **Heartbeat** - Include the binary checksum in every heartbeat.
4. **Capability Updates** - Include the binary checksum in `PUT /v1/nodes/{node_id}/capabilities`.

The control plane compares the reported checksum against known-good checksums for each plexd version. A mismatch triggers a security alert.

### Capability Announcement

When plexd registers or when its capabilities change (e.g. hooks added/removed, binary updated), it announces its full capability set to the control plane.

**Registration (`POST /v1/register`) - Extended Payload:**

```json
{
  "token": "plx_enroll_a8f3c7...",
  "public_key": "...",
  "hostname": "web-01",
  "metadata": { ... },
  "capabilities": {
    "binary": {
      "version": "1.4.2",
      "checksum": "sha256:a1b2c3d4e5f6..."
    },
    "builtin_actions": [
      {
        "name": "diagnostics.collect",
        "description": "Collect system diagnostics",
        "parameters": [
          { "name": "include_network", "type": "bool", "required": false, "default": "true" },
          { "name": "include_processes", "type": "bool", "required": false, "default": "true" }
        ]
      }
    ],
    "hooks": [
      {
        "name": "backup",
        "description": "Run incremental backup of application data",
        "source": "script",
        "checksum": "sha256:f7e8d9c0b1a2...",
        "parameters": [
          { "name": "target", "type": "string", "required": true },
          { "name": "compress", "type": "bool", "required": false, "default": "true" }
        ],
        "timeout": "300s",
        "sandbox": "namespaced"
      },
      {
        "name": "db-backup",
        "description": "PostgreSQL backup to S3",
        "source": "crd",
        "checksum": "sha256:abc123...",
        "parameters": [
          { "name": "bucket", "type": "string", "required": true },
          { "name": "compress", "type": "bool", "required": false, "default": "true" }
        ],
        "timeout": "600s",
        "privileged": false
      }
    ]
  }
}
```

**Runtime Capability Update:**

```
PUT /v1/nodes/{node_id}/capabilities
```

Used when capabilities change after initial registration (e.g. hook files added/removed/modified, `PlexdHook` CRs created/updated/deleted, plexd binary updated). Same `capabilities` payload structure as in the registration request.

**Data Model:**

| Type | Fields |
|---|---|
| `BinaryInfo` | `version`, `checksum` |
| `ActionCapability` | `name`, `description`, `parameters[]` |
| `HookCapability` | `name`, `description`, `source` (`script` or `crd`), `checksum`, `parameters[]`, `timeout`, `sandbox` (script) / `privileged` (crd) |
| `ParameterDef` | `name`, `type`, `required`, `default`, `description` |

### Execution Flow & Callback

```
Control Plane                          plexd                          Hook/Action
     │                                  │                                │
     │── SSE: action_request ──────────►│                                │
     │   (signed envelope)              │── Verify Ed25519 signature     │
     │                                  │── Validate (nonce, staleness)  │
     │                                  │── Verify integrity (hooks)     │
     │◄── POST .../ack ─────────────────│                                │
     │    { status: "accepted" }        │                                │
     │                                  │── Execute ────────────────────►│
     │                                  │                                │── run
     │                                  │◄── exit code + stdout/stderr ──│
     │◄── POST .../result ──────────────│                                │
     │    { status, exit_code,          │                                │
     │      stdout, stderr, duration }  │                                │
```

**ACK/NACK (immediate):**

```
POST {callback_url}/ack

{
  "execution_id": "exec_a1b2c3d4",
  "status": "accepted",       // or "rejected"
  "reason": ""                 // Reason if rejected (e.g. "unknown action", "integrity violation")
}
```

**Result (asynchronous):**

```
POST {callback_url}/result

{
  "execution_id": "exec_a1b2c3d4",
  "status": "success",         // success, failure, timeout, cancelled
  "exit_code": 0,
  "stdout": "...",             // Truncated to 64 KiB
  "stderr": "...",             // Truncated to 64 KiB
  "duration": "2.34s",
  "finished_at": "2025-01-15T10:30:02Z"
}
```

**Retry & Persistence:**

- If the callback POST fails, plexd retries with exponential backoff (1s, 2s, 4s, ... up to 5 minutes).
- Pending results are persisted to `data_dir` and re-delivered when the SSE connection is re-established.

### Sandbox Options

Hooks can run in one of three sandbox levels, configured per hook:

| Level | Isolation | Description |
|---|---|---|
| `none` | Minimal | cgroup resource limits, runs as configured `user` |
| `namespaced` | Medium | PID and mount namespaces, read-only root filesystem, writable paths via whitelist |
| `container` | High | Ephemeral OCI container (requires container runtime on the node) |

**No sandbox (`none`) details:**

```yaml
sandbox: none
sandbox_options:
  cpu: "1.0"             # CPU limit (cgroup v2 cpu.max)
  memory: 512M           # Memory limit (cgroup v2 memory.max)
```

The hook process runs directly on the host as the configured `user`. Only cgroup-based resource limits (CPU, memory) are applied. The process has full access to the filesystem and network. Use this level only for trusted hooks that require broad system access.

**Namespace sandbox (`namespaced`) details:**

```yaml
sandbox: namespaced
sandbox_options:
  writable_paths:
    - /tmp
    - /var/backups
  mount_proc: true
  allowed_devices: []
```

The hook runs in isolated PID and mount namespaces. The root filesystem is mounted read-only; only explicitly listed `writable_paths` are bind-mounted as writable. `/proc` is optionally mounted (for process inspection). Network access is inherited from the host. cgroup limits are applied on top.

**Container sandbox (`container`) details:**

```yaml
sandbox: container
sandbox_options:
  image: ""              # OCI image (optional, uses host rootfs if empty)
  writable_paths:
    - /tmp
  network: none          # none | host (default: none)
  capabilities: []       # Additional Linux capabilities (e.g. NET_RAW)
```

The hook runs as an ephemeral OCI container using the container runtime available on the node (containerd, podman). If `image` is empty, the host root filesystem is used as the container's rootfs (read-only). Network isolation defaults to `none` (no network access). This provides the strongest isolation for untrusted or third-party hooks.

### Session-Based Action Authorization

Actions triggered via the control plane SSE stream are implicitly authorized - the control plane has already verified permissions before dispatching. Actions triggered locally via `plexd actions run` in an SSH session require explicit authorization through a session-scoped JWT.

**Authorization Flow:**

```
User                Platform / CP              plexd (Target Node)
 │                       │                            │
 │── Request SSH ───────►│                            │
 │   session             │── Check RBAC               │
 │                       │   (user × node × actions)  │
 │                       │                            │
 │                       │── Issue session JWT        │
 │                       │   { sub, node_id,          │
 │                       │     actions, exp }         │
 │                       │                            │
 │                       │── SSH setup via SSE ──────►│
 │                       │   (includes session token) │── Start SSH session
 │◄════════ SSH session (tunneled through mesh) ═════►│── Inject PLEXD_SESSION_TOKEN
 │                       │                            │
 │── plexd actions run ──────────────────────────────►│
 │   diagnostics.collect │                            │── Read token from env
 │                       │                            │── Validate JWT (local)
 │                       │                            │── Check action scope
 │                       │                            │── Execute
 │◄── Result ─────────────────────────────────────────│
 │                       │◄── Callback (result + ─────│
 │                       │    session context)        │
```

**Session JWT Structure:**

```json
{
  "iss": "plexsphere",
  "sub": "user_abc123",
  "email": "admin@example.com",
  "node_id": "n_xyz789",
  "session_id": "sess_a1b2c3",
  "actions": [
    "diagnostics.*",
    "health.check",
    "hooks/backup"
  ],
  "iat": 1705312200,
  "exp": 1705341000
}
```

The JWT is signed with the control plane's Ed25519 key. plexd receives the corresponding public key during registration and uses it for local validation - no roundtrip required.

**Action Scope Patterns:**

| Pattern | Matches |
|---|---|
| `*` | All actions and hooks |
| `diagnostics.*` | All actions in the `diagnostics` namespace |
| `hooks/*` | All hooks (script and CRD) |
| `hooks/backup` | Only the `backup` hook |
| `health.check` | Exactly one action |

**Local Transport - Unix Socket:**

The `plexd actions run` CLI does not execute actions directly. It connects to the plexd daemon via a Unix socket (`/var/run/plexd.sock`), which ensures that locally triggered actions go through the same path as SSE-triggered ones: token validation, integrity checks, sandbox, resource limits, and audit.

```
plexd actions run diagnostics.collect --param include_network=true
       │
       │── Unix socket (/var/run/plexd.sock) ──► plexd daemon
                                                    ├── Validate session JWT
                                                    ├── Check action scope
                                                    ├── Verify hook integrity
                                                    ├── Apply sandbox + limits
                                                    ├── Execute
                                                    └── Report to control plane
```

**Authorization Tiers:**

| Trigger | Authentication | Authorization | Audit |
|---|---|---|---|
| SSE (control plane) | Authenticated SSE stream | Pre-authorized by control plane | `triggered_by.type: "control_plane"` |
| SSH via access proxy | `PLEXD_SESSION_TOKEN` (JWT) | Local JWT validation + action scope check | `triggered_by.type: "session"` with user identity |
| Direct SSH (no token) | No token present | Denied (or control-plane roundtrip if online) | `triggered_by.type: "direct_access"` |
| Local root access | `--local` flag, root or plexd user only | No scope limit, emergency use | `triggered_by.type: "local_emergency"` |

**Token Revocation:**

When an SSH session ends (disconnect, admin termination, timeout), the control plane pushes a `session_revoked` SSE event:

```json
{
  "session_id": "sess_a1b2c3",
  "revoked_at": "2025-01-15T12:00:00Z"
}
```

plexd adds the `session_id` to a local revocation set (bounded, TTL = maximum token lifetime). Subsequent action requests using a revoked session token are rejected immediately.

**Result Callback with Session Context:**

Actions triggered from an SSH session include the session context in the result callback, providing a full audit trail:

```json
{
  "execution_id": "exec_a1b2c3d4",
  "status": "success",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "...",
  "duration": "2.34s",
  "finished_at": "2025-01-15T10:30:02Z",
  "triggered_by": {
    "type": "session",
    "session_id": "sess_a1b2c3",
    "user_id": "user_abc123",
    "email": "admin@example.com"
  }
}
```

The `triggered_by.type` field distinguishes the origin: `control_plane`, `session`, `direct_access`, or `local_emergency`.

### Security Considerations

- **Signed delivery** - All SSE events (including `action_request`, `peer_added`, `peer_removed`, `rotate_keys`, etc.) are signed with the control plane's Ed25519 key. plexd verifies every signature before processing. Local action requests via Unix socket require a valid session JWT.
- **Replay protection** - Every SSE event includes `issued_at` (max staleness: 5 minutes) and `nonce` (tracked in bounded set). Signature verification, staleness, and nonce checks are applied uniformly to all event types.
- **Hook file permissions** - plexd verifies that hook files are owned by root and not group- or other-writable before execution.
- **Symlink protection** - Hook paths are resolved and validated to prevent symlink escape outside the configured hooks directory.
- **Checksum enforcement** - Hook checksums are verified before every execution. Binary checksums are reported continuously. On Kubernetes, image digests serve as checksums - hooks without pinned digest (`@sha256:...`) are rejected.
- **Resource isolation** - Hooks run with cgroup limits at minimum; higher sandbox levels add namespace or container isolation. On Kubernetes, hooks always run as separate Pods with native resource limits.
- **CRD privilege control** - Kubernetes hooks requiring host-level access (`hostPID`, `hostNetwork`, `privileged`) must declare `privileged: true` in the `PlexdHook` spec. The platform can enforce approval policies.
- **Session token scoping** - JWTs are bound to a specific node (`node_id` claim) and a specific set of actions (`actions` claim). Tokens cannot be used on other nodes or for unauthorized actions.
- **Session revocation** - When an SSH session ends, the control plane pushes `session_revoked` via SSE. plexd maintains a local revocation set to reject tokens from terminated sessions.
- **Local emergency access** - `plexd actions run --local` requires root or plexd user, bypasses JWT authorization, but is logged as `local_emergency` and reported to the control plane.

## Local Node API

### Overview

Local workloads, scripts, and operators need access to node information assigned by PlexSphere (metadata, configuration data, secrets) as well as a channel to report information back upstream. The Local Node API provides this bidirectional data exchange between the node and the control plane, consumable either via a Unix socket API (bare-metal/VM) or a PlexdNodeState CRD (Kubernetes).

**Downstream (Control Plane → Node):**

- `metadata` -- String key-value pairs (labels, tags, environment, role) managed by the control plane
- `data` -- Named entries with arbitrary JSON payload (opaque to plexd)
- `secrets` -- Named secret values (credentials, tokens, certificates), envelope-encrypted with a per-node key and served in real-time (never cached in plaintext)

**Upstream (Node → Control Plane):**

- `report` -- Named entries with arbitrary JSON payload, written locally by workloads

### Data Model

Each `data`, `secret`, and `report` entry follows a common envelope structure:

```json
{
  "key": "database-config",
  "content_type": "application/json",
  "payload": { "host": "db.internal", "port": 5432 },
  "version": 3,
  "updated_at": "2025-01-15T10:30:00Z"
}
```

| Field | Type | Description |
|---|---|---|
| `key` | string | Unique name within its category (metadata, data, secrets, report) |
| `content_type` | string | MIME type of the payload (e.g. `application/json`, `text/plain`) |
| `payload` | any | Opaque JSON value - plexd does not interpret the content |
| `version` | integer | Monotonically increasing version, set by the writer (control plane or node) |
| `updated_at` | string | ISO 8601 timestamp of the last update |

Metadata entries are simpler key-value pairs (`map[string]string`) without the envelope structure.

### Secret Encryption (NSK)

Secret values are protected by **envelope encryption** using a per-node symmetric key:

1. During [registration](#phase-1-registration), the control plane generates a random 256-bit AES key -- the **Node Secret Key (NSK)** -- and delivers it to the node in the registration response over authenticated TLS.
2. The NSK is stored in `data_dir` with `0600` permissions, alongside the node's private key.
3. When the control plane serves a secret value (via `GET /v1/nodes/{node_id}/secrets/{key}`), it encrypts the plaintext with `AES-256-GCM(NSK, random-nonce)` before sending the response. The response contains the ciphertext and the GCM nonce.
4. plexd decrypts the value in memory using the local NSK and serves the plaintext to the authorized caller. **The plaintext is never written to disk.**
5. The NSK is rotated together with mesh keys (via `rotate_keys`) or independently. On rotation, the control plane generates a new NSK, delivers it over the authenticated channel, and plexd replaces the old NSK on disk.

```
Consumer          plexd (Node)                    Control Plane
  │                  │                                  │
  │── GET secret ───►│                                  │
  │                  │── GET /v1/.../secrets/{key} ────►│
  │                  │                                  │── Encrypt(NSK, value)
  │                  │◄── { ciphertext, nonce } ────────│
  │                  │── Decrypt(NSK, ciphertext)       │
  │◄── plaintext ────│                                  │
  │                  │   (plaintext only in memory,     │
  │                  │    never persisted)               │
```

This design ensures that:
- **Network interception** (even with TLS compromise) yields only NSK-encrypted ciphertext
- **Disk access** on the node reveals no secret plaintext (values are never cached)
- **Socket/CRD access** without the NSK yields nothing usable (K8s Secrets contain only ciphertext)
- **Control plane access control** is enforced on every secret read (real-time fetch, no stale cache)

### Non-Kubernetes: Unix Socket API

On bare-metal and VM nodes, the Node API is served over HTTP/1.1 on a Unix socket (default `/var/run/plexd/api.sock`). This is a separate socket from the existing Actions socket.

**Endpoints:**

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/state` | Full node state summary (metadata + data keys + report keys) |
| `GET` | `/v1/state/metadata` | All metadata key-value pairs |
| `GET` | `/v1/state/metadata/{key}` | Single metadata value |
| `GET` | `/v1/state/data` | List all data entry keys with versions |
| `GET` | `/v1/state/data/{key}` | Single data entry (full envelope) |
| `GET` | `/v1/state/secrets` | List secret names and versions (no values, served from local cache) |
| `GET` | `/v1/state/secrets/{key}` | Single secret value (real-time fetch from control plane, decrypted on-the-fly; requires elevated access) |
| `GET` | `/v1/state/report` | List all report entry keys with versions |
| `GET` | `/v1/state/report/{key}` | Single report entry |
| `PUT` | `/v1/state/report/{key}` | Create or update a report entry |
| `DELETE` | `/v1/state/report/{key}` | Delete a report entry |

**Access control:**

- Metadata, data, and report endpoints require membership in the `plexd` group (enforced via socket file permissions)
- Secret endpoints require membership in the `plexd-secrets` group or root privileges
- When using the optional TCP listener (`node_api.http`), all requests require a `Authorization: Bearer <token>` header

**Secret real-time fetch:**

Secret values are **never cached in plaintext** on the node. When a client requests `GET /v1/state/secrets/{key}`, plexd proxies the request to the control plane in real-time (`GET /v1/nodes/{node_id}/secrets/{key}`), decrypts the response using the node's secret encryption key (NSK), and returns the plaintext to the authorized caller. If the control plane is unreachable, the endpoint returns `503 Service Unavailable`. This is an explicit security trade-off: secret access requires live control plane connectivity.

Only secret names and versions are cached locally (in `data_dir/state/secrets.json`) for the listing endpoint (`GET /v1/state/secrets`).

**Examples:**

```bash
# Read all metadata
curl --unix-socket /var/run/plexd/api.sock http://localhost/v1/state/metadata

# Read a specific data entry
curl --unix-socket /var/run/plexd/api.sock http://localhost/v1/state/data/database-config

# Write a report entry
curl --unix-socket /var/run/plexd/api.sock \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"content_type":"application/json","payload":{"status":"healthy","checked_at":"2025-01-15T10:30:00Z"}}' \
  http://localhost/v1/state/report/app-health

# Delete a report entry
curl --unix-socket /var/run/plexd/api.sock \
  -X DELETE \
  http://localhost/v1/state/report/app-health

# Read a secret (requires plexd-secrets group, fetched from control plane in real-time)
curl --unix-socket /var/run/plexd/api.sock http://localhost/v1/state/secrets/tls-cert

# Via TCP listener (with bearer token)
curl -H "Authorization: Bearer $(cat /etc/plexd/node-api-token)" \
  http://127.0.0.1:9100/v1/state/metadata
```

**Optimistic concurrency:**

Write operations on report entries support optimistic concurrency via the `If-Match` header. The header value is the `version` of the entry the client last read. If the current version does not match, the server responds with `409 Conflict`.

```bash
# Read current version
curl --unix-socket /var/run/plexd/api.sock http://localhost/v1/state/report/app-health
# Response includes "version": 5

# Update with version check
curl --unix-socket /var/run/plexd/api.sock \
  -X PUT \
  -H "Content-Type: application/json" \
  -H "If-Match: 5" \
  -d '{"content_type":"application/json","payload":{"status":"degraded"}}' \
  http://localhost/v1/state/report/app-health
```

### Kubernetes: PlexdNodeState CRD

On Kubernetes, plexd manages a `PlexdNodeState` custom resource for metadata, data, and report entries. Workloads interact with non-secret state through the standard Kubernetes API. For secrets, plexd exposes a node-local decryption API -- Kubernetes Secrets referenced by the CRD contain only NSK-encrypted ciphertext, not plaintext.

**CRD Definition:**

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: plexdnodestates.plexd.plexsphere.com
spec:
  group: plexd.plexsphere.com
  names:
    kind: PlexdNodeState
    listKind: PlexdNodeStateList
    plural: plexdnodestates
    singular: plexdnodestate
    shortNames:
      - pns
  scope: Namespaced
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                nodeId:
                  type: string
                meshIp:
                  type: string
                metadata:
                  type: object
                  additionalProperties:
                    type: string
                data:
                  type: array
                  items:
                    type: object
                    properties:
                      key:
                        type: string
                      contentType:
                        type: string
                      payload:
                        x-kubernetes-preserve-unknown-fields: true
                      version:
                        type: integer
                      updatedAt:
                        type: string
                        format: date-time
                secretRefs:
                  type: array
                  items:
                    type: object
                    properties:
                      key:
                        type: string
                      secretName:
                        type: string
                      version:
                        type: integer
            status:
              type: object
              properties:
                report:
                  type: array
                  items:
                    type: object
                    properties:
                      key:
                        type: string
                      contentType:
                        type: string
                      payload:
                        x-kubernetes-preserve-unknown-fields: true
                      version:
                        type: integer
                      updatedAt:
                        type: string
                        format: date-time
      subresources:
        status: {}
      additionalPrinterColumns:
        - name: Node ID
          type: string
          jsonPath: .spec.nodeId
        - name: Mesh IP
          type: string
          jsonPath: .spec.meshIp
        - name: Data Entries
          type: integer
          jsonPath: .spec.data[*].key
        - name: Age
          type: date
          jsonPath: .metadata.creationTimestamp
```

**Example Resource:**

```yaml
apiVersion: plexd.plexsphere.com/v1alpha1
kind: PlexdNodeState
metadata:
  name: node-n-abc123
  namespace: plexd-system
  labels:
    plexd.plexsphere.com/node-id: n_abc123
spec:
  nodeId: n_abc123
  meshIp: 10.100.1.5
  metadata:
    environment: production
    region: eu-west-1
    role: worker
  data:
    - key: database-config
      contentType: application/json
      payload:
        host: db.internal
        port: 5432
        database: myapp
      version: 3
      updatedAt: "2025-01-15T10:30:00Z"
    - key: feature-flags
      contentType: application/json
      payload:
        enable_new_ui: true
        max_connections: 100
      version: 7
      updatedAt: "2025-01-15T11:00:00Z"
  secretRefs:
    - key: tls-cert
      secretName: plexd-secret-n-abc123-tls-cert
      version: 2
    - key: api-token
      secretName: plexd-secret-n-abc123-api-token
      version: 1
status:
  report:
    - key: app-health
      contentType: application/json
      payload:
        status: healthy
        checked_at: "2025-01-15T10:30:00Z"
      version: 12
      updatedAt: "2025-01-15T10:30:00Z"
```

**Secrets handling:**

Secrets are stored as native Kubernetes Secrets with `ownerReferences` pointing to the `PlexdNodeState` resource. This ensures secrets are garbage-collected when the node state is deleted. **Important:** The Kubernetes Secret contains the NSK-encrypted ciphertext, not the plaintext value. Reading the Secret directly yields unusable encrypted data.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: plexd-secret-n-abc123-tls-cert
  namespace: plexd-system
  ownerReferences:
    - apiVersion: plexd.plexsphere.com/v1alpha1
      kind: PlexdNodeState
      name: node-n-abc123
      uid: <uid>
  annotations:
    plexd.plexsphere.com/encrypted: "true"
    plexd.plexsphere.com/encryption-algorithm: AES-256-GCM
type: Opaque
data:
  value: <base64-encoded-NSK-encrypted-ciphertext>
  nonce: <base64-encoded-GCM-nonce>
```

The `PlexdNodeState` `.spec.secretRefs` array lists the secret names and versions. To obtain plaintext values, workloads must call plexd's node-local decryption API rather than reading the Kubernetes Secret directly.

**Node-local decryption API (Kubernetes):**

On Kubernetes, plexd's DaemonSet pod exposes a decryption endpoint for workloads on the same node. This follows the same pattern as node-local DNS or kube-proxy:

| Access method | Configuration | Use case |
|---|---|---|
| Host-network socket | `/var/run/plexd/api.sock` mounted via `hostPath` | Pods with host path access |
| Node-local HTTP | `http://<node-ip>:9100/v1/state/secrets/{key}` via `hostPort` | General pod access, requires bearer token |

Workloads call `GET /v1/state/secrets/{key}` on the node-local endpoint. plexd verifies the caller's authorization (bearer token or ServiceAccount identity), fetches the encrypted value from the control plane in real-time, decrypts with the NSK, and returns the plaintext. Like on bare-metal, the call fails with `503` if the control plane is unreachable.

```bash
# From a pod on the same node (using the Kubernetes node internal IP)
curl -H "Authorization: Bearer $(cat /var/run/secrets/plexd/token)" \
  http://${NODE_IP}:9100/v1/state/secrets/tls-cert
```

plexd validates the bearer token against the Kubernetes TokenReview API to verify the caller's ServiceAccount and namespace before serving the decrypted secret.

**RBAC:**

```yaml
# Read access to PlexdNodeState spec (metadata, data, secretRefs)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: plexd-state-reader
  namespace: plexd-system
rules:
  - apiGroups: ["plexd.plexsphere.com"]
    resources: ["plexdnodestates"]
    verbs: ["get", "list", "watch"]

---
# Write access to PlexdNodeState status (report entries)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: plexd-state-reporter
  namespace: plexd-system
rules:
  - apiGroups: ["plexd.plexsphere.com"]
    resources: ["plexdnodestates/status"]
    verbs: ["get", "patch"]

---
# Read access to plexd-managed secrets (encrypted ciphertext only -- plaintext requires decryption API)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: plexd-secrets-reader
  namespace: plexd-system
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: []  # Scoped to specific secret names by the operator
    verbs: ["get"]
```

> **Note:** The `plexd-secrets-reader` role grants access to the Kubernetes Secret objects, but these contain only NSK-encrypted ciphertext. For plaintext access, workloads must call plexd's node-local decryption API with a valid bearer token. This two-layer model ensures that neither Kubernetes RBAC alone nor socket/network access alone is sufficient to read secret values.

The `.spec` (including `nodeId`, `meshIp`, `metadata`, `data`, `secretRefs`) is managed exclusively by plexd. Workloads write upstream data by patching `.status.report` via the status subresource, which has separate RBAC from the main resource.

### Data Sync Protocol

**Downstream sync (Control Plane → Node):**

1. On initial connect, plexd fetches the full node state from `GET /v1/nodes/{node_id}/state` (the same reconciliation endpoint, extended with `metadata`, `data`, and `secretRefs` fields). Secret values are not included -- only names and versions.
2. During steady state, the control plane pushes `node_state_updated` and `node_secrets_updated` SSE events when state changes.
3. `node_state_updated` contains the updated metadata and data entries inline (same signed envelope as all SSE events).
4. `node_secrets_updated` contains only secret names and versions - **never secret values** (neither plaintext nor ciphertext). This event updates the local secret index so that listing endpoints reflect the current state.
5. Secret values are fetched **on demand** when a consumer requests them via `GET /v1/state/secrets/{key}`. plexd proxies to `GET /v1/nodes/{node_id}/secrets/{key}` on the control plane, which returns the NSK-encrypted ciphertext. plexd decrypts with the local NSK and returns the plaintext to the authorized caller. No plaintext is persisted.
6. The reconciliation loop compares local state cache (metadata, data, secret index) against the control plane, correcting any drift. Secret values are not part of reconciliation -- they are always fetched live.

**Upstream sync (Node → Control Plane):**

1. When a workload writes a report entry (via Unix socket API or CRD status patch), plexd buffers the change locally.
2. After a debounce period (default 5s), plexd syncs the report to the control plane via `POST /v1/nodes/{node_id}/report`.
3. If the control plane is unreachable, report entries are buffered in `data_dir/state/report/` and drained when connectivity is restored.
4. The sync payload includes all changed report entries since the last successful sync.

**Offline behavior:**

- The local state cache in `data_dir/state/` survives agent restarts and control plane outages
- Workloads can read cached metadata and data entries even when the control plane is unreachable
- **Secrets are unavailable offline** -- since secret values are fetched in real-time from the control plane and never cached in plaintext, `GET /v1/state/secrets/{key}` returns `503 Service Unavailable` when the control plane is unreachable. This is an explicit security trade-off.
- Report entries are buffered locally and synced when connectivity is restored
- On Kubernetes, the `PlexdNodeState` resource (metadata, data, report) persists in etcd independently of the control plane. Kubernetes Secrets contain only encrypted ciphertext and remain in etcd, but cannot be decrypted without the control plane (since decryption requires a live fetch to verify authorization).

**File cache structure:**

```
data_dir/state/
├── metadata.json          # Cached metadata key-value pairs
├── data/
│   ├── database-config.json
│   └── feature-flags.json
├── secrets.json           # Secret index only (names + versions, NO values)
└── report/
    └── app-health.json    # Locally written, pending sync
```

> **Note:** Secret values are never written to the file cache. Only the secret index (names and versions) is persisted for the listing endpoint. Plaintext values exist only in memory during the brief window between decryption and response delivery.

### Comparison: Socket API vs. CRD

| Aspect | Unix Socket API | PlexdNodeState CRD |
|---|---|---|
| **Platform** | Bare-metal, VM | Kubernetes |
| **Read access** | `curl --unix-socket` / HTTP client | `kubectl get pns` / client-go / watch |
| **Write access (report)** | `PUT /v1/state/report/{key}` | Status subresource patch |
| **Secret access** | Real-time fetch via plexd proxy, `plexd-secrets` group or bearer token | Real-time fetch via plexd node-local API, bearer token (K8s Secrets contain only NSK-encrypted ciphertext) |
| **Access control** | File permissions (groups) | Kubernetes RBAC |
| **Offline resilience** | File cache in `data_dir/state/` | CRD persists in etcd |
| **Change notification** | Poll or watch `Last-Modified` header | Kubernetes watch on CRD |
| **Concurrency control** | `If-Match` header (optimistic) | Kubernetes resource version (optimistic) |

### Security Considerations

- **Envelope encryption (NSK)** - All secret values are encrypted with a per-node AES-256-GCM key (Node Secret Key) before leaving the control plane. The NSK is generated during registration and delivered to the node over authenticated TLS. Even if TLS is compromised or an attacker gains access to the Unix socket, CRD, or Kubernetes Secret objects, they only see ciphertext without the NSK.
- **No plaintext at rest** - Secret values are never written to disk or etcd in plaintext. The file cache stores only the secret index (names + versions). On Kubernetes, Secret objects contain NSK-encrypted ciphertext. Plaintext exists only transiently in plexd's process memory during decryption and response delivery.
- **Real-time fetch** - Secret values are fetched from the control plane on every access, not cached. This ensures the control plane remains the authoritative source and can enforce access policies, audit access, and revoke secrets in real-time. The trade-off is that secrets are unavailable when the control plane is unreachable (503).
- **Two-layer access control** - Access to decrypted secrets requires both: (1) authorization at the plexd API level (Unix socket group membership or bearer token), and (2) live connectivity to the control plane. Neither layer alone is sufficient. On Kubernetes, even RBAC access to the K8s Secret objects only yields encrypted ciphertext.
- **Transport security** - All control plane communication (state fetch, secret fetch, report sync) uses TLS-encrypted HTTPS. The NSK encryption layer provides defense-in-depth: secrets remain protected even if TLS is compromised. The Unix socket is local-only and protected by filesystem permissions.
- **Least privilege** - The CRD splits `.spec` (plexd-managed) from `.status` (workload-writable) using the Kubernetes status subresource. Workloads that need to write reports do not need write access to the node's metadata, data, or secret references.
- **Secret rotation** - When secrets are updated on the control plane, `node_secrets_updated` updates the local secret index. Since values are fetched in real-time, the next access automatically returns the new value. No local cache invalidation is needed.
- **NSK rotation** - The NSK is rotated together with mesh keys via the `rotate_keys` flow, or independently via a dedicated `rotate_nsk` control plane API. During rotation, the control plane re-encrypts all secrets for the node with the new NSK.
- **Owner references** - On Kubernetes, plexd-managed Secrets have `ownerReferences` to the `PlexdNodeState` resource, ensuring cleanup on node deregistration.
- **Cache integrity** - The file cache in `data_dir/state/` inherits the `data_dir` permissions (`0700`, owned by `plexd` user). The NSK is stored in `data_dir` with `0600` permissions, accessible only to the plexd process.

## Development

### Prerequisites

- Go 1.22+
- WireGuard tools (`wg`, `wg-quick`)
- nftables
- Docker (for integration tests)

### Build

```bash
make build        # Build binary
make test         # Run unit tests
make test-e2e     # Run integration tests (requires Docker)
make lint         # Run linter
```

### Project Structure

```
plexd/
├── cmd/                  # CLI entrypoints
│   └── plexd/
├── internal/
│   ├── agent/            # Core agent lifecycle
│   ├── api/              # Control plane API client
│   ├── mesh/             # Tunnel management
│   ├── nat/              # STUN-based NAT traversal and endpoint discovery
│   ├── policy/           # Policy evaluation and firewall rules
│   ├── reconcile/        # State reconciliation loop
│   ├── registration/     # Token handling and enrollment
│   ├── observe/          # Metrics collection and reporting
│   ├── logs/             # Log collection and forwarding
│   ├── audit/            # System audit collection (auditd, K8s audit logs)
│   ├── access/           # SSH and Kubernetes API access proxy
│   ├── auth/             # Session JWT validation, token revocation, scope matching
│   ├── crypto/           # Ed25519 signature verification, signing key management and rotation
│   ├── actions/          # Built-in action definitions and dispatcher
│   ├── hooks/            # Hook configuration, checksum verification, file watcher
│   ├── execution/        # Action/hook execution engine, sandbox, callbacks
│   ├── bridge/           # Bridge mode: user access, public ingress, site-to-site, relay
│   └── nodeapi/          # Local Node API server, state cache, report sync
├── pkg/                  # Shared library packages
├── deploy/
│   ├── docker/           # Dockerfiles
│   ├── systemd/          # Unit files
│   └── kubernetes/       # DaemonSet manifests, CRDs, RBAC
├── docs/
├── Makefile
└── README.md
```

## Security

- **Bootstrap tokens** are one-time-use with a short TTL. They are deleted from disk after successful registration.
- **Private keys** are generated during registration and stored in `/var/lib/plexd/`. They never leave the node.
- **Control plane communication** is TLS-encrypted (HTTPS). The agent validates the server certificate. Every SSE event is additionally signed with the control plane's Ed25519 key and verified by the agent before processing.
- **Mesh traffic** is encrypted end-to-end via WireGuard.
- **Compromised nodes** can be force-removed from the control plane, triggering key rotation across all affected peers.
- **Hook integrity** is enforced via SHA-256 checksums computed at startup, monitored via inotify, and re-verified before every execution. Mismatches block execution and trigger alerts.
- **Binary verification** - plexd reports its own SHA-256 checksum at registration and with every heartbeat. The control plane compares against known-good checksums per version.

## Key Exchange and Trust Model

plexd uses WireGuard's [Noise_IKpsk2](https://www.wireguard.com/protocol/) handshake with static Curve25519 key pairs. The control plane acts as a trusted key distribution center but never has access to private keys. All events from the control plane (peer changes, policy updates, action requests, key rotations) are signed with an Ed25519 signing key and verified by the agent before processing.

### Trust Chain

```
Bootstrap Token (one-time, short TTL)
        │
        ▼
   Control Plane  ──── Trust anchor: distributes public keys, PSKs,
        │               and its own Ed25519 signing public key
        │
        ├──► Signing Key ──── Verifies all SSE events + session JWTs
        │
        ▼
   Node Identity  ──── Public key bound to node ID and mesh IP
        │
        ▼
   Peer Tunnels   ──── WireGuard E2E encryption (private key stays local)
```

### Phase 1: Registration

During registration the node generates its Curve25519 key pair locally. Only the public key is sent to the control plane. The private key never leaves the node.

```
Client                                    Control Plane
  │                                              │
  │── Generate Curve25519 keypair                │
  │                                              │
  │── POST /v1/register ────────────────────────►│
  │   { token, public_key, hostname,             │── Validate token (one-time)
  │     metadata, capabilities }                 │
  │                                              │── Assign mesh IP (10.100.x.x)
  │                                              │── Store public key
  │                                              │── Generate PSK per peer pair
  │                                              │── Generate Node Secret Key (NSK)
  │◄─────────────────────────────────────────────│
  │   { node_id, mesh_ip,                        │
  │     signing_public_key,                      │
  │     node_secret_key,                         │
  │     peers: [                                 │
  │       { id, public_key, mesh_ip,             │
  │         endpoint, allowed_ips, psk }         │
  │     ] }                                      │
```

### Phase 2: Tunnel Setup

The client configures the local WireGuard interface using the registration response:

1. Create WireGuard interface (`plexd0`)
2. Assign mesh IP and set private key
3. Add each peer with its public key, endpoint, allowed IPs, and PSK
4. Run STUN discovery and report the node's public endpoint to the control plane
5. Receive NAT-discovered endpoints of peers and update WireGuard accordingly

### Phase 3: Steady State

The control plane pushes peer and key updates via SSE. Every SSE event is signed with the control plane's Ed25519 signing key. The client verifies the signature before applying any change.

**Signed Event Envelope:**

Every SSE event is wrapped in a signed envelope. The `signature` covers the canonical JSON serialization of all fields except `signature` itself (i.e. `event_type`, `event_id`, `issued_at`, `nonce`, and `payload`):

```json
{
  "event_type": "peer_added",
  "event_id": "evt_d4e5f6",
  "issued_at": "2025-01-15T10:30:00Z",
  "nonce": "unique-random-nonce-value",
  "payload": {
    "peer_id": "n_peer456",
    "public_key": "...",
    "mesh_ip": "10.100.1.5",
    "endpoint": "203.0.113.10:51820",
    "allowed_ips": ["10.100.1.5/32"],
    "psk": "..."
  },
  "signature": "base64-encoded-ed25519-signature"
}
```

**Verification on every event:**

1. Verify Ed25519 signature over the canonical JSON of all fields except `signature`, using the control plane's signing public key (received during registration).
2. Check `issued_at` staleness (max 5 minutes).
3. Check `nonce` uniqueness (bounded in-memory set with automatic expiry).
4. If any check fails, reject the event and log a security warning.

This ensures that even if the TLS connection is compromised (e.g. through a rogue proxy or certificate authority), events cannot be forged or replayed.

**SSE Events:**

| SSE Event | Client Action |
|---|---|
| `peer_added` | Add peer with public key, endpoint, and PSK |
| `peer_removed` | Remove peer from WireGuard interface |
| `peer_key_rotated` | Replace peer's public key and PSK |
| `peer_endpoint_changed` | Update peer's WireGuard endpoint |
| `policy_updated` | Update local firewall rules |
| `action_request` | Validate, ACK, and execute the requested action (see [Actions & Hooks](#actions--hooks)) |
| `session_revoked` | Add session to local revocation set, reject future actions with that session's token |
| `ssh_session_setup` | Set up SSH session: start listener, inject session token |
| `rotate_keys` | Generate new Curve25519 keypair and initiate key rotation (see [Phase 4: Key Rotation](#phase-4-key-rotation)) |
| `signing_key_rotated` | Update the control plane's signing public key (see [Signing Key Rotation](#signing-key-rotation)) |
| `node_state_updated` | Update local node state cache (metadata, data entries) and notify Node API consumers (see [Local Node API](#local-node-api)) |
| `node_secrets_updated` | Fetch updated secret values from control plane via HTTPS and update local secret store (names and versions only in SSE, never plaintext) |

The reconciliation loop (`reconcile.interval`) periodically pulls the full state from the control plane and corrects any drift between the local WireGuard configuration, node metadata, data entries, secret references, and the desired state.

### Phase 4: Key Rotation

Key rotation is triggered by the control plane - either on a schedule, by admin action, or in response to a compromised node. The `rotate_keys` SSE event is signed like all other events and verified before processing.

```
Client                                    Control Plane
  │                                              │
  │◄── SSE: rotate_keys (signed) ────────────────│
  │                                              │
  │── Verify signature                           │
  │── Generate new Curve25519 keypair            │
  │                                              │
  │── POST /v1/keys/rotate ─────────────────────►│
  │   { node_id, new_public_key }                │── Store new public key
  │                                              │── Generate new PSKs
  │                                              │── Push new key to all peers
  │◄─────────────────────────────────────────────│
  │   { updated_peers }                          │
  │                                              │
  │── Replace private key on WireGuard interface │
  │── Update all peer PSKs                       │
```

When a node is force-removed from the control plane, all peers that had a tunnel to the compromised node receive a `peer_removed` event followed by fresh PSKs for their remaining peer pairs.

### Signing Key Rotation

The control plane's Ed25519 signing key (used for SSE event signatures and session JWTs) can be rotated independently of WireGuard mesh keys. During rotation, both the old and the new key are valid for a transition period.

```
Client                                    Control Plane
  │                                             │
  │◄── SSE: signing_key_rotated ────────────────│
  │   { new_signing_public_key,                 │── Signed with CURRENT key
  │     valid_from,                             │
  │     transition_period: "24h" }              │
  │                                             │
  │── Store new key, keep old key               │
  │   for transition_period                     │
  │                                             │
  │   During transition: accept events          │
  │   signed with either key                    │
  │                                             │
  │   After transition: remove old key,         │
  │   only accept new key                       │
```

The `signing_key_rotated` event is signed with the **current** (old) key, which the node already trusts. This creates a chain of trust - each key vouches for its successor.

### Pre-Shared Keys (PSK)

Each peer pair uses a unique PSK generated by the control plane and distributed to both peers. PSKs provide:

- **Post-quantum resistance:** An additional symmetric key layer on top of the Curve25519 ECDH, protecting against future quantum attacks on elliptic-curve cryptography.
- **Defense in depth:** Even if the Curve25519 key exchange is compromised, the PSK layer prevents decryption.

PSKs are rotated together with the main key pairs and whenever a peer is removed from the mesh.

### Client-Side Implementation

| Module | Responsibility |
|---|---|
| `internal/registration/` | Generate key pair, exchange bootstrap token for node identity |
| `internal/api/` | SSE stream, receive peer updates with public keys and PSKs |
| `internal/mesh/` | WireGuard interface management, apply key and peer configuration |
| `internal/nat/` | STUN discovery, report and receive endpoint updates |
| `internal/reconcile/` | Periodic full-state comparison: local WireGuard config vs. control plane |
| `internal/auth/` | Session JWT validation, token revocation set, action scope matching |
| `internal/crypto/` | Ed25519 event signature verification, signing key storage and rotation |
| `internal/actions/` | Built-in action definitions, action dispatcher, Unix socket listener |
| `internal/hooks/` | Hook configuration, checksum computation, inotify file watcher, CRD controller |
| `internal/execution/` | Action/hook execution engine, sandbox setup, callback delivery |
| `internal/nodeapi/` | Local Node API server (Unix socket + optional TCP), state cache, report sync, PlexdNodeState CRD controller (Kubernetes) |

### Control Plane API Endpoints

plexd requires the following API endpoints on the control plane. All endpoints use the `/v1` prefix and HTTPS. Authentication uses the node's identity token (received during registration) unless noted otherwise. Request and response bodies are JSON (`Content-Type: application/json`) unless noted otherwise.

#### Registration & Identity

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/register` | Register a new node with a bootstrap token |

**`POST /v1/register`** — Authenticated via one-time bootstrap token (not node identity).

Request body:

```json
{
  "token": "plx_enroll_a8f3c7...",
  "public_key": "base64-encoded-curve25519-public-key",
  "hostname": "web-01",
  "metadata": { "os": "linux", "arch": "amd64", "kernel": "6.1.0" },
  "capabilities": {
    "binary": { "version": "1.4.2", "checksum": "sha256:a1b2c3d4e5f6..." },
    "builtin_actions": [ { "name": "...", "description": "...", "parameters": [] } ],
    "hooks": [ { "name": "...", "description": "...", "source": "script", "checksum": "sha256:...", "parameters": [], "timeout": "300s", "sandbox": "namespaced" } ]
  }
}
```

Response (`201 Created`):

```json
{
  "node_id": "n_abc123",
  "mesh_ip": "10.100.1.1",
  "signing_public_key": "base64-encoded-ed25519-public-key",
  "node_secret_key": "base64-encoded-aes-256-key",
  "peers": [
    {
      "id": "n_peer456",
      "public_key": "base64-encoded-curve25519-public-key",
      "mesh_ip": "10.100.1.2",
      "endpoint": "203.0.113.10:51820",
      "allowed_ips": ["10.100.1.2/32"],
      "psk": "base64-encoded-psk"
    }
  ]
}
```

| Response | Meaning |
|---|---|
| `201 Created` | Registration successful |
| `400 Bad Request` | Invalid payload (missing fields, malformed key) |
| `401 Unauthorized` | Invalid, expired, or already-used bootstrap token |
| `409 Conflict` | Node with this hostname already registered in the tenant |

#### SSE Event Stream

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/nodes/{node_id}/events` | Server-Sent Events stream (persistent connection) |

**`GET /v1/nodes/{node_id}/events`** — Long-lived SSE connection. Supports `Last-Event-ID` header for replay after reconnection. Each event is a signed envelope (see [Signed Event Envelope](#phase-3-steady-state)).

Event types delivered on this stream:

| Event Type | Payload Summary |
|---|---|
| `peer_added` | Peer identity, public key, mesh IP, endpoint, allowed IPs, PSK |
| `peer_removed` | Peer ID |
| `peer_key_rotated` | Peer ID, new public key, new PSK |
| `peer_endpoint_changed` | Peer ID, new endpoint |
| `policy_updated` | Full policy ruleset (L3/L4 rules scoped to mesh IPs) |
| `action_request` | Execution ID, action name, type, parameters, timeout, callback URL |
| `session_revoked` | Session ID, revocation timestamp |
| `ssh_session_setup` | Session token, target configuration |
| `rotate_keys` | Key rotation trigger |
| `signing_key_rotated` | New signing public key, valid_from, transition period |
| `node_state_updated` | Updated metadata and data entries |
| `node_secrets_updated` | Updated secret names and versions (never values) |

| Response | Meaning |
|---|---|
| `200 OK` | SSE stream established (text/event-stream) |
| `401 Unauthorized` | Invalid node identity |
| `404 Not Found` | Unknown node ID |

#### Heartbeat

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/nodes/{node_id}/heartbeat` | Periodic heartbeat signal |

**`POST /v1/nodes/{node_id}/heartbeat`** — Sent at `heartbeat.interval` (default 30s).

Request body:

```json
{
  "node_id": "n_abc123",
  "timestamp": "2025-01-15T10:30:00Z",
  "status": "healthy",
  "uptime": "72h15m",
  "binary_checksum": "sha256:a1b2c3d4e5f6...",
  "mesh": {
    "interface": "plexd0",
    "peer_count": 12,
    "listen_port": 51820
  },
  "nat": {
    "public_endpoint": "203.0.113.10:51820",
    "type": "full_cone"
  }
}
```

| Response | Meaning |
|---|---|
| `200 OK` | Heartbeat acknowledged |
| `200 OK` + `{ "reconcile": true }` | Trigger immediate reconciliation |
| `200 OK` + `{ "rotate_keys": true }` | Trigger key rotation |
| `401 Unauthorized` | Node identity invalid, re-register |

#### Deregistration

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/nodes/{node_id}/deregister` | Graceful node unregistration |

**`POST /v1/nodes/{node_id}/deregister`** — Sent on shutdown or explicit `plexd deregister` command. No request body. The control plane removes the node from peer lists and pushes `peer_removed` events to all peers.

| Response | Meaning |
|---|---|
| `200 OK` | Deregistration acknowledged |
| `401 Unauthorized` | Invalid node identity |

#### Key Management

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/keys/rotate` | Submit new public key during key rotation |

**`POST /v1/keys/rotate`** — Called after receiving a `rotate_keys` SSE event.

Request body:

```json
{
  "node_id": "n_abc123",
  "new_public_key": "base64-encoded-curve25519-public-key"
}
```

Response (`200 OK`):

```json
{
  "updated_peers": [
    {
      "id": "n_peer456",
      "public_key": "base64-encoded-curve25519-public-key",
      "mesh_ip": "10.100.1.2",
      "endpoint": "203.0.113.10:51820",
      "allowed_ips": ["10.100.1.2/32"],
      "psk": "base64-encoded-new-psk"
    }
  ]
}
```

#### Capabilities

| Method | Path | Description |
|---|---|---|
| `PUT` | `/v1/nodes/{node_id}/capabilities` | Update node capabilities at runtime |

**`PUT /v1/nodes/{node_id}/capabilities`** — Sent when capabilities change after registration (hooks added/removed, binary updated).

Request body: Same `capabilities` structure as in `POST /v1/register` (see [Capability Announcement](#capability-announcement)).

| Response | Meaning |
|---|---|
| `200 OK` | Capabilities updated |
| `401 Unauthorized` | Invalid node identity |

#### NAT Endpoint Discovery

| Method | Path | Description |
|---|---|---|
| `PUT` | `/v1/nodes/{node_id}/endpoint` | Report NAT-discovered public endpoint |

**`PUT /v1/nodes/{node_id}/endpoint`** — Called after STUN discovery and periodically at `nat_traversal.refresh_interval` (default 60s).

Request body:

```json
{
  "public_endpoint": "203.0.113.10:51820",
  "nat_type": "full_cone"
}
```

Response (`200 OK`):

```json
{
  "peer_endpoints": [
    {
      "peer_id": "n_peer456",
      "endpoint": "198.51.100.5:51820"
    }
  ]
}
```

Returns the NAT-discovered endpoints of all peers that have reported their endpoints, allowing the node to update its WireGuard peer configurations.

#### Reconciliation & State

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/nodes/{node_id}/state` | Pull full desired state for reconciliation |
| `POST` | `/v1/nodes/{node_id}/drift` | Report drift detected during reconciliation |

**`GET /v1/nodes/{node_id}/state`** — Called at `reconcile.interval` (default 60s) and on SSE reconnection.

Response (`200 OK`):

```json
{
  "peers": [
    {
      "id": "n_peer456",
      "public_key": "...",
      "mesh_ip": "10.100.1.2",
      "endpoint": "203.0.113.10:51820",
      "allowed_ips": ["10.100.1.2/32"],
      "psk": "..."
    }
  ],
  "policies": [
    {
      "id": "pol_abc",
      "rules": [ { "src": "10.100.1.0/24", "dst": "10.100.1.5/32", "port": 443, "protocol": "tcp", "action": "allow" } ]
    }
  ],
  "signing_keys": {
    "current": "base64-encoded-ed25519-public-key",
    "previous": "base64-encoded-ed25519-public-key-or-null",
    "transition_expires": "2025-01-16T10:30:00Z"
  },
  "metadata": { "environment": "production", "region": "eu-west-1" },
  "data": [
    { "key": "database-config", "content_type": "application/json", "payload": { "host": "db.internal", "port": 5432 }, "version": 3, "updated_at": "2025-01-15T10:30:00Z" }
  ],
  "secret_refs": [
    { "key": "tls-cert", "version": 2 }
  ]
}
```

**`POST /v1/nodes/{node_id}/drift`** — Reports what was corrected during reconciliation.

Request body:

```json
{
  "timestamp": "2025-01-15T10:31:00Z",
  "corrections": [
    { "type": "peer_added", "detail": "n_peer789 was missing from WireGuard config" },
    { "type": "policy_rule_removed", "detail": "Stale rule for 10.100.1.99/32 removed" }
  ]
}
```

#### Secrets

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/nodes/{node_id}/secrets/{key}` | Fetch a single secret value (NSK-encrypted) |

**`GET /v1/nodes/{node_id}/secrets/{key}`** — Called on-demand when a consumer requests a secret via the Local Node API. Returns the value encrypted with the node's AES-256-GCM Node Secret Key (NSK).

Response (`200 OK`):

```json
{
  "key": "tls-cert",
  "ciphertext": "base64-encoded-aes-256-gcm-ciphertext",
  "nonce": "base64-encoded-gcm-nonce",
  "version": 2
}
```

| Response | Meaning |
|---|---|
| `200 OK` | Encrypted secret value |
| `401 Unauthorized` | Invalid node identity |
| `403 Forbidden` | Node not authorized to access this secret |
| `404 Not Found` | Secret key does not exist |

#### Reports

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/nodes/{node_id}/report` | Sync report entries upstream |

**`POST /v1/nodes/{node_id}/report`** — Batched report sync with debounce (default 5s).

Request body:

```json
{
  "entries": [
    {
      "key": "app-health",
      "content_type": "application/json",
      "payload": { "status": "healthy", "checked_at": "2025-01-15T10:30:00Z" },
      "version": 12,
      "updated_at": "2025-01-15T10:30:00Z"
    }
  ],
  "deleted": ["old-report-key"]
}
```

| Response | Meaning |
|---|---|
| `200 OK` | Report entries accepted |
| `401 Unauthorized` | Invalid node identity |
| `409 Conflict` | Version conflict on one or more entries |

#### Action Execution Callbacks

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/nodes/{node_id}/executions/{execution_id}/ack` | ACK or NACK an action request |
| `POST` | `/v1/nodes/{node_id}/executions/{execution_id}/result` | Report action execution result |

**`POST /v1/nodes/{node_id}/executions/{execution_id}/ack`** — Sent immediately after receiving an `action_request`.

Request body:

```json
{
  "execution_id": "exec_a1b2c3d4",
  "status": "accepted",
  "reason": ""
}
```

`status` is `accepted` or `rejected`. When rejected, `reason` provides the cause (e.g. `"unknown action"`, `"integrity violation"`, `"max concurrent executions reached"`).

**`POST /v1/nodes/{node_id}/executions/{execution_id}/result`** — Sent after action execution completes. Retried with exponential backoff on failure.

Request body:

```json
{
  "execution_id": "exec_a1b2c3d4",
  "status": "success",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "...",
  "duration": "2.34s",
  "finished_at": "2025-01-15T10:30:02Z",
  "triggered_by": {
    "type": "control_plane",
    "session_id": "",
    "user_id": "",
    "email": ""
  }
}
```

`status` is `success`, `failure`, `timeout`, or `cancelled`. `stdout` and `stderr` are truncated to 64 KiB each. The `triggered_by` block is included for audit purposes (see [Session-Based Action Authorization](#session-based-action-authorization)).

#### Observability

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/nodes/{node_id}/metrics` | Batch metrics delivery |
| `POST` | `/v1/nodes/{node_id}/logs` | Batch log forwarding |
| `POST` | `/v1/nodes/{node_id}/audit` | Batch audit event forwarding |

All three observability endpoints use the same delivery model: **gzip-compressed** request body with `Content-Encoding: gzip`.

**`POST /v1/nodes/{node_id}/metrics`** — Delivered at `observe.batch_interval` (default 10s) or when `observe.batch_max_size` (default 500) data points are buffered.

Request body (`Content-Type: application/json`, `Content-Encoding: gzip`):

```json
[
  {
    "timestamp": "2025-01-15T10:30:00Z",
    "group": "node_resources",
    "data": { "cpu_percent": 23.5, "memory_used": 4294967296, "memory_total": 8589934592 }
  },
  {
    "timestamp": "2025-01-15T10:30:00Z",
    "group": "tunnel_health",
    "peer_id": "n_peer456",
    "data": { "handshake_age_seconds": 15, "tx_bytes": 1048576, "rx_bytes": 524288, "packet_loss_percent": 0.1 }
  }
]
```

**`POST /v1/nodes/{node_id}/logs`** — Delivered at `logs.batch_interval` (default 10s) or when `logs.batch_max_size` (default 1000) lines are buffered.

Request body (`Content-Type: application/x-ndjson`, `Content-Encoding: gzip`):

```
{"timestamp":"2025-01-15T10:30:00.123Z","source":"journald","unit":"plexd","message":"reconciliation completed, 0 drifts corrected","severity":"info","hostname":"web-01"}
{"timestamp":"2025-01-15T10:30:01.456Z","source":"journald","unit":"sshd","message":"Accepted publickey for admin","severity":"info","hostname":"web-01"}
```

**`POST /v1/nodes/{node_id}/audit`** — Delivered at `audit.batch_interval` (default 10s) or when `audit.batch_max_size` (default 500) events are buffered.

Request body (`Content-Type: application/x-ndjson`, `Content-Encoding: gzip`):

```
{"timestamp":"2025-01-15T10:30:00.456Z","source":"auditd","event_type":"SYSCALL","subject":{"uid":1000,"pid":4523,"comm":"sshd"},"object":{"path":"/etc/shadow"},"action":"open","result":"denied","hostname":"web-01","raw":"..."}
```

| Response | Meaning |
|---|---|
| `202 Accepted` | Batch received and queued for processing |
| `401 Unauthorized` | Invalid node identity |
| `413 Payload Too Large` | Batch exceeds server-side size limit |
| `429 Too Many Requests` | Rate limit exceeded, retry with backoff |

#### Artifacts

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/artifacts/plexd/{version}/{os}/{arch}` | Download plexd binary for upgrade |

**`GET /v1/artifacts/plexd/{version}/{os}/{arch}`** — Called during `service.upgrade` action execution. Returns the binary as an octet stream.

| Parameter | Example | Description |
|---|---|---|
| `version` | `1.5.0` | Target version |
| `os` | `linux` | Operating system |
| `arch` | `amd64` | CPU architecture |

Response: `200 OK` with `Content-Type: application/octet-stream`. The SHA-256 checksum is provided in the `action_request` parameters and verified by plexd after download.

#### Endpoint Summary

| # | Method | Path | Purpose |
|---|---|---|---|
| 1 | `POST` | `/v1/register` | Node registration |
| 2 | `GET` | `/v1/nodes/{node_id}/events` | SSE event stream |
| 3 | `POST` | `/v1/nodes/{node_id}/heartbeat` | Heartbeat |
| 4 | `POST` | `/v1/nodes/{node_id}/deregister` | Graceful deregistration |
| 5 | `POST` | `/v1/keys/rotate` | Key rotation |
| 6 | `PUT` | `/v1/nodes/{node_id}/capabilities` | Capability update |
| 7 | `PUT` | `/v1/nodes/{node_id}/endpoint` | NAT endpoint reporting |
| 8 | `GET` | `/v1/nodes/{node_id}/state` | Full state pull (reconciliation) |
| 9 | `POST` | `/v1/nodes/{node_id}/drift` | Drift reporting |
| 10 | `GET` | `/v1/nodes/{node_id}/secrets/{key}` | Secret fetch (NSK-encrypted) |
| 11 | `POST` | `/v1/nodes/{node_id}/report` | Report entry sync |
| 12 | `POST` | `/v1/nodes/{node_id}/executions/{execution_id}/ack` | Action ACK/NACK |
| 13 | `POST` | `/v1/nodes/{node_id}/executions/{execution_id}/result` | Action result |
| 14 | `POST` | `/v1/nodes/{node_id}/metrics` | Metrics batch |
| 15 | `POST` | `/v1/nodes/{node_id}/logs` | Log batch |
| 16 | `POST` | `/v1/nodes/{node_id}/audit` | Audit batch |
| 17 | `GET` | `/v1/artifacts/plexd/{version}/{os}/{arch}` | Binary download |

### Key Storage

Private keys, PSKs, and the Node Secret Key (NSK) are stored in `data_dir` (default `/var/lib/plexd/`) with file permissions `0600`. The NSK (AES-256) is used to decrypt secret values fetched from the control plane and is received during registration. It is rotated together with mesh keys or independently via the control plane. The control plane's Ed25519 signing public key (used for SSE event signature verification and session JWT validation) is also stored in `data_dir`, received during registration, and updated via `signing_key_rotated` events. During signing key rotation, both old and new keys are stored for the transition period. The bootstrap token is deleted from disk immediately after successful registration.

### Threat Model

| Scenario | Impact | Mitigation |
|---|---|---|
| Control plane compromised | Attacker has signing key - can forge SSE events and inject malicious peers | PSK layer for mesh traffic; signing key rotation to limit exposure window; admin-side integrity monitoring; nodes log all applied events for forensic analysis |
| Node compromised | Attacker has private key and NSK of one node | Force-remove node, trigger key rotation + PSK refresh on all affected peers; rotate NSK to prevent decryption of future secrets; secrets are not cached so no plaintext on disk to exfiltrate |
| Bootstrap token stolen | Attacker could register a rogue node | One-time-use + short TTL limits the attack window |
| MITM during registration | Could intercept public key exchange and signing key | TLS + server certificate validation on all control plane communication |
| MITM on SSE stream | Could inject forged events (peer changes, action requests, key rotations) | Ed25519 signature verification on every event; TLS as first layer; forged events rejected without valid signature |
| Signing key compromised | Attacker can forge SSE events until key is rotated | Signing key rotation via `signing_key_rotated` event (signed with current key); transition period for graceful rollover |
| Session token stolen | Attacker could execute scoped actions on target node | Short TTL, node-bound, scoped action list, revocation on session end |
| Unauthorized local action execution | SSH user runs actions without permission | Requires valid session JWT; `--local` restricted to root and logged as emergency |
| Unauthorized secret access (local) | Attacker on node reads secrets via socket or K8s Secret | Socket requires `plexd-secrets` group; K8s Secrets contain only NSK-encrypted ciphertext; decryption requires plexd API with valid bearer token + live control plane |
| NSK compromised | Attacker could decrypt secret ciphertext from K8s Secrets or intercepted responses | NSK rotation invalidates old key; secrets are fetched in real-time so no historical ciphertext accumulates on-node; control plane re-encrypts with new NSK |

## Network Requirements

plexd requires the following network connectivity. All control plane communication is outbound-initiated from the node.

### Node Mode

| Direction | Protocol | Port | Destination | Purpose |
|---|---|---|---|---|
| Outbound | TCP/443 | - | Control plane API | Registration, heartbeat, observability, log/audit forwarding, callbacks |
| Outbound | TCP/443 | - | Control plane SSE | Real-time event stream (persistent connection) |
| Outbound | UDP/3478, UDP/19302 | - | STUN servers | NAT type discovery, public endpoint detection |
| Inbound/Outbound | UDP/51820 | 51820 | Mesh peers | WireGuard encrypted mesh traffic (P2P) |

### Bridge Mode (additional)

| Direction | Protocol | Port | Destination | Purpose |
|---|---|---|---|---|
| Inbound | UDP/51820 | 51820 | NAT relay clients | WireGuard relay for nodes behind symmetric NAT |
| Inbound | TCP/443 | 443 | Public internet | Public ingress (if `ingress.enabled`) |
| Inbound | UDP/51821 | 51821 | User access clients | WireGuard user access (if configured) |
| Outbound | UDP/varies | - | Site-to-site peers | VPN tunnels to external networks |

> **Note:** Nodes behind NAT do not need any inbound port forwarding. STUN discovery and relay fallback handle NAT traversal automatically.

## Operational Behavior

### Offline Behavior

plexd is designed to remain functional when the control plane is temporarily unreachable:

- **Mesh connectivity persists:** Established WireGuard tunnels continue to operate independently of the control plane. Peers can communicate as long as the tunnels are up.
- **Configuration is cached:** The last known peer list, policies, and signing keys are persisted to `data_dir`. On restart without control plane connectivity, plexd restores the cached state and establishes tunnels to known peers.
- **Buffered telemetry:** Log, audit, and observability data are buffered in local ringbuffers and drained when connectivity is restored.
- **No new peers:** New peers cannot be added while offline, as peer key exchange requires the control plane. Existing peers continue to work.
- **Heartbeat failure:** After 3 missed heartbeats, the control plane marks the node as `unreachable`. This does not affect the node's local operation.
- **Actions are unavailable:** SSE-triggered actions cannot be received while offline. Local actions via `plexd actions run --local` remain available.
- **Secrets are unavailable:** Secret values are fetched in real-time from the control plane and never cached in plaintext. When the control plane is unreachable, secret read requests return `503 Service Unavailable`. Metadata and data entries remain available from the local cache.

### Upgrade Process

plexd supports in-place upgrades triggered by the control plane via the `service.upgrade` built-in action:

1. Control plane sends `action_request` with `action: service.upgrade`, including the target `version` and expected binary `checksum`.
2. plexd downloads the new binary from the control plane's artifact store, verifies the SHA-256 checksum, and places it alongside the current binary.
3. plexd signals the systemd service to restart (or re-execs in non-systemd environments).
4. On startup, the new binary computes its own checksum and reports it in the registration/heartbeat. The control plane verifies the upgrade succeeded.
5. If the new binary fails to start (crash loop), systemd's `RestartSec` and `StartLimitBurst` prevent excessive restarts. Manual intervention or rollback via the control plane is required.

Rollback is a new `service.upgrade` action pointing to the previous version.

### Mesh IP Allocation

Each node receives a unique mesh IP from the `10.100.0.0/16` range during registration. IPs are assigned by the control plane and are stable for the lifetime of the node's registration.

- **Format:** `10.100.x.y/32` (single host address per node)
- **Uniqueness:** Guaranteed by the control plane within a tenant
- **Persistence:** The mesh IP is stored in `data_dir` and reused across restarts
- **Deregistration:** When a node deregisters, its mesh IP is returned to the pool after a cooldown period (to avoid conflicts with cached peer configurations on other nodes)
- **Bridge nodes:** Typically assigned from a reserved range (e.g. `10.100.255.x`) by convention, but this is a control plane policy, not enforced by plexd

### Reconciliation Details

The reconciliation loop (`reconcile.interval`, default 60s) ensures that the local state matches the control plane's desired state. It acts as a consistency fallback for the real-time SSE event stream.

Each reconciliation cycle:

1. **Pull full state** from `GET /v1/nodes/{node_id}/state` - includes peer list, policies, signing keys, pending actions, node metadata, data entries, and secret references.
2. **Diff** the received state against the local WireGuard configuration, nftables rules, signing key store, and node state cache.
3. **Apply corrections** for any detected drift:
   - Add/remove WireGuard peers
   - Update endpoints, allowed IPs, PSKs
   - Add/remove nftables rules
   - Update signing keys
   - Update node metadata, data entries, and secret references
4. **Report drift** to the control plane for observability (`POST /v1/nodes/{node_id}/drift`), including what was corrected.

Reconciliation is also triggered immediately after SSE reconnection (see [SSE reconnection](#phase-3-details-steady-state)).

## Troubleshooting

### Agent fails to register

```bash
plexd status          # Check current state
journalctl -u plexd   # View service logs
```

Verify that the bootstrap token has not expired and that the node can reach the control plane API (`PLEXD_API`).

### No peers connected

```bash
plexd peers           # List peer status
plexd status          # Check NAT traversal state
```

Common causes: firewall blocking UDP traffic, STUN servers unreachable, or the node has not yet received its peer list from the control plane.

### Tunnel established but no traffic

```bash
plexd policies        # Check active policies
```

Network policies may be blocking traffic. Verify that the desired communication is allowed by the policies configured in the control plane.

### Hook execution fails with integrity violation

```bash
plexd hooks verify    # Check all hook checksums
plexd logs            # Look for integrity_violation events
```

A checksum mismatch means the hook script was modified after plexd computed its initial checksum. This can happen if the file was updated manually without reloading hooks. Run `plexd hooks reload` to re-scan and recompute checksums, then retry. If the mismatch is unexpected, investigate whether the file was modified by an unauthorized process.

### SSE stream keeps disconnecting

```bash
plexd status          # Check SSE connection state and reconnect count
plexd log-status      # Check if log forwarding is buffering (indicates connectivity issues)
```

Frequent SSE disconnections are typically caused by network instability, an overloaded proxy between the node and the control plane, or TLS inspection appliances that terminate long-lived connections. Check for HTTP proxies or firewalls with idle timeout settings shorter than the heartbeat interval (30s). plexd reconnects automatically with exponential backoff.

### Node marked as unreachable but is running

```bash
plexd status          # Verify heartbeat is being sent
journalctl -u plexd --since "5 minutes ago" | grep heartbeat
```

If plexd is running but the control plane shows the node as `unreachable`, the heartbeat POST may be failing. Common causes: DNS resolution failure for the control plane API, expired TLS certificate on an intermediate proxy, or network partition. Check that `PLEXD_API` is reachable with `curl -s -o /dev/null -w "%{http_code}" $PLEXD_API/health`.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
