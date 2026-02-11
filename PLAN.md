# plexd — Node Agent for Plexsphere Mesh Networking

plexd is a node agent that runs on every node in a Plexsphere-managed environment. It connects to the control plane, registers the node, establishes encrypted WireGuard mesh tunnels to peers, enforces network policies, and continuously reconciles local state. This plan organizes development into 6 phases: core foundation, mesh networking, policy and security, bridge mode, observability and operations, and platform support.

## Phase 1: Core Foundation

Establish the fundamental building blocks: control plane communication, node registration, state reconciliation, and the local node API. Everything else depends on these.

- **S001: Control Plane Client (HTTPS + SSE)** [high]
  Implement the outbound-only communication layer to the Plexsphere control plane. Uses HTTPS for API calls (registration, key exchange, policy fetch) and Server-Sent Events (SSE) for real-time event streaming from the control plane. All connections are initiated by the node — no inbound ports required.
- **S002: Self-Registration & Bootstrap Authentication** [high] (depends on: S001)
  Authenticate with the control plane using a one-time bootstrap token and enroll the node. Supports platform-provisioned tokens (injected via Cloud-Init or Kubernetes Secret) and manually provided tokens for user-onboarded resources. After successful registration, the node receives its identity, mesh IP, and initial configuration.
- **S003: Configuration Reconciliation Loop** [high] (depends on: S001, S002)
  Periodically compare local tunnel and policy state against the control plane's source of truth. Detect configuration drift (missing tunnels, stale peers, outdated policies) and correct it automatically. This is the core convergence loop that keeps every node aligned with desired state.
- **S004: Local Node API** [high] (depends on: S001, S002)
  Expose node state (metadata, configuration data, secrets) to local workloads and scripts. On bare-metal/VM, serve via a Unix socket API. On Kubernetes, expose state via a PlexdNodeState CRD. Supports bidirectional data exchange — downstream from the control plane and upstream reporting from the node.

## Phase 2: Mesh Networking

Build the encrypted mesh connectivity layer using WireGuard, including direct peer-to-peer tunnels and NAT traversal via STUN.

- **S005: WireGuard Tunnel Management** [high] (depends on: S002, S003)
  Create, configure, and manage WireGuard interfaces and peer entries. Establish direct encrypted tunnels to all authorized peers within the same tenant. Implement full-mesh topology where every node can communicate directly with every other node. Handle key generation, peer configuration, and tunnel lifecycle.
- **S006: NAT Traversal via STUN** [high] (depends on: S001)
  Discover the node's public endpoint using STUN servers. Determine NAT type and public IP:port mapping so peers behind NAT can establish direct connections. Report discovered endpoints to the control plane for distribution to peers.
- **S007: Peer Endpoint Exchange** [high] (depends on: S005, S006)
  Exchange discovered public endpoints with peers through the control plane. Receive peer endpoint updates via SSE events and update local WireGuard peer configurations accordingly. Handle endpoint changes due to NAT rebinding or IP changes gracefully.

## Phase 3: Policy & Security

Implement network policy enforcement, secure access tunneling, and integrity verification to ensure the mesh is locked down and trustworthy.

- **S008: Network Policy Enforcement** [high] (depends on: S003, S005)
  Receive network policies from the control plane and enforce them locally. Implement two enforcement mechanisms: peer visibility filtering (controlling which peers a node can see and connect to) and firewall rules (controlling traffic flow between peers). Policies are reconciled as part of the configuration loop.
- **S009: Secure Access Tunneling** [medium] (depends on: S005, S008)
  Enable platform-mediated access to managed resources. Tunnel SSH sessions to servers/VMs and Kubernetes API access through the mesh without exposing services directly to the internet. The control plane orchestrates access sessions; plexd provides the local tunnel endpoints.
- **S010: Integrity Verification** [high] (depends on: S001)
  Ensure integrity of the plexd binary itself and any custom hook scripts via SHA-256 checksum verification. Verify checksums on startup, after updates, and before executing hook scripts. Report integrity violations to the control plane.

## Phase 4: Bridge Mode

Implement bridge/gateway functionality that connects the mesh to external networks — user access, public traffic, site-to-site VPN, and relay for nodes that cannot establish direct P2P connectivity.

- **S011: Bridge Mode Core** [high] (depends on: S005, S008)
  Implement the bridge/gateway operating mode for plexd. A bridge node has both a mesh-side interface (participating in the WireGuard mesh) and an access-side interface (connecting to external networks). Handle dual-interface routing, traffic forwarding between mesh and external networks, and bridge-specific registration with the control plane.
- **S012: NAT Relay** [high] (depends on: S011, S007)
  Serve as a relay for nodes that cannot establish direct P2P tunnels (e.g., both peers behind symmetric NAT). Bridge nodes forward encrypted traffic between unreachable peers. Nodes fall back to relay automatically when direct connectivity fails after STUN-based NAT traversal attempts.
- **S013: User Access Integration** [medium] (depends on: S011)
  Route user access traffic into the mesh via external VPN clients. Support integration with Tailscale, Netbird, and standard WireGuard clients. Developers, admins, and on-call engineers connect through the bridge to reach resources on the mesh without direct mesh membership.
- **S014: Public Ingress** [medium] (depends on: S011)
  Expose mesh-internal services to public internet traffic through the bridge node. Handle inbound traffic on public IPs and route it to the appropriate mesh peer. Support TLS termination or passthrough as needed.
- **S015: Site-to-Site VPN Connectivity** [medium] (depends on: S011)
  Connect the mesh to external VPN networks for site-to-site connectivity. The bridge node establishes VPN tunnels to partner networks, corporate data centers, or other external environments and routes traffic between the mesh and these external networks.

## Phase 5: Observability & Operations

Add monitoring, logging, auditing, and remote management capabilities to provide full operational visibility and control.

- **S016: Metrics Collection & Reporting** [medium] (depends on: S001, S005)
  Collect and report node metrics to the control plane: tunnel health, peer latency, resource utilization (CPU, memory, disk, network), and mesh-specific metrics (handshake success rates, packet loss). Enable centralized monitoring dashboards.
- **S017: Log Forwarding** [medium] (depends on: S001)
  Stream system and application logs from the node to the control plane for centralized monitoring and troubleshooting. Support structured log formats and efficient transport. Handle log buffering during connectivity interruptions.
- **S018: Audit Data Collection & Forwarding** [medium] (depends on: S001)
  Collect and forward audit data from managed resources for compliance and security analysis. On Linux, integrate with auditd. On Kubernetes, collect Kubernetes audit logs. Forward audit events to the control plane with minimal latency.
- **S019: Remote Actions & Hooks** [medium] (depends on: S001, S010)
  Execute platform-triggered actions on nodes. Support built-in operations (diagnostics, service management) and custom hook scripts. Hooks are delivered from the control plane with SHA-256 checksums for integrity verification. Report action results back to the control plane.

## Phase 6: Platform Support & Packaging

Ensure plexd runs correctly across all supported platforms with appropriate packaging, deployment mechanisms, and platform-specific integrations.

- **S020: Bare-Metal Support (systemd)** [high] (depends on: S002, S005)
  Package plexd as a systemd service for bare-metal Linux servers. Include systemd unit files, installation scripts, and support for both manual enrollment (user provides bootstrap token) and automated enrollment. Support amd64 and arm64 architectures.
- **S021: VM Support (Cloud-Init)** [high] (depends on: S020)
  Support automated deployment on virtual machines via Cloud-Init. Provide Cloud-Init user-data templates that install plexd and inject the bootstrap token automatically during VM provisioning. Integrate with cloud provider metadata services where applicable.
- **S022: Kubernetes Support (DaemonSet)** [high] (depends on: S002, S004, S005, S018)
  Deploy plexd as a DaemonSet on Kubernetes clusters. Bootstrap token is injected via Kubernetes Secret. Auto-detect Kubernetes environment and enable K8s-specific features: PlexdNodeState CRD for the local node API, Kubernetes audit log collection, and integration with the cluster's networking stack.
