---
title: Platform Communication & Mesh Networking
---

# Platform Communication & Mesh Networking

plexd communicates with the Plexsphere control plane through four outbound-only HTTPS channels: registration, SSE event streaming, heartbeat, and reconciliation. No inbound ports or public IPs are required on the node side.

Between nodes, plexd forms an encrypted WireGuard mesh for direct peer-to-peer traffic. The control plane coordinates key exchange and peer discovery but never sits in the data path — all mesh traffic flows directly between nodes.

## How plexd Communicates with Plexsphere

All communication is initiated by the node. The control plane never connects inbound to a node.

![A sequence diagram between plexd on the node and the Plexsphere control plane in five phases. Phase 1, registration, once: plexd generates a Curve25519 key pair, sends POST /v1/register with project_id, resource_handle, bootstrap_token, nonce, public_key and the optional requested_resource_id, receives node_id, mesh_ip, signing_public_key, signing_key_id, nsk, peer_snapshot and domain_mesh_cidr, and deletes the bootstrap token from disk. Phase 2, the persistent SSE event stream: plexd opens GET /v1/nodes/{id}/events with SSE and Last-Event-ID, and the control plane sends Ed25519-signed event envelopes such as node_state_updated, policy_updated, action_request, session_setup and bridge_config_updated. Phase 3, the heartbeat every 30 seconds: plexd sends POST /v1/nodes/{id}/heartbeat with client_now, binary_checksum, binary_version, nat_summary and features, and the control plane answers 200 OK with accepted_at and the optional reconcile and rotate_keys flags. Phase 4, reconciliation every 60 seconds: plexd sends GET /v1/nodes/{id}/state, receives mesh_ip, peers, reachability, policy, bridge, state, reports, executions, sessions, secrets, signing_key, hooks and dns, diffs by presence and applies corrections. Phase 5, observability, periodically: plexd posts to /v1/nodes/{id}/metrics, /v1/nodes/{id}/logs and /v1/nodes/{id}/audit.](../diagrams/communication-channels.svg)

### Channel Summary

| Channel | Direction | Protocol | Frequency | Purpose |
|---------|-----------|----------|-----------|---------|
| Registration | Node → CP | HTTPS POST | Once | Bootstrap identity, receive keys and peers |
| SSE Stream | Node ← CP | HTTPS SSE | Persistent | Real-time peer, policy, action, and key events |
| Heartbeat | Node → CP | HTTPS POST | Every 30s | Liveness, status reporting, reconcile/rotate hints |
| Reconciliation | Node → CP | HTTPS GET | Every 60s | State consistency fallback; pulls the desired-state snapshot and the queued action dispatches |
| Observability | Node → CP | HTTPS POST | Periodic | Metrics, logs, and audit event uploads |

The SSE stream is the primary real-time channel. Reconciliation acts as a consistency fallback — if an SSE event is missed, the next reconciliation cycle detects and corrects the drift. Action dispatches are the one payload that never rides the event stream at all: they are delivered in the `executions` block of the reconciliation pull, and the matching `action_request` event merely pulls the next cycle forward. See [Heartbeat Service](/reference/core/heartbeat-service) and [Reconciliation](/reference/core/reconciliation) for protocol details.

## Node Lifecycle

A node progresses through four phases from first boot to shutdown.

![The four phases of a node. Bootstrap: plexd reads its config and locates the bootstrap token, generates a Curve25519 key pair, sends POST /v1/register with the token and public key, receives its node ID, mesh IP, NSK, signing key and peers, and deletes the token from disk. Tunnel setup: it creates the WireGuard interface plexd0, adds the peers with their public keys, PSKs and allowed IPs, discovers its public endpoint with STUN, and reports the endpoint and receives a freshness deadline. Steady state: it then runs the SSE event stream, the heartbeat loop every 30 seconds, the reconciliation loop every 60 seconds, the observability uploads and the Node API server; the heartbeat's reconcile flag triggers the reconciliation loop and its rotate_keys flag a key rotation, and the reconciliation loop feeds the action dispatcher. Shutdown: a SIGTERM or SIGINT leads from the event stream, the heartbeat loop and the reconciliation loop to stopping new work, draining in-flight actions for up to 30 seconds, tearing down the WireGuard interface, and stopping the subsystems.](../diagrams/communication-node-lifecycle.svg)

See [Agent Lifecycle](/guide/agent-lifecycle) for the full startup sequence and shutdown details.

## The Encrypted Mesh Network

Nodes form a full-mesh WireGuard network in the `10.100.0.0/16` address space. Each node gets a unique `/32` mesh IP at registration. Every state pull carries the node's address as `mesh_ip`, so the control plane can move a node to another address, and the node follows with its next pull and keeps the new address across restarts. The control plane moves only a node whose heartbeat declares `mesh_readdress` in its `features` (see [Mesh Address Changes](/guide/agent-lifecycle#mesh-address-changes)). The control plane distributes public keys and pre-shared keys but never handles mesh traffic.

![The Plexsphere control plane, with its registration API, key and peer manager and SSE event bus, above the encrypted WireGuard mesh in 10.100.0.0/16. In the mesh, the plexd nodes A at 10.100.1.1, B at 10.100.1.2 and C at 10.100.1.3 and a plexd bridge at 10.100.255.1 are joined pairwise by P2P tunnels, and each of the four connects to the control plane over HTTPS and SSE. Below the mesh is the bridge's external access: the bridge links to user access through Tailscale, Netbird or WireGuard, to public ingress with ACME and SNI routing, and by a tunnel to a site-to-site VPN to partner networks. The bridge and its external access are marked bridge mode: they exist in bridge mode only.](../diagrams/communication-mesh-topology.svg)

Key properties of the mesh:

- **Outbound-only** — nodes initiate all connections. No inbound ports required.
- **NAT traversal** — nodes behind NAT use STUN to discover their public endpoint and exchange it via the control plane. See [NAT Traversal](/reference/networking/nat-traversal).
- **Relay fallback** — when direct P2P is not possible, traffic is relayed through a bridge node. See [NAT Relay](/reference/bridge/nat-relay).
- **Per-peer PSKs** — each peer pair has a unique pre-shared key for post-quantum forward secrecy.
- **Network policy** — the control plane pushes visibility rules that control which peers can communicate. See [Network Policy](/reference/networking/network-policy).

## What the Mesh Enables

![The WireGuard mesh on all nodes enables P2P communication over direct encrypted tunnels, NAT traversal with STUN and endpoint reporting, network policy as peer visibility rules through the host firewall, secure tunnels for SSH-based access through the mesh, remote actions by pull-dispatched execution, and observability with metrics, logs and audit forwarding. A bridge node, in bridge mode only, adds the NAT relay, a UDP relay for unreachable peers; public ingress with ACME certificates and SNI routing; user access through Tailscale, Netbird or WireGuard; and the site-to-site VPN for partner network connectivity.](../diagrams/communication-mesh-capabilities.svg)

### Core Capabilities (all nodes)

| Capability | Description | Reference |
|------------|-------------|-----------|
| P2P Communication | Direct encrypted WireGuard tunnels between all peers | [WireGuard Tunnels](/reference/networking/wireguard) |
| NAT Traversal | STUN-based public endpoint discovery and exchange | [NAT Traversal](/reference/networking/nat-traversal) |
| Network Policy | Peer visibility rules enforced via the host firewall (nftables, pf or WFP) | [Network Policy](/reference/networking/network-policy) |
| Secure Tunnels | SSH-based access to services through the mesh | [Secure Access Tunneling](/reference/networking/secure-access-tunneling) |
| Remote Actions | Execute built-in and hook-based actions dispatched in the state pull | [Remote Actions & Hooks](/reference/actions/remote-actions-hooks) |
| Observability | Metrics, logs, and audit event forwarding | [Metrics](/reference/observability/metrics-collection), [Logs](/reference/observability/log-forwarding), [Audit](/reference/observability/audit-forwarding) |

### Bridge-Only Capabilities

| Capability | Description | Reference |
|------------|-------------|-----------|
| NAT Relay | UDP relay for peers that cannot establish direct P2P | [NAT Relay](/reference/bridge/nat-relay) |
| Public Ingress | ACME certificate management and SNI-based routing | [Public Ingress](/reference/bridge/public-ingress), [ACME & SNI](/reference/bridge/acme-sni) |
| User Access | Integration with Tailscale, Netbird, or standalone WireGuard | [User Access](/reference/bridge/user-access-integration) |
| Site-to-Site VPN | Connect partner or customer networks to the mesh | [Site-to-Site VPN](/reference/bridge/site-to-site-vpn) |

## See Also

- [Architecture](/guide/architecture) — detailed diagrams, platform support, mesh topology
- [Agent Lifecycle](/guide/agent-lifecycle) — full startup sequence, operational behavior, deregistration
- [Security & Trust Model](/guide/security) — key exchange, trust chain, threat model, network requirements
- [Agent Internals](/concepts) — subsystem overview, goroutine map, shutdown sequence
- [Control Plane Client](/reference/core/control-plane-client) — HTTP client implementation details
- [Registration](/reference/core/registration) — bootstrap authentication and identity persistence
