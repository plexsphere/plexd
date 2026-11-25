---
title: Architecture
---

# Architecture

> For a visual, diagram-driven overview of communication channels and mesh topology, see [Platform Communication & Mesh](/guide/platform-communication).

## Supported Platforms

| Platform | Mode | Notes |
|---|---|---|
| Bare-metal servers | `node` | systemd service, manual or automated enrollment |
| Virtual machines | `node` | Cloud-Init support for automated token injection |
| Kubernetes clusters | `node` | DaemonSet deployment, auto-detects K8s audit logs |
| Bridge / Gateway | `bridge` | User access, public ingress, site-to-site VPN, NAT relay |
| OpenWRT routers | `node` | Manual install with procd init script, see `deploy/openwrt/` |
| macOS hosts | `node`, `bridge` | launchd daemon, runs as root, WireGuard on a utun device |
| Windows hosts | `node`, `bridge` | Windows service, runs as LocalSystem, WireGuard on a Wintun adapter |

**OS:** Linux (amd64, arm64, mipsle), macOS (amd64, arm64), Windows (amd64, arm64). What each one supports, feature by feature, is in [Platform Support](/guide/platform-support).

## Detailed Architecture

This diagram expands the [high-level overview](/) to show the control plane's internal components, the mesh IP addressing, and the bridge node's dual-interface design.

![The plexsphere control plane holds four components: the Registration API, the Key & Peer Manager, the Policy Engine and the Event Bus (SSE). Four plexd nodes, on bare metal at 10.100.1.1, on two VMs at 10.100.1.2 and 10.100.1.3 and on Kubernetes at 10.100.1.4, and a plexd bridge connect to it over HTTPS and SSE, outbound only. The four nodes join the encrypted WireGuard full mesh: every node has a direct peer-to-peer tunnel to every node, each peer uses STUN to discover its public endpoint for NAT traversal, and traffic falls back to relay via the bridge when direct connectivity fails. The bridge's mesh side, at 10.100.1.250, joins the mesh and is the NAT relay. Its access side holds user access through Tailscale, Netbird or WireGuard, public ingress, and site-to-site VPN, and serves developers, admins and on-call staff, public internet traffic, and partner or customer networks.](../diagrams/architecture-detailed.svg)

**Control plane** — The four components at the top handle distinct responsibilities: the **Registration API** bootstraps new nodes, the **Key & Peer Manager** distributes WireGuard public keys and pre-shared keys, the **Policy Engine** evaluates visibility and firewall rules, and the **Event Bus (SSE)** pushes real-time update notifications (peer changes, policy updates, action requests, key rotations) to connected nodes. Those notifications are hints: the node applies the change — and picks up queued action dispatches — from its authoritative state pull.

**Node mesh** — Each node receives a unique mesh IP from the `10.100.0.0/16` range at registration (e.g. `10.100.1.1/32`). The control plane may move a node to another address later. A node that declares `mesh_readdress` on its heartbeat follows the move with its next state pull, without a restart, and keeps the new address across restarts (see [Mesh Address Changes](/guide/agent-lifecycle#mesh-address-changes)). All nodes form a **full-mesh WireGuard topology** with direct peer-to-peer tunnels. Nodes behind NAT discover their public endpoints via STUN and exchange them through the control plane. When direct connectivity is not possible, traffic is relayed through bridge nodes.

**Bridge node** — A bridge operates with two interfaces. The **mesh side** (`10.100.1.250`) participates in the WireGuard mesh like any regular node and additionally serves as a NAT relay for peers that cannot reach each other directly. The **access side** exposes three services to external consumers: user access (Tailscale, Netbird, or standalone WireGuard), public ingress with ACME certificates and SNI routing, and site-to-site VPN for partner or customer networks.

**Data path separation** — The control plane coordinates identity, keys, policies, and events but never touches mesh traffic. All data flows directly between nodes over the encrypted WireGuard tunnels.

## See Also

- [Agent Lifecycle](/guide/agent-lifecycle) — Startup phases, steady-state protocols, deregistration, operational behavior
- [Platform Communication & Mesh](/guide/platform-communication) — Visual, diagram-driven overview of communication channels
- [Security & Trust Model](/guide/security) — Authentication, encryption, and trust boundaries
