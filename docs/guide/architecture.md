---
title: Architecture
---

# Architecture

> For a visual, diagram-driven overview of communication channels and mesh topology, see [Platform Communication & Mesh](/guide/platform-communication).

## Supported Platforms

| Platform | Mode | Notes |
|---|---|---|
| Bare-metal servers | `node` | Systemd service, manual or automated enrollment |
| Virtual machines | `node` | Cloud-Init support for automated token injection |
| Kubernetes clusters | `node` | DaemonSet deployment, auto-detects K8s audit logs |
| Bridge / Gateway | `bridge` | User access, public ingress, site-to-site VPN, NAT relay |
| OpenWRT routers | `node` | Manual install with procd init script, see `deploy/openwrt/` |

**OS:** Linux (amd64, arm64, mipsle)

## Detailed Architecture

This diagram expands the [high-level overview](/) to show the control plane's internal components, the mesh IP addressing, and the bridge node's dual-interface design.

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

**Control plane** — The four components at the top handle distinct responsibilities: the **Registration API** bootstraps new nodes, the **Key & Peer Manager** distributes WireGuard public keys and pre-shared keys, the **Policy Engine** evaluates visibility and firewall rules, and the **Event Bus (SSE)** pushes real-time updates (peer changes, policy updates, action requests, key rotations) to connected nodes.

**Node mesh** — Each node receives a unique mesh IP from the `10.100.0.0/16` range at registration (e.g. `10.100.1.1/32`). All nodes form a **full-mesh WireGuard topology** with direct peer-to-peer tunnels. Nodes behind NAT discover their public endpoints via STUN and exchange them through the control plane. When direct connectivity is not possible, traffic is relayed through bridge nodes.

**Bridge node** — A bridge operates with two interfaces. The **mesh side** (`10.100.1.250`) participates in the WireGuard mesh like any regular node and additionally serves as a NAT relay for peers that cannot reach each other directly. The **access side** exposes three services to external consumers: user access (Tailscale, Netbird, or standalone WireGuard), public ingress with ACME certificates and SNI routing, and site-to-site VPN for partner or customer networks.

**Data path separation** — The control plane coordinates identity, keys, policies, and events but never touches mesh traffic. All data flows directly between nodes over the encrypted WireGuard tunnels.

## See Also

- [Agent Lifecycle](/guide/agent-lifecycle) — Startup phases, steady-state protocols, deregistration, operational behavior
- [Platform Communication & Mesh](/guide/platform-communication) — Visual, diagram-driven overview of communication channels
- [Security & Trust Model](/guide/security) — Authentication, encryption, and trust boundaries
