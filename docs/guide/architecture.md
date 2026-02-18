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

**OS:** Linux (amd64, arm64)

## Detailed Architecture

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

## See Also

- [Agent Lifecycle](/guide/agent-lifecycle) — Startup phases, steady-state protocols, deregistration, operational behavior
- [Platform Communication & Mesh](/guide/platform-communication) — Visual, diagram-driven overview of communication channels
- [Security & Trust Model](/guide/security) — Authentication, encryption, and trust boundaries
