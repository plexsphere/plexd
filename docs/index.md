# Plexsphere Node Agent Documentation

## Capabilities

The Plexsphere node agent (`plexd`) is a lightweight daemon that runs on every managed node. It handles:

- **Registration** — self-registers with the control plane using a bootstrap token
- **WireGuard Mesh** — creates and manages WireGuard interfaces and encrypted peer tunnels
- **NAT Traversal** — discovers public endpoints via STUN and exchanges them with peers
- **Network Policy** — enforces peer visibility rules and firewall policies via nftables
- **Secure Tunneling** — provides SSH-based secure access tunnels through the mesh
- **State Reconciliation** — periodically fetches desired state and applies drift corrections
- **Remote Actions** — executes built-in and hook-based actions requested via SSE events
- **Observability** — collects and forwards metrics, logs, and audit events to the control plane
- **Local Node API** — exposes node state (metadata, data, secrets) to local workloads via Unix socket API or PlexdNodeState CRD
- **Integrity** — verifies checksums of the plexd binary and hook scripts
- **Bridge Mode** — optional gateway mode with NAT relay, public ingress, user access, and site-to-site VPN

## Operating Modes

| Mode | Status | Description |
|------|--------|-------------|
| `node` | **Active** | Default mode. Runs all core subsystems. |
| `bridge` | **Active** | Extends node mode with bridge-specific subsystems (relay, ingress, user access, site-to-site). Enabled when `mode: bridge` and `bridge.enabled: true`. |

## High-Level Overview

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

plexd communicates outbound only — no inbound ports or public IPs required on the node side. For detailed architecture diagrams, see [Architecture](guide/architecture.md).

## Guide

- [Installation & Quick Start](guide/installation.md) — Install plexd and get running
- [Architecture](guide/architecture.md) — Platform support, architecture diagrams, mesh topology
- [Agent Lifecycle](guide/agent-lifecycle.md) — Startup phases, heartbeat, SSE, deregistration, operational behavior
- [Platform Communication & Mesh](guide/platform-communication.md) — Communication channels, node lifecycle, mesh topology, and capabilities
- [Security & Trust Model](guide/security.md) — Key exchange, threat model, network requirements
- [Troubleshooting](guide/troubleshooting.md) — Common issues and diagnostics

## How-To Guides

Step-by-step guides for common operational tasks.

- [Bare-Metal Installation](how-to/bare-metal-installation.md) — Install plexd on a bare-metal Linux server
- [Cloud VM Deployment](how-to/cloud-vm-deployment.md) — Deploy plexd on cloud VMs using Cloud-Init
- [Kubernetes Deployment](how-to/kubernetes-deployment.md) — Deploy plexd as a DaemonSet on Kubernetes
- [Using the Local Node API](how-to/local-node-api.md) — Read node state and write reports via the local API
- [Creating Custom Hook Scripts](how-to/custom-hook-scripts.md) — Extend plexd with custom hook scripts for remote actions

## Reference

Operator and admin reference for configuring and deploying plexd.

- [CLI Reference](reference/core/cli.md) — Command-line interface and subcommands
- [Configuration Reference](reference/core/configuration.md) — Full YAML configuration schema with all fields and defaults
- [Environment Variables Reference](reference/core/environment-variables.md) — All PLEXD_* environment variable overrides
- [Key Storage](reference/core/key-storage.md) — Private keys, PSKs, NSK, and signing key storage
- [Control Plane API Endpoints](reference/core/api-endpoints.md) — Full control plane REST API reference
- [Local Node API](reference/core/nodeapi.md) — Unix socket and TCP API for local node state access

### Actions

- [Remote Actions and Hooks](reference/actions/remote-actions-hooks.md) — Remote action execution and hook system
- [Session-Based Action Authorization](reference/actions/session-authorization.md) — Session JWT authorization for SSH-triggered actions
- [Sandbox Options](reference/actions/sandbox-options.md) — Sandbox levels for hook execution
- [PlexdHook CRD Reference](reference/actions/plexdhook-crd.md) — Kubernetes CRD for declarative hook execution

### Deployment

- [Bare-Metal Packaging Reference](reference/deployment/bare-metal-packaging.md) — Systemd service installation and packaging
- [Cloud-Init VM Deployment Reference](reference/deployment/cloud-init-vm-deployment.md) — IMDS provider, cloud-init templates, and Terraform examples
- [Kubernetes DaemonSet Deployment Reference](reference/deployment/kubernetes-deployment.md) — Kubernetes manifests, RBAC, and DaemonSet configuration
- [Container Image (Dockerfile) Reference](reference/deployment/dockerfile.md) — Container image build and configuration

## Internals

Developer and contributor reference for plexd subsystem internals.

- [Agent Internals](concepts.md) — Core concepts, subsystem architecture, and agent lifecycle

### Core

- [Control Plane Client](reference/core/control-plane-client.md) — HTTP client for the Plexsphere control plane API
- [API Types](reference/core/api-types.md) — Shared API request/response types
- [Event Verification](reference/core/event-verification.md) — SSE event signature verification
- [Registration](reference/core/registration.md) — Node self-registration and bootstrap authentication
- [Configuration Reconciliation](reference/core/reconciliation.md) — State reconciliation with the control plane
- [Heartbeat Service](reference/core/heartbeat-service.md) — Periodic heartbeat reporting

### Networking

- [WireGuard Tunnel Management](reference/networking/wireguard.md) — WireGuard interface and peer management
- [NAT Traversal via STUN](reference/networking/nat-traversal.md) — STUN-based NAT traversal for mesh connectivity
- [Peer Endpoint Exchange](reference/networking/peer-endpoint-exchange.md) — Peer endpoint discovery and exchange
- [Network Policy Enforcement](reference/networking/network-policy.md) — Network policy rules and enforcement
- [nftables Firewall Controller](reference/networking/nftables-firewall.md) — nftables-based firewall management
- [Secure Access Tunneling](reference/networking/secure-access-tunneling.md) — Secure tunnel access for services

### Bridge

- [Bridge Mode](reference/bridge/bridge-mode.md) — Gateway bridge mode operation
- [NAT Relay](reference/bridge/nat-relay.md) — NAT relay for indirect connectivity
- [User Access Integration](reference/bridge/user-access-integration.md) — User access control integration
- [VPN Providers](reference/bridge/vpn-providers.md) — VPN provider integrations
- [Public Ingress](reference/bridge/public-ingress.md) — Public ingress configuration
- [ACME and SNI Routing](reference/bridge/acme-sni.md) — ACME certificate management and SNI-based routing
- [Site-to-Site VPN](reference/bridge/site-to-site-vpn.md) — Site-to-site VPN connectivity
- [Tunnel Providers](reference/bridge/tunnel-providers.md) — Tunnel provider integrations
- [Netlink Route Controller](reference/bridge/netlink-route-controller.md) — Netlink-based route management

### Observability

- [Metrics Collection & Reporting](reference/observability/metrics-collection.md) — System metrics collection and forwarding
- [Log Forwarding](reference/observability/log-forwarding.md) — Log collection and forwarding to the control plane
- [Audit Forwarding](reference/observability/audit-forwarding.md) — Audit event collection and forwarding

### Integrity

- [Integrity Verification](reference/actions/integrity-verification.md) — Hook integrity verification via checksums

### Development

- [Getting Started (Development)](reference/development/getting-started.md) — Prerequisites, build, project structure
- [CI Workflow](reference/development/ci-workflow.md) — Continuous integration workflow
- [Container Workflow](reference/development/container-workflow.md) — Container image build workflow
- [Release Workflow](reference/development/release-workflow.md) — Release and versioning workflow
- [E2E Workflow](reference/development/e2e-workflow.md) — End-to-end test orchestration workflow
- [Docker E2E Test](reference/development/docker-e2e-test.md) — Docker Compose-based E2E test
- [Kubernetes E2E Test](reference/development/kubernetes-e2e-test.md) — kind-based Kubernetes E2E test
- [Systemd E2E Test](reference/development/systemd-e2e-test.md) — Systemd-based E2E test
- [Mock Central API Server](reference/development/mock-api-server.md) — Mock API server for testing
- [File System Utilities](reference/development/fsutil.md) — File system utility functions
