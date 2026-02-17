# plexd Documentation

plexd is the Plexsphere node agent — a lightweight daemon that runs on every managed node, handles registration, state reconciliation, remote actions, and observability forwarding. For architecture and component overview, see [Architecture and Concepts](concepts.md). For build instructions and quick start, see the [README](../README.md).

## Getting Started

- [Architecture and Concepts](concepts.md) — How plexd works, subsystem map, startup lifecycle

## How-To Guides

Step-by-step guides for common operational tasks.

- [Bare-Metal Installation](how-to/bare-metal-installation.md) — Install plexd on a bare-metal Linux server
- [Cloud VM Deployment](how-to/cloud-vm-deployment.md) — Deploy plexd on cloud VMs using Cloud-Init
- [Kubernetes Deployment](how-to/kubernetes-deployment.md) — Deploy plexd as a DaemonSet on Kubernetes
- [Using the Local Node API](how-to/local-node-api.md) — Read node state and write reports via the local API
- [Creating Custom Hook Scripts](how-to/custom-hook-scripts.md) — Extend plexd with custom hook scripts for remote actions

## Reference

Detailed reference documentation for all plexd subsystems.

### Core

Agent core, CLI, API client, and registration.

- [CLI Reference](reference/core/cli.md) — Command-line interface and subcommands
- [Configuration Reference](reference/core/configuration.md) — Full YAML configuration schema with all fields and defaults
- [Environment Variables Reference](reference/core/environment-variables.md) — All PLEXD_* environment variable overrides
- [Control Plane Client](reference/core/control-plane-client.md) — HTTP client for the Plexsphere control plane API
- [API Types](reference/core/api-types.md) — Shared API request/response types
- [Event Verification](reference/core/event-verification.md) — SSE event signature verification
- [Registration](reference/core/registration.md) — Node self-registration and bootstrap authentication
- [Configuration Reconciliation](reference/core/reconciliation.md) — State reconciliation with the control plane
- [Heartbeat Service](reference/core/heartbeat-service.md) — Periodic heartbeat reporting
- [Local Node API](reference/core/nodeapi.md) — Unix socket and TCP API for local node state access

### Networking

WireGuard mesh, NAT traversal, and network policy enforcement.

> **Note:** The subsystems in this section have code in the repository but are not active in the current release. Their configuration is parsed but the subsystems are not started. See individual pages for details.

- [WireGuard Tunnel Management](reference/networking/wireguard.md) — WireGuard interface and peer management
- [NAT Traversal via STUN](reference/networking/nat-traversal.md) — STUN-based NAT traversal for mesh connectivity
- [Peer Endpoint Exchange](reference/networking/peer-endpoint-exchange.md) — Peer endpoint discovery and exchange
- [Network Policy Enforcement](reference/networking/network-policy.md) — Network policy rules and enforcement
- [nftables Firewall Controller](reference/networking/nftables-firewall.md) — nftables-based firewall management
- [Secure Access Tunneling](reference/networking/secure-access-tunneling.md) — Secure tunnel access for services

### Bridge

Gateway/bridge mode, NAT relay, VPN and tunnel providers, and ingress.

> **Note:** The subsystems in this section have code in the repository but are not active in the current release. Their configuration is parsed but the subsystems are not started. See individual pages for details.

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

Metrics, logs, and audit event forwarding.

- [Metrics Collection & Reporting](reference/observability/metrics-collection.md) — System metrics collection and forwarding
- [Log Forwarding](reference/observability/log-forwarding.md) — Log collection and forwarding to the control plane
- [Audit Forwarding](reference/observability/audit-forwarding.md) — Audit event collection and forwarding

### Actions

Remote actions, hooks, and integrity verification.

- [Remote Actions and Hooks](reference/actions/remote-actions-hooks.md) — Remote action execution and hook system
- [PlexdHook CRD Reference](reference/actions/plexdhook-crd.md) — Kubernetes CRD for declarative hook execution
- [Integrity Verification](reference/actions/integrity-verification.md) — Hook integrity verification via checksums

### Deployment

Packaging, container images, and deployment manifests.

- [Bare-Metal Packaging Reference](reference/deployment/bare-metal-packaging.md) — Systemd service installation and packaging
- [Cloud-Init VM Deployment Reference](reference/deployment/cloud-init-vm-deployment.md) — IMDS provider, cloud-init templates, and Terraform examples
- [Kubernetes DaemonSet Deployment Reference](reference/deployment/kubernetes-deployment.md) — Kubernetes manifests, RBAC, and DaemonSet configuration
- [Container Image (Dockerfile) Reference](reference/deployment/dockerfile.md) — Container image build and configuration

### Development

CI/CD workflows, E2E tests, and utilities.

- [CI Workflow](reference/development/ci-workflow.md) — Continuous integration workflow
- [Container Workflow](reference/development/container-workflow.md) — Container image build workflow
- [Release Workflow](reference/development/release-workflow.md) — Release and versioning workflow
- [E2E Workflow](reference/development/e2e-workflow.md) — End-to-end test orchestration workflow
- [Docker E2E Test](reference/development/docker-e2e-test.md) — Docker Compose-based E2E test
- [Kubernetes E2E Test](reference/development/kubernetes-e2e-test.md) — kind-based Kubernetes E2E test
- [Systemd E2E Test](reference/development/systemd-e2e-test.md) — Systemd-based E2E test
- [Mock Central API Server](reference/development/mock-api-server.md) — Mock API server for testing
- [File System Utilities](reference/development/fsutil.md) — File system utility functions
