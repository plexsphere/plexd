# plexd

[![Docs](https://img.shields.io/badge/docs-GitHub_Pages-blue?logo=vitepress)](https://plexsphere.github.io/plexd/)
[![DeepWiki](https://img.shields.io/badge/DeepWiki-plexsphere%2Fplexd-blue.svg?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAC/ElEQVR4AcXBsW4TURRA0bN3xhN7JpNgESUiSIiGMg19fiAfQE1FgWgoqOjSRUoRKUWUNJEcx3bsGc+desACSgrkL3DORz5+/XKL+I/EN5e3OHm7BKe6vMfJcMC7i4s4O1zw6fMVOFXkPU4sBzmcy0Jn+3CKSI2T+B3FRILjEhyjkrhp6OMiNc5JLpefSTy4TBjEJ0JGkmMCt7h8RM5J3F68IHCYL1GkmEnkMkmMiaQjipxT1PQ8uPr5itev9vnw5hkn8x1O3j17D86OmDCC5HDtM4rDiE3GEGJSZ3YJDR0UyQUFO5CSy71MkLscFn1U35GMGFPkXbIPhqq+p7iql0rMNBXVVIqC+L+lMndUk7mI/EycKOaDShKINNFR0R/R0TE6KBI6ogjVpCYz3CVtLhN3miApIxnxP0OIcSSIjSp1Th8HTPV2sMZJdsAiT4URG7PdNMQY4zCJjJhExkTSYdOKjkhGRrLLBqMb8X5BYmqCPl08xsnTJ4844h1x4iDHEuMgNYkjeSFweNUEMCGLSSSISRkBR6/2SUzLJC4TGStJRGS0KKXICJNILEZJ+B0mHSWSWJhERIyLpqMI/UQSR0mFaSCExJjOZwNGM4CJJnEjkqCSxOEnkMIlMIiIS2SQSGWdNJqOSmExGiJdSckwy4l0yYhKJrJJBnFSa2BlRTCK3SmZMYkYkeaGQySCOOIkRp5L9UBDb24TPU0J8TSZM5MxvOQnptCLHkhMJJqETOMc4M77aIWEih4JkF2gmMVElK8l+KCSR2ClJjkNhhxIZJ9F7fplEHheJjAlGIjOdCXHGzqGDNyQO3Uf8NjSR2KlkH5OIGV+LYrBKJmt8oJh1Rjb1iBNRJL8jkX1Q5HGR7GPfEGsik0gkMpEI7JKZlFAUPVFl/IuSGJNJRCS2Ei2tGeK/C44Y4qSTSiCRNLqo8m/j8p4i/4M+5KGOO0Y3yocrpT8Mq7tGdKHJX+bIaZFA7dER/RAjcHGYT0fVY/v4LPIi/c0N8+h/W/34DpKhN7JuFvpoAAAAASUVORK5CYII=)](https://deepwiki.com/plexsphere/plexd)

plexd runs on every node in a Plexsphere-managed environment. It connects to
the control plane, registers the node, establishes encrypted WireGuard mesh
tunnels to peers, enforces network policies, and continuously reconciles
local state against the desired state.

> **MVP / Work in Progress** – This project is under active development.
> APIs, configuration formats, protocols, and internal interfaces are subject
> to change without prior notice. Do not rely on current behavior or
> interfaces for production use.

## Key Capabilities

- **Self-Registration** with one-time bootstrap tokens (Cloud-Init, K8s Secret, or manual enrollment)
- **Mesh Connectivity** via direct encrypted WireGuard tunnels between authorized peers
- **NAT Traversal** with STUN endpoint discovery and bridge-node relay fallback
- **Policy Enforcement** through peer visibility filtering and local firewall rules
- **Configuration Reconciliation** against the control plane's source of truth
- **Bridge Mode** for user access, public ingress, site-to-site VPN, and NAT relay
- **Observability** with metrics collection, log forwarding, and audit data forwarding
- **Remote Actions & Hooks** with SHA-256 integrity verification
- **Local Node API** exposing node state via Unix socket (bare-metal/VM) or CRD (Kubernetes)
- **Secure Access** for platform-mediated SSH and Kubernetes API tunneling through the mesh

Runs on bare-metal servers, VMs, Kubernetes clusters, OpenWRT routers, and as
bridge/gateway. Linux (amd64, arm64, mipsle).

## Quick Start

```bash
# Install
curl -fsSL https://get.plexsphere.com/plexd | sh

# Enroll the node (interactive token prompt)
plexd join

# Run as a service
sudo plexd install
sudo systemctl enable --now plexd
```

See [Installation & Quick Start](https://plexsphere.github.io/plexd/guide/installation.html)
for container, Kubernetes, OpenWRT, and bridge-mode deployments.

## Documentation

The full documentation lives at **<https://plexsphere.github.io/plexd/>**:

- [Installation & Quick Start](https://plexsphere.github.io/plexd/guide/installation.html)
- [Architecture](https://plexsphere.github.io/plexd/guide/architecture.html), [Agent Lifecycle](https://plexsphere.github.io/plexd/guide/agent-lifecycle.html), and [Security & Trust Model](https://plexsphere.github.io/plexd/guide/security.html)
- How-to guides for [bare-metal](https://plexsphere.github.io/plexd/how-to/bare-metal-installation.html), [VM](https://plexsphere.github.io/plexd/how-to/vm-deployment.html), and [Kubernetes](https://plexsphere.github.io/plexd/how-to/kubernetes-deployment.html) deployments
- Reference for the [CLI](https://plexsphere.github.io/plexd/reference/core/cli.html), [configuration](https://plexsphere.github.io/plexd/reference/core/configuration.html), [environment variables](https://plexsphere.github.io/plexd/reference/core/environment-variables.html), and [control plane API](https://plexsphere.github.io/plexd/reference/core/api-endpoints.html)
- [Troubleshooting](https://plexsphere.github.io/plexd/guide/troubleshooting.html)

The documentation source is in [docs/](docs/); preview locally with
`npm install && npm run docs:dev`.

## Development

Requires Go 1.26+, WireGuard tools, and nftables.

```bash
make build   # Build the plexd binary
make test    # Run unit tests
make lint    # Run golangci-lint
```

See [Development: Getting Started](https://plexsphere.github.io/plexd/reference/development/getting-started.html)
for the project structure, e2e tests, and CI workflows.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
