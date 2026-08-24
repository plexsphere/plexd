---
title: Getting Started with Development
package: cmd/plexd
feature: PXD-0026
---

# Getting Started with Development

## Prerequisites

- Go 1.26+
- WireGuard tools (`wg`, `wg-quick`)
- nftables
- Docker (for integration tests)

## Make Targets

```bash
make build        # Build binary
make test         # Run unit tests
make test-e2e     # Run integration tests (requires Docker)
make lint         # Run linter
```

## Project Structure

```
plexd/
├── cmd/                    # CLI entrypoints
│   └── plexd/
├── internal/
│   ├── actions/            # Remote actions, hook execution, file watcher
│   ├── agent/              # Core agent lifecycle and heartbeat
│   ├── api/                # Control plane API client, SSE, event verification
│   ├── auditfwd/           # Audit log collection and forwarding (auditd, K8s)
│   ├── bridge/             # Bridge mode: user access, public ingress, site-to-site, relay
│   ├── fsutil/             # Atomic file operations
│   ├── integrity/          # Binary and file integrity verification
│   ├── kubernetes/         # K8s detection, CRD controller, PlexdHook types
│   ├── logfwd/             # Log collection and forwarding (journald, file sources)
│   ├── metrics/            # Metrics collection, system stats, tunnel stats
│   ├── nat/                # STUN-based NAT traversal and endpoint discovery
│   ├── nodeapi/            # Local Node API server, state cache, report sync
│   ├── packaging/          # Bare-metal installer, systemd unit generation
│   ├── peerexchange/       # Peer endpoint exchange protocol
│   ├── policy/             # Network policy evaluation, nftables firewall rules
│   ├── reconcile/          # Configuration reconciliation loop
│   ├── registration/       # Token handling, enrollment, Ed25519 key management
│   ├── tunnel/             # SSH server, secure access tunneling, K8s API proxy
│   └── wireguard/          # WireGuard interface management via netlink
├── deploy/
│   ├── cloud-init/         # Cloud-init templates and Terraform examples
│   ├── install.sh          # Bare-metal installer script
│   ├── kubernetes/         # DaemonSet manifests, RBAC
│   │   └── crds/           # Custom Resource Definitions (PlexdHook, PlexdNodeState)
│   └── systemd/            # Unit files
├── docs/
│   ├── how-to/             # Task-oriented guides
│   └── reference/          # API and configuration reference
├── Makefile
└── README.md
```

## Platform-specific files

Code that only builds on some operating systems lives in its own file, tagged by the platform it serves. Two conventions are in use:

| Tag | File suffix | Used for | Examples |
|---|---|---|---|
| `//go:build linux` / `//go:build !linux` | `_linux.go` / `_other.go` | Controllers that exist only on Linux, paired with a stub elsewhere | `cmd/plexd/cmd/up_linux.go`, `cmd/plexd/cmd/up_other.go`, `internal/nodeapi/socket_perms_other.go` |
| `//go:build unix` / `//go:build windows` | `_unix.go` / `_windows.go` | Syscall helpers that Linux and macOS share | `internal/actions/builtins_unix.go`, `internal/actions/builtins_windows.go` |

Pick `unix` / `windows` when Linux and macOS want the same implementation; `!linux` would wrongly catch Windows. Every such file carries an explicit `//go:build` line, even when its name already implies the constraint: only `_windows.go`, `_linux.go` and `_darwin.go` are implicit to the Go tool, and `_unix.go` and `_other.go` are not.

Before pushing, check that the tree still builds for every supported target:

```bash
for t in linux/amd64 linux/arm64 linux/mipsle darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go build ./... || exit 1
done

for t in linux/amd64 linux/arm64 linux/mipsle darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go vet ./... || exit 1
done
```

`go vet` compiles the test files too, so it catches a platform-tagged test that no longer builds.

## Client-Side Implementation

| Module | Responsibility |
|---|---|
| `internal/registration/` | Generate key pair, exchange bootstrap token for node identity |
| `internal/api/` | SSE stream, receive peer updates with public keys and PSKs, Ed25519 event signature verification |
| `internal/wireguard/` | WireGuard interface management via netlink, apply key and peer configuration |
| `internal/nat/` | STUN discovery, report and receive endpoint updates |
| `internal/peerexchange/` | Peer endpoint exchange protocol |
| `internal/reconcile/` | Periodic full-state comparison: local WireGuard config vs. control plane |
| `internal/actions/` | Remote actions, hook execution engine, checksum verification, file watcher |
| `internal/tunnel/` | SSH server, secure access tunneling, K8s API proxy |
| `internal/nodeapi/` | Local Node API server (Unix socket + optional TCP), auth, state cache, report sync |
| `internal/kubernetes/` | K8s detection, CRD controller, PlexdHook types |
