# plexd - Project Overview

## Purpose
plexd is a node agent for the Plexsphere platform. It runs on every node in a managed environment, connecting to the control plane, registering nodes, establishing encrypted WireGuard mesh tunnels, enforcing network policies, and reconciling local state.

## Tech Stack
- **Language:** Go 1.24.0
- **Module:** github.com/plexsphere/plexd
- **Dependencies:** go.uber.org/goleak, golang.org/x/crypto
- **Platform:** Linux (amd64, arm64)

## Project Structure
- `internal/` - All packages are internal
  - `registration/` - Node self-registration
  - `tunnel/` - WireGuard tunnel management
  - `bridge/` - Bridge/gateway mode
  - `wireguard/` - WireGuard operations
  - `policy/` - Network policy enforcement
  - `reconcile/` - State reconciliation
  - `nat/` - NAT traversal
  - `peerexchange/` - Peer endpoint exchange
  - `metrics/` - Metrics collection
  - `logfwd/` - Log forwarding
  - `auditfwd/` - Audit data forwarding
  - `actions/` - Remote actions and hooks
  - `nodeapi/` - Local node API
  - `api/` - API types
  - `fsutil/` - File system utilities
  - `integrity/` - Binary integrity checking
  - `packaging/` - Systemd service packaging
