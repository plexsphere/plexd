---
title: WireGuard Tunnel Management
package: internal/wireguard
feature: PXD-0005
---

# WireGuard Tunnel Management

The `internal/wireguard` package creates, configures, and manages WireGuard interfaces and peer entries. It establishes direct encrypted tunnels to all authorized peers within the same tenant, handles peer configuration lifecycle, and integrates with the reconciliation loop and SSE event stream for continuous convergence.

All OS-level WireGuard operations go through a `WGController` interface, enabling full unit testing without root privileges or kernel modules.

## Config

`Config` holds WireGuard interface parameters passed to the `Manager` constructor.

| Field           | Type     | Default | Description                          |
|-----------------|----------|---------|--------------------------------------|
| `InterfaceName` | `string` | `plexd0`   | WireGuard network interface name     |
| `ListenPort`    | `int`    | `51820` | UDP listen port                      |
| `MTU`           | `int`    | `0`     | Interface MTU (0 = system default)   |

```go
cfg := wireguard.Config{
    ListenPort: 51821,
}
cfg.ApplyDefaults() // sets InterfaceName to "plexd0", ListenPort stays 51821
if err := cfg.Validate(); err != nil {
    log.Fatal(err) // rejects port <=0 or >65535, negative MTU
}
```

### Validation Rules

| Field           | Rule                        | Error Message                                           |
|-----------------|-----------------------------|---------------------------------------------------------|
| `ListenPort`    | Must be 1–65535             | `wireguard: config: ListenPort must be between 1 and 65535` |
| `MTU`           | Must be >= 0                | `wireguard: config: MTU must not be negative`           |

## WGController

Interface abstracting OS-level WireGuard operations. The production implementation (netlink/userspace) is provided externally; this package defines and consumes the interface.

```go
type WGController interface {
    CreateInterface(name string, privateKey []byte, listenPort int) error
    DeleteInterface(name string) error
    ConfigureAddress(name string, address string) error
    SetInterfaceUp(name string) error
    SetMTU(name string, mtu int) error
    AddPeer(iface string, cfg PeerConfig) error
    RemovePeer(iface string, publicKey []byte) error
}
```

## PeerConfig

WireGuard-native peer configuration. Keys are raw bytes (decoded from base64).

```go
type PeerConfig struct {
    PublicKey           []byte   // 32-byte Curve25519 public key
    Endpoint            string   // host:port (may be empty)
    AllowedIPs          []string // e.g., ["10.0.0.2/32"]
    PSK                 []byte   // nil if no pre-shared key
    PersistentKeepalive int      // seconds (0 = disabled)
}
```

### PeerConfigFromAPI

Translates an `api.Peer` (base64-encoded wire format) to a `PeerConfig` (raw bytes).

```go
func PeerConfigFromAPI(peer api.Peer) (PeerConfig, error)
```

- `PublicKey`: decoded via `base64.StdEncoding` (error if invalid)
- `PSK`: decoded if non-empty; `nil` if empty string
- `Endpoint`: copied as-is (may be empty for NAT-traversal peers)
- `AllowedIPs`: copied as-is

## PeerIndex

Thread-safe mapping from peer IDs (control plane identifiers) to base64-encoded public keys (WireGuard identifiers). Protected by `sync.RWMutex`.

```go
func NewPeerIndex() *PeerIndex
```

| Method                              | Description                                      |
|-------------------------------------|--------------------------------------------------|
| `Add(peerID, publicKey string)`     | Adds or overwrites mapping                       |
| `Remove(peerID string)`             | Removes mapping (no-op if absent)                |
| `Lookup(peerID string) (string, bool)` | Returns public key and whether found          |
| `Update(peerID, newPublicKey string)` | Updates mapping (semantically distinct from Add) |
| `LoadFromPeers(peers []api.Peer)`   | Bulk-populates; clears existing entries first    |

## Manager

Central coordinator for WireGuard interface and peer lifecycle.

### Constructor

```go
func NewManager(ctrl WGController, cfg Config, logger *slog.Logger) *Manager
```

- Applies config defaults via `cfg.ApplyDefaults()`
- Creates an empty `PeerIndex`

### Methods

| Method          | Signature                                                                    | Description                                                    |
|-----------------|------------------------------------------------------------------------------|----------------------------------------------------------------|
| `Setup`         | `(ctx context.Context, identity *registration.NodeIdentity) error`           | Creates interface, assigns the mesh IP with the `domain_mesh_cidr` prefix (fallback `/32`), sets MTU if > 0, brings up |
| `Teardown`      | `() error`                                                                   | Deletes the WireGuard interface                                |
| `AddPeer`       | `(peer api.Peer) error`                                                      | Translates and adds peer; updates index                        |
| `RemovePeer`    | `(publicKey []byte) error`                                                   | Removes peer by raw public key                                 |
| `RemovePeerByID`| `(peerID string) error`                                                      | Resolves ID via index, removes peer, cleans index              |
| `UpdatePeer`    | `(peer api.Peer) error`                                                      | Upserts peer config (AddPeer is idempotent); updates index     |
| `ConfigurePeers`| `(ctx context.Context, peers []api.Peer) error`                              | Bulk-adds peers with context cancellation; individual errors logged |
| `PeerIndex`     | `() *PeerIndex`                                                              | Returns the peer index                                         |

### Lifecycle

```go
logger := slog.Default()

// Create manager with a WGController implementation
mgr := wireguard.NewManager(ctrl, wireguard.Config{}, logger)

// Setup interface using node identity from registration
identity, _ := registration.LoadIdentity("/var/lib/plexd")
if err := mgr.Setup(ctx, identity); err != nil {
    log.Fatal(err)
}

// Configure initial peers from registration response
if err := mgr.ConfigurePeers(ctx, registerResponse.Peers); err != nil {
    log.Fatal(err)
}

// Individual peer operations (driven by SSE events or reconciliation)
mgr.AddPeer(newPeer)
mgr.UpdatePeer(updatedPeer)
mgr.RemovePeerByID("peer-123")

// Graceful shutdown
if err := mgr.Teardown(); err != nil {
    logger.Warn("teardown failed", "error", err)
}
```

### Setup Sequence

1. `CreateInterface(name, privateKey, listenPort)` — create WireGuard interface with node's private key
2. `ConfigureAddress(name, meshIP+"/<prefix>")` — assign the mesh IP. The prefix length comes from the registration `domain_mesh_cidr`, so the kernel installs an on-link route for the whole mesh (which the snapshot peers, advertised as `mesh_ip/32`, rely on). Identities without the field, or with an unparseable value, fall back to a host `/32` (the unparseable case is logged as a warning)
3. `SetMTU(name, mtu)` — only if `Config.MTU > 0`
4. `SetInterfaceUp(name)` — bring the interface up

### Error Handling

| Method            | Individual Peer Failure          | Context Cancellation       |
|-------------------|----------------------------------|----------------------------|
| `AddPeer`         | Returns error                    | —                          |
| `RemovePeerByID`  | Returns error                    | —                          |
| `UpdatePeer`      | Returns error                    | —                          |
| `ConfigurePeers`  | Logged at error, continues       | Returns context error      |

### Logging

All log entries use `component=wireguard`. Private keys and PSKs are never logged.

| Level   | Event                        | Keys                                  |
|---------|------------------------------|---------------------------------------|
| `Info`  | Interface configured         | `interface`, `listen_port`, `mesh_ip` |
| `Info`  | Peers configured (bulk)      | `count`                               |
| `Debug` | Peer added/removed/updated   | `peer_id`                             |
| `Error` | Peer operation failed (bulk) | `peer_id`, `error`                    |

## ReconcileHandler

Factory function returning a `reconcile.ReconcileHandler` that applies peer changes from the `StateDiff`. Peer membership comes solely from the snapshot `peers` block.

```go
func ReconcileHandler(mgr *Manager) reconcile.ReconcileHandler
```

### Processing Order

1. **Removes** — `diff.PeersToRemove` (node IDs) via `RemovePeerByID`
2. **Updates** — `diff.PeersToUpdate` via `UpdatePeer`
3. **Adds** — `diff.PeersToAdd` via `AddPeer`

Adds and updates carry `api.SnapshotPeer` entries, converted to the WireGuard `api.Peer` by `peerFromSnapshot`:

- `AllowedIPs` is derived locally as `mesh_ip/32` — the snapshot never sends allowed IPs.
- `Endpoint` is the peer's `fallback_endpoint` (the relay target). Direct endpoints keep arriving via the untouched `peer_endpoint_changed` SSE path.
- **No PSK is fabricated** — peers are configured without a preshared key. PSK distribution is deferred until the control plane exposes one.

Individual failures are logged and collected. The handler returns an aggregated error via `errors.Join` (nil if all succeed). This ensures the reconciler marks the cycle as failed and retries on the next tick.

### Registration

```go
mgr := wireguard.NewManager(ctrl, wireguard.Config{}, logger)

r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(wireguard.ReconcileHandler(mgr))
```

The agent registers this handler **only when WireGuard `Setup` succeeded**. On hosts without a programmable WireGuard stack the interface fails to come up, the agent continues without WireGuard, and the peer reconcile handler is skipped — a handler that failed every cycle would hold the reconciler snapshot back and prevent convergence (for example, the policy fingerprint short-circuit could never hold).

## Peer Programming

There are no WireGuard-specific SSE handlers. Peers are programmed from the
authoritative state snapshot, not from fine-grained events. The peer topology
events (`peer_registered`, `peer_psk_assigned`, `peer_deregistered`,
`peer_endpoint_changed`, `peer_key_rotated`) carry opaque payloads and dispatch to
`TriggerReconcile()`; the reconcile loop then pulls the snapshot and
`ReconcileHandler` (see above) converges the interface.

`peerFromSnapshot(api.SnapshotPeer) (api.Peer, error)` builds each programmed
peer from a snapshot entry, deriving `AllowedIPs` locally as `mesh_ip/32`. The
manager then adds, updates, or removes peers so the interface matches the desired
set.

## Integration Points

### Registration Bootstrap

After registration, pass initial peers to `ConfigurePeers`:

```go
identity, _ := reg.Register(ctx)
mgr.Setup(ctx, identity)
mgr.ConfigurePeers(ctx, registerResponse.Peers)
```

### Reconciliation Loop

The reconcile handler ensures WireGuard state converges to desired state even after missed SSE events, network partitions, or agent restarts.

### SSE Real-Time Updates

Peer topology events trigger a reconcile for a prompt convergence; the reconcile
loop also catches any missed changes on its next cycle. The snapshot pull, not the
event payload, is authoritative.

### Graceful Shutdown

Call `Teardown()` on context cancellation to remove the WireGuard interface:

```go
<-ctx.Done()
if err := mgr.Teardown(); err != nil {
    logger.Warn("wireguard teardown failed", "error", err)
}
```
