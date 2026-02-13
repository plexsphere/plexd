---
title: WireGuard Tunnel Management
quadrant: backend
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
| `Setup`         | `(ctx context.Context, identity *registration.NodeIdentity) error`           | Creates interface, assigns mesh IP/32, sets MTU if > 0, brings up |
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
2. `ConfigureAddress(name, meshIP+"/32")` — assign mesh IP as point-to-point address
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

Factory function returning a `reconcile.ReconcileHandler` that applies peer changes from the `StateDiff`.

```go
func ReconcileHandler(mgr *Manager) reconcile.ReconcileHandler
```

### Processing Order

1. **Removes** — `diff.PeersToRemove` via `RemovePeerByID`
2. **Updates** — `diff.PeersToUpdate` via `UpdatePeer`
3. **Adds** — `diff.PeersToAdd` via `AddPeer`

Individual failures are logged and collected. The handler returns an aggregated error via `errors.Join` (nil if all succeed). This ensures the reconciler marks the cycle as failed and retries on the next tick.

### Registration

```go
mgr := wireguard.NewManager(ctrl, wireguard.Config{}, logger)

r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(wireguard.ReconcileHandler(mgr))
```

## SSE Event Handlers

Factory functions returning `api.EventHandler` for real-time peer topology updates. Each parses the `SignedEnvelope.Payload` and calls the appropriate `Manager` method.

| Factory                    | Event Type              | Payload Type               | Action                              |
|----------------------------|-------------------------|----------------------------|-------------------------------------|
| `HandlePeerAdded`          | `peer_added`            | `api.Peer`                 | `AddPeer`                           |
| `HandlePeerRemoved`        | `peer_removed`          | `{"peer_id": "..."}`       | `RemovePeerByID`                    |
| `HandlePeerKeyRotated`     | `peer_key_rotated`      | `api.Peer` (new key)       | `RemovePeerByID` + `AddPeer`        |
| `HandlePeerEndpointChanged`| `peer_endpoint_changed` | `api.Peer` (new endpoint)  | `UpdatePeer`                        |

- Malformed payloads are logged at error level and return an error (the dispatcher logs but does not halt)
- `HandlePeerKeyRotated` removes the old peer first (via index lookup), then adds with the new key. If removal fails (e.g., peer already removed), it continues with the add.

### Registration

```go
mgr := wireguard.NewManager(ctrl, wireguard.Config{}, logger)

dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventPeerAdded, wireguard.HandlePeerAdded(mgr))
dispatcher.Register(api.EventPeerRemoved, wireguard.HandlePeerRemoved(mgr))
dispatcher.Register(api.EventPeerKeyRotated, wireguard.HandlePeerKeyRotated(mgr))
dispatcher.Register(api.EventPeerEndpointChanged, wireguard.HandlePeerEndpointChanged(mgr))
```

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

SSE handlers provide immediate mesh topology updates. The reconcile loop catches any missed changes on its next cycle — SSE handlers do not trigger reconciliation.

### Graceful Shutdown

Call `Teardown()` on context cancellation to remove the WireGuard interface:

```go
<-ctx.Done()
if err := mgr.Teardown(); err != nil {
    logger.Warn("wireguard teardown failed", "error", err)
}
```
