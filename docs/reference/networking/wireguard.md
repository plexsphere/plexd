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

Interface abstracting OS-level WireGuard operations. The Linux implementation is `NetlinkController` (`controller_linux.go`); the macOS implementation is `DarwinController` (`controller_darwin.go`) and the Windows one is `WindowsController` (`controller_windows.go`), both built on the userspace backend below.

```go
type WGController interface {
    CreateInterface(name string, privateKey []byte, listenPort int) error
    DeleteInterface(name string) error
    ConfigureAddress(name string, address string) error
    SetInterfaceUp(name string) error
    SetMTU(name string, mtu int) error
    AddPeer(iface string, cfg PeerConfig) error
    RemovePeer(iface string, publicKey []byte) error
    SetPrivateKey(name string, privateKey []byte) error
}
```

## Userspace backend

`UserspaceBackend` (`internal/wireguard/userspace.go`) runs wireguard-go devices inside the plexd process. It is the base of the macOS (utun) and Windows (Wintun) `WGController` implementations and of the bridge access and site-to-site controllers. On Linux plexd stays on the kernel path through `NetlinkController`; the backend compiles and is tested there but is not wired in.

The caller creates the tun device and hands it to `CreateDevice`; the backend owns the wireguard-go device lifecycle, the private key, the listen port and the peers. Addressing, MTU and the interface flag stay with the per-OS controller. Devices are keyed by the configured interface name, so `wg show <name>` works even where the kernel gives the tun another name (`utunN` on macOS).

```go
func NewUserspaceBackend(logger *slog.Logger) *UserspaceBackend

func (b *UserspaceBackend) CreateDevice(name string, tdev tun.Device, privateKey []byte, listenPort int) error
func (b *UserspaceBackend) DeleteDevice(name string) error
func (b *UserspaceBackend) SetPrivateKey(name string, privateKey []byte) error
func (b *UserspaceBackend) AddPeer(name string, cfg PeerConfig) error
func (b *UserspaceBackend) RemovePeer(name string, publicKey []byte) error
```

- **`CreateDevice`** takes ownership of `tdev`: it closes the tun on any error, and the caller never closes a tun it handed in. It sets the key and port, brings the device up, and serves the UAPI endpoint. Because the device is brought up here, a listen port already in use surfaces as an error from this call. A `listenPort` of `0` binds an ephemeral port.
- **`DeleteDevice`** closes the UAPI listener and the device, which closes the tun. It is idempotent: deleting an unknown device returns `nil`.
- **`SetPrivateKey`**, **`AddPeer`** and **`RemovePeer`** return an error wrapping `os.ErrNotExist` for an unknown device. `AddPeer` upserts by public key and validates its input in the same order and with the same error text as `NetlinkController`; `RemovePeer` is silent for a public key with no matching peer.

### UAPI endpoint

The backend serves the WireGuard UAPI for each device so `wg show` and any `wgctrl` reader can query it: a Unix socket at `/var/run/wireguard/<name>.sock` on macOS (`uapi_unix.go`) and the named pipe `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>` on Windows (`uapi_windows.go`).

Configuration is applied in process through the device's UAPI text protocol (`device.Device.IpcSet`), not through `wgctrl`. `wgctrl`'s userspace transport reaches a device only through a root-owned socket directory on Unix and a LocalSystem-owned named pipe on Windows, so it cannot configure the device from an unprivileged test; the in-process path is the same in production and under test on all three platforms. The served endpoint still lets `wgctrl` and `wg(8)` read the device.

wireguard-go's own log lines are adapted to plexd's `slog.Logger`, appearing at `debug` and `error` with `component=wireguard`. Private keys and preshared keys are never logged.

## macOS controller

`DarwinController` (`internal/wireguard/controller_darwin.go`) is the `WGController` on macOS. It creates the tun device, hands it to the userspace backend, and programs the address, the on-link route, the MTU and the interface flag with `/sbin/ifconfig` and `/sbin/route`. Absolute paths, because launchd starts the daemon with a minimal environment.

`plexd up` must run as root on macOS: creating a utun device is privileged. Without it `CreateInterface` fails with `wireguard: create interface: create utun: operation not permitted (creating a utun device requires root)`, `plexd up` logs `wireguard setup failed, continuing without WireGuard`, and the agent runs on without a tunnel. The launchd daemon `plexd install` registers already runs as root.

### The utunN name

macOS names a WireGuard device `utunN` and accepts no other name. `tun.CreateTUN` is asked for `utun`, which lets the kernel pick the next free unit; an `interface_name` that already names a unit (`utun7`) is passed through, so an operator can pin one.

Everything addressed through plexd keeps the configured name: the backend's device key, the UAPI socket (`wg show plexd0`), the policy chain, the bridge managers and the `status.mesh` report. The kernel name is used for the `ifconfig` and `route` calls, and for the readiness check, which resolves it through `Manager.OSInterfaceName()` because `net.InterfaceByName` knows only `utunN`.

The pairing is logged once per interface, at `info`:

```
utun device created  component=wireguard interface=plexd0 utun=utun4
```

`address configured`, `mtu configured`, `interface brought up`, `route already exists` and `utun device released` carry the same `interface` and `utun` keys at `debug`.

### Commands

| Method | Command |
|---|---|
| `ConfigureAddress` (IPv4) | `ifconfig utunN inet 10.0.0.5/16 10.0.0.5 alias`, then `route -n add -inet 10.0.0.0/16 -interface utunN` |
| `ConfigureAddress` (IPv6) | `ifconfig utunN inet6 fd00::5/64 alias`, then `route -n add -inet6 fd00::/64 -interface utunN` |
| `SetMTU` | `ifconfig utunN mtu 1380` |
| `SetInterfaceUp` | `ifconfig utunN up` |
| `DeleteInterface` | none |

A utun is point-to-point, so the `inet` form takes the destination address after the local one, and the alias installs a host route only. Linux gets the route for the whole prefix implicitly when the address is added, so `ConfigureAddress` adds it here explicitly; otherwise every packet for a mesh peer would leave through the default route. A `/32` or `/128` needs no route, since the alias already installed it. Routes for peer `AllowedIPs` beyond the address prefix belong to the bridge route controller, as they do on Linux.

`route(8)` reports an existing route as `File exists`, which the controller treats as success, matching the idempotency `NetlinkRouteController` grants `EEXIST`.

`DeleteInterface` runs no command: closing the device closes the tun, and the kernel then destroys the `utunN` with its addresses and routes.

A `Config.MTU` of `0` leaves the device at wireguard-go's `device.DefaultMTU` of 1420, the same value the Linux kernel gives a WireGuard link, so "system default" means the same on both platforms.

## Windows controller

`WindowsController` (`internal/wireguard/controller_windows.go`) is the `WGController` on Windows. It creates a Wintun adapter, hands it to the userspace backend, and programs the address and the MTU through the IP Helper API (`CreateUnicastIpAddressEntry` and `SetIpInterfaceEntry`, via `golang.zx2c4.com/wireguard/windows`'s `winipcfg`). Interfaces are addressed by the adapter's LUID, not by name, so nothing depends on the host's display language.

plexd must run as Administrator on Windows: creating a Wintun adapter is privileged. Without it `CreateInterface` fails with `wireguard: create interface: create plexd0: Access is denied. (creating a Wintun adapter requires Administrator)`, `plexd up` logs `wireguard setup failed, continuing without WireGuard`, and the agent runs on without a tunnel. The service `plexd install` registers already runs as LocalSystem.

The adapter carries the configured `interface_name`, so `net.InterfaceByName` and the readiness check resolve it directly and there is no kernel-name indirection of the kind macOS needs. Its GUID is derived from that name, which keeps Windows from registering a new network profile, and applying that profile's firewall category, on every restart. Adapters are registered under the tunnel type `plexd`.

### The driver

Wintun is not part of Windows, and its loader searches only the executable's own directory and System32. `internal/wintundll` carries the signed `wintun.dll` (0.14.1) inside the plexd binary, one architecture per build, and writes it beside `plexd.exe` before the first adapter is created; a file that already matches is left alone. That keeps the release a single `.exe`, so `service.upgrade` still replaces one file and carries a newer driver with it. The driver's licence is committed at `internal/wintundll/LICENSE`.

A missing driver surfaces as `wireguard: create interface: create plexd0: The specified module could not be found. (wintun.dll is missing beside plexd.exe)`.

### Addresses, MTU and the interface flag

| Method | What it does |
|---|---|
| `ConfigureAddress` | `CreateUnicastIpAddressEntry` with the prefix length; no route call |
| `SetMTU` | `SetIpInterfaceEntry` for IPv4 and IPv6, then `ForceMTU` on the running device |
| `SetInterfaceUp` | nothing |
| `DeleteInterface` | nothing beyond closing the device |

The address carries its own prefix length, and Windows installs the on-link route for that prefix itself, the way Linux does when an address is added. macOS is the exception that needs the route added by hand. Routes for peer `AllowedIPs` beyond the address prefix belong to the bridge route controller, as they do everywhere else. An address already on the adapter is reported as `ERROR_OBJECT_ALREADY_EXISTS`, which the controller treats as success.

The MTU is programmed twice over an interface's life: once at creation, to 1420, and again whenever the configuration asks for another value. Creating the adapter records the MTU in wireguard-go's own field without telling the interface, and no OS event ever reports an MTU change back on Windows, so the controller both programs the interface and pushes the value to the running device. A `Config.MTU` of `0` therefore still means 1420, as it does on Linux and macOS.

`SetInterfaceUp` runs nothing: a Wintun adapter's media state is connected from the moment its session starts inside `CreateTUN`. `DeleteInterface` runs nothing either, because closing the device closes the tun, which ends the session and closes the adapter; Windows then removes it with its addresses and routes. The adapter is scoped to the handles that own it, so it also disappears if the process dies without a clean shutdown.

The UAPI named pipe is `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>`, so `wg show plexd0` works against the running service. Its security descriptor grants LocalSystem and Administrators full access under a high mandatory label, but names no owner, so the creating process becomes the owner. wireguard-go's own descriptor assigns the pipe to LocalSystem, which only a LocalSystem process may do: an elevated Administrator running `plexd up` by hand would fail to open the pipe at all, and with it the interface. The cost of leaving the owner out is that `wgctrl`, which requires a LocalSystem-owned pipe, does not find a device belonging to a plexd started from a console; against the service, which is how plexd runs, `wg show` is unaffected.

Until the Windows firewall controller lands, Windows Defender Firewall may drop unsolicited inbound handshakes on the listen port. Handshakes plexd initiates are unaffected, so a node behind it still reaches peers that are reachable.

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
| `OSInterfaceName` | `() string`                                                                | The name the OS knows the interface by (`utunN` on macOS), else `Config.InterfaceName` |
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
2. `ConfigureAddress(name, meshIP+"/<prefix>")` — assign the mesh IP. The prefix length comes from the registration `domain_mesh_cidr`, so the kernel installs an on-link route for the whole mesh (which the snapshot peers, advertised as `mesh_ip/32`, rely on). Identities without the field, or with an unparseable value, fall back to a host `/32` (the unparseable case is logged as a warning). On macOS the on-link route is not implicit and `DarwinController` installs it explicitly (see [macOS controller](#macos-controller))
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
