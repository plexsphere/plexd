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
| `EdgePSK`       | `*bool`  | `nil` (enabled) | Fetch each edge's PSK and program it on the peer (`edge_psk`). See [Edge PSKs](#edge-psks) |
| `PersistentKeepalive` | `*time.Duration` | `nil` (25s) | Keepalive interval written on every mesh peer (`persistent_keepalive`). See [Endpoint selection](#endpoint-selection) |

`EdgePSK` is a pointer so that an omitted key stays apart from an explicit `false`. `EdgePSKEnabled()` returns the effective value: true unless the field is set to `false`. `ApplyDefaults` leaves the field alone, so a `false` survives it.

`PersistentKeepalive` is a pointer for the same reason: an omitted key reads as the default, and an explicit `0s` turns the keepalive off. `KeepaliveInterval()` returns the effective value, `DefaultPersistentKeepalive` (25s) when the field is nil. The keepalive makes WireGuard send an empty packet to an idle mesh peer, which holds open the NAT mapping a node opened by dialing out, and which makes WireGuard start a handshake towards an endpoint newly programmed on an idle peer. [Endpoint selection](#endpoint-selection) depends on that handshake, so `0s` turns it off as well.

```go
cfg := wireguard.Config{
    ListenPort: 51821,
}
cfg.ApplyDefaults() // sets InterfaceName to "plexd0", ListenPort stays 51821
if err := cfg.Validate(); err != nil {
    log.Fatal(err) // rejects port <=0 or >65535, negative MTU, an invalid keepalive
}
```

### Validation Rules

| Field           | Rule                        | Error Message                                           |
|-----------------|-----------------------------|---------------------------------------------------------|
| `ListenPort`    | Must be 1–65535             | `wireguard: config: ListenPort must be between 1 and 65535` |
| `MTU`           | Must be >= 0                | `wireguard: config: MTU must not be negative`           |
| `EdgePSK`       | Not validated; any value is accepted | none                                           |
| `PersistentKeepalive` | Must be >= 0          | `wireguard: config: PersistentKeepalive must not be negative` |
| `PersistentKeepalive` | Must be <= 65535s     | `wireguard: config: PersistentKeepalive must not exceed 65535s` |
| `PersistentKeepalive` | Must be a whole number of seconds | `wireguard: config: PersistentKeepalive must be a whole number of seconds` |

The keepalive rules check `KeepaliveInterval()`, so an omitted key passes as 25s. WireGuard carries the interval as a 16-bit count of seconds.

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

### PeerStatsReader

Reading a peer's runtime state is a separate, optional interface. Callers type-assert it on the controller, as they do `OSInterfaceNamer`. Adding the method to `WGController` would force it onto every test double of that interface, none of which needs it.

```go
// PeerStat is one peer's runtime state as the device reports it.
type PeerStat struct {
    PublicKey     [32]byte
    Endpoint      netip.AddrPort // invalid when the device knows no endpoint
    LastHandshake time.Time      // zero when no handshake has completed
    RxBytes       uint64
    TxBytes       uint64
}

// PeerStatsReader is implemented by controllers that can read peer runtime state.
type PeerStatsReader interface {
    PeerStats(name string) ([]PeerStat, error)
}
```

`NetlinkController`, `UserspaceBackend`, `DarwinController` and `WindowsController` implement it. `NetlinkController.PeerStats` opens a wgctrl client per call, as `AddPeer` does, reads the device with `client.Device(name)` and maps each `wgtypes.Peer`: the key bytes, `Endpoint.AddrPort()` when the peer has an endpoint, `LastHandshakeTime` (wgctrl already yields a zero time when no handshake has completed), and the receive and transmit byte counters. Its errors are `wireguard: peer stats: open wgctrl: <cause>` and `wireguard: peer stats: read device: <cause>`; a missing interface wraps `os.ErrNotExist`. `DarwinController` and `WindowsController` delegate to the [userspace backend](#userspace-backend).

## Userspace backend

`UserspaceBackend` (`internal/wireguard/userspace.go`) runs wireguard-go devices inside the plexd process. It is the base of the macOS (utun) and Windows (Wintun) `WGController` implementations and, through those two controllers, of the bridge access and site-to-site controllers (`WGAccessController` and `WGVPNController` in `internal/bridge`), which wrap the platform's `WGController`. On Linux plexd stays on the kernel path through `NetlinkController`; the backend compiles and is tested there but is not wired in.

The caller creates the tun device and hands it to `CreateDevice`; the backend owns the wireguard-go device lifecycle, the private key, the listen port and the peers. Addressing, MTU and the interface flag stay with the per-OS controller. Devices are keyed by the configured interface name, so `wg show <name>` works even where the kernel gives the tun another name (`utunN` on macOS).

```go
func NewUserspaceBackend(logger *slog.Logger) *UserspaceBackend

func (b *UserspaceBackend) CreateDevice(name string, tdev tun.Device, privateKey []byte, listenPort int) error
func (b *UserspaceBackend) DeleteDevice(name string) error
func (b *UserspaceBackend) SetPrivateKey(name string, privateKey []byte) error
func (b *UserspaceBackend) AddPeer(name string, cfg PeerConfig) error
func (b *UserspaceBackend) RemovePeer(name string, publicKey []byte) error
func (b *UserspaceBackend) PeerStats(name string) ([]PeerStat, error)
```

- **`CreateDevice`** takes ownership of `tdev`: it closes the tun on any error, and the caller never closes a tun it handed in. It sets the key and port, brings the device up, and serves the UAPI endpoint. Because the device is brought up here, a listen port already in use surfaces as an error from this call. A `listenPort` of `0` binds an ephemeral port.
- **`DeleteDevice`** closes the UAPI listener and the device, which closes the tun. It is idempotent: deleting an unknown device returns `nil`.
- **`SetPrivateKey`**, **`AddPeer`** and **`RemovePeer`** return an error wrapping `os.ErrNotExist` for an unknown device. `AddPeer` upserts by public key and validates its input in the same order and with the same error text as `NetlinkController`; `RemovePeer` is silent for a public key with no matching peer.
- **`PeerStats`** implements [`PeerStatsReader`](#peerstatsreader). For an unknown device it returns `wireguard: peer stats: <cause>` wrapping `os.ErrNotExist`. It reads the device's UAPI dump with `device.Device.IpcGet` (a failure returns `wireguard: peer stats: read device: <cause>`) and parses it with `parseUAPIPeerStats`.

`parseUAPIPeerStats` splits the dump into `key=value` lines. `public_key` (64 hex characters) starts a new peer; `endpoint` parses with `netip.ParseAddrPort`; `rx_bytes` and `tx_bytes` parse as `uint64`; `last_handshake_time_sec` and `last_handshake_time_nsec` give `time.Unix(sec, nsec)`. Both at 0 give the zero time. The parser does not copy wgctrl's `sec > 0 && nsec > 0` check, which drops a handshake that lands on a whole second. Empty lines and every other key (`private_key`, `listen_port`, `fwmark`, `preshared_key`, `protocol_version`, `persistent_keepalive_interval`, `allowed_ip`, `errno`) are skipped. A dump with device keys only yields an empty slice.

| Input | Error |
|---|---|
| A line without `=` | `wireguard: peer stats: line <n> has no '='` |
| A peer key before any `public_key` | `wireguard: peer stats: <key> before public_key` |
| An unparseable value of one of the six peer keys | `wireguard: peer stats: parse <key>: <cause>` |

No error text quotes a line or the value of a skipped key, because the dump carries `private_key` and `preshared_key`.

### UAPI endpoint

The backend serves the WireGuard UAPI for each device so `wg show` and any `wgctrl` reader can query it: a Unix socket at `/var/run/wireguard/<name>.sock` on macOS (`uapi_unix.go`) and the named pipe `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>` on Windows (`uapi_windows.go`).

Configuration is applied in process through the device's UAPI text protocol (`device.Device.IpcSet`), not through `wgctrl`. `wgctrl`'s userspace transport reaches a device only through a root-owned socket directory on Unix and a LocalSystem-owned named pipe on Windows, so it cannot configure the device from an unprivileged test; the in-process path is the same in production and under test on all three platforms. The served endpoint still lets `wgctrl` and `wg(8)` read the device.

wireguard-go's own log lines are adapted to plexd's `slog.Logger`, appearing at `debug` and `error` with `component=wireguard`. Private keys and preshared keys are never logged.

## macOS controller

`DarwinController` (`internal/wireguard/controller_darwin.go`) is the `WGController` on macOS. It creates the tun device, hands it to the userspace backend, and programs the address, the on-link route, the MTU and the interface flag with `/sbin/ifconfig` and `/sbin/route`. Absolute paths, because launchd starts the daemon with a minimal environment.

`plexd up` must run as root on macOS: creating a utun device is privileged. Without it `CreateInterface` fails with `wireguard: create interface: create utun: operation not permitted (creating a utun device requires root)`, `plexd up` logs `wireguard setup failed, continuing without WireGuard`, and the agent runs on without a tunnel. The launchd daemon `plexd install` registers already runs as root.

### The utunN name

macOS names a WireGuard device `utunN` and accepts no other name. `tun.CreateTUN` is asked for `utun`, which lets the kernel pick the next free unit; an `interface_name` that already names a unit (`utun7`) is passed through, so an operator can pin one.

Everything addressed through plexd keeps the configured name: the backend's device key, the UAPI socket (`wg show plexd0`), the bridge managers and the `status.mesh` report. The kernel name is used for the `ifconfig` and `route` calls, for the [pf policy rules](./pf-wfp-firewall.md#interface-names), for the readiness check and for the route calls the [site-to-site manager](../bridge/site-to-site-vpn.md#sitetositemanager) makes for a tunnel, because `net.InterfaceByName` knows only `utunN`. The first three resolve it through `Manager.OSInterfaceName()`, the last through the bridge controller's `OSInterfaceName`.

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

`route(8)` reports every routing-socket failure in its output and still exits 0, so the controller reads that output whatever the exit status is. `File exists` is success, matching the idempotency `NetlinkRouteController` grants `EEXIST`; any other line carrying `writing to routing socket:` fails with the command line and the message `route(8)` printed. Trusting the exit status would leave the mesh prefix on the default route with nothing recording why.

`DeleteInterface` runs no command: closing the device closes the tun, and the kernel then destroys the `utunN` with its addresses and routes.

A `Config.MTU` of `0` leaves the device at wireguard-go's `device.DefaultMTU` of 1420, the same value the Linux kernel gives a WireGuard link, so "system default" means the same on both platforms.

## Windows controller

`WindowsController` (`internal/wireguard/controller_windows.go`) is the `WGController` on Windows. It creates a Wintun adapter, hands it to the userspace backend, and programs the address and the MTU through the IP Helper API (`CreateUnicastIpAddressEntry` and `SetIpInterfaceEntry`, via `golang.zx2c4.com/wireguard/windows`'s `winipcfg`). Interfaces are addressed by the adapter's LUID, not by name, so nothing depends on the host's display language.

plexd must run as Administrator on Windows: creating a Wintun adapter is privileged. Without it `CreateInterface` fails with `wireguard: create interface: create plexd0: Access is denied. (creating a Wintun adapter requires Administrator)`, `plexd up` logs `wireguard setup failed, continuing without WireGuard`, and the agent runs on without a tunnel. The service `plexd install` registers already runs as LocalSystem.

The adapter carries the configured `interface_name`, so `net.InterfaceByName` and the readiness check resolve it directly and there is no kernel-name indirection of the kind macOS needs. Its GUID is derived from that name, which keeps Windows from registering a new network profile, and applying that profile's firewall category, on every restart. Adapters are registered under the tunnel type `plexd`.

### The driver

Wintun is not part of Windows, and its loader searches only the executable's own directory and System32. `internal/wintundll` carries the signed `wintun.dll` (0.14.1) inside the plexd binary, one architecture per build, and writes it beside `plexd.exe` before the first adapter is created; a file that already matches is left alone. That keeps the release a single `.exe`, so `service.upgrade` still replaces one file and carries a newer driver with it. The driver's licence is committed at `internal/wintundll/LICENSE`.

A missing driver surfaces as `wireguard: create interface: create plexd0: The specified module could not be found. (wintun.dll is missing beside plexd.exe)`.

### Adapter visibility

`CreateInterface` returns only once `net.InterfaceByName` resolves the adapter. Windows settles the IP stack a moment after the adapter appears, while the callers that run next resolve it by name in one attempt and never retry: the route controller's `LookupLUID` and the WFP enforcer's `lookupWinIface`. The lookup is repeated every 200 ms for at most 10 seconds; on the deadline the device is deleted and the call fails with `wireguard: create interface: adapter <name> not visible to the IP stack within 10s:` followed by the lookup error. An adapter that needed more than one attempt is logged at `debug`:

```
wintun adapter visible after wait  component=wireguard interface=plexd0 waited=412ms
```

The adapter is recorded before the wait starts, so the wait runs outside the controller's lock. Holding it for up to ten seconds would block every other method on the same controller — the `ConfigureAddress` and `SetMTU` of an unrelated interface, and the `DeleteInterface` a teardown makes — on a call that only polls.

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

Windows Defender Firewall may drop unsolicited inbound handshakes on the listen port: plexd's own WFP permits are soft and cannot open a port the host firewall closes (see [Soft permits](./pf-wfp-firewall.md#soft-permits)). The [Windows installation guide](../../how-to/windows-installation.md) adds the inbound rule. Handshakes plexd initiates are unaffected, so a node behind it still reaches peers that are reachable.

## PeerConfig

WireGuard-native peer configuration. Keys are raw bytes (decoded from base64).

```go
type PeerConfig struct {
    PublicKey           []byte   // 32-byte Curve25519 public key
    Endpoint            string   // host:port (may be empty)
    AllowedIPs          []string // e.g., ["10.0.0.2/32"]
    PSK                 []byte   // nil if no pre-shared key
    PersistentKeepalive int      // seconds; always written, 0 clears it
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
- `PersistentKeepalive`: always 0

The manager never writes that result as it is. Every mesh peer write goes through `Manager.peerConfig(peer, endpoint)`, which calls `PeerConfigFromAPI`, then sets `Endpoint` to the entry of the [dial order](#dial-order) being programmed (empty to leave the device's endpoint alone) and `PersistentKeepalive` to `KeepaliveInterval()` in whole seconds. `AddPeer`, `UpdatePeer`, `ConfigurePeers`, `SetPeerPSK` and the endpoint selection switch all build their write through it.

For a mesh peer, `api.Peer.PSK` is the edge PSK the [edge PSK store](#edge-psks) holds for the peer's node ID and current public key, base64-encoded, and empty while the store holds none. `NetlinkController.AddPeer` and the [userspace backend](#userspace-backend) leave the device peer's preshared key as it is when `PeerConfig.PSK` is empty, and its endpoint as it is when `Endpoint` is empty. Every write replaces the allowed IPs.

Both write the keepalive interval on every call. `NetlinkController.AddPeer` builds its wgctrl configuration in `netlinkPeerConfig`, which always sets `PersistentKeepaliveInterval`: wgctrl leaves the device's interval as it is for a nil pointer and clears it for a pointer to 0. The userspace backend's `peerUAPI` always emits `persistent_keepalive_interval=<n>`. A `persistent_keepalive: 0s` therefore clears a keepalive an earlier run left on a device peer. Bridge peers get no keepalive: `internal/bridge/wg_controller.go` passes a `PeerConfig` without the field, and the Linux access and site-to-site controllers build their wgctrl configuration without one.

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
| `NodeIDsByPublicKey() map[[32]byte]string` | Reverse map from decoded public key to node ID. Skips a key that does not decode with `base64.StdEncoding` to 32 bytes, and leaves out a key two node IDs share, because no single node owns it |

## Manager

Central coordinator for WireGuard interface and peer lifecycle.

### Constructor

```go
func NewManager(ctrl WGController, cfg Config, logger *slog.Logger) *Manager
```

- Applies config defaults via `cfg.ApplyDefaults()`
- Creates an empty `PeerIndex` and an empty [dial state](#programmed-peers) map
- Sets a local-prefix function that returns no prefixes, until `SetLocalPrefixes` replaces it

### Methods

| Method          | Signature                                                                    | Description                                                    |
|-----------------|------------------------------------------------------------------------------|----------------------------------------------------------------|
| `Setup`         | `(ctx context.Context, identity *registration.NodeIdentity) error`           | Creates interface, assigns the mesh IP with the `domain_mesh_cidr` prefix (fallback `/32`), sets MTU if > 0, brings up |
| `Teardown`      | `() error`                                                                   | Deletes the WireGuard interface                                |
| `OSInterfaceName` | `() string`                                                                | The name the OS knows the interface by (`utunN` on macOS), else `Config.InterfaceName` |
| `AddPeer`       | `(peer api.Peer) error`                                                      | Writes the peer with the first entry of its dial order and starts its endpoint selection; updates index |
| `RemovePeer`    | `(publicKey []byte) error`                                                   | Removes peer by raw public key                                 |
| `RemovePeerByID`| `(peerID string) error`                                                      | Resolves ID via index, removes peer, drops its dial state, cleans index |
| `UpdatePeer`    | `(peer api.Peer) error`                                                      | Rewrites the peer (AddPeer is idempotent): a connected peer with an unchanged key keeps its device endpoint, any other starts its dial order over; updates index. See [Endpoint selection](#endpoint-selection) |
| `ConfigurePeers`| `(ctx context.Context, peers []api.Peer) error`                              | Bulk-adds peers as `AddPeer` does, with context cancellation, and replaces the dial state with the peers it wrote; individual errors logged |
| `PeerIndex`     | `() *PeerIndex`                                                              | Returns the peer index                                         |
| `MeshPeerStats` | `() ([]MeshPeerStat, error)`                                                 | Reads the mesh interface's peers and maps them to node IDs; see [Mesh peer stats](#mesh-peer-stats) |
| `MeshPrefix`    | `() netip.Prefix`                                                            | The Domain mesh prefix the interface was set up with; see [Mesh prefix](#mesh-prefix) |
| `SetPeerPSK`    | `(peerNodeID, publicKey string, psk []byte) error`                           | Rewrites the stored peer of `peerNodeID` with `psk` when it was last written with `publicKey`; see [Installing a PSK](#installing-a-psk) |
| `SetLocalPrefixes` | `(fn func() ([]netip.Prefix, error))`                                     | Sets the function the reconcile handler reads this host's interface prefixes from, to order a peer's on-link candidates first. Call it before the handler runs. See [Dial order](#dial-order) |
| `RunEndpointSelection` | `(ctx context.Context, interval time.Duration) error`                 | Tries each peer's dial order until a handshake completes, one pass per `interval`, until `ctx` is done; see [Endpoint selection](#endpoint-selection) |

The package function `ProgrammedEndpoint` (`handler.go`) returns the endpoint the pull gives a snapshot peer without its candidates, from the peer and `MeshPrefix()`; see [Dial order](#dial-order).

### Programmed peers

The manager keeps a dial state per node ID: the last `api.Peer` it wrote, the position in the peer's dial order of the endpoint programmed on the device, when that endpoint was programmed, and whether a fresh handshake shows the peer connected. `SetPeerPSK` reads the stored peer, because it has to repeat a peer's allowed IPs to write its PSK, and [endpoint selection](#endpoint-selection) reads the rest. `AddPeer` and `UpdatePeer` store the state after a successful device write, `ConfigurePeers` replaces the whole map with the peers it wrote, and `RemovePeerByID` drops the entry after a successful removal. A failed device write in `AddPeer`, `UpdatePeer` or `SetPeerPSK` leaves the state as it was, so a peer whose first write failed has none. One mutex guards the map and serializes every mesh peer device write, since the reconcile handler, the edge PSK store and endpoint selection write the same peers from different call paths.

### Mesh prefix

`Setup` records the prefix of the address it assigns, masked: the Domain mesh CIDR (`10.99.0.0/24` for mesh IP `10.99.0.5` and `domain_mesh_cidr` `10.99.0.0/24`), or the mesh IP's host `/32` when the identity carries no usable `domain_mesh_cidr`. `MeshPrefix` returns it, and returns the zero prefix before `Setup` succeeds. The [dial order](#dial-order) refuses a direct endpoint or candidate inside it, and `plexd up` publishes no [local endpoint candidate](./nat-traversal.md#local-endpoint-candidates) inside it.

### Mesh peer stats

`MeshPeerStats` is the read path behind the [handshake report](../core/heartbeat-service.md#handshake-reporter) and the [tunnel metrics](../observability/metrics-collection.md#tunnelcollector). It reads the interface through the controller's [`PeerStatsReader`](#peerstatsreader) and names each device peer by the node ID the peer index holds for its key.

```go
type MeshPeerStat struct {
    NodeID        string
    Endpoint      netip.AddrPort
    LastHandshake time.Time
    RxBytes, TxBytes uint64
}

var ErrPeerStatsUnsupported = errors.New("wireguard: controller cannot read peer stats")
```

- It returns `ErrPeerStatsUnsupported` when the manager has no controller or the controller is not a `PeerStatsReader`, and wraps a read error as `wireguard: mesh peer stats: <cause>`.
- It keeps only the device peers whose key `PeerIndex.NodeIDsByPublicKey` maps. A key the index does not know, such as one left on the device after a peer's key rotation, is dropped.
- It keeps peers with no handshake (a zero `LastHandshake`), because the metrics report them.
- It returns the result sorted by `NodeID`, and an empty, non-nil slice when nothing maps.
- `Endpoint` passes through unfiltered. The handshake reporter applies the wire rules.

### Endpoint selection

WireGuard holds one endpoint per peer. Endpoint selection (`dial.go`) programs the entries of a peer's [dial order](#dial-order) one after another and keeps the first one that completes a WireGuard handshake. The order only says which entry to try first; a completed handshake proves the choice.

A peer's order is `api.Peer.Endpoints`, or `Endpoint` alone when `Endpoints` is empty and `Endpoint` is set, so a caller that sets only `Endpoint` keeps working. The selection state lives in the manager's [dial state](#programmed-peers), and the device writes change it as follows:

- `AddPeer` programs the first entry of the order, or no endpoint for an empty order, and starts the trial: position 0, programmed now, not connected. `ConfigurePeers` does the same for each peer it loads.
- `UpdatePeer` on a connected peer whose public key is unchanged writes the peer with an empty endpoint, which both controllers leave untouched on the device, so an endpoint WireGuard roamed to stays. It stores the new peer, sets the position to where the entry last programmed sits in the new order (0 when it is no longer there), and keeps the connected flag and the timestamp.
- `UpdatePeer` on a peer that is not connected, or whose public key changed, behaves like `AddPeer` with the new order. WireGuard keys peers by public key, so a rotated key is a new device peer that has no endpoint yet.
- `SetPeerPSK` writes an empty endpoint and leaves the selection as it is.
- `RemovePeerByID` drops the state once the device removal succeeds, so a removed peer is never switched.

#### The trial

Each pass reads the device through [`MeshPeerStats`](#mesh-peer-stats) before it takes the manager's mutex. A read error, `ErrPeerStatsUnsupported` included, ends the pass with nothing written. A peer is fresh when the device reports a non-zero `LastHandshake` for it that is younger than 180 s: WireGuard rekeys a session it uses every two minutes and refuses one older than 180 s, so an older handshake says the path no longer carries traffic. One entry is tried for the keepalive interval plus 5 s, 30 s with the default keepalive. The pass walks the peers in node-ID order:

| Peer | What the pass does |
|---|---|
| Fresh, not marked connected | Marks it connected and logs `wireguard: endpoint selected` with the endpoint the device reports, which may be one WireGuard roamed to |
| Fresh, marked connected | Nothing |
| Not fresh, marked connected | Clears the mark, restarts the timer and logs `wireguard: peer handshake went stale, resuming endpoint selection`. The entry on the device gets a full trial before the next switch |
| Not fresh, not connected, with fewer than 2 entries or programmed less than the trial ago | Nothing |
| Not fresh, not connected, trial over | Programs the next entry (after the last one, the first again), restarts the timer and logs `wireguard: trying next endpoint candidate` |

A peer counts as connected while its latest handshake is younger than 180 s. Neither a pass nor `UpdatePeer` rewrites the device endpoint of a connected peer, so WireGuard roaming, a peer answering from another address, stays in effect.

A failed switch logs `wireguard: endpoint switch failed`, leaves the peer on the entry still programmed, and joins `wireguard: switch endpoint of peer <node id>: <cause>` into the pass's error. The timer restarts all the same, so the next attempt at that entry follows a full trial later.

The trial depends on the keepalive. WireGuard starts a handshake only when it sends something, and the keepalive timer is what makes it send to an entry newly programmed on an idle peer. A switch happens on the first pass after the trial ran out, so up to one interval late. With the defaults, an order of ten entries, the contract's cap of eight candidates plus the direct endpoint and the fallback, reaches its fallback after about 270 s and has tried every entry after about 300 s. A restarted plexd starts every peer at the first entry again.

#### RunEndpointSelection

```go
const EndpointSelectionInterval = 5 * time.Second

func (m *Manager) RunEndpointSelection(ctx context.Context, interval time.Duration) error
```

- With `persistent_keepalive: 0s` it logs `wireguard: endpoint selection disabled, persistent_keepalive is 0s` and returns nil at once. Every peer keeps the first entry of its dial order.
- Otherwise it logs `wireguard: endpoint selection started` with `interval` and `timeout` (the trial) and runs a pass on every tick, the first one interval after it starts.
- A pass that returns `ErrPeerStatsUnsupported` logs `wireguard: endpoint selection unavailable, the controller cannot read peer stats` and returns nil. Peers keep the entry they have.
- Any other pass error logs `wireguard: endpoint selection pass failed` with `error`, and the next tick runs again.
- It returns nil once `ctx` is done.

`plexd up` runs it with `EndpointSelectionInterval` as step 17b, only when the WireGuard interface came up.

#### Cost

The keepalive sends one empty data packet (32 bytes of payload) per idle peer every 25 s and keeps a rekey handshake running about every 2 minutes per peer, so a node with 100 idle peers sends about 4 packets per second. Endpoint selection adds one device read every 5 s, the reconcile handler one interface read each time it runs, and the [candidate publisher](./nat-traversal.md#local-endpoint-candidates) one `PUT` per cycle (60 s by default).

#### Endpoint selection log lines

All carry `component=wireguard`.

| Level  | Message | Keys |
|--------|---------|------|
| `Info` | `wireguard: endpoint selection started` | `interval`, `timeout` |
| `Info` | `wireguard: endpoint selection disabled, persistent_keepalive is 0s` | none |
| `Info` | `wireguard: endpoint selection unavailable, the controller cannot read peer stats` | none |
| `Info` | `wireguard: endpoint selected` | `peer_id`, `endpoint` (empty when the device reports none) |
| `Info` | `wireguard: peer handshake went stale, resuming endpoint selection` | `peer_id` |
| `Info` | `wireguard: trying next endpoint candidate` | `peer_id`, `endpoint`, `attempt` (the entry's 1-based position), `of` (the order's length) |
| `Warn` | `wireguard: endpoint switch failed` | `peer_id`, `endpoint`, `error` |
| `Warn` | `wireguard: endpoint selection pass failed` | `error` |

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

// Individual peer operations (driven by reconciliation; see ReconcileHandler)
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
5. Record the address's masked prefix as the [mesh prefix](#mesh-prefix)

### Error Handling

| Method            | Individual Peer Failure          | Context Cancellation       |
|-------------------|----------------------------------|----------------------------|
| `AddPeer`         | Returns error                    | —                          |
| `RemovePeerByID`  | Returns error                    | —                          |
| `UpdatePeer`      | Returns error                    | —                          |
| `ConfigurePeers`  | Logged at error, continues       | Returns context error      |
| `SetPeerPSK`      | Returns `wireguard: set peer psk: <cause>` | —                |
| `RunEndpointSelection` | A failed switch is logged at warn and the pass goes on | Returns nil |

### Logging

All log entries use `component=wireguard`. Private keys and PSKs are never logged.

| Level   | Event                        | Keys                                  |
|---------|------------------------------|---------------------------------------|
| `Info`  | Interface configured         | `interface`, `listen_port`, `mesh_ip` |
| `Info`  | Peers configured (bulk)      | `count`                               |
| `Debug` | Peer added/removed/updated   | `peer_id`                             |
| `Debug` | Peer PSK set (`peer psk set`) | `peer_id`                            |
| `Error` | Peer operation failed (bulk) | `peer_id`, `error`                    |

Endpoint selection writes the lines in [Endpoint selection log lines](#endpoint-selection-log-lines), and the reconcile handler the dial order lines in [Dial order](#dial-order).

## ReconcileHandler

Factory function returning a `reconcile.ReconcileHandler` that applies peer changes from the `StateDiff`. Peer membership comes solely from the snapshot `peers` block.

```go
func ReconcileHandler(mgr *Manager, psks EdgePSKLookup) reconcile.ReconcileHandler

// EdgePSKLookup returns the edge PSK fetched for a peer, keyed by the peer's
// node ID and the public key it was fetched for.
type EdgePSKLookup interface {
    Lookup(peerNodeID, publicKey string) ([]byte, bool)
}
```

`*EdgePSKs` implements `EdgePSKLookup`; see [Edge PSKs](#edge-psks). A nil `psks` programs no PSK.

### Processing Order

1. **Removes** — `diff.PeersToRemove` (node IDs) via `RemovePeerByID`
2. **Updates** — `diff.PeersToUpdate` via `UpdatePeer`
3. **Adds** — `diff.PeersToAdd` via `AddPeer`

Adds and updates carry `api.SnapshotPeer` entries, converted to the WireGuard `api.Peer` by `peerFromSnapshot(p, order, psk)`, where `order` is the peer's [dial order](#dial-order):

- `AllowedIPs` is derived locally as `mesh_ip/32`. The snapshot never sends allowed IPs. A `mesh_ip` that is not a bare IPv4 address fails the peer.
- `Endpoints` is the dial order and `Endpoint` its first entry, empty for an empty order. The manager programs the first entry and [endpoint selection](#endpoint-selection) moves along the order until a handshake completes. See [Dial order](#dial-order).
- `PSK` is the key `psks.Lookup` returns for the peer's node ID and current `public_key`, base64-encoded. A PSK fetched for another public key is never returned, so a peer whose key changed gets no PSK until the store holds one for the new key. With no PSK the field stays empty, and the store writes the PSK through [`SetPeerPSK`](#installing-a-psk) once it arrives.

Individual failures are logged and collected. The handler returns an aggregated error via `errors.Join` (nil if all succeed). This ensures the reconciler marks the cycle as failed and retries on the next tick.

### Dial order

```go
func dialOrder(p api.SnapshotPeer, local []netip.Prefix, mesh netip.Prefix) (order []string, dropped int)
func ProgrammedEndpoint(p api.SnapshotPeer, mesh netip.Prefix) (endpoint string, directRejected bool)
```

The handler reads this host's interface prefixes, through the function [`SetLocalPrefixes`](#methods) set, and `MeshPrefix()` once per call. For each peer it adds or updates, `dialOrder` builds the order in which [endpoint selection](#endpoint-selection) tries the peer's endpoints:

1. the peer's `endpoint_candidates` that are on-link, on a subnet this node is also on
2. the peer's direct `endpoint`, when it is usable
3. the remaining, off-link candidates
4. the peer's `fallback_endpoint` (the relay target), when it is set

Candidates keep the order the pull lists them in within each group. A duplicate keeps its first position. A peer with no usable candidate, no usable direct endpoint and no fallback gets an empty order and is programmed without an endpoint.

The control plane lists a peer's peer-observed endpoints, NAT mappings other nodes of the Domain completed handshakes over, ahead of its local candidates (see [State](../core/api-endpoints.md#get-v1-nodes-node-id-state)). The on-link test, not the wire position, decides where one lands. A mapping is usually off-link, so it comes after the direct endpoint and ahead of the later off-link candidates. It is on-link, and comes first, only when this node has an address in a prefix that contains it, such as a public address configured on an eligible interface. A mapping on the direct endpoint's address with another port, such as a published `:51820` that the peer's router maps to `:10482`, is a separate entry, tried right after the endpoint.

The direct endpoint and each candidate are held to the same rules. One is usable when all of these hold:

- It parses with `netip.ParseAddrPort` and its port is not 0.
- Its address carries no zone.
- Its address, with an IPv4-mapped IPv6 address unmapped, is not unspecified, loopback, multicast, link-local unicast or link-local multicast.
- It lies outside `mesh`, the Domain mesh prefix from [`MeshPrefix`](#mesh-prefix). An endpoint inside it would be routed through the mesh interface, so WireGuard would send the peer's encrypted packets into its own tunnel. A zero `mesh` skips this check.

A usable endpoint enters the order in canonical form, so `[::ffff:10.0.0.5]:51820` becomes `10.0.0.5:51820`. The fallback enters it as the pull sent it and is never validated, because the contract allows a hostname there.

A candidate is on-link when a local prefix of the same address family contains it. Only a prefix shorter than a host prefix counts: a `/32` or `/128` says nothing about the addresses next to it, so it makes nothing on-link. In `plexd up` the local prefixes are the prefixes of the host addresses [`nat.EligiblePrefixes`](./nat-traversal.md#local-endpoint-candidates) accepts, under the filter the candidate publisher uses. When they cannot be read, the handler logs at `warn` and orders every candidate as off-link, which still tries each of them:

```
wireguard: read local prefixes failed, ordering every candidate as off-link  component=wireguard error=<cause>
```

A refused direct endpoint is left out of the order and logged at `warn`. An absent `endpoint` means the peer has no fresh NAT observation and logs nothing.

```
wireguard: peer direct endpoint unusable, leaving it out of the dial order  component=wireguard peer_id=<node id> endpoint=10.99.0.4:51820 fallback=203.0.113.1:51820
```

Refused candidates are counted in `dropped` and logged at `debug` as `wireguard: dropped endpoint candidates` with `peer_id` and `count`.

`ProgrammedEndpoint` returns what the pull gives a peer without its candidates: the direct `endpoint` when it is usable, the `fallback_endpoint` otherwise. `directRejected` is true only when the peer carried a non-empty `endpoint` that was refused, which is what the handler's `warn` line keys on. The node API's peer list shows this endpoint (see [Node API peer list](#node-api-peer-list)); the endpoint on the device is the one endpoint selection settles on.

The differ compares `endpoint`, `fallback_endpoint` and `endpoint_candidates`, the candidates in order, so a peer whose direct endpoint, fallback or candidates appear, change, reorder or disappear lands in `PeersToUpdate` and is written again. A missing and an empty `endpoint_candidates` compare equal.

### Registration

```go
mgr := wireguard.NewManager(ctrl, wireguard.Config{}, logger)
psks := wireguard.NewEdgePSKs(client, identity.NodeID, nsk, mgr, logger)

r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterDispatchHandler(wireguard.EdgePSKDispatchHandler(psks))
r.RegisterHandler(wireguard.ReconcileHandler(mgr, psks))
```

Without edge PSKs, pass a nil `EdgePSKLookup` interface value, as `plexd up` does. A nil `*EdgePSKs` stored in the interface is not nil to the handler, and its `Lookup` panics.

`plexd up` calls `mgr.SetLocalPrefixes` in step 5a-2, before the handler first runs, with a function that returns `nat.EligiblePrefixes` over `nat.SystemInterfaces()` and passes a read error through. Without that call the handler orders every candidate as off-link.

The agent registers this handler **only when WireGuard `Setup` succeeded**. On hosts without a programmable WireGuard stack the interface fails to come up, the agent continues without WireGuard, and the peer reconcile handler is skipped — a handler that failed every cycle would hold the reconciler snapshot back and prevent convergence (for example, the policy fingerprint short-circuit could never hold).

## Peer Programming

There are no WireGuard-specific SSE handlers. Peers are programmed from the
authoritative state snapshot, not from fine-grained events. The peer topology
events (`peer_registered`, `peer_psk_assigned`, `peer_deregistered`,
`peer_endpoint_changed`, `peer_key_rotated`) dispatch to `TriggerReconcile()`, and
plexd never decodes their payloads. The reconcile loop then pulls the snapshot, the
[edge PSK store](#edge-psks) (when edge PSKs are on) syncs against its peers, and
`ReconcileHandler` (see above) converges the interface.

`peerFromSnapshot(p api.SnapshotPeer, order []string, psk []byte) (api.Peer, error)`
builds each programmed peer from a snapshot entry: `AllowedIPs` derived locally as
`mesh_ip/32`, `Endpoints` set to the [dial order](#dial-order) and `Endpoint` to its
first entry, and `psk` base64-encoded (none for a nil `psk`). The manager then adds,
updates, or removes peers so the interface matches the desired set, and
[endpoint selection](#endpoint-selection) settles each peer's endpoint.

## Edge PSKs

The control plane derives a WireGuard preshared key for every edge, the pair of nodes at the two ends of a tunnel, and serves it to each end sealed under that node's NSK on `GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk` (see [Edge PSK](../core/api-endpoints.md#edge-psk) in the API endpoints reference). `EdgePSKs` (`internal/wireguard/psk.go`) fetches each peer's PSK, opens it, refuses an envelope older than the one in force, and installs it on the device peer. It keeps the PSKs in memory, where the reconcile handler looks them up for the peers it adds or updates.

```go
type EdgePSKFetcher interface {
    FetchEdgePSK(ctx context.Context, nodeID, peerNodeID string) (*api.EdgePSKEnvelope, error)
}

type EdgePSKInstaller interface {
    SetPeerPSK(peerNodeID, publicKey string, psk []byte) error
}

func NewEdgePSKs(fetcher EdgePSKFetcher, nodeID string, nsk []byte, installer EdgePSKInstaller, logger *slog.Logger) *EdgePSKs
func EdgePSKDispatchHandler(s *EdgePSKs) reconcile.DispatchHandler
```

`*api.ControlPlane` implements the fetcher and `*Manager` the installer. `NewEdgePSKs` copies the NSK, and every log line it writes carries `component=wireguard`.

| Method          | Signature                                                  | Description |
|-----------------|------------------------------------------------------------|-------------|
| `Lookup`        | `(peerNodeID, publicKey string) ([]byte, bool)`            | A copy of the PSK held for the peer when it was fetched for `publicKey`, stale or not. Implements [`EdgePSKLookup`](#reconcilehandler) |
| `InvalidateAll` | `()`                                                       | Marks every PSK stale, so the next `Sync` fetches each peer's again |
| `Sync`          | `(ctx context.Context, peers []api.SnapshotPeer)`          | Forgets the peers missing from `peers`, fetches the PSKs that are due, and installs every PSK the installer has not accepted yet. Returns nothing |

### Wiring in plexd up

`plexd up` builds the store only when the WireGuard interface came up and `wireguard.edge_psk` is on. It decodes the NSK with `identity.SecretKey()`; an NSK that does not decode logs `edge psk disabled, the node secret key does not decode` at `warn` with `error`, and the agent runs without edge PSKs. With the store built:

- `EdgePSKDispatchHandler(store)` is registered as a [dispatch handler](../core/reconciliation.md#dispatchhandler), so `Sync` runs with the pull's `peers` on every successful pull, drift or not. Dispatch handlers run before the reconcile handlers, so a new peer's PSK is in the store when `ReconcileHandler` adds the peer in the same cycle.
- The store is the `EdgePSKLookup` passed to `ReconcileHandler`.
- The key rotator gets `rotationReconcileTrigger` as its reconcile trigger. Its `TriggerReconcile` calls `InvalidateAll` and then triggers the reconcile. The rotator fires the trigger once per committed rotation (see [Mesh key rotation](../core/key-storage.md#mesh-key-rotation-rotate-keys)), so the pull that follows fetches every PSK again.

A failed fetch never fails the WireGuard reconcile handler. A handler that fails every cycle holds the reconciler snapshot back, and a control plane that does not serve edge PSKs fails every fetch.

### Fetch rule

`Sync` fetches a peer's PSK when:

1. the peer first appears in the pull,
2. its `public_key` changed since its PSK was fetched, or
3. this node completed its own key rotation since then (`InvalidateAll`).

A peer whose fetch failed or was answered as not ready, or whose envelope was refused or did not open, holds no current PSK, so it stays due for a later pull. Once every peer holds a current PSK, a pull with an unchanged peer set sends no request. A stale PSK stays on the device, and `Lookup` keeps returning it, until its replacement arrives. A rotation that completes while a fetch is in flight leaves the fetched PSK stale, so the next pull fetches it again. For a peer that leaves the pull, the store forgets its PSK (zeroing the key) and its epoch floor.

The due peers are fetched one at a time in node-ID order, and no lock is held during a request. After the pass, unless its context was cancelled, `Sync` installs every PSK the installer has not accepted yet, again in node-ID order.

### Control plane answers

| Answer | What the store does |
|---|---|
| `200` with a 60-byte envelope and both headers | Checks the epoch floor, opens the envelope and stores the PSK, which the install step at the end of the pass writes to the device. Logs `wireguard: edge psk fetched` |
| `404 peer_not_found`, `409 psk_not_ready` | Not ready yet. `peer_not_found` is the lag after a peer registers, which the contract asks the agent to retry. Logs at `debug`, goes on to the next peer, and retries on the next pull |
| `404` with no code or any code but `peer_not_found`, `501 psk_delivery_not_provisioned` | The control plane does not serve edge PSKs (`api.IsEdgePSKNotServed`). Ends the pass, so an older control plane sees at most one request per pull, and retries on the next pull |
| `429` | Pauses every fetch for `Retry-After`, at least 1 s, and ends the pass. Until the pause ends, `Sync` only forgets departed peers: it fetches and installs nothing |
| `403`, any code | Terminal under the contract (`node_deregistered` says this node was revoked). The store stops: no later `Sync` sends a request or installs anything |
| Transport error | A refused connection, a request timeout or any other `*url.Error`. Logs `wireguard: edge psk: control plane unreachable, retrying on the next pull` and ends the pass: the remaining peers would fail the same way, and the fetches run before the reconcile handlers, so a hanging control plane costs one request timeout (`api.request_timeout`, 30 s by default) per pull instead of one per peer |
| Any other error | Includes a malformed `200`. Logs `wireguard: edge psk: fetch failed`, goes on to the next peer, and retries on the next pull |

A cancelled context ends the pass at once, and nothing is installed.

### Opening the envelope

`api.ControlPlane.FetchEdgePSK` requires a body of exactly `api.EdgePSKEnvelopeSize` (60) bytes, a 12-byte nonce followed by the 32-byte PSK sealed with its 16-byte GCM tag, and both the `X-Plexsphere-PSK-KID` and `X-Plexsphere-PSK-Epoch` headers. The store opens the envelope with AES-256-GCM under the 32-byte NSK and this additional authenticated data:

```
plexsphere/mesh/edge-psk/v1|<self node id>|<peer node id>|<epoch>
```

Both node IDs are trimmed and lowercased, and the epoch is the header's value verbatim. The prefix must stay byte-identical to the control plane's constant. Binding the two IDs keeps another edge's envelope, or a secret envelope sealed with no additional data, from opening as this edge's PSK. Binding the epoch makes the epoch header a trustworthy statement of the envelope's age. The KID must be present, but the store does not use it: plexd holds one NSK.

Every cipher or tag failure returns `wireguard: open edge psk: authentication failed`, with no detail. The other errors are `wireguard: open edge psk: nsk must be 32 bytes` and `wireguard: open edge psk: plaintext is <n> bytes, want 32`. The store logs any of them as `wireguard: edge psk: open failed` and installs nothing.

### Epoch floor

The store keeps the highest epoch it accepted for each peer. An envelope whose epoch sorts below it is refused before it is opened, logged as `wireguard: edge psk: refusing an envelope older than the epoch in force`, and installs nothing. An equal epoch is accepted. The comparison is a plain string compare, because the epoch is fixed-width UTC, so byte order is chronological order.

The floor survives a change of the peer's public key, so an envelope from before the peer's rotation is refused as well. It is dropped when the peer leaves the pull. Floors and PSKs live in memory only: a restarted plexd fetches every PSK again, with no floor.

### Installing a PSK

`Manager.SetPeerPSK(peerNodeID, publicKey, psk)` writes the PSK to the device:

- With no [dial state](#programmed-peers) for the node ID, or one stored with another public key, it writes nothing and returns nil. The PSK belongs to a different device peer, and the reconcile handler takes it from the store through `Lookup` when it next adds or updates the peer with that key.
- Otherwise it rewrites the stored peer with its allowed IPs, which every device write replaces, the PSK, the keepalive interval, and an empty endpoint, which leaves the device's endpoint as it is. It then records the PSK on the stored peer. The endpoint selection state is left as it is.
- A device error returns `wireguard: set peer psk: <cause>`. The store logs `wireguard: edge psk: install failed`, and the next pull retries the install without fetching again.

### Edge PSK log lines

| Level   | Message | Keys |
|---------|---------|------|
| `Info`  | `wireguard: edge psk fetched` | `peer_id`, `epoch` |
| `Info`  | `wireguard: edge psk: control plane does not serve edge psks, retrying on later pulls` | `status`, `code` |
| `Info`  | `wireguard: edge psk: control plane serves edge psks` | none |
| `Warn`  | `wireguard: edge psk: rate limited, pausing fetches` | `retry_after` |
| `Error` | `wireguard: edge psk: control plane refused this node, stopping edge psk fetches` | `code` |
| `Debug` | `wireguard: edge psk: not ready, retrying on the next pull` | `peer_id`, `code` |
| `Warn`  | `wireguard: edge psk: control plane unreachable, retrying on the next pull` | `peer_id`, `error` |
| `Warn`  | `wireguard: edge psk: fetch failed` | `peer_id`, `error` |
| `Warn`  | `wireguard: edge psk: refusing an envelope older than the epoch in force` | `peer_id` |
| `Warn`  | `wireguard: edge psk: open failed` | `peer_id`, `error` |
| `Warn`  | `wireguard: edge psk: install failed` | `peer_id`, `error` |

The not-served line is logged when the store enters that state, not on every pull, and the serves line on the first success after it. No log line or error carries a key, an envelope or the NSK.

### Turning edge PSKs off

`wireguard.edge_psk` (`Config.EdgePSK`) defaults to true; see [Configuration Reference](../core/configuration.md#wireguard). WireGuard needs the same PSK on both ends of a tunnel, and the [NAT relay](../bridge/nat-relay.md#data-flow) forwards the WireGuard packets end to end. An edge between a plexd that installs edge PSKs and an older plexd therefore fails, direct and relayed, until both ends match.

During a rolling upgrade, set `edge_psk: false` on the upgraded nodes, and turn it back on once every node of the Domain runs a plexd that installs edge PSKs. With the setting false and the interface up, `plexd up` logs `edge psk disabled by wireguard.edge_psk` at `info`, builds no store, registers no dispatch handler, passes a nil lookup to `ReconcileHandler`, and gives the key rotator the reconciler itself as its trigger. `plexd up` reads the setting once, when it starts.

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

The pull is the only source of a peer's direct endpoint and its endpoint candidates.
`peer_endpoint_changed` only moves the next pull forward, and that pull carries the
new endpoint. With edge
PSKs on, `peer_psk_assigned` moves the store's next sync forward the same way. That
sync fetches every PSK still due under the [fetch rule](#fetch-rule), such as one
the control plane answered with `409 psk_not_ready`, and sends no request for a PSK
the store holds as current.

### Node API peer list

`GET /v1/peers` on the node API, and with it [`plexd peers`](../core/cli.md#plexd-peers),
reports for each peer the endpoint [`ProgrammedEndpoint`](#dial-order) returns: its
usable direct endpoint, else its fallback. The agent's peer snapshot calls it with
`MeshPrefix()` when the WireGuard interface came up, and with the zero prefix
otherwise. The list shows neither the candidates nor the endpoint
[endpoint selection](#endpoint-selection) settled on; `wg show` and the
[handshake report](../core/heartbeat-service.md#handshake-reporter) carry the
endpoint on the device.

### Graceful Shutdown

Call `Teardown()` on context cancellation to remove the WireGuard interface:

```go
<-ctx.Done()
if err := mgr.Teardown(); err != nil {
    logger.Warn("wireguard teardown failed", "error", err)
}
```
