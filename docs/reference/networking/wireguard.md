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
| `MTU`           | `int`    | `0`     | Interface MTU. `0` sizes the interface to the uplink, a positive value pins it. See [MTU detection](#mtu-detection) |
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

The device starts at wireguard-go's `device.DefaultMTU` of 1420, the same value the Linux kernel gives a WireGuard link. With a `Config.MTU` of `0`, 1420 is the starting value on both platforms, and [MTU detection](#mtu-detection) can lower it through the `SetMTU` command above.

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

The MTU is programmed once at creation, to 1420, and again on every `SetMTU`: for a `Config.MTU` that pins another value, or when [MTU detection](#mtu-detection) changes it at startup or on a later round. Creating the adapter records the MTU in wireguard-go's own field without telling the interface, and no OS event ever reports an MTU change back on Windows, so the controller both programs the interface and pushes the value to the running device. With a `Config.MTU` of `0`, 1420 is the starting value, as it is on Linux and macOS, and detection can lower it from there.

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
| `Setup`         | `(ctx context.Context, identity *registration.NodeIdentity) error`           | Chooses the MTU, probing the uplink when no MTU is pinned, then creates interface, assigns the mesh IP with the `domain_mesh_cidr` prefix (fallback `/32`), sets MTU when it is pinned or not 1420, brings up. See [Setup Sequence](#setup-sequence) |
| `Teardown`      | `() error`                                                                   | Deletes the WireGuard interface                                |
| `OSInterfaceName` | `() string`                                                                | The name the OS knows the interface by (`utunN` on macOS), else `Config.InterfaceName` |
| `AddPeer`       | `(peer api.Peer) error`                                                      | Writes the peer with the first entry of its dial order and starts its endpoint selection; updates index |
| `RemovePeer`    | `(publicKey []byte) error`                                                   | Removes peer by raw public key                                 |
| `RemovePeerByID`| `(peerID string) error`                                                      | Resolves ID via index, removes peer, drops its dial state, cleans index |
| `UpdatePeer`    | `(peer api.Peer) error`                                                      | Rewrites the peer (AddPeer is idempotent) by the first of five ordered rules that applies: a new key starts its dial order over, a peer on a relay the update takes away moves to the update's first relay on a fresh device peer, a relayed peer whose relay stays in the set keeps it, a connected peer keeps its device endpoint, and any other starts its dial order over; updates index. See [Endpoint selection](#endpoint-selection) |
| `ConfigurePeers`| `(ctx context.Context, peers []api.Peer) error`                              | Bulk-adds peers as `AddPeer` does, with context cancellation, and replaces the dial state with the peers it wrote; individual errors logged |
| `PeerIndex`     | `() *PeerIndex`                                                              | Returns the peer index                                         |
| `MeshPeerStats` | `() ([]MeshPeerStat, error)`                                                 | Reads the mesh interface's peers and maps them to node IDs; see [Mesh peer stats](#mesh-peer-stats) |
| `MeshPrefix`    | `() netip.Prefix`                                                            | The Domain mesh prefix the interface was set up with; see [Mesh prefix](#mesh-prefix) |
| `SetPeerPSK`    | `(peerNodeID, publicKey string, psk []byte) error`                           | Rewrites the stored peer of `peerNodeID` with `psk` when it was last written with `publicKey`; see [Installing a PSK](#installing-a-psk) |
| `SetLocalPrefixes` | `(fn func() ([]netip.Prefix, error))`                                     | Sets the function the reconcile handler reads this host's interface prefixes from, to order a peer's on-link candidates first. Call it before the handler runs. See [Dial order](#dial-order) |
| `SetRelayProbe` | `(send func(meshIP netip.Addr) error)`                                       | Sets the function endpoint selection sends the relay liveness probe with; `plexd up` passes `SendRelayProbe`. Call it before `RunEndpointSelection`. Without it no probe goes out. See [Relay liveness probe](#relay-liveness-probe) |
| `RunEndpointSelection` | `(ctx context.Context, interval time.Duration) error`                 | Tries each peer's dial order until a handshake completes, one pass per `interval`, until `ctx` is done; see [Endpoint selection](#endpoint-selection) |
| `SetPathMTUProbe` | `(probe func(context.Context) (int, error))`                              | Sets the function `Setup` and `RunMTUProbe` measure the uplink's path MTU with. Call it before `Setup`. See [MTU detection](#mtu-detection) |
| `RunMTUProbe`   | `(ctx context.Context, interval time.Duration) error`                        | Measures the uplink again once per `interval` and lowers or raises the MTU to fit, until `ctx` is done; see [Probing again](#probing-again) |

The package function `ProgrammedEndpoint` (`handler.go`) returns the endpoint the pull gives a snapshot peer without its candidates, from the peer and `MeshPrefix()`; see [Dial order](#dial-order). The package function `SendRelayProbe` (`dial.go`) is the sender `plexd up` passes to `SetRelayProbe`; see [Relay liveness probe](#relay-liveness-probe).

### Programmed peers

The manager keeps a dial state per node ID: the last `api.Peer` it wrote, the position in the peer's dial order of the endpoint programmed on the device, when that endpoint was programmed, and whether a fresh handshake shows the peer connected. It also records whether the peer is [relayed](#the-trial), last seen connected over one of its relays, when a relay re-dial last replaced its device peer, and the [relay liveness probe](#relay-liveness-probe)'s state: the device's `RxBytes` for the peer at the last pass, when the silence window started (the counter moved, the peer turned connected, came back on a relay or roamed to another relay of its set, or a probe send failed), when the outstanding probe went out (zero when none is), and whether the last probe send failed. `SetPeerPSK` reads the stored peer, because it has to repeat a peer's allowed IPs to write its PSK, and [endpoint selection](#endpoint-selection) reads the rest. `AddPeer` and `UpdatePeer` store the state after a successful device write, `ConfigurePeers` replaces the whole map with the peers it wrote, and `RemovePeerByID` drops the entry after a successful removal. A failed device write in `AddPeer`, `UpdatePeer` or `SetPeerPSK` leaves the state as it was, so a peer whose first write failed has none. One mutex guards the map and serializes every mesh peer device write, since the reconcile handler, the edge PSK store and endpoint selection write the same peers from different call paths.

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
- `UpdatePeer` applies the first of the five rules below that fits.
- `SetPeerPSK` writes an empty endpoint and leaves the selection as it is.
- `RemovePeerByID` drops the state once the device removal succeeds, so a removed peer is never switched.

`UpdatePeer` checks its rules in this order:

1. **No state, or a new key.** It behaves like `AddPeer` with the new order. WireGuard keys peers by public key, so a rotated key is a new device peer that has no endpoint yet. The new state is not relayed.
2. **A relay taken away.** When the entry programmed is one of the peer's relays, the peer is relayed or not connected, and the update names relays, the peer moves at once if the relay programmed is not among them, or if the update's first relay changed and is not the relay programmed. A relayed peer on a standby it moved to on its own therefore follows the control plane once the control plane names a new first relay. A connected peer that is not relayed runs on a direct path WireGuard roamed to, which the move would cut, so rule 4 keeps it. `UpdatePeer` [dials](#relay-liveness-probe) the update's first relay on a fresh device peer, logs `wireguard: relay fallback changed, moving to the new relay`, and stores a new state at that relay's position: programmed now, not connected, relayed when the old state was, and the probe started over. A peer in its relay hold that never connected moves the same way, and its hold starts over on the new relay.
3. **A relayed peer whose relay stays.** A [relayed](#the-trial) peer whose programmed relay is still among the update's relays keeps it, connected or not. This includes a standby it moved to on its own: a pull that still names the dead first relay first, or that names the standby first, does not move it back. The write carries an empty endpoint, the position moves to the relay's place in the new order, and the connected flag, the timestamp and the probe's state stay. A relayed peer that waits for its partner is never sent back to the first entry.
4. **A connected peer.** The write carries an empty endpoint, which both controllers leave untouched on the device, so an endpoint WireGuard roamed to stays. It stores the new peer, sets the position to where the entry last programmed sits in the new order (0 when it is no longer there), and keeps the connected flag and the timestamp. A relayed peer gets here only when the update names no relays, and it stops being relayed.
5. **Any other peer.** It behaves like `AddPeer` with the new order. A peer in its relay hold that never connected therefore restarts its walk on any update that is not a move, including one that only changes a standby.

A failed write returns `wireguard: update peer: <cause>` and leaves the state as it was. A move the device refuses has the cause `remove device peer: <cause>` or `add device peer: <cause>`, and the reconciler keeps its snapshot and retries the update on its next cycle.

#### The trial

Each pass reads the device through [`MeshPeerStats`](#mesh-peer-stats) before it takes the manager's mutex. A read error, `ErrPeerStatsUnsupported` included, ends the pass with nothing written. A peer is fresh when the device reports a non-zero `LastHandshake` for it that is younger than 180 s: WireGuard rekeys a session it uses every two minutes and refuses one older than 180 s, so an older handshake says the path no longer carries traffic. One entry is tried for the keepalive interval plus 5 s, 30 s with the default keepalive.

The relays are held longer. `api.Peer.Fallbacks` holds the peer's relays as they end the order, in set order. When entries precede the first relay, every relay of the set, the first and each standby, is tried for one trial per entry before the first relay instead of one trial: as long as those entries took together. When the order starts with its relays, a relay gets one trial. This is the relay hold. A peer that is not relayed walks its order up to and including its first relay, then starts over at the first entry. The walk never programs a standby. Each side of a pair then spends at least half its walk on the first relay, so the relay windows of two peers behind hard NATs always overlap or touch. A walk of two entries behaves as with one trial per entry. The standbys get the same hold as the first relay, so two relayed peers that move through the set keep the gap between them. A node on an older plexd keeps the 30 s trial on its fallback, and the [NAT relay](../bridge/nat-relay.md) serves it like any other peer.

A connected peer is relayed when it runs over one of its relays. Each pass that finds the peer's handshake fresh decides the mark again:

- A device endpoint equal to a relay of the set that is an address (an IPv4-mapped address compares as IPv4) means the peer is relayed over that relay, whatever entry is programmed. WireGuard roams a peer to the address its partner's initiation came from, so a peer programmed on a direct entry or on another relay can run over this relay. The position then moves to that relay.
- With no device endpoint, the peer is relayed over the entry programmed when that entry is a relay.
- A device endpoint that matches no relay means the peer is not relayed: it opened a direct path and WireGuard roamed to it, which a relay move must not cut and the probe must not judge. A hostname cannot be compared, so when the set holds one and the entry programmed is a relay, the peer is relayed over the entry programmed.
- A peer that is not connected keeps the mark it had when it was last connected.

A peer that roams off a relay, back onto one, or to another relay of its set is therefore followed. A relayed peer stays on its relays, because the direct entries before them already failed. The pass never programs one of its direct entries. When its relay fails, the pass dials the next relay of its set on a fresh device peer, wrapping around to the first after the last: when the [relay liveness probe](#relay-liveness-probe) goes unanswered, when the handshake goes stale, and after each relay hold that passes without a handshake. For a set of one the next relay is the same relay. Both sides of a pair hold the same list and detect a dead relay in the same window, so without a pull they move to the same standby. The peer walks its direct entries again only when an update leaves it no relay, when its key rotates, when it is removed and added again, after a restart, or when WireGuard roamed it to a direct path that then failed: that peer lost the mark while connected, so its stale handshake resumes endpoint selection as for any peer that is not relayed. A peer that lost the mark on a standby sits outside its walk, and goes back to the walk's first entry once its trial on the standby ends.

A control plane that sends no `fallback_endpoints` gives a peer with a `fallback_endpoint` a set of one, and plexd dials that one relay again when it fails. A node on an older plexd dials only `fallback_endpoint`, the first relay, and dials it again when it fails. A pair with one side on an older plexd therefore fails over only when the control plane names a new first relay: the older side keeps dialing the first relay, and the newer side comes back to it each time it wraps around the set.

The pass walks the peers in node-ID order:

| Peer | What the pass does |
|---|---|
| Fresh, not marked connected | Marks it connected, marks it relayed when it runs over one of its relays and moves its position to that relay, clears the mark otherwise, starts the probe's silence window, and logs `wireguard: endpoint selected` with the endpoint the device reports, which may be one WireGuard roamed to, and `relayed` |
| Fresh, marked connected, not relayed | Nothing |
| Fresh, marked connected, relayed | Runs the [relay liveness probe](#relay-liveness-probe), which dials the next relay of the set when the probe goes unanswered. A peer that came back on a relay, or roamed to another relay of its set, moves its position to that relay and starts a new silence window first |
| Not fresh, marked connected, relayed | Clears the mark, logs `wireguard: relayed peer handshake went stale, dialing the relay again` and dials the next relay of the set |
| Not fresh, marked connected, not relayed | Clears the mark, restarts the timer and logs `wireguard: peer handshake went stale, resuming endpoint selection`. The entry on the device gets its full trial, the relay hold for a relay, before the next switch |
| Not fresh, not connected, relayed, programmed less than the relay hold ago | Nothing |
| Not fresh, not connected, relayed, hold over | Logs `wireguard: still no handshake over the relay, dialing it again` with `trial` and dials the next relay of the set, after the last one the first again. No direct entry is programmed |
| Not fresh, not connected, not relayed, with an empty order, on the only entry of its walk, or programmed less than the entry's trial ago | Nothing |
| Not fresh, not connected, not relayed, trial over | Programs the next entry of its walk (after the last one, the first again; from a standby, the first), restarts the timer and logs `wireguard: trying next endpoint candidate` with `trial`, how long it tries the entry it programmed: one trial, or the relay hold for the first relay |

The relay hold is one trial per entry before the first relay, and one trial when the order starts with its relays. A relay re-dial removes the device peer and adds it again with the relay it dials as its endpoint; see [Relay liveness probe](#relay-liveness-probe) for why. A successful one leaves the peer relayed, not connected, programmed now, at the position of the relay it dialed, and with its probe started over.

A peer counts as connected while its latest handshake is younger than 180 s. Neither a pass nor `UpdatePeer` rewrites the device endpoint of a connected peer, so WireGuard roaming, a peer answering from another address, stays in effect. The relay makes two exceptions: a pass dials the next relay of its set for a relayed peer whose probe went unanswered while its handshake is still fresh, and `UpdatePeer` moves a relayed peer to the update's first relay when the update takes its relay away.

A relay re-dial replaces the device peer while a pass may already have read the device: the pass reads it before it takes the mutex, and `UpdatePeer` can move a peer in between. So a handshake older than the device peer's last replacement does not count as fresh. It belongs to the dropped session, and the pass leaves the new device peer not connected until a handshake completes on it.

A failed switch logs `wireguard: endpoint switch failed`, leaves the peer on the entry still programmed, and joins `wireguard: switch endpoint of peer <node id>: <cause>` into the pass's error. The timer restarts all the same, so the next attempt follows that entry's full trial later: one trial, or the relay hold when the peer is on a relay. A failed relay re-dial logs the same line with the relay it tried as `endpoint` and joins the same error, whose cause is `remove device peer: <cause>` or `add device peer: <cause>` for a write the device refused. The peer's position still moves to that relay, the peer stays relayed and not connected, and its timer restarts. The next attempt, one relay hold later, therefore dials the relay after it: a relay the device keeps refusing, such as a hostname that no longer resolves, does not hold the peer back from the rest of its set. A fresh handshake on the device peer that a failed remove left in place marks the peer connected again first, over the relay it came from.

The trial depends on the keepalive. WireGuard starts a handshake only when it sends something, and the keepalive timer is what makes it send to an entry newly programmed on an idle peer. A switch happens on the first pass after the trial ran out, so up to one interval late. With the defaults, a walk of ten entries, the contract's cap of eight candidates plus the direct endpoint and the first relay, reaches its first relay after about 270 s, holds it for about 270 s, and returns to the first entry after about 540 s, one cycle. The order itself can hold 13 entries with the contract's cap of four relays, but the walk ends at the first relay. A relayed peer whose relays never complete a handshake dials the next relay once per relay hold: every 30 s when at most one entry precedes the first relay, every 270 s with nine before it. A restarted plexd starts every peer at the first entry again.

#### Relay liveness probe

A fresh handshake does not show that a relay still forwards. A WireGuard session stays valid for up to 180 s after the relay stopped, and a relayed peer would wait out that age before its handshake went stale. A device counter that stands still does not show that the relay stopped either. A received keepalive restarts WireGuard's own keepalive timer, so on an idle tunnel one side can receive nothing until the next rekey, about two minutes later. A data packet is different: WireGuard answers one with a keepalive within 10 s when it has nothing else to send. The probe sends such a packet into a silent tunnel and watches for the answer.

```go
const relayProbeTimeout = 15 * time.Second // the verdict window
const relayProbePort = 9                   // the discard port

func (m *Manager) SetRelayProbe(send func(meshIP netip.Addr) error)
func SendRelayProbe(meshIP netip.Addr) error
```

`SetRelayProbe` sets the function the probe is sent with. Call it before `RunEndpointSelection`, like `SetLocalPrefixes`. `SendRelayProbe` is the sender `plexd up` passes. It sends one UDP datagram of one zero byte to port 9 of `meshIP`. The host routes the datagram into the mesh interface, and WireGuard carries it to the peer as data. Nothing has to listen on the port: the peer's WireGuard answers the data packet whatever the host behind it does with the datagram. `SendRelayProbe` refuses an address that is not IPv4, because mesh IPs are IPv4, with `wireguard: relay probe: mesh ip <ip> is not IPv4`, and wraps a failed dial or write as `wireguard: relay probe <ip>: <cause>`.

Each pass checks a [relayed](#the-trial) peer that is marked connected and whose handshake is fresh against the device's `RxBytes` for it:

| Peer | What the pass does |
|---|---|
| `RxBytes` moved since the last pass | Records the counter, restarts the silence window and clears an outstanding probe |
| Silent for less than one trial, no probe outstanding | Nothing |
| Silent for one trial, no probe outstanding | Sends the probe to the peer's mesh IP and logs `wireguard: relayed peer silent, probing` at Debug |
| Probe outstanding for less than 15 s | Nothing |
| Probe outstanding for 15 s, `RxBytes` unmoved | Logs `wireguard: relayed peer did not answer the probe, dialing the relay again` with `silent_for` and dials the next relay of the set |

The silence window is one trial, the keepalive interval plus 5 s, 30 s with the default keepalive. It starts when the peer turns connected, comes back on a relay or roams to another relay of its set, again each time the counter moves, and again after a failed send, so a peer that receives traffic is never probed. The verdict window, `relayProbeTimeout`, is fixed at 15 s: WireGuard's `KeepaliveTimeout` of 10 s, in which a live path answers the probe, plus its `RekeyTimeout` of 5 s for the answer to arrive.

No probe goes out without a sender, or to a peer whose `MeshIP` does not parse or lies outside the [mesh prefix](#mesh-prefix). With the host `/32` of an identity without `domain_mesh_cidr`, or the zero prefix before `Setup`, the host would route the datagram past the mesh interface, and its silence would read as a dead relay. Without a probe, a relayed peer counts as failed only once its handshake goes stale.

A failed send logs `wireguard: relay probe send failed` with `error`, at Warn the first time and at Debug while the sends keep failing. It restarts the silence window, so no verdict follows a probe that never left, and the next attempt follows one trial later. A send that succeeds ends the run of failures, and the next failure logs at Warn again. The probe is sent under the manager's mutex, because one UDP send does not block.

With the defaults, a 25 s keepalive and a pass every 5 s:

- The pass that counts the relay's last packet starts the silence window, up to 5 s after the packet arrived.
- The probe goes out on the first pass 30 s or more after that pass.
- The verdict comes on the first pass 15 s or more after the probe, and dials the next relay of the set.
- A relay that stops forwarding is therefore left 45 to 50 s after its last packet. A pass reads the clock after it reads the device, so a window can miss its closing pass by a fraction of a second and close one pass later. With both windows late, the re-dial comes up to 60 s after the last packet.

Both sides of the pair leave the relay in that window and reach the same standby. The gap between them is absorbed by the relay hold, at least 30 s, plus the 30 s a relay keeps a pending initiation (see [First Contact](../bridge/nat-relay.md#first-contact)). With a 1 s keepalive, as in the in-process relay test, the pair completes a handshake over the standby about 21 s after the first relay stops.

Without the probe, a relayed peer waits until its handshake is 180 s old. With it, a pair with two or more relays moves to the next relay of its set within about a minute when its relay stops forwarding or restarts, with no pull. For a set of one the next relay is the same relay. A relay that restarted and lost its index table then carries the pair again within about a minute. With a set of one, a dead relay stays dead until the control plane names another first relay, and `UpdatePeer` then moves the peer at once.

Every re-dial of a relay is the same write, whether it follows an update that takes the relay away, an unanswered probe, a stale relayed handshake or a relay hold without a handshake: plexd removes the device peer and adds it again with the relay it dials as the endpoint. That is the update's first relay for a move, and the next relay of the set otherwise. The relay routes a transport message by its receiver index and drops one whose index it does not hold, with reason `unknown_index` (see [Forwarding Table](../bridge/nat-relay.md#forwarding-table)). A write that only changed the endpoint would keep the peer's session, which a new or restarted relay does not know. WireGuard starts a new handshake on its own only after 15 s of unanswered data, or once the session is 120 to 180 s old. The new device peer has no session. Its write turns the keepalive interval on, and wireguard-go sends a keepalive when that happens, which starts a handshake at once. The Linux kernel module is assumed to do the same.

A failed add leaves the peer off the device until the next attempt. That attempt's remove names a key the device does not hold, which the [userspace backend](#userspace-backend) accepts. The Linux kernel module is assumed to accept it as well.

A re-dial makes a new device peer, as a key rotation does, so its handshake time and byte counters start over. The [handshake report](../core/heartbeat-service.md#handshake-reporter) leaves the peer out until its new handshake completes, as it does for any new device peer, and the [tunnel metrics](../observability/metrics-collection.md#tunnelcollector) count its `rx_bytes` and `tx_bytes` from 0 again.

The probe costs at most one datagram per relayed peer per silence window, sent only while the peer receives nothing and answered by one 32-byte keepalive. A re-dial costs one extra handshake, whether it dials the same relay or the next one of the set. The probe is off with `persistent_keepalive: 0s`, which turns endpoint selection off, and without `SetRelayProbe`. Nothing on the wire changes: the peer's WireGuard answers the probe, not its plexd, so the probe works against a peer on any version, and a node on an older plexd keeps the 180 s hold.

#### RunEndpointSelection

```go
const EndpointSelectionInterval = 5 * time.Second

func (m *Manager) RunEndpointSelection(ctx context.Context, interval time.Duration) error
```

- With `persistent_keepalive: 0s` it logs `wireguard: endpoint selection disabled, persistent_keepalive is 0s` and returns nil at once. Every peer keeps the first entry of its dial order, so no standby relay is ever dialed.
- Otherwise it logs `wireguard: endpoint selection started` with `interval`, `timeout` (the trial) and `relay_probe`, true when `SetRelayProbe` set a sender, and runs a pass on every tick, the first one interval after it starts.
- A pass that returns `ErrPeerStatsUnsupported` logs `wireguard: endpoint selection unavailable, the controller cannot read peer stats` and returns nil. Peers keep the entry they have.
- Any other pass error logs `wireguard: endpoint selection pass failed` with `error`, and the next tick runs again.
- It returns nil once `ctx` is done.

`plexd up` runs it with `EndpointSelectionInterval` as step 17b, only when the WireGuard interface came up. The step first calls `SetRelayProbe(wireguard.SendRelayProbe)`, so the probe is on and the started line carries `relay_probe=true`.

#### Cost

The keepalive sends one empty data packet (32 bytes of payload) per idle peer every 25 s and keeps a rekey handshake running about every 2 minutes per peer, so a node with 100 idle peers sends about 4 packets per second. Endpoint selection adds one device read every 5 s, the reconcile handler one interface read each time it runs, and the [candidate publisher](./nat-traversal.md#local-endpoint-candidates) one `PUT` per cycle (60 s by default). The [relay liveness probe](#relay-liveness-probe) adds at most one datagram per relayed peer that received nothing for 30 s, answered by one keepalive, and each relay re-dial one handshake, whether it dials the same relay or the next one of the set.

#### Endpoint selection log lines

All carry `component=wireguard`.

| Level  | Message | Keys |
|--------|---------|------|
| `Info` | `wireguard: endpoint selection started` | `interval`, `timeout`, `relay_probe` (true when `SetRelayProbe` set a sender) |
| `Info` | `wireguard: endpoint selection disabled, persistent_keepalive is 0s` | none |
| `Info` | `wireguard: endpoint selection unavailable, the controller cannot read peer stats` | none |
| `Info` | `wireguard: endpoint selected` | `peer_id`, `endpoint` (empty when the device reports none), `relayed` (true when the peer connected over one of its relays, which may be a relay other than the one programmed) |
| `Info` | `wireguard: peer handshake went stale, resuming endpoint selection` | `peer_id` |
| `Info` | `wireguard: trying next endpoint candidate` | `peer_id`, `endpoint`, `attempt` (the entry's 1-based position), `of` (the number of entries the walk cycles through: the order up to and including its first relay, or the whole order for a peer without relays), `trial` (how long the entry just programmed is tried, such as `30s`, or `1m0s` for a first relay that follows two entries) |
| `Info` | `wireguard: relay fallback changed, moving to the new relay` | `peer_id`, `from` (the relay programmed, which may be a standby), `to` (the update's first relay). Logged by `UpdatePeer` |
| `Debug` | `wireguard: relayed peer silent, probing` | `peer_id`, `mesh_ip`, `silent_for` (the time since the silence window started, such as `30s`; after a failed send it counts from that send) |
| `Warn`, `Debug` | `wireguard: relay probe send failed` | `peer_id`, `mesh_ip`, `error`. `Warn` for the first failure, `Debug` while the sends keep failing |
| `Info` | `wireguard: relayed peer did not answer the probe, dialing the relay again` | `peer_id`, `from` (the relay the peer was on), `endpoint` (the relay dialed, the next of the set; the same relay for a set of one), `silent_for` (the time since the silence window started, such as `45s`) |
| `Info` | `wireguard: relayed peer handshake went stale, dialing the relay again` | `peer_id`, `from` (the relay the peer was on), `endpoint` (the relay dialed, the next of the set; the same relay for a set of one) |
| `Info` | `wireguard: still no handshake over the relay, dialing it again` | `peer_id`, `from` (the relay the peer was on), `endpoint` (the relay dialed, the next of the set; the same relay for a set of one), `trial` (the relay hold, such as `30s`) |
| `Warn` | `wireguard: endpoint switch failed` | `peer_id`, `endpoint` (the entry it tried to program, the relay it tried to dial for a failed relay re-dial), `error` |
| `Warn` | `wireguard: endpoint selection pass failed` | `error` |

### MTU detection

WireGuard sends every mesh packet inside a UDP datagram on the uplink. When the uplink carries less than the interface MTU plus that encapsulation, full-size mesh packets are lost without an error: pings and handshakes are small and pass, while every TCP connection over the mesh stalls at its first full-size segment. DS-Lite over PPPoE, common on the consumer and carrier-grade uplinks edge nodes sit behind, puts the path at 1452 bytes. The manager therefore sizes the interface to what the uplink carries (`mtu.go`), measured with the [path MTU probe](./nat-traversal.md#path-mtu-probe).

```go
// DefaultMTU is the MTU Linux and wireguard-go give a WireGuard link: 1500 minus 80.
const DefaultMTU = 1420

// MinMTU is the smallest MTU detection programs.
const MinMTU = 1280

// MTUProbeInterval is how often RunMTUProbe measures the uplink again in plexd up.
const MTUProbeInterval = 10 * time.Minute

func MeshMTU(pathMTU int) int
func (m *Manager) SetPathMTUProbe(probe func(context.Context) (int, error))
func (m *Manager) RunMTUProbe(ctx context.Context, interval time.Duration) error
```

#### Sizing rule

`MeshMTU` turns `pathMTU`, the largest IPv4 packet in bytes that reached a STUN server, into the interface MTU:

```
MeshMTU(pathMTU) = min(1420, max(1280, pathMTU - 80))
```

80 bytes is WireGuard's worst-case encapsulation: an IPv6 header (40), UDP (8) and WireGuard's data header and tag (16 + 16). The probe measures IPv4, which needs only 60, but peers can dial this node's IPv6 candidates. WireGuard uses the same 80 for its own default (1420 = 1500 − 80), so a node on a 1500-byte uplink keeps exactly 1420.

| Path MTU | Mesh MTU |
|---|---|
| 9000 | 1420, the cap |
| 1500 | 1420 |
| 1492 (PPPoE) | 1412 |
| 1452 (DS-Lite over PPPoE) | 1372 |
| 1360 and below, the probe's 48-byte baseline included | 1280, the floor |

The cap keeps a node on a jumbo-frame uplink at the 1420 every node had before detection. When `pathMTU − 80` is below 1280, `Setup` or a round still programs 1280 and logs `wireguard: uplink carries less than the mesh minimum mtu` with `path_mtu` and `mtu`.

#### At startup

`plexd up` calls `SetPathMTUProbe` before `Setup` with a function that runs [`nat.ProbePathMTU`](./nat-traversal.md#path-mtu-probe) over `nat.stun_servers` with `nat.MTUProbeTimeout` (2 s). `Setup` chooses the MTU first, before it calls `CreateInterface`:

| Case | MTU | `mtu_source` |
|---|---|---|
| `Config.MTU > 0` | That value. The probe is never called | `config` |
| A probe is set and returns a path MTU | `MeshMTU(pathMTU)` | `probe` |
| A probe is set and returns an error | 1420. Logs `wireguard: mtu probe inconclusive, using the default mtu` with the error | `default` |
| No probe is set | 1420 | `default` |

`SetMTU` keeps its place between `ConfigureAddress` and `SetInterfaceUp`. It runs when `Config.MTU > 0` or when the chosen MTU is not 1420. All three controllers create the device at 1420, so a 1420 result needs no call, and a node without a pinned MTU on a 1500-byte uplink makes the same controller calls it made before detection. A `SetMTU` error fails `Setup` with `wireguard: setup: <cause>`. The `wireguard interface configured` line carries `mtu`, `mtu_source` and, with `mtu_source=probe`, the measured `path_mtu`.

Startup waits for the probe round. On a healthy uplink that is one round trip to the STUN servers. It takes up to 2 s only while some probe goes unanswered: on a black-holed uplink, or when no STUN server is reachable.

#### Probing again

An uplink can change after startup, through LTE failover or a laptop changing networks. `RunMTUProbe` measures it again on every tick of `interval`:

- It returns nil at once when no probe is set or `Config.MTU > 0`.
- Otherwise it logs `wireguard: mtu probe started` with `interval` and runs a round on every tick. The startup probe in `Setup` counts as the first round, so the first tick comes one interval after start.
- It returns nil once `ctx` is done.

`plexd up` runs it with `MTUProbeInterval` as step 17c, only when the WireGuard interface came up.

A round compares the target, `MeshMTU(pathMTU)`, with the MTU last programmed:

| Round | What it does |
|---|---|
| Target below the current MTU | Calls `SetMTU` with the target at once and logs `wireguard: mesh mtu lowered` |
| Target above the current MTU and equal to the pending raise | Calls `SetMTU` with the target and logs `wireguard: mesh mtu raised` |
| Target above the current MTU, with no pending raise or another one | Records the target as the pending raise and logs `wireguard: higher mesh mtu seen, raising when the next probe agrees` at `debug`. No device write |
| Target equal to the current MTU | Clears the pending raise |
| The probe returned an error | Keeps the MTU, clears the pending raise, and logs `wireguard: mtu probe inconclusive, keeping the current mtu` |
| `ctx` done, during or after the probe | Returns without touching the device and logs nothing. Shutdown deletes the interface before it waits for the loop |

A lower MTU applies at once, because the uplink already loses packets at the current one. A higher MTU applies only when two rounds in a row ask for the same target, 10 minutes apart in `plexd up`. A round with another target, the current MTU or a failed probe in between starts the wait over.

A failed `SetMTU` logs `wireguard: mesh mtu change failed`, keeps the MTU last programmed, and clears the pending raise. The next round retries a failed lowering, because a target below the MTU applies at once. A failed raise starts the two-round wait over: the next round records the raise again, and the one after writes it. A successful `SetMTU` records the new MTU and clears the pending raise.

Only `Setup` touches the MTU last programmed and the pending raise, and after it returns only the one `RunMTUProbe` goroutine does, so they need no lock. `SetMTU` does not take the mutex that serializes peer writes.

#### Turning detection off

- `wireguard.mtu` above 0 pins the MTU. `Setup` programs it with `mtu_source=config` and never calls the probe, and `RunMTUProbe` returns at once. `wireguard.mtu: 1420` pins the MTU plexd used before detection.
- `nat.enabled: false` turns detection off. `plexd up` sets no probe, and when `wireguard.mtu` is 0 it logs `mesh mtu detection disabled by nat.enabled` at `info`. The interface comes up at 1420 with `mtu_source=default`. A `nat` block that sets only `enabled: false` does not get there: the block's zero-value heuristic sets `enabled` back to `true` when `stun_servers`, `refresh_interval`, `timeout` and `min_report_interval` are all unset, so set one of them beside it (see [Config](./nat-traversal.md#config)).

#### Limits

- WireGuard has one MTU per interface, so peers on the same LAN get the reduced MTU too.
- The probe measures the path to the STUN servers over IPv4, in the outbound direction. An IPv6-only node gets an inconclusive probe and keeps 1420. A bottleneck on a path the STUN traffic does not cross stays unseen; pin the MTU with `wireguard.mtu` there.
- A peer keeps its own MTU. TCP over the mesh fits in both directions, because the lowered side announces the smaller MSS. Non-TCP packets above the reduced size that the far side sends can still be lost.
- Only the mesh interface is sized. The bridge access and site-to-site interfaces do not carry mesh traffic over the uplink the probe measures.

#### MTU detection log lines

All carry `component=wireguard`.

| Level | Message | Keys | When |
|-------|---------|------|------|
| `Info` | `wireguard interface configured` | `interface`, `listen_port`, `mesh_ip`, `mtu`, `mtu_source` (`config`, `probe`, `default`), `path_mtu` (only with `probe`) | `Setup` succeeded |
| `Warn` | `wireguard: mtu probe inconclusive, using the default mtu` | `mtu` (1420), `error` | The startup probe failed |
| `Warn` | `wireguard: uplink carries less than the mesh minimum mtu` | `path_mtu`, `mtu` (1280) | `Setup` or a round programs 1280 because `pathMTU − 80 < 1280` |
| `Info` | `wireguard: mtu probe started` | `interval` | `RunMTUProbe` begins |
| `Info` | `wireguard: mesh mtu lowered` | `old_mtu`, `mtu`, `path_mtu` | A round lowered the MTU |
| `Info` | `wireguard: mesh mtu raised` | `old_mtu`, `mtu`, `path_mtu` | A second agreeing round raised it |
| `Debug` | `wireguard: higher mesh mtu seen, raising when the next probe agrees` | `mtu`, `raise_to`, `path_mtu` | A round asked for a raise |
| `Warn` | `wireguard: mtu probe inconclusive, keeping the current mtu` | `mtu`, `error` | A round's probe failed |
| `Warn` | `wireguard: mesh mtu change failed` | `old_mtu`, `mtu`, `error` | A round's `SetMTU` failed |

`plexd up` itself logs `mesh mtu detection disabled by nat.enabled` at `info` when `nat.enabled` is false and `wireguard.mtu` is 0.

### Lifecycle

```go
logger := slog.Default()

// Create manager with a WGController implementation
mgr := wireguard.NewManager(ctrl, wireguard.Config{}, logger)

// Size the interface to the uplink; without a probe it comes up at 1420
mgr.SetPathMTUProbe(func(ctx context.Context) (int, error) {
    return nat.ProbePathMTU(ctx, natCfg.STUNServers, nat.MTUProbeTimeout)
})

// Setup interface using node identity from registration
identity, _ := registration.LoadIdentity("/var/lib/plexd")
if err := mgr.Setup(ctx, identity); err != nil {
    log.Fatal(err)
}

// Measure the uplink again every 10 minutes (blocks until ctx is done)
go mgr.RunMTUProbe(ctx, wireguard.MTUProbeInterval)

// Configure initial peers from registration response
if err := mgr.ConfigurePeers(ctx, registerResponse.Peers); err != nil {
    log.Fatal(err)
}

// Probe relayed peers that fall silent, then try each peer's dial order
// every 5 seconds (blocks until ctx is done)
mgr.SetRelayProbe(wireguard.SendRelayProbe)
go mgr.RunEndpointSelection(ctx, wireguard.EndpointSelectionInterval)

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

1. Choose the MTU: `Config.MTU` when it is above 0; otherwise, with a probe set through `SetPathMTUProbe`, `MeshMTU` of the path MTU it measures, or 1420 when it returns an error; otherwise 1420. The probe runs before any controller call (see [At startup](#at-startup))
2. `CreateInterface(name, privateKey, listenPort)` — create WireGuard interface with node's private key
3. `ConfigureAddress(name, meshIP+"/<prefix>")` — assign the mesh IP. The prefix length comes from the registration `domain_mesh_cidr`, so the kernel installs an on-link route for the whole mesh (which the snapshot peers, advertised as `mesh_ip/32`, rely on). Identities without the field, or with an unparseable value, fall back to a host `/32` (the unparseable case is logged as a warning). On macOS the on-link route is not implicit and `DarwinController` installs it explicitly (see [macOS controller](#macos-controller))
4. `SetMTU(name, mtu)` — only if `Config.MTU > 0` or the chosen MTU is not 1420, the MTU every controller creates the device with
5. `SetInterfaceUp(name)` — bring the interface up
6. Record the address's masked prefix as the [mesh prefix](#mesh-prefix)

### Error Handling

| Method            | Individual Peer Failure          | Context Cancellation       |
|-------------------|----------------------------------|----------------------------|
| `AddPeer`         | Returns error                    | —                          |
| `RemovePeerByID`  | Returns error                    | —                          |
| `UpdatePeer`      | Returns `wireguard: update peer: <cause>` and leaves the state as it was. A failed move to a new relay names `remove device peer` or `add device peer`, and the reconciler retries it on its next cycle | — |
| `ConfigurePeers`  | Logged at error, continues       | Returns context error      |
| `SetPeerPSK`      | Returns `wireguard: set peer psk: <cause>` | —                |
| `RunEndpointSelection` | A failed switch or relay re-dial is logged at warn and the pass goes on; the next re-dial, one relay hold later, dials the relay after the one that failed. A failed probe send is logged at warn, then at debug while it keeps failing, and takes no verdict: the next probe follows one trial later | Returns nil |
| `RunMTUProbe`     | A failed probe or `SetMTU` is logged at warn. The next round probes again and retries a failed lowering; a failed raise starts the two-round wait over | Returns nil |

### Logging

All log entries use `component=wireguard`. Private keys and PSKs are never logged.

| Level   | Event                        | Keys                                  |
|---------|------------------------------|---------------------------------------|
| `Info`  | Interface configured         | `interface`, `listen_port`, `mesh_ip`, `mtu`, `mtu_source`, `path_mtu` (only with `mtu_source=probe`) |
| `Info`  | Peers configured (bulk)      | `count`                               |
| `Debug` | Peer added/removed/updated   | `peer_id`                             |
| `Debug` | Peer PSK set (`peer psk set`) | `peer_id`                            |
| `Error` | Peer operation failed (bulk) | `peer_id`, `error`                    |

Endpoint selection writes the lines in [Endpoint selection log lines](#endpoint-selection-log-lines), MTU detection the lines in [MTU detection log lines](#mtu-detection-log-lines), and the reconcile handler the dial order lines in [Dial order](#dial-order).

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

Adds and updates carry `api.SnapshotPeer` entries, converted to the WireGuard `api.Peer` by `peerFromSnapshot(p, order, fallbacks, psk)`, where `order` is the peer's [dial order](#dial-order) and `fallbacks` its last `relays` entries, the relays that end it:

- `AllowedIPs` is derived locally as `mesh_ip/32`. The snapshot never sends allowed IPs. A `mesh_ip` that is not a bare IPv4 address fails the peer.
- `Endpoints` is the dial order and `Endpoint` its first entry, empty for an empty order. The manager programs the first entry and [endpoint selection](#endpoint-selection) moves along the order until a handshake completes. See [Dial order](#dial-order).
- `Fallbacks` is the peer's relay set as it ends the order, in dial order, and nil for a peer without a relay. A candidate or direct endpoint equal to a relay is left out of the entries before the relays, so a relay it repeats is still in `Fallbacks`. [Endpoint selection](#the-trial) holds these entries longer and moves a relayed peer along them.
- `PSK` is the key `psks.Lookup` returns for the peer's node ID and current `public_key`, base64-encoded. A PSK fetched for another public key is never returned, so a peer whose key changed gets no PSK until the store holds one for the new key. With no PSK the field stays empty, and the store writes the PSK through [`SetPeerPSK`](#installing-a-psk) once it arrives.

Individual failures are logged and collected. The handler returns an aggregated error via `errors.Join` (nil if all succeed). This ensures the reconciler marks the cycle as failed and retries on the next tick.

### Dial order

```go
func dialOrder(p api.SnapshotPeer, local []netip.Prefix, mesh netip.Prefix) (order []string, relays, dropped int)
func ProgrammedEndpoint(p api.SnapshotPeer, mesh netip.Prefix) (endpoint string, directRejected bool)
```

The handler reads this host's interface prefixes, through the function [`SetLocalPrefixes`](#methods) set, and `MeshPrefix()` once per call. For each peer it adds or updates, `dialOrder` builds the order in which [endpoint selection](#endpoint-selection) tries the peer's endpoints:

1. the peer's `endpoint_candidates` that are on-link, on a subnet this node is also on
2. the peer's direct `endpoint`, when it is usable
3. the remaining, off-link candidates
4. the peer's relays, in set order: the entries of `fallback_endpoints`, or `fallback_endpoint` alone from a control plane that sends no `fallback_endpoints`

Candidates keep the order the pull lists them in within each group. A duplicate keeps its first position, except that a candidate or direct endpoint equal to a relay is left out: the relays always end the order whole and in set order, the same on both sides of a pair. An empty or repeated relay entry is skipped, and `relays` counts the relays that end the order. A peer with no usable candidate, no usable direct endpoint and no relay gets an empty order and is programmed without an endpoint.

`fallback_endpoints` holds the peer's relays as `host:port` (an IPv6 host in brackets) in dial order, at most four under the contract: the relay of the peer's assigned bridge first, then its standby relays. Both nodes of a pair receive the same list for each other, and the list never names the receiving node. `fallback_endpoint` is always its first entry, and the only relay a control plane that predates the set sends. When `fallback_endpoints` is non-empty, `dialOrder` does not read `fallback_endpoint` and does not check that the two agree. A `null` `fallback_endpoints` reads as an absent one, and one that is not an array of strings fails the pull's decode like any malformed pull. plexd does not cap the list.

The control plane lists a peer's peer-observed endpoints, NAT mappings other nodes of the Domain completed handshakes over, ahead of its local candidates (see [State](../core/api-endpoints.md#get-v1-nodes-node-id-state)). The on-link test, not the wire position, decides where one lands. A mapping is usually off-link, so it comes after the direct endpoint and ahead of the later off-link candidates. It is on-link, and comes first, only when this node has an address in a prefix that contains it, such as a public address configured on an eligible interface. A mapping on the direct endpoint's address with another port, such as a published `:51820` that the peer's router maps to `:10482`, is a separate entry, tried right after the endpoint.

The direct endpoint and each candidate are held to the same rules. One is usable when all of these hold:

- It parses with `netip.ParseAddrPort` and its port is not 0.
- Its address carries no zone.
- Its address, with an IPv4-mapped IPv6 address unmapped, is not unspecified, loopback, multicast, link-local unicast or link-local multicast.
- It lies outside `mesh`, the Domain mesh prefix from [`MeshPrefix`](#mesh-prefix). An endpoint inside it would be routed through the mesh interface, so WireGuard would send the peer's encrypted packets into its own tunnel. A zero `mesh` skips this check.

A usable endpoint enters the order in canonical form, so `[::ffff:10.0.0.5]:51820` becomes `10.0.0.5:51820`. Every relay of the set enters it as the pull sent it and is never validated, because the contract allows a hostname there.

A candidate is on-link when a local prefix of the same address family contains it. Only a prefix shorter than a host prefix counts: a `/32` or `/128` says nothing about the addresses next to it, so it makes nothing on-link. In `plexd up` the local prefixes are the prefixes of the host addresses [`nat.EligiblePrefixes`](./nat-traversal.md#local-endpoint-candidates) accepts, under the filter the candidate publisher uses. When they cannot be read, the handler logs at `warn` and orders every candidate as off-link, which still tries each of them:

```
wireguard: read local prefixes failed, ordering every candidate as off-link  component=wireguard error=<cause>
```

A refused direct endpoint is left out of the order and logged at `warn`. An absent `endpoint` means the peer has no fresh NAT observation and logs nothing.

```
wireguard: peer direct endpoint unusable, leaving it out of the dial order  component=wireguard peer_id=<node id> endpoint=10.99.0.4:51820 fallback=203.0.113.1:51820
```

Refused candidates are counted in `dropped` and logged at `debug` as `wireguard: dropped endpoint candidates` with `peer_id` and `count`.

`ProgrammedEndpoint` returns what the pull gives a peer without its candidates: the direct `endpoint` when it is usable, the `fallback_endpoint` (the first relay) otherwise. `directRejected` is true only when the peer carried a non-empty `endpoint` that was refused, which is what the handler's `warn` line keys on. The node API's peer list shows this endpoint (see [Node API peer list](#node-api-peer-list)); the endpoint on the device is the one endpoint selection settles on.

The differ compares `endpoint`, `fallback_endpoint`, `fallback_endpoints` and `endpoint_candidates`, the relays and the candidates in order, so a peer whose direct endpoint, relays or candidates appear, change, reorder or disappear lands in `PeersToUpdate` and is written again. A change of only a standby relay, or of the relays' order, updates the peer too. A missing and an empty `fallback_endpoints` or `endpoint_candidates` compare equal.

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

`peerFromSnapshot(p api.SnapshotPeer, order, fallbacks []string, psk []byte) (api.Peer, error)`
builds each programmed peer from a snapshot entry: `AllowedIPs` derived locally as
`mesh_ip/32`, `Endpoints` set to the [dial order](#dial-order) and `Endpoint` to its
first entry, `Fallbacks` set to `fallbacks`, the relays that end the order, and
`psk` base64-encoded (none for a nil `psk`). The manager then adds,
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
