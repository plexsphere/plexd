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
    AllowedIPs    []netip.Prefix // in the device's order; nil when the peer has none
}

// PeerStatsReader is implemented by controllers that can read peer runtime state.
type PeerStatsReader interface {
    PeerStats(name string) ([]PeerStat, error)
}
```

`NetlinkController`, `UserspaceBackend`, `DarwinController` and `WindowsController` implement it. `NetlinkController.PeerStats` opens a wgctrl client per call, as `AddPeer` does, reads the device with `client.Device(name)` and maps each `wgtypes.Peer`: the key bytes, `Endpoint.AddrPort()` when the peer has an endpoint, `LastHandshakeTime` (wgctrl already yields a zero time when no handshake has completed), the receive and transmit byte counters, and the allowed IPs as prefixes in the device's order, an IPv4-mapped address unmapped and an entry whose mask does not fit its address left out. Its errors are `wireguard: peer stats: open wgctrl: <cause>` and `wireguard: peer stats: read device: <cause>`; a missing interface wraps `os.ErrNotExist`. `DarwinController` and `WindowsController` delegate to the [userspace backend](#userspace-backend).

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

`parseUAPIPeerStats` splits the dump into `key=value` lines. `public_key` (64 hex characters) starts a new peer; `endpoint` parses with `netip.ParseAddrPort`; `rx_bytes` and `tx_bytes` parse as `uint64`; `last_handshake_time_sec` and `last_handshake_time_nsec` give `time.Unix(sec, nsec)`. Both at 0 give the zero time. Each `allowed_ip` line parses with `netip.ParsePrefix` and appends one prefix to `AllowedIPs`. The parser does not copy wgctrl's `sec > 0 && nsec > 0` check, which drops a handshake that lands on a whole second. Empty lines and every other key (`private_key`, `listen_port`, `fwmark`, `preshared_key`, `protocol_version`, `persistent_keepalive_interval`, `errno`) are skipped. A dump with device keys only yields an empty slice.

| Input | Error |
|---|---|
| A line without `=` | `wireguard: peer stats: line <n> has no '='` |
| A peer key before any `public_key` | `wireguard: peer stats: <key> before public_key` |
| An unparseable value of one of the seven peer keys | `wireguard: peer stats: parse <key>: <cause>` |

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

Everything addressed through plexd keeps the configured name: the backend's device key, the UAPI socket (`wg show plexd0`), the bridge managers and the `status.mesh` report. The kernel name is used for the `ifconfig` and `route` calls, for the [pf policy rules](./pf-wfp-firewall.md#interface-names), for the readiness check and for the routes of a peer's [routed subnets](#routed-subnets), because `net.InterfaceByName` knows only `utunN`. All four resolve it through `Manager.OSInterfaceName()`. A macOS bridge serves no site-to-site tunnel, so no tunnel route names a utun (see [Site-to-Site VPN](../bridge/site-to-site-vpn.md)).

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

A utun is point-to-point, so the `inet` form takes the destination address after the local one, and the alias installs a host route only. Linux gets the route for the whole prefix implicitly when the address is added, so `ConfigureAddress` adds it here explicitly; otherwise every packet for a mesh peer would leave through the default route. A `/32` or `/128` needs no route, since the alias already installed it. A peer's allowed IPs beyond the address prefix, its accepted [routed subnets](#routed-subnets), get their routes from the manager through its `PeerRouter`, the platform's route controller, as they do on Linux.

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

The address carries its own prefix length, and Windows installs the on-link route for that prefix itself, the way Linux does when an address is added. macOS is the exception that needs the route added by hand. A peer's allowed IPs beyond the address prefix, its accepted [routed subnets](#routed-subnets), get their routes from the manager through its `PeerRouter`, the platform's route controller, as they do everywhere else. An address already on the adapter is reported as `ERROR_OBJECT_ALREADY_EXISTS`, which the controller treats as success.

The MTU is programmed once at creation, to 1420, and again on every `SetMTU`: for a `Config.MTU` that pins another value, or when [MTU detection](#mtu-detection) changes it at startup or on a later round. Creating the adapter records the MTU in wireguard-go's own field without telling the interface, and no OS event ever reports an MTU change back on Windows, so the controller both programs the interface and pushes the value to the running device. With a `Config.MTU` of `0`, 1420 is the starting value, as it is on Linux and macOS, and detection can lower it from there.

`SetInterfaceUp` runs nothing: a Wintun adapter's media state is connected from the moment its session starts inside `CreateTUN`. `DeleteInterface` runs nothing either, because closing the device closes the tun, which ends the session and closes the adapter; Windows then removes it with its addresses and routes. The adapter is scoped to the handles that own it, so it also disappears if the process dies without a clean shutdown.

The UAPI named pipe is `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>`, so `wg show plexd0` works against the running service. Its security descriptor grants LocalSystem and Administrators full access under a high mandatory label, but names no owner, so the creating process becomes the owner. wireguard-go's own descriptor assigns the pipe to LocalSystem, which only a LocalSystem process may do: an elevated Administrator running `plexd up` by hand would fail to open the pipe at all, and with it the interface. The cost of leaving the owner out is that `wgctrl`, which requires a LocalSystem-owned pipe, does not find a device belonging to a plexd started from a console; against the service, which is how plexd runs, `wg show` is unaffected.

Windows Defender Firewall may drop unsolicited inbound handshakes on the listen port: plexd's own WFP permits are soft and cannot open a port the host firewall closes (see [Soft permits](./pf-wfp-firewall.md#soft-permits)). The [Windows installation guide](../../how-to/windows-installation.md) adds the inbound rule. Handshakes plexd initiates are unaffected, so a node behind it still reaches peers that are reachable.

### The mesh rewriter

```go
func (c *WindowsController) SetMeshRewriter(r *MeshRewriter)
```

`SetMeshRewriter` hands the controller a [mesh rewriter](#in-process-mesh-source-rewrite) and is called before `CreateInterface`. With a rewriter, `createAdapter` hands wireguard-go `r.Wrap(name, tdev)` in place of the Wintun tun: it wraps after it has taken the adapter's LUID and set the default MTU, and before `UserspaceBackend.CreateDevice`, so the LUID and `ForceMTU` stay the raw device's. Without a rewriter nothing changes.

`plexd up` builds the rewriter with `newMeshRewriter` only on a Windows node in bridge mode that does not opt out of both user access and site-to-site tunnels, and sets it on all three `WindowsController`s: the mesh controller's, before the mesh device is created, the user access controller's and the site-to-site controller's. Every other node hands wireguard-go the raw tun, so it pays no copy per packet.

`controller_windows_test.go` checks that `AddMeshSourceRewrite` between two interfaces of a controller with `SetMeshRewriter` returns nil, that the LUID and the MTU hook stay the raw adapter's, and that deleting an interface closes its wrapper and the rewriter forgets it; for the interfaces of a controller without a rewriter it returns `the mesh interface is no device of this process`.

## In-process mesh source rewrite

A bridge rewrites the source of what a provider's interface or a tunnel's link forwards into the mesh to its own mesh address, the only source a mesh node accepts from it. Linux does it with nftables and macOS with pf (see [Mesh Source Rewrite](../bridge/netlink-route-controller.md#mesh-source-rewrite) and [Mesh source rewrite](./pf-wfp-firewall.md#mesh-source-rewrite)). Windows has no kernel mechanism that fits: WinNAT translates nothing into the mesh while the bridge NAT's object covers the mesh prefix, and what it translates passes no WFP forward filter (see [What WinNAT does, measured](./pf-wfp-firewall.md#what-winnat-does-measured)). A Windows bridge therefore rewrites inside the plexd process.

Both ends of the forwarding step are wireguard-go devices of plexd's own: the mesh device and the device of a `wireguard` provider or a `wireguard` tunnel. The rewrite sits at the seam every packet already passes, the `tun.Device` a `WindowsController` hands wireguard-go. A wrapper around it sees a far end's packet before Windows does, and a mesh peer's reply before Windows does, so translated traffic never crosses Windows forwarding, WinNAT or the WFP forward layer. The code is platform neutral, `internal/wireguard/meshrewrite.go` and `internal/wireguard/meshrewrite_nat.go` without a build tag, and its tests run on Linux, macOS and Windows. Only Windows wires it.

```go
// MeshRewriter rewrites, inside the process, the source of what the far end
// of a registered interface sends into the mesh to the mesh interface's
// address.
type MeshRewriter struct{ /* ... */ }

func NewMeshRewriter(logger *slog.Logger) *MeshRewriter

// Wrap returns the tun.Device to hand wireguard-go in place of dev and
// knows it under name until it is closed.
func (r *MeshRewriter) Wrap(name string, dev tun.Device) tun.Device

func (r *MeshRewriter) AddMeshSourceRewrite(fromIface, meshIface string) error
func (r *MeshRewriter) RemoveMeshSourceRewrite(fromIface, meshIface string) error
func (r *MeshRewriter) ResetMeshSourceRewrite() error
```

The three methods have the signatures of `bridge.MeshSourceRewriter`. `internal/wireguard` does not import `internal/bridge`, so the assertion `var _ bridge.MeshSourceRewriter = (*wireguard.MeshRewriter)(nil)` lives in `cmd/plexd/cmd/up_windows.go`. There `newMeshSourceRewriter` returns the rewriter to the user access and site-to-site managers, and an untyped nil for a nil one.

A connection belongs to the side that opened it. What a far end opens is translated in process. What the host or a mesh node opens through a provider's interface or a tunnel's link goes through Windows, and its replies are handed to Windows untouched. Linux gets the same split from connection tracking, which masquerades new connections only. What a mesh node sends to a site stays in Windows forwarding, because that is where the bridge's policy filters it (see [Routes and Policy](../bridge/site-to-site-vpn.md#routes-and-policy)).

### The wrapper

`Wrap` returns nil for a nil device, so `CreateDevice` still refuses it. The wrapper it returns otherwise behaves as follows. A wrapper whose interface takes part in no rewrite passes every packet through.

- `Write(bufs, offset)` decides each packet by the [rules](#what-the-rewriter-does-with-a-packet) below. Packets for Windows go to the wrapped device's `Write` in one call, in their order. A packet the rules translate is copied and queued for the device it leaves through. It returns `len(bufs)` and the wrapped device's error.
- `Read(bufs, sizes, offset)` returns the next packets from two sources: what a goroutine of the wrapper reads from the wrapped device, one copy each, and the queue of translated packets. It blocks until a packet arrives, fills up to `len(bufs)` packets without blocking again, and returns an error wrapping `os.ErrClosed` once the device is closed.
- The queue holds 512 packets. A packet that finds it full is dropped and counted as `queue_full`, so a slow device never blocks the device the packet came from.
- `Close` closes the wrapped device, ends the goroutine, and forgets the name, every rewrite the interface took part in, as the source or as the mesh interface, and the flows of those rewrites. `MTU`, `Name`, `File`, `Events` and `BatchSize` are the wrapped device's.

### Adding and removing a rewrite

`AddMeshSourceRewrite(fromIface, meshIface)`:

- It checks the mesh interface first. When `meshIface` names no device `Wrap` knows, it returns `bridge: add mesh source rewrite from "<from>" to "<mesh>": the mesh interface is no device of this process`, whatever `fromIface` names, so a rewriter that knows neither interface returns this error.
- When `fromIface` names no such device, it returns nil and logs at Info `mesh source rewrite not needed, the interface is no device of this process` with `from_iface` and `mesh_iface`. A vendor client's adapter, such as Tailscale's, is such an interface.
- A rewrite that exists for `fromIface` is left alone: it returns nil, logs at Debug `mesh source rewrite already present, idempotent success` and reads no address.
- Otherwise it reads the IPv4 prefixes of both interfaces through the seam `addrs func(iface string) ([]netip.Prefix, error)`, in production `net.InterfaceByName` and its `Addrs`, the mesh interface's first. The first IPv4 address of the mesh interface is the mesh address. A failed read of either interface, or a mesh interface without an IPv4 address, returns `bridge: add mesh source rewrite from "<from>" to "<mesh>": address of the mesh interface: <cause>`: a failed read of the source interface's addresses carries the same suffix, and a mesh interface without one the cause `no IPv4 address`. None of these leaves a rewrite behind. The source interface may carry no address.

`RemoveMeshSourceRewrite` forgets the rewrite of `fromIface` and its flows, and returns nil for an interface without one. `ResetMeshSourceRewrite` forgets every rewrite and returns nil: nothing of a rewrite outlives the process, so a start has nothing to remove. `plexd up` calls it through `CleanupUserAccess` at start, as on Linux and macOS.

### What the rewriter does with a packet

Only IPv4 is rewritten, as on Linux and macOS. The far end is the device or the site host behind a source interface, the remote the mesh address it talks to. All state sits under one mutex and reads time through the seam `now func() time.Time`. The rules are free of I/O.

A packet wireguard-go writes to a source interface's device comes from the far end. wireguard-go has already checked its source against the peer's allowed IPs. The first row that applies decides:

| # | Packet | What happens |
|---|---|---|
| A1 | No IPv4 packet, or its header length or total length does not fit its bytes | To Windows, unchanged |
| A2 | The destination is the mesh address, lies in a prefix the source interface carries, lies in `224.0.0.0/4` or is `255.255.255.255` | To Windows |
| A3 | It answers a flow the host sent through this interface: its addresses and ports, or echo id, are the reverse of a host flow, it is an ICMP error that quotes a packet of one, or it is a later fragment whose first fragment answered one and left a record naming that host flow | To Windows |
| A4 | An ICMP error that quotes the reply of a translated flow of this interface | Outer source becomes the mesh address, the quoted destination the mesh address and mesh port. Queued for the mesh device |
| A5 | A later fragment (fragment offset above 0) | With the record its first fragment left: source becomes the mesh address, queued for the mesh device. Without one: dropped, `fragment` |
| A6 | Neither TCP, UDP nor an ICMP echo request | Dropped, `unsupported_protocol` |
| A7 | TTL of 1 or 0 | Dropped, `ttl`. An ICMP time exceeded (type 11, code 0) goes from the mesh address to the far end |
| A8 | Longer than the mesh device's `MTU()` | With DF: dropped without being counted under any reason, and an ICMP destination unreachable (type 3, code 4) that names that MTU goes from the mesh address to the far end. Without DF: dropped, `oversize` |
| A9 | Anything else | Translated: source becomes the mesh address and the flow's mesh port (echo: mesh id), TTL minus 1, checksums updated. Queued for the mesh device. A first fragment leaves a fragment record |

Right after A2, a packet that is no later fragment and whose TCP, UDP or ICMP header does not fit its bytes is dropped and counted as `unsupported_protocol`, the reason of A6, rather than handed to Windows: rows A3 and A4 need the header it cuts short, and Windows would forward it with the far end's own source. A packet of another protocol has no such header and goes on to A6.

A packet wireguard-go writes to the mesh device comes from a mesh peer:

| # | Packet | What happens |
|---|---|---|
| B1 | The destination is the mesh address, and protocol, destination port (echo reply: id), source address and source port are a translated flow's | Destination becomes the far end's address and port (echo reply: id), TTL minus 1, checksums updated. Queued for the flow's source interface. A first fragment leaves a fragment record. TTL of 1 or 0: dropped, `ttl`, with no ICMP time exceeded. Longer than that device's `MTU()`: as A8, the ICMP error to the mesh peer |
| B2 | A later fragment to the mesh address with a fragment record | Destination becomes the far end's address. Queued for the flow's source interface |
| B3 | An ICMP error to the mesh address that quotes a packet of a translated flow | Outer destination becomes the far end's address, the quoted source the far end's address and port. Queued for the flow's source interface |
| B4 | Anything else, also a packet whose IPv4 header, total length or TCP, UDP or ICMP header does not fit its bytes, and a later fragment without a record | To Windows, unchanged |

A TCP or UDP packet or an ICMP echo request that the host hands a source interface's device, which the wrapper reads from the wrapped device for `Read`, passes through and creates or refreshes a host flow of that interface. An echo reply creates none, and neither does a later fragment. That is how the reply to a connection a mesh node opened toward a site, which Windows forwarded out of the tunnel's link, is known in A3. A first fragment of such a reply leaves a record that names the host flow, so its later fragments go to Windows too.

A far end therefore reaches the bridge itself and what a mesh peer's allowed IPs cover, and nothing else the Windows host routes: Windows gets only what rows A1 to A3 hand it, and on the mesh device wireguard-go drops a packet that no peer's allowed IPs cover.

### Flows and mesh ports

A translated flow is keyed by source interface, protocol, far end address, far end port or echo id, remote address and remote port. Its mesh port, or mesh id, lies in 32768 to 49151 and is unique per protocol, remote address and remote port, so two far ends that send from the same port to the same remote leave with different mesh ports. The search starts at a hash of the far end's address and port.

The range lies below Windows' default dynamic ports, 49152 to 65535, so the host's own sockets on the mesh address do not draw from it. plexd does not guard a mesh port against a host socket that binds a number inside 32768 to 49151 explicitly: when such a socket talks to the same remote address and port as a translated flow that holds the same number, the remote's packets to it match the flow in B1 and go to the far end, and the socket receives none of them.

A fragment record is keyed by the source address, destination address, protocol and IP identification the fragments arrive with, and names the flow: a translated flow, or the host flow a first fragment answered. A later fragment from a far end that arrives before its first finds no record and is dropped as `fragment` (A5); one from a mesh peer finds none either and goes to Windows (B4). The rewriter reassembles nothing.

### Lifetimes

An entry lives for the time below after its last packet. The values are netfilter's connection tracking defaults (`nf_conntrack_tcp_timeout_established` 432000, `nf_conntrack_udp_timeout` 30, `nf_conntrack_udp_timeout_stream` 120, `nf_conntrack_icmp_timeout` 30), so a flow lives about as long on a Windows bridge as on a Linux one.

| Entry | Lifetime |
|---|---|
| TCP flow | 120 s until packets of both directions were seen, 432,000 s after that, 120 s once a FIN or RST was seen |
| UDP flow | 30 s until both directions were seen, 120 s after |
| ICMP echo flow | 30 s |
| Fragment record | 30 s |

An expired entry is removed when a lookup finds it, and by a sweep inside packet handling at most every 30 s. A TCP or UDP reply to a host flow that has expired is taken as opened by the far end (A9), as a Linux bridge masquerades a flow whose connection tracking entry has expired. An echo reply opens no flow, so one whose host flow has expired is dropped as `unsupported_protocol` (A6).

### Limits of the rewrite

- At most 65,536 translated flows and 65,536 host flows exist. A packet that would create one more, or finds no free mesh port, is dropped as `table_full`: a far end's packet in A9, or a packet the host sends through a source interface's device that would open a host flow. The limit bounds memory: one far end can fill the table, as it can fill a Linux bridge's connection tracking table.
- At most 65,536 fragment records exist. A first fragment beyond the limit still translates, or still goes to Windows, but leaves no record, so its later fragments from a far end are dropped as `fragment` and those from a mesh peer go to Windows (B4).
- Each wrapper queues at most 512 translated packets (see [The wrapper](#the-wrapper)).
- Only TCP, UDP and ICMP echo are translated. Another protocol, an oversize packet without DF and a later fragment from a far end that arrives before its first are dropped and counted, where the Linux kernel carries, fragments or reassembles them.

### Checksums and ICMP errors

The IPv4 header checksum and the TCP and UDP checksums are updated incrementally (RFC 1624), so a fragment needs no reassembly. A UDP checksum of 0 stays 0, and one that the update turns into 0 is sent as `0xffff` (RFC 768). An ICMP echo's checksum is updated for its id. An ICMP error's checksum is recomputed over the message, the quoted header's checksum is recomputed, and the quoted transport checksum is left alone.

An ICMP error plexd sends of its own (A7, A8 and B1) leaves with TTL 64, without DF and with IP identification 0, and quotes the offending packet's IP header and the first 8 bytes after it. plexd sends at most 100 per second, counted in a fixed window of one second that starts with the first error after the last window ended, and none for an ICMP error or a later fragment.

### Drops and log lines

Drops are counted per reason: `queue_full`, `fragment`, `unsupported_protocol`, `ttl`, `oversize` and `table_full`. Each reason is logged at Warn as `mesh source rewrite dropped packets` with `reason` and `count`, the number since the last line of that reason, at most once per 60 s per reason. The first drop of a reason, and a drop 60 s or more after that reason's last line, is logged at once. A drop within 60 s of the last line waits, and the waiting count is reported by the next packet the rewriter handles 60 s or more after that line, whatever that packet is. No log line carries a packet's content.

The rewriter logs with `component=bridge`, in the wording of the Linux controller:

| Level | Message | Keys |
|---|---|---|
| `Debug` | `mesh source rewrite added` | `from_iface`, `mesh_iface`, `mesh_addr` |
| `Debug` | `mesh source rewrite already present, idempotent success` | `from_iface`, `mesh_iface` |
| `Debug` | `mesh source rewrite removed`, `mesh source rewrite not found, idempotent success` | `from_iface`, `mesh_iface` |
| `Debug` | `mesh source rewrites reset` | (none) |
| `Info` | `mesh source rewrite not needed, the interface is no device of this process` | `from_iface`, `mesh_iface` |
| `Warn` | `mesh source rewrite dropped packets` | `reason`, `count` |

### Tests

`meshrewrite_nat_test.go` drives the rows above with a fake clock, the lifetimes, the limits, the ICMP error budget and the checksums. `meshrewrite_test.go` covers the wrapper, the three methods and the drop lines, and `TestMeshRewriter_Devices` runs four wireguard-go devices in one process over channel tuns, with real UDP on `127.0.0.1`: the bridge's mesh device (`10.255.241.1`) and provider device (pool `10.255.242.0/24`) over `rewriter.Wrap`, node N (`10.255.241.2`) and device D (`10.255.242.2`, and `10.255.242.3` for two far ends on one source port). N's peer entry for the bridge allows `10.255.241.1/32` alone, so wireguard-go at N drops a packet that kept D's address, as a mesh node does. Both files run in `Run unit tests` on Linux, macOS and Windows.

`TestMeshSourceRewrite_RealWintun` in `internal/bridge/meshrewrite_windows_test.go` proves the rewrite on real Wintun adapters, built by the production constructors, with WireGuard traffic between three wireguard-go far ends, and the NAT exemption of a tunnel's adapter with it. It skips unless `PLEXD_TEST_REAL_WINTUN=1`, `PLEXD_TEST_REAL_ROUTES=1` and `PLEXD_TEST_REAL_WFP=1` are set and the token is elevated. It is the only proof of either on Windows and runs in the step `Run real mesh source rewrite tests` (see [CI Workflow](../development/ci-workflow.md)).

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
| `Teardown`      | `() error`                                                                   | Removes the routes of the [routed subnets](#routed-subnets) it programmed, then deletes the WireGuard interface |
| `OSInterfaceName` | `() string`                                                                | The name the OS knows the interface by (`utunN` on macOS), else `Config.InterfaceName` |
| `AddPeer`       | `(peer api.Peer) error`                                                      | Writes the peer with the first entry of its dial order and starts its endpoint selection; updates index |
| `RemovePeer`    | `(publicKey []byte) error`                                                   | Removes peer by raw public key                                 |
| `RemovePeerByID`| `(peerID string) error`                                                      | Resolves ID via index, removes peer, drops its dial state, cleans index |
| `UpdatePeer`    | `(peer api.Peer) error`                                                      | Rewrites the peer (AddPeer is idempotent) by the first of six ordered rules that applies: a new key starts its dial order over, a relayed peer, or one in a [direct retry](#direct-retry), tries its direct entries again on a fresh device peer when the update adds one and a running retry goes on with the entries the update still lists, a peer on a relay the update takes away moves to the update's first relay on a fresh device peer, a relayed peer whose relay stays in the set keeps it, a connected peer keeps its device endpoint, and any other starts its dial order over; updates index. See [Endpoint selection](#endpoint-selection) |
| `ConfigurePeers`| `(ctx context.Context, peers []api.Peer) error`                              | Bulk-adds peers as `AddPeer` does, with context cancellation, and replaces the dial state with the peers it wrote; individual errors logged |
| `PeerIndex`     | `() *PeerIndex`                                                              | Returns the peer index                                         |
| `MeshPeerStats` | `() ([]MeshPeerStat, error)`                                                 | Reads the mesh interface's peers and maps them to node IDs; see [Mesh peer stats](#mesh-peer-stats) |
| `MeshPrefix`    | `() netip.Prefix`                                                            | The Domain mesh prefix the interface was set up with; see [Mesh prefix](#mesh-prefix) |
| `SetPeerPSK`    | `(peerNodeID, publicKey string, psk []byte) error`                           | Rewrites the stored peer of `peerNodeID` with `psk` when it was last written with `publicKey`; see [Installing a PSK](#installing-a-psk) |
| `SetLocalPrefixes` | `(fn func() ([]netip.Prefix, error))`                                     | Sets the function the reconcile handler reads this host's interface prefixes from, to order a peer's on-link candidates first and to skip a routed subnet inside a local network. Endpoint selection reads it too, at most once per 30 s, to start a [direct retry](#direct-retry) when a local network makes a relayed peer's direct entry on-link. Call it before the handler and `RunEndpointSelection` run. See [Dial order](#dial-order) |
| `SetPeerRouter` | `(r PeerRouter)`                                                             | Sets the router the reconcile handler programs the routes of the peers' routed subnets with. Call it before the handler runs. Without one the manager programs the routed subnets as allowed IPs and adds no route. See [Routed subnets](#routed-subnets) |
| `SetRelayProbe` | `(send func(meshIP netip.Addr) error)`                                       | Sets the function endpoint selection sends the relay liveness probe with; `plexd up` passes `SendRelayProbe`. Call it before `RunEndpointSelection`. Without it no probe goes out. See [Relay liveness probe](#relay-liveness-probe) |
| `SetFailureDetection` | `(detectAfter time.Duration) (time.Duration, bool)`                    | Sets the failure-detection time, how long a relayed peer may stay silent before endpoint selection dials the next relay of its set. Ignores a value of zero or less, clamps any other to `MinFailureDetection` (5 s) and `MaxFailureDetection` (180 s), and returns the value in force and whether it changed. See [Failure detection time](#failure-detection-time) |
| `FailureDetection` | `() (time.Duration, bool)`                                                | The failure-detection time held, and `0, false` while none is. See [Failure detection time](#failure-detection-time) |
| `RunEndpointSelection` | `(ctx context.Context, interval time.Duration) error`                 | Tries each peer's dial order until a handshake completes, one pass per `interval`, or per pass of the [failure-detection time](#failure-detection-time) when that is shorter, until `ctx` is done; see [Endpoint selection](#endpoint-selection) |
| `SetPathMTUProbe` | `(probe func(context.Context) (int, error))`                              | Sets the function `Setup` and `RunMTUProbe` measure the uplink's path MTU with. Call it before `Setup`. See [MTU detection](#mtu-detection) |
| `RunMTUProbe`   | `(ctx context.Context, interval time.Duration) error`                        | Measures the uplink again once per `interval` and lowers or raises the MTU to fit, until `ctx` is done; see [Probing again](#probing-again) |

The package function `ProgrammedEndpoint` (`handler.go`) returns the endpoint the pull gives a snapshot peer without its candidates, from the peer and `MeshPrefix()`; see [Dial order](#dial-order). The package function `SendRelayProbe` (`dial.go`) is the sender `plexd up` passes to `SetRelayProbe`; see [Relay liveness probe](#relay-liveness-probe). The package function `FailureDetectionDispatchHandler` (`handler.go`) is the [dispatch handler](../core/reconciliation.md#dispatchhandler) `plexd up` registers to hand each pull's `failure_detection` block to `SetFailureDetection`; see [Failure detection time](#failure-detection-time).

### Programmed peers

The manager keeps a dial state per node ID: the last `api.Peer` it wrote, the position in the peer's dial order of the endpoint programmed on the device, when that endpoint was programmed, and whether a fresh handshake shows the peer connected. It also records whether the peer is [relayed](#the-trial), last seen connected over one of its relays, when a re-dial, of a relay or of a direct retry's entry, last replaced its device peer, the `LastHandshake` at the last pass that found it fresh, the session a [move back](#the-trial) was last written for, and the [relay liveness probe](#relay-liveness-probe)'s state: the device's `RxBytes` for the peer at the last pass, when the silence window started (the counter moved, the peer turned connected or came back on a relay, a pass followed a roam to another relay of its set, or a probe send failed), when the outstanding probe went out (zero when none is; under a [failure-detection time](#failure-detection-time), when the last probe was sent), and whether the last probe send failed. For the [direct retry](#direct-retry) it records the direct entries a running retry tries after the one programmed, in order, the relay the retry dials when no entry answers, which is set exactly while a retry runs, and the direct entries that left the peer's dial order or failed a retry, each with the time it was recorded, which the retry remembers for 10 min. While a retry runs, the peer is neither connected nor relayed, and the position is that of the entry tried. `SetPeerPSK` reads the stored peer, because it has to repeat a peer's allowed IPs to write its PSK, the [peer routes](#routed-subnets) follow the routed subnets of the stored peers, and [endpoint selection](#endpoint-selection) reads the rest. `AddPeer` and `UpdatePeer` store the state after a successful device write, `ConfigurePeers` replaces the whole map with the peers it wrote, and `RemovePeerByID` drops the entry after a successful removal. A failed device write in `AddPeer`, `UpdatePeer` or `SetPeerPSK` leaves the state as it was, so a peer whose first write failed has none. One mutex guards the map and serializes every mesh peer device write, since the reconcile handler, the edge PSK store and endpoint selection write the same peers from different call paths. The manager also holds the [failure-detection time](#failure-detection-time), zero while no pull carried one, and the same mutex guards it.

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
- It keeps only the device peers whose key `PeerIndex.NodeIDsByPublicKey` maps. A key the index does not know, such as one two node IDs share, is dropped.
- It keeps peers with no handshake (a zero `LastHandshake`), because the metrics report them.
- It returns the result sorted by `NodeID`, and an empty, non-nil slice when nothing maps.
- `Endpoint` passes through unfiltered. The handshake reporter applies the wire rules.

### Endpoint selection

WireGuard holds one endpoint per peer. Endpoint selection (`dial.go`) programs the entries of a peer's [dial order](#dial-order) one after another and keeps the first one that completes a WireGuard handshake. The order only says which entry to try first; a completed handshake proves the choice.

A peer's order is `api.Peer.Endpoints`, or `Endpoint` alone when `Endpoints` is empty and `Endpoint` is set, so a caller that sets only `Endpoint` keeps working. The selection state lives in the manager's [dial state](#programmed-peers), and the device writes change it as follows:

- `AddPeer` programs the first entry of the order, or no endpoint for an empty order, and starts the trial: position 0, programmed now, not connected. `ConfigurePeers` does the same for each peer it loads.
- `UpdatePeer` applies the first of the six rules below that fits.
- `SetPeerPSK` writes an empty endpoint and leaves the selection as it is.
- `RemovePeerByID` drops the state once the device removal succeeds, so a removed peer is never switched.

`UpdatePeer` checks its rules in this order:

1. **No state, or a new key.** It behaves like `AddPeer` with the new order. WireGuard keys peers by public key, so a rotated key is a new device peer that has no endpoint yet. The device peer of the old key is removed first: WireGuard moves to the new key only the allowed IPs its write names, so the old key would keep a routed subnet the update no longer lists. A failed removal fails the update and writes nothing, so the next run tries the rotation again. The new state is not relayed.
2. **A new direct entry for a relayed peer.** A [relayed](#the-trial) peer, connected or not, or a peer in a [direct retry](#direct-retry), whose update names relays tries its direct entries again when the update adds a new one. The direct entries are the entries of the order before its first relay, and one is new when the order plexd holds for the peer does not list it among them and plexd does not [remember](#direct-retry) it. `UpdatePeer` then starts a retry with every direct entry of the update's order that is not remembered, in that order: it removes the device peer, adds it again with the first of them as the endpoint, logs `wireguard: trying the direct endpoints again` with `reason=pull`, and stores a state at that entry's position, programmed now, neither connected nor relayed, with the other entries left to try and the relay the retry ends on. That relay is the one a running retry ends on, or the relay the peer is on when none runs. An update that takes that relay away, by the test of rule 3, makes it the update's first relay instead, so a pull that moves the relay and adds a direct entry runs the retry first and logs no relay move. A running retry the update adds nothing to goes on, on a fresh device peer whose window starts over, with the entry it tries and the entries it had left, those the update still lists, in the update's order. When the update lists none of them, `UpdatePeer` dials the relay the retry ends on at once on a fresh device peer, logs `wireguard: no direct endpoint answered, dialing the relay again`, and stores the peer relayed and not connected at that relay's position, with its probe started over. In this rule and in rules 3 and 4, a direct entry the update drops from the order of a relayed peer, or of a peer in a retry, is remembered. A relayed peer whose update adds no direct entry goes on to the next rules, and so does any peer whose update names no relays: a peer in a retry, which is never connected, then reaches rule 6.
3. **A relay taken away.** When the entry programmed is one of the peer's relays, the peer is relayed or not connected, and the update names relays, the peer moves at once if the relay programmed is not among them, or if the update's first relay changed and is not the relay programmed. A relayed peer on a standby it moved to on its own therefore follows the control plane once the control plane names a new first relay. A connected peer that is not relayed runs on a direct path WireGuard roamed to, which the move would cut, so rule 5 keeps it. `UpdatePeer` [dials](#relay-liveness-probe) the update's first relay on a fresh device peer, logs `wireguard: relay fallback changed, moving to the new relay`, and stores a new state at that relay's position: programmed now, not connected, relayed when the old state was, and the probe started over. A peer in its relay hold that never connected moves the same way, and its hold starts over on the new relay.
4. **A relayed peer whose relay stays.** A [relayed](#the-trial) peer whose programmed relay is still among the update's relays keeps it, connected or not. This includes a standby it moved to on its own: a pull that still names the dead first relay first, or that names the standby first, does not move it back. The write carries an empty endpoint, the position moves to the relay's place in the new order, and the connected flag, the timestamp and the probe's state stay. Without a new direct entry, a relayed peer that waits for its partner is never sent back to the first entry.
5. **A connected peer.** The write carries an empty endpoint, which both controllers leave untouched on the device, so an endpoint WireGuard roamed to stays. It stores the new peer, sets the position to where the entry last programmed sits in the new order (0 when it is no longer there), and keeps the connected flag and the timestamp. A relayed peer gets here only when the update names no relays, and it stops being relayed.
6. **Any other peer.** It behaves like `AddPeer` with the new order. A peer in its relay hold that never connected therefore restarts its walk on any update that is not a move, including one that only changes a standby. So does a peer in a direct retry whose update names no relays, which ends the retry.

A failed write returns `wireguard: update peer: <cause>` and leaves the state as it was. A move or a retry's write that the device refuses has the cause `remove device peer: <cause>` or `add device peer: <cause>`, and the reconciler keeps its snapshot and retries the update on its next cycle.

#### The trial

Each pass reads the device through [`MeshPeerStats`](#mesh-peer-stats) before it takes the manager's mutex. A read error, `ErrPeerStatsUnsupported` included, ends the pass with nothing written. A peer is fresh when the device reports a non-zero `LastHandshake` for it that is younger than 180 s: WireGuard rekeys a session it uses every two minutes and refuses one older than 180 s, so an older handshake says the path no longer carries traffic. One entry is tried for the keepalive interval plus 5 s, 30 s with the default keepalive.

The relays are held longer. `api.Peer.Fallbacks` holds the peer's relays as they end the order, in set order. When entries precede the first relay, every relay of the set, the first and each standby, is tried for one trial per entry before the first relay instead of one trial: as long as those entries took together. When the order starts with its relays, a relay gets one trial. This is the relay hold. A peer that is not relayed walks its order up to and including its first relay, then starts over at the first entry. The walk never programs a standby. Each side of a pair then spends at least half its walk on the first relay, so the relay windows of two peers behind hard NATs always overlap or touch. A walk of two entries behaves as with one trial per entry. The standbys get the same hold as the first relay, so two relayed peers that move through the set keep the gap between them. A node on an older plexd keeps the 30 s trial on its fallback, and the [NAT relay](../bridge/nat-relay.md) serves it like any other peer.

A connected peer is relayed when it runs over one of its relays. Each pass that finds the peer's handshake fresh decides the mark again:

- A device endpoint equal to a relay of the set that is an address (an IPv4-mapped address compares as IPv4) means the peer is relayed over that relay, whatever entry is programmed. WireGuard roams a peer to the address its partner's initiation came from, so a peer programmed on a direct entry or on another relay can run over this relay. The position then moves to that relay. The exception is a relayed peer that roamed to another relay of its set with no new handshake: the pass moves it back, once per session, and a second roam in that session is followed.
- With no device endpoint, the peer is relayed over the entry programmed when that entry is a relay.
- A device endpoint that matches no relay means the peer is not relayed: it opened a direct path and WireGuard roamed to it, which a relay move must not cut and the probe must not judge. A hostname cannot be compared, so when the set holds one and the entry programmed is a relay, the peer is relayed over the entry programmed.
- A peer that is not connected keeps the mark it had when it was last connected.

A peer that roams off a relay or back onto one is therefore followed, and so is a roam to another relay of its set that came with a new handshake. A relayed peer stays on its relays, because the direct entries before them already failed. Outside a [direct retry](#direct-retry), the pass never programs one of its direct entries. When its relay fails, the pass dials the next relay of its set on a fresh device peer, wrapping around to the first after the last: when the [relay liveness probe](#relay-liveness-probe) goes unanswered or, on a node that holds a [failure-detection time](#failure-detection-time), the peer stays silent past it, when the handshake goes stale, and after each relay hold that passes without a handshake. For a set of one the next relay is the same relay. Both sides of a pair hold the same list and detect a dead relay in the same window, so without a pull they move to the same standby. The peer tries its direct entries again in a direct retry when a pull adds a direct entry plexd does not remember, and when a change of this node's local networks makes one of its direct entries on-link. It walks them again when an update leaves it no relay, when its key rotates, when it is removed and added again, after a restart, or when WireGuard roamed it to a direct path that then failed: that peer lost the mark while connected, so its stale handshake resumes endpoint selection as for any peer that is not relayed. A peer that lost the mark on a standby sits outside its walk, and goes back to the walk's first entry once its trial on the standby ends.

A roam between relays with no new handshake almost always means a stale packet moved the device, such as one from a [bridge that resumed after a freeze](../bridge/nat-relay.md#meeting-on-the-relay), because a relay drops every packet of a session whose handshake it did not forward. The session then still runs over the entry programmed, and the pass writes that entry back to the device. It keeps the device peer, because a re-dial would cut a valid session, and leaves the position and the probe's state as they are. The stale packet's bytes count as received, so the [silence window](#relay-liveness-probe) starts over on the next pass. The bound is one pass: up to 5 s on a node that holds no failure-detection time, and `detectPass` of the value on a node that holds one, 1 s at the default 15 s (see [Failure detection time](#failure-detection-time)). The one genuine case is a pass that reads the device in the round trip between consuming a partner's initiation and that handshake completing: it writes the old relay back, the partner's next packet brings the new handshake, and the next pass follows it, at a cost of at most one packet. A session gets one move back, because a stale packet that lands within one pass of a handshake makes the position itself wrong. The partner's next packet then heals the device, and a second roam in the session is followed, which heals the position. A roam to an address no entry of the set names cannot be judged when the set holds a hostname, because that address may be the hostname's relay, so the pass writes nothing. An address entry of such a set still matches, so a roam to it is moved back.

A control plane that sends no `fallback_endpoints` gives a peer with a `fallback_endpoint` a set of one, and plexd dials that one relay again when it fails. A node on an older plexd dials only `fallback_endpoint`, the first relay, and dials it again when it fails. A pair with one side on an older plexd therefore fails over only when the control plane names a new first relay: the older side keeps dialing the first relay, and the newer side comes back to it each time it wraps around the set.

The pass walks the peers in node-ID order:

| Peer | What the pass does |
|---|---|
| Relayed or in a direct retry, on the pass whose read found the local networks changed, with a direct entry that is on-link with the new networks, was not with the old ones, and is not remembered | Before any row below: starts a [direct retry](#direct-retry) on a fresh device peer, logs `wireguard: trying the direct endpoints again` with `reason=local_networks`, and goes on to the next peer. A failed write logs `wireguard: endpoint switch failed`, leaves the state as it was, and goes on to the next peer too |
| Fresh, not marked connected | Marks it connected, marks it relayed when it runs over one of its relays and moves its position to that relay, clears the mark otherwise, starts the probe's silence window, and logs `wireguard: endpoint selected` with the endpoint the device reports, which may be one WireGuard roamed to, and `relayed`. For a peer in a direct retry this ends the retry: connected over the direct entry it tries, the peer is not relayed, and connected over a relay, because the partner's initiation came through one, it is relayed again |
| Fresh, marked connected, not relayed | Nothing |
| Fresh, marked connected, relayed | Runs the [relay liveness probe](#relay-liveness-probe), which dials the next relay of the set when the probe goes unanswered. A node that holds a failure-detection time runs the watch of [Failure detection time](#failure-detection-time) instead, which dials the next relay when the peer stays silent past the time. A peer that came back on a relay, or roamed to another relay of its set with a new handshake or for the second time in a session, moves its position to that relay and starts a new silence window first. On the first roam of a session with no new handshake, the pass instead writes the entry programmed back to the device, logs `wireguard: relayed peer roamed to a relay its session does not run over, moving it back`, and skips the probe |
| Not fresh, marked connected, relayed | Clears the mark, logs `wireguard: relayed peer handshake went stale, dialing the relay again` and dials the next relay of the set |
| Not fresh, marked connected, not relayed | Clears the mark, restarts the timer and logs `wireguard: peer handshake went stale, resuming endpoint selection`. The entry on the device gets its full trial, the relay hold for a relay, before the next switch |
| Not fresh, not connected, relayed, programmed less than the relay hold ago | Nothing |
| Not fresh, not connected, relayed, hold over | Logs `wireguard: still no handshake over the relay, dialing it again` with `trial` and dials the next relay of the set, after the last one the first again. No direct entry is programmed |
| Not fresh, not connected, in a direct retry, entry programmed less than 10 s ago | Nothing |
| Not fresh, not connected, in a direct retry, window over, entries left | Remembers the entry programmed as failed, logs `wireguard: direct retry, trying the next endpoint` with `remaining`, and writes the next entry of the retry on a fresh device peer, programmed now |
| Not fresh, not connected, in a direct retry, window over, no entry left | Remembers the entry programmed as failed, ends the retry, marks the peer relayed, logs `wireguard: no direct endpoint answered, dialing the relay again`, and dials the relay the retry ends on, on a fresh device peer, as a relay re-dial does |
| Not fresh, not connected, not relayed, no direct retry, with an empty order, on the only entry of its walk, or programmed less than the entry's trial ago | Nothing |
| Not fresh, not connected, not relayed, no direct retry, trial over | Programs the next entry of its walk (after the last one, the first again; from a standby, the first), restarts the timer and logs `wireguard: trying next endpoint candidate` with `trial`, how long it tries the entry it programmed: one trial, or the relay hold for the first relay |

The relay hold is one trial per entry before the first relay, and one trial when the order starts with its relays. A relay re-dial removes the device peer and adds it again with the relay it dials as its endpoint; see [Relay liveness probe](#relay-liveness-probe) for why. A successful one leaves the peer relayed, not connected, programmed now, at the position of the relay it dialed, and with its probe started over.

A peer counts as connected while its latest handshake is younger than 180 s. Neither a pass nor `UpdatePeer` rewrites the device endpoint of a connected peer, so WireGuard roaming, a peer answering from another address, stays in effect. The relay makes three exceptions, and the direct retry a fourth: a pass dials the next relay of its set for a relayed peer whose probe went unanswered, or that stayed silent past the [failure-detection time](#failure-detection-time), while its handshake is still fresh, `UpdatePeer` moves a relayed peer to the update's first relay when the update takes its relay away, a pass moves a relayed peer back from a relay its session does not run over, and `UpdatePeer` or a pass starts a [direct retry](#direct-retry) for a relayed peer, which replaces its device peer and cuts the relayed session. The move back applies only to a roam between relays of the set, and the retry only to a relayed peer, so neither touches a direct path.

A relay re-dial, and each write of a direct retry, replaces the device peer while a pass may already have read the device: the pass reads it before it takes the mutex, and `UpdatePeer` can move a peer in between. So a handshake older than the device peer's last replacement does not count as fresh. It belongs to the dropped session, and the pass leaves the new device peer not connected until a handshake completes on it.

A failed switch logs `wireguard: endpoint switch failed`, leaves the peer on the entry still programmed, and joins `wireguard: switch endpoint of peer <node id>: <cause>` into the pass's error. The timer restarts all the same, so the next attempt follows that entry's full trial later: one trial, or the relay hold when the peer is on a relay. A failed relay re-dial logs the same line with the relay it tried as `endpoint` and joins the same error, whose cause is `remove device peer: <cause>` or `add device peer: <cause>` for a write the device refused. The peer's position still moves to that relay, the peer stays relayed and not connected, and its timer restarts. The next attempt, one relay hold later, therefore dials the relay after it: a relay the device keeps refusing, such as a hostname that no longer resolves, does not hold the peer back from the rest of its set. A fresh handshake on the device peer that a failed remove left in place marks the peer connected again first, over the relay it came from. A failed move back logs the same line with the entry programmed as `endpoint` and joins the same error, but records nothing and restarts no timer, so the next pass tries the same relay again. A failed write of a direct retry's next entry logs the same line with that entry as `endpoint` and joins the same error. The position still moves to that entry and its window restarts, so the next step, one window later, tries the entry after it. A failed write of a retry that a change of the local networks starts leaves the state as it was (see [Direct retry](#direct-retry)).

The trial depends on the keepalive. WireGuard starts a handshake only when it sends something, and the keepalive timer is what makes it send to an entry newly programmed on an idle peer. A switch happens on the first pass after the trial ran out, so up to one interval late. With the defaults, a walk of ten entries, the contract's cap of eight candidates plus the direct endpoint and the first relay, reaches its first relay after about 270 s, holds it for about 270 s, and returns to the first entry after about 540 s, one cycle. The order itself can hold 13 entries with the contract's cap of four relays, but the walk ends at the first relay. A relayed peer whose relays never complete a handshake dials the next relay once per relay hold: every 30 s when at most one entry precedes the first relay, every 270 s with nine before it. A restarted plexd starts every peer at the first entry again.

#### Relay liveness probe

A fresh handshake does not show that a relay still forwards. A WireGuard session stays valid for up to 180 s after the relay stopped, and a relayed peer would wait out that age before its handshake went stale. A device counter that stands still does not show that the relay stopped either. A received keepalive restarts WireGuard's own keepalive timer, so on an idle tunnel one side can receive nothing until the next rekey, about two minutes later. A data packet is different: WireGuard answers one with a keepalive within 10 s when it has nothing else to send. The probe sends such a packet into a silent tunnel and watches for the answer.

The windows below are those of a node that holds no [failure-detection time](#failure-detection-time) (`checkRelay`). A node that holds one sends the same probe on every pass and judges the peer against that time instead (`watchRelay`). The sender, the policy exemption, the mesh-prefix rule, the failed-send logging and the re-dial write apply to both.

```go
const relayProbeTimeout = 15 * time.Second // the verdict window
const relayProbePort = 9                   // the discard port

func (m *Manager) SetRelayProbe(send func(meshIP netip.Addr) error)
func SendRelayProbe(meshIP netip.Addr) error
```

`SetRelayProbe` sets the function the probe is sent with. Call it before `RunEndpointSelection`, like `SetLocalPrefixes`. `SendRelayProbe` is the sender `plexd up` passes. It sends one UDP datagram of one zero byte to port 9 of `meshIP`. The host routes the datagram into the mesh interface, and WireGuard carries it to the peer as data. Nothing has to listen on the port: the peer's WireGuard answers the data packet whatever the host behind it does with the datagram. `SendRelayProbe` refuses an address that is not IPv4, because mesh IPs are IPv4, with `wireguard: relay probe: mesh ip <ip> is not IPv4`, and wraps a failed dial or write as `wireguard: relay probe <ip>: <cause>`.

Every policy backend lets the node send UDP to port 9 over the mesh interface without a rule, ahead of the policy rules, so the probe leaves under any policy: the nftables output chain, the pf anchor and the WFP connect layers each pass it (see [What the rules govern](./pf-wfp-firewall.md#what-the-rules-govern)). The backends name the port `policy.RelayProbePort`. `TestRelayProbePortIsPolicyExempt` (`dial_test.go`) fails when `relayProbePort` and `policy.RelayProbePort` differ. Without the exemption a narrow policy would fail every probe send, and plexd would notice a dead relay only once the handshake went stale. The receiving node's inbound rules still apply to the datagram. That does not matter here, since the peer's WireGuard answers the data packet whatever the host behind it does with the datagram.

On a node that holds no failure-detection time, each pass checks a [relayed](#the-trial) peer that is marked connected and whose handshake is fresh against the device's `RxBytes` for it, except the pass that moves the peer back, which skips the probe for that peer:

| Peer | What the pass does |
|---|---|
| `RxBytes` moved since the last pass | Records the counter, restarts the silence window and clears an outstanding probe |
| Silent for less than one trial, no probe outstanding | Nothing |
| Silent for one trial, no probe outstanding | Sends the probe to the peer's mesh IP and logs `wireguard: relayed peer silent, probing` at Debug |
| Probe outstanding for less than 15 s | Nothing |
| Probe outstanding for 15 s, `RxBytes` unmoved | Logs `wireguard: relayed peer did not answer the probe, dialing the relay again` with `silent_for` and dials the next relay of the set |

On such a node the silence window is one trial, the keepalive interval plus 5 s, 30 s with the default keepalive. It starts when the peer turns connected or comes back on a relay, when a pass follows a roam to another relay of its set, again each time the counter moves, and again after a failed send, so a peer that receives traffic is never probed. The verdict window, `relayProbeTimeout`, is fixed at 15 s: WireGuard's `KeepaliveTimeout` of 10 s, in which a live path answers the probe, plus its `RekeyTimeout` of 5 s for the answer to arrive.

No probe goes out without a sender, or to a peer whose `MeshIP` does not parse or lies outside the [mesh prefix](#mesh-prefix). With the host `/32` of an identity without `domain_mesh_cidr`, or the zero prefix before `Setup`, the host would route the datagram past the mesh interface, and its silence would read as a dead relay. Without a probe, a relayed peer counts as failed only once its handshake goes stale. This holds under a failure-detection time too.

A failed send logs `wireguard: relay probe send failed` with `error`, at Warn the first time and at Debug while the sends keep failing. It restarts the silence window, so no verdict follows a probe that never left. The next attempt follows one trial later on a node that holds no failure-detection time, and on the next pass on a node that holds one. A send that succeeds ends the run of failures, and the next failure logs at Warn again. The probe is sent under the manager's mutex, because one UDP send does not block.

On a node that holds no failure-detection time, with the defaults, a 25 s keepalive and a pass every 5 s:

- The pass that counts the relay's last packet starts the silence window, up to 5 s after the packet arrived.
- The probe goes out on the first pass 30 s or more after that pass.
- The verdict comes on the first pass 15 s or more after the probe, and dials the next relay of the set.
- A relay that stops forwarding is therefore left 45 to 50 s after its last packet. A pass reads the clock after it reads the device, so a window can miss its closing pass by a fraction of a second and close one pass later. With both windows late, the re-dial comes up to 60 s after the last packet.

Under the default failure-detection time of 15 s the re-dial comes 14 to 15 s after the last packet, and up to 16 s after it when a pass runs late (see [Failure detection time](#failure-detection-time)).

Both sides of the pair leave the relay in that window and reach the same standby. The gap between them is absorbed by the relay hold, at least 30 s, plus the 30 s a relay keeps a pending initiation (see [First Contact](../bridge/nat-relay.md#first-contact)). With a 1 s keepalive, as in the in-process relay test, and neither node holding a failure-detection time, the pair completes a handshake over the standby about 21 s after the first relay stops. With both nodes holding 5 s, `TestRelayIntegration_FailureDetectionMovesThePairToTheStandby` requires a handshake over the standby on both within 15 s of the stop.

Without the probe, a relayed peer waits until its handshake is 180 s old. With it, a pair with two or more relays moves to the next relay of its set with no pull when its relay stops forwarding or restarts, within about a minute when its nodes hold no failure-detection time. When they hold one, it moves within that time, one pass later when a pass runs late. For a set of one the next relay is the same relay. A relay that restarted and lost its index table then carries the pair again within the same time. With a set of one, a dead relay stays dead until the control plane names another first relay, and `UpdatePeer` then moves the peer at once.

Every re-dial of a relay is the same write, whether it follows an update that takes the relay away, an unanswered probe, a silence past the failure-detection time, a stale relayed handshake or a relay hold without a handshake: plexd removes the device peer and adds it again with the relay it dials as the endpoint. That is the update's first relay for a move, and the next relay of the set otherwise. The relay routes a transport message by its receiver index and drops one whose index it does not hold, with reason `unknown_index` (see [Forwarding Table](../bridge/nat-relay.md#forwarding-table)). A write that only changed the endpoint would keep the peer's session, which a new or restarted relay does not know. WireGuard starts a new handshake on its own only after 15 s of unanswered data, or once the session is 120 to 180 s old. The new device peer has no session. Its write turns the keepalive interval on, and wireguard-go sends a keepalive when that happens, which starts a handshake at once. The Linux kernel module is assumed to do the same.

A failed add leaves the peer off the device until the next attempt. That attempt's remove names a key the device does not hold, which the [userspace backend](#userspace-backend) accepts. The Linux kernel module is assumed to accept it as well.

A re-dial makes a new device peer, as a key rotation does, so its handshake time and byte counters start over. The [handshake report](../core/heartbeat-service.md#handshake-reporter) leaves the peer out until its new handshake completes, as it does for any new device peer, and the [tunnel metrics](../observability/metrics-collection.md#tunnelcollector) count its `rx_bytes` and `tx_bytes` from 0 again.

On a node that holds no failure-detection time, the probe costs at most one datagram per relayed peer per silence window, sent only while the peer receives nothing and answered by one 32-byte keepalive. A node that holds one sends a probe on every pass (see [Cost](#cost)). A re-dial costs one extra handshake, whether it dials the same relay or the next one of the set. The probe is off with `persistent_keepalive: 0s`, which turns endpoint selection off, and without `SetRelayProbe`. Nothing on the wire changes: the peer's WireGuard answers the probe, not its plexd, so the probe works against a peer on any version, and a node on an older plexd keeps the 180 s hold. A failure-detection time under 15 s is the exception: against a peer that sends no probes of its own, it re-dials a healthy relay (see [Failure detection time](#failure-detection-time)).

#### Failure detection time

A Domain sets how long a relayed peer may stay silent before its nodes dial the next relay of the peer's set. The [state pull](../core/api-endpoints.md#get-v1-nodes-node-id-state) carries that time as the `failure_detection` block. Its `detect_after_seconds` is a whole number of seconds from 5 to 180, and 15 for a Domain that never set it:

```json
"failure_detection": {
  "detect_after_seconds": 15
}
```

A node that holds the value watches each relayed peer against it instead of the fixed windows of the [relay liveness probe](#relay-liveness-probe). Under the default of 15 s the node dials the next relay 14 to 15 s after the relay's last packet, where a node that holds no value takes 45 to 60 s. A change reaches the node with its next pull, at most one reconcile interval later (60 s by default). No event carries it.

```go
const (
    MinFailureDetection = 5 * time.Second
    MaxFailureDetection = connectedHandshakeAge // 180 s
)

func detectPass(d time.Duration) time.Duration
func detectSilence(d time.Duration) time.Duration

func (m *Manager) SetFailureDetection(detectAfter time.Duration) (time.Duration, bool)
func (m *Manager) FailureDetection() (time.Duration, bool)
func FailureDetectionDispatchHandler(mgr *Manager) reconcile.DispatchHandler
```

`FailureDetectionDispatchHandler` (`handler.go`) is a [dispatch handler](../core/reconciliation.md#dispatchhandler), so it runs on every successful pull, drift or not. `plexd up` registers it when the WireGuard interface came up, before the WireGuard reconcile handler. The pull carries the block raw, as `api.NodeStateSnapshot.FailureDetection`, a `json.RawMessage`, and the handler decodes it into `api.NodeStateFailureDetection`, so a malformed value never fails the pull that carries the peers and the policy. `DetectAfterSeconds` is an `int64`, so a value out of range decodes on a 32-bit build too. The handler keeps its state in its closure, which only the reconcile goroutine enters, and logs with `component=wireguard`. Per pull:

- An absent key or a `null` changes nothing and logs nothing. The node keeps the value of its last pull that carried one.
- A block `json.Unmarshal` refuses, such as a string or a `detect_after_seconds` of `15.5` or `"15"`, changes nothing and logs `wireguard: failure detection block malformed` at Warn, once until a block decodes again.
- A `detect_after_seconds` of zero or less, `{}` included, changes nothing and logs `wireguard: failure detection time out of range` at Warn.
- A value from 1 to 4 applies 5 s, and a value above 180 applies 180 s. Both log the same Warn line with `applied`. The handler bounds the integer before it multiplies it by `time.Second`, so no value overflows a `time.Duration`.
- The out-of-range line is logged once per run of the same raw value. A value from 5 to 180 ends the run.
- Every positive value, clamped or not, goes to `SetFailureDetection`.

`SetFailureDetection` ignores a value of zero or less and clamps any other to `MinFailureDetection` and `MaxFailureDetection`. It returns the value in force and whether it changed. A change restarts the silence window of every relayed peer and clears its probe state, so no peer is judged against a window it did not start under, and logs `wireguard: failure detection time set` at Info with `detect_after`, `previous` (`0s` when none was held) and `pass`. A pull that repeats the value logs nothing. `FailureDetection` returns the value held, and `0, false` while none is. The ceiling is the stale-handshake age: once a relayed peer's handshake is 180 s old, the pass dials the next relay whatever the value says (see [The trial](#the-trial)). Site gateway failover ([#217](https://github.com/plexsphere/plexd/issues/217)) is not built yet; it will read the value through `FailureDetection`.

The value lives in memory only. It is not persisted and has no config key or flag: the Domain owns it, the first pull after a start delivers it again, and a restarted plexd starts every peer at the first entry of its dial order anyway. A node that never received a value, such as one whose control plane sends no block, keeps `checkRelay` with its silence window of one trial (30 s with the default keepalive), its 15 s verdict and the pass every 5 s of `plexd up` (see [Relay liveness probe](#relay-liveness-probe)).

The value held, `d`, sets two times (`dial.go`):

- `detectPass(d)` is `d/15` truncated to whole seconds, at least 1 s and at most `EndpointSelectionInterval` (5 s). It is the pass interval and the probe interval.
- `detectSilence(d)` is `d - detectPass(d)`, how long a relayed peer may stay silent before the pass dials the next relay.

| Value | Pass and probe | Silence |
|---|---|---|
| 5 s | 1 s | 4 s |
| 14 s | 1 s | 13 s |
| 15 s | 1 s | 14 s |
| 29 s | 1 s | 28 s |
| 30 s | 2 s | 28 s |
| 60 s | 4 s | 56 s |
| 75 s | 5 s | 70 s |
| 180 s | 5 s | 175 s |

While a value is held, a pass calls `watchRelay` in place of `checkRelay` for a [relayed](#the-trial) peer that is marked connected and whose handshake is fresh, except the pass that moves the peer back. `watchRelay` applies these rules in order:

1. `RxBytes` moved since the last pass: it records the counter, restarts the silence window, and goes on to the rules below.
2. No sender, or a `MeshIP` that does not parse or lies outside the [mesh prefix](#mesh-prefix): it does nothing more. Without a probe there is no verdict, and the peer counts as failed only once its handshake goes stale.
3. Silent for `detectSilence(d)` or longer: it logs `wireguard: relayed peer silent past the failure detection time, dialing the relay again` and dials the next relay of the set, the same relay for a set of one, on a fresh device peer, the write every [relay re-dial](#relay-liveness-probe) makes.
4. No probe sent yet, or the last one sent `detectPass(d)/2` or longer ago: it sends the probe.

The probe goes out whether or not the peer is silent, and in `plexd up` on every pass. Two nodes that both hold a value therefore count each other's probes on every pass, where a probe sent only into silence would leave one side waiting for its partner's WireGuard to answer. The half-pass gate keeps a pass that runs a few milliseconds early from skipping its probe, and holds a caller that runs passes faster than `detectPass(d)`, such as the relay integration test at 100 ms, to two probes per `detectPass(d)`. A sent probe logs nothing: under a value, neither `wireguard: relayed peer silent, probing` nor `wireguard: relayed peer did not answer the probe, dialing the relay again` is logged. A failed send logs `wireguard: relay probe send failed` as on a node without a value, at Warn the first time and at Debug while the sends keep failing. It restarts the silence window, so no verdict follows a probe that never left, and the next attempt follows on the next pass.

The silence window starts on the same events as on a node without a value, and again when the value changes. A pass counts a packet up to one pass after it arrived, and dials on the first pass at which the window is `detectSilence(d)` old. The re-dial therefore comes between `detectSilence(d)` and `d` after the last packet, and one pass later when a pass runs late. At the default 15 s that is 14 to 15 s, or up to 16 s with a late pass.

A peer that sends nothing on its own, such as a plexd on v0.37.0 or older, a node that holds no value or a plain WireGuard peer, still answers the probes. Its WireGuard answers a data packet through its keepalive timer: `timersDataReceived` arms the timer for `KeepaliveTimeout`, 10 s, the keepalive's own send deletes it through `timersAnyAuthenticatedPacketSent`, and the next probe arms it again (`device/timers.go` of `golang.zx2c4.com/wireguard`). A received packet also pushes out the peer's persistent keepalive. Its answers therefore arrive up to 10 s plus one probe interval apart: 11 s at 15 s, inside the 14 s silence, which leaves 3 s for the round trip. That is why a value of 15 s or more holds against a peer on any release. The Linux kernel module is assumed to do the same.

A value under 15 s holds only once every node of the Domain runs a release that reads the block and has pulled the value. Against a peer that sends no probes, a relayed pair under such a value re-dials a healthy relay about once per `detect_after_seconds`, each time with a new handshake. plexd does not tell an older peer apart: it runs no listener for the probe and adds no firewall exemption for one. Between two nodes that both probe, at 5 s two probes in a row can be lost before the silence reaches 4 s.

While a value is held, `RunEndpointSelection` runs its passes every `passInterval(interval)`, the shorter of `interval` and `detectPass(d)`. With no value held, `passInterval` returns `interval`. In `plexd up`, which passes `EndpointSelectionInterval`, a value gives a pass every `detectPass(d)`: 1 s at the default 15 s. The loop reads it again after every pass and resets its ticker when it changed, so a new value takes effect at most one pass of the old interval late. The trial, the relay hold, the direct retry's 10 s window and the 180 s stale-handshake age keep their lengths. They compare the clock against their windows and close on the first pass after their end, which comes sooner under a value.

A peer connected over a direct path is never watched, under any value: WireGuard's roaming owns that path, and the value governs the paths a node watches on its own, which today are its relays.

A value adds one device read per pass and one probe per pass per relayed connected peer; see [Cost](#cost).

#### Direct retry

A [relayed](#the-trial) peer stays on its relays because its direct entries, the entries of its dial order before its first relay, already failed. A direct retry (`dial.go`, `manager.go`) tries them again at two moments: when a pull adds a direct entry to the peer, and when this node's own local networks change so that one of the peer's direct entries is on-link. A handshake over a direct entry then leaves the relay. A peer is eligible while it is relayed, connected or not, and while a retry runs for it, so a relayed peer that waits for its partner loses nothing to a retry. A peer that is neither relayed nor in a retry walks its entries anyway and gets none.

```go
const directRetryTimeout = 10 * time.Second    // how long one entry is tried
const directRetryMemory = 10 * time.Minute     // how long a tried entry is remembered
const localNetworksInterval = 30 * time.Second // how often, at most, the local networks are read
```

A pull starts a retry through `UpdatePeer` (rule 2 of [Endpoint selection](#endpoint-selection)) when the update names relays and adds a new direct entry: one that is not among the direct entries of the order plexd holds for the peer, and that plexd does not remember. A pull that only removes or reorders direct entries starts none, because every entry left already failed. The retry tries every direct entry of the update that is not remembered, in the update's dial order, which the handler just built with the current local prefixes, so the on-link entries come first. `UpdatePeer` logs `wireguard: trying the direct endpoints again` with `reason=pull`.

The selection pass reads the local prefixes through the function `SetLocalPrefixes` set, after its device read and before it takes the mutex, at most once per 30 s (`localNetworksInterval`). A pass whose device read fails does not read them. The pass compares networks, not addresses: each prefix shorter than a host prefix, masked, sorted and without duplicates. A host prefix, `/32` or `/128`, makes nothing on-link and is left out, and a new address inside a known network is no change. The first successful read is the baseline and triggers nothing. A read that finds other networks than the last successful one logs `wireguard: local networks changed` at Debug with `networks`. In that pass, at the top of each eligible peer's turn, a direct entry of the peer that is on-link with the new networks, was not on-link with the old ones, and is not remembered starts a retry. The retry tries every direct entry that is not remembered, those on-link with the new networks first, each group in the order plexd holds. That is the built order, not the pull's candidate list, so a direct endpoint that is on-link moves forward with the candidates. The pass logs `wireguard: trying the direct endpoints again` with `reason=local_networks` and does nothing else for that peer in that pass.

A failed read logs `wireguard: read local networks failed` with `error`, at Warn the first time and at Debug while the reads keep failing, keeps the networks of the last successful read, and reports no change. The next read follows 30 s later. A read that succeeds ends the run of failures, and the next failure logs at Warn again. In `plexd up` the error is the one `nat.SystemInterfaces` returns, `nat: list interfaces: <cause>`.

plexd remembers a direct entry for 10 min (`directRetryMemory`) when an update drops it from the order of a relayed peer or of a peer in a retry, and when it fails a retry: its window passed without a handshake. A remembered entry starts no retry and is left out of one. The control plane leaves a peer's direct endpoint out while it has no fresh observation and lists only unexpired candidates, so without the memory every stale-and-back cycle of a peer's reports would cut its relayed pairs. The memory also keeps a second pull within 10 min from trying again what the first retry just tried. It lives in the peer's [dial state](#programmed-peers), so an update that starts the peer's walk over, a key rotation, a removal and a restart forget it.

A retry removes the device peer and adds it again with the first entry to try as its endpoint, the write a relay re-dial makes. The fresh device peer has no session, and its write turns the keepalive on, which makes WireGuard start a handshake at once. While the retry runs, the peer is neither connected nor relayed, and its position is that of the entry tried. Each entry is tried for 10 s (`directRetryTimeout`): WireGuard sends its initiation at once and repeats it after its `RekeyTimeout` of 5 s, so the window holds two initiations. The first pass at or after the end of the window remembers the entry, logs `wireguard: direct retry, trying the next endpoint` with `remaining`, and writes the next entry on a fresh device peer. A handshake that completes ends the retry, and the device endpoint decides, as for any peer that turns connected, whether the peer is relayed: connected over the direct entry, it is not, and connected over a relay, because the partner's initiation came through one, it is relayed again. When no entry answers, the pass logs `wireguard: no direct endpoint answered, dialing the relay again` and dials the relay the retry ends on, on a fresh device peer. The peer is then relayed and not connected, as after any relay re-dial, and its relay hold starts.

The relay a retry ends on is the relay the peer was on when the retry started. A pull that takes that relay away, by the test of rule 3, makes it the pull's first relay, during a retry too. A pull that takes the relay away and adds a direct entry therefore runs the retry first and ends it on the pull's first relay: the move needs a fresh device peer anyway, and the new entry would otherwise never be tried. During a retry, a pull that adds a new direct entry starts the retry over with the pull's direct entries that are not remembered, and a change of the local networks that makes one on-link starts it over with the peer's direct entries that are not remembered. The entry under trial is not remembered yet, so either way it is tried again while it is still listed. A pull that adds none goes on with the entry under trial and the entries left that the pull still lists, on a fresh device peer whose window starts over, and dials the relay at once when it lists none of them. A pull that names no relays ends the retry and starts the peer's walk over.

A retry replaces the device peer and so cuts the relayed session. Writing only the endpoint would keep the session, but WireGuard moves a peer's endpoint to the source of every authenticated packet it receives, so the partner's next packet through the relay would put the device back on the relay before the direct entry was judged. A fresh session accepts nothing the partner still sends through the relay in the old one.

On a node that holds no [failure-detection time](#failure-detection-time), with the defaults, a pass every 5 s, the first pass at or after the end of a window comes 10 to 15 s after the entry's write. A retry that fails therefore cuts the pair for 10 to 15 s per entry, about 1 min with four entries and up to 2 min 15 s with the contract's nine, eight candidates plus the direct endpoint. Under the default failure-detection time of 15 s, a pass every 1 s, it cuts the pair for 10 to 11 s per entry, 40 to 44 s with four entries and 90 to 99 s with nine. Either way the cut lasts about 5 s more while the handshake goes back over the relay, which holds back the pair's first initiation for one WireGuard retry (see [Forwarding Table](../bridge/nat-relay.md#forwarding-table)). The partner on the relay hears nothing meanwhile. It dials the next relay of its set after about 45 s when its node holds no failure-detection time (see [Relay liveness probe](#relay-liveness-probe)), and after 14 to 15 s when its node holds the default 15 s. The pair then meets again by the relay rules of [The trial](#the-trial). A peer's candidates move only the pairs that peer is part of, so a node that publishes unstable candidates cuts its own relayed pairs and no others.

No configuration key turns the retry on or off. It needs endpoint selection, so `persistent_keepalive: 0s` turns it off with everything else: no pass runs, so no peer is marked relayed, no retry starts and the local networks are never read. Nothing on the wire changes. A partner on any plexd version follows a successful retry: its WireGuard answers the initiation and roams to the direct address, and its plexd reads a device endpoint that matches no relay as not relayed.

Each write of a retry makes a new device peer, as a relay re-dial does, so the peer's handshake time and byte counters start over. The [handshake report](../core/heartbeat-service.md#handshake-reporter) leaves the peer out until its new handshake completes, and the [tunnel metrics](../observability/metrics-collection.md#tunnelcollector) count its `rx_bytes` and `tx_bytes` from 0 again.

A failed write in `UpdatePeer` returns `wireguard: update peer: <cause>`, with the cause `remove device peer: <cause>` or `add device peer: <cause>`, and leaves the state as it was. The reconciler keeps its snapshot and applies the update again on its next cycle. A retry that a change of the local networks starts and the device refuses logs `wireguard: endpoint switch failed` with the first entry as `endpoint`, joins `wireguard: switch endpoint of peer <node id>: <cause>` into the pass's error, leaves the state as it was, and goes on to the next peer. That change starts no retry again. In both cases a failed add after a successful remove leaves no device peer until the next write: the next pass finds a connected relayed peer's handshake stale and dials the next relay of its set, a relayed peer that was not connected dials it once its relay hold ends, and a peer in a retry goes on with its retry. A failed write of a later entry logs and joins the same way, and still moves the position to that entry and restarts its window, so the step after it, one window later, tries the entry after it. A failed dial of the relay at the end is a failed relay re-dial (see [The trial](#the-trial)).

#### RunEndpointSelection

```go
const EndpointSelectionInterval = 5 * time.Second

func (m *Manager) RunEndpointSelection(ctx context.Context, interval time.Duration) error
```

- With `persistent_keepalive: 0s` it logs `wireguard: endpoint selection disabled, persistent_keepalive is 0s` and returns nil at once. Every peer keeps the first entry of its dial order, so no standby relay is ever dialed, no [direct retry](#direct-retry) runs, and the local networks are never read.
- Otherwise it logs `wireguard: endpoint selection started` with `interval`, the interval it was given, `timeout` (the trial) and `relay_probe`, true when `SetRelayProbe` set a sender, and runs a pass on every tick, the first one tick after it starts.
- It ticks every `passInterval(interval)`: `interval` while no [failure-detection time](#failure-detection-time) is held, and the shorter of `interval` and `detectPass` of the value while one is. It reads that again after every pass and resets its ticker when it changed, so a new value takes effect at most one pass of the old interval late.
- A pass that returns `ErrPeerStatsUnsupported` logs `wireguard: endpoint selection unavailable, the controller cannot read peer stats` and returns nil. Peers keep the entry they have.
- Any other pass error logs `wireguard: endpoint selection pass failed` with `error`, and the next tick runs again.
- It returns nil once `ctx` is done.

`plexd up` runs it with `EndpointSelectionInterval` as step 17b, only when the WireGuard interface came up. The step first calls `SetRelayProbe(wireguard.SendRelayProbe)`, so the probe is on and the started line carries `relay_probe=true`. On the same condition `plexd up` registers `FailureDetectionDispatchHandler`, so step 17b's relay watch follows the Domain's value: a pass every 1 s at the default 15 s.

#### Cost

The keepalive sends one empty data packet (32 bytes of payload) per idle peer every 25 s and keeps a rekey handshake running about every 2 minutes per peer, so a node with 100 idle peers sends about 4 packets per second. Endpoint selection adds one device read every 5 s, on a node that holds no failure-detection time, and one interface read, of the local networks, every 30 s, the reconcile handler one interface read each time it runs, and the [candidate publisher](./nat-traversal.md#local-endpoint-candidates) one `PUT` per cycle (60 s by default). On such a node the [relay liveness probe](#relay-liveness-probe) adds at most one datagram per relayed peer that received nothing for 30 s, answered by one keepalive. A node that holds a [failure-detection time](#failure-detection-time) reads the device once per pass instead, every 1 s at the default 15 s against every 5 s, and sends one probe per pass per relayed connected peer: a 64-byte WireGuard message, 92 bytes with its UDP and IPv4 headers, about 8 MB a day per relayed peer and direction at the default, and a fifth of that from 75 s up. Each relay re-dial adds one handshake, whether it dials the same relay or the next one of the set. A [move back](#the-trial) adds at most one device write per peer per session, and a failed write is tried again on the next pass. A [direct retry](#direct-retry) adds one handshake per entry tried, and the relay re-dial that ends a failed one adds its own.

#### Endpoint selection log lines

All carry `component=wireguard`.

| Level  | Message | Keys |
|--------|---------|------|
| `Info` | `wireguard: endpoint selection started` | `interval`, `timeout`, `relay_probe` (true when `SetRelayProbe` set a sender) |
| `Info` | `wireguard: endpoint selection disabled, persistent_keepalive is 0s` | none |
| `Info` | `wireguard: endpoint selection unavailable, the controller cannot read peer stats` | none |
| `Info` | `wireguard: failure detection time set` | `detect_after` (the value now in force), `previous` (the value before, `0s` when none was held), `pass` (`detectPass` of the value, such as `1s`). Logged by `SetFailureDetection` when the value changes |
| `Warn` | `wireguard: failure detection block malformed` | `error`. Logged by `FailureDetectionDispatchHandler`, once until a block decodes again |
| `Warn` | `wireguard: failure detection time out of range` | `detect_after_seconds` (the value the pull carried), `applied` (the bound applied, only for a value from 1 to 4 or above 180). Logged by `FailureDetectionDispatchHandler`, once per run of the same raw value |
| `Info` | `wireguard: endpoint selected` | `peer_id`, `endpoint` (empty when the device reports none), `relayed` (true when the peer connected over one of its relays, which may be a relay other than the one programmed) |
| `Info` | `wireguard: peer handshake went stale, resuming endpoint selection` | `peer_id` |
| `Info` | `wireguard: trying next endpoint candidate` | `peer_id`, `endpoint`, `attempt` (the entry's 1-based position), `of` (the number of entries the walk cycles through: the order up to and including its first relay, or the whole order for a peer without relays), `trial` (how long the entry just programmed is tried, such as `30s`, or `1m0s` for a first relay that follows two entries) |
| `Info` | `wireguard: relay fallback changed, moving to the new relay` | `peer_id`, `from` (the relay programmed, which may be a standby), `to` (the update's first relay). Logged by `UpdatePeer` |
| `Debug` | `wireguard: relayed peer silent, probing` | `peer_id`, `mesh_ip`, `silent_for` (the time since the silence window started, such as `30s`; after a failed send it counts from that send). Only a node that holds no [failure-detection time](#failure-detection-time) logs it |
| `Warn`, `Debug` | `wireguard: relay probe send failed` | `peer_id`, `mesh_ip`, `error`. `Warn` for the first failure, `Debug` while the sends keep failing |
| `Info` | `wireguard: relayed peer did not answer the probe, dialing the relay again` | `peer_id`, `from` (the relay the peer was on), `endpoint` (the relay dialed, the next of the set; the same relay for a set of one), `silent_for` (the time since the silence window started, such as `45s`). Only a node that holds no failure-detection time logs it |
| `Info` | `wireguard: relayed peer silent past the failure detection time, dialing the relay again` | `peer_id`, `from` (the relay the peer was on), `endpoint` (the relay dialed, the next of the set; the same relay for a set of one), `silent_for` (the time since the silence window started), `detect_after` (the value held). Only a node that holds a failure-detection time logs it |
| `Info` | `wireguard: relayed peer handshake went stale, dialing the relay again` | `peer_id`, `from` (the relay the peer was on), `endpoint` (the relay dialed, the next of the set; the same relay for a set of one) |
| `Info` | `wireguard: still no handshake over the relay, dialing it again` | `peer_id`, `from` (the relay the peer was on), `endpoint` (the relay dialed, the next of the set; the same relay for a set of one), `trial` (the relay hold, such as `30s`) |
| `Info` | `wireguard: relayed peer roamed to a relay its session does not run over, moving it back` | `peer_id`, `from` (the relay the device roamed to), `endpoint` (the entry programmed, which the pass writes back) |
| `Info` | `wireguard: trying the direct endpoints again` | `peer_id`, `reason` (`pull` when `UpdatePeer` started the [direct retry](#direct-retry), `local_networks` when a pass did), `endpoint` (the first entry tried), `entries` (the number of entries the retry tries), `relay` (the relay it dials when no entry answers) |
| `Info` | `wireguard: direct retry, trying the next endpoint` | `peer_id`, `endpoint` (the entry written), `remaining` (the entries left after it) |
| `Info` | `wireguard: no direct endpoint answered, dialing the relay again` | `peer_id`, `endpoint` (the relay dialed, the one the retry ends on). Logged by a pass after the last entry's window, and by `UpdatePeer` when an update leaves a running retry no entry |
| `Debug` | `wireguard: local networks changed` | `networks` (the networks of the new read, such as `[10.0.0.0/24]`) |
| `Warn`, `Debug` | `wireguard: read local networks failed` | `error`. `Warn` for the first failure, `Debug` while the reads keep failing |
| `Warn` | `wireguard: endpoint switch failed` | `peer_id`, `endpoint` (the entry it tried to program, the relay it tried to dial for a failed relay re-dial, the entry it tried to write for a failed write of a direct retry), `error` |
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

// Take the Domain's failure-detection time from every pull; it tunes the
// relay watch of endpoint selection
r.RegisterDispatchHandler(wireguard.FailureDetectionDispatchHandler(mgr))

// Peers come from the state pull, not from the registration response:
// the reconcile handler adds, updates and removes them (see ReconcileHandler).
r.RegisterHandler(wireguard.ReconcileHandler(mgr, psks))

// Probe relayed peers, then try each peer's dial order every 5 seconds,
// or every pass of the failure-detection time (blocks until ctx is done)
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
2. `CreateInterface(name, privateKey, listenPort)` — create WireGuard interface with node's private key. On Linux the kernel keeps a WireGuard link when the process that made it ends without its teardown, as a killed or crashed plexd does. `NetlinkController` therefore deletes a WireGuard link that already holds the name, with its addresses, routes and peers, creates the interface afresh and logs it at `warn`. A link of another type that holds the name fails the create with `wireguard: create interface: file exists: a <type> link holds the name <name>`
3. `ConfigureAddress(name, meshIP+"/<prefix>")` — assign the mesh IP. The prefix length comes from the registration `domain_mesh_cidr`, so the kernel installs an on-link route for the whole mesh (which the snapshot peers, whose allowed IPs start with `mesh_ip/32`, rely on). Identities without the field, or with an unparseable value, fall back to a host `/32` (the unparseable case is logged as a warning). On macOS the on-link route is not implicit and `DarwinController` installs it explicitly (see [macOS controller](#macos-controller))
4. `SetMTU(name, mtu)` — only if `Config.MTU > 0` or the chosen MTU is not 1420, the MTU every controller creates the device with
5. `SetInterfaceUp(name)` — bring the interface up
6. Record the address's masked prefix as the [mesh prefix](#mesh-prefix)

### Error Handling

| Method            | Individual Peer Failure          | Context Cancellation       |
|-------------------|----------------------------------|----------------------------|
| `AddPeer`         | Returns error                    | —                          |
| `RemovePeerByID`  | Returns error                    | —                          |
| `UpdatePeer`      | Returns `wireguard: update peer: <cause>` and leaves the state as it was. A failed move to a new relay or a failed write of a [direct retry](#direct-retry) names `remove device peer` or `add device peer`, and the reconciler retries it on its next cycle | — |
| `ConfigurePeers`  | Logged at error, continues       | Returns context error      |
| `SetPeerPSK`      | Returns `wireguard: set peer psk: <cause>` | —                |
| `RunEndpointSelection` | A failed switch or relay re-dial is logged at warn and the pass goes on; the next re-dial, one relay hold later, dials the relay after the one that failed. A failed move back is logged at warn too, and the next pass tries the same relay again. A failed write of a [direct retry](#direct-retry)'s entry is logged at warn: the next step, one window later, tries the entry after it, and a retry that a change of the local networks starts is not tried again for that change. A failed probe send is logged at warn, then at debug while it keeps failing, and takes no verdict: the next probe follows one trial later, or on the next pass under a [failure-detection time](#failure-detection-time). A failed read of the local networks is logged at warn, then at debug while it keeps failing, and the next read follows 30 s later | Returns nil |
| `RunMTUProbe`     | A failed probe or `SetMTU` is logged at warn. The next round probes again and retries a failed lowering; a failed raise starts the two-round wait over | Returns nil |

### Logging

All log entries use `component=wireguard`. Private keys and PSKs are never logged.

| Level   | Event                        | Keys                                  |
|---------|------------------------------|---------------------------------------|
| `Info`  | Interface configured         | `interface`, `listen_port`, `mesh_ip`, `mtu`, `mtu_source`, `path_mtu` (only with `mtu_source=probe`) |
| `Warn`  | Linux only: a WireGuard link an earlier process left behind was replaced (`wireguard: replaced an interface an earlier process left behind`) | `interface` |
| `Info`  | Peers configured (bulk)      | `count`                               |
| `Debug` | Peer added/removed/updated   | `peer_id`                             |
| `Debug` | Peer PSK set (`peer psk set`) | `peer_id`                            |
| `Error` | Peer operation failed (bulk) | `peer_id`, `error`                    |

Endpoint selection writes the lines in [Endpoint selection log lines](#endpoint-selection-log-lines), MTU detection the lines in [MTU detection log lines](#mtu-detection-log-lines), and the reconcile handler the dial order lines in [Dial order](#dial-order) and the peer route lines in [Routed subnets](#routed-subnets). `FailureDetectionDispatchHandler` and `SetFailureDetection` write the failure-detection lines in [Endpoint selection log lines](#endpoint-selection-log-lines).

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

1. **Removes** — `diff.PeersToRemove` (node IDs) via `RemovePeerByID`; a node ID the peer index no longer holds is already gone and is skipped, because a failed cycle hands the same removal over again on the next tick
2. **Updates** — `diff.PeersToUpdate` via `UpdatePeer`
3. **Adds** — `diff.PeersToAdd` via `AddPeer`
4. **Peer routes** — `syncPeerRoutes` routes the routed subnets of the peers now on the device through the mesh interface and removes the routes no peer lists any more (see [Routed subnets](#routed-subnets))

Adds and updates carry `api.SnapshotPeer` entries, converted to the WireGuard `api.Peer` by `peerFromSnapshot(p, order, fallbacks, psk, routed)`, where `order` is the peer's [dial order](#dial-order), `fallbacks` its last `relays` entries, the relays that end it, and `routed` the entries of its `routed_subnets` that [`usableRoutedSubnets`](#routed-subnets) accepts:

- `AllowedIPs` is derived locally as `mesh_ip/32` followed by `routed`, in the list's order. The snapshot never sends allowed IPs. A `mesh_ip` that is not a bare IPv4 address fails the peer. `RoutedSubnets` carries `routed`, and is nil when it is empty.
- `Endpoints` is the dial order and `Endpoint` its first entry, empty for an empty order. The manager programs the first entry and [endpoint selection](#endpoint-selection) moves along the order until a handshake completes. See [Dial order](#dial-order).
- `Fallbacks` is the peer's relay set as it ends the order, in dial order, and nil for a peer without a relay. A candidate or direct endpoint equal to a relay is left out of the entries before the relays, so a relay it repeats is still in `Fallbacks`. [Endpoint selection](#the-trial) holds these entries longer and moves a relayed peer along them.
- `PSK` is the key `psks.Lookup` returns for the peer's node ID and current `public_key`, base64-encoded. A PSK fetched for another public key is never returned, so a peer whose key changed gets no PSK until the store holds one for the new key. With no PSK the field stays empty, and the store writes the PSK through [`SetPeerPSK`](#installing-a-psk) once it arrives.

Individual failures are logged and collected. The handler returns an aggregated error via `errors.Join` (nil if all succeed). This ensures the reconciler marks the cycle as failed and retries on the next tick.

### Dial order

```go
func dialOrder(p api.SnapshotPeer, local []netip.Prefix, mesh netip.Prefix) (order []string, relays, dropped int)
func ProgrammedEndpoint(p api.SnapshotPeer, mesh netip.Prefix) (endpoint string, directRejected bool)
```

The handler reads this host's interface prefixes, through the function [`SetLocalPrefixes`](#methods) set, and `MeshPrefix()` once per call. The selection pass reads the local prefixes too, at most once per 30 s, to start a [direct retry](#direct-retry) when a local network makes a relayed peer's direct entry on-link. For each peer the handler adds or updates, `dialOrder` builds the order in which [endpoint selection](#endpoint-selection) tries the peer's endpoints:

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

The differ compares `endpoint`, `fallback_endpoint`, `fallback_endpoints`, `endpoint_candidates` and `routed_subnets`, the relays, the candidates and the routed subnets in order, so a peer whose direct endpoint, relays, candidates or routed subnets appear, change, reorder or disappear lands in `PeersToUpdate` and is written again. A change of only a standby relay, or of the relays' order, updates the peer too. A missing and an empty `fallback_endpoints`, `endpoint_candidates` or `routed_subnets` compare equal.

### Routed subnets

```go
type PeerRouter interface {
    AddRoute(subnet, iface string) error
    RemoveRoute(subnet, iface string) error
}

func (m *Manager) SetPeerRouter(r PeerRouter)
func usableRoutedSubnets(subnets []string, mesh netip.Prefix, local []netip.Prefix) (accepted []string, skipped []skippedSubnet)
```

A peer's `routed_subnets` lists the IPv4 networks the control plane routes through it: the networks behind the site-to-site tunnels of a peer that is a bridge, the union of their `allowed_subnets`, each prefix once. The control plane delivers the member only to the nodes of the bridge Resource's Project, and the registration response never carries it, so a node programs the subnets from its first pull. See [Site-to-Site VPN](../bridge/site-to-site-vpn.md) for the tunnels behind them.

For each peer it adds or updates, the handler splits the list with `usableRoutedSubnets`, against the mesh prefix and the local prefixes it reads for the [dial order](#dial-order). The peer's allowed IPs are its mesh address as a `/32` followed by the accepted subnets, in the list's order and in canonical form. The first rule that applies skips an entry:

| Reason | The entry |
|---|---|
| `invalid` | does not parse with `netip.ParsePrefix`, is not IPv4, or has host bits set, such as `10.20.0.1/16`, `fd00::/64` or `not-a-prefix` |
| `overlaps_mesh` | overlaps the [mesh prefix](#mesh-prefix), such as `10.99.0.0/25` in the mesh `10.99.0.0/24`; `0.0.0.0/0` overlaps every mesh |
| `inside_local_network` | lies inside a local prefix: one of the prefixes the handler orders endpoint candidates by contains its address and is no longer than it. On a host in `192.168.1.0/24`, `192.168.1.0/24` and `192.168.1.128/25` are skipped, and `192.168.0.0/16` is accepted |
| `duplicate` | repeats an earlier entry of the list |

The first two would let the peer's key send from addresses past the networks behind it, because the allowed IPs are WireGuard's authorization of a peer's source addresses. The third would route this host's own network, its gateway included, into the mesh. The local prefixes are those of `nat.EligiblePrefixes` (see below): they leave out loopback and point-to-point interfaces, container, VPN and other virtual interfaces, and every interface outside `nat.candidate_interfaces` when that list is set, so a network of such an interface is not protected and a routed subnet inside it is programmed. The contract has a node add a peer's `routed_subnets` as they are; plexd deviates from it in these three cases. When the local prefixes cannot be read, no entry is skipped as `inside_local_network`. Each skipped entry is logged at Warn whenever the handler adds or updates the peer:

```
wireguard: routed subnet not programmed  component=wireguard peer_id=<node id> subnet=10.20.0.1/16 reason=invalid
```

The handler ends with `syncPeerRoutes`, which brings the routes on the mesh interface in line with the [programmed peers](#programmed-peers), the peers the manager last wrote. The wanted set is the union of their `RoutedSubnets`. It removes the route of every subnet it programmed that no such peer lists any more, then adds a route for every wanted subnet that has none, in subnet order, each through the `PeerRouter` on `OSInterfaceName()`, the name the operating system knows the mesh interface by (`utunN` on macOS). A subnet two peers list is routed once and keeps its route until the last of them drops it. plexd does not arbitrate between two peers that list the same subnet: the control plane refuses a second tunnel of a Project to an overlapping subnet, and the device gives an equal prefix to the peer written last. A peer the handler removes, or whose update drops the member, loses its routes in the same run, and `SetPeerPSK` writes a peer's routed subnets again with its PSK, since every device write replaces the allowed IPs. A run that changed a route logs the change once at Info:

```
wireguard: peer routes changed  component=wireguard added=[10.20.0.0/16] removed=[]
```

A route call that fails is logged at Error and leaves that subnet's state as it was, so the next run tries it again. The handler returns the failure joined with its others, so the reconciler applies the snapshot again:

```
wireguard: peer route failed  component=wireguard subnet=10.20.0.0/16 op=add error=<cause>
```

The route calls run under a mutex of their own, never under the one that serializes peer writes, so a slow `route(8)` or IP Helper call holds up no peer write and no pass of endpoint selection.

Every `bridge.RouteController` satisfies `PeerRouter`: `NetlinkRouteController` on Linux (see [Netlink Route Controller](../bridge/netlink-route-controller.md)), and `DarwinRouteController` and `WindowsRouteController` on macOS and Windows (see [Route Controllers on macOS and Windows](../bridge/route-controllers-macos-windows.md)). Both calls are idempotent: adding a route that exists and removing one that does not return nil. `plexd up` builds the route controller once, after the firewall controller and before the bridge subsystem (step 5e), and hands it to `SetPeerRouter` when the WireGuard interface came up; in bridge mode the bridge manager drives the same instance. Every node routes the networks behind a peer that way, on Linux, macOS and Windows, whether or not it runs in bridge mode. A manager without a router, on a platform without a route controller, programs the routed subnets as allowed IPs and adds no route.

`Teardown` removes the routes it programmed before it deletes the interface. A route it cannot remove is logged at Warn as `wireguard: peer route failed` and stops nothing, since the delete takes the interface's routes with it, and the routes it removed are logged as `wireguard: peer routes changed` with `removed`.

A route admits no traffic by itself. The node's [policy](./network-policy.md) filters what it sends into the mesh, and the control plane compiles a rule to a network behind a bridge with that network as `destination_cidr`. plexd does not guard against a routed subnet that holds the control plane's address or a peer's endpoint: it cannot tell which addresses the host must reach outside the mesh, and the control plane refuses the overlaps it can see.

The [Docker e2e test](../development/docker-e2e-test.md) proves the routes on Linux with traffic, and `TestPeerRoutes_RealUTUN` and `TestPeerRoutes_RealWintun` read the allowed IPs, through `PeerStat.AllowedIPs`, and the route on macOS and Windows on the CI runners, without traffic (see [CI Workflow](../development/ci-workflow.md)).

### Registration

```go
mgr := wireguard.NewManager(ctrl, wireguard.Config{}, logger)
psks := wireguard.NewEdgePSKs(client, identity.NodeID, nsk, mgr, logger)

r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterDispatchHandler(wireguard.EdgePSKDispatchHandler(psks))
r.RegisterDispatchHandler(wireguard.FailureDetectionDispatchHandler(mgr))
r.RegisterHandler(wireguard.ReconcileHandler(mgr, psks))
```

Without edge PSKs, pass a nil `EdgePSKLookup` interface value, as `plexd up` does. A nil `*EdgePSKs` stored in the interface is not nil to the handler, and its `Lookup` panics.

`plexd up` calls `mgr.SetLocalPrefixes` in step 5a-2, before the handler first runs and before endpoint selection starts in step 17b, with a function that returns `nat.EligiblePrefixes` over `nat.SystemInterfaces()` and passes a read error through. Without that call the handler orders every candidate as off-link and skips no routed subnet as `inside_local_network`, and no change of the local networks starts a [direct retry](#direct-retry). It calls `mgr.SetPeerRouter` with the route controller before that, right after `Setup` (see [Routed subnets](#routed-subnets)).

The agent registers this handler **only when WireGuard `Setup` succeeded**. On hosts without a programmable WireGuard stack the interface fails to come up, the agent continues without WireGuard, and the peer reconcile handler is skipped — a handler that failed every cycle would hold the reconciler snapshot back and prevent convergence (for example, the policy fingerprint short-circuit could never hold).

## Peer Programming

There are no WireGuard-specific SSE handlers. Peers are programmed from the
authoritative state snapshot, not from fine-grained events. The peer topology
events (`peer_registered`, `peer_psk_assigned`, `peer_deregistered`,
`peer_endpoint_changed`, `peer_key_rotated`) dispatch to `TriggerReconcile()`, and
plexd never decodes their payloads. The reconcile loop then pulls the snapshot, the
[edge PSK store](#edge-psks) (when edge PSKs are on) syncs against its peers, and
`ReconcileHandler` (see above) converges the interface.

`peerFromSnapshot(p api.SnapshotPeer, order, fallbacks []string, psk []byte, routed []string) (api.Peer, error)`
builds each programmed peer from a snapshot entry: `AllowedIPs` derived locally as
`mesh_ip/32` followed by `routed`, the [routed subnets](#routed-subnets) the node
accepted, `Endpoints` set to the [dial order](#dial-order) and `Endpoint` to its
first entry, `Fallbacks` set to `fallbacks`, the relays that end the order, and
`psk` base64-encoded (none for a nil `psk`). The manager then adds,
updates, or removes peers so the interface matches the desired set, routes the
accepted subnets through the mesh interface, and
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

After registration, `Setup` takes the identity. The `peer_snapshot` of the registration response is not programmed: the reconcile handler programs the peers from the `peers` block of the state pull.

```go
identity, _ := reg.Register(ctx)
mgr.Setup(ctx, identity)
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

Call `Teardown()` on context cancellation to remove the peer routes and the WireGuard interface:

```go
<-ctx.Done()
if err := mgr.Teardown(); err != nil {
    logger.Warn("wireguard teardown failed", "error", err)
}
```
