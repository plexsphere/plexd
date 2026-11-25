---
title: macOS & Windows Route Controllers
package: internal/bridge
---

# macOS & Windows Route Controllers

`DarwinRouteController` (`route_darwin.go`) and `WindowsRouteController` (`route_windows.go`) are the non-Linux implementations of the `RouteController` interface defined in `internal/bridge`. macOS programs routes with `route(8)` and IPv4 forwarding with `sysctl(8)`; Windows programs both through the IP Helper API via the `winipcfg` package. The macOS controller requires root, the Windows controller Administrator, which the LocalSystem service satisfies.

The Linux implementation is [`NetlinkRouteController`](./netlink-route-controller.md).

## Architecture

![The Bridge Manager, in bridge mode only, for the access routes, forwarding and NAT, and wireguard.Manager, for the peer routes on every node through utunN on macOS, each call DarwinRouteController or WindowsRouteController over one bus. The user access and site-to-site managers, in bridge mode, sit below that bus and call both route controllers for forwarding and the routes of their providers and tunnels, PFController for the mesh source rewrite on macOS, wireguard.MeshRewriter for the rewrite on Windows, and WFPController for the NAT exemption of a tunnel on Windows. DarwinRouteController runs route(8) and sysctl(8) and delegates NAT to PFController. WindowsRouteController uses winipcfg and delegates NAT to WFPController.](../../diagrams/bridge-route-controllers-macos-windows.svg)

`plexd up` builds the controller on every node, in bridge mode or not, and hands it to the WireGuard manager, which routes the `routed_subnets` of each peer through the mesh interface with `AddRoute` and `RemoveRoute` (see [Routed subnets](../networking/wireguard.md#routed-subnets)). In bridge mode the bridge manager uses the same instance for the access subnets, forwarding and NAT.

The user access and site-to-site managers hold the route controller too. On macOS and Windows each provider's interface and each tunnel's link claims a forwarding pair, and a tunnel's `allowed_subnets` are routed over its link, on macOS under the kernel's `utunN` name and on Windows under the adapter's configured name. The source rewrite of what they forward into the mesh is no route controller's: on macOS it is `PFController`'s (see [Mesh source rewrite](../networking/pf-wfp-firewall.md#mesh-source-rewrite)), and on Windows it is `wireguard.MeshRewriter`'s, which rewrites inside the plexd process between its own wireguard-go devices (see [In-process mesh source rewrite](../networking/wireguard.md#in-process-mesh-source-rewrite)). On Windows the site-to-site manager also has `WFPController` exempt each tunnel's adapter from the bridge NAT (see [Site-to-Site VPN](site-to-site-vpn.md#routes-and-policy)).

A state pull can move the bridge to another mesh address (see [Mesh address changes](../networking/wireguard.md#mesh-address-changes)). Neither route controller holds the address. pf's rewrite on macOS names the mesh utun in its `-> (<mesh>)` form and takes the address the utun carries. `wireguard.MeshRewriter` reads the address once, when a rewrite is added, so `plexd up` calls `MeshRewriter.SetMeshAddress(meshIface string, addr netip.Addr)` once the mesh adapter carries the new address: every rewrite into the mesh adapter takes the new address, and every flow translated to another one is removed, so the far end's next packet opens a flow on the new address (see [Following a new mesh address](../networking/wireguard.md#following-a-new-mesh-address)). After the move the WireGuard manager adds each peer route again through the route controller, whose `AddRoute` is idempotent, so a route that survived the move costs one call.

## Constructors

```go
func NewDarwinRouteController(logger *slog.Logger, nat NATController) *DarwinRouteController
func NewWindowsRouteController(logger *slog.Logger, nat NATController) *WindowsRouteController
```

Logger entries use `component=bridge`.

## NAT

`RouteController` embeds a `NATController`:

```go
type NATController interface {
    AddNATMasquerade(iface string) error
    RemoveNATMasquerade(iface string) error
}
```

`NetlinkRouteController` implements it itself through nftables. On macOS and Windows the masquerade belongs to pf and to WinNAT, which the firewall controller owns, so both constructors take a backend to delegate to. `cmd/plexd/cmd/up_darwin.go` and `up_windows.go` build one `PFController` or `WFPController` and hand the same instance to the policy enforcer and to the route controller; see [pf & WFP Firewall Controllers](../networking/pf-wfp-firewall.md#nat). On Windows the same instance is also the site-to-site manager's `bridge.NATExempter`, through `newNATExempter`, so the bridge NAT's object and the exemptions of tunnels come from one controller (see [The NAT exemption of a tunnel](../networking/pf-wfp-firewall.md#the-nat-exemption-of-a-tunnel)).

A controller built without a backend, which is what the tests do, still fails on `AddNATMasquerade`:

```
bridge: add NAT masquerade on "en1": NAT masquerade is not available on this
platform; set bridge.enable_nat: false to run the bridge without NAT
```

The error wraps `bridge.ErrNATUnavailable`. Failing is deliberate: a gateway that came up logging `nat=true` without a masquerade would forward mesh traffic with mesh source addresses, and the return path would disappear silently.

`RemoveNATMasquerade` returns `nil` with no backend. Nothing could have been added, and the interface documents removal as idempotent.

## Forwarding

Only IPv4 is toggled, matching Linux. The mesh is IPv4, and on macOS the IPv6 knob is global as well, so setting it would make the host route IPv6 between every interface it has. An IPv6 subnet in `access_subnets` still gets its route.

| Platform | Mechanism |
|----------|-----------|
| macOS   | `sysctl -n net.inet.ip.forwarding` to read, `sysctl -w net.inet.ip.forwarding=1` to write. One global knob. |
| Windows | `MibIPInterfaceRow.ForwardingEnabled` for `AF_INET`, read with `GetIpInterfaceEntry` and written with `SetIpInterfaceEntry`. One flag per interface. This is what `netsh interface ipv4 set interface <name> forwarding=enabled` sets, so no registry value and no reboot are involved. |

### The ledger

Linux writes a per-interface sysctl and every manager writes its own, so `NetlinkRouteController` keeps no state. The other two platforms share a knob: macOS has exactly one, and on Windows the mesh adapter's flag is claimed by every pair that names the mesh adapter. Without bookkeeping, releasing one pair would switch forwarding off under another. On macOS the user access and site-to-site managers claim the knob too, one pair per provider or tunnel, and give each pair back when its provider or tunnel goes down, when a bring-up fails after its forwarding was switched on, and at teardown, which `plexd up` runs before the bridge manager's. The knob is therefore restored once the bridge manager releases its own pair, and `net.inet.ip.forwarding` is back at what the host had after plexd stops. On Windows the user access and site-to-site managers claim a pair per provider or tunnel too and give none back, since `forwardingKnobIsShared` is `false` there: a provider's or a tunnel's adapter goes with its provider or tunnel and the mesh adapter with the process, and a release after the adapter is gone would fail on its LUID. The access interface's flag is held by the bridge manager alone and comes back when it lets go. A vendor client's adapter keeps the flag plexd set, as `tailscale0` does on Linux. The WireGuard manager adds routes and switches no forwarding.

Both controllers track holders in a `forwardingLedger`, keyed by the knob:

- The first `EnableForwarding` for a knob reads the current value and saves it. Later callers only re-assert the value; they never overwrite what the first one found.
- `DisableForwarding` writes the saved value back only when the last holder releases the knob. While another pair holds it, nothing is written.
- A pair that never enabled forwarding writes nothing, and a failed enable records no holder, so the matching disable is a no-op.

The value that comes back is the one the host had before plexd started, so a host that already forwarded still forwards after plexd stops.

## Routes

| Platform | Add | Remove |
|----------|-----|--------|
| macOS   | `route -n add {-inet\|-inet6} <prefix> -interface <iface>` | `route -n delete {-inet\|-inet6} <prefix>` |
| Windows | `CreateIpForwardEntry2` with metric 0 and an unspecified next hop | `DeleteIpForwardEntry2` |

The subnet is masked before use, so `10.1.0.5/24` programs `10.1.0.0/24`.

The macOS delete names the destination alone. The kernel matches a delete on destination and mask, and an `-interface` argument would only make teardown fail once the interface itself is gone. `wg-quick` deletes the same way on this platform.

An unspecified next hop (`0.0.0.0` or `::`) with metric 0 is how Windows expresses an on-link route, the equivalent of the link-scoped route netlink installs on Linux. It is the same next hop wireguard-windows uses for its own routes.

### Idempotency

| Operation | Duplicate condition | macOS | Windows |
|-----------|---------------------|-------|---------|
| `AddRoute`    | This interface already carries the route | `File exists` in the output, and `route -n get` names the same interface | `ERROR_OBJECT_ALREADY_EXISTS` |
| `RemoveRoute` | Route not found      | `not in table` in the output | `ERROR_NOT_FOUND` |

Both are reported as success, which is the idempotency `NetlinkRouteController` grants through `EEXIST` and `ESRCH`.

On macOS the duplicate is only idempotent when this interface holds the prefix. `File exists` names neither the prefix's owner nor a next hop, and `RemoveRoute` names the destination alone, so accepting a prefix another interface routes would let one tunnel delete another tunnel's route while both are still reported as carried. The controller therefore runs `route -n get <family> <prefix>` and compares the `interface:` line with the interface the add named; anything else fails with `the prefix is already routed via "<other>"`.

macOS `route(8)` exits 0 on a routing-socket error and reports the failure only in its output, so the controller reads that output whatever the exit status is. `File exists` on an add and `not in table` on a delete are success; any other line carrying `writing to routing socket:` is a failure, reported with the command line and the message `route(8)` printed. A utun that carries no IPv4 address answers `Network is unreachable`. The mesh utun carries the node's mesh IP, so the peer routes install over it, which `TestPeerRoutes_RealUTUN` proves. For the same reason `plexd up` builds the site-to-site controller with the node's mesh IP as a `/32`, which the utun of every `wireguard` tunnel carries; see [Site-to-Site VPN](./site-to-site-vpn.md#vpncontroller) and [A New Mesh Address](./site-to-site-vpn.md#a-new-mesh-address).

## Interface Names

Neither controller maps names. Each passes what it is given straight to the platform, so `bridge.access_interface` must carry the name the platform knows:

| Platform | Name | Example |
|----------|------|---------|
| Linux   | Kernel interface name | `eth1` |
| macOS   | Kernel interface name | `en1` |
| Windows | The adapter's friendly name, as `Get-NetAdapter` lists it | `Ethernet` |

On Windows, `net.InterfaceByName` resolves the friendly name and `ConvertInterfaceIndexToLuid` turns it into the LUID the IP Helper API addresses. A Wintun adapter is created under the configured interface name, so `plexd0` resolves without a mapping; see [Windows controller](../networking/wireguard.md#windows-controller).

macOS is the platform where this matters most. The kernel names a tunnel device `utunN`, not `plexd0`, so a caller routing over a WireGuard interface has to resolve the kernel name first and hand that in. The bridge manager routes over `access_interface`, which is already a kernel name. The WireGuard manager adds each peer route on `Manager.OSInterfaceName()`, which is the mesh device's `utunN` on macOS and the configured name on Windows; see [The utunN name](../networking/wireguard.md#the-utunn-name). The user access and site-to-site managers do the same on macOS: they read the `utunN` behind a provider's or a tunnel's configured name from `WGAccessController.OSInterfaceName` and `WGVPNController.OSInterfaceName` when the interface exists, and hand it to forwarding, the routes and the rewrite. The `utun device created` line at `Info` maps the two names. On Windows they hand over the configured names, which the adapters carry.

The mesh interface name reaches only `EnableForwarding` and `DisableForwarding`. macOS logs it and programs the global sysctl; Windows resolves it and programs its flag. The user access and site-to-site managers hand it the mesh device's `utunN` on macOS and `plexd0` on Windows, from `Manager.OSInterfaceName()`.

## Error Prefixes

| Method | Prefix |
|--------|--------|
| `EnableForwarding`    | `bridge: enable forwarding:` |
| `DisableForwarding`   | `bridge: disable forwarding:` |
| `AddRoute`            | `bridge: add route:` for parse and lookup failures, `bridge: add route "<subnet>" via "<iface>":` for the operation |
| `RemoveRoute`         | `bridge: remove route:` and `bridge: remove route "<subnet>" via "<iface>":` |
| `AddNATMasquerade`    | `bridge: add NAT masquerade on "<iface>":` |

These match the Linux prefixes, so a log line reads the same on every platform.

A privilege failure carries a hint, because the tool's own message does not say what to change. macOS appends `(bridge mode on macOS requires root)` when the output holds `must be root` or `Operation not permitted`; Windows appends `(bridge mode on Windows requires Administrator)` on `ERROR_ACCESS_DENIED`. A macOS failure also carries the command line and the tool's own output, since `exit status 1` alone is not actionable:

```
bridge: add route "10.1.0.0/24" via "en99": /sbin/route -n add -inet 10.1.0.0/24 -interface en99: exit status 68: route: bad address: en99
```

A refusal `route(8)` wrote to its output while exiting 0 takes the same form without the exit status, the message being what followed `writing to routing socket:`:

```
bridge: add route "10.1.0.0/24" via "utun9": /sbin/route -n add -inet 10.1.0.0/24 -interface utun9: Network is unreachable
```

The delete names the destination alone, so its form is `bridge: remove route "<subnet>" via "<iface>": /sbin/route -n delete -inet <subnet>: <message>`.

Every `route` and `sysctl` invocation runs under a 10 second timeout, so a wedged host cannot stall bridge setup.

## Logging

All entries are at `Debug` with `component=bridge`.

| Message | Keys |
|---------|------|
| `route added`, `route removed` | `subnet`, `interface` |
| `route already exists, idempotent success` | `subnet`, `interface` |
| `route not found, idempotent success` | `subnet`, `interface` |
| `IP forwarding enabled` | `mesh_iface`, `access_iface` |
| `IP forwarding restored` (macOS) | `mesh_iface`, `access_iface`, `value` |
| `IP forwarding disabled` (Windows) | `mesh_iface`, `access_iface`, `restored` |
| `IP forwarding left as is` (macOS) | `mesh_iface`, `access_iface`, `held` |
| `NAT masquerade backend absent, nothing to remove` | `interface` |

## Tests

Both controllers reach the operating system through a seam, so every argument list and every idempotent case is exercised on an ordinary unprivileged runner: macOS through the package's `CommandExecutor` and its recording mock, Windows through the `ipRouter` interface and a fake. The macOS cases cover the outputs that arrive with exit status 0 (`Network is unreachable`, `File exists`, `not in table`, `Permission denied`), the `route get` answers the ownership check reads (the same interface, another interface, no `interface:` line, a failed `get`), and the two helpers that parse them, `routeSocketError` and `routeInterface`. `vpn_controller_wg_test.go` covers the kernel-name mapping of `WGVPNController` with a controller that maps `wg-s2s-0` to `utun9`, and the package `wireguard` pins with fakes which route calls the WireGuard manager makes for the peer routes.

Seven tests drive the real kernel and are gated:

| Test | Gate | Locally |
|------|------|---------|
| `TestDarwinRouteController_Real` | `os.Geteuid() == 0` | `sudo go test -run TestDarwinRouteController_Real ./internal/bridge/` |
| `TestWindowsRouteController_Real` | `PLEXD_TEST_REAL_ROUTES=1` and an elevated token | `$env:PLEXD_TEST_REAL_ROUTES='1'; go test -run TestWindowsRouteController_Real ./internal/bridge/` from an elevated shell |
| `TestWGControllers_RealUTUN` | `os.Geteuid() == 0` | `sudo go test -run TestWGControllers_RealUTUN ./internal/bridge/` |
| `TestWGControllers_RealWintun` | `PLEXD_TEST_REAL_WINTUN=1` and an elevated token | `$env:PLEXD_TEST_REAL_WINTUN='1'; go test -run TestWGControllers_RealWintun ./internal/bridge/` from an elevated shell |
| `TestPeerRoutes_RealUTUN` | `os.Geteuid() == 0` | `sudo go test -run TestPeerRoutes_RealUTUN ./internal/bridge/` |
| `TestPeerRoutes_RealWintun` | `PLEXD_TEST_REAL_WINTUN=1`, `PLEXD_TEST_REAL_ROUTES=1` and an elevated token | `$env:PLEXD_TEST_REAL_WINTUN='1'; $env:PLEXD_TEST_REAL_ROUTES='1'; go test -run TestPeerRoutes_RealWintun ./internal/bridge/` from an elevated shell |
| `TestPeerRoutes_RealWintunAtReservedUDPPorts` | `PLEXD_TEST_REAL_PORT_RESERVATION=1`, `PLEXD_TEST_REAL_WINTUN=1`, `PLEXD_TEST_REAL_ROUTES=1` and an elevated token | `$env:PLEXD_TEST_REAL_PORT_RESERVATION='1'; $env:PLEXD_TEST_REAL_WINTUN='1'; $env:PLEXD_TEST_REAL_ROUTES='1'; go test -run TestPeerRoutes_RealWintunAtReservedUDPPorts ./internal/bridge/` from an elevated shell with no other test running |

The two route-controller tests each add a `/30`, check the routing table for it, repeat the add to prove idempotency, remove it twice, then toggle forwarding and assert the prior value comes back.

The two `TestWGControllers_Real*` tests drive the bridge access and site-to-site controllers over a real device. `TestWGControllers_RealUTUN` proves that `AddRoute` over an unnumbered tunnel utun fails with `Network is unreachable` and that the same route installs over a utun addressed `10.255.251.1/32`, where `netstat -rn -f inet` then lists it. It programs a peer through the UAPI socket, removes the interface and repeats the removal, and puts the access controller through the same create, peer and repeated remove. `TestWGControllers_RealWintun` proves that the adapter resolves on the first `net.InterfaceByName` call after creation, that `OSInterfaceName` reports the configured name there, and that the on-link route installs by LUID on an adapter carrying no address.

`TestPeerRoutes_RealUTUN` and `TestPeerRoutes_RealWintun` prove the peer routes without traffic. Each builds a `wireguard.Manager` over the platform's controller with the platform's route controller as its `PeerRouter`, sets it up at `10.99.0.1` in `10.99.0.0/24`, and runs `wireguard.ReconcileHandler` with one peer at `10.99.0.2` whose `routed_subnets` are `["10.20.0.0/16"]`. They want the peer's allowed IPs on the mesh device to be `10.99.0.2/32` and `10.20.0.0/16`, read through `PeerStats`, and the system's route for the subnet to name the mesh interface: `route -n get 10.20.0.1` on macOS names the mesh `utunN`, and on Windows the route for `10.20.0.0/16` is found on the adapter's LUID. A second run without the member wants both gone. `TestPeerRoutes_RealWintunAtReservedUDPPorts` runs `TestPeerRoutes_RealWintun` once more while the host holds a UDP port reservation and the kernel's UDP pick has reached it, which pins that the test's listen port, taken from the kernel, is not a reserved one. CI runs all seven, and the macOS, Wintun and port reservation steps fail unless the `--- PASS:` line of their peer route test is in their output; see [CI Workflow](../development/ci-workflow.md).

## Usage

```go
logger := slog.Default()

// The pf controller supplies the NAT backend.
ctrl := bridge.NewDarwinRouteController(logger, policy.NewPFController(logger))

mgr := bridge.NewManager(ctrl, bridge.Config{
    Enabled:         true,
    AccessInterface: "en1",
    AccessSubnets:   []string{"10.0.0.0/24"},
    EnableNAT:       bridge.BoolPtr(true),
}, logger)

if err := mgr.Setup("plexd0"); err != nil {
    log.Fatal(err)
}
```
