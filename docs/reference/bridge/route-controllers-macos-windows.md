---
title: macOS & Windows Route Controllers
package: internal/bridge
---

# macOS & Windows Route Controllers

`DarwinRouteController` (`route_darwin.go`) and `WindowsRouteController` (`route_windows.go`) are the non-Linux implementations of the `RouteController` interface defined in `internal/bridge`. macOS programs routes with `route(8)` and IPv4 forwarding with `sysctl(8)`; Windows programs both through the IP Helper API via the `winipcfg` package. The macOS controller requires root, the Windows controller Administrator, which the LocalSystem service satisfies.

The Linux implementation is [`NetlinkRouteController`](./netlink-route-controller.md).

## Architecture

```
Bridge Manager / UserAccessManager / SiteToSiteManager
                                  │
                 ┌────────────────┴─────────────────┐
                 ▼                                  ▼
┌──────────────────────────────────┐   ┌──────────────────────────┐
│      DarwinRouteController       │   │  WindowsRouteController  │
└──┬──────────┬────────────┬───────┘   └────┬────────────┬────────┘
   │          │            │                │            │
   ▼          ▼            ▼                ▼            ▼
route(8)  sysctl(8)  PFController       winipcfg   WFPController
```

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

`NetlinkRouteController` implements it itself through nftables. On macOS and Windows the masquerade belongs to pf and to WinNAT, which the firewall controller owns, so both constructors take a backend to delegate to. `cmd/plexd/cmd/up_darwin.go` and `up_windows.go` build one `PFController` or `WFPController` and hand the same instance to the policy enforcer and to the route controller; see [pf & WFP Firewall Controllers](../networking/pf-wfp-firewall.md#nat).

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

Linux writes a per-interface sysctl and every manager writes its own, so `NetlinkRouteController` keeps no state. The other two platforms share a knob: macOS has exactly one, and on Windows the access adapter's flag is claimed by the bridge manager and the user-access manager alike. Without bookkeeping, tearing down a site-to-site tunnel would switch forwarding off under a live bridge.

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

macOS `route(8)` exits 0 on a routing-socket error and reports the failure only in its output, so the controller reads that output whatever the exit status is. `File exists` on an add and `not in table` on a delete are success; any other line carrying `writing to routing socket:` is a failure, reported with the command line and the message `route(8)` printed. A utun that carries no IPv4 address answers `Network is unreachable`, which is why a site-to-site tunnel utun carries the node's mesh IP as a `/32`; see [Site-to-Site VPN](./site-to-site-vpn.md#vpncontroller).

## Interface Names

Neither controller maps names. Each passes what it is given straight to the platform, so `bridge.access_interface` must carry the name the platform knows:

| Platform | Name | Example |
|----------|------|---------|
| Linux   | Kernel interface name | `eth1` |
| macOS   | Kernel interface name | `en1` |
| Windows | The adapter's friendly name, as `Get-NetAdapter` lists it | `Ethernet` |

On Windows, `net.InterfaceByName` resolves the friendly name and `ConvertInterfaceIndexToLuid` turns it into the LUID the IP Helper API addresses. A Wintun adapter is created under the configured interface name, so `plexd0` resolves without a mapping; see [Windows controller](../networking/wireguard.md#windows-controller).

macOS is the platform where this matters most. The kernel names a tunnel device `utunN`, not `plexd0`, so a caller routing over a WireGuard interface has to resolve the kernel name first and hand that in. The bridge manager routes over `access_interface`, which is already a kernel name. `SiteToSiteManager` resolves the name of a tunnel interface through `wireguard.OSInterfaceNamer`, which `WGVPNController` implements over `DarwinController`, and hands the resulting `utunN` to `AddRoute`, `RemoveRoute` and the two forwarding calls; see [Site-to-Site VPN](./site-to-site-vpn.md#sitetositemanager). User access installs no route, so its forwarding calls carry the configured name, which macOS only logs, and `WGAccessController` exposes no mapping of its own.

The mesh interface name reaches only `EnableForwarding`. macOS logs it and programs the global sysctl; Windows resolves it and programs its flag.

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

Both controllers reach the operating system through a seam, so every argument list and every idempotent case is exercised on an ordinary unprivileged runner: macOS through the package's `CommandExecutor` and its recording mock, Windows through the `ipRouter` interface and a fake. The macOS cases cover the outputs that arrive with exit status 0 (`Network is unreachable`, `File exists`, `not in table`, `Permission denied`), the `route get` answers the ownership check reads (the same interface, another interface, no `interface:` line, a failed `get`), and the two helpers that parse them, `routeSocketError` and `routeInterface`. `site_to_site_test.go` covers the kernel-name resolution with a `VPNController` that maps `wg-s2s-0` to `utun9` and one that reports no mapping.

Four tests drive the real kernel and are gated:

| Test | Gate | Locally |
|------|------|---------|
| `TestDarwinRouteController_Real` | `os.Geteuid() == 0` | `sudo go test -run TestDarwinRouteController_Real ./internal/bridge/` |
| `TestWindowsRouteController_Real` | `PLEXD_TEST_REAL_ROUTES=1` and an elevated token | `$env:PLEXD_TEST_REAL_ROUTES='1'; go test -run TestWindowsRouteController_Real ./internal/bridge/` from an elevated shell |
| `TestWGControllers_RealUTUN` | `os.Geteuid() == 0` | `sudo go test -run TestWGControllers_RealUTUN ./internal/bridge/` |
| `TestWGControllers_RealWintun` | `PLEXD_TEST_REAL_WINTUN=1` and an elevated token | `$env:PLEXD_TEST_REAL_WINTUN='1'; go test -run TestWGControllers_RealWintun ./internal/bridge/` from an elevated shell |

The two route-controller tests each add a `/30`, check the routing table for it, repeat the add to prove idempotency, remove it twice, then toggle forwarding and assert the prior value comes back.

The other two drive the bridge access and site-to-site controllers over a real device. `TestWGControllers_RealUTUN` proves that `AddRoute` over an unnumbered tunnel utun fails with `Network is unreachable` and that the same route installs over a utun addressed `10.255.251.1/32`, where `netstat -rn -f inet` then lists it. It programs a peer through the UAPI socket, removes the interface and repeats the removal, and puts the access controller through the same create, peer and repeated remove. `TestWGControllers_RealWintun` proves that the adapter resolves on the first `net.InterfaceByName` call after creation, that `OSInterfaceName` reports the configured name there, and that the on-link route installs by LUID on an adapter carrying no address. CI runs all four; see [CI Workflow](../development/ci-workflow.md).

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
