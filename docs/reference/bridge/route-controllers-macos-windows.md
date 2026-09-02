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
        ┌───────────────┴───────────────┐
        ▼                               ▼
┌───────────────────────┐   ┌────────────────────────┐
│ DarwinRouteController │   │ WindowsRouteController │
└──┬─────────┬──────────┘   └──┬──────────┬──────────┘
   │         │                 │          │
   ▼         ▼                 ▼          ▼
route(8)  sysctl(8)        winipcfg   NATController
                                       (#11, nil today)
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

`NetlinkRouteController` implements it itself through nftables. On macOS and Windows the masquerade rules belong to pf and to the Windows Filtering Platform, which the firewall controller owns, so both constructors take a backend to delegate to. Until that controller exists, `cmd/plexd/cmd/up_darwin.go` and `up_windows.go` pass `nil`, and `AddNATMasquerade` fails:

```
bridge: add NAT masquerade on "en1": NAT masquerade is not available on this
platform; set bridge.enable_nat: false to run the bridge without NAT
```

The error wraps `bridge.ErrNATUnavailable`. `bridge.enable_nat` defaults to true, so a bridge on either platform must set it to `false` until the firewall controller lands. Failing is deliberate: a gateway that came up logging `nat=true` without a masquerade would forward mesh traffic with mesh source addresses, and the return path would disappear silently.

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
| `AddRoute`    | Route already exists | `File exists` in the output | `ERROR_OBJECT_ALREADY_EXISTS` |
| `RemoveRoute` | Route not found      | `not in table` in the output | `ERROR_NOT_FOUND` |

Both are reported as success, which is the idempotency `NetlinkRouteController` grants through `EEXIST` and `ESRCH`.

## Interface Names

Neither controller maps names. Each passes what it is given straight to the platform, so `bridge.access_interface` must carry the name the platform knows:

| Platform | Name | Example |
|----------|------|---------|
| Linux   | Kernel interface name | `eth1` |
| macOS   | Kernel interface name | `en1` |
| Windows | The adapter's friendly name, as `Get-NetAdapter` lists it | `Ethernet` |

On Windows, `net.InterfaceByName` resolves the friendly name and `ConvertInterfaceIndexToLuid` turns it into the LUID the IP Helper API addresses. A Wintun adapter is created under the configured interface name, so `plexd0` resolves without a mapping; see [Windows controller](../networking/wireguard.md#windows-controller).

macOS is the platform where this matters most. The kernel names a tunnel device `utunN`, not `plexd0`, so a caller routing over a WireGuard interface has to resolve the kernel name first and hand that in. The bridge manager routes over `access_interface`, which is already a kernel name; the user-access and site-to-site controllers own that resolution for the interfaces they create.

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

Both controllers reach the operating system through a seam, so every argument list and every idempotent case is exercised on an ordinary unprivileged runner: macOS through the package's `CommandExecutor` and its recording mock, Windows through the `ipRouter` interface and a fake.

Two tests drive the real kernel and are gated:

| Test | Gate | Locally |
|------|------|---------|
| `TestDarwinRouteController_Real` | `os.Geteuid() == 0` | `sudo go test -run TestDarwinRouteController_Real ./internal/bridge/` |
| `TestWindowsRouteController_Real` | `PLEXD_TEST_REAL_ROUTES=1` and an elevated token | `$env:PLEXD_TEST_REAL_ROUTES='1'; go test -run TestWindowsRouteController_Real ./internal/bridge/` from an elevated shell |

Each adds a `/30`, checks the routing table for it, repeats the add to prove idempotency, removes it twice, then toggles forwarding and asserts the prior value comes back. CI runs both; see [CI Workflow](../development/ci-workflow.md).

## Usage

```go
logger := slog.Default()

// nil until the pf or WFP controller supplies a NAT backend.
ctrl := bridge.NewDarwinRouteController(logger, nil)

mgr := bridge.NewManager(ctrl, bridge.Config{
    Enabled:         true,
    AccessInterface: "en1",
    AccessSubnets:   []string{"10.0.0.0/24"},
    EnableNAT:       bridge.BoolPtr(false), // required until #11 lands
}, logger)

if err := mgr.Setup("plexd0"); err != nil {
    log.Fatal(err)
}
```
