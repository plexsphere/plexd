---
title: Netlink Route Controller
quadrant: backend
package: internal/bridge
feature: PXD-0027
---

# Netlink Route Controller

`NetlinkRouteController` is the Linux production implementation of the `RouteController` interface defined in `internal/bridge`. It manages IP routes via netlink, IP forwarding via sysctl, and NAT masquerading via nftables. It requires `CAP_NET_ADMIN` and the `//go:build linux` constraint.

## Architecture

```
Bridge Manager
       │
       ▼
┌────────────────────────┐
│ NetlinkRouteController │
└───┬──────┬──────┬──────┘
    │      │      │
    ▼      ▼      ▼
 netlink  sysctl  nftables
 (routes) (fwd)   (NAT)
```

The `Manager` calls `NetlinkRouteController` methods during bridge setup, teardown, and route updates. Each subsystem (routing, forwarding, NAT) uses the appropriate Linux mechanism.

## Constructor

```go
func NewNetlinkRouteController(logger *slog.Logger) *NetlinkRouteController
```

Logger entries use `component=bridge`.

## Interface Implementation

`NetlinkRouteController` implements all six methods of `RouteController`:

| Method                | Mechanism | Linux Subsystem                                |
|-----------------------|-----------|------------------------------------------------|
| `EnableForwarding`    | sysctl    | `/proc/sys/net/ipv4/conf/{iface}/forwarding`   |
| `DisableForwarding`   | sysctl    | `/proc/sys/net/ipv4/conf/{iface}/forwarding`   |
| `AddRoute`            | netlink   | `RTM_NEWROUTE` via `vishvananda/netlink`       |
| `RemoveRoute`         | netlink   | `RTM_DELROUTE` via `vishvananda/netlink`       |
| `AddNATMasquerade`    | nftables  | `plexd-nat` table, postrouting masquerade      |
| `RemoveNATMasquerade` | nftables  | Delete `plexd-nat` table                       |

## EnableForwarding / DisableForwarding

Writes `"1"` or `"0"` to the per-interface sysctl path for both the mesh and access interfaces:

```
/proc/sys/net/ipv4/conf/{meshIface}/forwarding
/proc/sys/net/ipv4/conf/{accessIface}/forwarding
```

Forwarding is enabled per-interface rather than globally to minimize the security surface.

## AddRoute / RemoveRoute

### AddRoute

1. Parses the subnet CIDR via `net.ParseCIDR`
2. Resolves the interface by name via `netlink.LinkByName`
3. Creates a `netlink.Route` with `SCOPE_LINK` and the interface's link index
4. Calls `netlink.RouteAdd`
5. On `EEXIST` — returns `nil` (idempotent)

### RemoveRoute

1. Parses the subnet CIDR and resolves the interface (same as `AddRoute`)
2. Calls `netlink.RouteDel`
3. On `ESRCH` — returns `nil` (idempotent)

### Idempotency

| Operation     | Duplicate Condition | Errno     | Behavior         |
|---------------|---------------------|-----------|------------------|
| `AddRoute`    | Route already exists| `EEXIST`  | Returns `nil`    |
| `RemoveRoute` | Route not found     | `ESRCH`   | Returns `nil`    |

## AddNATMasquerade / RemoveNATMasquerade

### AddNATMasquerade

Creates an nftables NAT masquerade rule using a dedicated table separated from the policy firewall table:

```
table ip plexd-nat {
    chain postrouting {
        type nat hook postrouting priority srcnat;
        oifname "eth1" counter masquerade
    }
}
```

The operation is idempotent: `AddTable` and `AddChain` are no-ops for existing objects, and `FlushChain` clears stale rules before adding the current masquerade rule.

### RemoveNATMasquerade

Deletes the entire `plexd-nat` table. Lists all IPv4 tables, finds `plexd-nat`, and deletes it. Returns `nil` if the table does not exist (idempotent).

### Table Separation

| Table        | Package           | Purpose                    |
|--------------|-------------------|----------------------------|
| `plexd`      | `internal/policy` | Firewall filter rules      |
| `plexd-nat`  | `internal/bridge` | NAT masquerade for bridge  |

The tables are deliberately separated to avoid conflicts between the policy firewall and bridge NAT subsystems.

## Error Prefixes

| Method                | Prefix                                    |
|-----------------------|-------------------------------------------|
| `EnableForwarding`    | `bridge: enable forwarding:`              |
| `DisableForwarding`   | `bridge: disable forwarding:`             |
| `AddRoute`            | `bridge: add route:`                      |
| `RemoveRoute`         | `bridge: remove route:`                   |
| `AddNATMasquerade`    | `bridge: add NAT masquerade:`             |
| `RemoveNATMasquerade` | `bridge: remove NAT masquerade:`          |

## Dependencies

| Package                          | Usage                        |
|----------------------------------|------------------------------|
| `github.com/vishvananda/netlink` | Route add/remove via netlink |
| `github.com/google/nftables`    | NAT masquerade via nftables  |
| `github.com/google/nftables/expr`| nftables expression types   |
| `golang.org/x/sys` (indirect)   | syscall errno constants      |

## Privileges

All methods require `CAP_NET_ADMIN`. Forwarding methods additionally require write access to `/proc/sys`. Tests that call privileged methods skip with `t.Skipf` when running without root.

## Usage

```go
logger := slog.Default()
ctrl := bridge.NewNetlinkRouteController(logger)

mgr := bridge.NewManager(ctrl, bridge.Config{
    Enabled:         true,
    AccessInterface: "eth1",
    AccessSubnets:   []string{"10.0.0.0/24"},
}, logger)

if err := mgr.Setup("plexd0"); err != nil {
    log.Fatal(err)
}
```
