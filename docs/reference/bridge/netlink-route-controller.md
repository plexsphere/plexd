---
title: Netlink Route Controller
package: internal/bridge
feature: PXD-0027
---

# Netlink Route Controller

`NetlinkRouteController` is the Linux production implementation of the `RouteController` interface defined in `internal/bridge`. It manages IP routes via netlink, IP forwarding via sysctl, and NAT masquerading via nftables. It also implements `MeshSourceRewriter`, the source rewrite of user access and site-to-site traffic into the mesh, in an nftables table of its own (see [Mesh Source Rewrite](#mesh-source-rewrite)). It requires `CAP_NET_ADMIN` and the `//go:build linux` constraint.

The macOS and Windows implementations are described in [macOS & Windows Route Controllers](./route-controllers-macos-windows.md).

## Architecture

![Four managers call NetlinkRouteController: in bridge mode only, the Bridge Manager for the access routes, forwarding and NAT, the UserAccessManager for forwarding and the source rewrite, and the SiteToSiteManager for routes, forwarding and the source rewrite; on every node, wireguard.Manager for the peer routes. NetlinkRouteController programs routes through netlink, forwarding through sysctl, and NAT and the mesh source rewrite through nftables.](../../diagrams/bridge-netlink-route-controller.svg)

`plexd up` builds one `NetlinkRouteController` on every Linux node and hands the same instance to every manager that calls it. Each subsystem (routing, forwarding, NAT) uses the appropriate Linux mechanism.

| Caller | Runs | Calls |
|---|---|---|
| `Manager`, the bridge manager | in bridge mode | `EnableForwarding`, `DisableForwarding`, `AddRoute` and `RemoveRoute` for the access subnets, `AddNATMasquerade` and `RemoveNATMasquerade`, during bridge setup and teardown |
| `UserAccessManager` | in bridge mode | `EnableForwarding` and the mesh source rewrite for each provider's interface (see [User Access Integration](user-access-integration.md)) |
| `SiteToSiteManager` | in bridge mode | `EnableForwarding`, the mesh source rewrite, and `AddRoute` and `RemoveRoute` for each allowed subnet of a tunnel, through the tunnel's link (see [Site-to-Site VPN](site-to-site-vpn.md#routes-and-policy)) |
| `wireguard.Manager` | on every node | `AddRoute` and `RemoveRoute` for the `routed_subnets` of each peer, through the mesh interface (see [Routed subnets](../networking/wireguard.md#routed-subnets)) |

Neither the user access nor the site-to-site manager calls `DisableForwarding`: the interface or link it forwarded for is deleted with it, and the forwarding of the mesh interface belongs to the bridge manager.

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
3. Creates a `netlink.Route` with `SCOPE_LINK`, the static protocol (`RTPROT_STATIC`) and the interface's link index
4. Calls `netlink.RouteAdd`
5. On `EEXIST` — returns `nil` (idempotent)

### RemoveRoute

1. Parses the subnet CIDR and resolves the interface (same as `AddRoute`)
2. Calls `netlink.RouteDel` with the scope and the protocol `AddRoute` installs
3. On `ESRCH` — returns `nil` (idempotent)

The kernel deletes an IPv4 route only when the request names the route's scope and protocol or leaves them open. Naming both deletes the route `AddRoute` added and never one plexd did not add: an access subnet that is the access interface's own network meets the kernel's route to it, which `AddRoute` takes for its own on `EEXIST`, and `RemoveRoute` leaves that route in place when the bridge stops.

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

| Table            | Package           | Purpose                                      |
|------------------|-------------------|----------------------------------------------|
| `plexd`          | `internal/policy` | Firewall filter rules                        |
| `plexd-nat`      | `internal/bridge` | NAT masquerade for bridge                    |
| `plexd-mesh-nat` | `internal/bridge` | Mesh source rewrite of user access providers and site-to-site tunnels |

The tables are deliberately separated to avoid conflicts between the policy firewall and bridge NAT subsystems. `plexd-nat` cannot hold a second translation, because `AddNATMasquerade` flushes its chain and `RemoveNATMasquerade` deletes the table whole, so the mesh source rewrite has a table of its own.

## Mesh Source Rewrite

`NetlinkRouteController` implements `MeshSourceRewriter`, which the user access manager calls for each provider's interface and the site-to-site manager for each tunnel's link (see [User Access Integration](user-access-integration.md#policy-and-device-traffic) and [Site-to-Site VPN](site-to-site-vpn.md#routes-and-policy)). On macOS `PFController` implements it in the pf anchor instead (see [Mesh source rewrite](../networking/pf-wfp-firewall.md#mesh-source-rewrite)). Both managers share the table:

| Method                    | Mechanism | Linux Subsystem                                      |
|---------------------------|-----------|------------------------------------------------------|
| `AddMeshSourceRewrite`    | nftables  | `plexd-mesh-nat` table, one tagged postrouting rule per interface |
| `RemoveMeshSourceRewrite` | nftables  | Delete the rule tagged with the interface's name     |
| `ResetMeshSourceRewrite`  | nftables  | Delete the `plexd-mesh-nat` table                    |

### AddMeshSourceRewrite

`AddMeshSourceRewrite(fromIface, meshIface)` masquerades the packets that arrive on `fromIface` and leave through `meshIface`, which gives them the address of `meshIface`, the bridge's mesh address. It adds the IPv4 table `plexd-mesh-nat` and its chain `postrouting` when they are missing, and one rule per interface, which carries `fromIface` as a comment in its user data:

```
table ip plexd-mesh-nat {
    chain postrouting {
        type nat hook postrouting priority srcnat;
        iifname "wg-ua-a0a0a0e1" oifname "plexd0" counter masquerade comment "wg-ua-a0a0a0e1"
        iifname "wg-s2s-a0a0a0e1" oifname "plexd0" counter masquerade comment "wg-s2s-a0a0a0e1"
    }
}
```

The operation is idempotent: a rule that carries `fromIface` is left alone, whatever `meshIface` it names. An empty interface name, or one that does not fit `IFNAMSIZ` with its terminator, is refused before any nftables call. `meshSourceRewriteExprs(fromIface, meshIface)` builds the rule's expressions, which a test checks without the kernel: the incoming interface name, then the outgoing one, each compared with its terminating NUL, a counter, and the masquerade.

### RemoveMeshSourceRewrite

Finds the rule by its comment and deletes it. `meshIface` is only logged. A missing rule, chain or table returns `nil` (idempotent).

### ResetMeshSourceRewrite

Deletes the whole `plexd-mesh-nat` table with every rule in it, also the rules of a process that was killed. It touches neither `plexd-nat` nor the policy table `plexd`. Returns `nil` if the table does not exist (idempotent). `bridge.CleanupUserAccess` calls it when the user access manager starts, and once at start on a bridge that opts out of user access, so `plexd up` resets the table once per start in bridge mode, before the site-to-site manager starts. `bridge.CleanupSiteToSite` does not call it: the rewrites of the tunnels a killed process left behind are gone with that reset.

The rewrite logs at Debug with `component=bridge`: `mesh source rewrite added`, `mesh source rewrite already present, idempotent success`, `mesh source rewrite removed` and `mesh source rewrite not found, idempotent success` with `from_iface` and `mesh_iface`, and `mesh source rewrite table removed` and `mesh source rewrite table not found, idempotent success` with `table`.

## Error Prefixes

| Method                | Prefix                                    |
|-----------------------|-------------------------------------------|
| `EnableForwarding`    | `bridge: enable forwarding:`              |
| `DisableForwarding`   | `bridge: disable forwarding:`             |
| `AddRoute`            | `bridge: add route:`                      |
| `RemoveRoute`         | `bridge: remove route:`                   |
| `AddNATMasquerade`    | `bridge: add NAT masquerade:`             |
| `RemoveNATMasquerade` | `bridge: remove NAT masquerade:`          |
| `AddMeshSourceRewrite` | `bridge: add mesh source rewrite:`; `bridge: add mesh source rewrite from "<fromIface>" to "<meshIface>":` when the commit to the kernel fails |
| `RemoveMeshSourceRewrite` | `bridge: remove mesh source rewrite:`; `bridge: remove mesh source rewrite from "<fromIface>":` when the deletion of the rule or its commit fails |
| `ResetMeshSourceRewrite` | `bridge: reset mesh source rewrite:`   |

## Dependencies

| Package                          | Usage                        |
|----------------------------------|------------------------------|
| `github.com/vishvananda/netlink` | Route add/remove via netlink |
| `github.com/google/nftables`    | NAT masquerade via nftables  |
| `github.com/google/nftables/expr`| nftables expression types   |
| `github.com/google/nftables/userdata` | The comment that tags a mesh source rewrite |
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
