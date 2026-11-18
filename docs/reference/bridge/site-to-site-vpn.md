---
title: Site-to-Site VPN
package: internal/bridge
feature: PXD-0015
---

# Site-to-Site VPN

A site-to-site tunnel joins a network outside the mesh, such as a branch office or a data center, to the nodes of a bridge's Domain. Each tunnel is an entry of the `bridge.site_to_site` block of the bridge's state pull, which an operator authors on the bridge Resource in the control plane. A `wireguard` tunnel is a WireGuard interface on the bridge with the remote site as its one peer. An `ipsec` tunnel is an IKEv2 connection of the host's strongSwan, bound to an xfrm interface on the bridge, and an `openvpn` tunnel is an OpenVPN process on a tun device on the bridge (see [Tunnel Providers](tunnel-providers.md)). For every kind the bridge routes the tunnel's `allowed_subnets` into the tunnel's link, forwards between the link and the mesh interface, and rewrites the source of what the link forwards into the mesh to the bridge's own mesh address. Every node of the Project routes the networks behind a bridge's tunnels through that bridge.

A Linux bridge serves the tunnels. On macOS and Windows no tunnel is served, because neither platform has the mesh source rewrite: a tunnel that passes its own [checks](#checks) reads `kind_not_served`, and one that fails them reads `invalid_tunnel` there as on Linux. No issue carries tunnels to either platform yet. The peer routes are programmed on Linux, macOS and Windows alike (see [Routed subnets](../networking/wireguard.md#routed-subnets)). Every bridge reports whether it serves site-to-site tunnels, and the state of each tunnel, with `PUT /v1/nodes/{node_id}/site-to-site-status` (see [Site-to-Site Status Report](#site-to-site-status-report)).

## Data Flow

![A remote site with its allowed_subnets reaches the bridge node over WireGuard, IPsec or OpenVPN and arrives on the tunnel links wg-s2s-a0a0a0e1, xf-s2s-a0a0a0e2 and ov-s2s-a0a0a0e3. Routes, forwarding and the source rewrite carry the traffic between the tunnel links and the mesh WireGuard interface plexd0, which exchanges it with the mesh peers in 10.42.0.0/16, which route the site's networks through the bridge. The VPNController creates one link per tunnel; a line joins it to the SiteToSiteManager, which holds one entry per tunnel, and lines join the manager to the InterfaceKeyStore under <data_dir>/site-to-site, to the RouteController and MeshSourceRewriter, and to the TunnelProvider for ipsec and openvpn. The control plane sends the bridge_config_updated event over SSE, which triggers a reconcile; the reconcile hands the desired bridge state to the SiteToSiteReconcileHandler, which calls Apply on the manager, and runs the SiteToSitePullHandler, which hands the manager the secret inventory and retries. The manager's entries reach the SiteToSiteStatusReporter, which sends the status report to the control plane.](../../diagrams/bridge-site-to-site-data-flow.svg)

The control plane delivers the block in the state pull and announces a change with a `bridge_config_updated` event, which only triggers a pull (see [SSE Event Handling](#sse-event-handling)). `SiteToSiteReconcileHandler` hands the block to `SiteToSiteManager.Apply`, which serves each tunnel on its own. For a tunnel the manager has the `VPNController` create the tunnel's link: for a `wireguard` tunnel a WireGuard interface with the key `InterfaceKeyStore` keeps and the remote site as its peer, for an `ipsec` tunnel an xfrm interface, for an `openvpn` tunnel a tun device. It switches forwarding on between the link and the mesh interface, adds the source rewrite with the `MeshSourceRewriter`, and routes each allowed subnet into the link with the `RouteController`. For an `ipsec` or `openvpn` tunnel it then hands the tunnel to its `TunnelProvider`, which runs the daemon's side. `SiteToSitePullHandler` hands the pull's secret inventory to the manager on every successful pull and retries the tunnels that are down (see [Retry](#retry)). `SiteToSiteStatusReporter` reads the manager and sends the report.

## Routes and Policy

A tunnel carries traffic both ways only when both ends of the mesh know where the site's networks lie:

- **On the bridge**, the manager adds a route for each of the tunnel's `allowed_subnets` into the tunnel's link (`RouteController.AddRoute(subnet, link)`), so what the bridge receives on the mesh interface for the site leaves through the tunnel.
- **On every node**, the WireGuard manager routes the `routed_subnets` of a peer through the mesh interface and accepts them as allowed IPs of that peer. The control plane lists the networks behind a bridge's tunnels in the `routed_subnets` of the bridge's peer entry, so a node sends traffic for the site to the bridge, and its WireGuard accepts the site's addresses from the bridge. A node skips a routed subnet that is malformed, overlaps the mesh prefix, or lies inside a network of one of its own interfaces; see [Routed subnets](../networking/wireguard.md#routed-subnets).

The bridge masquerades what a tunnel's link forwards out through the mesh interface, so a packet the site sends into the mesh leaves the bridge with the bridge's mesh address as its source. The source rewrite is the same rule user access uses, `iifname <link> oifname plexd0 masquerade`, in the nftables table `plexd-mesh-nat` (see [Mesh Source Rewrite](netlink-route-controller.md#mesh-source-rewrite)). A packet a mesh node sends to the site keeps its source.

The policy applies differently in each direction:

| Direction | Source seen at the far end | Where the policy applies |
|---|---|---|
| Mesh node to the site | The node's mesh address | The sending node's output chain filters what it sends under its compiled rules; the control plane compiles a rule to a network behind a bridge with that network as `destination_cidr`. The bridge's forward chain filters the packet too, because its policy chain matches what arrives on the mesh interface. The site's reply passes the bridge as a reply to a tracked connection and reaches the node with the site's address, which the node's WireGuard accepts from the bridge as a routed subnet |
| Site to a mesh node | The bridge's mesh address | The bridge does not filter it: the packet arrives on the tunnel's link, and the policy chain of the forward hook matches only what arrives on the mesh interface. The destination node filters it under its rules for the bridge's mesh address, as it does for every packet a node forwards into the mesh (see [Connection Tracking](../networking/nftables-firewall.md#connection-tracking)) |

A rule that lets a mesh node reach the site therefore names the site's network as its destination, and a Policy that allows the bridge's mesh address to a destination allows every host of every site behind the bridge to reach it. Phase 18 of the systemd suite proves both directions with packets (see [Systemd E2E Test](../development/systemd-e2e-test.md#_18-site-to-site-through-a-bridge)).

## The bridge.site_to_site Block

The block is the control plane's `NodeStateBridgeSiteToSite` and each tunnel a `NodeStateBridgeSiteToSiteTunnel`. The section "Site-to-site tunnels" of [plexsphere's agent contract](https://github.com/plexsphere/plexsphere/blob/4935e06/docs/reference/api/plexd-agent-contract.md#site-to-site-tunnels) defines it; the control plane delivers it since [plexsphere/plexsphere#1109](https://github.com/plexsphere/plexsphere/pull/1109). The pull lists the tunnels by `slug`. A bridge with a `wireguard` tunnel to a branch office and an `ipsec` tunnel to a data center pulls:

```json
"bridge": {
  "site_to_site": {
    "enabled": true,
    "tunnels": [
      {
        "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1",
        "slug": "branch-berlin",
        "kind": "wireguard",
        "remote_host": "vpn.branch.example.com",
        "remote_port": 51820,
        "allowed_subnets": ["10.20.0.0/16"],
        "listen_port": 51830,
        "remote_public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
        "auth_secret_name": "branch-berlin-psk"
      },
      {
        "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2",
        "slug": "dc-east",
        "kind": "ipsec",
        "remote_host": "203.0.113.10",
        "remote_port": 500,
        "allowed_subnets": ["10.30.0.0/16", "10.31.0.0/16"],
        "auth_secret_name": "dc-east-ike"
      }
    ]
  }
}
```

Each tunnel carries the members every kind has, and the members of its kind. plexd reads the members of the tunnel's kind and ignores the others:

| Field | Type | Kinds | Description |
|---|---|---|---|
| `id` | string | every kind | The tunnel's id, a UUID. Its last 8 hex digits name the link, and the id names the key file and the provider's files |
| `slug` | string | every kind | The tunnel's name within the bridge Resource; the log lines and the local status name it |
| `kind` | string | every kind | `wireguard`, `ipsec` or `openvpn` |
| `remote_host` | string | every kind | The remote site's host name or IP address. A `wireguard` tunnel takes the address it resolves to as its peer's endpoint; the other kinds hand the name to their daemon |
| `remote_port` | int | every kind | The remote site's port, 1 to 65535 |
| `allowed_subnets` | array | every kind | The 1 to 64 IPv4 networks behind the remote site, in the order the operator wrote them. The bridge routes them into the tunnel, and a `wireguard` tunnel accepts them from its peer |
| `listen_port` | int | `wireguard` | The UDP port of the tunnel's interface on the bridge, 1 to 65535 |
| `remote_public_key` | string | `wireguard` | The remote site's WireGuard public key, 44 characters of standard base64 that decode to 32 bytes |
| `auth_secret_name` | string | every kind | The Secret that holds the tunnel's key as plain text: the optional preshared key of a `wireguard` tunnel, the IKE pre-shared key of an `ipsec` tunnel, the static key of an `openvpn` tunnel |

No member is a private key or the value of a Secret. The `enabled` member is the control plane's switch for the block: the bridge serves the tunnels only when it is `true` and the bridge's local configuration does not opt out (see [Activation](#activation)).

The block is whole. A tunnel missing from a later pull is torn down. The bridge serves each tunnel on its own, so a tunnel it cannot serve leaves the others up. A block whose `enabled` is `false` serves no tunnel. A `site_to_site` child that is absent or `null`, and a pull without a `bridge` block, serve none either, and they also delete every key file (see [The Key File](#the-key-file)). A block in the shape before plexsphere/plexsphere#1107, with tunnels that carry a tunnel id, a remote endpoint, local and remote subnets, an inline preshared key, an interface name and a provider type, decodes to tunnels without an `id`, which a bridge neither serves nor reports.

## Activation

A bridge serves the pulled tunnels when three conditions hold:

1. It runs in bridge mode: `mode: bridge` and `bridge.enabled: true`.
2. Its local configuration does not opt out: `bridge.site_to_site_enabled` is absent or `true`.
3. The block carries `enabled: true`.

A bridge that never set `bridge.site_to_site_enabled` starts serving the tunnels the control plane delivers after an upgrade: before, `site_to_site_enabled` was an opt-in that defaulted to `false`. A host that must stay closed sets `bridge.site_to_site_enabled: false` before it upgrades.

| Field | Type | Default | Description |
|---|---|---|---|
| `SiteToSiteEnabled` | `*bool` | nil | `bridge.site_to_site_enabled`: the local switch for site-to-site tunnels. nil and `true` serve, `false` opts out and is reported as `opted_out`. `SiteToSiteOptedOut()` is true exactly when it is non-nil and `false` |
| `SwanctlConfDir` | `string` | `""` | `bridge.swanctl_conf_dir`: the directory plexd writes the strongSwan connection file of each `ipsec` tunnel into. Empty means `<run dir>/swanctl`, `/var/run/plexd/swanctl` on Linux (see [Tunnel Providers](tunnel-providers.md#host-requirements)) |

`Validate` refuses an explicit `true` while `bridge.enabled` is `false`, with `bridge: config: site-to-site requires bridge mode to be enabled`. An absent key and an explicit `false` are valid without `bridge.enabled`, so a node outside bridge mode loads either. A `swanctl_conf_dir` that is not an absolute path fails `Validate` with `bridge: config: swanctl_conf_dir: "<dir>" is not an absolute path`, whatever the other settings say; `filepath.IsAbs` decides, so on Windows the path needs a drive letter.

A bridge with `bridge.site_to_site_enabled: false` opts out. Step 5e of `plexd up` builds no site-to-site manager, so no code path creates a tunnel's link, starts a daemon or routes a site's network into the mesh, whatever the pull says. It runs `CleanupSiteToSite` once instead, with the same controller and providers a manager would get, which removes every link whose name starts with `wg-s2s-`, `xf-s2s-` or `ov-s2s-` and the providers' files an earlier process left behind, so no link of that process keeps a port open. A failed cleanup is logged at Error as `bridge: site-to-site: clean up failed` and does not stop the start. The step then logs `site-to-site: opted out by bridge.site_to_site_enabled, no tunnel is served`, and `bridge subsystem initialized` reads `site_to_site=false`. The opt-out keeps the key files. The reconcile handler logs a Warn when the pull enables tunnels (see [SiteToSiteReconcileHandler](#sitetositereconcilehandler)), and the bridge reports `opted_out`. plexd reads its configuration once per start, so a changed `bridge.site_to_site_enabled` takes effect, and is reported, with the next restart.

### The Replaced Keys

The four keys of the local model are replaced by what the control plane delivers. They stay parseable, so a configuration written for an older plexd still loads after an upgrade, and they are ignored: they have no default, no validation, the check of the `tunnel_providers` values included, and nothing reads them. In bridge mode, `plexd up` logs one Warn at start when any of them is set to a value other than its zero value:

```text
bridge: config: site-to-site keys are ignored, the control plane delivers tunnels keys=[site_to_site_listen_port]
```

`Config.ReplacedSiteToSiteKeys()` returns the set keys in this order, and nil when none is set: `site_to_site_interface_prefix`, `site_to_site_listen_port`, `max_site_to_site_tunnels`, `tunnel_providers`. See [bridge](../core/configuration.md#bridge) in the configuration reference.

## The Interfaces

A tunnel's link is named by its kind's prefix and the last 8 hex digits of its id, lower case:

| Kind | Link | Prefix constant | Name for the id `0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1` |
|---|---|---|---|
| `wireguard` | WireGuard interface | `SiteToSiteWireGuardPrefix`, `wg-s2s-` | `wg-s2s-a0a0a0e1` |
| `ipsec` | xfrm interface | `SiteToSiteXfrmPrefix`, `xf-s2s-` | `xf-s2s-a0a0a0e1` |
| `openvpn` | Persistent tun device | `SiteToSiteTunPrefix`, `ov-s2s-` | `ov-s2s-a0a0a0e1` |

Each name has 15 characters, the kernel's limit. The first digits of a UUIDv7 are its timestamp and repeat for tunnels created within a minute, so the name takes the last ones. `SiteToSiteInterfacePrefixes` lists the three prefixes in this order; a start removes the links a killed process left behind by them.

A `wireguard` interface listens on the tunnel's `listen_port` and holds one peer, the remote site, with `remote_public_key`, the tunnel's `allowed_subnets` as its allowed IPs, the remote site's address and `remote_port` as its endpoint, and the preshared key of the tunnel's Secret when it names one. The bridge sets no persistent keepalive. An `ipsec` tunnel's xfrm interface takes the same 8 hex digits as a number for its interface id, 2694881506 for an id ending `a0a0a0e2`, and strongSwan binds the connection to it with `if_id_in` and `if_id_out`. An `openvpn` tunnel's tun device is created before the daemon starts, without packet information and without an address, and the daemon attaches to it by name. No link on Linux carries an address: a route names the link itself.

## The Key File

A `wireguard` tunnel's private key is generated once and kept, so the tunnel's public key, which the remote site names as its peer's key, survives a restart. `InterfaceKeyStore` keeps it in `<data_dir>/site-to-site/<id>.key`, `/var/lib/plexd/site-to-site/<id>.key` on Linux, with the id in lower case. The file holds the standard base64 encoding of the 32 bytes and is written with mode 0600 through an atomic write; the store creates the directory with mode 0700 when it first needs it. A file that does not decode to 32 bytes is an error and is never replaced, because a fresh key would invalidate the remote site's configuration: the tunnel reads `key_unavailable` until an operator fixes or deletes the file. The store is the one user access keeps its keys with (see [InterfaceKeyStore](user-access-integration.md#interfacekeystore)).

The key file lives as long as the pull lists the tunnel:

| Event | Key file |
|---|---|
| `plexd` restarts, or a killed process is restarted | kept; the tunnel comes back with the same public key |
| The bridge opts out with `bridge.site_to_site_enabled: false` | kept; no manager runs, so nothing deletes it |
| An applied block lists the tunnel, also one whose `enabled` is `false` | kept |
| An applied block no longer lists the tunnel | deleted |
| An applied block is absent or `null`, or the pull has no `bridge` block | every key file deleted |

`Apply` runs `Prune` with the ids of every tunnel the block lists, whatever `enabled` and whatever kind, and `Prune` deletes the key file of every other id. `Teardown` keeps every key file. An `ipsec` or `openvpn` tunnel has no key file here: its key is the value of its Secret, which its provider writes under the run directory while the tunnel exists (see [Tunnel Providers](tunnel-providers.md#the-key-on-disk)).

## Applying the Block

`Apply(ctx, block)` serves the block whole. It does nothing while the manager is not active.

1. It checks each listed tunnel (see [Checks](#checks)). A tunnel with an invalid or repeated id gets no state and no report entry.
2. A held tunnel the block no longer serves is torn down: the provider's side of it, its routes, its source rewrite and its link. `site-to-site tunnel removed` is logged. A block whose `enabled` is `false` serves no tunnel, so it tears down every held one.
3. `Prune` deletes the key files of the tunnels the block does not list.
4. A held tunnel whose entry is unchanged is kept. Unchanged means the same `kind`, `remote_host`, `remote_port`, `allowed_subnets` in order, `listen_port`, `remote_public_key` and `auth_secret_name`, and the same verdict of the [checks](#checks), compared by its error text. A changed `slug`, and the case of the id, are taken over in place. The verdict depends on the tunnels before it in the block, so a tunnel whose own members stay the same is rebuilt when an earlier tunnel of the block comes to overlap its subnets or take its link name: it is torn down, an up one included, and reads `invalid_tunnel`.
5. Any other tunnel is brought up, in block order. A held tunnel whose entry changed is torn down and brought up again; a `wireguard` tunnel keeps its key, because its id names the key file.

The manager never switches forwarding off: a tunnel's link is deleted with the tunnel, and the forwarding of the mesh interface belongs to the bridge manager.

### Checks

Every listed tunnel is checked first. The first check that fails puts the tunnel down with `invalid_tunnel`, and the tunnel's `site-to-site tunnel down` line carries the error text:

| Check | Kinds | Error text |
|---|---|---|
| The id is a UUID in canonical form, in either case, other than the zero UUID (`api.ValidSiteToSiteTunnelID`) | every kind | `the id is no UUID other than the zero UUID` |
| No earlier tunnel of the block has the same id, compared without case | every kind | `an earlier tunnel of the block has the same id` |
| `remote_host` matches `^[A-Za-z0-9.:-]{1,253}$` | every kind | `remote_host "<host>" is no host name or IP address` |
| `remote_port` is 1 to 65535 | every kind | `remote_port <n> is outside 1 to 65535` |
| `allowed_subnets` holds 1 to 64 subnets | every kind | `allowed_subnets holds <n> subnets, want 1 to 64` |
| Each subnet is an IPv4 prefix | every kind | `allowed subnet "<subnet>" is no IPv4 prefix` |
| Each subnet has no host bits set | every kind | `allowed subnet <subnet> has host bits set` |
| No subnet repeats within the tunnel | every kind | `allowed subnet <subnet> repeats` |
| No subnet overlaps the Domain mesh CIDR | every kind | `allowed subnet <subnet> overlaps the mesh CIDR <cidr>` |
| No subnet overlaps a subnet of an earlier tunnel of the block | every kind | `allowed subnet <subnet> overlaps the subnet <other> of an earlier tunnel of the block` |
| The last 8 hex digits of the id are not all zero | every kind | `the last 8 hex digits of the id are zero` |
| No earlier tunnel of the same kind ends its id in the same 8 hex digits | every kind | `an earlier <kind> tunnel of the block ends its id in the same 8 hex digits` |
| `listen_port` is 1 to 65535 | `wireguard` | `listen_port <n> is outside 1 to 65535` |
| `remote_public_key` is 44 characters of standard base64 that decode to 32 bytes | `wireguard` | `remote_public_key is no WireGuard key of 44 characters of standard base64` |
| `auth_secret_name`, when set, matches the Secret name grammar `^[a-z][a-z0-9_-]{0,62}$` (`api.ValidSecretName`) | `wireguard` | `auth_secret_name "<name>" is no Secret name` |
| `auth_secret_name` matches the Secret name grammar | `ipsec`, `openvpn` | `auth_secret_name "<name>" is no Secret name` |

A tunnel whose id fails one of the first two checks gets no state: the control plane refuses a whole report for one such entry, so it has no entry in the report, and its `site-to-site tunnel down` line is logged once while the block lists it. A tunnel with a valid id claims its valid subnets and its kind's link name, whatever its other checks say, so a later tunnel's verdict depends only on the tunnels before it. Without a Domain mesh CIDR no subnet is checked against it.

### Bringing Up a Tunnel

The first step that fails sets the tunnel's reason:

1. The checks above: `invalid_tunnel`.
2. Without a `MeshSourceRewriter`, on macOS and Windows: `kind_not_served`. A `kind` this plexd does not know, and an `ipsec` or `openvpn` tunnel without a provider of its kind, read `kind_not_served` too.
3. The secret inventory does not list the Secret the tunnel names: `auth_secret_not_listed`. An `ipsec` tunnel on a bridge without a Domain mesh CIDR: `setup_failed`, since it has no local traffic selector.
4. A `remote_host` that is no IP address is resolved, with a timeout of 5 s: `remote_host_unresolved` when the lookup fails or returns no address. A `wireguard` tunnel takes the first IPv4 address among those returned, or the first address when none is IPv4, and `<address>:<remote_port>` as its peer's endpoint. An IP address is taken as it is, without a lookup.
5. The fetch of the Secret the tunnel names, in the version the inventory lists: `auth_secret_unreadable`. The value is trimmed of surrounding white space. For a `wireguard` tunnel a value that is not 44 characters of standard base64 decoding to 32 bytes: `setup_failed`. A `wireguard` tunnel without `auth_secret_name` fetches nothing and gets no preshared key.
6. The link. `wireguard`: `InterfaceKeyStore.LoadOrCreate(id)`, `key_unavailable` when it fails; `VPNController.CreateTunnelInterface(name, key, listen_port)`, `bind_failed` when the error wraps `ErrListenPortInUse` and `setup_failed` for any other error; then `ConfigureTunnelPeer(name, remote_public_key, allowed_subnets, endpoint, psk)`. `ipsec`: `CreateXfrmInterface(name, <interface id>)`. `openvpn`: `CreateTunInterface(name)`. An error of these three calls: `setup_failed`. After a failed create or peer the manager removes a link of that name.
7. `RouteController.EnableForwarding(plexd0, name)`, `MeshSourceRewriter.AddMeshSourceRewrite(name, plexd0)` and `RouteController.AddRoute(subnet, name)` for each allowed subnet: `setup_failed`.
8. `ipsec` and `openvpn`: the provider's `CreateTunnel` with the link, the remote host and port, the allowed subnets as the remote subnets, the Domain mesh CIDR as the local subnet, and the Secret's value as the key: `client_missing` when the error wraps `exec.ErrNotFound`, `setup_failed` for any other error. The commands of an `ipsec` tunnel run under a timeout of 30 s. An `openvpn` process runs under the manager's context, which `Teardown` cancels, since a process ends with the context it was started under.

The tunnel is then up, and `site-to-site tunnel up` is logged. Steps 4 and 5 run outside the manager's mutex, so `Teardown` and the status readers do not wait for a lookup or a Secret fetch; an attempt that finds the manager torn down or the tunnel no longer held after them sets nothing up. Steps 6 to 8 run under the mutex. A failure in steps 6 to 8 undoes what the attempt added, in reverse: the routes, the rewrite, the link. A new tunnel, and one rebuilt for a new Secret version, has no entry in the local status or the report until its attempt ends; a tunnel that `Retry` brings up again keeps its `down` entry while its attempt runs.

Tearing a tunnel down runs the provider's `RemoveTunnel` under a timeout of 30 s, `RouteController.RemoveRoute` for each allowed subnet, `MeshSourceRewriter.RemoveMeshSourceRewrite` and `VPNController.RemoveTunnelInterface`. Every step runs; their errors are joined.

## Retry

No reconcile cycle fails for a tunnel, so one broken tunnel never makes the reconciler apply the whole snapshot again. A tunnel that is down is tried again by `Retry`, which `SiteToSitePullHandler` calls on every successful pull, drift or not. `Retry` brings up again every tunnel that is down for a reason it retries and whose next attempt is due on the manager's clock. The delay after a failed attempt is 5 s, doubling with each further failure to at most 60 s (5 s, 10 s, 20 s, 40 s, 60 s), or the `Retry-After` of a `429` answer to the Secret fetch (`APIError.RetryAfter`) when that is longer. The count is of consecutive failed attempts, whatever their reason, and starts again when the tunnel comes up or its entry changes. A tunnel is tried again at the first pull after its delay has passed.

| Reason | Retried |
|---|---|
| `invalid_tunnel`, `kind_not_served` | No, until the entry changes |
| `bind_failed`, `setup_failed`, `key_unavailable`, `auth_secret_not_listed`, `auth_secret_unreadable`, `client_missing`, `remote_host_unresolved` | Yes |

A changed entry is brought up at once by `Apply`, whatever its reason was. The Domain mesh CIDR is read once at start, so an `ipsec` tunnel down for the missing CIDR stays down with `setup_failed` until a restart finds one. A `remote_host` is resolved when the tunnel is brought up: a `wireguard` tunnel that is up keeps the address it resolved, and WireGuard follows the remote site when it sends from a new address; a restart or a change of the entry resolves again.

### A New Secret Version

`SyncSecretInventory` replaces the held inventory, then rebuilds every tunnel that is up and whose Secret the inventory lists at another version than the one the tunnel was built with: the tunnel is torn down and brought up with the new version, a `wireguard` tunnel with its kept key. Without the rebuild, a rotated key that stayed unread would end the tunnel at its next rekey with nothing in the report. For an `ipsec` tunnel strongSwan unloads the connection and loads it again; for an `openvpn` tunnel the process starts again. The tunnel has no entry in the local status while it is rebuilt. A tunnel whose Secret the inventory no longer lists keeps running with the key it has. `SyncSecretInventory` then calls `Retry`, so a tunnel down for `auth_secret_not_listed` comes up at the first pull whose inventory lists its Secret, once its delay has passed.

The inventory is a map from Secret name to version, filtered as the node API's [secret index](../core/nodeapi.md#secretindexdispatchhandler) filters it: the first entry of a name counts, and a name outside the grammar or a version below 1 counts as not listed. The manager holds no inventory until the first `SyncSecretInventory`.

## Site-to-Site Status Report

A bridge reports with [`PUT /v1/nodes/{node_id}/site-to-site-status`](../core/api-endpoints.md#site-to-site-status) whether its local configuration serves site-to-site tunnels, so the control plane refuses a tunnel that no bridge would serve, and how each tunnel fares. The report is the only way the public key of a `wireguard` tunnel's interface reaches the control plane, and with it the operator who configures the remote site. Every node in bridge mode reports, whether or not it opts out, and a node outside bridge mode sends nothing. The control plane's side of the report is plexsphere/plexsphere#1109.

### Reported States

| State | `bridge.site_to_site_enabled` | Meaning |
|---|---|---|
| `enabled` | absent or `true` | The bridge serves the tunnels the pull enables |
| `opted_out` | `false` | The bridge built no site-to-site manager and serves no tunnel whatever the pull says |

The state follows from the local configuration alone, so one process always reports the same state. An `opted_out` report carries the state alone: its body is exactly `{"state":"opted_out"}`. An `enabled` report without entries, before the first pull is applied or for a block without tunnels, is `{"state":"enabled"}`.

### Tunnel Entries

An `enabled` report carries `tunnels`: one entry per tunnel of the last applied block with a valid, unrepeated id, in block order, built from `SiteToSiteManager.TunnelReports`.

| Tunnel | Members |
|---|---|
| down | `id`, `health` `down`, `reason` |
| `wireguard`, up | `id`, `health` `up`, `established`, `public_key` |
| `ipsec` or `openvpn`, up | `id`, `health` `up`, `established` |

`id` is the tunnel's id as pulled. `public_key` is the public half of the interface's key, 44 characters of standard base64; the remote site names it as its peer's key. An `ipsec` or `openvpn` tunnel carries no public key: its daemon authenticates with the tunnel's Secret. `established` says whether the remote site answers, and is sent while the tunnel is up, `false` included:

| Kind | `established` is true when |
|---|---|
| `wireguard` | The latest handshake with the remote peer is at most 180 s old on the manager's clock (`VPNController.TunnelPeerHandshake`). A peer that never completed a handshake reads false, and so does an idle tunnel whose last handshake aged past 180 s, which a persistent keepalive on the remote site prevents |
| `ipsec` | `swanctl --list-sas` shows the IKE security association established and a child security association installed (`IPsecProvider.Established`, under a timeout of 5 s) |
| `openvpn` | The openvpn process reports `CONNECTED` on its management socket (`OpenVPNProvider.Established`, under a timeout of 5 s) |

The manager reads `established` outside its mutex each time it builds the reports: one device read or one command per tunnel that is up. A failed read counts false and is logged at Debug. An `openvpn` process that exits after its start leaves the tunnel `up` with `established` false: the executor reports no exit (see [Tunnel Providers](tunnel-providers.md#what-the-report-says)).

A report carries at most 256 entries (`api.MaxSiteToSiteStatusTunnels`). A manager that reports more has the first 256 sent, in order, and the reporter logs the Warn `site-to-site status: more tunnels than a report carries, reporting the first 256` with `tunnels` once on entering that state.

### Reasons

A reason is a token of the grammar `^[a-z][a-z0-9_]{0,62}$`, and the control plane stores any token of that grammar. plexd sends these:

| Token | Kinds | Meaning |
|---|---|---|
| `invalid_tunnel` | every kind | A member of the entry is missing or malformed, or the entry clashes with an earlier one of the block (see [Checks](#checks)). Not retried until the entry changes |
| `kind_not_served` | every kind | This plexd serves no tunnel of the kind: the platform has no mesh source rewrite (macOS, Windows), the kind is unknown to it, or no provider of the kind is built in. Not retried until the entry changes |
| `key_unavailable` | `wireguard` | The interface's key file could not be read, decoded or created |
| `bind_failed` | `wireguard` | The interface cannot listen on its `listen_port`, which another socket holds, such as the mesh interface or another tunnel's interface |
| `setup_failed` | every kind | The link, the remote peer, the forwarding, the source rewrite, a route or the daemon's side could not be set up; the Secret of a `wireguard` tunnel holds no preshared key; or an `ipsec` tunnel has no Domain mesh CIDR as its local traffic selector |
| `auth_secret_not_listed` | every kind | The secret inventory does not list `auth_secret_name`, a Secret the bridge may not read |
| `auth_secret_unreadable` | every kind | The inventory lists the Secret, but the bridge could not fetch or open it |
| `client_missing` | `ipsec`, `openvpn` | The host has no client of the kind: `swanctl` or `openvpn` is not found |
| `remote_host_unresolved` | every kind | `remote_host` is a host name that does not resolve, or resolves to no address |

`invalid_tunnel`, `setup_failed` and `key_unavailable` are plexd's additions to the contract's table, which lists the other six. The `SiteToSiteReason*` constants of `site_to_site.go` hold every token.

### Reporter

`SiteToSiteStatusReporter` (`site_to_site_status.go`) sends the report from a goroutine of its own. It follows the loop of the [user access status reporter](user-access-integration.md#reporter) as a type of its own.

```go
type SiteToSiteTunnelReport struct {
    TunnelID    string
    Kind        string // the kind as pulled
    Health      string // api.SiteToSiteHealth*
    Reason      string // a SiteToSiteReason* while Health is down
    PublicKey   string // a wireguard tunnel's public key while it is up
    Established bool   // whether the remote site answers, while the tunnel is up
}

// SiteToSiteTunnelReportSource is the part of *SiteToSiteManager the reporter reads.
type SiteToSiteTunnelReportSource interface {
    TunnelReports() []SiteToSiteTunnelReport
    ReportChanged() <-chan struct{}
}

func NewSiteToSiteStatusReporter(interval time.Duration, nodeID string, client SiteToSiteStatusClient,
    optedOut bool, tunnels SiteToSiteTunnelReportSource, logger *slog.Logger) *SiteToSiteStatusReporter
func (r *SiteToSiteStatusReporter) Run(ctx context.Context) error // returns nil when ctx is done
```

`*api.ControlPlane` satisfies `SiteToSiteStatusClient`. The state is fixed at construction: `opted_out` when `optedOut` is true, `enabled` otherwise. `tunnels` is nil on an opted-out bridge. A non-positive `interval` becomes 30 s. The reporter's logger carries `component=bridge`.

`Run` logs `site-to-site status: reporter started` with `interval` and `state`, sends one report at once, and then:

- **On a change.** When `ReportChanged` signals, it builds the report and does nothing when its entries equal those of the last accepted report in `id`, `health`, `reason`, `public_key` and `established`. Otherwise it sends when at least 5 s have passed since the last on-change send, and arms one timer for the rest of the 5 s when they have not. When the timer fires, it builds the report again and sends it only when its entries still differ from those of the last accepted report. An on-change send restarts the interval.
- **On a tick.** It drops a pending change signal and the timer, and sends.
- **When `ctx` is done.** It returns nil and sends nothing.

The manager signals `ReportChanged` without blocking at the end of every `Apply`, every `Retry`, and so every `SyncSecretInventory`, and `Teardown`. A change of `established` alone raises no signal: the next pull's `Retry` signals, or the next tick sends it, so it reaches the control plane at most one interval late. The send at start carries no entries, because no pull is applied yet; the first `Apply` signals, and the entries follow. A failed send is not retried within its tick, and the report never gates serving: the reporter only reads the manager.

Step 17d of `plexd up` starts `bridge.NewSiteToSiteStatusReporter(statusInterval, identity.NodeID, client, cfg.Bridge.SiteToSiteOptedOut(), siteToSiteTunnels, logger)` beside the relay, ingress and user access status reporters, whenever bridge mode runs. `statusInterval` is `heartbeat.interval`, 30 s by default. `siteToSiteTunnels` is the manager, or an untyped nil on a bridge that opts out: a nil `*SiteToSiteManager` in the interface would not compare equal to nil.

### Answers

No answer stops the loop, and none changes what the bridge serves:

| Answer | Reporter behavior |
|---|---|
| `200 OK` | Debug `site-to-site status: accepted` with `state`, `tunnels` (the number of entries sent) and `accepted_at` on every accepted send. Info `site-to-site status: reported` with `state` and `tunnels` for the first accepted send. After a not-served phase, one Info `site-to-site status: control plane accepts site-to-site status reports` |
| `404` with any code but `site_to_site_status_node_gone`, or `501 site_to_site_status_not_provisioned` | The control plane does not serve the report, as `api.IsSiteToSiteStatusNotServed` classifies it. Info `site-to-site status: control plane does not accept site-to-site status reports, retrying every interval` with `status` and `code`, once on entering that state. plexd keeps reporting every interval and keeps serving as the pull says |
| `404 site_to_site_status_node_gone` | The node was removed while the request ran. Warn `site-to-site status: rejected, this node was removed` with `code` on every send |
| `api.ErrCredentialRefused` | Debug `site-to-site status: send failed` with `error`. The heartbeat parked the agent on a refused credential and names the cause once |
| Any error after `ctx` ended | Nothing, because that is the shutdown |
| Anything else, `400 malformed_site_to_site_status`, `400 invalid_site_to_site_status`, `413 site_to_site_status_body_too_large`, a `501` with another code and `context.DeadlineExceeded` included | Warn `site-to-site status: send failed` with `error`, on every send |

### What the Control Plane Does

The control plane keeps the latest state per node and never ages it, so a bridge that reported `opted_out` and went offline stays opted out until it reports `enabled`. While a bridge's report reads `opted_out`, the control plane refuses a create or an update of a tunnel on its bridge Resource. Each report replaces the tunnel entries of the one before, and the entries age once a bridge's reports stop. A tunnel no report has named reads `not_reported`, which is what an operator saw on every tunnel before plexd sent the report. A control plane that predates the report answers `404`, and plexd keeps serving as the pull says. See [Site-to-site status](https://github.com/plexsphere/plexsphere/blob/4935e06/docs/reference/api/plexd-agent-contract.md#site-to-site-status) in plexsphere's agent contract.

## The Remote Site of a wireguard Tunnel

The remote site of a `wireguard` tunnel is a WireGuard interface the site's operator configures by hand or with their own tooling. It needs:

| Setting | Value |
|---|---|
| Private key | The key whose public half the tunnel carries as `remote_public_key` |
| Listen port | The tunnel's `remote_port`, on the address `remote_host` names, since the bridge sends to `<remote_host>:<remote_port>` |
| Peer public key | The `public_key` of the tunnel's entry in the status report. It is the same after a restart and after a kill of plexd, and changes only when the tunnel's key file is deleted |
| Peer endpoint | The bridge's address and the tunnel's `listen_port`. Optional when only the bridge starts the handshake; needed for the site to start one |
| Peer allowed IPs | The mesh networks the site exchanges traffic with, the Domain mesh CIDR. A packet a mesh node sends to the site keeps the node's mesh address, and the bridge's replies to traffic the site started come from the mesh addresses it reached |
| Preshared key | The value of the tunnel's Secret when the tunnel names `auth_secret_name`; none otherwise |
| Persistent keepalive | Recommended, for example 25 s: the bridge sets none, a site behind NAT needs one to stay reachable, and an idle tunnel without one reads `established` false once its last handshake is 180 s old |
| Routes | The Domain mesh CIDR into the interface |

The bridge's host must let UDP to the tunnel's `listen_port` in; plexd opens no port in a host firewall. A host of the site then reaches a mesh node under the node's rules for the bridge's mesh address, and a mesh node reaches a host of the site once a rule to the site's network allows it (see [Routes and Policy](#routes-and-policy)).

## Local Status

`SiteToSiteStatus()` feeds the node API's `status.site-to-site` report: whether the last applied block enabled site-to-site tunnels, and one entry per tunnel the manager holds with a settled attempt, in block order, with its slug, kind, link, health, reason, whether it is established, listen port, remote host and port, and allowed subnets. A bridge that opts out, and a node outside bridge mode, publish `{"enabled": false}`. See [`status.site-to-site`](../core/nodeapi.md#status-site-to-site) for the payload.

## SiteToSiteManager

```go
type SiteToSiteDeps struct {
    VPN           VPNController
    Routes        RouteController
    Rewriter      MeshSourceRewriter        // nil: this platform serves no tunnel
    Keys          *InterfaceKeyStore        // must not be nil
    Secrets       SecretValueFetcher        // must not be nil while a tunnel names a listed Secret
    Providers     map[string]TunnelProvider // by kind: ipsec, openvpn
    Resolve       func(ctx context.Context, host string) ([]netip.Addr, error) // nil: net.DefaultResolver.LookupNetIP(ctx, "ip", host)
    MeshInterface string
    MeshCIDR      string                    // the Domain mesh CIDR; empty when the node has none
    Logger        *slog.Logger
}

func NewSiteToSiteManager(deps SiteToSiteDeps) *SiteToSiteManager

// CleanupSiteToSite removes what a killed process left behind:
// vpn.RemoveTunnelInterfaces(SiteToSiteInterfacePrefixes) and each
// provider's Reset, under a timeout of 30 s. A nil vpn is skipped; every
// step runs, and their errors are joined.
func CleanupSiteToSite(vpn VPNController, providers map[string]TunnelProvider) error
```

The manager is concurrent-safe through a mutex. `Apply`, `SyncSecretInventory` and `Retry` are called from the reconciler's goroutine alone.

| Method | Signature | Description |
|---|---|---|
| `Setup` | `() error` | Runs `CleanupSiteToSite`, creates the context the `openvpn` processes run under and marks the manager active. A failed cleanup fails `Setup` with `bridge: site-to-site: clean up: <error>`, and `plexd up` with `plexd up: site-to-site setup: <error>`. Idempotent while active |
| `Apply` | `(ctx context.Context, block api.SiteToSiteConfig)` | Serves the block whole (see [Applying the Block](#applying-the-block)); a no-op while inactive |
| `SyncSecretInventory` | `(ctx context.Context, inventory []api.NodeStateSecret)` | Replaces the secret inventory, rebuilds the tunnels whose Secret moved to another version, then calls `Retry`; a no-op while inactive |
| `Retry` | `(ctx context.Context)` | Brings up again each tunnel that is down for a retried reason and whose next attempt is due (see [Retry](#retry)); a no-op while inactive |
| `Teardown` | `() error` | Removes every tunnel, the provider's side, its routes, its source rewrite and its link, cancels the context of the `openvpn` processes and keeps the key files. Idempotent; joins its errors |
| `TunnelReports` | `() []SiteToSiteTunnelReport` | One report per tunnel with a valid, unrepeated id, in block order, with `established` read for each tunnel that is up; nil while inactive |
| `ReportChanged` | `() <-chan struct{}` | Signalled, without blocking, when what `TunnelReports` returns may have changed; capacity 1 |
| `SiteToSiteStatus` | `() *api.SiteToSiteInfo` | The `status.site-to-site` payload; nil while inactive |

`Setup` exists because a killed process leaves its kernel links behind, and the next create for the same tunnel would fail on the name. The process the unit starts next removes them and brings each tunnel up again, a `wireguard` tunnel with its kept key, so the remote site connects again unchanged. The source rewrites of a killed process are gone before `Setup` runs: `plexd up` runs `CleanupUserAccess` in both of its user access branches, which deletes the table `plexd-mesh-nat` both managers share. An `openvpn` process of a killed plexd ends with the unit's control group; a host that runs plexd without one keeps the orphan until its tun device is deleted.

## SiteToSiteReconcileHandler

```go
func SiteToSiteReconcileHandler(mgr *SiteToSiteManager, logger *slog.Logger) reconcile.ReconcileHandler
```

Returns a `reconcile.ReconcileHandler` that serves the pull's `bridge.site_to_site` block. `mgr` is nil on a bridge that opts out with `bridge.site_to_site_enabled: false`. The handler returns nil in every case: a tunnel that is down is retried by `SiteToSitePullHandler`.

| `mgr` | Pulled block | What the handler does |
|---|---|---|
| any | nil snapshot | Returns nil |
| set | `Bridge` or `SiteToSite` nil | Applies the zero block, which tears every tunnel down and deletes every key file |
| set | any block | Applies the block as it is; `Apply` serves tunnels only when `enabled` is `true` |
| nil | `enabled` true, at least one tunnel, and `diff.BridgeChanged` set | Logs the Warn `site-to-site: the control plane enables site-to-site tunnels, but bridge.site_to_site_enabled is false` with `tunnels=<n>`, and returns nil |
| nil | anything else | Returns nil without a log line |

Reconcile handlers run on every cycle with drift, a changed peer or policy included, so the Warn is gated on `BridgeChanged`: it is logged once per change of the pulled `bridge` block, the first pull after every start included.

## SiteToSitePullHandler

```go
func SiteToSitePullHandler(mgr *SiteToSiteManager) reconcile.DispatchHandler
```

The handler runs on the dispatch seam, on every successful pull, drift or not (see [DispatchHandler](../core/reconciliation.md#dispatchhandler)). A nil snapshot changes nothing. A nil `desired.Secrets` keeps the inventory the manager holds and calls `mgr.Retry`; any other block goes to `mgr.SyncSecretInventory`, which calls `Retry` itself. A pull whose only change is the `secrets` block reports no drift, so no reconcile handler would see a rotated Secret, and a tunnel whose port was taken or whose remote host did not resolve needs a retry whatever drifted. Dispatch handlers run before the reconcile handlers, so a cycle that brings a new tunnel and its Secret hands the inventory over before `Apply` reads it.

`cmd/plexd/cmd/up.go` registers `SiteToSiteReconcileHandler` whenever bridge mode runs, and `SiteToSitePullHandler` only when the manager exists:

```go
if s2sMgr != nil {
    reconciler.RegisterDispatchHandler(bridge.SiteToSitePullHandler(s2sMgr))
}
reconciler.RegisterHandler(bridge.SiteToSiteReconcileHandler(s2sMgr, logger)) // nil on an opted-out bridge
```

## SSE Event Handling

There are no site-to-site SSE handlers. The control plane emits a single `bridge_config_updated` event with an opaque payload; `bridge.HandleBridgeConfigUpdated` dispatches it to `TriggerReconcile()`, and the handlers above serve the block of the authoritative state snapshot. `node_secrets_updated` also only triggers a pull, whose `secrets` block reaches `SiteToSitePullHandler`.

## VPNController

Interface abstracting the links of site-to-site tunnels.

```go
const (
    SiteToSiteWireGuardPrefix = "wg-s2s-"
    SiteToSiteXfrmPrefix      = "xf-s2s-"
    SiteToSiteTunPrefix       = "ov-s2s-"
)

var SiteToSiteInterfacePrefixes = []string{SiteToSiteWireGuardPrefix, SiteToSiteXfrmPrefix, SiteToSiteTunPrefix}

type VPNController interface {
    CreateTunnelInterface(name string, privateKey []byte, listenPort int) error
    CreateXfrmInterface(name string, ifID uint32) error
    CreateTunInterface(name string) error
    RemoveTunnelInterface(name string) error
    RemoveTunnelInterfaces(prefixes []string) error
    ConfigureTunnelPeer(iface, publicKey string, allowedIPs []string, endpoint, psk string) error
    RemoveTunnelPeer(iface, publicKey string) error
    TunnelPeerHandshake(iface, publicKey string) (time.Time, error)
}
```

| Method | Description |
|---|---|
| `CreateTunnelInterface` | Creates a WireGuard interface, configures the 32-byte private key and the listen port and brings it up. A failure after the interface exists removes it again. A listen port another socket holds fails with an error wrapping `ErrListenPortInUse` where the implementation can tell. A name that exists fails with an error wrapping `os.ErrExist` |
| `CreateXfrmInterface` | Creates the xfrm interface of an `ipsec` tunnel with the interface id and brings it up; id 0 is refused. A failure after the interface exists removes it again |
| `CreateTunInterface` | Creates the persistent tun device of an `openvpn` tunnel, without packet information and without an address, and brings it up. A failure after the device exists removes it again |
| `RemoveTunnelInterface` | Removes the link by name, whatever its kind; idempotent |
| `RemoveTunnelInterfaces` | Removes every site-to-site link whose name starts with one of the prefixes; an empty list and an empty prefix are refused; idempotent |
| `ConfigureTunnelPeer` | Adds or updates the remote peer: public key, allowed IPs, endpoint and an optional preshared key; idempotent |
| `RemoveTunnelPeer` | Removes the remote peer by public key; idempotent |
| `TunnelPeerHandshake` | The latest handshake of the peer with the given public key; the zero time for a peer that never completed one and for a peer the interface does not hold |

`NetlinkVPNController` (`vpn_controller_linux.go`) implements it on Linux through netlink and `wgctrl`. `CreateTunnelInterface` works as the user access controller's create does, without an address: the key is parsed before the link is added, and `EADDRINUSE` from `ConfigureDevice` or from `LinkSetUp` is wrapped with `ErrListenPortInUse`, which is what makes the manager report `bind_failed`. `CreateXfrmInterface` adds what `ip link add <name> type xfrm dev lo if_id <id>` adds, with the loopback link as its parent, so the interface depends on no uplink. `CreateTunInterface` adds what `ip tuntap add <name> mode tun` adds; the kernel attaches to a tun device that already carries the name and that no process holds open, so such a device is taken over, and a link of another kind under the name fails. `RemoveTunnelInterfaces` removes only links of type `wireguard`, `xfrm` or `tuntap`, so a link of another type is kept whatever its name starts with; it lists the links again while the kernel reports the dump as interrupted, up to three times. `TestNetlinkVPNController_RealLinks` proves the three kinds of link, the port sentinel and the sweep against the kernel in a network namespace of its own, gated by `PLEXD_TEST_REAL_LINKS` and root; CI runs it in its privileged Linux step.

`WGVPNController` (`vpn_controller_wg.go`) implements it on macOS and Windows over the platform `WGController`, a utun device or a Wintun adapter on the [userspace backend](../networking/wireguard.md#userspace-backend). It passes the key through, returns an error wrapping `errors.ErrUnsupported` from `CreateXfrmInterface` and `CreateTunInterface`, since both links are Linux kernel features, returns nil from `RemoveTunnelInterfaces`, since a userspace device ends with its process, and reads handshakes through `wireguard.PeerStatsReader`. On macOS `plexd up` builds it with the node's mesh IP as a `/32`, because `route(8)` refuses a route over a utun without an IPv4 address. Both controllers stay compiled and tested, and `plexd up` builds them, but no tunnel reaches them: one that passes its checks reads `kind_not_served`, and one that fails them reads `invalid_tunnel`.

## Wiring in plexd up

Step 5e of `plexd up` builds the manager on a bridge that does not opt out, after the user access block:

```go
swanctlDir := cfg.Bridge.SwanctlConfDir
if swanctlDir == "" {
    swanctlDir = filepath.Join(paths.RunDir(), "swanctl")
}
vpnCtrl := newVPNController(logger, identity.MeshIP)
tunnelProviders := map[string]bridge.TunnelProvider{
    api.SiteToSiteKindIPsec:   bridge.NewIPsecProvider(bridge.NewStdCommandExecutor(), swanctlDir, logger),
    api.SiteToSiteKindOpenVPN: bridge.NewOpenVPNProvider(bridge.NewStdCommandExecutor(), bridge.DefaultTunnelConfigDir, logger),
}
s2sMgr = bridge.NewSiteToSiteManager(bridge.SiteToSiteDeps{
    VPN:           vpnCtrl,
    Routes:        routeCtrl,
    Rewriter:      newMeshSourceRewriter(routeCtrl),
    Keys:          bridge.NewInterfaceKeyStore(filepath.Join(cfg.DataDir, "site-to-site")),
    Secrets:       secrets, // nodeSecretFetcher
    Providers:     tunnelProviders,
    MeshInterface: cfg.WireGuard.InterfaceName,
    MeshCIDR:      userAccessMeshCIDR(wgMgr.MeshPrefix()),
    Logger:        logger,
})
if err := s2sMgr.Setup(); err != nil {
    return fmt.Errorf("plexd up: site-to-site setup: %w", err)
}
```

`routeCtrl` is the route controller `plexd up` builds once for every node, the instance the WireGuard manager adds the peer routes with. `secrets` is built when ingress, user access or site-to-site tunnels are not opted out, so a bridge that opts out of all three reads no node secret key. `userAccessMeshCIDR` returns the Domain mesh prefix, masked to its network, and an empty string for a prefix that is not valid or covers a single address. A bridge that opts out builds the same controller and providers and runs `bridge.CleanupSiteToSite(vpnCtrl, tunnelProviders)` once instead (see [Activation](#activation)). The shutdown sequence calls `Teardown` after the user access manager's and logs a failure as `site-to-site teardown error`.

## API Types

### SiteToSiteConfig

`api.BridgeSnapshot.SiteToSite`, present-but-nullable.

```go
type SiteToSiteConfig struct {
    Enabled bool               `json:"enabled"`
    Tunnels []SiteToSiteTunnel `json:"tunnels"`
}

type SiteToSiteTunnel struct {
    ID              string   `json:"id"`
    Slug            string   `json:"slug"`
    Kind            string   `json:"kind"`
    RemoteHost      string   `json:"remote_host"`
    RemotePort      int      `json:"remote_port"`
    AllowedSubnets  []string `json:"allowed_subnets"`
    ListenPort      int      `json:"listen_port,omitempty"`
    RemotePublicKey string   `json:"remote_public_key,omitempty"`
    AuthSecretName  string   `json:"auth_secret_name,omitempty"`
}

const (
    SiteToSiteKindWireGuard = "wireguard"
    SiteToSiteKindIPsec     = "ipsec"
    SiteToSiteKindOpenVPN   = "openvpn"
)

func ValidSiteToSiteTunnelID(s string) bool // the check of ValidUserAccessProviderID
```

The reconciler's snapshot copies the tunnels and each tunnel's `AllowedSubnets`, so a change to a copy leaves the stored snapshot as it was. `StateDiff.BridgeChanged` covers the block.

The report's types, `SiteToSiteStatusRequest`, `SiteToSiteStatusTunnel` and `SiteToSiteStatusResponse`, are listed in [API Types](../core/api-types.md#site-to-site-status), and the local payload `SiteToSiteInfo` in [`status.site-to-site`](../core/nodeapi.md#status-site-to-site). A peer's `routed_subnets` is `api.SnapshotPeer.RoutedSubnets` (see [Routed subnets](../networking/wireguard.md#routed-subnets)).

## Error Prefixes

| Source | Prefix |
|---|---|
| `Config.Validate` | `bridge: config: site-to-site requires bridge mode to be enabled`; `bridge: config: swanctl_conf_dir: ` |
| `SiteToSiteManager.Setup` | `bridge: site-to-site: clean up: ` |
| `plexd up` (setup) | `plexd up: site-to-site setup: ` |
| `CleanupSiteToSite` (provider) | `reset the <kind> provider: ` |
| `SiteToSiteManager.Teardown` (provider) | `bridge: site-to-site: remove the <kind> side of <id>: ` |
| `SiteToSiteManager.Teardown` (route) | `bridge: site-to-site: remove route <subnet> via <link>: ` |
| `SiteToSiteManager.Teardown` (rewrite) | `bridge: site-to-site: remove mesh source rewrite <link>: ` |
| `SiteToSiteManager.Teardown` (link) | `bridge: site-to-site: remove interface <link>: ` |
| The `error` of a tunnel down for its link | `create interface <link>: `, `configure the remote peer on <link>: `, `create xfrm interface <link>: `, `create tun device <link>: ` |
| The `error` of a tunnel down for its forwarding, rewrite or route | `enable forwarding: `, `add mesh source rewrite: `, `add route <subnet>: ` |
| The `error` of a tunnel down for its remote host | `resolve "<host>": ` |
| `InterfaceKeyStore` | `bridge: key store: ` |

The `error` of a tunnel down for one of the checks is the text the [Checks](#checks) table lists; the others are `this platform has no mesh source rewrite`, `kind "<kind>" is not known`, `no <kind> provider is built in`, `the secret inventory does not list "<name>"`, `the node has no mesh CIDR as the local traffic selector` and `the Secret "<name>" holds no preshared key of 44 characters of standard base64`. A provider's error carries `bridge: ipsec: ` or `bridge: openvpn: ` (see [Tunnel Providers](tunnel-providers.md#error-prefixes)). The controller carries prefixes of its own:

| Step | Prefix |
|---|---|
| Private key parse | `bridge: vpn: parse private key:` |
| Interface creation | `bridge: vpn: create interface <name>:` |
| xfrm interface creation | `bridge: vpn: create xfrm interface <name>:` |
| tun device creation | `bridge: vpn: create tun interface <name>:` |
| Device configuration (key, port) | `bridge: vpn: configure device:` |
| Address assignment | `bridge: vpn: configure address <cidr>:` |
| Bringing the link up | `bridge: vpn: set interface up:` |
| Removal after a failed create | `bridge: vpn: remove interface <name> after a failed create:` |
| Link removal | `bridge: vpn: remove interface:` |
| Removal by prefix | `bridge: vpn: remove tunnel interfaces:` |
| Handshake read | `bridge: vpn: peer handshake:` |
| Opening wgctrl | `bridge: vpn: open wgctrl:` |
| Peer public key decode | `bridge: vpn: decode public key:` |
| Peer public key parse | `bridge: vpn: parse public key:` |
| Endpoint resolution | `bridge: vpn: resolve endpoint:` |
| Allowed IP parse | `bridge: vpn: parse allowed IP "<cidr>":` |
| PSK decode | `bridge: vpn: decode psk:` |
| PSK parse | `bridge: vpn: parse psk:` |
| Peer programming | `bridge: vpn: configure peer:` |
| Peer removal | `bridge: vpn: remove peer:` |

The `configure device` and `set interface up` errors of a taken port read `bridge: vpn: <step>: listen port in use: <cause>`. The address assignment is a step of the macOS controller alone; the device configuration, the xfrm and tun creates, the removal after a failed create, the removal by prefix and the opening of wgctrl are steps of the Linux controller alone. On macOS and Windows the text after a prefix is the `wireguard:` controller's own message.

## Logging

All site-to-site log entries use `component=bridge`, the reporter's included, except `site-to-site teardown error` and `bridge subsystem initialized`, which `plexd up` logs without it. `bridge subsystem initialized` carries `site_to_site=false` on a bridge that opts out. No log line and no error carries a key or a Secret's value.

| Level | Message | Keys |
|---|---|---|
| `Info` | `site-to-site manager started` | (none) |
| `Info` | `site-to-site manager stopped` | (none); logged by a `Teardown` without errors |
| `Info` | `site-to-site tunnel up` | `tunnel_id`, `slug`, `kind`, `interface`, and `listen_port` for a `wireguard` tunnel |
| `Warn` | `site-to-site tunnel down` | `tunnel_id`, `slug`, `kind`, `reason`, `error`; once per change of the tunnel's reason, and once while the block lists a tunnel without state |
| `Info` | `site-to-site tunnel removed` | `tunnel_id`, `interface` (empty for a tunnel that was down); not logged when a changed tunnel is rebuilt |
| `Warn` | `site-to-site: the control plane enables site-to-site tunnels, but bridge.site_to_site_enabled is false` | `tunnels`; once per change of the pulled `bridge` block, on a bridge that opts out |
| `Warn` | `bridge: config: site-to-site keys are ignored, the control plane delivers tunnels` | `keys`; logged by step 5e of `plexd up` |
| `Info` | `site-to-site: opted out by bridge.site_to_site_enabled, no tunnel is served` | (none); logged by step 5e of `plexd up` on a bridge that opts out |
| `Info` | `site-to-site status: reporter started` | `interval`, `state` |
| `Info` | `site-to-site status: reported` | `state`, `tunnels`; logged for the first accepted send |
| `Info` | `site-to-site status: control plane does not accept site-to-site status reports, retrying every interval` | `status`, `code`; logged on entering the not-served state only |
| `Info` | `site-to-site status: control plane accepts site-to-site status reports` | (none); logged once after a not-served phase |
| `Warn` | `site-to-site status: rejected, this node was removed` | `code`; logged on every send |
| `Warn` | `site-to-site status: send failed` | `error` |
| `Warn` | `site-to-site status: more tunnels than a report carries, reporting the first 256` | `tunnels`; once on entering that state |
| `Debug` | `site-to-site status: accepted` | `state`, `tunnels`, `accepted_at` |
| `Debug` | `site-to-site status: send failed` | `error`; logged instead of the Warn while the client holds a refused credential (`api.ErrCredentialRefused`) |
| `Error` | `bridge: site-to-site: clean up failed` | `error`; logged by step 5e of `plexd up` on a bridge that opts out |
| `Error` | `bridge: site-to-site: tear down tunnel failed` | `tunnel_id`, `interface`, `error` |
| `Error` | `bridge: site-to-site: prune keys failed` | `error` |
| `Error` | `site-to-site teardown error` | `error`; logged by the shutdown of `plexd up` |
| `Info` | `tunnel interface created` | `interface`, and `listen_port` for a WireGuard interface or `if_id` for an xfrm interface |
| `Info` | `tunnel interface removed` | `interface`; also for each link the sweep of `RemoveTunnelInterfaces` removes |
| `Debug` | `tunnel interface addressed` | `interface`, `address`; macOS only |
| `Debug` | `tunnel peer configured` | `interface` |
| `Debug` | `tunnel peer removed` | `interface` |

A failed read of `established` is logged at Debug. The providers' own lines are listed in [Tunnel Providers](tunnel-providers.md#logging), the peer routes' in [Routed subnets](../networking/wireguard.md#routed-subnets), and the source rewrite's in [Netlink Route Controller](netlink-route-controller.md#mesh-source-rewrite).
