---
title: User Access Integration
package: internal/bridge
feature: PXD-0013
---

# User Access Integration

User access lets devices outside the mesh, such as an operator's laptop, reach the nodes of a bridge's Domain. Each way in is a user access provider of the `bridge.user_access` block of the bridge's state pull, which an operator authors on the bridge Resource in the control plane. A `wireguard` provider is a WireGuard interface on the bridge that admits the devices the operator registers by their public keys. A `tailscale` or `netbird` provider joins the bridge to that vendor's network with the vendor's client (see [VPN Providers](vpn-providers.md)). For every kind the bridge forwards the traffic of the provider's interface into the mesh and rewrites its source to the bridge's own mesh address.

A Linux bridge serves the providers. On macOS and Windows no provider is served, because neither platform has the source rewrite yet: a provider that passes its own [checks](#checks) reads `kind_not_served`, and one that fails them reads `invalid_provider` there as on Linux. Serving there is [#213](https://github.com/plexsphere/plexd/issues/213) and [#214](https://github.com/plexsphere/plexd/issues/214). Every bridge reports whether it serves user access, and the state of each provider, with `PUT /v1/nodes/{node_id}/user-access-status` (see [User Access Status Report](#user-access-status-report)).

## Data Flow

![Devices of a wireguard provider reach the bridge node over WireGuard on the provider's UDP listen_port and arrive on the provider's WireGuard interface wg-ua-a0a0a0e1 with the address 10.99.0.1/24. Forwarding with a source rewrite carries their traffic to the mesh WireGuard interface plexd0, which exchanges it with the mesh peers in 10.42.0.0/16. The AccessController creates the provider's interface and configures its devices; a line joins it to the UserAccessManager, and a line joins the manager to the InterfaceKeyStore under <data_dir>/user-access. The control plane sends the bridge_config_updated event over SSE, which triggers a reconcile; the reconcile hands the desired bridge state to the UserAccessReconcileHandler, which calls Apply on the UserAccessManager. The manager's entries reach the UserAccessStatusReporter, which sends the status report to the control plane.](../../diagrams/bridge-user-access-data-flow.svg)

The control plane delivers the block in the state pull and announces a change with a `bridge_config_updated` event, which only triggers a pull (see [SSE Event Handling](#sse-event-handling)). `UserAccessReconcileHandler` hands the block to `UserAccessManager.Apply`, which serves each provider on its own. For a `wireguard` provider the manager reads the interface's private key from `InterfaceKeyStore`, has the `AccessController` create the interface and configure each device as a peer, switches forwarding on between the interface and the mesh interface, and adds the source rewrite with the `MeshSourceRewriter`. `UserAccessPullHandler` hands the pull's secret inventory to the manager on every successful pull and retries the providers that are down (see [Retry](#retry)). `UserAccessStatusReporter` reads the manager and sends the report.

## Policy and Device Traffic

A device is no peer of the mesh. The bridge masquerades what a provider's interface forwards out through the mesh interface, so the packet leaves with the bridge's mesh address as its source, and a mesh node sees the device's traffic as the bridge's. A mesh node's WireGuard accepts from the bridge only the bridge's mesh address, so a packet that kept the device's address would be dropped by the first peer it meets.

The bridge does not filter a device's packet on its way into the mesh. The destination node filters device traffic under its rules for the bridge's mesh address, as it does for every packet a node forwards into the mesh: on Linux such a packet takes the forward hook, whose policy chain matches only what arrives on the mesh interface, so the bridge's policy does not filter it on its way out (see [Connection Tracking](../networking/nftables-firewall.md#connection-tracking)). The replies pass the bridge's forward chain as replies to a tracked connection. A Policy that allows the bridge's mesh address to a destination therefore allows every device behind the bridge to reach it.

This deviates from the control plane's agent contract, whose section "User access" says that the bridge's compiled policy applies to device traffic as to the bridge's own traffic. plexd keeps the decision recorded in `internal/policy/nftables_linux.go`, under which the output chain filters only what the node itself sends.

## The bridge.user_access Block

The block is the control plane's `NodeStateBridgeUserAccess`, each provider a `NodeStateBridgeUserAccessProvider` and each device a `NodeStateBridgeUserAccessDevice`. The section "User access" of [plexsphere's agent contract](https://github.com/plexsphere/plexsphere/blob/4935e06/docs/reference/api/plexd-agent-contract.md#user-access) defines it; the control plane delivers it since [plexsphere/plexsphere#1108](https://github.com/plexsphere/plexsphere/pull/1108). The pull lists the providers and the devices by `slug`. A bridge with a `wireguard` provider that admits two devices and a `tailscale` provider pulls:

```json
"bridge": {
  "user_access": {
    "enabled": true,
    "providers": [
      {
        "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1",
        "slug": "field-team",
        "kind": "wireguard",
        "listen_port": 51821,
        "address_pool": "10.99.0.0/24",
        "max_devices": 64,
        "devices": [
          {
            "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d1",
            "slug": "alice-laptop",
            "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "address": "10.99.0.2"
          },
          {
            "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d2",
            "slug": "bob-phone",
            "public_key": "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
            "address": "10.99.0.3"
          }
        ]
      },
      {
        "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2",
        "slug": "tailnet",
        "kind": "tailscale",
        "auth_secret_name": "tailscale-auth-key"
      }
    ]
  }
}
```

Each provider carries `id`, `slug` and `kind`, and the members of its kind. plexd reads the members of the provider's kind and ignores the others:

| Field | Type | Kinds | Description |
|---|---|---|---|
| `id` | string | every kind | The provider's id, a UUID. Its last 8 hex digits name the interface, and the id names the key file |
| `slug` | string | every kind | The provider's name within the bridge Resource; the log lines and the local status name it |
| `kind` | string | every kind | `wireguard`, `tailscale` or `netbird` |
| `listen_port` | int | `wireguard` | The UDP port of the provider's interface, 1 to 65535 |
| `address_pool` | string | `wireguard` | The IPv4 network, in CIDR notation, the interface and the devices take their addresses from |
| `max_devices` | int | `wireguard` | The most devices the provider admits. plexd decodes it and does not enforce it: the control plane refuses a device past the ceiling |
| `devices` | array | `wireguard` | The devices the provider admits; `[]` when it admits none |
| `auth_secret_name` | string | `tailscale`, `netbird` | The Secret that holds the key the provider joins with (see [VPN Providers](vpn-providers.md#the-join-key)) |

Each device carries:

| Field | Type | Description |
|---|---|---|
| `id` | string | The device's id; the Warn `user access device not served` names it |
| `slug` | string | The device's name within the provider |
| `public_key` | string | The device's WireGuard public key, 44 characters of standard base64 that decode to 32 bytes |
| `address` | string | The device's IPv4 address in the pool, its one allowed IP as a `/32` |

The `enabled` member is the control plane's switch for the block: the bridge serves the providers only when it is `true` and the bridge's local configuration does not opt out (see [Activation](#activation)). The control plane sends `true` on every block it delivers, and a bridge without providers gets no block at all.

The block is whole. A provider missing from a later pull is torn down, and a device missing from its provider is removed from the interface. The bridge serves each provider on its own, so a provider it cannot serve leaves the others serving. A block whose `enabled` is `false` serves no provider. A `user_access` child that is absent or `null`, and a pull without a `bridge` block, serve none either, and they also delete every key file (see [The Key File](#the-key-file)). A block in the shape before plexsphere/plexsphere#1108, with `interface_name`, `listen_port` and `peers`, decodes to no providers, so a bridge under an older control plane serves nothing.

## Activation

A bridge serves the pulled providers when three conditions hold:

1. It runs in bridge mode: `mode: bridge` and `bridge.enabled: true`.
2. Its local configuration does not opt out: `bridge.user_access_enabled` is absent or `true`.
3. The block carries `enabled: true`.

The control plane sends `enabled: true` on every block, so the bridge host's configuration decides. A bridge that never set `bridge.user_access_enabled` starts serving the providers the control plane delivers after an upgrade. A host that must stay closed sets `bridge.user_access_enabled: false` before it upgrades.

| Field | Type | Default | Description |
|---|---|---|---|
| `UserAccessEnabled` | `*bool` | nil | `bridge.user_access_enabled`: the local switch for user access. nil and `true` serve, `false` opts out and is reported as `opted_out`. `UserAccessOptedOut()` is true exactly when it is non-nil and `false` |

`Validate` refuses only an explicit `true` while `bridge.enabled` is `false`, with `bridge: config: user access requires bridge mode to be enabled`. An absent key and an explicit `false` are valid without `bridge.enabled`, so a node outside bridge mode loads either. `Validate` does not read `mode`: `mode: node` with `bridge.enabled: true` and `bridge.user_access_enabled: true` loads, and serves no provider, because `plexd up` builds the bridge subsystem only when both conditions of step 1 hold.

A bridge with `bridge.user_access_enabled: false` opts out. Step 5e of `plexd up` builds no user access manager, so no code path creates a provider's interface or starts a vendor client, whatever the pull says. It runs `CleanupUserAccess` once instead, which on Linux removes every interface whose name starts with `wg-ua-` and the nftables table `plexd-mesh-nat` that an earlier process left behind, so no interface of that process keeps a port open. A failed cleanup is logged at Error as `bridge: user access: clean up failed` and does not stop the start. The step then logs `user access: opted out by bridge.user_access_enabled, no provider is served`, and `bridge subsystem initialized` reads `user_access=false`. The opt-out keeps the key files. The reconcile handler logs a Warn when the pull enables user access with providers (see [UserAccessReconcileHandler](#useraccessreconcilehandler)), and the bridge reports `opted_out`. plexd reads its configuration once per start, so a changed `bridge.user_access_enabled` takes effect, and is reported, with the next restart.

### The Replaced Keys

The six keys of the local model are replaced by what the control plane delivers. They stay parseable, so a configuration written for an older plexd still loads after an upgrade, and they are ignored: they have no default, no validation, and nothing reads them. In bridge mode, `plexd up` logs one Warn at start when any of them is set to a value other than its zero value:

```text
bridge: config: user access keys are ignored, the control plane delivers providers keys=[user_access_listen_port]
```

`Config.ReplacedUserAccessKeys()` returns the set keys in this order, and nil when none is set: `user_access_interface_name`, `user_access_listen_port`, `max_access_peers`, `user_access_provider_type`, `auth_key_env`, `setup_key_env`. See [bridge](../core/configuration.md#bridge) in the configuration reference.

## The Interface

A `wireguard` provider's interface is named `wg-ua-` and the last 8 hex digits of its id, lower case: `wg-ua-a0a0a0e1` for `0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1`. The name has 14 characters, inside the kernel's limit of 15. The first digits of a UUIDv7 are its timestamp and repeat for providers created within a minute, so the name takes the last ones. `UserAccessInterfacePrefix` holds the prefix `wg-ua-`, by which a start finds the interfaces a killed process left behind.

The interface listens on the provider's `listen_port` and takes the first host address of `address_pool` with the pool's prefix length: `10.99.0.1/24` for `10.99.0.0/24`. Each device becomes a peer of the interface with its `public_key` and its `address` as a `/32` allowed IP, without a preshared key.

## The Key File

The interface's private key is generated once and kept, so the provider's public key, which every device names as its peer's key, survives a restart. `InterfaceKeyStore` keeps it in `<data_dir>/user-access/<id>.key`, `/var/lib/plexd/user-access/<id>.key` on Linux, with the id in lower case. The file holds the standard base64 encoding of the 32 bytes, the form the node's own private key is stored in, and is written with mode 0600 through an atomic write. The store creates the directory with mode 0700 when it first needs it; a directory that exists keeps its mode. A file that does not decode to 32 bytes is an error and is never replaced, because a fresh key would invalidate every device: the provider reads `key_unavailable` until an operator fixes or deletes the file.

The key file lives as long as the pull lists the provider:

| Event | Key file |
|---|---|
| `plexd` restarts, or a killed process is restarted | kept; the provider comes back with the same public key |
| The bridge opts out with `bridge.user_access_enabled: false` | kept; no manager runs, so nothing deletes it |
| An applied block lists the provider, also one whose `enabled` is `false` | kept |
| An applied block no longer lists the provider | deleted |
| An applied block is absent or `null`, or the pull has no `bridge` block | every key file deleted |

`Apply` runs `Prune` with the ids of every provider the block lists, whatever `enabled` says, and `Prune` deletes the key file of every other id. It considers only regular files named `<id>.key`, so it leaves other files of the directory, such as the temp file of an interrupted write, alone. `Teardown` keeps every key file.

## Applying the Block

`Apply(ctx, block)` serves the block whole. It does nothing while the manager is not active.

1. It checks each listed provider (see [Checks](#checks)). A provider with an invalid or repeated id gets no state and no report entry.
2. A held provider the block no longer serves is torn down: its vendor client stopped or its interface removed, and its source rewrite removed. `user access provider removed` is logged. A block whose `enabled` is `false` serves no provider, so it tears down every held one.
3. `Prune` deletes the key files of the providers the block does not list.
4. A held provider whose entry is unchanged is kept. Unchanged means the same `kind` and the same verdict of the [checks](#checks), compared by its error text, and for a `wireguard` provider the same `listen_port` and `address_pool`, for a `tailscale` or `netbird` provider the same `auth_secret_name`; `slug`, `max_devices`, `devices` and the case of the id change in place. The verdict depends on the providers before it in the block, so a provider whose own members stay the same is rebuilt when an earlier provider of the block comes to take its interface name or its vendor kind: it is torn down, an up one included, and reads `invalid_provider`. The devices of a kept `wireguard` provider that is up are brought in line with the block by public key: a device the block no longer lists is removed with `RemovePeer`, and a new device, or one with another address, is configured with `ConfigurePeer`.
5. Any other provider is brought up, in block order. A held provider whose entry changed is torn down and brought up again; a `wireguard` provider keeps its key, because its id names the key file.

The manager never switches forwarding off: the provider's interface is deleted with the provider, and the forwarding of the mesh interface belongs to the bridge manager.

### Checks

Every listed provider is checked first. The first check that fails puts the provider down with `invalid_provider`, and the provider's `user access provider down` line carries the error text:

| Check | Kinds | Error text |
|---|---|---|
| The id is a UUID in canonical form, in either case, other than the zero UUID (`api.ValidUserAccessProviderID`) | every kind | `the id is no UUID other than the zero UUID` |
| No earlier provider of the block has the same id, compared without case | every kind | `an earlier provider of the block has the same id` |
| `listen_port` is 1 to 65535 | `wireguard` | `listen_port <n> is outside 1 to 65535` |
| `address_pool` is an IPv4 prefix of length 30 or shorter | `wireguard` | `address_pool "<pool>" is no IPv4 prefix of length 30 or shorter` |
| No earlier `wireguard` provider of the block takes the same interface name | `wireguard` | `an earlier provider of the block takes the interface name <name>` |
| `auth_secret_name` matches the Secret name grammar `^[a-z][a-z0-9_-]{0,62}$` (`api.ValidSecretName`) | `tailscale`, `netbird` | `auth_secret_name "<name>" is no Secret name` |
| No earlier provider of the block has the same kind | `tailscale`, `netbird` | `an earlier provider of the block has the kind <kind>` |

A provider whose id fails one of the first two checks gets no state: the control plane refuses a whole report for one such entry, so it has no entry in the report, and its `user access provider down` line is logged once while the block lists it. A `wireguard` provider claims its interface name, and a vendor provider its kind, whatever its other checks say, so a later provider's verdict depends only on the providers before it.

### Bringing Up a wireguard Provider

The first step that fails sets the provider's reason:

1. The checks above: `invalid_provider`.
2. Without a `MeshSourceRewriter`, on macOS and Windows: `kind_not_served`.
3. `InterfaceKeyStore.LoadOrCreate(id)` reads or creates the key file: `key_unavailable`.
4. `AccessController.CreateInterface(name, key, listen_port, address)`: `bind_failed` when the error wraps `ErrListenPortInUse`, `setup_failed` for any other error. The manager removes an interface of that name afterwards.
5. `RouteController.EnableForwarding(plexd0, name)`, then `MeshSourceRewriter.AddMeshSourceRewrite(name, plexd0)`: `setup_failed`. The manager removes the interface.
6. Each device becomes a peer. A device the bridge cannot serve is skipped, and the provider stays up.

The provider is then up, and `user access provider up` is logged. A device is skipped with the Warn `user access device not served` and one of these reasons, the first that applies:

| Reason | Cause |
|---|---|
| `invalid_public_key` | `public_key` is not 44 characters of standard base64 that decode to 32 bytes |
| `invalid_address` | `address` is no IPv4 address |
| `address_outside_pool` | `address` lies outside `address_pool` |
| `address_is_interface` | `address` is the interface's address |
| `duplicate_public_key` | An earlier device of the provider has the same key; the first one is served |
| `duplicate_address` | An earlier device of the provider has the same address; the first one is served |
| `configure_failed` | `ConfigurePeer` failed; the line carries `error`, and the next `Apply` tries again |

Each skip is logged once while it lasts.

### Bringing Up a tailscale or netbird Provider

The first step that fails sets the provider's reason (see [VPN Providers](vpn-providers.md) for the clients):

1. The checks above: `invalid_provider`.
2. Without a `MeshSourceRewriter`, on macOS and Windows, or without a client of the kind: `kind_not_served`.
3. A `tailscale` provider without a Domain mesh CIDR to advertise: `setup_failed`, before the inventory is read.
4. The secret inventory does not list `auth_secret_name`: `auth_secret_not_listed`.
5. The fetch of the Secret, in the version the inventory lists: `auth_secret_unreadable`.
6. `UserAccessClient.Start`: `client_missing` when the error wraps `exec.ErrNotFound`, `join_failed` for any other error.
7. The client reports no interface: the manager stops the client, `join_failed`.
8. `EnableForwarding` and `AddMeshSourceRewrite` for the client's interface: the manager stops the client, `setup_failed`.

Steps 5 to 7 run outside the manager's mutex, so `Teardown` and the status readers do not wait for the Secret fetch or the client's start. Step 8 runs under the mutex, and a join that finds the manager torn down by then stops the client it started. A provider whose first join still runs has no report entry until the join ends.

## Retry

No reconcile cycle fails for a provider, so one broken provider never makes the reconciler apply the whole snapshot again. A provider that is down is tried again by `Retry`, which `UserAccessPullHandler` calls on every successful pull, drift or not. `Retry` brings up again every provider that is down for a reason it retries and whose next attempt is due on the manager's clock. The delay after a failed attempt is 5 s, doubling with each further failure to at most 60 s (5 s, 10 s, 20 s, 40 s, 60 s), or the `Retry-After` of a `429` answer to the Secret fetch (`APIError.RetryAfter`) when that is longer. The count is of consecutive failed attempts, whatever their reason, and starts again when the provider comes up or its entry changes. A provider is tried again at the first pull after its delay has passed.

| Reason | Retried |
|---|---|
| `invalid_provider`, `kind_not_served` | No, until the entry changes |
| `key_unavailable`, `bind_failed`, `setup_failed`, `auth_secret_not_listed`, `auth_secret_unreadable`, `join_failed`, `client_missing` | Yes |

A changed entry is brought up at once by `Apply`, whatever its reason was. The Domain mesh CIDR is read once at start, so a `tailscale` provider down for the missing CIDR stays down with `setup_failed` until a restart finds one.

A vendor client that runs keeps its join when the inventory lists a new version of its Secret or stops listing it: the inventory is read only at a join, and the next join uses the version it lists then.

## User Access Status Report

A bridge reports with [`PUT /v1/nodes/{node_id}/user-access-status`](../core/api-endpoints.md#user-access-status) whether its local configuration serves user access, so the control plane refuses a provider or a device that no bridge would serve, and how each provider fares. The report is the only way the public key of a `wireguard` provider's interface reaches the control plane: `plexctl bridge user-access device config` renders a device's configuration only while the provider's state carries the key. Every node in bridge mode reports, whether or not it opts out, and a node outside bridge mode sends nothing. The control plane's side of the report is plexsphere/plexsphere#1108.

### Reported States

| State | `bridge.user_access_enabled` | Meaning |
|---|---|---|
| `enabled` | absent or `true` | The bridge serves the providers the pull enables |
| `opted_out` | `false` | The bridge built no user access manager and serves no provider whatever the pull says |

The state follows from the local configuration alone, so one process always reports the same state. An `opted_out` report carries the state alone: its body is exactly `{"state":"opted_out"}`.

### Provider Entries

An `enabled` report carries `providers`: one entry per provider of the last applied block, in block order, built from `UserAccessManager.ProviderReports`. A provider whose id fails the id checks has no entry, and a vendor provider whose first join still runs has none until the join ends.

| Provider | Members |
|---|---|
| down | `id`, `health` `down`, `reason` |
| `wireguard`, up | `id`, `health` `up`, `public_key`, `connected_devices` |
| `tailscale` or `netbird`, up | `id`, `health` `up` |

`id` is the provider's id as pulled. `public_key` is the public half of the interface's key, 44 characters of standard base64. `connected_devices` counts the devices configured on the interface whose latest WireGuard handshake is at most 180 s old on the manager's clock; a device whose handshake is 181 s old, a peer the block does not list, and a peer that never completed a handshake do not count. The count is sent when it is 0 and is cut to 1,024, the contract's ceiling. The manager reads the handshakes of each up `wireguard` provider once per report; a failed read counts 0 and is logged at Debug. A vendor entry carries neither member: the vendor's network manages its own keys, and the control plane records no devices for such a provider.

A report carries at most 256 entries (`api.MaxUserAccessStatusProviders`). A manager that reports more has the first 256 sent, in order, and the reporter logs the Warn `user access status: more providers than a report carries, reporting the first 256` with `providers` once on entering that state.

### Reasons

A reason is a token of the grammar `^[a-z][a-z0-9_]{0,62}$`, and the control plane stores any token of that grammar. plexd sends these:

| Token | Kinds | Meaning |
|---|---|---|
| `invalid_provider` | every kind | A member of the entry is malformed, or the entry clashes with an earlier one of the block (see [Checks](#checks)). Not retried until the entry changes |
| `kind_not_served` | every kind | This plexd serves no provider of the kind: the platform has no mesh source rewrite (macOS, Windows), the kind is unknown to it, or no client of the kind is built in. Not retried until the entry changes |
| `key_unavailable` | `wireguard` | The interface's key file could not be read, decoded or created |
| `bind_failed` | `wireguard` | The interface cannot listen on its `listen_port`, which another socket holds |
| `setup_failed` | `wireguard`, `tailscale`, `netbird` | The interface, its forwarding or its source rewrite could not be set up, or a `tailscale` provider has no Domain mesh CIDR to advertise |
| `auth_secret_not_listed` | `tailscale`, `netbird` | The secret inventory does not list `auth_secret_name`, a Secret the bridge may not read |
| `auth_secret_unreadable` | `tailscale`, `netbird` | The inventory lists the Secret, but the bridge could not fetch or open it |
| `join_failed` | `tailscale`, `netbird` | The client did not join the network with the key, or reports no interface after it did |
| `client_missing` | `tailscale`, `netbird` | The host has no client of the kind: its executable is not found |

`invalid_provider`, `setup_failed` and `key_unavailable` are plexd's additions to the contract's table, which lists the other six. The `UserAccessReason*` constants of `user_access.go` hold every token.

### Reporter

`UserAccessStatusReporter` (`user_access_status.go`) sends the report from a goroutine of its own. It follows the loop of the [ingress status reporter](public-ingress.md#reporter) as a type of its own.

```go
type UserAccessProviderReport struct {
    ProviderID       string
    Kind             string // the kind as pulled
    Health           string // api.UserAccessHealth*
    Reason           string // a UserAccessReason* while Health is down
    PublicKey        string // a wireguard provider's public key while it is up
    ConnectedDevices int    // a wireguard provider's connected devices while it is up
}

// UserAccessProviderReportSource is the part of *UserAccessManager the reporter reads.
type UserAccessProviderReportSource interface {
    ProviderReports() []UserAccessProviderReport
    ReportChanged() <-chan struct{}
}

func NewUserAccessStatusReporter(interval time.Duration, nodeID string, client UserAccessStatusClient,
    optedOut bool, providers UserAccessProviderReportSource, logger *slog.Logger) *UserAccessStatusReporter
func (r *UserAccessStatusReporter) Run(ctx context.Context) error // returns nil when ctx is done
```

`*api.ControlPlane` satisfies `UserAccessStatusClient`. The state is fixed at construction: `opted_out` when `optedOut` is true, `enabled` otherwise. `providers` is nil on an opted-out bridge. A non-positive `interval` becomes 30 s. The reporter's logger carries `component=bridge`.

`Run` logs `user access status: reporter started` with `interval` and `state`, sends one report at once, and then:

- **On a change.** When `ReportChanged` signals, it builds the report and does nothing when its entries equal those of the last accepted report in `id`, `health`, `reason` and `public_key`. Otherwise it sends when at least 5 s have passed since the last on-change send, and arms one timer for the rest of the 5 s when they have not. When the timer fires, it builds the report again and sends it only when its entries still differ from those of the last accepted report, so a change undone within the 5 s sends nothing. An on-change send restarts the interval.
- **On a tick.** It drops a pending change signal and the timer, and sends.
- **When `ctx` is done.** It returns nil and sends nothing.

A change of `connected_devices` alone sends nothing; the tick carries it. The manager signals `ReportChanged` without blocking at the end of every `Apply`, every `Retry`, and so every `SyncSecretInventory`, and `Teardown`. The send at start carries no entries, because no pull is applied yet; the first `Apply` signals, and the entries follow. A failed send is not retried within its tick, and the report never gates serving: the reporter only reads the manager.

Step 17d of `plexd up` starts `bridge.NewUserAccessStatusReporter(statusInterval, identity.NodeID, client, cfg.Bridge.UserAccessOptedOut(), userAccessProviders, logger)` beside the relay and the ingress status reporters, whenever bridge mode runs. `statusInterval` is `heartbeat.interval`, 30 s by default. `userAccessProviders` is the manager, or an untyped nil on a bridge that opts out.

### Answers

No answer stops the loop, and none changes what the bridge serves:

| Answer | Reporter behavior |
|---|---|
| `200 OK` | Debug `user access status: accepted` with `state`, `providers` (the number of entries sent) and `accepted_at` on every accepted send. Info `user access status: reported` with `state` and `providers` for the first accepted send. After a not-served phase, one Info `user access status: control plane accepts user access status reports` |
| `404` with any code but `user_access_status_node_gone`, or `501 user_access_status_not_provisioned` | The control plane does not serve the report, as `api.IsUserAccessStatusNotServed` classifies it. Info `user access status: control plane does not accept user access status reports, retrying every interval` with `status` and `code`, once on entering that state. plexd keeps reporting every interval and keeps serving as the pull says |
| `404 user_access_status_node_gone` | The node was removed while the request ran. Warn `user access status: rejected, this node was removed` with `code` on every send |
| `api.ErrCredentialRefused` | Debug `user access status: send failed` with `error`. The heartbeat parked the agent on a refused credential and names the cause once |
| Any error after `ctx` ended | Nothing, because that is the shutdown |
| Anything else, `400 malformed_user_access_status`, `400 invalid_user_access_status`, `413 user_access_status_body_too_large` and `context.DeadlineExceeded` included | Warn `user access status: send failed` with `error`, on every send |

### What the Control Plane Does

The control plane keeps the latest state per node and never ages it, so a bridge that reported `opted_out` and went offline stays opted out until it reports `enabled`. While a bridge's report reads `opted_out`, the control plane answers a create or an update of a provider, and a device admission, on its bridge Resource with `409 bridge_user_access_opted_out`. It keeps the providers and devices stored before the opt-out and keeps delivering them with `enabled: true`. The opted-out bridge ignores them, and serves them again once a restart without the opt-out makes it report `enabled`.

Each report replaces the provider entries of the one before. A bridge that has not reported for three heartbeat intervals has its providers read `stale`, and a provider the latest report does not name reads `not_reported`. A control plane that predates the report answers `404`, and plexd keeps serving as the pull says. See [User access status](https://github.com/plexsphere/plexsphere/blob/4935e06/docs/reference/api/plexd-agent-contract.md#user-access-status) in plexsphere's agent contract.

## Local Status

`UserAccessStatus()` feeds the node API's `status.user-access` report: whether the last applied block enabled user access, and one entry per provider the manager holds, with its slug, kind, interface, health, reason, listen port, configured devices and connected devices. A bridge that opts out, and a node outside bridge mode, publish `{"enabled": false}`. See [`status.user-access`](../core/nodeapi.md#status-user-access) for the payload.

## UserAccessManager

```go
type UserAccessDeps struct {
    Access        AccessController
    Routes        RouteController
    Rewriter      MeshSourceRewriter          // nil: this platform serves no provider
    Keys          *InterfaceKeyStore          // must not be nil
    Secrets       SecretValueFetcher          // must not be nil while Clients holds a client
    Clients       map[string]UserAccessClient // the vendor client of each vendor kind, by kind
    MeshInterface string
    MeshCIDR      string                      // the Domain mesh CIDR; empty when the node has none
    Logger        *slog.Logger
}

func NewUserAccessManager(deps UserAccessDeps) *UserAccessManager
```

The manager is concurrent-safe through a mutex. `Apply`, `SyncSecretInventory` and `Retry` are called from the reconciler's goroutine alone.

| Method | Signature | Description |
|---|---|---|
| `Setup` | `() error` | Runs `CleanupUserAccess`, creates the context the vendor clients run under and marks the manager active. A failed cleanup fails `Setup` with `bridge: user access: clean up: <error>`, and `plexd up` with `plexd up: user access setup: <error>`. Idempotent while active |
| `Apply` | `(ctx context.Context, block api.UserAccessConfig)` | Serves the block whole (see [Applying the Block](#applying-the-block)); a no-op while inactive |
| `SyncSecretInventory` | `(ctx context.Context, inventory []api.NodeStateSecret)` | Replaces the secret inventory the vendor providers read, then calls `Retry`; a no-op while inactive |
| `Retry` | `(ctx context.Context)` | Brings up again each provider that is down for a retried reason and whose next attempt is due (see [Retry](#retry)); a no-op while inactive |
| `Teardown` | `() error` | Stops every vendor client, removes every source rewrite and every interface, cancels the clients' context and keeps the key files. Idempotent; joins its errors |
| `ProviderReports` | `() []UserAccessProviderReport` | One report per provider with a valid, unrepeated id, in block order; nil while inactive |
| `ReportChanged` | `() <-chan struct{}` | Signalled, without blocking, when what `ProviderReports` returns may have changed; capacity 1 |
| `UserAccessStatus` | `() *api.UserAccessInfo` | The `status.user-access` payload; nil while inactive |

`Setup` exists because a killed process leaves its kernel interfaces behind, and the next `CreateInterface` for the same provider would fail on the name. The process the unit starts next removes them and brings each provider up again with its kept key, so a device connects again unchanged. `CleanupUserAccess` removes the nftables table `plexd-mesh-nat` for the same reason.

The inventory is a map from Secret name to version, filtered as the node API's [secret index](../core/nodeapi.md#secretindexdispatchhandler) filters it: the first entry of a name counts, and a name outside the grammar or a version below 1 counts as not listed. The manager holds no inventory until the first `SyncSecretInventory`.

## UserAccessReconcileHandler

```go
func UserAccessReconcileHandler(mgr *UserAccessManager, logger *slog.Logger) reconcile.ReconcileHandler
```

Returns a `reconcile.ReconcileHandler` that serves the pull's `bridge.user_access` block. `mgr` is nil on a bridge that opts out with `bridge.user_access_enabled: false`. The handler returns nil in every case: a provider that is down is retried by `UserAccessPullHandler`.

| `mgr` | Pulled block | What the handler does |
|---|---|---|
| any | nil snapshot | Returns nil |
| set | `Bridge` or `UserAccess` nil | Applies the zero block, which tears every provider down and deletes every key file |
| set | any block | Applies the block as it is; `Apply` serves providers only when `enabled` is `true` |
| nil | `enabled` true, at least one provider, and `diff.BridgeChanged` set | Logs the Warn `user access: the control plane enables user access, but bridge.user_access_enabled is false` with `providers=<n>`, and returns nil |
| nil | anything else | Returns nil without a log line |

Reconcile handlers run on every cycle with drift, a changed peer or policy included, so the Warn is gated on `BridgeChanged`: it is logged once per change of the pulled `bridge` block, the first pull after every start included.

## UserAccessPullHandler

```go
func UserAccessPullHandler(mgr *UserAccessManager) reconcile.DispatchHandler
```

The handler runs on the dispatch seam, on every successful pull, drift or not (see [DispatchHandler](../core/reconciliation.md#dispatchhandler)). A nil snapshot changes nothing. A nil `desired.Secrets` keeps the inventory the manager holds and calls `mgr.Retry`; any other block goes to `mgr.SyncSecretInventory`, which calls `Retry` itself. A pull whose only change is the `secrets` block reports no drift, so no reconcile handler would see a Secret the inventory newly lists, and a provider whose port was taken needs a retry whatever drifted. Dispatch handlers run before the reconcile handlers, so a cycle that brings a new provider and its Secret hands the inventory over before `Apply` reads it.

`cmd/plexd/cmd/up.go` registers `UserAccessReconcileHandler` whenever bridge mode runs, and `UserAccessPullHandler` only when the manager exists:

```go
if userAccessMgr != nil {
    reconciler.RegisterDispatchHandler(bridge.UserAccessPullHandler(userAccessMgr))
}
reconciler.RegisterHandler(bridge.UserAccessReconcileHandler(userAccessMgr, logger)) // nil on an opted-out bridge
```

## SSE Event Handling

There are no user access SSE handlers. The control plane emits a single `bridge_config_updated` event with an opaque payload; `bridge.HandleBridgeConfigUpdated` dispatches it to `TriggerReconcile()`, and the handlers above serve the block of the authoritative state snapshot. `node_secrets_updated` also only triggers a pull, whose `secrets` block reaches `UserAccessPullHandler`.

## AccessController

Interface abstracting the WireGuard interface of a `wireguard` provider.

```go
var ErrListenPortInUse = errors.New("listen port in use")

type AccessController interface {
    CreateInterface(name string, privateKey []byte, listenPort int, address string) error
    RemoveInterface(name string) error
    RemoveInterfaces(prefix string) error
    ConfigurePeer(iface, publicKey string, allowedIPs []string, psk string) error
    RemovePeer(iface, publicKey string) error
    PeerHandshakes(iface string) (map[string]time.Time, error)
}
```

| Method | Description |
|---|---|
| `CreateInterface` | Creates the interface, configures the 32-byte private key and the listen port, assigns `address` (a CIDR; empty leaves the interface unnumbered) and brings it up. A failure after the interface exists removes it again. A name that exists fails with an error wrapping `os.ErrExist` |
| `RemoveInterface` | Removes the interface by name; idempotent |
| `RemoveInterfaces` | Removes every WireGuard interface whose name starts with the prefix; idempotent |
| `ConfigurePeer` | Adds or updates a peer; idempotent |
| `RemovePeer` | Removes a peer by public key; idempotent |
| `PeerHandshakes` | The latest handshake of every peer, keyed by its public key in standard base64; the zero time for a peer that never completed one |

`NetlinkAccessController` (`access_controller_linux.go`) implements it on Linux through netlink and `wgctrl`. The kernel binds a WireGuard device's listen port when the device comes up, and again when the port changes on a device that is up, so a port another socket holds surfaces as `EADDRINUSE` from `LinkSetUp` or from `ConfigureDevice`. The controller wraps such an error with `ErrListenPortInUse`, which is what makes the manager report `bind_failed`; step 7 of the systemd suite's user access phase checks that a provider on the port `plexd0` holds reads `bind_failed` (see [Systemd E2E Test](../development/systemd-e2e-test.md#_17-user-access-through-a-bridge)). `RemoveInterfaces` refuses an empty prefix, which would match the mesh interface. It lists the links again while the kernel reports the dump as interrupted, up to three times.

`WGAccessController` (`access_controller_wg.go`) implements it on macOS and Windows over the platform `WGController`, a utun device or a Wintun adapter on the [userspace backend](../networking/wireguard.md#userspace-backend). It passes the key and the address through, reads handshakes through `wireguard.PeerStatsReader`, and returns nil from `RemoveInterfaces`, since a userspace device ends with its process. `plexd up` builds it on both platforms, and no provider reaches it there: one that passes its checks reads `kind_not_served`, and one that fails them reads `invalid_provider`.

## MeshSourceRewriter

```go
const UserAccessInterfacePrefix = "wg-ua-"

type MeshSourceRewriter interface {
    AddMeshSourceRewrite(fromIface, meshIface string) error
    RemoveMeshSourceRewrite(fromIface, meshIface string) error
    ResetMeshSourceRewrite() error
}

// CleanupUserAccess removes what a killed process left behind:
// access.RemoveInterfaces(UserAccessInterfacePrefix) and, with a rewriter,
// rewriter.ResetMeshSourceRewrite(). A nil access or rewriter is skipped;
// both run, and their errors are joined.
func CleanupUserAccess(access AccessController, rewriter MeshSourceRewriter) error
```

`NetlinkRouteController` implements the rewriter on Linux in an IPv4 nftables table of its own, `plexd-mesh-nat`, with one chain `postrouting` (type nat, hook postrouting, priority srcnat). `AddMeshSourceRewrite` adds one rule per provider interface, `iifname <fromIface> oifname <meshIface> counter masquerade`, tagged with the interface's name; masquerade gives the packet the address of the mesh interface, the bridge's mesh address. See [Netlink Route Controller](netlink-route-controller.md#mesh-source-rewrite).

The rewriter is a dependency of its own, not a method of `NATController`, so the pf and WinNAT backends do not implement it. `cmd/plexd/cmd/up_linux.go` builds it with `newMeshSourceRewriter(routeCtrl)`, which returns the `NetlinkRouteController`; the macOS, Windows and other builds return nil, which makes every provider that passes its checks read `kind_not_served`.

## InterfaceKeyStore

```go
func NewInterfaceKeyStore(dir string) *InterfaceKeyStore
func (s *InterfaceKeyStore) LoadOrCreate(id string) (wgtypes.Key, error)
func (s *InterfaceKeyStore) Prune(keep map[string]struct{}) error
```

`plexd up` builds the store over `<data_dir>/user-access`. `LoadOrCreate` returns the key stored for the id, and generates, writes and returns one when there is none (see [The Key File](#the-key-file)). `Prune` deletes the key file of every id not in `keep`; a directory that does not exist is no error, and a failed deletion does not stop the others. The store is safe for concurrent use and carries no user access wording, because site-to-site tunnels will keep their keys with it ([#212](https://github.com/plexsphere/plexd/issues/212)).

## Wiring in plexd up

Step 5e of `plexd up` builds the manager on a bridge that does not opt out:

```go
userAccessMgr = bridge.NewUserAccessManager(bridge.UserAccessDeps{
    Access:   newAccessController(logger),
    Routes:   routeCtrl,
    Rewriter: newMeshSourceRewriter(routeCtrl),
    Keys:     bridge.NewInterfaceKeyStore(filepath.Join(cfg.DataDir, "user-access")),
    Secrets:  secrets, // nodeSecretFetcher
    Clients: map[string]bridge.UserAccessClient{
        api.UserAccessKindTailscale: bridge.NewTailscaleProvider(bridge.NewStdCommandExecutor(), logger),
        api.UserAccessKindNetbird:   bridge.NewNetbirdProvider(bridge.NewStdCommandExecutor(), logger),
    },
    MeshInterface: cfg.WireGuard.InterfaceName,
    MeshCIDR:      userAccessMeshCIDR(wgMgr.MeshPrefix()),
    Logger:        logger,
})
if err := userAccessMgr.Setup(); err != nil {
    return fmt.Errorf("plexd up: user access setup: %w", err)
}
```

`userAccessMeshCIDR` returns the Domain mesh prefix, masked to its network, and an empty string for a prefix that is not valid or covers a single address: the WireGuard manager falls back to the mesh IP's `/32` when the identity carries no usable `domain_mesh_cidr`, and a route to the bridge alone would reach no other node. The shutdown sequence calls `Teardown` after the ingress manager's and logs a failure as `user access teardown error`.

## API Types

### UserAccessConfig

`api.BridgeSnapshot.UserAccess`, present-but-nullable.

```go
type UserAccessConfig struct {
    Enabled   bool                 `json:"enabled"`
    Providers []UserAccessProvider `json:"providers"`
}

type UserAccessProvider struct {
    ID             string             `json:"id"`
    Slug           string             `json:"slug"`
    Kind           string             `json:"kind"`
    ListenPort     int                `json:"listen_port,omitempty"`
    AddressPool    string             `json:"address_pool,omitempty"`
    MaxDevices     int                `json:"max_devices,omitempty"`
    Devices        []UserAccessDevice `json:"devices,omitempty"`
    AuthSecretName string             `json:"auth_secret_name,omitempty"`
}

type UserAccessDevice struct {
    ID        string `json:"id"`
    Slug      string `json:"slug"`
    PublicKey string `json:"public_key"`
    Address   string `json:"address"`
}

const (
    UserAccessKindWireGuard = "wireguard"
    UserAccessKindTailscale = "tailscale"
    UserAccessKindNetbird   = "netbird"
)

func ValidUserAccessProviderID(s string) bool // the check of ValidIngressRuleID
```

The reconciler's snapshot copies the providers and each provider's devices, so a change to a copy leaves the stored snapshot as it was. `StateDiff.BridgeChanged` covers the block.

The report's types, `UserAccessStatusRequest`, `UserAccessStatusProvider` and `UserAccessStatusResponse`, are listed in [API Types](../core/api-types.md#user-access-status), and the local payload `UserAccessInfo` in [`status.user-access`](../core/nodeapi.md#status-user-access).

## Error Prefixes

| Source | Prefix |
|---|---|
| `Config.Validate` | `bridge: config: user access requires bridge mode to be enabled` |
| `UserAccessManager.Setup` | `bridge: user access: clean up: ` |
| `plexd up` (setup) | `plexd up: user access setup: ` |
| `UserAccessManager.Teardown` (client) | `bridge: user access: stop <kind> client: ` |
| `UserAccessManager.Teardown` (interface) | `bridge: user access: remove interface <iface>: ` |
| `UserAccessManager.Teardown` (rewrite) | `bridge: user access: remove mesh source rewrite <iface>: ` |
| The `error` of a provider down for its forwarding | `enable forwarding: ` |
| The `error` of a provider down for its source rewrite | `add mesh source rewrite: ` |
| `InterfaceKeyStore` | `bridge: key store: ` |

The `error` of a provider down for one of the checks is the text the [Checks](#checks) table lists; the others are `this platform has no mesh source rewrite`, `kind "<kind>" is not known`, `no <kind> client is built in`, `the node has no mesh CIDR to advertise`, `the secret inventory does not list "<name>"` and `the client reports no interface`. The controller carries prefixes of its own:

| Step | Prefix |
|---|---|
| Private key parse | `bridge: access: parse private key:` |
| Address parse | `bridge: access: parse address "<cidr>":` |
| Interface creation | `bridge: access: create interface <name>:` |
| Device configuration (key, port) | `bridge: access: configure device:` |
| Address assignment | `bridge: access: configure address <cidr>:` |
| Bringing the interface up | `bridge: access: set interface up:` |
| Removal after a failed create | `bridge: access: remove interface <name> after a failed create:` |
| Interface removal | `bridge: access: remove interface:` |
| Removal by prefix | `bridge: access: remove interfaces:` |
| Handshake read | `bridge: access: peer handshakes:` |
| Opening wgctrl | `bridge: access: open wgctrl:` |
| Peer public key decode | `bridge: access: decode public key:` |
| Peer public key parse | `bridge: access: parse public key:` |
| Allowed IP parse | `bridge: access: parse allowed IP "<cidr>":` |
| PSK decode | `bridge: access: decode psk:` |
| PSK parse | `bridge: access: parse psk:` |
| Peer programming | `bridge: access: configure peer:` |
| Peer removal | `bridge: access: remove peer:` |

The `configure device` and `set interface up` errors of a taken port read `bridge: access: <step>: listen port in use: <cause>`. The address parse, the device configuration, the removal after a failed create, the removal by prefix and the opening of wgctrl are steps of the Linux controller alone. On macOS and Windows the text after a prefix is the `wireguard:` controller's own message.

## Logging

All user access log entries use `component=bridge`, the reporter's included, except `user access teardown error` and `bridge subsystem initialized`, which `plexd up` logs without it. `bridge subsystem initialized` carries `user_access=false` on a bridge that opts out.

| Level | Message | Keys |
|---|---|---|
| `Info` | `user access manager started` | (none) |
| `Info` | `user access manager stopped` | (none); logged by a `Teardown` without errors |
| `Info` | `user access provider up` | `provider_id`, `slug`, `kind`, `interface`, and `listen_port` for a `wireguard` provider |
| `Warn` | `user access provider down` | `provider_id`, `slug`, `kind`, `reason`, `error`; once per change of the provider's reason, and once while the block lists a provider without state |
| `Info` | `user access provider removed` | `provider_id`, `interface` (empty for a provider that was down); not logged when a changed provider is rebuilt |
| `Warn` | `user access device not served` | `provider_id`, `device_id`, `reason`, and `error` for `configure_failed`; once while the skip lasts |
| `Warn` | `user access: the control plane enables user access, but bridge.user_access_enabled is false` | `providers`; once per change of the pulled `bridge` block, on a bridge that opts out |
| `Warn` | `bridge: config: user access keys are ignored, the control plane delivers providers` | `keys`; logged by step 5e of `plexd up` |
| `Info` | `user access: opted out by bridge.user_access_enabled, no provider is served` | (none); logged by step 5e of `plexd up` on a bridge that opts out |
| `Info` | `user access status: reporter started` | `interval`, `state` |
| `Info` | `user access status: reported` | `state`, `providers`; logged for the first accepted send |
| `Info` | `user access status: control plane does not accept user access status reports, retrying every interval` | `status`, `code`; logged on entering the not-served state only |
| `Info` | `user access status: control plane accepts user access status reports` | (none); logged once after a not-served phase |
| `Warn` | `user access status: rejected, this node was removed` | `code`; logged on every send |
| `Warn` | `user access status: send failed` | `error` |
| `Warn` | `user access status: more providers than a report carries, reporting the first 256` | `providers`; once on entering that state |
| `Debug` | `user access status: accepted` | `state`, `providers`, `accepted_at` |
| `Debug` | `user access status: send failed` | `error`; logged instead of the Warn while the client holds a refused credential (`api.ErrCredentialRefused`) |
| `Debug` | `bridge: user access: read handshakes failed` | `provider_id`, `interface`, `error` |
| `Error` | `bridge: user access: clean up failed` | `error`; logged by step 5e of `plexd up` on a bridge that opts out |
| `Error` | `bridge: user access: tear down provider failed` | `provider_id`, `interface`, `error` |
| `Error` | `bridge: user access: prune keys failed` | `error` |
| `Error` | `bridge: user access: remove device failed` | `provider_id`, `device_id`, `error` |
| `Error` | `bridge: user access: stop client failed` | `provider_id`, `kind`, `error` |
| `Error` | `user access teardown error` | `error`; logged by the shutdown of `plexd up` |
| `Info` | `access interface created` | `interface`, `listen_port` |
| `Info` | `access interface removed` | `interface` |
| `Debug` | `access interface addressed` | `interface`, `address` |
| `Debug` | `access peer configured` | `interface` |
| `Debug` | `access peer removed` | `interface` |

No log line and no error carries a key or a Secret's value. The vendor clients' own lines are listed in [VPN Providers](vpn-providers.md#logging), and the source rewrite's in [Netlink Route Controller](netlink-route-controller.md#mesh-source-rewrite).
