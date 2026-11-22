---
title: API Types
package: internal/api
feature: PXD-0001
---

# API Types

All request/response types for the control plane API endpoints, organized by endpoint group. All types use JSON struct tags matching the API specification.

## Registration

### `POST /v1/register`

Unauthenticated (`security: []`): the bootstrap token travels in the request
body, not an `Authorization` header. Success is `201 Created`; errors use RFC
9457 `application/problem+json`. See [Control Plane API Endpoints](api-endpoints.md)
for the wire examples and error taxonomy.

**RegisterRequest**

| Field                 | Type     | JSON Tag                            | Constraints                     |
|-----------------------|----------|-------------------------------------|---------------------------------|
| `ProjectID`           | `string` | `"project_id"`                      | Required. Platform project UUID. |
| `ResourceHandle`      | `string` | `"resource_handle"`                 | Required. Platform Resource handle. |
| `BootstrapToken`      | `string` | `"bootstrap_token"`                 | Required. Format `psb_<env>_<project>_<kind>_<random>`, matching `^psb_[a-z]+_[a-z2-7]+_(node\|bridge)_[a-z2-7]{20,}$`. |
| `Nonce`               | `string` | `"nonce"`                           | Required. Fresh UUIDv4 generated per registration attempt (server-side replay protection). |
| `PublicKey`           | `string` | `"public_key"`                      | Required. Curve25519 public key as 44-char standard base64, matching `^[A-Za-z0-9+/]{43}=$`. |
| `RequestedResourceID` | `string` | `"requested_resource_id,omitempty"` | Optional. Resource ID override when substrate naming differs from the handle. |

`hostname`, `metadata`, and `capabilities` are no longer part of registration.
Capabilities are published after registration via `PUT /v1/nodes/{node_id}/capabilities`.

**RegisterResponse** (`201 Created`)

| Field              | Type            | JSON Tag               | Description                        |
|--------------------|-----------------|------------------------|------------------------------------|
| `NodeID`           | `string`        | `"node_id"`            | Assigned node identifier (UUID)    |
| `MeshIP`           | `string`        | `"mesh_ip"`            | Assigned mesh IP address           |
| `SigningPublicKey` | `string`        | `"signing_public_key"` | Control plane signing public key   |
| `SigningKeyID`     | `string`        | `"signing_key_id"`     | Signing key id for rotation-aware signature verification (e.g. `did:web:plexsphere.com#key-2026-04`) |
| `NSK`              | `string`        | `"nsk"`                | Node secret key, returned exactly once: 44-char standard-padded base64 that decodes to the 32-byte AES-256-GCM key. Never sent as it is: the bearer credential is the envelope `BearerToken()` builds from the node ID and the decoded key (see [BearerToken](registration.md#bearertoken)). Decoded before use as a key |
| `PeerSnapshot`     | `[]RegisterPeer`| `"peer_snapshot"`      | Initial peer snapshot              |
| `DomainMeshCIDR`   | `string`        | `"domain_mesh_cidr"`   | Domain mesh address range (e.g. `100.64.0.0/10`) |

**RegisterPeer**

| Field              | Type     | JSON Tag                       | Description                     |
|--------------------|----------|--------------------------------|---------------------------------|
| `NodeID`           | `string` | `"node_id"`                    | Peer node ID                    |
| `MeshIP`           | `string` | `"mesh_ip"`                    | Peer mesh IP address            |
| `PublicKey`        | `string` | `"public_key"`                 | Peer Curve25519 public key      |
| `FallbackEndpoint` | `string` | `"fallback_endpoint,omitempty"`| Optional fallback WireGuard endpoint |

`RegisterPeer` is deliberately narrow: it carries **no** `psk`, `allowed_ips`, or
`endpoint`. The reconciliation peer shape is `SnapshotPeer` (see
[State](#state)), used by `GET /v1/nodes/{node_id}/state`.

**Peer**

`Peer` is the internal WireGuard programming shape. The wireguard package builds
it from a `SnapshotPeer` (see [State](#state)) and never reads it off the wire:
the state pull carries `SnapshotPeer`, and plexd never decodes the payloads of the
SSE `peer_*` events.

| Field        | Type       | JSON Tag       | Description                |
|--------------|------------|----------------|----------------------------|
| `ID`         | `string`   | `"id"`         | Peer node ID               |
| `PublicKey`  | `string`   | `"public_key"` | WireGuard public key       |
| `MeshIP`     | `string`   | `"mesh_ip"`    | Mesh IP address            |
| `Endpoint`   | `string`   | `"endpoint"`   | First entry of `Endpoints`, or empty when the peer has no endpoint to dial |
| `Endpoints`  | `[]string` | `"endpoints,omitempty"` | The peer's dial order: the endpoints the WireGuard manager tries one after another until a handshake completes (see [Dial order](../networking/wireguard.md#dial-order)) |
| `Fallbacks`  | `[]string` | `"fallbacks,omitempty"` | The peer's relays as they end `Endpoints`, in dial order: the relay of its assigned bridge first, then its standby relays. Nil when the peer has no relay. Endpoint selection holds each relay as long as the entries before the first relay took together, and only a peer that connected over a relay dials the standbys (see [The trial](../networking/wireguard.md#the-trial)) |
| `AllowedIPs` | `[]string` | `"allowed_ips"`| `mesh_ip/32` followed by `RoutedSubnets`, derived locally |
| `PSK`        | `string`   | `"psk"`        | Edge PSK fetched for the peer's current public key, standard base64; empty when plexd holds none |
| `RoutedSubnets` | `[]string` | `"routed_subnets,omitempty"` | The entries of the peer's `routed_subnets` this node accepted, in the list's order and in canonical form; nil when it accepted none. The WireGuard manager routes each through the mesh interface (see [Routed subnets](../networking/wireguard.md#routed-subnets)) |

## Heartbeat

### `POST /v1/nodes/{node_id}/heartbeat`

**HeartbeatRequest**

| Field            | Type             | JSON Tag            | Description                    |
|------------------|------------------|---------------------|--------------------------------|
| `ClientNow`      | `time.Time`      | `"client_now"`      | RFC 3339 UTC send time, stamped fresh per request; the server rejects a skew above 60s |
| `BinaryChecksum` | `string`         | `"binary_checksum"` | SHA-256 of the running binary (64-char hex or 44-char base64 of 32 bytes) |
| `BinaryVersion`  | `string`         | `"binary_version"`  | Build version (`dev` when unset); never empty |
| `NATSummary`     | `map[string]any` | `"nat_summary"`     | Always a JSON object: `{}` before discovery, else `{"endpoint", "nat_type"}` |

`nat_summary` is a `map[string]any` rather than a nil-able pointer so it always
marshals to an object: a nil map would emit `null`, which the control plane
rejects with `malformed_heartbeat_request`.

The in-memory NAT discovery result that feeds `nat_summary` is
[`nat.DiscoveryResult`](../networking/nat-traversal.md#discoveryresult); it is
never serialized on its own.

**HeartbeatResponse**

| Field        | Type        | JSON Tag        | Description                       |
|--------------|-------------|-----------------|-----------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time (used for skew estimation) |
| `Reconcile`  | `bool`      | `"reconcile"`   | Whether to trigger reconciliation |
| `RotateKeys` | `bool`      | `"rotate_keys"` | Whether to rotate keys            |

## State

### `GET /v1/nodes/{node_id}/state`

**NodeStateSnapshot**

The desired-state envelope. Every block key is **always present on the wire**: a
`null` value means "block not populated", never "field absent", so the differ
distinguishes a nil pointer from a populated block. None of the thirteen fields
carry `omitempty`.

| Field          | Type                   | JSON Tag         | Description                                              |
|----------------|------------------------|------------------|---------------------------------------------------------|
| `Peers`        | `[]SnapshotPeer`       | `"peers"`        | Desired peers; `[]` when empty, node_id ascending, self excluded |
| `Reachability` | `json.RawMessage`      | `"reachability"` | The control plane's verdict about this node, carried opaquely and decoded leniently by the reachability observer |
| `Policy`       | `*PolicySnapshot`      | `"policy"`       | Merged network policy block                             |
| `Bridge`       | `*BridgeSnapshot`      | `"bridge"`       | Bridge subtrees                                         |
| `State`        | `*NodeStateBlock`      | `"state"`        | Node state buckets                                     |
| `Reports`      | `*NodeStateBlock`      | `"reports"`      | Mirrors `state` today (forward-compat split)           |
| `Executions`   | `[]NodeStateExecution` | `"executions"`   | Pending action dispatches; `[]` when empty, never `null` |
| `Sessions`     | `*[]NodeStateSession`  | `"sessions"`     | Live mediated-access sessions; `[]` when empty, never `null` on the wire. A pointer, like the block fields above: a `nil` value is a block the control plane did **not** populate, which is not a teardown signal |
| `Secrets`      | `*[]NodeStateSecret`   | `"secrets"`      | The node's secret inventory, ordered by name ascending; `[]` when the node may read nothing, never `null` on the wire. A pointer, like `Sessions`: a `nil` value (the wire's `null`, or a pull from a control plane that predates the block and omits it) keeps the node API's secret index, and `[]` empties it |
| `SigningKey`   | `*NodeStateSigningKey` | `"signing_key"`  | The key the node's Domain signs envelopes and session tokens with. A `nil` value (the wire's `null`, or a pull from a control plane that predates the block and omits it) means "keep the key you hold", never "drop it" |
| `Hooks`        | `*[]NodeStateHook`     | `"hooks"`        | The published hook versions a rollout assigns the node, ordered by name ascending: the node's full desired set. A pointer, like `Secrets`: `[]` removes every rolled-out hook, and a `nil` value (the wire's `null`, which the control plane sends when it could not compute the set, or a pull from a control plane that predates the block and omits it) keeps every one |
| `DNS`          | `*NodeStateDNS`        | `"dns"`          | The mesh DNS names of the node's Domain and the node's DNS forwarding setting: the full set, never a delta, which replaces the names the node answers. A `nil` value (the wire's `null`, or a pull from a control plane that predates the block and omits it) keeps the names and the forwarding the node holds |
| `FailureDetection` | `json.RawMessage` | `"failure_detection"` | The Domain's failure-detection time, a `NodeStateFailureDetection`, carried raw like `Reachability` and decoded leniently by the WireGuard manager's dispatch handler, so a malformed block never fails the pull. A `nil` value (the wire's `null`, or a pull from a control plane that predates the block and omits it) keeps the value the node holds |

Eight members are consumed on the dispatch seam rather than by the differ.
`executions` is not desired state at all — it is a delivery queue, documented
under [Executions](#executions) below. `sessions` *is* desired state, but state
the tunnel dispatcher converges on itself, documented under
[Sessions](#sessions) below. `reachability` is not state to converge on either:
the reachability observer decodes it leniently and logs the verdict when it
changes. `signing_key` has nothing to converge on: the first dispatch handler
installs and persists it (see `NodeStateSigningKey` below).
`secrets` is never diffed: the node API's `SecretIndexDispatchHandler` replaces
the secret index from it on every successful pull (see `NodeStateSecret` below).
`hooks` is never diffed either: the rollout installer's dispatch handler hands it
to the installer on every successful pull (see `NodeStateHook` below).
`dns` is never diffed either: the mesh resolver's dispatch handler builds the
names it answers and the table it forwards with from it on every successful
pull (see `NodeStateDNS` below).
`failure_detection` is never diffed either: the WireGuard manager's
`FailureDetectionDispatchHandler` decodes it on every successful pull and hands
the time to the manager (see `NodeStateFailureDetection` below).
`peers` goes to both: the differ drives the WireGuard reconcile handler
from it, and the edge PSK store reads it on the dispatch seam.
`policy` goes to both as well: the differ reports a new fingerprint as policy
drift in the cycle log, and the policy dispatch handler applies the block on
every successful pull (see
[DispatchHandler](../networking/network-policy.md#dispatchhandler)).

**SnapshotPeer**

Carries the peer's direct `endpoint`, its `endpoint_candidates` and its
`routed_subnets` but **no** `psk` or `allowed_ips`. plexd derives `AllowedIPs`
locally as `mesh_ip/32` followed by the entries of `routed_subnets` it accepts
(see [Routed subnets](../networking/wireguard.md#routed-subnets)). plexd
builds the peer's dial order from the candidates on a subnet this node is also
on, then `endpoint` when it is usable, then the remaining candidates, then the
peer's relays (`fallback_endpoints`, or `fallback_endpoint` alone when that list
is absent or empty), and keeps the first entry that completes
a WireGuard handshake (see [Dial order](../networking/wireguard.md#dial-order)
and [Endpoint selection](../networking/wireguard.md#endpoint-selection)).
Unless `wireguard.edge_psk` is `false`, plexd fetches the pairwise edge PSK per
edge from `GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk` (see
[Edge PSK](#edge-psk)).

A direct endpoint or candidate is usable when it parses as an IP address and
port with a non-zero port and no zone, its address (an IPv4-mapped address is
unmapped first) is not unspecified, loopback, multicast or link-local, and it
lies outside the Domain mesh prefix. plexd leaves a refused one out of the
order, logging a refused `endpoint` at Warn and refused candidates at Debug.
plexd does not validate the relays in `fallback_endpoints` or
`fallback_endpoint`, because the contract allows a hostname there. It skips an
empty relay entry and a repeated one, and it does not cap the list. When
`fallback_endpoints` is not empty, the dial order does not use
`fallback_endpoint`, and plexd does not check that the two agree.

| Field              | Type     | JSON Tag                        | Description                   |
|--------------------|----------|---------------------------------|-------------------------------|
| `NodeID`           | `string` | `"node_id"`                     | Peer node ID                  |
| `MeshIP`           | `string` | `"mesh_ip"`                     | Peer mesh IP address          |
| `PublicKey`        | `string` | `"public_key"`                  | Peer WireGuard public key     |
| `Endpoint`         | `string` | `"endpoint,omitempty"`          | Peer's direct WireGuard endpoint as `host:port` (an IPv6 host in brackets), the address it last reported through `PUT /v1/nodes/{node_id}/endpoint`; absent while the peer has no fresh observation |
| `FallbackEndpoint` | `string` | `"fallback_endpoint,omitempty"` | The first entry of `FallbackEndpoints`, and the only relay a control plane that predates the set sends. The dial order uses it only when `FallbackEndpoints` is empty. Absent while the peer has no relay |
| `FallbackEndpoints` | `[]string` | `"fallback_endpoints,omitempty"` | The peer's relays as `host:port` (an IPv6 host in brackets) in dial order, at most 4 by the contract: the relay of the peer's assigned bridge first, then its standby relays. Both nodes of a pair receive the same list for each other, and it never names this node. Absent while the peer has no relay; `null` reads as absent |
| `EndpointCandidates` | `[]string` | `"endpoint_candidates,omitempty"` | The peer's endpoint candidates as `host:port` strings, at most 8: first its peer-observed endpoints, the addresses at which at least two live nodes of the Domain report a direct handshake with it, then its last accepted, unexpired local candidates (`PUT /v1/nodes/{node_id}/endpoint-candidates`) in the order it sent them (see [State](api-endpoints.md#get-v1-nodes-node-id-state)); absent when the peer has none and on every control plane that does not deliver them |
| `RoutedSubnets` | `[]string` | `"routed_subnets,omitempty"` | The IPv4 networks the control plane routes through the peer as CIDRs: the networks behind the site-to-site tunnels of a peer that is a bridge, each once, sorted. Delivered only to the nodes of the bridge Resource's Project, absent for a peer that routes no network, and never carried by the registration response. plexd adds the entries it accepts to the peer's allowed IPs and routes them through the mesh interface, and skips one that is malformed, overlaps the mesh prefix, lies inside a network of this host's interfaces or repeats an earlier one. The differ compares the list in order; absent and `[]` compare equal |

**ReachabilitySnapshot**

The interior of the `reachability` block. `NodeStateSnapshot.Reachability` stays
a `json.RawMessage`: decoding it inside `FetchState` would let a malformed
diagnostic block abort the whole state pull, so the decode happens in the
reachability observer instead.

`State` is a plain string and is **never validated** against the constants below.
The verdict vocabulary belongs to the control plane and grows there —
`never_reported` was added after plexd shipped — so a value this build does not
know is logged verbatim rather than rejected.

| Field             | Type         | JSON Tag                          | Description                                              |
|-------------------|--------------|-----------------------------------|----------------------------------------------------------|
| `State`           | `string`     | `"state"`                         | `ReachabilityHealthy` (`healthy`), `ReachabilityStale` (`stale`), `ReachabilityUnreachable` (`unreachable`), or `ReachabilityNeverReported` (`never_reported`); any other value is carried through |
| `LastHeartbeatAt` | `*time.Time` | `"last_heartbeat_at,omitempty"`   | Absent until the control plane accepts the first heartbeat |
| `ChangedAt`       | `time.Time`  | `"changed_at"`                    | When the verdict last changed; always present            |

**PolicySnapshot**

The single merged policy block. Every rule is an allow and rule order carries no meaning: traffic no rule allows is dropped.

| Field         | Type           | JSON Tag          | Description                                                     |
|---------------|----------------|-------------------|-----------------------------------------------------------------|
| `RevisionID`  | `string`       | `"revision_id"`   | Policy revision identifier                                      |
| `Fingerprint` | `string`       | `"fingerprint"`   | 44-char base64 SHA-256 over the server's canonical rule stream; plexd compares it byte-for-byte and never re-derives it |
| `Rules`       | `[]PolicyRule` | `"rules"`         | Allow rules, in no meaningful order                             |
| `Revisions`   | `[]PolicyRevisionRef` | `"revisions,omitempty"` | The (Policy, revision) pair of every compiled row the block merges, in ascending `policy_id`, the order `Fingerprint` covers. The first pair's `revision_id` equals `RevisionID`. `nil` when the control plane sends none, as one before plexsphere/plexsphere#1059 does. plexd echoes the pairs in its [policy status report](#policy-status) and never parses them |

`func (p *PolicySnapshot) Clone() *PolicySnapshot` returns a deep copy: its `Rules`, each rule's `Ports` and `LegacyAction`, and its `Revisions` share no memory with `p`. A `nil` receiver yields `nil`. The reconciler's stored snapshot copies the block through it, and so does the Enforcer's record of the applied, the received and the rejected block.

**PolicyRevisionRef**

Names one revision of one Policy. Both ids are UUIDs that plexd passes through as strings.

| Field        | Type     | JSON Tag        | Description                    |
|--------------|----------|-----------------|--------------------------------|
| `PolicyID`   | `string` | `"policy_id"`   | The Policy's id                |
| `RevisionID` | `string` | `"revision_id"` | The id of the Policy's revision the block compiled |

**PolicyRule**

Allows the traffic from `SourceCIDR` to `DestinationCIDR` that its protocol and port range match. Both prefixes are IPv4 or both IPv6. `Ports` is present iff `Protocol` is `tcp` or `udp`.

| Field             | Type         | JSON Tag             | Description                              |
|-------------------|--------------|----------------------|------------------------------------------|
| `Protocol`        | `string`     | `"protocol"`         | `tcp`, `udp`, `icmp`, or `any`; `icmp` in an IPv6 rule is ICMPv6 |
| `SourceCIDR`      | `string`     | `"source_cidr"`      | Source prefix, IPv4 or IPv6; `0.0.0.0/0` is every IPv4 address and `::/0` every IPv6 address. An IPv4-mapped IPv6 prefix such as `::ffff:10.0.0.1/128` is invalid |
| `DestinationCIDR` | `string`     | `"destination_cidr"` | Destination prefix, of the source's family |
| `Ports`           | `*PortRange` | `"ports,omitempty"`  | Inclusive destination port range        |
| `Log`             | `bool`       | `"log,omitempty"`    | Asks for the rule's traffic to be logged; absent, `null` and `false` mean the same. plexd logs `policy rule allowed connection` for each connection the rule allows; see [Connection logging](../networking/network-policy.md#connection-logging) |
| `LegacyAction`    | `*string`    | `"action,omitempty"` | The `action` key of the format before plexsphere/plexsphere#1058; `nil` when the key is absent. `allow` reads as an allow, and any other value, `""` included, rejects the revision |

A `log` that is not a boolean, such as `"yes"`, fails the decode of the whole state pull with a `*json.UnmarshalTypeError`, as any mistyped field of the snapshot does, so the pull fails and the previous ruleset stays. The node API's [`GET /v1/policies`](nodeapi.md#get-v1-policies) serves the block plexd applied, as it decoded it, so a rule carries `action` there only when the control plane sent one, and `log` only when it is `true`. See [BuildFirewallRules](../networking/network-policy.md#buildfirewallrules) for how plexd translates the rules.

**PortRange**

A single inclusive destination port range (`from <= to`).

| Field  | Type  | JSON Tag  | Description       |
|--------|-------|-----------|-------------------|
| `From` | `int` | `"from"`  | Range start port  |
| `To`   | `int` | `"to"`    | Range end port    |

**BridgeSnapshot**

Carries the four bridge subtrees. Each child is present-but-nullable; there are
no base fields on the wire. `RelayConfig`, `RelayAssignment`, `UserAccessConfig`,
`UserAccessProvider`, `UserAccessDevice`, `IngressConfig`, `IngressRule`,
`SiteToSiteConfig` and `SiteToSiteTunnel` follow below.

| Field        | Type                | JSON Tag           | Description                     |
|--------------|---------------------|--------------------|---------------------------------|
| `Relay`      | `*RelayConfig`      | `"relay"`          | Relay request: whether this bridge relays, on which UDP port, and the peers whose first relay it is |
| `UserAccess` | `*UserAccessConfig` | `"user_access"`    | User access providers; `null` or absent serves no provider and deletes every provider's key file |
| `Ingress`    | `*IngressConfig`    | `"ingress"`        | Public ingress rules; `null` or absent closes every public listener |
| `SiteToSite` | `*SiteToSiteConfig` | `"site_to_site"`   | Site-to-site tunnels; `null` or absent serves no tunnel and deletes every tunnel's key file |

**RelayConfig**

The `bridge.relay` block, the control plane's `NodeStateBridgeRelay`. A bridge
relays only when both its local `bridge.relay_enabled` and `Enabled` are true;
it then listens on `ListenPort` and forwards among the peers of the same pull.
See [NAT Relay](/reference/bridge/nat-relay).

| Field         | Type                | JSON Tag          | Description                                  |
|---------------|---------------------|-------------------|----------------------------------------------|
| `Enabled`     | `bool`              | `"enabled"`       | Whether the control plane asks this bridge to relay |
| `ListenPort`  | `int`               | `"listen_port"`   | UDP port the relay listens on; authoritative |
| `Assignments` | `[]RelayAssignment` | `"assignments"`   | Peers whose first relay is this bridge; a peer that has this bridge only as a standby relay is not listed. Decoded and carried; the relay does not read it |

**RelayAssignment**

| Field                  | Type     | JSON Tag                   | Description                              |
|------------------------|----------|----------------------------|------------------------------------------|
| `PeerNodeID`           | `string` | `"peer_node_id"`           | Node ID of a peer whose first relay is this bridge |
| `FallbackEndpoint`     | `string` | `"fallback_endpoint"`      | Host of that peer's first relay          |
| `FallbackEndpointPort` | `int`    | `"fallback_endpoint_port"` | Port of that peer's first relay          |

**UserAccessConfig**

The `bridge.user_access` block, the control plane's `NodeStateBridgeUserAccess`,
which it delivers since
[plexsphere/plexsphere#1108](https://github.com/plexsphere/plexsphere/pull/1108).
A bridge serves its providers when `Enabled` is true and its local configuration
does not opt out with `bridge.user_access_enabled: false`; a bridge that opts
out serves no provider whatever the block says and reports `opted_out` in its
[user access status report](#user-access-status). The block is applied whole,
and a block in the shape before plexsphere/plexsphere#1108 (`interface_name`,
`listen_port`, `peers`) decodes to no providers. See
[User Access Integration](/reference/bridge/user-access-integration).

| Field       | Type                   | JSON Tag      | Description |
|-------------|------------------------|---------------|-------------|
| `Enabled`   | `bool`                 | `"enabled"`   | The control plane's switch, `true` on every block it delivers. A block with `false` serves no provider and keeps the key files of the providers it lists |
| `Providers` | `[]UserAccessProvider` | `"providers"` | Every provider of the bridge Resource, by slug ascending; absent and `null` decode to none |

**UserAccessProvider**

One provider of the block, the control plane's
`NodeStateBridgeUserAccessProvider`. It carries the members of its kind and no
others. `UserAccessKindWireGuard`, `UserAccessKindTailscale` and
`UserAccessKindNetbird` name the kinds, `"wireguard"`, `"tailscale"` and
`"netbird"`, and a Linux bridge serves all three.

| Field            | Type                 | JSON Tag                       | Description |
|------------------|----------------------|--------------------------------|-------------|
| `ID`             | `string`             | `"id"`                         | Provider id, a UUID; `ValidUserAccessProviderID` checks it |
| `Slug`           | `string`             | `"slug"`                       | Provider name within the bridge Resource |
| `Kind`           | `string`             | `"kind"`                       | `wireguard`, `tailscale` or `netbird` |
| `ListenPort`     | `int`                | `"listen_port,omitempty"`      | UDP port of a `wireguard` provider's interface |
| `AddressPool`    | `string`             | `"address_pool,omitempty"`     | IPv4 network of a `wireguard` provider; its interface takes the first host address with the pool's prefix length |
| `MaxDevices`     | `int`                | `"max_devices,omitempty"`      | The most devices a `wireguard` provider admits; decoded, not enforced |
| `Devices`        | `[]UserAccessDevice` | `"devices,omitempty"`          | The devices a `wireguard` provider admits |
| `AuthSecretName` | `string`             | `"auth_secret_name,omitempty"` | The Secret that holds a `tailscale` or `netbird` provider's join key |

**UserAccessDevice**

One device of a `wireguard` provider, the control plane's
`NodeStateBridgeUserAccessDevice`: a WireGuard peer of the provider's interface.

| Field       | Type     | JSON Tag       | Description |
|-------------|----------|----------------|-------------|
| `ID`        | `string` | `"id"`         | Device id |
| `Slug`      | `string` | `"slug"`       | Device name within the provider |
| `PublicKey` | `string` | `"public_key"` | The device's WireGuard public key, standard base64 |
| `Address`   | `string` | `"address"`    | The device's IPv4 address in the pool, its one allowed IP as a `/32` |

`ValidUserAccessProviderID(s string) bool` applies the check of
`ValidIngressRuleID`: a UUID in canonical form, in either case, other than the
zero UUID, the id the control plane accepts in a user access status report.

**IngressConfig**

The `bridge.ingress` block, the control plane's `NodeStateBridgeIngress`. A
bridge serves its rules when `Enabled` is true and its local configuration does
not opt out with `bridge.ingress_enabled: false`; a bridge that opts out opens
no public listener whatever the block says and reports `opted_out` in its
[ingress status report](#ingress-status). The block is applied whole. See
[Public Ingress](/reference/bridge/public-ingress#activation).

| Field     | Type            | JSON Tag           | Description                                |
|-----------|-----------------|--------------------|--------------------------------------------|
| `Enabled` | `bool`          | `"enabled"`        | The control plane's switch, `true` on every block it delivers. A block without the member decodes to `false`, and a block with `false` opens no public listener. No `omitempty`: a zero `IngressConfig` marshals with `"enabled":false` |
| `Rules`   | `[]IngressRule` | `"rules"`          | Every rule of the bridge Resource, by slug ascending |
| `ACME`    | `*IngressACME`  | `"acme,omitempty"` | The ACME account the block's `acme` rules share, the control plane's `NodeStateBridgeIngressACME`; present exactly when a rule has mode `acme`, nil otherwise |

**IngressACME**

The ACME account of a bridge's `acme` rules. A bridge accepts only an absolute
https `DirectoryURL`, and only one its local `bridge.acme_directory_urls` lists
when that list is not empty. See
[ACME and SNI Routing](/reference/bridge/acme-sni).

| Field          | Type     | JSON Tag                    | Description                                  |
|----------------|----------|-----------------------------|----------------------------------------------|
| `DirectoryURL` | `string` | `"directory_url"`           | ACME directory (RFC 8555) the bridge registers its account at |
| `ContactEmail` | `string` | `"contact_email,omitempty"` | Contact the account registers with; empty for none |

**IngressRule**

One rule of the block, the control plane's `NodeStateBridgeIngressRule`.
`IngressProtocolTCP` (`"tcp"`) and `IngressProtocolUDP` (`"udp"`) name its
protocols: a `tcp` rule forwards the connections that reach its listen port,
and a `udp` rule the datagrams. `IngressModePassthrough`, `IngressModeTerminate`
and `IngressModeACME` name its modes, and a bridge serves all three: a
`terminate` rule ends TLS with the certificate of the Secret
`CertificateSecretName` names, and an `acme` rule with a certificate the bridge
obtains from the account of the block's `ACME` member. A `udp` rule is a
`passthrough` rule without `SNIHost`. See
[Forwarding Datagrams](/reference/bridge/public-ingress#forwarding-datagrams).
A `terminate` or `acme` rule may carry `Conditions`; rules with conditions
share one listen port and SNI host, and the bridge hands each request to one of
them. See [Routing a Request](/reference/bridge/public-ingress#routing-a-request).
A rule names one to eight `Targets`, over which the bridge spreads its
connections, requests or client flows by round robin. See
[Several Targets](/reference/bridge/public-ingress#several-targets).
A `terminate` or `acme` rule may carry `ClientAuth`; the bridge then completes
the TLS handshake only with a client whose certificate chains to one of the
rule's client authorities. See
[Client Certificates](/reference/bridge/public-ingress#client-certificates).

| Field           | Type     | JSON Tag                 | Description                                  |
|-----------------|----------|--------------------------|----------------------------------------------|
| `ID`            | `string` | `"id"`                   | Rule id                                      |
| `Slug`          | `string` | `"slug"`                 | Rule name within the bridge Resource         |
| `Protocol`      | `string` | `"protocol,omitempty"`   | `tcp` or `udp`. A rule of a control plane older than [plexsphere/plexsphere#1110](https://github.com/plexsphere/plexsphere/pull/1110) carries none and decodes to `""`, which a bridge serves as `tcp` |
| `ListenPort`    | `int`    | `"listen_port"`          | Public port, 1 to 65535, TCP or UDP by `Protocol` |
| `Mode`          | `string` | `"mode"`                 | `passthrough`, `terminate` or `acme`         |
| `SNIHost`       | `string` | `"sni_host,omitempty"`   | Server name the rule matches, exact or `*.` plus a suffix; empty for the only rule on its port |
| `Targets`       | `[]IngressTarget` | `"targets,omitempty"` | The rule's targets, one to eight, in round-robin order, as a control plane since [plexsphere/plexsphere#1120](https://github.com/plexsphere/plexsphere/pull/1120) sends them. A rule of an earlier control plane carries none and marshals without the key; an absent, `null` or empty member decodes to an empty `Targets` |
| `TargetNodeID`  | `string` | `"target_node_id"`       | Deprecated: the first target's node; not dialed. A bridge reads `TargetNodeID`, `TargetAddress` and `TargetPort` only when `Targets` is empty, as a control plane before [plexsphere/plexsphere#1120](https://github.com/plexsphere/plexsphere/pull/1120) sends a rule |
| `TargetAddress` | `string` | `"target_address"`       | Deprecated: the first target's mesh address, IPv4 or IPv6, without brackets |
| `TargetPort`    | `int`    | `"target_port"`          | Deprecated: the port dialed on the first target, 1 to 65535 |
| `CertificateSecretName` | `string` | `"certificate_secret_name,omitempty"` | Secret of the bridge's Project that holds a `terminate` rule's certificate chain and key, one PEM document; empty on every other mode. The bridge fetches it in the version the pull's `secrets` block lists. See [Certificates from the Secret Store](/reference/bridge/public-ingress#certificates-from-the-secret-store) |
| `Conditions` | `IngressConditions` | `"conditions,omitzero"` | The request conditions of a `terminate` or `acme` rule. A rule without conditions marshals without the key, and an absent, `null` or empty member, or one with an empty `headers` list, decodes to a rule without conditions |
| `StripPathPrefix` | `bool` | `"strip_path_prefix,omitempty"` | The bridge removes the matched path prefix from the front of the path the target receives. Only a rule whose path prefix is present and not `/` carries it |
| `ClientAuth` | `*IngressClientAuth` | `"client_auth,omitempty"` | The client certificate requirement of a `terminate` or `acme` rule, as a control plane since [plexsphere/plexsphere#1121](https://github.com/plexsphere/plexsphere/pull/1121) sends it. A pointer, because presence is the requirement: an absent member and `null` decode to nil, which marshals without the key, and `{}` and `{"ca_bundle": ""}` decode to a value with an empty bundle, which the bridge cannot build its authorities from (`client_ca_invalid`) |

The `Conditions.Headers` and `Targets` slices rule out `==` on two rules, so
the compiler refuses it. `Equal(o IngressRule) bool` compares two rules with
`reflect.DeepEqual` and treats a nil and an empty `Conditions.Headers` as
equal, and a nil and an empty `Targets`; the order of the headers and of the
targets counts. `reflect.DeepEqual` follows the `ClientAuth` pointer: a nil and
a non-nil `ClientAuth` differ, and two bundles compare by their text, so a
bundle that differs in one byte or in the order of its blocks makes another
rule. The bridge calls it to tell an unchanged rule from a changed one.

**IngressClientAuth**

The client certificate requirement of an ingress rule, the control plane's
`BridgeIngressRuleClientAuthBundle`.

| Field      | Type     | JSON Tag      | Description |
|------------|----------|---------------|-------------|
| `CABundle` | `string` | `"ca_bundle"` | The rule's client authorities: 1 to 8 CA certificates as PEM `CERTIFICATE` blocks, each without headers, as the control plane stores them. The bridge holds them in memory and logs no byte of them |

**IngressTarget**

One target of an ingress rule, the control plane's
`NodeStateBridgeIngressRuleTarget`: a target node, its mesh address and a port
on it. The control plane sends no two targets of a rule with the same `NodeID`
and `Port`, while one node may appear with several ports.

| Field     | Type     | JSON Tag    | Description |
|-----------|----------|-------------|-------------|
| `NodeID`  | `string` | `"node_id"` | Target node; not dialed |
| `Address` | `string` | `"address"` | Target node's mesh address, IPv4 or IPv6, without brackets |
| `Port`    | `int`    | `"port"`    | Port dialed on the target, 1 to 65535 |

**IngressConditions**

The request conditions of an ingress rule, the control plane's
`NodeStateBridgeIngressConditions`: a path prefix and up to 8 header
conditions, all of which a request must match. `IsZero() bool` reports a rule
without conditions, one with no path prefix and no header; `encoding/json`
calls it for `omitzero`.

| Field        | Type                       | JSON Tag                  | Description |
|--------------|----------------------------|---------------------------|-------------|
| `PathPrefix` | `string`                   | `"path_prefix,omitempty"` | A path the request path equals or continues with `/` after; empty and `/` match every path |
| `Headers`    | `[]IngressHeaderCondition` | `"headers,omitempty"`     | The header conditions, in name order |

**IngressHeaderCondition**

One header condition: the request carries a field of `Name` with exactly
`Value`.

| Field   | Type     | JSON Tag  | Description |
|---------|----------|-----------|-------------|
| `Name`  | `string` | `"name"`  | The field name, a lowercase RFC 9110 token of 1 to 64 characters, never `host` |
| `Value` | `string` | `"value"` | The value, 1 to 256 printable ASCII characters without a leading or trailing space, compared with case |

**SiteToSiteConfig**

The `bridge.site_to_site` block, the control plane's `NodeStateBridgeSiteToSite`,
which it delivers since
[plexsphere/plexsphere#1109](https://github.com/plexsphere/plexsphere/pull/1109).
A bridge serves its tunnels when `Enabled` is true and its local configuration
does not opt out with `bridge.site_to_site_enabled: false`; a bridge that opts
out serves no tunnel whatever the block says and reports `opted_out` in its
[site-to-site status report](#site-to-site-status). The block is applied whole:
a tunnel a later pull no longer lists is torn down. A block in the shape before
plexsphere/plexsphere#1107 decodes to tunnels without an id, which a bridge
neither serves nor reports. See
[Site-to-Site VPN](/reference/bridge/site-to-site-vpn).

| Field     | Type                 | JSON Tag    | Description |
|-----------|----------------------|-------------|-------------|
| `Enabled` | `bool`               | `"enabled"` | The control plane's switch, `true` on every block it delivers. A block with `false` serves no tunnel and keeps the key files of the tunnels it lists |
| `Tunnels` | `[]SiteToSiteTunnel` | `"tunnels"` | Every tunnel of the bridge Resource, by slug ascending; absent and `null` decode to none |

**SiteToSiteTunnel**

One tunnel of the block, the control plane's
`NodeStateBridgeSiteToSiteTunnel`. Every tunnel carries `ID`, `Slug`, `Kind`,
`RemoteHost`, `RemotePort` and `AllowedSubnets`; the other members follow from
its kind. `SiteToSiteKindWireGuard`, `SiteToSiteKindIPsec` and
`SiteToSiteKindOpenVPN` name the kinds, `"wireguard"`, `"ipsec"` and
`"openvpn"`, and a Linux bridge serves all three. No member is a private key or
the value of a Secret.

| Field             | Type       | JSON Tag                        | Description |
|-------------------|------------|---------------------------------|-------------|
| `ID`              | `string`   | `"id"`                          | Tunnel id, a UUID; `ValidSiteToSiteTunnelID` checks it |
| `Slug`            | `string`   | `"slug"`                        | Tunnel name within the bridge Resource |
| `Kind`            | `string`   | `"kind"`                        | `wireguard`, `ipsec` or `openvpn` |
| `RemoteHost`      | `string`   | `"remote_host"`                 | The remote site's host name of at most 253 characters, or its IP address |
| `RemotePort`      | `int`      | `"remote_port"`                 | The remote site's port, 1 to 65535 |
| `AllowedSubnets`  | `[]string` | `"allowed_subnets"`             | The 1 to 64 networks behind the remote site, in CIDR notation and in the order the operator wrote them |
| `ListenPort`      | `int`      | `"listen_port,omitempty"`       | UDP port of a `wireguard` tunnel's interface |
| `RemotePublicKey` | `string`   | `"remote_public_key,omitempty"` | The remote site's WireGuard public key of a `wireguard` tunnel, 44 characters of standard base64 that decode to 32 bytes |
| `AuthSecretName`  | `string`   | `"auth_secret_name,omitempty"`  | The Secret that holds the tunnel's key as plain text: the preshared key of a `wireguard` tunnel, absent when it uses none, the IKE pre-shared key of an `ipsec` tunnel, or the static key of an `openvpn` tunnel |

`ValidSiteToSiteTunnelID(s string) bool` applies the check of
`ValidUserAccessProviderID`: a UUID in canonical form, in either case, other
than the zero UUID, the id the control plane accepts in a site-to-site status
report.

**NodeStateBlock**

A three-bucket state block. Each bucket is a required array (never `null` when the
block is populated), with entries ordered by key ascending.

| Field      | Type          | JSON Tag     | Description        |
|------------|---------------|--------------|--------------------|
| `Metadata` | `[]StateEntry`| `"metadata"` | Metadata entries   |
| `Data`     | `[]StateEntry`| `"data"`     | Data entries       |
| `Reports`  | `[]StateEntry`| `"reports"`  | Report entries     |

**StateEntry**

`Value` is an opaque string; `WorkloadTag` is absent/empty when the entry is
unattributed.

| Field         | Type     | JSON Tag                    | Description             |
|---------------|----------|-----------------------------|-------------------------|
| `Key`         | `string` | `"key"`                     | Entry key               |
| `Value`       | `string` | `"value"`                   | Opaque string value     |
| `WorkloadTag` | `string` | `"workload_tag,omitempty"`  | Owning workload, if any |

**NodeStateSigningKey**

The interior of the `signing_key` block: the Domain signing key as the "Domain
signing key" section of plexsphere's agent contract
(`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere)
describes it, in the encodings `POST /v1/register` uses for `signing_key_id` and
`signing_public_key`. plexd installs the key every successful pull carries into
the verifier that checks event envelopes and ssh session tokens (a key whose id
or bytes differ from the current pair replaces it and drops any rotation grace
entry), and writes a key that differs from the persisted pair to the
`signing_public_key` file and `identity.json`, so a restart starts from it.

| Field       | Type     | JSON Tag       | Description                                         |
|-------------|----------|----------------|-----------------------------------------------------|
| `KeyID`     | `string` | `"key_id"`     | Id the key signs under; plexd rejects an empty one  |
| `PublicKey` | `string` | `"public_key"` | 32-byte Ed25519 public key in standard base64; plexd rejects any other length |

**NodeStateSecret**

One entry of the `secrets` block: a Secret the node may read, as the "Secret
inventory" section of plexsphere's agent contract
(`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere)
describes it. The entry carries the Secret's name and current version, never its
value; plexd fetches the value from `GET /v1/nodes/{node_id}/secrets/{key}` (see
[Secrets](#secrets)). The node API's `SecretIndexDispatchHandler` maps `Name`
onto `SecretRef.Key`, keeps `Version`, and keeps the pull order. It drops an
entry whose name is outside the grammar, whose version is below 1, or whose name
an earlier kept entry already has, and logs each dropped entry at Warn as
`secret inventory entry dropped`, once until the set of dropped entries changes.

| Field     | Type     | JSON Tag    | Description                                         |
|-----------|----------|-------------|-----------------------------------------------------|
| `Name`    | `string` | `"name"`    | The Secret's name, matching `^[a-z][a-z0-9_-]{0,62}$`; becomes `SecretRef.Key` in the node API's secret index |
| `Version` | `int`    | `"version"` | The Secret's current version, at least 1            |

**NodeStateHook**

One entry of the `hooks` block: a published hook version a rollout assigns the
node, as the "Published hooks" section of plexsphere's agent contract
(`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere)
describes it. The entry never carries the script; plexd fetches each version it
has not installed from
[`GET /v1/nodes/{node_id}/hooks/{name}/versions/{version}`](#published-hooks).
`actions.RolloutInstaller` drops an entry whose name is outside the grammar,
whose version is below 1, or whose name an earlier entry already has, and logs
each dropped entry at Warn as `actions: rollout: entry dropped`, once until the
set of dropped entries changes. It reports an entry whose checksum is not 32
bytes of standard base64 as `verification_failed` and fetches nothing for it.
See [Rolled-out Hooks](../actions/remote-actions-hooks.md#rolled-out-hooks).

| Field      | Type     | JSON Tag     | Description                                         |
|------------|----------|--------------|-----------------------------------------------------|
| `Name`     | `string` | `"name"`     | The hook's name, matching `^[a-z0-9][a-z0-9_-]{0,62}$`, so it never carries a dot and never shares a name with a built-in action |
| `Version`  | `int`    | `"version"`  | The published version, at least 1                   |
| `Checksum` | `string` | `"checksum"` | SHA-256 of the version's script: 32 bytes, standard-padded base64, the encoding of `DeclaredHook.Checksum`. The installed hook is pinned to it |

**NodeStateDNS**

The interior of the `dns` block: the mesh DNS names of the node's Domain, the
DNS records the Domain and its Projects define, and the DNS forwarding setting
that applies to the node, as the
"Mesh DNS names" section of plexsphere's agent contract
(`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere)
describes it. The control plane sends every name in lower case without a
trailing dot, and an empty list as `[]`. `meshdns.BuildRecords` validates every
entry and skips the ones that break a rule, such as a zone under `arpa`, `local`
or `localhost`, a host outside every accepted zone, or a repeated `fqdn`. It
skips a record whose `type` is not one of the six, whose `fqdn` is not a valid
name, lies under no accepted zone or is a host's `fqdn`, whose data breaks the
rule of its type, which shares its name with a CNAME, or which repeats an
earlier record. `meshdns.BuildForwarding` checks the `forwarding` member the
same way and skips a forward zone that is no valid name, is reserved, lies
under an accepted zone or reverse zone, repeats an earlier forward zone or has
no usable resolver, and a resolver that is no IP address, is no address plexd
forwards to, is the resolver's own listen address or repeats an earlier one.
The manager logs them at Warn as
`mesh dns skipped invalid entries`, with the count and the first five
sentences. See
[Mesh DNS](../networking/mesh-dns.md#records) and
[Forward Zones and Resolvers](../networking/mesh-dns.md#forward-zones-and-resolvers).

| Field          | Type                 | JSON Tag          | Description                                         |
|----------------|----------------------|-------------------|-----------------------------------------------------|
| `SearchDomain` | `string`             | `"search_domain"` | The zone of the node's own Project, which bare host names resolve under. Kept only when it is an accepted zone |
| `Zones`        | `[]string`           | `"zones"`         | The Domain's default domain and every Project zone, ascending |
| `Hosts`        | `[]NodeStateDNSHost` | `"hosts"`         | Every node of the Domain, the pulling node included, ordered by `fqdn` |
| `Records`      | `[]NodeStateDNSRecord` | `"records"`     | The DNS records of the Domain and of every Project, ordered by `fqdn`, then by `type`. A `nil` value (the wire's `null`, or a key a control plane that predates records never wrote) means the Domain has no records: the block is the full set, so it is no signal to keep the records held |
| `ReverseZones` | `[]string`           | `"reverse_zones"` | The `in-addr.arpa` or `ip6.arpa` zones that cover the Domain's mesh CIDR and nothing wider |
| `Forwarding`   | `*NodeStateDNSForwarding` | `"forwarding,omitempty"` | The DNS forwarding setting that applies to the pulling node. A pointer, because the member is the full setting and its absence says something else: a `nil` value (the wire's `null`, or a key a control plane that predates forwarding never wrote) means the control plane did not say this time, and the node keeps the forwarding it holds. Two empty lists end it. `omitempty` lets the mock control plane, which marshals this type, serve a block without the member |

**NodeStateDNSForwarding**

The `forwarding` member of the `dns` block, as the "Mesh DNS names" section of
plexsphere's agent contract describes it: the Project's setting when the node's
Project holds one, otherwise its Domain's, otherwise two empty lists. A resolver
is an IPv4 or IPv6 address in text form, asked in list order on port 53 over
plain DNS. A `nil` list (the wire's `null`, or a missing key) is an empty one.
See [Forwarding](../networking/mesh-dns.md#forwarding).

| Field          | Type                        | JSON Tag          | Description                                         |
|----------------|-----------------------------|-------------------|-----------------------------------------------------|
| `ForwardZones` | `[]NodeStateDNSForwardZone` | `"forward_zones"` | The forward zones, ascending by `zone`, each with 1 to 3 resolvers |
| `CatchAll`     | `[]string`                  | `"catch_all"`     | 0 to 3 resolvers, which answer every name outside the mesh zones, the reverse zones and the forward zones. With an accepted one, plexd on Linux makes the mesh interface the host's default DNS route |

**NodeStateDNSForwardZone**

One entry of the `forward_zones` list: a zone outside the mesh and the resolvers
that answer the names under it, as the "Mesh DNS names" section of plexsphere's
agent contract describes it.

| Field       | Type       | JSON Tag      | Description                                         |
|-------------|------------|---------------|-----------------------------------------------------|
| `Zone`      | `string`   | `"zone"`      | The zone, in lower case without a trailing dot. A label may carry `_`, as in `_msdcs.corp.example.com`. A zone that equals an accepted zone or reverse zone of the block, or lies under one, is skipped |
| `Resolvers` | `[]string` | `"resolvers"` | The resolvers of the zone, in the order they are asked |

**NodeStateDNSHost**

One entry of the `hosts` list: a node of the Domain, as the "Mesh DNS names"
section of plexsphere's agent contract describes it.

| Field    | Type     | JSON Tag    | Description                                         |
|----------|----------|-------------|-----------------------------------------------------|
| `NodeID` | `string` | `"node_id"` | The node's id. Carried, never answered              |
| `FQDN`   | `string` | `"fqdn"`    | The node's fully qualified name, at least one label below one of `zones` |
| `MeshIP` | `string` | `"mesh_ip"` | The node's mesh IP, IPv4 or IPv6 by the family of the Domain's mesh CIDR. The `A` or `AAAA` answer for `fqdn`. Its reverse name answers `PTR` with `fqdn` when it lies under one of `reverse_zones` |

**NodeStateDNSRecord**

One entry of the `records` list: a DNS record the Domain or one of its Projects
defines, as the "Mesh DNS names" section of plexsphere's agent contract
describes it. An entry carries `fqdn`, `type` and the data members of its type,
and no other member. The three numbers are `*int`, so a `priority` or `weight`
of `0` is sent as `0`, and a member the type does not take stays absent when
the mock control plane marshals the type. They are `int` rather than `uint16`,
so a number out of range costs only its record, which the resolver skips, and
not the decode of the whole snapshot. The resolver ignores a member the
record's type does not take.

| Field      | Type       | JSON Tag                | Description                                         |
|------------|------------|-------------------------|-----------------------------------------------------|
| `FQDN`     | `string`   | `"fqdn"`                | The record's fully qualified name: one of `zones` or a name under one, and never a host's `fqdn`. A label may carry `_`, as in `_postgres._tcp.openstack.lab.internal` |
| `Type`     | `string`   | `"type"`                | `A`, `AAAA`, `CNAME`, `TXT`, `SRV` or `MX`, in upper case |
| `Address`  | `string`   | `"address,omitempty"`   | `A` and `AAAA`: the IPv4 or the IPv6 address. An IPv4-mapped IPv6 address is neither |
| `Target`   | `string`   | `"target,omitempty"`    | `CNAME`, `SRV` and `MX`: the name the record points at, inside or outside the mesh zones |
| `Priority` | `*int`     | `"priority,omitempty"`  | `SRV` and `MX`: 0 to 65535. The preference of an `MX` |
| `Weight`   | `*int`     | `"weight,omitempty"`    | `SRV`: 0 to 65535 |
| `Port`     | `*int`     | `"port,omitempty"`      | `SRV`: 0 to 65535 |
| `Text`     | `[]string` | `"text,omitempty"`      | `TXT`: at least one string, each of at most 255 bytes, answered in order |

**NodeStateFailureDetection**

The interior of the `failure_detection` block: the Domain's failure-detection
time, as the "Failure detection" section of plexsphere's agent contract
(`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere)
describes it. The envelope carries the block raw, and
`wireguard.FailureDetectionDispatchHandler` decodes it on every successful
pull. A `null` block keeps the value the node holds and logs nothing. A block
`json.Unmarshal` refuses, such as a string or a `detect_after_seconds` of
`15.5` or `"15"`, keeps it too and is logged at Warn as
`wireguard: failure detection block malformed`, once until a block decodes
again. A value of zero or less changes nothing. The handler clamps a positive
value to 5 to 180 s (`wireguard.MinFailureDetection` and
`wireguard.MaxFailureDetection`) and hands it to `Manager.SetFailureDetection`.
A value outside 5 to 180 is logged at Warn as
`wireguard: failure detection time out of range`, once until a block carries
another value. See
[Failure detection time](../networking/wireguard.md#failure-detection-time).

| Field                | Type    | JSON Tag                 | Description                                         |
|----------------------|---------|--------------------------|-----------------------------------------------------|
| `DetectAfterSeconds` | `int64` | `"detect_after_seconds"` | How long a relayed peer may stay silent before plexd dials the next relay of its set: a whole number of seconds from 5 to 180, and 15 for a Domain that never set it. `int64` rather than `int`, so a value out of range decodes on a 32-bit build too and is clamped rather than refused as malformed. A block without the member, `{}`, reads as 0 and changes nothing |

### Supporting types

These types are part of the API but are not members of the state snapshot.
`SigningKeyRotation` is the payload of the `signing_key_rotated` SSE event.
`SessionRevocation` is the payload of the `session_revoked` SSE event.
`SessionConnectRequest` is the payload of the `session_connect` SSE event.
`SecretRef` is the entry of the local node API's secret index, fed from the
pull's `NodeStateSecret` entries (the name becomes `key`). `DataEntry` is the
shape the local node API serves for cached data entries.

**SigningKeyRotation**

| Field               | Type        | JSON Tag                | Description                                       |
|---------------------|-------------|-------------------------|--------------------------------------------------|
| `KeyID`             | `string`    | `"key_id"`              | Key id of the new current signing key            |
| `PublicKey`         | `string`    | `"public_key"`          | Base64 Ed25519 public key of the new current key |
| `PreviousKeyID`     | `string`    | `"previous_key_id"`     | Prior key id kept valid during the grace window  |
| `TransitionExpires` | `time.Time` | `"transition_expires"`  | When the previous key id stops being accepted    |

**SessionRevocation**

| Field          | Type        | JSON Tag          | Description                                        |
|----------------|-------------|-------------------|----------------------------------------------------|
| `SessionID`    | `string`    | `"session_id"`    | Id of the session the control plane revoked        |
| `JTI`          | `string`    | `"jti"`           | The revoked session token's jti, equal to `session_id`; plexd closes nothing when the two differ or `session_id` is empty |
| `RevokedAt`    | `time.Time` | `"revoked_at"`    | When the control plane revoked the session         |
| `RevokeReason` | `string`    | `"revoke_reason"` | One of the `RevokeReason*` values                  |

**RevokeReason constants**

Carried on `SessionRevocation.RevokeReason`. The first four are operator-driven,
supplied on the explicit revoke call; the last two are set by the control
plane's sweeper. The description names the `terminated_by` plexd reports on the
`session_ended` row of the session the event closes. An empty or unrecognised
value is reported as `operator_revoke` too, with a Warn.

| Constant                             | Value                     | Description                                      |
|--------------------------------------|---------------------------|--------------------------------------------------|
| `RevokeReasonOperatorRequest`        | `operator_request`        | Operator-driven; reported as `operator_revoke`   |
| `RevokeReasonPolicyViolation`        | `policy_violation`        | Operator-driven; reported as `operator_revoke`   |
| `RevokeReasonIdentityCompromise`     | `identity_compromise`     | Operator-driven; reported as `operator_revoke`   |
| `RevokeReasonResourceDecommissioned` | `resource_decommissioned` | Operator-driven; reported as `operator_revoke`   |
| `RevokeReasonTTLExpired`             | `ttl_expired`             | Sweeper, at the session's hard expiry; reported as `ttl_expired` |
| `RevokeReasonIdleTimeout`            | `idle_timeout`            | Sweeper, at the session's idle timeout; reported as `idle_timeout` |

**SessionConnectRequest**

Its shape is the control plane's `access.SessionConnectRequested` event. The
payload also carries that event's `event_id` and `occurred_at` header members,
which plexd does not read.

| Field          | Type        | JSON Tag          | Description                                        |
|----------------|-------------|-------------------|----------------------------------------------------|
| `SessionID`    | `string`    | `"session_id"`    | Id of the ssh session a client attached to         |
| `ConnectionID` | `string`    | `"connection_id"` | One-time id of the connection the node is asked to open; the last segment of [`GET /v1/nodes/{node_id}/sessions/{session_id}/connections/{connection_id}`](api-endpoints.md#get-v1-nodes-node-id-sessions-session-id-connections-connection-id). plexd opens nothing when it or `session_id` is empty |
| `ExpiresAt`    | `time.Time` | `"expires_at"`    | When the control plane stops accepting the connection. plexd does not judge it against its own clock; the control plane refuses a late connection with `404 session_connection_not_found` |

**DataEntry**

| Field        | Type              | JSON Tag       | Description              |
|--------------|-------------------|----------------|--------------------------|
| `Key`        | `string`          | `"key"`        | Entry key                |
| `ContentType`| `string`          | `"content_type"`| MIME content type       |
| `Payload`    | `json.RawMessage` | `"payload"`    | Arbitrary JSON payload   |
| `Version`    | `int`             | `"version"`    | Entry version            |
| `UpdatedAt`  | `time.Time`       | `"updated_at"` | Last update timestamp    |

**SecretRef**

| Field    | Type   | JSON Tag    | Description      |
|----------|--------|-------------|------------------|
| `Key`    | `string`| `"key"`    | The Secret's name, from `NodeStateSecret.Name` |
| `Version`| `int`  | `"version"` | Secret version   |

## Secrets

### `GET /v1/nodes/{node_id}/secrets/{key}`

**SecretEnvelope**

The raw AES-256-GCM envelope served by the endpoint. Unlike every other type on
this page it carries **no JSON tags**: `Data` is read from the octet-stream body,
`Version` and `KID` from response headers — the type is never JSON-marshaled or
unmarshaled.

| Field     | Type     | Source                                      | Description                                          |
|-----------|----------|---------------------------------------------|------------------------------------------------------|
| `Data`    | `[]byte` | Response body (`application/octet-stream`)  | `<12-byte nonce> \|\| <ciphertext + 16-byte GCM tag>` |
| `Version` | `int`    | `X-Plexsphere-Secret-Version` header        | Version of the returned secret                       |
| `KID`     | `string` | `X-Plexsphere-Secret-KID` header            | Key id of the NSK the envelope was sealed under      |

## Edge PSK

### `GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk`

**EdgePSKEnvelope**

The pairwise WireGuard PSK for one edge, sealed under the calling node's NSK with
AES-256-GCM. Like `SecretEnvelope` it carries **no JSON tags**: `Data` is read
from the octet-stream body, `KID` and `Epoch` from response headers, and the type
is never JSON-marshaled or unmarshaled. `FetchEdgePSK` refuses a body of any other
length than `EdgePSKEnvelopeSize` and a response that lacks either header. `Data`
is key material and is never logged.

| Field   | Type     | Source                                      | Description                                          |
|---------|----------|---------------------------------------------|------------------------------------------------------|
| `Data`  | `[]byte` | Response body (`application/octet-stream`)  | `<12-byte nonce> \|\| <32-byte PSK + 16-byte GCM tag>`, exactly `EdgePSKEnvelopeSize` bytes |
| `KID`   | `string` | `X-Plexsphere-PSK-KID` header               | Key id of the NSK the envelope was sealed under; required, but plexd holds one NSK and selects nothing by it |
| `Epoch` | `string` | `X-Plexsphere-PSK-Epoch` header             | PSK epoch; required, part of the additional authenticated data and used verbatim |

The wireguard package opens `Data` under the 32-byte NSK with the additional
authenticated data `plexsphere/mesh/edge-psk/v1|<self node id>|<peer node id>|<epoch>`,
both node IDs trimmed and lowercased. It refuses an envelope whose epoch sorts
below the highest epoch it already accepted for the edge. That floor survives a
change of the peer's public key and lives in memory only. See
[Edge PSKs](../networking/wireguard.md#edge-psks) for the fetch rule and how plexd
handles each answer.

**Constants**

| Constant              | Value | Description                                                       |
|-----------------------|-------|-------------------------------------------------------------------|
| `EdgePSKEnvelopeSize` | `60`  | Exact envelope length: 12-byte nonce, 32-byte PSK, 16-byte GCM tag |

## Published Hooks

### `GET /v1/nodes/{node_id}/hooks/{name}/versions/{version}`

**NodeHookVersion**

The `200` body of the hook version fetch: the signed envelope that describes one
published hook version, and the script. The script sits outside the envelope, so
the signature covers its checksum in the payload rather than its bytes.
`FetchHookVersion` decodes the body and verifies nothing; the rollout installer
checks the envelope type, the payload, the signature and the script's digest
before it writes anything (see
[Verification](../actions/remote-actions-hooks.md#verification)).

| Field          | Type       | JSON Tag          | Description                                         |
|----------------|------------|-------------------|-----------------------------------------------------|
| `Envelope`     | `Envelope` | `"envelope"`      | The signed envelope: the members of an [event envelope](event-verification.md#envelope), with `type` `hook_version`, `id` the version id, `scope` the Domain of the hook's Project, and `issued_at` the instant the version was signed. Its payload is a `HookVersionPayload` |
| `ScriptBase64` | `string`   | `"script_base64"` | The script, standard base64                         |

**HookVersionPayload**

The payload of a `hook_version` envelope. `Name` and `Version` repeat the pair
the node fetched. The last four fields are the hook's sidecar fields, signed
together with its checksum; the installer writes them into the sidecar of the
installed script.

| Field            | Type            | JSON Tag                      | Description                                        |
|------------------|-----------------|-------------------------------|----------------------------------------------------|
| `ProjectID`      | `string`        | `"project_id"`                | The Project that published the hook; plexd does not check it |
| `Name`           | `string`        | `"name"`                      | The hook's name                                    |
| `Version`        | `int`           | `"version"`                   | The published version                              |
| `Checksum`       | `string`        | `"checksum"`                  | SHA-256 of the script, in the encoding of `NodeStateHook.Checksum` |
| `Description`    | `string`        | `"description,omitempty"`     | What the hook does; sent only when the version declares it |
| `Parameters`     | `[]ActionParam` | `"parameters,omitempty"`      | What the hook expects; sent only when the version declares them |
| `TimeoutSeconds` | `int64`         | `"timeout_seconds,omitempty"` | The hook's timeout in seconds; sent only when the version declares one. plexd installs a value from 0 to 86400 |
| `SandboxLevel`   | `string`        | `"sandbox_level"`             | Always sent. plexd installs `none` or an empty value only |

**Constants**

| Constant                  | Value         | Description                                          |
|---------------------------|---------------|------------------------------------------------------|
| `HookVersionEnvelopeType` | `hook_version` | The `type` of the envelope a published hook version is signed in. The envelope never rides the event stream |

## Reports

### `PUT` / `DELETE /v1/nodes/{node_id}/state/reports/{key}`

Per-key node state reports. `PUT` upserts the report at `{key}`; `DELETE` removes
it. `{key}` follows the report key grammar `^[a-z][a-z0-9._-]{0,127}$`, and
`Value` is capped at 4096 bytes. See
[Control Plane API Endpoints](api-endpoints.md#reports) for the wire examples and
error taxonomy.

**NodeStateReportRequest** (`PUT` body)

| Field         | Type     | JSON Tag                    | Description                                |
|---------------|----------|-----------------------------|--------------------------------------------|
| `Value`       | `string` | `"value"`                   | Opaque report payload (at most 4096 bytes) |
| `WorkloadTag` | `string` | `"workload_tag,omitempty"`  | Owning workload; absent when unattributed  |

**NodeStateReportResponse** (`200 OK` on `PUT`)

`DELETE` returns `204 No Content` with no body (or `404` `report_not_found` when
the key has no report).

| Field        | Type        | JSON Tag        | Description                     |
|--------------|-------------|-----------------|---------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time             |
| `Key`        | `string`    | `"key"`         | Echoes the addressed report key |

## Executions

The `executions` block of the state snapshot and the single execution callback the
node posts back to `POST /v1/nodes/{node_id}/executions/{execution_id}`.

### `executions` block of `GET /v1/nodes/{node_id}/state`

**NodeStateExecution**

One pending action dispatch. The block is the delivery channel for action
dispatches: it is always present (`[]` when empty, never `null`) and ordered by
`RequestedAt`, then `ExecutionID`. An entry keeps reappearing on every pull until
its execution reaches a terminal status through the execution callback, so a
consumer must tolerate re-observing the same `ExecutionID`. The entry carries **no**
callback URL and **no** hook checksum.

| Field         | Type             | JSON Tag         | Description                                            |
|---------------|------------------|------------------|--------------------------------------------------------|
| `ExecutionID` | `string`         | `"execution_id"` | Execution identifier                                   |
| `Action`      | `string`         | `"action"`       | Action name: a builtin, a hook, or a PlexdHook's `metadata.name` |
| `Type`        | `string`         | `"type"`         | One of the `ActionKind*` values                        |
| `Parameters`  | `map[string]json.RawMessage` | `"parameters"` | Action parameters, each held as raw JSON so a large integer keeps every digit; nullable, a JSON `null` decodes to a nil map |
| `Status`      | `string`         | `"status"`       | `pending`, `ack`, or `started`                         |
| `RequestedAt` | `time.Time`      | `"requested_at"` | When the control plane dispatched the execution        |
| `ExpiresAt`   | `time.Time`      | `"expires_at"`   | Absolute UTC deadline, **not** a relative timeout      |
| `CancelRequestedAt` | `*time.Time` | `"cancel_requested_at,omitempty"` | Present only on a `started` entry, once an operator cancelled the Execution; its presence is the signal to stop the run, and plexd never compares its value with its own clock. A JSON `null` and an absent key both decode to nil, and a value that is not an RFC 3339 string fails the decode of the whole state response (see [Cancel](../actions/remote-actions-hooks.md#cancel)) |

**ActionKind constants**

| Constant            | Value     | Description                            |
|---------------------|-----------|----------------------------------------|
| `ActionKindBuiltin` | `builtin` | Dispatches an action built into plexd  |
| `ActionKindHook`    | `hook`    | Dispatches a hook registered by the node |
| `ActionKindPlexdHook` | `plexd_hook` | Dispatches a PlexdHook resource of the node's cluster, run as a Kubernetes Job (see [Kubernetes CRD Hooks](../actions/remote-actions-hooks.md#kubernetes-crd-hooks)) |

**Pull-only execution status**

| Constant                 | Value     | Description                                                        |
|--------------------------|-----------|--------------------------------------------------------------------|
| `ExecutionStatusPending` | `pending` | Dispatched and not yet acknowledged; observed only on the pull block and **never** reported by a node on the callback |

The other two statuses an entry can carry, `ack` and `started`, are the
node-reportable constants listed below.

### `POST /v1/nodes/{node_id}/executions/{execution_id}`

A single callback advances an execution through its lifecycle, posted once per
transition: `ack` → `started` → `succeeded` | `failed` | `cancelled`.

**ExecutionCallbackRequest**

| Field                | Type              | JSON Tag                          | Description                                             |
|----------------------|-------------------|-----------------------------------|---------------------------------------------------------|
| `Status`             | `string`          | `"status"`                        | One of the `ExecutionStatus*` values                    |
| `ExitCode`           | `*int`            | `"exit_code,omitempty"`           | Process exit code on a terminal callback (explicit zero)|
| `Error`              | `string`          | `"error,omitempty"`               | Failure reason on a `failed` terminal                   |
| `DeclaredOutputBytes`| `int64`           | `"declared_output_bytes,omitempty"`| Captured output length; over 16 KiB drives the presign  |
| `Output`             | `*ExecutionOutput`| `"output,omitempty"`              | Captured output on a terminal callback                  |

**ExecutionOutput**

| Field       | Type   | JSON Tag               | Description                                          |
|-------------|--------|------------------------|------------------------------------------------------|
| `Inline`    | `string`| `"inline,omitempty"`  | Base64 output body, used only when at most 16 KiB    |
| `ObjectKey` | `string`| `"object_key,omitempty"`| Object-store key of an uploaded over-ceiling output|
| `SHA256`    | `string`| `"sha256,omitempty"`  | Lowercase-hex SHA-256 of the uploaded bytes          |

**ExecutionCallbackResponse**

| Field            | Type   | JSON Tag                       | Description                                              |
|------------------|--------|--------------------------------|----------------------------------------------------------|
| `Status`         | `string`| `"status"`                    | The new invocation status                                |
| `OutputUploadURL`| `string`| `"output_upload_url,omitempty"`| Presigned PUT URL, set only on the declaring callback    |

**ExecutionStatus constants**

| Constant                  | Value        | Description                                    |
|---------------------------|--------------|------------------------------------------------|
| `ExecutionStatusAck`      | `ack`        | Acknowledges receipt of the action request     |
| `ExecutionStatusStarted`  | `started`    | Reports that the action has begun running       |
| `ExecutionStatusSucceeded`| `succeeded`  | Terminal callback for a successful run          |
| `ExecutionStatusFailed`   | `failed`     | Terminal callback for a failed run              |
| `ExecutionStatusCancelled`| `cancelled`  | Terminal callback for a cancelled run           |

## Observability

The control-plane leg of the three ingest endpoints sends the flattened wire
types below and receives an `IngestReceipt` on `202 Accepted`. The internal
pipeline and the optional local endpoint keep the richer `MetricPoint` /
`LogEntry` / `AuditEntry` shapes; see
[Metrics Collection](../observability/metrics-collection.md),
[Log Forwarding](../observability/log-forwarding.md), and
[Audit Forwarding](../observability/audit-forwarding.md).

### `POST /v1/nodes/{node_id}/metrics`

Body is a JSON array of `MetricSample`.

**MetricSample**

| Field       | Type                | JSON Tag             | Description                                                    |
|-------------|---------------------|----------------------|----------------------------------------------------------------|
| `Group`     | `string`            | `"group"`            | Wire group: `node_resources`, `tunnel_health`, `peer_latency`, or `agent_stats` |
| `Name`      | `string`            | `"name"`             | Sample name                                                    |
| `Value`     | `float64`           | `"value"`            | Sample value                                                   |
| `Labels`    | `map[string]string` | `"labels,omitempty"` | Dimensions (e.g. `peer_id`); absent when the sample has none   |
| `Timestamp` | `time.Time`         | `"timestamp"`        | Sample time                                                    |

**MetricPoint** — internal pipeline and local-endpoint format; `MetricBatch` is a
type alias for `[]MetricPoint`

| Field      | Type              | JSON Tag            | Description          |
|------------|-------------------|---------------------|----------------------|
| `Timestamp`| `time.Time`       | `"timestamp"`       | Measurement time     |
| `Group`    | `string`          | `"group"`           | Metric group name    |
| `PeerID`   | `string`          | `"peer_id,omitempty"`| Optional peer ID    |
| `Data`     | `json.RawMessage` | `"data"`            | Metric data payload  |

### `POST /v1/nodes/{node_id}/logs`

Body is NDJSON: one `LogLine` per line.

**LogLine**

| Field       | Type        | JSON Tag              | Description                                                    |
|-------------|-------------|-----------------------|----------------------------------------------------------------|
| `Severity`  | `string`    | `"severity"`          | Syslog severity: `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug` |
| `Unit`      | `string`    | `"unit,omitempty"`    | Systemd unit; absent when unknown                              |
| `Hostname`  | `string`    | `"hostname,omitempty"`| Origin hostname; absent when unknown                           |
| `Message`   | `string`    | `"message"`           | Log message (non-empty)                                        |
| `Timestamp` | `time.Time` | `"timestamp"`         | Log time                                                       |

**LogEntry** — internal pipeline and local-endpoint format; `LogBatch` is a type
alias for `[]LogEntry`

| Field      | Type        | JSON Tag      | Description        |
|------------|-------------|---------------|--------------------|
| `Timestamp`| `time.Time` | `"timestamp"` | Log timestamp      |
| `Source`   | `string`    | `"source"`    | Log source         |
| `Unit`     | `string`    | `"unit"`      | Systemd unit       |
| `Message`  | `string`    | `"message"`   | Log message        |
| `Severity` | `string`    | `"severity"`  | Log level          |
| `Hostname` | `string`    | `"hostname"`  | Origin hostname    |

### `POST /v1/nodes/{node_id}/audit`

Body is NDJSON: one `AuditEvent` per line.

**AuditEvent**

| Field       | Type        | JSON Tag      | Description                     |
|-------------|-------------|---------------|---------------------------------|
| `Source`    | `string`    | `"source"`    | Wire source: `auditd`, `k8s`, or `plexd`  |
| `Action`    | `string`    | `"action"`    | Action performed (non-empty)    |
| `Outcome`   | `string`    | `"outcome"`   | Outcome (non-empty)             |
| `Timestamp` | `time.Time` | `"timestamp"` | Event time                      |

**AuditEntry** — internal pipeline and local-endpoint format; `AuditBatch` is a
type alias for `[]AuditEntry`

| Field      | Type              | JSON Tag       | Description         |
|------------|-------------------|----------------|---------------------|
| `Timestamp`| `time.Time`       | `"timestamp"`  | Event timestamp     |
| `Source`   | `string`          | `"source"`     | Audit source        |
| `EventType`| `string`          | `"event_type"` | Audit event type    |
| `Subject`  | `json.RawMessage` | `"subject"`    | Who performed it    |
| `Object`   | `json.RawMessage` | `"object"`     | What was affected   |
| `Action`   | `string`          | `"action"`     | Action performed    |
| `Result`   | `string`          | `"result"`     | Action result       |
| `Hostname` | `string`          | `"hostname"`   | Origin hostname     |
| `Raw`      | `string`          | `"raw"`        | Raw audit record    |

### Ingest receipt

**IngestReceipt** (`202 Accepted` for all three ingest endpoints)

| Field        | Type        | JSON Tag        | Description                                |
|--------------|-------------|-----------------|--------------------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | When the control plane accepted the batch  |
| `Records`    | `int`       | `"records"`     | Number of records accepted from the batch  |

## Capabilities

### `PUT /v1/nodes/{node_id}/capabilities`

**CapabilityManifestRequest**

| Field                   | Type                    | JSON Tag                                | Description                                             |
|-------------------------|-------------------------|-----------------------------------------|---------------------------------------------------------|
| `BinaryVersion`         | `string`                | `"binary_version"`                      | Agent version, non-empty after trimming                 |
| `BinaryChecksum`        | `string`                | `"binary_checksum"`                     | Running binary's SHA-256: 32 bytes, standard-padded base64 |
| `SSHHostKeyFingerprint` | `string`                | `"ssh_host_key_fingerprint,omitempty"`  | Optional `SHA256:<base64>` host-key fingerprint         |
| `DeclaredHooks`         | `[]DeclaredHook`        | `"declared_hooks,omitempty"`            | Optional hook declarations, at most 128, unique names   |
| `PlexdHooks`            | `[]DiscoveredPlexdHook` | `"plexd_hooks,omitempty"`               | Optional PlexdHook resources in the ServiceAccount's namespace, at most 128, unique names |
| `BuiltinActions`        | `[]ActionInfo`          | `"builtin_actions,omitempty"`           | Optional builtin action inventory sorted by name, at most 128 actions of at most 64 parameters |
| `HookRolloutErrors`     | `[]HookRolloutError`    | `"hook_rollout_errors,omitempty"`       | Optional: the published hook versions the last pull listed that the node could not install, at most 64. Omitted when nil rather than sent as `null`; the control plane stores an absent list as `[]`, so the node clears an error by leaving it out |

**DeclaredHook**

| Field            | Type            | JSON Tag                      | Description                                        |
|------------------|-----------------|-------------------------------|----------------------------------------------------|
| `Name`           | `string`        | `"name"`                      | Hook identifier, non-empty                         |
| `Checksum`       | `string`        | `"checksum"`                  | Hook payload SHA-256: 32 bytes, standard-padded base64 |
| `Description`    | `string`        | `"description,omitempty"`     | What the hook does, at most 4096 characters        |
| `Parameters`     | `[]ActionParam` | `"parameters,omitempty"`      | What the hook expects, in sidecar order, at most 64. Each `Name` is non-empty after trimming and unique within the hook, and `Name`, `Type`, `Default`, and `Description` are at most 4096 characters each |
| `TimeoutSeconds` | `int64`         | `"timeout_seconds,omitempty"` | The timeout the sidecar declares, in whole seconds from 0 to 86400. 0 means none declared |
| `SandboxLevel`   | `string`        | `"sandbox_level,omitempty"`   | The sandbox level the sidecar declares, at most 64 characters, free-form |
| `Source`         | `string`        | `"source,omitempty"`          | `rollout` for a script installed from a published version. Empty, and off the wire, for every other hook: the contract reads an absent `source` as `local`. The contract also accepts `local`, and answers any other value with `400 declared_hook_invalid` |
| `Version`        | `int`           | `"version,omitempty"`         | The published version installed, 1 to 2147483647. Required with `source` `rollout` and refused on any other entry, both with `400 declared_hook_invalid`, so it is zero, and off the wire, for every other entry |

The four fields after `Checksum` come from the hook's sidecar and describe the
hook. They gate nothing at the control plane and sit outside its digest, so a
hand-placed hook with no sidecar marshals to `name` and `checksum` alone. plexd
applies the sidecar's `timeout` and `sandbox` when it runs the hook. Characters
are Unicode code points, and a NUL in any of these strings is refused.

`Source` and `Version` mark a hook a rollout installed. The control plane then
takes the published checksum of that version as the hook's baseline instead of
the first digest the node reported, so a rolled-out hook is never trusted on
first use. A hand-placed hook is sent with neither key, so a node with no
rolled-out hook sends the manifest it sent before rollouts existed.

**HookRolloutError** — one published hook version the node could not install.
`Name` and `Version` are the pair the pull listed, so the operator's per-node
rollout status can put the error beside the rollout that caused it.

| Field     | Type     | JSON Tag             | Description                                        |
|-----------|----------|----------------------|----------------------------------------------------|
| `Name`    | `string` | `"name"`             | The hook name, as the pull listed it               |
| `Version` | `int`    | `"version"`          | The version the pull listed, 1 to 2147483647       |
| `Code`    | `string` | `"code"`             | What went wrong, matching `^[a-z0-9_]{1,64}$`: one of the `HookRolloutCode` constants below |
| `Detail`  | `string` | `"detail,omitempty"` | An explanation, at most 1024 code points with no NUL. plexd replaces a NUL with U+FFFD and cuts a longer detail |

More than 64 entries answer `400 hook_rollout_errors_too_many`, and an entry that
breaks a limit `400 hook_rollout_error_invalid`. plexd sends at most 64, sorted
by name, and keeps each entry inside the limits.

**Hook source and rollout constants**

| Constant                            | Value                 | Description |
|-------------------------------------|-----------------------|-------------|
| `HookSourceLocal`                   | `local`               | A hook placed on the node by other means than a rollout, such as a script in `hooks_dir`. `HookInfo.Source` carries it; the manifest leaves the key off |
| `HookSourceRollout`                 | `rollout`             | A script installed from a published hook version |
| `HookRolloutCodeCollision`          | `collision`           | `hooks_dir` holds a hook of the rollout's name |
| `HookRolloutCodeVerificationFailed` | `verification_failed` | The version's signature or checksum did not verify |
| `HookRolloutCodeFetchFailed`        | `fetch_failed`        | The version could not be fetched |
| `HookRolloutCodeInstallFailed`      | `install_failed`      | The version could not be installed, or will not be on this platform or under this configuration |
| `MaxHookRolloutErrors`              | `64`                  | The most `hook_rollout_errors` entries one manifest may carry |
| `MaxHookRolloutDetailChars`         | `1024`                | The longest `detail`, in Unicode code points |

The control plane accepts any code that matches the pattern and shows it as
sent, so a newer agent's code never refuses the manifest.

**DiscoveredPlexdHook** — one `PlexdHook` resource as the manifest reports it
(the contract's `PlexdHook` schema).

| Field            | Type                | JSON Tag                      | Description                                        |
|------------------|---------------------|-------------------------------|----------------------------------------------------|
| `Name`           | `string`            | `"name"`                      | Resource name, unique within its namespace         |
| `ImageDigest`    | `string`            | `"image_digest"`              | Hook image digest, canonical `sha256:<64 lowercase hex>` |
| `Parameters`     | `map[string]string` | `"parameters,omitempty"`      | The spec's name/value list folded into a map       |
| `TimeoutSeconds` | `int64`             | `"timeout_seconds,omitempty"` | Execution timeout; never set, because the CRD has no timeout field |
| `Sandbox`        | `bool`              | `"sandbox,omitempty"`         | `true` unless the hook is privileged               |

The handler decodes this body with `DisallowUnknownFields`, so the manifest
carries these fields and nothing else. Three consequences are worth stating
outright:

- **The digest is base64, never hex.** Both checksum fields are declared
  `format: byte`, so a hex digest decodes to 48 bytes and is refused with
  `binary_checksum_invalid`. `integrity.WireChecksum` converts the hex form the
  integrity package works in into the wire form.
- **One refused entry costs the whole manifest.** An inventory entry that breaks
  an invariant is answered `422`, and the binary version and checksum are lost
  with it. plexd therefore sends only entries it knows are valid: at most 128 per
  inventory, at most 64 parameters per action, unique names, and a canonical
  image digest on every PlexdHook. A declared hook's metadata that breaks a limit
  is answered `400`, not `422`: `declared_hooks_too_many` past 64 parameters and
  `declared_hook_invalid` otherwise. plexd leaves such a field off with a warning,
  and a manifest refused anyway for its metadata goes out again in the short
  `name` and `checksum` form.
- **Empty inventories are omitted.** Both inventory fields,
  `ActionInfo.Parameters`, and `DeclaredHook.Parameters` are `omitempty`, so an
  empty list leaves its key off instead of sending `null` where the contract
  expects an array.

A missing key means none, because the control plane replaces its stored row on
every PUT. A manifest that leaves `declared_hooks` or `plexd_hooks` off clears
that list; it does not keep what the last manifest reported.

**BinaryInfo** — the node API's local view of the running binary. The control
plane receives the same two values as the manifest's flat fields.

| Field    | Type   | JSON Tag    | Description        |
|----------|--------|-------------|--------------------|
| `Version`| `string`| `"version"`| Binary version     |
| `Checksum`| `string`| `"checksum"`| Binary checksum  |

**ActionInfo**

| Field        | Type            | JSON Tag        | Description            |
|--------------|-----------------|-----------------|------------------------|
| `Name`       | `string`        | `"name"`        | Action name            |
| `Description`| `string`        | `"description"` | Action description     |
| `Parameters` | `[]ActionParam` | `"parameters"`  | Action parameters      |

**ActionParam**

| Field        | Type   | JSON Tag        | Description              |
|--------------|--------|-----------------|--------------------------|
| `Name`       | `string`| `"name"`       | Parameter name           |
| `Type`       | `string`| `"type"`       | Parameter type           |
| `Required`   | `bool` | `"required"`    | Whether required         |
| `Default`    | `string`| `"default,omitempty"` | Default value for optional parameters |
| `Description`| `string`| `"description"`| Parameter description   |

**HookInfo**

| Field        | Type            | JSON Tag        | Description           |
|--------------|-----------------|-----------------|-----------------------|
| `Name`       | `string`        | `"name"`        | Hook name             |
| `Description`| `string`        | `"description"` | Hook description      |
| `Source`     | `string`        | `"source"`      | Where the hook came from: `local` for a hook in `hooks_dir`, `rollout` for one plexd installed from a published version |
| `Checksum`   | `string`        | `"checksum"`    | Source checksum       |
| `Parameters` | `[]ActionParam` | `"parameters"`  | Hook parameters       |
| `Timeout`    | `string`        | `"timeout"`     | Execution timeout     |
| `Sandbox`    | `string`        | `"sandbox"`     | Sandbox type          |
| `Version`    | `int`           | `"version,omitempty"` | The published version a rolled-out hook was installed from; zero, and omitted, for a `local` hook |

## NAT Endpoint

### `PUT /v1/nodes/{node_id}/endpoint`

**EndpointRequest**

| Field        | Type        | JSON Tag        | Description                            |
|--------------|-------------|-----------------|----------------------------------------|
| `Endpoint`   | `string`    | `"endpoint"`    | Discovered public endpoint (`ip:port`) |
| `NATType`    | `string`    | `"nat_type"`    | Wire NAT type (`full_cone`, `restricted`, `port_restricted`, `symmetric`, `unknown`) |
| `PortMapping` | `string`   | `"port_mapping,omitempty"` | Whether the NAT kept the STUN probe's source port: `preserved` or `translated`; omitted when empty |
| `ReportedAt` | `time.Time` | `"reported_at"` | RFC 3339 UTC, stamped fresh per attempt |

**EndpointResponse**

| Field        | Type        | JSON Tag        | Description                            |
|--------------|-------------|-----------------|----------------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time                    |
| `StaleAfter` | `time.Time` | `"stale_after"` | Deadline after which the endpoint is stale; drives the re-report cadence |

The response does not carry peer endpoints. Each peer's direct endpoint rides the
state pull as `SnapshotPeer.Endpoint` (see [State](#state)). A
`peer_endpoint_changed` SSE event only triggers a reconcile, and plexd never
decodes its payload.

## Endpoint Candidates

### `PUT /v1/nodes/{node_id}/endpoint-candidates`

The node's local interface addresses, each joined with its WireGuard listen
port. Each report replaces the previous set. Peers receive the set as
`SnapshotPeer.EndpointCandidates` (see [State](#state)). See
[Control Plane API Endpoints](api-endpoints.md#put-v1-nodes-node-id-endpoint-candidates)
for the field rules and error taxonomy.

**EndpointCandidatesRequest**

| Field        | Type        | JSON Tag        | Description                                    |
|--------------|-------------|-----------------|------------------------------------------------|
| `Candidates` | `[]string`  | `"candidates"`  | 0 to `MaxEndpointCandidates` (8) distinct `host:port` strings, an IPv6 host in brackets and without a zone; `[]` when empty, never `null`. An empty array withdraws every earlier candidate |
| `ReportedAt` | `time.Time` | `"reported_at"` | RFC 3339 UTC; the server refuses a value more than 60s from its own time with `400 endpoint_clock_skew` |

`ReportEndpointCandidates` sends a nil `Candidates` as an empty array, on a
copy, so the caller's request is left as passed: the control plane answers
`null` with `400 malformed_endpoint_candidates`. More than
`MaxEndpointCandidates` entries return an error matching
`ErrEndpointCandidatesTooMany` without sending a request.

**EndpointCandidatesResponse** (`200 OK`)

| Field        | Type        | JSON Tag        | Description                                    |
|--------------|-------------|-----------------|------------------------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time                            |
| `StaleAfter` | `time.Time` | `"stale_after"` | Deadline after which the control plane drops the set; drives the next report |

**Constants**

| Constant                | Value | Description                                          |
|-------------------------|-------|------------------------------------------------------|
| `MaxEndpointCandidates` | `8`   | Most candidates one report may carry                 |

## Handshakes

### `POST /v1/nodes/{node_id}/handshakes`

The per-peer WireGuard handshake report the control plane derives mesh edge
health from. The handler decodes with unknown fields refused, and every `400`
refuses the whole report. See
[Control Plane API Endpoints](api-endpoints.md#mesh-edge-health) for the wire
examples and error taxonomy.

**HandshakeReportRequest**

| Field        | Type                    | JSON Tag        | Description                                    |
|--------------|-------------------------|-----------------|------------------------------------------------|
| `ObservedAt` | `time.Time`             | `"observed_at"` | Node wall clock when the report was assembled; the server refuses a skew above 60s |
| `Peers`      | `[]HandshakeReportPeer` | `"peers"`       | 0 to `MaxHandshakeReportPeers` (4096) entries; `[]` when empty, never `null` |

`ReportHandshakes` replaces a nil `Peers` with an empty slice before it marshals
the body, because the control plane answers `null` with
`400 malformed_handshake_report`. More than `MaxHandshakeReportPeers` entries
return an error matching `ErrHandshakeReportTooMany` without sending a request.

**HandshakeReportPeer**

| Field                     | Type     | JSON Tag                       | Description                                    |
|---------------------------|----------|--------------------------------|------------------------------------------------|
| `PeerNodeID`              | `string` | `"peer_node_id"`               | Peer node ID, a non-zero UUID; unique within the report |
| `LastHandshakeAgeSeconds` | `int32`  | `"last_handshake_age_seconds"` | Seconds since the latest completed handshake, 0 to 2147483647 |
| `Endpoint`                | `string` | `"endpoint"`                   | Endpoint WireGuard uses for the peer, `host:port` with an IPv6 host in brackets; a non-zero port, a specified address and no zone |

**HandshakeReportResponse** (`200 OK`)

| Field        | Type        | JSON Tag        | Description                                    |
|--------------|-------------|-----------------|------------------------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time every age was anchored on  |
| `Recorded`   | `int`       | `"recorded"`    | Entries stored as the latest observation of their edge |
| `Ignored`    | `int`       | `"ignored"`     | Entries naming the node itself, an unknown node, a node of another Domain, or a deregistered peer |

**Constants**

| Constant                  | Value  | Description                                          |
|---------------------------|--------|------------------------------------------------------|
| `MaxHandshakeReportPeers` | `4096` | Most entries one report may carry (the contract's `maxItems`) |

## Relay Status

### `PUT /v1/nodes/{node_id}/relay-status`

The state of a bridge's relay, which the control plane reads to stop assigning
a relay that does not run. The handler decodes with unknown members refused, and
`State` decides which other members a report carries. See
[Control Plane API Endpoints](api-endpoints.md#relay-status) for the wire
examples and error taxonomy, and
[NAT Relay](../bridge/nat-relay.md#relay-status-report) for how plexd derives
the state.

**RelayStatusRequest**

| Field          | Type     | JSON Tag                    | Description                                    |
|----------------|----------|-----------------------------|------------------------------------------------|
| `State`        | `string` | `"state"`                   | One of the `RelayState*` constants             |
| `ListenPort`   | `int`    | `"listen_port,omitempty"`   | The relay's UDP port, 1..65535; set for `running` and `bind_failed`, left 0 and so omitted otherwise |
| `BoundSeconds` | `*int64` | `"bound_seconds,omitempty"` | Whole seconds since the relay socket was bound, 0 to `MaxRelayStatusBoundSeconds`; set for `running`, left nil and so omitted otherwise |

`BoundSeconds` is a pointer because 0 is a valid value, for a socket bound less
than a second ago: a plain `int64` with `omitempty` would drop it, and the
control plane would refuse the `running` report with
`400 invalid_relay_status`. `ListenPort` stays a plain `int`: 0 is never a valid
port, and the two states that forbid the member leave it 0, so `omitempty` drops
it exactly where it must be absent. A member the state requires or forbids is
refused with `400 invalid_relay_status`, and an out-of-range value or a `null`
member with `400 malformed_relay_status`. `ReportRelayStatus` checks none of
this and sends the request as passed. The server anchors `BoundSeconds` on its
receive time, so plexd builds a fresh request for every attempt.

**RelayStatusResponse** (`200 OK`)

| Field        | Type        | JSON Tag        | Description                                    |
|--------------|-------------|-----------------|------------------------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time `BoundSeconds` was anchored on |

**Constants**

| Constant                     | Value             | Description                                          |
|------------------------------|-------------------|------------------------------------------------------|
| `RelayStateRunning`          | `"running"`       | The relay socket is bound on `ListenPort`            |
| `RelayStateStopped`          | `"stopped"`       | The relay does not run: the pull does not enable it, names a `listen_port` outside 1..65535, or plexd stops it because it shuts down |
| `RelayStateBindFailed`       | `"bind_failed"`   | The relay socket could not be bound on `ListenPort`  |
| `RelayStateNotConsented`     | `"not_consented"` | The pull enables a relay that `bridge.relay_enabled` does not consent to |
| `MaxRelayStatusBoundSeconds` | `315360000`       | The contract's ceiling on `bound_seconds`, 3650 days |

## Ingress Status

### `PUT /v1/nodes/{node_id}/ingress-status`

Whether a bridge's local configuration serves public ingress, which the control
plane reads to refuse an ingress rule that no listener would serve, and the
state of each ingress rule, on a rule with `client_auth` whether the bridge
verifies its clients and the last client it refused per reason. The control
plane keeps the latest state per node and never ages it, and each report
replaces the rule entries of the one before.
The handler decodes with unknown members refused, of the report and of each
entry. See [Control Plane API Endpoints](api-endpoints.md#ingress-status) for
the wire example and error taxonomy, and
[Public Ingress](../bridge/public-ingress.md#ingress-status-report) for how
plexd derives the state and each entry.

**IngressStatusRequest**

| Field   | Type                  | JSON Tag            | Description                              |
|---------|-----------------------|---------------------|------------------------------------------|
| `State` | `string`              | `"state"`           | One of the `IngressState*` constants     |
| `Rules` | `[]IngressStatusRule` | `"rules,omitempty"` | One entry per reported rule, in the order of the pull, at most `MaxIngressStatusRules`; nil omits the member, which reads as no entries |

**IngressStatusRule**, the control plane's `IngressStatusReportRule`. Each
member after `Listener` is sent exactly when the facet before it calls for it,
and `omitempty` drops an empty one, so a caller leaves every member it must not
send empty:

| Field               | Type     | JSON Tag                        | Description |
|---------------------|----------|---------------------------------|-------------|
| `ID`                | `string` | `"id"`                          | The rule's `id` from the pull, a UUID other than the zero UUID |
| `Listener`          | `string` | `"listener"`                    | One of the `IngressListener*` constants |
| `ListenerReason`    | `string` | `"listener_reason,omitempty"`   | A reason token; exactly when `Listener` is `not_listening` |
| `Certificate`       | `string` | `"certificate,omitempty"`       | One of the `IngressCertificate*` constants; exactly when `Listener` is `listening` |
| `CertificateReason` | `string` | `"certificate_reason,omitempty"` | A reason token; exactly when `Certificate` is `not_ready` |
| `Dial`              | `string` | `"dial,omitempty"`              | One of the `IngressDial*` constants; exactly when `Listener` is `listening` |
| `DialReason`        | `string` | `"dial_reason,omitempty"`       | A reason token; exactly when `Dial` is `failed` |
| `DialAgeSeconds`    | `*int64` | `"dial_age_seconds,omitempty"`  | Whole seconds from the dial to the report, 0 to `MaxIngressStatusDialAgeSeconds`; exactly when `Dial` is `succeeded` or `failed`. A pointer, because 0 is a valid age |
| `Targets`           | `[]IngressStatusTarget` | `"targets,omitempty"` | At most `MaxIngressStatusTargets` entries, one per target of the rule, only beside a `Listener` of `listening`; nil omits the member, which reads as no entries |
| `ClientAuthEnforced` | `bool` | `"client_auth_enforced,omitempty"` | The bridge verifies every client of the rule against its client authorities, or serves no client of the rule. `true` only beside a `Listener` of `listening`, and sent only for a rule whose pull entry carries `client_auth`; `false` omits the member, which the contract reads as `false` |
| `ClientRefusals` | `[]IngressStatusClientRefusal` | `"client_refusals,omitempty"` | At most `MaxIngressStatusClientRefusals` entries, one per reason, only beside a `ClientAuthEnforced` of `true`; nil omits the member, which reads as no entries. plexd sends at most four, one per refusal reason it knows |

**IngressStatusTarget**, the control plane's `IngressStatusReportRuleTarget`:
the target as the pull names it and the last dial the bridge made to it.
`DialReason` is sent exactly when `Dial` is `failed`, and `DialAgeSeconds`
exactly when `Dial` is `succeeded` or `failed`. No two entries of one rule name
the same `NodeID` and `Port`:

| Field            | Type     | JSON Tag                       | Description |
|------------------|----------|--------------------------------|-------------|
| `NodeID`         | `string` | `"node_id"`                    | The target's `node_id` from the pull, a UUID other than the zero UUID |
| `Port`           | `int`    | `"port"`                       | The target's `port` from the pull, 1 to 65535 |
| `Dial`           | `string` | `"dial"`                       | One of the `IngressDial*` constants |
| `DialReason`     | `string` | `"dial_reason,omitempty"`      | A reason token; exactly when `Dial` is `failed` |
| `DialAgeSeconds` | `*int64` | `"dial_age_seconds,omitempty"` | Whole seconds from the last dial to the target to the report, 0 to `MaxIngressStatusDialAgeSeconds`; exactly when `Dial` is `succeeded` or `failed` |

**IngressStatusClientRefusal**, the control plane's
`IngressStatusReportRuleClientRefusal`: the last client the bridge refused for
one reason. No two entries of one rule name the same `Reason`:

| Field        | Type     | JSON Tag        | Description |
|--------------|----------|-----------------|-------------|
| `Reason`     | `string` | `"reason"`      | A reason token: `no_certificate`, `unknown_authority`, `certificate_expired` or `certificate_invalid` |
| `AgeSeconds` | `int64`  | `"age_seconds"` | Whole seconds from the refusal to the report, 0 to `MaxIngressStatusRefusalAgeSeconds`. The contract requires the member, and 0 is a valid age, so it has no `omitempty` |

The `Targets` and `ClientRefusals` slices make a rule entry incomparable with
`==`, so the reporter compares two entries member by member, the dial ages of
the rule and of its targets and the client refusals ignored, so a refusal
alone sends nothing, while a change of `ClientAuthEnforced` counts.

A missing, `null` or unknown state, an unknown member, data after the report,
more than `MaxIngressStatusRules` entries, and an entry with a malformed id or
a value outside its member's rule answer `400 malformed_ingress_status`, and so
do more than `MaxIngressStatusTargets` target entries and a target entry with a
malformed `node_id` or a value outside its member's rule. A
`client_auth_enforced` that is not a boolean, a `client_refusals` that is not
an array or holds more than `MaxIngressStatusClientRefusals` entries, and a
refusal entry that is not an object, carries an unknown member, or whose
`reason` is not a reason token or whose `age_seconds` is outside its range
answer `400 malformed_ingress_status` too. An opted-out report with entries, a
repeated id, an entry that breaks the presence rules, target entries on a rule
that is not listening, a target entry that breaks the presence rules, two
target entries of one rule with the same `node_id` and `port`, a
`client_auth_enforced` of `true` on a rule that is not listening, refusal
entries on a rule without a `client_auth_enforced` of `true`, and two refusal
entries of one rule with the same `reason` answer `400 invalid_ingress_status`.
`ReportIngressStatus` checks none of this and sends the request as passed.

**IngressStatusResponse** (`200 OK`)

| Field        | Type        | JSON Tag        | Description                    |
|--------------|-------------|-----------------|--------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time of the report |

**Constants**

| Constant               | Value         | Description                                          |
|------------------------|---------------|------------------------------------------------------|
| `IngressStateEnabled`  | `"enabled"`   | The bridge's local configuration serves the public ingress rules the state pull enables: `bridge.ingress_enabled` is absent or `true` |
| `IngressStateOptedOut` | `"opted_out"` | The bridge's local configuration, `bridge.ingress_enabled: false`, rules public ingress out: it opens no public listener whatever the pull says |
| `IngressListenerListening` | `"listening"` | The rule's listen port is bound |
| `IngressListenerNotListening` | `"not_listening"` | The bridge does not listen for the rule; `ListenerReason` says why |
| `IngressCertificateNotRequired` | `"not_required"` | A `passthrough` rule, which needs no certificate at the bridge |
| `IngressCertificateReady` | `"ready"` | A `terminate` or `acme` rule whose certificate is in place |
| `IngressCertificateNotReady` | `"not_ready"` | A `terminate` or `acme` rule without its certificate; `CertificateReason` says why |
| `IngressDialNone` | `"none"` | On a rule entry, the bridge has not dialled a target of the rule for a client yet, or, for a `udp` rule, not sent a client's datagram yet; on a target entry, the bridge has not dialled the target yet |
| `IngressDialSucceeded` | `"succeeded"` | On a rule entry, a target took the rule's last unit; on a target entry, the last dial reached the target |
| `IngressDialFailed` | `"failed"` | On a rule entry, no target took the rule's last unit; on a target entry, the last dial to the target failed. `DialReason` says why |
| `MaxIngressStatusRules` | `1024` | The most entries one report carries |
| `MaxIngressStatusDialAgeSeconds` | `2147483647` | The ceiling of `dial_age_seconds`, the largest signed 32-bit integer |
| `MaxIngressStatusTargets` | `8` | The most target entries one rule entry carries, the most targets a rule holds |
| `MaxIngressStatusClientRefusals` | `8` | The contract's ceiling on the refusal entries of one rule entry |
| `MaxIngressStatusRefusalAgeSeconds` | `2147483647` | The ceiling of a refusal's `age_seconds`, the largest signed 32-bit integer |

**Validators**

| Function | Description |
|----------|-------------|
| `ValidIngressRuleID(s string) bool` | `s` is a UUID in canonical form, groups of 8, 4, 4, 4 and 12 hex digits in either case joined by hyphens, other than the zero UUID. Written by hand: `github.com/google/uuid` stays an indirect dependency |
| `ValidIngressTargetNodeID(s string) bool` | `s` is a `node_id` the control plane accepts in a target entry: a UUID in canonical form other than the zero UUID, as `ValidIngressRuleID` checks it |
| `ValidIngressReason(s string) bool` | `s` matches `^[a-z][a-z0-9_]{0,62}$` |

## User Access Status

### `PUT /v1/nodes/{node_id}/user-access-status`

Whether a bridge's local configuration serves user access, which the control
plane reads to refuse a provider or a device that no bridge would serve, and
whether each user access provider of its pull is up. The control plane keeps
the latest state per node and never ages it, and each report replaces the
provider entries of the one before. The control plane's side is
[plexsphere/plexsphere#1108](https://github.com/plexsphere/plexsphere/pull/1108).
See [Control Plane API Endpoints](api-endpoints.md#user-access-status) for the
wire example and error taxonomy, and
[User Access Integration](../bridge/user-access-integration.md#user-access-status-report)
for how plexd derives the state and each entry.

**UserAccessStatusRequest**

| Field       | Type                         | JSON Tag                | Description |
|-------------|------------------------------|-------------------------|-------------|
| `State`     | `string`                     | `"state"`               | One of the `UserAccessState*` constants |
| `Providers` | `[]UserAccessStatusProvider` | `"providers,omitempty"` | One entry per reported provider, in the order of the pull, at most `MaxUserAccessStatusProviders`; nil omits the member, which reads as no entries |

**UserAccessStatusProvider**, the control plane's
`UserAccessStatusReportProvider`. `Reason` is sent exactly when `Health` is
`down`; `PublicKey` and `ConnectedDevices` only when it is `up`, and plexd sends
both for a `wireguard` provider that is up and neither for a `tailscale` or
`netbird` one. `omitempty` drops an empty member, so a caller leaves every
member it must not send empty:

| Field              | Type     | JSON Tag                         | Description |
|--------------------|----------|----------------------------------|-------------|
| `ID`               | `string` | `"id"`                           | The provider's `id` from the pull, a UUID other than the zero UUID |
| `Health`           | `string` | `"health"`                       | One of the `UserAccessHealth*` constants |
| `Reason`           | `string` | `"reason,omitempty"`             | A reason token of the grammar `^[a-z][a-z0-9_]{0,62}$`; exactly when `Health` is `down` |
| `PublicKey`        | `string` | `"public_key,omitempty"`         | The public key of a `wireguard` provider's interface: 44 characters of standard base64 that decode to 32 bytes |
| `ConnectedDevices` | `*int`   | `"connected_devices,omitempty"`  | The provider's devices whose latest WireGuard handshake is at most 180 s old, 0 to 1024. A pointer, because 0 is a valid count: a nil pointer omits the member, a pointer to 0 sends `"connected_devices":0` |

A missing, `null` or unknown state, an unknown member, data after the report,
more than `MaxUserAccessStatusProviders` entries, an entry with a malformed id
or a value outside its member's rule, and an entry that breaks the presence
rules answer `400 malformed_user_access_status`; an opted-out report with
entries and a repeated id answer `400 invalid_user_access_status`. A body over
64 KiB answers `413 user_access_status_body_too_large`.
`ReportUserAccessStatus` checks none of this and sends the request as passed.

**UserAccessStatusResponse** (`200 OK`)

| Field        | Type        | JSON Tag        | Description                    |
|--------------|-------------|-----------------|--------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time of the report |

**Constants**

| Constant | Value | Description |
|---|---|---|
| `UserAccessStateEnabled` | `"enabled"` | The bridge's local configuration serves the user access providers the state pull enables: `bridge.user_access_enabled` is absent or `true` |
| `UserAccessStateOptedOut` | `"opted_out"` | The bridge's local configuration, `bridge.user_access_enabled: false`, rules user access out: it serves no provider whatever the pull says |
| `UserAccessHealthUp` | `"up"` | The bridge serves the provider |
| `UserAccessHealthDown` | `"down"` | The bridge does not serve the provider; `Reason` says why |
| `MaxUserAccessStatusProviders` | `256` | The most entries one report carries; a bridge with more reports the first ones in the order of the pull |

The reason tokens plexd sends, and what each means, are listed in
[Reasons](../bridge/user-access-integration.md#reasons).
`ValidUserAccessProviderID` checks an entry's id (see `UserAccessProvider`
under [State](#state)).

**Client and classifier**

| Function | Description |
|---|---|
| `(*ControlPlane).ReportUserAccessStatus(ctx, nodeID string, req UserAccessStatusRequest) (*UserAccessStatusResponse, error)` | Sends `PUT /v1/nodes/{node_id}/user-access-status` with the request as JSON and returns the receipt. It path-escapes the node ID and validates nothing |
| `IsUserAccessStatusNotServed(err error) bool` | True for an `*APIError` with status `404` and any code but `user_access_status_node_gone`, and for a `501` carrying `user_access_status_not_provisioned`: the control plane does not serve the operation. False for everything else, a `404 user_access_status_node_gone` included |

## Site-to-Site Status

### `PUT /v1/nodes/{node_id}/site-to-site-status`

Whether a bridge's local configuration serves site-to-site tunnels, which the
control plane reads to refuse a tunnel no bridge would serve, and whether each
tunnel of its pull is up and answered by its remote site. The control plane
keeps the latest state per node and never ages it, and each report replaces the
tunnel entries of the one before. The control plane's side is
[plexsphere/plexsphere#1109](https://github.com/plexsphere/plexsphere/pull/1109).
See [Control Plane API Endpoints](api-endpoints.md#site-to-site-status) for the
wire example and error taxonomy, and
[Site-to-Site VPN](../bridge/site-to-site-vpn.md) for how plexd derives the
state and each entry.

**SiteToSiteStatusRequest**

| Field     | Type                       | JSON Tag              | Description |
|-----------|----------------------------|-----------------------|-------------|
| `State`   | `string`                   | `"state"`             | One of the `SiteToSiteState*` constants |
| `Tunnels` | `[]SiteToSiteStatusTunnel` | `"tunnels,omitempty"` | One entry per reported tunnel, in the order of the pull, at most `MaxSiteToSiteStatusTunnels`; nil omits the member, which reads as no entries |

**SiteToSiteStatusTunnel**, the control plane's
`SiteToSiteStatusReportTunnel`. `Reason` is sent exactly when `Health` is
`down`, `Established` exactly when it is `up`, and `PublicKey` only when it is
`up`: plexd sends it for a `wireguard` tunnel that is up and never for an
`ipsec` or `openvpn` one. `omitempty` drops an empty member, so a caller leaves
every member it must not send empty, and `Established` nil:

| Field         | Type     | JSON Tag                  | Description |
|---------------|----------|---------------------------|-------------|
| `ID`          | `string` | `"id"`                    | The tunnel's `id` from the pull, a UUID other than the zero UUID |
| `Health`      | `string` | `"health"`                | One of the `SiteToSiteHealth*` constants |
| `Reason`      | `string` | `"reason,omitempty"`      | A reason token of the grammar `^[a-z][a-z0-9_]{0,62}$`; exactly when `Health` is `down` |
| `Established` | `*bool`  | `"established,omitempty"` | Whether the remote site answers: for a `wireguard` tunnel the latest handshake with the remote peer is at most 180 s old, for an `ipsec` tunnel the IKE and child security associations stand, and for an `openvpn` tunnel the peer is connected. A pointer, because `false` is a value the contract requires on a tunnel that is up: a nil pointer omits the member, a pointer to `false` sends `"established":false` |
| `PublicKey`   | `string` | `"public_key,omitempty"`  | The public key of a `wireguard` tunnel's interface: 44 characters of standard base64 that decode to 32 bytes |

A missing, `null` or unknown state, an unknown member, data after the report,
more than `MaxSiteToSiteStatusTunnels` entries, an entry with a malformed id or
a value outside its member's rule, and an entry that breaks the presence rules
answer `400 malformed_site_to_site_status`; an opted-out report with entries
and a repeated id answer `400 invalid_site_to_site_status`. A body over 64 KiB
answers `413 site_to_site_status_body_too_large`. `ReportSiteToSiteStatus`
checks none of this and sends the request as passed.

**SiteToSiteStatusResponse** (`200 OK`)

| Field        | Type        | JSON Tag        | Description                    |
|--------------|-------------|-----------------|--------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time of the report |

**Constants**

| Constant | Value | Description |
|---|---|---|
| `SiteToSiteStateEnabled` | `"enabled"` | The bridge's local configuration serves the site-to-site tunnels the state pull enables: `bridge.site_to_site_enabled` is absent or `true` |
| `SiteToSiteStateOptedOut` | `"opted_out"` | The bridge's local configuration, `bridge.site_to_site_enabled: false`, rules site-to-site tunnels out: it serves no tunnel whatever the pull says |
| `SiteToSiteHealthUp` | `"up"` | The bridge serves the tunnel |
| `SiteToSiteHealthDown` | `"down"` | The bridge does not serve the tunnel; `Reason` says why |
| `MaxSiteToSiteStatusTunnels` | `256` | The most entries one report carries; a bridge with more reports the first ones in the order of the pull |

The reason tokens plexd sends, and what each means, are listed on
[Site-to-Site VPN](../bridge/site-to-site-vpn.md); besides the contract's,
plexd sends `invalid_tunnel`, `setup_failed` and `key_unavailable`, which the
control plane stores as it stores any token of the grammar.
`ValidSiteToSiteTunnelID` checks an entry's id (see `SiteToSiteTunnel` under
[State](#state)).

**Client and classifier**

| Function | Description |
|---|---|
| `(*ControlPlane).ReportSiteToSiteStatus(ctx, nodeID string, req SiteToSiteStatusRequest) (*SiteToSiteStatusResponse, error)` | Sends `PUT /v1/nodes/{node_id}/site-to-site-status` with the request as JSON and returns the receipt. It path-escapes the node ID and validates nothing |
| `IsSiteToSiteStatusNotServed(err error) bool` | True for an `*APIError` with status `404` and any code but `site_to_site_status_node_gone`, and for a `501` carrying `site_to_site_status_not_provisioned`: the control plane does not serve the operation. False for everything else, a `404 site_to_site_status_node_gone` included |

## Policy Status

### `PUT /v1/nodes/{node_id}/policy-status`

What the node did with the policy block of its pulls: what it enforces, the
ruleset it applied, the ruleset its latest apply failed on and why, and what its
default deny dropped. The handler decodes with unknown members refused. See
[Control Plane API Endpoints](api-endpoints.md#policy-status) for the wire
examples and error taxonomy, and
[Policy status report](../networking/network-policy.md#policy-status-report)
for how plexd builds the report.

**PolicyStatusRequest**

| Field         | Type                    | JSON Tag                 | Description                                    |
|---------------|-------------------------|--------------------------|------------------------------------------------|
| `Enforcement` | `string`                | `"enforcement"`          | One of the `PolicyEnforcement*` constants      |
| `Applied`     | `*PolicyStatusApplied`  | `"applied,omitempty"`    | The ruleset the node applied last; nil while it applied none since plexd started |
| `Rejected`    | `*PolicyStatusRejected` | `"rejected,omitempty"`   | The ruleset the node's latest apply failed on; nil when the latest apply did not fail |
| `Drops`       | `*PolicyStatusDrops`    | `"drops,omitempty"`      | The default deny's counters; nil when the firewall backend does not count drops |

**PolicyStatusApplied**

| Field         | Type                  | JSON Tag                 | Description                                    |
|---------------|-----------------------|--------------------------|------------------------------------------------|
| `Fingerprint` | `string`              | `"fingerprint,omitempty"` | The applied block's fingerprint; empty, and so absent, when the applied pull carried `policy: null` |
| `Revisions`   | `[]PolicyRevisionRef` | `"revisions"`            | The applied block's revisions, at most 4096; `[]` for a `policy: null` pull, never `null` |

**PolicyStatusRejected**

| Field         | Type                  | JSON Tag          | Description                                    |
|---------------|-----------------------|-------------------|------------------------------------------------|
| `Fingerprint` | `string`              | `"fingerprint"`   | The rejected block's fingerprint               |
| `Revisions`   | `[]PolicyRevisionRef` | `"revisions"`     | The rejected block's revisions, at most 4096; never `null` |
| `Reason`      | `string`              | `"reason"`        | Why the apply failed: 1 to 1024 bytes of UTF-8 without control characters |

**PolicyStatusDrops**

| Field     | Type    | JSON Tag    | Description                                    |
|-----------|---------|-------------|------------------------------------------------|
| `Packets` | `int64` | `"packets"` | Packets the default deny dropped since plexd last installed the ruleset, at least 0 |
| `Bytes`   | `int64` | `"bytes"`   | Bytes the default deny dropped since then, at least 0 |

Every member of `PolicyStatusApplied`, `PolicyStatusRejected` and
`PolicyStatusDrops` is required where its block is present, except
`PolicyStatusApplied.Fingerprint`. The control plane refuses a `null`
`revisions` with `400 invalid_policy_status`, so `ReportPolicyStatus` replaces a
nil `Revisions` in `Applied` and in `Rejected` with `[]`, on a copy, and leaves
the caller's request as passed. It checks nothing else. A counter below its
previous report tells the control plane that the count restarted. plexd counts
in `uint64` and caps each counter at `math.MaxInt64` before it sends.

**PolicyStatusResponse** (`200 OK`)

| Field        | Type        | JSON Tag        | Description                                    |
|--------------|-------------|-----------------|------------------------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time the report is stored with  |
| `Status`     | `string`    | `"status"`      | The policy status the report derives against the ruleset the pull serves: `applied`, `pending`, `rejected` or `not_enforced` |

**Constants**

| Constant                       | Value           | Description                                    |
|--------------------------------|-----------------|------------------------------------------------|
| `PolicyEnforcementEnforcing`   | `"enforcing"`   | The node programs the rulesets it applies, with its default deny after them |
| `PolicyEnforcementDisabled`    | `"disabled"`    | The node's local configuration turned enforcement off (`policy.enabled: false`) |
| `PolicyEnforcementUnavailable` | `"unavailable"` | Enforcement is on, but the node has no firewall backend that can program rules |

## Key Rotation

### `POST /v1/keys/rotate`

The server identifies the rotating node from its NSK bearer credential, so the
request carries no node id. The response is a receipt, not a peer list. The
propagated peer changes arrive via the next state pull. With edge PSKs on, plexd
fetches every edge PSK again on that pull from
`GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk` (see [Edge PSK](#edge-psk)).

**KeyRotateRequest**

| Field          | Type     | JSON Tag           | Description                                          |
|----------------|----------|--------------------|-----------------------------------------------------|
| `NewPublicKey` | `string` | `"new_public_key"` | New Curve25519 public key (44-char standard base64) |

**KeyRotateResponse**

| Field            | Type     | JSON Tag             | Description                                |
|------------------|----------|----------------------|--------------------------------------------|
| `RotationID`     | `string` | `"rotation_id"`      | Identifier for this rotation               |
| `KID`            | `string` | `"kid"`              | Key identifier for the rotated material    |
| `WrapKeyVersion` | `int`    | `"wrap_key_version"` | Wrap-key version (monotonic, `>= 0`)       |

## Sessions

The `sessions` block of the state snapshot and the activity records the node posts
back to `POST /v1/nodes/{node_id}/sessions/{session_id}`.

### `sessions` block of `GET /v1/nodes/{node_id}/state`

**NodeStateSession**

One live mediated-access session. The block is **desired state, not a queue**: it
is always present on the wire (`[]` when empty, never `null`). A response that
violates that contract by omitting or nulling the key decodes to a `nil`
`Sessions` pointer, which the tunnel dispatcher leaves alone rather than reading
as an empty block — emptiness tears every live session down, so the two cases
must stay distinguishable. An entry appears when the control plane issues the
session and disappears on revocation or hard expiry — that disappearance *is* the
teardown signal, so there is no revocation callback to answer and no terminal
status to report. A revocation the control plane announces in a verified
`session_revoked` event is normally closed by that event first (see
[Event Types](#event-types)); the disappearance stays the teardown for every
other revocation. A live entry is redelivered on every
pull, so a consumer must tolerate re-observing the same `SessionID`.

| Field                | Type            | JSON Tag                            | Description                                                          |
|----------------------|-----------------|-------------------------------------|----------------------------------------------------------------------|
| `SessionID`          | `string`        | `"session_id"`                      | Session identifier                                                   |
| `JTI`                | `string`        | `"jti"`                             | Equals the session id; carried opaquely and **never** evaluated      |
| `Kind`               | `string`        | `"kind"`                            | One of the `SessionKind*` values; selects the member of `Target`     |
| `Target`             | `SessionTarget` | `"target"`                          | Exactly one member set, matching `Kind`                              |
| `ExpiresAt`          | `time.Time`     | `"expires_at"`                      | Absolute UTC deadline, **not** a relative timeout                    |
| `IdleTimeoutSeconds` | `int`           | `"idle_timeout_seconds,omitempty"`  | Idle window in seconds; `0` or absent means no idle window           |

**SessionTarget**

| Field | Type                | JSON Tag          | Description                        |
|-------|---------------------|-------------------|------------------------------------|
| `SSH` | `*SessionTargetSSH` | `"ssh,omitempty"` | Target of an `ssh` session         |
| `K8s` | `*SessionTargetK8s` | `"k8s,omitempty"` | Target of a `k8s` session          |
| `TCP` | `*SessionTargetTCP` | `"tcp,omitempty"` | Target of a `tcp` session          |

**SessionTargetSSH**

| Field             | Type       | JSON Tag                       | Description                                            |
|-------------------|------------|--------------------------------|--------------------------------------------------------|
| `User`            | `string`   | `"user"`                       | Local account the session logs in as                   |
| `AllowedCommands` | `[]string` | `"allowed_commands,omitempty"` | Closed set of command lines the session may run        |

**SessionTargetK8s**

| Field               | Type       | JSON Tag                         | Description                            |
|---------------------|------------|----------------------------------|----------------------------------------|
| `User`              | `string`   | `"user"`                         | Impersonated Kubernetes user           |
| `ImpersonateGroups` | `[]string` | `"impersonate_groups,omitempty"` | Groups impersonated alongside the user |

**SessionTargetTCP**

| Field  | Type     | JSON Tag | Description                                       |
|--------|----------|----------|---------------------------------------------------|
| `Host` | `string` | `"host"` | Host the node forwards the session's connections to |
| `Port` | `int`    | `"port"` | Port on that host                                 |

**SessionKind constants**

| Constant          | Value | Description                                        |
|-------------------|-------|----------------------------------------------------|
| `SessionKindSSH`  | `ssh` | Mediates an SSH session; `Target.SSH` is set       |
| `SessionKindK8s`  | `k8s` | Mediates a Kubernetes API session; `Target.K8s` is set |
| `SessionKindTCP`  | `tcp` | Mediates a plain TCP forward; `Target.TCP` is set  |

This agent provisions `tcp` entries, and `ssh` entries on Linux and macOS; `k8s`
entries, and `ssh` entries on Windows, are decoded and settled as unsupported.
See
[Secure Access Tunneling](../networking/secure-access-tunneling.md) for how plexd
consumes the block.

### `POST /v1/nodes/{node_id}/sessions/{session_id}`

A one-of session activity record: exactly one of `ssh`, `k8s`, or `tcp` is set,
selecting the session kind. plexd emits `tcp` rows for tcp sessions and `ssh` rows
for ssh sessions; the `k8s` variant is carried by the type and accepted by the
server but not emitted. Success is `204 No Content`.

**SessionActivityRequest**

| Field | Type           | JSON Tag          | Description                     |
|-------|----------------|-------------------|---------------------------------|
| `SSH` | `*SSHActivity` | `"ssh,omitempty"` | SSH session lifecycle or command row |
| `K8s` | `*K8sActivity` | `"k8s,omitempty"` | Per-request Kubernetes API row   |
| `TCP` | `*TCPActivity` | `"tcp,omitempty"` | TCP session lifecycle or `session_active` row |

**SSHActivity**

A row takes one of two shapes. A command row carries `command`, optionally with
`exit_code`, `started_at` and `completed_at`. A lifecycle row carries `phase`
plus `terminated_by` on `session_ended`, and no command fields. An ssh session
binds no listener, so plexd sends no `listener_endpoint`; the field stays for
the `session_started` rows older agents post with one, which the server still
admits. plexd never posts an empty `command`: the server refuses a row that
mixes the shapes.

| Field              | Type         | JSON Tag                         | Description                            |
|--------------------|--------------|----------------------------------|----------------------------------------|
| `Command`          | `string`     | `"command,omitempty"`            | Command line of an `exec` (1 to 1024 bytes); command rows only |
| `ExitCode`         | `*int`       | `"exit_code,omitempty"`          | Command exit code, on the row posted after the command exited |
| `StartedAt`        | `*time.Time` | `"started_at,omitempty"`         | RFC 3339 start time (UTC)              |
| `CompletedAt`      | `*time.Time` | `"completed_at,omitempty"`       | RFC 3339 completion time (UTC)         |
| `Phase`            | `string`     | `"phase,omitempty"`              | One of the `SSHPhase*` values; lifecycle rows only |
| `ListenerEndpoint` | `string`     | `"listener_endpoint,omitempty"`  | Never sent by plexd, because an ssh session binds no listener; kept for the `session_started` rows older agents post |
| `TerminatedBy`     | `string`     | `"terminated_by,omitempty"`      | One of the `TerminatedBy*` values; `session_ended` rows only |

**SSHPhase constants**

| Constant                 | Value             | Description                           |
|--------------------------|-------------------|---------------------------------------|
| `SSHPhaseSessionStarted` | `session_started` | An SSH session is ready to serve the connections the control plane asks for |
| `SSHPhaseSessionEnded`   | `session_ended`   | Close of an SSH session               |

**K8sActivity**

| Field          | Type    | JSON Tag                    | Description               |
|----------------|---------|-----------------------------|---------------------------|
| `Verb`         | `string`| `"verb"`                    | API verb                  |
| `ResourceKind` | `string`| `"resource_kind,omitempty"` | Target resource kind      |
| `Namespace`    | `string`| `"namespace,omitempty"`     | Target namespace          |
| `Name`         | `string`| `"name,omitempty"`          | Target object name        |
| `StatusCode`   | `int`   | `"status_code,omitempty"`   | Response status code      |
| `DurationMS`   | `int64` | `"duration_ms,omitempty"`   | Request duration in ms    |

**TCPActivity**

| Field          | Type    | JSON Tag                   | Description                                             |
|----------------|---------|----------------------------|---------------------------------------------------------|
| `Phase`        | `string`| `"phase"`                  | One of the `TCPPhase*` values; a `session_active` row carries the phase alone |
| `TargetHost`   | `string`| `"target_host,omitempty"`  | Forward target host                                     |
| `TargetPort`   | `int`   | `"target_port,omitempty"`  | Forward target port                                     |
| `ListenerEndpoint` | `string`| `"listener_endpoint,omitempty"` | Address the node's listener bound; set on `session_started` rows only |
| `BytesIn`      | `*int64`| `"bytes_in,omitempty"`     | Operator→target bytes (explicit `0` on `session_ended`) |
| `BytesOut`     | `*int64`| `"bytes_out,omitempty"`    | Target→operator bytes (explicit `0` on `session_ended`) |
| `TerminatedBy` | `string`| `"terminated_by,omitempty"`| One of the `TerminatedBy*` values                       |

**TCPPhase constants**

| Constant                 | Value             | Description                  |
|--------------------------|-------------------|------------------------------|
| `TCPPhaseSessionStarted` | `session_started` | Opening of a TCP session     |
| `TCPPhaseSessionActive`  | `session_active`  | The TCP session forwarded bytes since its previous `session_active` row |
| `TCPPhaseSessionEnded`   | `session_ended`   | Close of a TCP session       |

**TerminatedBy constants**

Shared by the `session_ended` rows of both kinds.

| Constant                     | Value            | Description                                   |
|------------------------------|------------------|-----------------------------------------------|
| `TerminatedByTTLExpired`     | `ttl_expired`    | Session reached its time-to-live              |
| `TerminatedByIdleTimeout`    | `idle_timeout`   | Idle window elapsed with no byte flow          |
| `TerminatedByPlexdClose`     | `plexd_close`    | plexd closed the session locally              |
| `TerminatedByOperatorRevoke` | `operator_revoke`| Operator's access was revoked. Reported only for a close caused by a verified `session_revoked` event; a drained entry without the event is reported as `plexd_close`, because plexd cannot tell a revocation from a block the control plane failed to serve |

## Integrity

### `POST /v1/nodes/{node_id}/integrity-violations`

A batch of the tamper-evidence divergences the agent detected on the node: a
mismatched binary checksum, a tampered hook checksum, or a rotated SSH host key.
The endpoint takes a batch even for a single finding, so a lone violation travels
as a one-entry array rather than as a bare object. Success is `200 OK` with a
receipt, not `202`: the violation rows and the `integrity_alert` outbox event are
committed before the response is written.

The handler decodes with `DisallowUnknownFields` and caps the body at 32 KiB, so
an unknown or renamed field refuses the whole request.

**IntegrityViolationsRequest**

| Field        | Type                         | JSON Tag       | Description                                    |
|--------------|------------------------------|----------------|------------------------------------------------|
| `Violations` | `[]IntegrityViolationReport` | `"violations"` | 1 to `MaxIntegrityViolationsPerBatch` (128) entries |

An empty array is refused with `400 integrity_violations_empty` and an oversized
one with `integrity_violations_too_many`. `ReportIntegrityViolations` checks both
bounds locally and returns `ErrIntegrityViolationsEmpty` or
`ErrIntegrityViolationsTooMany` without sending, since a refused request would
take every violation in it down.

**IntegrityViolationReport**

| Field                 | Type                     | JSON Tag                          | Description                                     |
|-----------------------|--------------------------|-----------------------------------|-------------------------------------------------|
| `Kind`                | `IntegrityViolationKind` | `"kind"`                          | Artifact class the divergence applies to        |
| `DetectedBy`          | `IntegrityDetector`      | `"detected_by"`                   | On-node detector that surfaced it               |
| `ArtifactID`          | `string`                 | `"artifact_id"`                   | Affected artifact; non-empty after trimming, at most 4096 bytes |
| `ObservedChecksum`    | `string`                 | `"observed_checksum,omitempty"`   | Computed SHA-256, 32 raw bytes in standard-padded base64 |
| `ExpectedChecksum`    | `string`                 | `"expected_checksum,omitempty"`   | Baseline digest, same encoding                  |
| `ObservedFingerprint` | `string`                 | `"observed_fingerprint,omitempty"`| Observed host-key fingerprint, `SHA256:<base64>`|
| `ExpectedFingerprint` | `string`                 | `"expected_fingerprint,omitempty"`| Baseline fingerprint, same form                 |

`Kind` decides which digest pair is legal: a checksum kind carries the checksums
and no fingerprint, the host-key kind carries the fingerprints and no checksum.
Crossing them is refused with `400 integrity_violation_kind_mismatch`, which is
why the four digest fields are `omitempty` — an unset one must be absent from the
JSON rather than present and empty.

The checksum fields are declared `format: byte`, so the hex form the integrity
package works in decodes to 48 bytes and is refused with
`integrity_violation_checksum_invalid`. `integrity.WireChecksum` converts hex into
the wire form.

**IntegrityViolationKind constants**

| Constant                      | Value             | Description                       |
|-------------------------------|-------------------|-----------------------------------|
| `IntegrityKindBinaryChecksum` | `binary_checksum` | The agent's own binary            |
| `IntegrityKindHookChecksum`   | `hook_checksum`   | A hook script                     |
| `IntegrityKindSSHHostKey`     | `ssh_host_key`    | The mesh SSH host key             |

**IntegrityDetector constants**

| Constant                       | Value          | Description                                             |
|--------------------------------|----------------|---------------------------------------------------------|
| `IntegrityDetectorStartupScan` | `startup_scan` | The agent's sweep of the artifacts it holds baselines for. The enum has no value for a periodic re-scan, so the interval-driven sweeps report this one too |
| `IntegrityDetectorInotify`     | `inotify`      | The hooks-directory watcher reacting to a filesystem event |
| `IntegrityDetectorPreDispatch` | `pre_dispatch` | The check that runs immediately before a hook executes  |

A value outside either set is refused with `400
integrity_violation_kind_invalid` or `integrity_violation_detected_by_invalid`.

**IntegrityViolationsResponse**

| Field            | Type        | JSON Tag            | Description                            |
|------------------|-------------|---------------------|----------------------------------------|
| `AcceptedAt`     | `time.Time` | `"accepted_at"`     | Server-side commit timestamp           |
| `ViolationCount` | `int`       | `"violation_count"` | Rows persisted; matches the input length |

## SSE Events

### `GET /v1/nodes/{node_id}/events`

Returns `text/event-stream` with signed event envelopes.

**Envelope**

| Field       | Type              | JSON Tag       | Description                                   |
|-------------|-------------------|----------------|-----------------------------------------------|
| `ID`        | `string`          | `"id"`         | Unique event identifier (required)            |
| `Type`      | `string`          | `"type"`       | Event type discriminator (required)           |
| `Scope`     | `string`          | `"scope"`      | Scope the event applies to                    |
| `KeyID`     | `string`          | `"key_id"`     | Key id that selects the verifying signing key |
| `IssuedAt`  | `time.Time`       | `"issued_at"`  | Event timestamp                               |
| `Payload`   | `json.RawMessage` | `"payload"`    | Event-specific JSON payload                   |
| `Signature` | `string`          | `"signature"`  | Base64 Ed25519 signature over the SHA-512 digest of the canonical form |

`ParseEnvelope` requires `id` and `type`. See [Event Verification](event-verification.md)
for the canonical form and signature rules.

### Event Types

The event set is organized in two tiers. Contract types are emitted today,
except `session_connect`, which only a control plane with
[plexsphere/plexsphere#928](https://github.com/plexsphere/plexsphere/issues/928) emits; documented-coming types are named for
the platform's 14-type taxonomy.
Reconcile-driving payloads are opaque — the state pull is authoritative. `session_revoked` is the exception: its payload names the session to close before the reconcile. `session_connect` drives no reconcile at all: its payload names a connection to open.

| Constant                   | Value                   | Tier              |
|----------------------------|-------------------------|-------------------|
| `EventNodeStateUpdated`    | `node_state_updated`    | contract          |
| `EventPolicyUpdated`       | `policy_updated`        | contract          |
| `EventBridgeConfigUpdated` | `bridge_config_updated` | contract          |
| `EventActionRequest`       | `action_request`        | contract          |
| `EventSessionSetup`        | `session_setup`         | contract          |
| `EventPeerEndpointChanged` | `peer_endpoint_changed` | contract          |
| `EventNodeSecretsUpdated`  | `node_secrets_updated`  | contract          |
| `EventSessionRevoked`      | `session_revoked`       | contract          |
| `EventSessionConnect`      | `session_connect`       | contract          |
| `EventPeerRegistered`      | `peer_registered`       | documented-coming |
| `EventPeerPSKAssigned`     | `peer_psk_assigned`     | documented-coming |
| `EventPeerDeregistered`    | `peer_deregistered`     | documented-coming |
| `EventPeerKeyRotated`      | `peer_key_rotated`      | documented-coming |
| `EventRotateKeys`          | `rotate_keys`           | documented-coming |
| `EventSigningKeyRotated`   | `signing_key_rotated`   | documented-coming |

`action_request` is a contract type with an opaque payload: action dispatches are
delivered in the `executions` block of the state pull, so the event only triggers
a reconcile and the resulting pull carries the dispatch. `session_setup` is the
same shape for mediated access — the session is delivered in the `sessions` block
of that pull.

`session_revoked` is a contract type whose payload plexd decodes, as a
`SessionRevocation` naming the session the control plane revoked.
`tunnel.Dispatcher.SessionRevokedHandler` closes that session when it is live,
reports the `terminated_by` its `revoke_reason` maps to (see **RevokeReason
constants** under [Supporting types](#supporting-types)), and only then triggers
a reconcile, so the pull cannot drain the session first. A payload that does not
decode, or whose `session_id` is empty or differs from its `jti`, closes nothing:
the handler triggers the reconcile and returns the error. A session leaving the
`sessions` block stays the teardown for a revocation whose event never arrives.

`session_connect` is a contract type whose payload plexd decodes, as a
`SessionConnectRequest` (see [Supporting types](#supporting-types)) naming one
connection of an ssh session a client attached to.
`tunnel.Dispatcher.SessionConnectHandler` opens that connection with
`ControlPlane.OpenSessionConnection` when the session is a live ssh session,
and serves the session's SSH login on it. It triggers no reconcile, because the
event carries no desired state. A payload that does not decode, or whose
`session_id` or `connection_id` is empty, opens nothing and returns the error.

`node_secrets_updated` is a contract type whose payload carries the node's full
secret inventory. plexd treats the payload as opaque and only triggers a
reconcile, because the `secrets` block of the state pull is authoritative. The
pull is the only writer of the node API's secret index, so an event that arrives
late can never roll the index back.

`peer_endpoint_changed` is a contract type the control plane emits now, and plexd
treats it as a reconcile trigger. Its payload is never decoded: each peer's direct
endpoint rides the `peers` block of the state pull as `SnapshotPeer.Endpoint`, and
the event only brings the next pull forward. `peer_psk_assigned` is a reconcile
trigger too, and it never forces a fetch on its own: plexd fetches an edge PSK
from `GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk` (see [Edge PSK](#edge-psk))
when a peer first appears, when its public key changes and after this node's own
key rotation, and a fetch still pending retries on the pull the event brings
forward.
