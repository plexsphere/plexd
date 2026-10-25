---
title: NAT Traversal via STUN
package: internal/nat
feature: PXD-0006
---

# NAT Traversal via STUN

The `internal/nat` package discovers a node's public endpoint using STUN servers, classifies the NAT type, and reports the result to the control plane. Peers behind NAT use the discovered endpoints to establish direct WireGuard connections. The package also publishes the node's local interface addresses as [endpoint candidates](#local-endpoint-candidates), which peers on the same network dial directly.

Discovery's STUN network operations go through a `STUNClient` interface, enabling full unit testing without real STUN servers or UDP sockets. The [path MTU probe](#path-mtu-probe), which measures how large a packet the uplink carries, opens its own sockets, and its tests run against a STUN server on loopback. The STUN protocol implementation covers RFC 5389 Binding requests, the padded requests of the probe, and XOR-MAPPED-ADDRESS parsing using the Go standard library. The probe also uses `golang.org/x/sys` to set the don't-fragment option on its sockets.

## Config

`Config` holds NAT traversal parameters passed to the `Discoverer`.

| Field             | Type            | Default                                                      | Description                         |
|-------------------|-----------------|--------------------------------------------------------------|-------------------------------------|
| `Enabled`         | `bool`          | `true`                                                       | Whether NAT traversal is active. `false` also turns the [path MTU probe](#path-mtu-probe) off |
| `STUNServers`     | `[]string`      | `["stun.l.google.com:19302", "stun.cloudflare.com:3478"]`   | STUN server addresses (host:port)   |
| `RefreshInterval` | `time.Duration` | `60s`                                                        | Interval between STUN refreshes     |
| `Timeout`         | `time.Duration` | `5s`                                                         | Per-server STUN request timeout     |
| `LocalCandidates` | `*bool`         | `nil` (enabled)                                              | Publish local endpoint candidates (`local_candidates`); see [Local endpoint candidates](#local-endpoint-candidates) |
| `CandidateInterfaces` | `[]string`  | empty (every eligible interface)                             | Allowlist of interface names to publish candidates from (`candidate_interfaces`) |

`LocalCandidates` is a pointer so that an omitted key stays apart from an explicit `false`. `LocalCandidatesEnabled()` returns the effective value: true unless the field is set to `false`. It is independent of `Enabled`, because a node whose STUN servers are unreachable still has local addresses a peer can dial.

```go
cfg := nat.Config{
    STUNServers: []string{"stun.example.com:3478"},
}
cfg.ApplyDefaults() // Enabled=true, RefreshInterval=60s, Timeout=5s
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

`ApplyDefaults` sets `Enabled=true` on a zero-valued Config (when `STUNServers == nil && RefreshInterval == 0 && Timeout == 0 && MinReportInterval == 0`). If any field is already set, `Enabled` is left as-is. To disable NAT traversal, set `Enabled=false` after calling `ApplyDefaults`. In the config file, a `nat` block that sets only `enabled: false` is therefore read as enabled; set `stun_servers`, `refresh_interval`, `timeout` or `min_report_interval` beside it.

### Validation Rules

| Field             | Rule                          | Error Message                                             |
|-------------------|-------------------------------|-----------------------------------------------------------|
| `STUNServers`     | Non-empty when `Enabled=true` | `nat: config: STUNServers must not be empty when enabled` |
| `RefreshInterval` | >= 10s                        | `nat: config: RefreshInterval must be at least 10s`       |
| `Timeout`         | > 0                           | `nat: config: Timeout must be positive`                   |
| `CandidateInterfaces` | No empty or whitespace-only entry | `nat: config: CandidateInterfaces must not contain an empty name` |

When `Enabled=false`, every rule but the `CandidateInterfaces` check is skipped. That check runs first, because the candidate publisher runs whether or not STUN traversal is enabled.

## STUNClient

Interface abstracting the UDP STUN binding round trip. The production implementation opens a UDP socket on `localPort` (0 for an OS-assigned ephemeral port), sends a STUN Binding Request, parses the response, and returns the mapped address together with the local port actually used.

STUN never runs on the WireGuard listen port. The kernel WireGuard socket owns that port, and UDP port sharing would require `SO_REUSEPORT` on both sockets — the kernel side does not set it, so binding it fails with `EADDRINUSE` on every node whose WireGuard interface is up. Discovery therefore measures the mapping of its own ephemeral socket, and the published endpoint combines the mapped IP with the WireGuard listen port (see Discoverer).

```go
type STUNClient interface {
    Bind(ctx context.Context, serverAddr string, localPort int) (MappedAddress, int, error)
}
```

| Parameter    | Description                                              |
|--------------|----------------------------------------------------------|
| `serverAddr` | STUN server address (host:port)                          |
| `localPort`  | Local UDP source port (0 for an OS-assigned ephemeral)   |

## MappedAddress

Result of a STUN binding — the public IP and port as seen by the STUN server.

```go
type MappedAddress struct {
    IP   net.IP
    Port int
}

func (m MappedAddress) String() string // returns "ip:port"
```

## NATType

Classified NAT behavior based on comparing mapped addresses from multiple STUN servers.

| Constant       | Value         | Meaning                                                           |
|----------------|---------------|-------------------------------------------------------------------|
| `NATNone`      | `"none"`      | Mapped port matches the STUN source port — no port translation    |
| `NATFullCone`  | `"full_cone"` | Same mapped address from different servers — consistent NAT       |
| `NATSymmetric` | `"symmetric"` | Different mapped addresses — per-destination NAT, relay needed    |
| `NATUnknown`   | `"unknown"`   | Only one server responded — classification incomplete             |

### Classification Logic

1. Send STUN binding to the first reachable server from an ephemeral source port → `firstAddr`; the cycle keeps that port
2. If `firstAddr.Port` equals the source port → `NATNone` (no port translation)
3. Send binding to a second server from the same source port → `secondAddr`
4. If `firstAddr == secondAddr` → `NATFullCone`
5. If `firstAddr != secondAddr` → `NATSymmetric`
6. If no second server responded → `NATUnknown`

### Wire Mapping

`NATType.Wire()` maps the classifier's value to the control-plane wire enum used by both the heartbeat `nat_summary` and the endpoint report:

- `none` → `full_cone` — an un-NATed endpoint is directly reachable with no filtering, the full_cone traversal posture
- `full_cone` and `symmetric` → themselves
- anything else (including `unknown`) → `unknown`

The wire enum also includes `restricted` and `port_restricted`, which this classifier does not currently emit.

### PortMapping

`PortMapping` records whether the published endpoint was observed or assumed. It comes from the first successful binding alone and travels as the `port_mapping` member of the endpoint report:

| Constant         | Value          | Meaning                                                                                                  |
|------------------|----------------|----------------------------------------------------------------------------------------------------------|
| `PortPreserved`  | `"preserved"`  | The mapped port equals the probe's source port. The published endpoint matches what discovery observed.  |
| `PortTranslated` | `"translated"` | The NAT assigned its own port. The published endpoint assumes the router forwards or preserves the WireGuard listen port. |

It is independent of `nat_type`, which keeps describing the mapping: two servers that see the same translated mapping still classify `full_cone`, with `port_mapping` `translated`. `NATNone` always goes with `preserved`, and `NATFullCone`, `NATSymmetric` and `NATUnknown` always go with `translated`, because discovery asks a second server only once the first one saw a translated port. On the wire both values can arrive with `nat_type` `full_cone`, since `NATNone` is sent as `full_cone`. A node behind a port forward of the listen port reports `translated` as well and keeps a working endpoint: discovery cannot tell it apart from a router that forwards nothing.

## Discoverer

Central coordinator for STUN discovery, NAT classification, and endpoint reporting.

The published endpoint is the STUN-mapped IP joined with `advertisePort` — the WireGuard listen port peers must dial — not the mapped port, which describes the discovery socket's own mapping. That endpoint is exact wherever the NAT preserves the port. Where the NAT translates ports, the reported `port_mapping` (`translated`) marks the endpoint as an assumption that holds only where the router forwards or preserves the listen port (see [PortMapping](#portmapping)).

### Constructor

```go
func NewDiscoverer(client STUNClient, cfg Config, advertisePort int, logger *slog.Logger) *Discoverer
```

| Parameter       | Description                                                  |
|-----------------|--------------------------------------------------------------|
| `client`        | STUN client implementation                                   |
| `cfg`           | NAT traversal configuration                                  |
| `advertisePort` | WireGuard listen port carried in every published endpoint    |
| `logger`        | Structured logger (`log/slog`)                               |

### Methods

| Method       | Signature                                                                                        | Description                                                  |
|--------------|--------------------------------------------------------------------------------------------------|--------------------------------------------------------------|
| `Discover`   | `(ctx context.Context) (*DiscoveryResult, error)`                                                | Single STUN discovery + NAT classification                   |
| `Run`        | `(ctx context.Context, reporter EndpointReporter, nodeID string) error`                          | Discovery + report loop (blocks until context cancelled)     |
| `LastResult` | `() *DiscoveryResult`                                                                            | Most recent result (thread-safe, nil before first discovery) |

### DiscoveryResult

```go
type DiscoveryResult struct {
    Endpoint    string      // "ip:port" format
    NATType     NATType
    PortMapping PortMapping // "preserved" or "translated"
}
```

### Lifecycle

```go
logger := slog.Default()

// Create discoverer; the WireGuard listen port is advertised in endpoints
disc := nat.NewDiscoverer(stunClient, natCfg, wireguard.DefaultListenPort, logger)

// Option A: Single discovery
result, err := disc.Discover(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Public endpoint: %s (NAT: %s)\n", result.Endpoint, result.NATType)

// Option B: Run continuous discovery + reporting loop (blocks)
err := disc.Run(ctx, controlPlane, nodeID)
// returns on context cancellation with ctx.Err()
```

### Run Sequence

1. Perform initial `Discover(ctx)` — returns error if all STUN servers fail
2. Report the endpoint via `report` — log warning on failure, continue
3. Enter a deadline-driven loop; each cycle waits until the next report deadline:
   - Re-discover → on failure: log warning, keep previous endpoint, retry after `nextDelay`
   - On endpoint change: log info with old/new endpoints
   - Report the endpoint → on failure: log warning, continue
   - Reset the timer from the response's `stale_after`
4. On context cancellation: return `ctx.Err()`

The report loop is deadline-driven rather than fixed-interval. After each successful report, `nextDelay` schedules the next cycle at `min(RefreshInterval, stale_after − now − 30s)`, floored at `MinReportInterval` (`endpointReportMargin` = 30s; `min_report_interval` defaults to 10s). A zero or absent `stale_after` falls back to `RefreshInterval`. With the server's default 5m TTL and the default 60s refresh, the cadence is unchanged; the deadline path takes over when the TTL is shorter than the refresh interval.

A `stale_after` shorter than `refresh_interval` means the control plane, not the operator, sets the cadence — every shortened cycle costs a full STUN round trip to each configured server plus an endpoint `PUT`. That is legitimate when the server's TTL is genuinely short, but a misconfigured or hostile control plane could use it to drive the whole fleet well above its configured rate. Two guards bound that: each shortened cycle logs a `Warn` naming the delay, the configured refresh interval, and the deadline that caused it; and `nat.min_report_interval` caps how far the server may accelerate the loop. Raising it to `refresh_interval` refuses server-driven acceleration entirely, at the cost of letting the endpoint go stale when the server's TTL is genuinely shorter.

### Heartbeat Integration

The `LastResult()` method provides the most recent `*DiscoveryResult` for the heartbeat's `nat_summary`. Access is protected by `sync.RWMutex` for safe concurrent reads from the heartbeat goroutine. The heartbeat builder folds the result into a JSON object, mapping the classified NAT type to its wire form via `NATType.Wire()`:

```go
summary := map[string]any{}
if info := disc.LastResult(); info != nil {
    summary["endpoint"] = info.Endpoint
    summary["nat_type"] = info.NATType.Wire()
}
// summary stays {} until the first discovery succeeds — never null,
// which the control plane would reject.
```

## EndpointReporter

Interface for reporting discovered endpoints to the control plane. Satisfied by `api.ControlPlane`.

```go
type EndpointReporter interface {
    ReportEndpoint(ctx context.Context, nodeID string, req api.EndpointRequest) (*api.EndpointResponse, error)
}
```

### Wire Types

```go
// Request: PUT /v1/nodes/{node_id}/endpoint
type EndpointRequest struct {
    Endpoint    string    `json:"endpoint"`               // "203.0.113.5:51820"
    NATType     string    `json:"nat_type"`               // "full_cone", "restricted", "port_restricted", "symmetric", "unknown"
    PortMapping string    `json:"port_mapping,omitempty"` // "preserved", "translated"; omitted when empty
    ReportedAt  time.Time `json:"reported_at"`            // RFC 3339 UTC, fresh per attempt
}

// Response
type EndpointResponse struct {
    AcceptedAt time.Time `json:"accepted_at"`
    StaleAfter time.Time `json:"stale_after"` // freshness deadline; drives the next report
}
```

The response no longer carries peer endpoints. Inbound peer endpoints arrive on the reconciliation state pull, as the `endpoint` member of each peer, and a `peer_endpoint_changed` SSE event only brings that pull forward.

## report

Internal function that sends the discovered endpoint to the control plane and returns the `stale_after` deadline.

1. Build an `EndpointRequest` with a fresh `reported_at`, the `Wire()` NAT type and the result's `port_mapping`
2. Call `reporter.ReportEndpoint`
3. On `endpoint_peer_not_found` (404) or `endpoint_peer_gone` (410): wrap the error in the internal `errEndpointRejected` sentinel so the caller can count the streak
4. Any other error is wrapped `nat: report endpoint: <cause>`
5. Return the response's `stale_after` (zero when the report failed or the response was empty)

`endpoint_clock_skew` (400) is deliberately **not** retried. `reported_at` is read from the same clock that produced the rejected timestamp, so an immediate second attempt carries an equally skewed value and is rejected identically — it would only double the request volume during the NTP incident that caused the skew. The heartbeat path already reports clock skew with the actionable "synchronize the system clock via NTP" guidance.

`Discoverer.reportEndpoint` wraps `report` and owns the failure logging. A rejection means the control plane no longer holds this node's peer record; re-reporting cannot clear it, and because heartbeats keep succeeding, no other health signal turns red. Consecutive rejections are therefore counted: the first two log at `Warn`, the third and beyond log at `Error` with `consecutive_rejections`, which is alertable. A successful report clears the streak; a transient failure leaves it intact, since it says nothing about whether the peer record came back. A refused credential (`api.ErrCredentialRefused`) while the heartbeat is parked leaves it intact too, and logs `endpoint report failed` at `Debug` (see [Quiet Failure Logs](../core/heartbeat-service.md#quiet-failure-logs)). Recovery still requires re-registration — the loop surfaces the condition rather than resolving it.

## Local endpoint candidates

Two nodes behind one NAT router both publish the router's address as their STUN endpoint. The node therefore also publishes its local interface addresses, each joined with the WireGuard listen port, on [`PUT /v1/nodes/{node_id}/endpoint-candidates`](../core/api-endpoints.md#put-v1-nodes-node-id-endpoint-candidates). Peers receive them as `endpoint_candidates` on the state pull, after any peer-observed endpoints of this node, which the control plane lists first and which can push trailing local candidates past the cap of 8 (see [Peer-observed endpoints](peer-endpoint-exchange.md#peer-observed-endpoints)). Peers try the ones on a subnet they share first, and keep the first entry that completes a handshake (see [Dial order](wireguard.md#dial-order) and [Endpoint selection](wireguard.md#endpoint-selection)).

A peer on the same network reaches a candidate only when UDP `wireguard.listen_port` is open on that local address. Where a host or network firewall drops it, the peer's trial of the candidate times out and the peer moves on to the next entry of its dial order.

### Gathering

```go
type Interface struct {
    Name     string
    Index    int
    Flags    net.Flags
    Prefixes []netip.Prefix
}

type CandidateFilter struct {
    Interfaces        []string     // allowlist; empty means every eligible interface
    ExcludeInterfaces []string     // always skipped
    ExcludePrefix     netip.Prefix // addresses inside it are skipped; the zero prefix skips nothing
}

func SystemInterfaces() ([]Interface, error)
func EligiblePrefixes(ifaces []Interface, f CandidateFilter) []netip.Prefix
func SelectCandidates(ifaces []Interface, port int, f CandidateFilter) (candidates []string, truncated int)
func GatherCandidates(port int, f CandidateFilter) (candidates []string, truncated int, err error)
```

`SystemInterfaces` reads `net.Interfaces()` and each interface's addresses. A failed listing returns `nat: list interfaces: <cause>`. An interface whose addresses cannot be read is skipped, and an address that is not a `*net.IPNet` is ignored. An IPv4-mapped IPv6 address becomes the IPv4 address it carries, with 96 bits taken off its prefix length (`::ffff:10.0.0.5/120` becomes `10.0.0.5/24`).

An interface is eligible under these rules, in order:

1. It is up, and it is neither a loopback nor a point-to-point interface. Point-to-point covers kernel WireGuard, tun and utun devices.
2. Its name is not in `ExcludeInterfaces`. `plexd up` passes the mesh interface under both its names, `wireguard.interface_name` and the name the OS knows it by (`utunN` on macOS).
3. With a non-empty `Interfaces` (`nat.candidate_interfaces`), its name is in that list. A listed name skips rule 4.
4. With an empty `Interfaces`, its name does not start with `docker`, `br-`, `veth`, `virbr`, `cni`, `flannel`, `cali`, `cilium`, `lxcbr`, `lxdbr`, `vxlan`, `kube-`, `podman`, `tailscale` or `zt`. These container, bridge, overlay and VPN interfaces exist on many hosts at once (Docker's `172.17.0.1` is on every Docker host), so a peer that dialed one would reach its own host.

An address on an eligible interface is skipped when it is invalid, unspecified, loopback, link-local unicast, link-local multicast, interface-local multicast or multicast, or when it lies inside `ExcludePrefix`. `plexd up` passes the Domain mesh prefix there ([`Manager.MeshPrefix`](wireguard.md#mesh-prefix)): a peer that dialed a mesh address would route WireGuard's packets into its own tunnel.

`SelectCandidates` renders each eligible address joined with `port` as a `host:port` string, an IPv6 host in brackets and without a zone. It sorts IPv4 before IPv6, then by the lower interface index, then by the lower address, so a report is stable across cycles and the cap keeps the same addresses. An address on two interfaces is published once, at its first position. Past `api.MaxEndpointCandidates` (8) it keeps the first eight and counts the rest in `truncated`. Nothing eligible yields an empty, non-nil slice, the report that withdraws every earlier candidate.

`EligiblePrefixes` returns the prefixes of the eligible addresses under the same rules, neither deduplicated nor capped. The WireGuard manager reads them to tell which of a peer's candidates share a subnet with this node. `GatherCandidates` is `SystemInterfaces` followed by `SelectCandidates`, and returns a read error unchanged.

`plexd up` builds one filter in step 5a-2, when the WireGuard interface came up: `Interfaces` from `nat.candidate_interfaces`, `ExcludeInterfaces` with the mesh interface's two names, and `ExcludePrefix` with the mesh prefix. The publisher gathers through it, and the function `Manager.SetLocalPrefixes` receives returns `EligiblePrefixes` over `SystemInterfaces()` through it.

### CandidatePublisher

```go
type CandidateReporter interface {
    ReportEndpointCandidates(ctx context.Context, nodeID string, req api.EndpointCandidatesRequest) (*api.EndpointCandidatesResponse, error)
}

func NewCandidatePublisher(gather func() ([]string, int, error), cfg Config, logger *slog.Logger) *CandidatePublisher
func (p *CandidatePublisher) Run(ctx context.Context, reporter CandidateReporter, nodeID string) error
```

`*api.ControlPlane` satisfies `CandidateReporter`. `gather` returns the candidates and how many were dropped past the cap; `cfg` supplies `RefreshInterval` and `MinReportInterval`. Every line the publisher logs carries `component=nat`.

`Run` logs `nat: endpoint candidates: started`, reports at once, and then reports once per cycle until `ctx` is done, when it returns nil. No answer ends the loop. One cycle:

1. Call `gather`. An error logs a `Warn` and sends nothing.
2. Send `{"candidates": [...], "reported_at": <now, UTC>}`, also when there are no candidates: the empty array withdraws the candidates reported before.
3. On an error, say nothing when `ctx` is done, and log it by its cause otherwise (see below).
4. On success, log the recovery line after a not-served phase, an `Info` line for the first accepted set and for a set that differs from the last accepted one, and a `Debug` line for every accepted report.

After an accepted report the next one follows `stale_after` as the [Discoverer's](#run-sequence) does: 30s before the deadline, floored at `MinReportInterval` and capped at `RefreshInterval`, and `RefreshInterval` for a zero `stale_after`. A deadline that shortens the cadence below `RefreshInterval` logs a `Warn`. After any failure, a failed interface read included, the next cycle follows `RefreshInterval`.

A control plane that does not serve the operation answers `404` with any code but `endpoint_peer_not_found`, or `501 endpoint_candidates_not_provisioned` ([`api.IsEndpointCandidatesNotServed`](../core/control-plane-client.md#error-types)). The publisher logs that once at `Info` when it enters the state, keeps reporting every `RefreshInterval` so an upgraded control plane is picked up without a restart, and logs one `Info` line on the first success after it.

### Wiring in plexd up

Step 24a starts the publisher when the WireGuard interface came up and `nat.local_candidates` is not `false`. It gathers with `GatherCandidates(wireguard.listen_port, filter)` and reports for the node's ID. It does not depend on `nat.enabled`, on STUN or on `peer_exchange.enabled`: a node whose STUN servers are unreachable still publishes its local addresses, while a failed initial STUN discovery ends the endpoint report loop. A node whose WireGuard interface did not come up accepts no tunnel and publishes nothing; `plexd up` logs `wireguard unavailable, skipping peer reconcile handler, handshake reports, tunnel metrics, endpoint selection and endpoint candidates` at `Warn`.

### Publisher log lines

| Level   | Message | Keys |
|---------|---------|------|
| `Info`  | `nat: endpoint candidates: started` | none |
| `Info`  | `nat: endpoint candidates: published` | `candidates`, `truncated` |
| `Debug` | `nat: endpoint candidates: accepted` | `count`, `stale_after` |
| `Info`  | `nat: endpoint candidates: control plane does not accept endpoint candidates, retrying every interval` | `status`, `code` |
| `Info`  | `nat: endpoint candidates: control plane accepts endpoint candidates` | none |
| `Warn`  | `nat: endpoint candidates: read interfaces failed` | `error` |
| `Warn`  | `nat: endpoint candidates: rejected, this node is not registered as a peer` | `code` (`endpoint_peer_not_found` or `endpoint_peer_gone`) |
| `Warn`  | `nat: endpoint candidates: rejected for clock skew` | `error` |
| `Warn` (`Debug` for `api.ErrCredentialRefused`) | `nat: endpoint candidates: send failed` | `error` |
| `Warn`  | `nat: endpoint candidates: control plane deadline shortens the report cadence` | `delay`, `refresh_interval`, `min_report_interval`, `stale_after` |

`send failed` covers every failure the other lines do not, among them `400 malformed_endpoint_candidates`, `400 endpoint_candidate_unparseable`, `401`, `403`, `413`, `500`, a `501` with another code and a transport error. A peer rejection clears once the control plane registers the node, and a clock skew once NTP corrects the clock, so both are logged on every cycle rather than once. A refused credential (`api.ErrCredentialRefused`), which the client returns without a request while the heartbeat is parked, logs `send failed` at `Debug`, because the heartbeat names the cause once when it parks (see [Quiet Failure Logs](../core/heartbeat-service.md#quiet-failure-logs)).

## Path MTU probe

`ProbePathMTU` (`mtu_probe.go`) measures the largest IPv4 packet the uplink carries to the STUN servers. The WireGuard manager sizes the mesh interface from the result, at startup and every 10 minutes (see [MTU detection](wireguard.md#mtu-detection)).

```go
// MTUProbeSizes are the IPv4 packet sizes ProbePathMTU tries, in bytes.
var MTUProbeSizes = []int{1500, 1492, 1480, 1472, 1460, 1452, 1440, 1428, 1420, 1400, 1380, 1360}

// MTUProbeTimeout bounds one probe round.
const MTUProbeTimeout = 2 * time.Second

var ErrMTUProbeInconclusive = errors.New("nat: mtu probe: no STUN server answered")

// ProbePathMTU returns the largest IPv4 packet size, in bytes, that reached a STUN server.
func ProbePathMTU(ctx context.Context, servers []string, timeout time.Duration) (int, error)
```

Every probe is one Binding Request sent with the don't-fragment (DF) bit set, so a router that cannot forward it drops it instead of fragmenting it, and an answer proves the uplink carried a packet of that size. A ladder entry is the whole IPv4 packet: the IPv4 header (20), UDP (8) and a [padded Binding Request](#padded-binding-request) of the entry minus 28 bytes. Each round also sends a baseline, the unpadded 20-byte request, 48 bytes as an IPv4 packet. The responses never echo the padding, so the probe measures the outbound direction only.

### A round

- The servers are probed concurrently. Each server is resolved once, with `net.SplitHostPort` and `net.DefaultResolver.LookupNetIP` for `"ip4"`, under the round's context. The probe does not use `net.ResolveUDPAddr`, which takes no context: a DNS server that hangs could then hold startup past the round's bound.
- For each server, the baseline and the 12 ladder sizes are probed concurrently, each on its own `udp4` socket from `net.Dialer{Control: setDontFragment}`. Each probe gets its own socket because Linux reports "fragmentation needed" as `EMSGSIZE` on the next read of the socket that sent the packet, and a shared socket could not say which probe the error belongs to.
- Each probe writes one request with a fresh random transaction ID, then reads into a 2048-byte buffer until a datagram is a response to that request. A datagram that is not is skipped and the read goes on.
- A response counts when it is at least 20 bytes long, carries the magic cookie and the probe's transaction ID, and is a Binding Success Response (`0x0101`) or a Binding Error Response (`0x0111`). An error response counts because a server without RFC 5780 answers the comprehension-required PADDING attribute (`0x0026`) with 420 Unknown Attribute, and that answer proves the request arrived.
- A probe ends at its answer or at its first write or read error. The errors include `EMSGSIZE` on write when the local link is smaller than the probe, `EMSGSIZE` on read after "fragmentation needed", `ECONNREFUSED` after "port unreachable", and the timeout. They are not told apart: a probe without an answer means the size was not carried.
- The round runs under one context that ends after `timeout` (`MTUProbeTimeout`, 2 s, in `plexd up`) or when `ctx` is done, whichever comes first. When it ends, a function registered with `context.AfterFunc` sets the deadline of every probe socket to now, which ends the reads still waiting.
- The round ends when every probe has ended. On a healthy uplink it returns after one round trip, and only unanswered probes wait for `timeout`.

The probe logs nothing; its caller does.

### The result

| Outcome | Returns |
|---|---|
| Some probe of some server was answered | The largest answered size over all servers, and `nil` |
| Only the baseline was answered | `48`, `nil`, which `MeshMTU` floors at 1280 |
| No probe of any server was answered | `0` and `ErrMTUProbeInconclusive` wrapping the per-server errors, joined. Each one reads `<server>: <cause>`, the cause being the resolve error, the dial or don't-fragment error, or the baseline probe's read error |
| `servers` is empty or nil | `0` and `ErrMTUProbeInconclusive` alone, at once, without opening a socket |
| `ctx` was done when the round ended | `0` and `nat: mtu probe: <ctx error>`, whatever was answered |

The result is the maximum over the servers, not the minimum. An answer proves the uplink carried that size, and one probe lost on one server must not lower the mesh MTU.

### Don't-fragment per OS

```go
func setDontFragment(network, address string, c syscall.RawConn) error
```

The dialer calls it on each socket before the socket connects. It returns the `RawConn.Control` error as it is and wraps a `setsockopt` error as `nat: mtu probe: set don't-fragment: <cause>`. The options come from `golang.org/x/sys`.

| OS | File | Option |
|---|---|---|
| Linux | `dontfrag_linux.go` | `IP_MTU_DISCOVER` = `IP_PMTUDISC_PROBE` (`unix.SetsockoptInt`) |
| macOS | `dontfrag_darwin.go` | `IP_DONTFRAG` = `1` (`unix.SetsockoptInt`) |
| Windows | `dontfrag_windows.go` | `IP_MTU_DISCOVER` = `IP_PMTUDISC_PROBE` (`windows.SetsockoptInt`) |
| Any other | `dontfrag_other.go` | None. Returns `nat: mtu probe: don't-fragment is not supported on this platform`. plexd has no WireGuard controller there |

`IP_PMTUDISC_PROBE` sets DF and ignores the path MTU the kernel cached from an earlier "fragmentation needed", so every round measures again instead of failing locally against an old value. Linux keeps such a value for 10 minutes, and `ip route get` shows it as `mtu`. A probe larger than the local link still fails on write with `EMSGSIZE`, which covers a node whose own link is the smaller one, such as PPPoE on the node itself or a cloud network at 1450 bytes.

### Trust and cost

STUN responses are unauthenticated (see `MappedAddress.Routable` in `stun.go`). A random 96-bit transaction ID per probe keeps off-path senders out. An on-path attacker can at most hold the MTU at 1420 by forging answers, or push it to 1280 by dropping probes, and `MeshMTU` bounds both.

A round sends 13 datagrams per server, 17,332 bytes of IPv4 packets: the 12 ladder sizes and the 48-byte baseline. With the two default servers that is about 35 KB per node every 10 minutes. Startup waits up to `MTUProbeTimeout` (2 s) only while some probe goes unanswered: on a black-holed uplink, or when no STUN server is reachable.

### The probe in plexd up

`plexd up` sets the probe on the WireGuard manager only when `nat.enabled` is true, so `nat.enabled: false` turns the MTU probe off. `nat.enabled` is also the key `Validate` ties to a non-empty `stun_servers`: the list is checked only while it is on. It does not stop endpoint discovery's STUN queries to the same servers; those follow `peer_exchange.enabled`, which starts the discoverer. The probe runs over `nat.stun_servers` with `MTUProbeTimeout`; `nat.timeout` does not apply to it. The probe itself does not depend on `peer_exchange.enabled`. A `nat` block that sets only `enabled: false` is read as enabled (see [Config](#config)), so the probe still runs.

## STUN Protocol Details

The package implements RFC 5389 STUN Binding Requests with the Go standard library (`encoding/binary`, `net`). The path MTU probe also uses `golang.org/x/sys` (`unix` on Linux and macOS, `windows` on Windows) to set the don't-fragment option on its sockets.

### Binding Request Format (20 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|     STUN Message Type     |         Message Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Cookie (0x2112A442)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Transaction ID (96 bits)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Message Type: `0x0001` (Binding Request)
- Message Length: `0x0000` (no attributes)
- Magic Cookie: `0x2112A442` (fixed per RFC 5389)
- Transaction ID: 12 bytes, cryptographically random

### Padded Binding Request

`buildPaddedBindingRequest(transactionID, size)` builds the request of a [path MTU probe](#path-mtu-probe): a Binding Request of exactly `size` bytes, made of the 20-byte header with message length `size − 20` and one PADDING attribute (`0x0026`, RFC 5780) whose value is `size − 24` zero bytes. Callers pass only a `size` of at least 24 that is a multiple of 4; every ladder entry minus 28 is one.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|  Binding Request (0x0001) |   Message Length (size - 20)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Magic Cookie (0x2112A442)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Transaction ID (96 bits)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        PADDING (0x0026)       |  Attribute Length (size - 24) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Value: size - 24 zero bytes                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

For the 1500-byte ladder entry `size` is 1472: message length 1452, attribute length 1448.

### Binding Response Parsing

The parser validates:
- Minimum 20-byte header
- Magic cookie matches `0x2112A442`
- Transaction ID matches the request
- Message type is `0x0101` (Binding Success Response)

The path MTU probe reads no attribute. `isResponseTo` accepts a datagram of at least 20 bytes that carries the magic cookie and the request's transaction ID, with type `0x0101` (Binding Success Response) or `0x0111` (Binding Error Response).

### XOR-MAPPED-ADDRESS (0x0020)

Preferred address attribute. Port and IP are XOR'd with the magic cookie:

```
XOR'd Port = Port ^ (Magic Cookie >> 16)
XOR'd IP   = IP ^ Magic Cookie           (IPv4)
```

### MAPPED-ADDRESS (0x0001)

Fallback attribute (used by older STUN servers). Port and IP are stored directly without XOR encoding.

## Integration Points

### With api.ControlPlane

`api.ControlPlane` satisfies the `EndpointReporter` interface directly:

```go
controlPlane := api.NewControlPlane(apiCfg, logger)
disc := nat.NewDiscoverer(stunClient, natCfg, wireguard.DefaultListenPort, logger)

// controlPlane.ReportEndpoint matches EndpointReporter.ReportEndpoint
disc.Run(ctx, controlPlane, nodeID)
```

### With SSE Events

The NAT discovery module registers no SSE handler. `plexd up` registers `peer_endpoint_changed` as a reconcile trigger and never decodes its payload: inbound peer endpoints arrive on the reconciliation state pull the event brings forward, and the WireGuard reconcile handler programs them (see [Peer Endpoint Exchange](peer-endpoint-exchange.md#data-flow)).

## Error Handling

| Scenario                      | Behavior                                           |
|-------------------------------|----------------------------------------------------|
| All STUN servers fail         | `Discover` returns error; `Run` fails on initial   |
| STUN server fails (fallback)  | Try next server in list; log warn                  |
| STUN server returns a non-routable address | Treated as a failed binding: log warn, try next server |
| STUN refresh failure           | Log warn, keep previous endpoint, retry next cycle |
| `endpoint_clock_skew` (400)   | Not retried; wrapped, logged at warn, waits for the next cycle |
| `endpoint_peer_not_found` (404) / `endpoint_peer_gone` (410) | Count the streak; warn, then error from the third consecutive rejection. Heals only via re-registration |
| Refused credential (`api.ErrCredentialRefused`, heartbeat parked) | Log debug, leave the rejection streak unchanged, continue refresh loop (see [Quiet Failure Logs](../core/heartbeat-service.md#quiet-failure-logs)) |
| `malformed_endpoint_request` (400) from a control plane without `port_mapping` support | Log warn on every cycle, continue refresh loop; the node's endpoint goes stale until the control plane is upgraded |
| Endpoint report failure (other) | Log warn, continue refresh loop                  |
| Context cancellation          | Clean abort, return `ctx.Err()`                    |

## Logging

All log entries use `component=nat`.

| Level   | Event                               | Keys                                   |
|---------|-------------------------------------|----------------------------------------|
| `Info`  | Endpoint discovered                 | `endpoint`, `nat_type`, `port_mapping`, `stun_server` |
| `Info`  | Endpoint changed                    | `old_endpoint`, `new_endpoint`         |
| `Warn`  | STUN binding failed                 | `server`, `error` (also covers a non-routable mapped address) |
| `Warn`  | NAT classification incomplete       | (no second server responded)           |
| `Warn`  | NAT translates ports                | `endpoint`, `nat_type`, `stun_port`, `mapped_port` (on the transition into `translated`, the first discovery included, not every cycle) |
| `Warn`  | STUN refresh failed                 | `error`                                |
| `Warn` (`Debug` for `api.ErrCredentialRefused`) | Endpoint report failed | `error`                       |
| `Warn`  | Control plane deadline shortens the report cadence | `delay`, `refresh_interval`, `min_report_interval`, `stale_after` |
| `Warn`/`Error` | Endpoint report rejected     | `error`, `consecutive_rejections` (404/410; `Error` from the third in a row) |
| `Debug` | STUN binding succeeded              | `server`, `mapped_address`             |

The candidate publisher's lines are listed under [Publisher log lines](#publisher-log-lines). The path MTU probe logs nothing; the WireGuard manager logs its outcome (see [MTU detection log lines](wireguard.md#mtu-detection-log-lines)).
