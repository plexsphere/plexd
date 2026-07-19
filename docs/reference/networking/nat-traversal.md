---
title: NAT Traversal via STUN
package: internal/nat
feature: PXD-0006
---

# NAT Traversal via STUN

The `internal/nat` package discovers a node's public endpoint using STUN servers, classifies the NAT type, and reports the result to the control plane. Peers behind NAT use the discovered endpoints to establish direct WireGuard connections.

All STUN network operations go through a `STUNClient` interface, enabling full unit testing without real STUN servers or UDP sockets. The STUN protocol implementation covers RFC 5389 Binding requests and XOR-MAPPED-ADDRESS parsing using only the Go standard library.

## Config

`Config` holds NAT traversal parameters passed to the `Discoverer`.

| Field             | Type            | Default                                                      | Description                         |
|-------------------|-----------------|--------------------------------------------------------------|-------------------------------------|
| `Enabled`         | `bool`          | `true`                                                       | Whether NAT traversal is active     |
| `STUNServers`     | `[]string`      | `["stun.l.google.com:19302", "stun.cloudflare.com:3478"]`   | STUN server addresses (host:port)   |
| `RefreshInterval` | `time.Duration` | `60s`                                                        | Interval between STUN refreshes     |
| `Timeout`         | `time.Duration` | `5s`                                                         | Per-server STUN request timeout     |

```go
cfg := nat.Config{
    STUNServers: []string{"stun.example.com:3478"},
}
cfg.ApplyDefaults() // Enabled=true, RefreshInterval=60s, Timeout=5s
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

`ApplyDefaults` sets `Enabled=true` on a zero-valued Config (when `STUNServers == nil && RefreshInterval == 0 && Timeout == 0`). If any field is already set, `Enabled` is left as-is. To disable NAT traversal, set `Enabled=false` after calling `ApplyDefaults`.

### Validation Rules

| Field             | Rule                          | Error Message                                             |
|-------------------|-------------------------------|-----------------------------------------------------------|
| `STUNServers`     | Non-empty when `Enabled=true` | `nat: config: STUNServers must not be empty when enabled` |
| `RefreshInterval` | >= 10s                        | `nat: config: RefreshInterval must be at least 10s`       |
| `Timeout`         | > 0                           | `nat: config: Timeout must be positive`                   |

When `Enabled=false`, validation is skipped entirely.

## STUNClient

Interface abstracting the UDP STUN binding round trip. The production implementation creates a UDP socket bound to the WireGuard listen port (using `SO_REUSEADDR`/`SO_REUSEPORT`), sends a STUN Binding Request, and parses the response.

```go
type STUNClient interface {
    Bind(ctx context.Context, serverAddr string, localPort int) (MappedAddress, error)
}
```

| Parameter    | Description                                    |
|--------------|------------------------------------------------|
| `serverAddr` | STUN server address (host:port)                |
| `localPort`  | Local UDP source port (must match WireGuard)   |

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
| `NATNone`      | `"none"`      | Mapped port matches local port — node has a public IP             |
| `NATFullCone`  | `"full_cone"` | Same mapped address from different servers — consistent NAT       |
| `NATSymmetric` | `"symmetric"` | Different mapped addresses — per-destination NAT, relay needed    |
| `NATUnknown`   | `"unknown"`   | Only one server responded — classification incomplete             |

### Classification Logic

1. Send STUN binding to first reachable server → `firstAddr`
2. If `firstAddr.Port == localPort` → `NATNone` (no NAT detected)
3. Send binding to a second server → `secondAddr`
4. If `firstAddr == secondAddr` → `NATFullCone`
5. If `firstAddr != secondAddr` → `NATSymmetric`
6. If no second server responded → `NATUnknown`

### Wire Mapping

`NATType.Wire()` maps the classifier's value to the control-plane wire enum used by both the heartbeat `nat_summary` and the endpoint report:

- `none` → `full_cone` — an un-NATed endpoint is directly reachable with no filtering, the full_cone traversal posture
- `full_cone` and `symmetric` → themselves
- anything else (including `unknown`) → `unknown`

The wire enum also includes `restricted` and `port_restricted`, which this classifier does not currently emit.

## Discoverer

Central coordinator for STUN discovery, NAT classification, and endpoint reporting.

### Constructor

```go
func NewDiscoverer(client STUNClient, cfg Config, localPort int, logger *slog.Logger) *Discoverer
```

| Parameter   | Description                                           |
|-------------|-------------------------------------------------------|
| `client`    | STUN client implementation                            |
| `cfg`       | NAT traversal configuration                           |
| `localPort` | WireGuard listen port (used as STUN source port)      |
| `logger`    | Structured logger (`log/slog`)                        |

### Methods

| Method       | Signature                                                                                        | Description                                                  |
|--------------|--------------------------------------------------------------------------------------------------|--------------------------------------------------------------|
| `Discover`   | `(ctx context.Context) (*DiscoveryResult, error)`                                                | Single STUN discovery + NAT classification                   |
| `Run`        | `(ctx context.Context, reporter EndpointReporter, nodeID string) error`                          | Discovery + report loop (blocks until context cancelled)     |
| `LastResult` | `() *DiscoveryResult`                                                                            | Most recent result (thread-safe, nil before first discovery) |

### DiscoveryResult

```go
type DiscoveryResult struct {
    Endpoint string  // "ip:port" format
    NATType  NATType
}
```

### Lifecycle

```go
logger := slog.Default()

// Create discoverer with WireGuard listen port
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
    Endpoint   string    `json:"endpoint"`    // "203.0.113.5:54321"
    NATType    string    `json:"nat_type"`    // "full_cone", "restricted", "port_restricted", "symmetric", "unknown"
    ReportedAt time.Time `json:"reported_at"` // RFC 3339 UTC, fresh per attempt
}

// Response
type EndpointResponse struct {
    AcceptedAt time.Time `json:"accepted_at"`
    StaleAfter time.Time `json:"stale_after"` // freshness deadline; drives the next report
}
```

The response no longer carries peer endpoints. Inbound peer endpoint updates arrive via the `peer_endpoint_changed` SSE event (and, once issue #20 lands, the reconciliation state pull).

## report

Internal function that sends the discovered endpoint to the control plane and returns the `stale_after` deadline.

1. Build an `EndpointRequest` with a fresh `reported_at` and the `Wire()` NAT type
2. Call `reporter.ReportEndpoint`
3. On `endpoint_peer_not_found` (404) or `endpoint_peer_gone` (410): wrap the error in the internal `errEndpointRejected` sentinel so the caller can count the streak
4. Any other error is wrapped `nat: report endpoint: <cause>`
5. Return the response's `stale_after` (zero when the report failed or the response was empty)

`endpoint_clock_skew` (400) is deliberately **not** retried. `reported_at` is read from the same clock that produced the rejected timestamp, so an immediate second attempt carries an equally skewed value and is rejected identically — it would only double the request volume during the NTP incident that caused the skew. The heartbeat path already reports clock skew with the actionable "synchronize the system clock via NTP" guidance.

`Discoverer.reportEndpoint` wraps `report` and owns the failure logging. A rejection means the control plane no longer holds this node's peer record; re-reporting cannot clear it, and because heartbeats keep succeeding, no other health signal turns red. Consecutive rejections are therefore counted: the first two log at `Warn`, the third and beyond log at `Error` with `consecutive_rejections`, which is alertable. A successful report clears the streak; a transient failure leaves it intact, since it says nothing about whether the peer record came back. Recovery still requires re-registration — the loop surfaces the condition rather than resolving it.

## STUN Protocol Details

The package implements RFC 5389 STUN Binding Requests using only the Go standard library (`encoding/binary`, `net`).

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

### Binding Response Parsing

The parser validates:
- Minimum 20-byte header
- Magic cookie matches `0x2112A442`
- Transaction ID matches the request
- Message type is `0x0101` (Binding Success Response)

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

The existing `wireguard.HandlePeerEndpointChanged` SSE handler (from B001) processes `peer_endpoint_changed` events for real-time endpoint updates. The NAT discovery module does not register its own SSE handler — it relies on the wireguard handler for inbound endpoint updates.

## Error Handling

| Scenario                      | Behavior                                           |
|-------------------------------|----------------------------------------------------|
| All STUN servers fail         | `Discover` returns error; `Run` fails on initial   |
| STUN server fails (fallback)  | Try next server in list; log warn                  |
| STUN server returns a non-routable address | Treated as a failed binding: log warn, try next server |
| STUN refresh failure           | Log warn, keep previous endpoint, retry next cycle |
| `endpoint_clock_skew` (400)   | Not retried; wrapped, logged at warn, waits for the next cycle |
| `endpoint_peer_not_found` (404) / `endpoint_peer_gone` (410) | Count the streak; warn, then error from the third consecutive rejection. Heals only via re-registration |
| Endpoint report failure (other) | Log warn, continue refresh loop                  |
| Context cancellation          | Clean abort, return `ctx.Err()`                    |

## Logging

All log entries use `component=nat`.

| Level   | Event                               | Keys                                   |
|---------|-------------------------------------|----------------------------------------|
| `Info`  | Endpoint discovered                 | `endpoint`, `nat_type`, `stun_server`  |
| `Info`  | Endpoint changed                    | `old_endpoint`, `new_endpoint`         |
| `Warn`  | STUN binding failed                 | `server`, `error` (also covers a non-routable mapped address) |
| `Warn`  | NAT classification incomplete       | (no second server responded)           |
| `Warn`  | STUN refresh failed                 | `error`                                |
| `Warn`  | Endpoint report failed              | `error`                                |
| `Warn`  | Control plane deadline shortens the report cadence | `delay`, `refresh_interval`, `min_report_interval`, `stale_after` |
| `Warn`/`Error` | Endpoint report rejected     | `error`, `consecutive_rejections` (404/410; `Error` from the third in a row) |
| `Debug` | STUN binding succeeded              | `server`, `endpoint`                   |
