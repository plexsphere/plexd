---
title: NAT Traversal via STUN
quadrant: backend
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

`ApplyDefaults` always sets `Enabled=true`. To disable NAT traversal, set `Enabled=false` after calling `ApplyDefaults`.

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
| `Run`        | `(ctx context.Context, reporter EndpointReporter, updater PeerUpdater, nodeID string) error`     | Discovery + report loop (blocks until context cancelled)     |
| `LastResult` | `() *api.NATInfo`                                                                                | Most recent result (thread-safe, nil before first discovery) |

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
err := disc.Run(ctx, controlPlane, wgManager, nodeID)
// returns on context cancellation with ctx.Err()
```

### Run Sequence

1. Perform initial `Discover(ctx)` — returns error if all STUN servers fail
2. Report endpoint via `reportAndApply` — log warning on failure, continue
3. Enter ticker loop at `Config.RefreshInterval`:
   - Re-discover → on failure: log warning, keep previous endpoint
   - On endpoint change: log info with old/new endpoints
   - Report via `reportAndApply` → on failure: log warning, continue
4. On context cancellation: return `ctx.Err()`

### Heartbeat Integration

The `LastResult()` method provides the most recent `*api.NATInfo` for inclusion in heartbeat payloads. Access is protected by `sync.RWMutex` for safe concurrent reads from the heartbeat goroutine.

```go
// In heartbeat loop (future agent lifecycle code)
heartbeat := api.HeartbeatRequest{
    NAT: disc.LastResult(), // nil-safe, returns nil before first discovery
}
```

## EndpointReporter

Interface for reporting discovered endpoints to the control plane. Satisfied by `api.ControlPlane`.

```go
type EndpointReporter interface {
    ReportEndpoint(ctx context.Context, nodeID string, req api.EndpointReport) (*api.EndpointResponse, error)
}
```

### Wire Types

```go
// Request: PUT /v1/nodes/{node_id}/endpoint
type EndpointReport struct {
    PublicEndpoint string `json:"public_endpoint"` // "203.0.113.5:54321"
    NATType        string `json:"nat_type"`        // "full_cone", "symmetric", "none", "unknown"
}

// Response
type EndpointResponse struct {
    PeerEndpoints []PeerEndpoint `json:"peer_endpoints"`
}

type PeerEndpoint struct {
    PeerID   string `json:"peer_id"`
    Endpoint string `json:"endpoint"` // empty if peer hasn't discovered yet
}
```

## PeerUpdater

Interface for updating WireGuard peer endpoints. Satisfied by `wireguard.Manager`.

```go
type PeerUpdater interface {
    UpdatePeer(peer api.Peer) error
}
```

## reportAndApply

Internal function that bridges endpoint reporting and peer configuration.

1. Call `reporter.ReportEndpoint` with the discovered endpoint and NAT type
2. Iterate `PeerEndpoints` from the response
3. Skip entries with empty endpoint strings (peer not yet discovered)
4. For each valid peer endpoint, call `updater.UpdatePeer`
5. Individual peer update failures are logged at warn level but do not halt processing

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
disc.Run(ctx, controlPlane, wgManager, nodeID)
```

### With wireguard.Manager

`wireguard.Manager` satisfies the `PeerUpdater` interface directly:

```go
wgManager := wireguard.NewManager(ctrl, wireguard.Config{}, logger)

// wgManager.UpdatePeer matches PeerUpdater.UpdatePeer
disc.Run(ctx, controlPlane, wgManager, nodeID)
```

### With SSE Events

The existing `wireguard.HandlePeerEndpointChanged` SSE handler (from B001) processes `peer_endpoint_changed` events for real-time endpoint updates. The NAT discovery module does not register its own SSE handler — it relies on the wireguard handler for inbound endpoint updates.

## Error Handling

| Scenario                      | Behavior                                           |
|-------------------------------|----------------------------------------------------|
| All STUN servers fail         | `Discover` returns error; `Run` fails on initial   |
| STUN server fails (fallback)  | Try next server in list; log warn                  |
| STUN refresh failure           | Log warn, keep previous endpoint, retry next cycle |
| Endpoint report failure       | Log warn, continue refresh loop                    |
| Individual peer update fails  | Log warn, continue processing remaining peers      |
| Context cancellation          | Clean abort, return `ctx.Err()`                    |

## Logging

All log entries use `component=nat`.

| Level   | Event                               | Keys                                   |
|---------|-------------------------------------|----------------------------------------|
| `Info`  | Endpoint discovered                 | `endpoint`, `nat_type`, `stun_server`  |
| `Info`  | Endpoint changed                    | `old_endpoint`, `new_endpoint`         |
| `Warn`  | STUN binding failed                 | `server`, `error`                      |
| `Warn`  | NAT classification incomplete       | (no second server responded)           |
| `Warn`  | STUN refresh failed                 | `error`                                |
| `Warn`  | Endpoint report failed              | `error`                                |
| `Warn`  | Peer endpoint update failed         | `peer_id`, `error`                     |
| `Debug` | STUN binding succeeded              | `server`, `endpoint`                   |
