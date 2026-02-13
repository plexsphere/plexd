---
title: Metrics Collection & Reporting
quadrant: backend
package: internal/metrics
feature: PXD-0016
---

# Metrics Collection & Reporting

The `internal/metrics` package collects node metrics (system resources, tunnel health, peer latency) and reports them to the control plane via `POST /v1/nodes/{node_id}/metrics`. All data sources are abstracted behind injectable interfaces for testability.

The `Manager` runs two independent ticker loops in a single goroutine: one for collection and one for reporting. Collected metrics are buffered in memory and flushed to the control plane at the configured report interval.

## Config

`Config` holds metrics collection and reporting parameters.

| Field             | Type            | Default | Description                                          |
|-------------------|-----------------|---------|------------------------------------------------------|
| `Enabled`         | `bool`          | `true`  | Whether metrics collection is active                 |
| `CollectInterval` | `time.Duration` | `15s`   | Interval between collection cycles (min 5s)          |
| `ReportInterval`  | `time.Duration` | `60s`   | Interval between reporting to control plane (min 10s)|

```go
cfg := metrics.Config{}
cfg.ApplyDefaults() // Enabled=true, CollectInterval=15s, ReportInterval=60s
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

`ApplyDefaults` sets `Enabled=true` on a zero-valued Config. To disable metrics, set `Enabled=false` after calling `ApplyDefaults`.

### Validation Rules

| Field             | Rule                         | Error Message                                              |
|-------------------|------------------------------|------------------------------------------------------------|
| `CollectInterval` | >= 5s                        | `metrics: config: CollectInterval must be at least 5s`     |
| `ReportInterval`  | >= 10s                       | `metrics: config: ReportInterval must be at least 10s`     |
| `ReportInterval`  | >= `CollectInterval`         | `metrics: config: ReportInterval must be >= CollectInterval`|

When `Enabled=false`, validation is skipped entirely.

## Collector

Interface for subsystem-specific metric collection. Each collector returns a slice of `api.MetricPoint`.

```go
type Collector interface {
    Collect(ctx context.Context) ([]api.MetricPoint, error)
}
```

### Metric Groups

| Constant       | Value       | Collector          | Description                    |
|----------------|-------------|--------------------|--------------------------------|
| `GroupSystem`  | `"system"`  | `SystemCollector`  | CPU, memory, disk, network     |
| `GroupTunnel`  | `"tunnel"`  | `TunnelCollector`  | Per-peer tunnel health         |
| `GroupLatency` | `"latency"` | `LatencyCollector` | Per-peer round-trip latency    |

## SystemCollector

Collects system resource metrics via an injectable `SystemReader`.

### SystemReader

```go
type SystemReader interface {
    ReadStats(ctx context.Context) (*SystemStats, error)
}
```

### SystemStats

```go
type SystemStats struct {
    CPUUsagePercent  float64 `json:"cpu_usage_percent"`
    MemoryUsedBytes  uint64  `json:"memory_used_bytes"`
    MemoryTotalBytes uint64  `json:"memory_total_bytes"`
    DiskUsedBytes    uint64  `json:"disk_used_bytes"`
    DiskTotalBytes   uint64  `json:"disk_total_bytes"`
    NetworkRxBytes   uint64  `json:"network_rx_bytes"`
    NetworkTxBytes   uint64  `json:"network_tx_bytes"`
}
```

### Constructor

```go
func NewSystemCollector(reader SystemReader, logger *slog.Logger) *SystemCollector
```

### Collect Behavior

Returns a single `MetricPoint` with `Group="system"`. The `Data` field contains the JSON-encoded `SystemStats`.

**Example JSON data:**

```json
{
  "cpu_usage_percent": 42.5,
  "memory_used_bytes": 2147483648,
  "memory_total_bytes": 8589934592,
  "disk_used_bytes": 53687091200,
  "disk_total_bytes": 107374182400,
  "network_rx_bytes": 1048576,
  "network_tx_bytes": 524288
}
```

On reader error, returns `nil, fmt.Errorf("metrics: system: %w", err)`.

## TunnelCollector

Collects per-peer tunnel health metrics via an injectable `TunnelStatsReader`.

### TunnelStatsReader

```go
type TunnelStatsReader interface {
    ReadTunnelStats(ctx context.Context) ([]TunnelStats, error)
}
```

### TunnelStats

```go
type TunnelStats struct {
    PeerID             string    `json:"peer_id"`
    LastHandshakeTime  time.Time `json:"last_handshake_time"`
    RxBytes            uint64    `json:"rx_bytes"`
    TxBytes            uint64    `json:"tx_bytes"`
    HandshakeSucceeded bool      `json:"handshake_succeeded"`
}
```

### Constructor

```go
func NewTunnelCollector(reader TunnelStatsReader, logger *slog.Logger) *TunnelCollector
```

### Collect Behavior

Returns one `MetricPoint` per peer with `Group="tunnel"` and `PeerID` set. Each point's `Data` field contains the JSON-encoded `TunnelStats`. Returns an empty slice (not nil) when no peers exist.

**Example JSON data (per peer):**

```json
{
  "peer_id": "peer-abc-123",
  "last_handshake_time": "2026-02-12T10:30:00Z",
  "rx_bytes": 104857600,
  "tx_bytes": 52428800,
  "handshake_succeeded": true
}
```

On reader error, returns `nil, fmt.Errorf("metrics: tunnel: %w", err)`.

## LatencyCollector

Measures per-peer round-trip latency via an injectable `Pinger` and `PeerLister`.

### Pinger

```go
type Pinger interface {
    Ping(ctx context.Context, peerID string) (rttNano int64, err error)
}
```

### PeerLister

```go
type PeerLister interface {
    PeerIDs() []string
}
```

### LatencyResult

```go
type LatencyResult struct {
    PeerID  string `json:"peer_id"`
    RTTNano int64  `json:"rtt_nano"`
}
```

### Constructor

```go
func NewLatencyCollector(pinger Pinger, lister PeerLister, logger *slog.Logger) *LatencyCollector
```

### Collect Behavior

Returns one `MetricPoint` per peer with `Group="latency"` and `PeerID` set. When a ping fails for a peer, the collector logs a warning and records `RTTNano=-1` (unreachable) — it does not skip the peer or return an error. Returns an empty slice when no peers exist. If the context is cancelled mid-iteration, returns partial results with `ctx.Err()`.

**Example JSON data (per peer):**

```json
{
  "peer_id": "peer-abc-123",
  "rtt_nano": 15000000
}
```

**Unreachable peer:**

```json
{
  "peer_id": "peer-xyz-789",
  "rtt_nano": -1
}
```

## MetricReporter

Interface abstracting the control plane metrics reporting API. Satisfied by `api.ControlPlane`.

```go
type MetricReporter interface {
    ReportMetrics(ctx context.Context, nodeID string, batch api.MetricBatch) error
}
```

## Manager

Orchestrates metric collection and reporting via two independent ticker loops.

### Constructor

```go
func NewManager(cfg Config, collectors []Collector, reporter MetricReporter, nodeID string, logger *slog.Logger) *Manager
```

| Parameter    | Description                                          |
|--------------|------------------------------------------------------|
| `cfg`        | Metrics configuration                                |
| `collectors` | Slice of Collector implementations to run each cycle |
| `reporter`   | MetricReporter for sending batches to control plane  |
| `nodeID`     | Node identifier included in report requests          |
| `logger`     | Structured logger (`log/slog`)                       |

### Run Method

```go
func (m *Manager) Run(ctx context.Context) error
```

Blocks until the context is cancelled. Returns `ctx.Err()` on cancellation.

### Lifecycle

```go
sysColl := metrics.NewSystemCollector(sysReader, logger)
tunColl := metrics.NewTunnelCollector(tunReader, logger)
latColl := metrics.NewLatencyCollector(pinger, lister, logger)

mgr := metrics.NewManager(cfg, []metrics.Collector{sysColl, tunColl, latColl}, controlPlane, nodeID, logger)

// Blocks until ctx is cancelled
err := mgr.Run(ctx)
// err == context.Canceled (normal shutdown)
```

### Run Sequence

1. If `Enabled=false`: log info, return nil immediately
2. Start collect ticker (`CollectInterval`) and report ticker (`ReportInterval`)
3. On collect tick: call each collector's `Collect`, append results to mutex-protected buffer, log errors per-collector but continue
4. On report tick: swap buffer under lock, send via `ReportMetrics`, log errors but continue
5. On context cancellation: best-effort flush of remaining buffer using `context.Background()`, return `ctx.Err()`

### Buffer Management

- Collected `MetricPoint`s are appended to an internal buffer protected by `sync.Mutex`
- On report tick, the buffer is swapped out atomically (lock, copy reference, set to nil, unlock)
- Empty buffers skip the report call entirely
- On shutdown, remaining buffered points are flushed with a background context

## API Contract

### POST /v1/nodes/{node_id}/metrics

Reports a batch of metric points to the control plane.

**Request body** (`api.MetricBatch = []api.MetricPoint`):

```json
[
  {
    "timestamp": "2026-02-12T10:30:00Z",
    "group": "system",
    "data": {
      "cpu_usage_percent": 42.5,
      "memory_used_bytes": 2147483648,
      "memory_total_bytes": 8589934592,
      "disk_used_bytes": 53687091200,
      "disk_total_bytes": 107374182400,
      "network_rx_bytes": 1048576,
      "network_tx_bytes": 524288
    }
  },
  {
    "timestamp": "2026-02-12T10:30:00Z",
    "group": "tunnel",
    "peer_id": "peer-abc-123",
    "data": {
      "peer_id": "peer-abc-123",
      "last_handshake_time": "2026-02-12T10:29:55Z",
      "rx_bytes": 104857600,
      "tx_bytes": 52428800,
      "handshake_succeeded": true
    }
  },
  {
    "timestamp": "2026-02-12T10:30:00Z",
    "group": "latency",
    "peer_id": "peer-abc-123",
    "data": {
      "peer_id": "peer-abc-123",
      "rtt_nano": 15000000
    }
  }
]
```

### MetricPoint Schema

```go
type MetricPoint struct {
    Timestamp time.Time       `json:"timestamp"`
    Group     string          `json:"group"`              // "system", "tunnel", "latency"
    PeerID    string          `json:"peer_id,omitempty"`  // set for tunnel and latency groups
    Data      json.RawMessage `json:"data"`               // group-specific JSON payload
}
```

| Field       | Type              | Description                                        |
|-------------|-------------------|----------------------------------------------------|
| `Timestamp` | `time.Time`       | When the metric was collected (RFC 3339)           |
| `Group`     | `string`          | Metric group identifier                            |
| `PeerID`    | `string`          | Peer identifier (omitted for system metrics)       |
| `Data`      | `json.RawMessage` | Group-specific payload (see schemas above)         |

## Error Handling

| Scenario                        | Behavior                                            |
|---------------------------------|-----------------------------------------------------|
| Collector returns error         | Log warn, skip collector, continue with others      |
| Reporter returns error          | Log warn, buffer is cleared, continue next cycle    |
| All collectors fail             | Empty buffer, report tick is a no-op                |
| Ping fails for a peer           | Log warn, record RTTNano=-1, continue other peers   |
| Context cancelled mid-collect   | Partial results returned by latency collector       |
| Context cancelled (shutdown)    | Best-effort flush, return `ctx.Err()`               |
| Metrics disabled                | Return nil immediately, no goroutines started       |

## Logging

All log entries use `component=metrics`.

| Level  | Event                      | Keys              |
|--------|----------------------------|--------------------|
| `Info` | Metrics disabled           | `component`        |
| `Warn` | Collector failed           | `component`, `error` |
| `Warn` | Metrics report failed      | `component`, `error` |
| `Warn` | Latency ping failed        | `peer_id`, `error` |

## Integration Points

### With api.ControlPlane

`api.ControlPlane` satisfies the `MetricReporter` interface directly:

```go
controlPlane, _ := api.NewControlPlane(apiCfg, "1.0.0", logger)

// controlPlane.ReportMetrics matches MetricReporter.ReportMetrics
mgr := metrics.NewManager(cfg, collectors, controlPlane, nodeID, logger)
mgr.Run(ctx)
```

### With wireguard.Manager

`wireguard.Manager.PeerIndex()` can serve as the basis for a `PeerLister` implementation, providing the list of active peer IDs to the `LatencyCollector`.
