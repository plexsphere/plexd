---
title: Metrics Collection & Reporting
package: internal/metrics
feature: PXD-0016
---

# Metrics Collection & Reporting

The `internal/metrics` package collects node metrics (system resources, tunnel health, peer latency) and reports them to the control plane via `POST /v1/nodes/{node_id}/metrics`. All data sources are abstracted behind injectable interfaces for testability.

The `Manager` runs two independent ticker loops in a single goroutine: one for collection and one for reporting. Collected metrics are buffered in memory and flushed to the control plane at the configured report interval.

## Metric Groups

plexd collects the following metric groups at the configured `collect_interval`:

| Metric Group | Data Points |
|---|---|
| `node_resources` | CPU usage (%), memory used/total, disk used/total, load average |
| `tunnel_health` | Per-peer handshake age, TX/RX bytes, packet loss (%), last handshake timestamp |
| `peer_latency` | Per-peer RTT (ms) via ICMP echo over the mesh interface |
| `agent_stats` | plexd goroutine count, heap memory, GC stats, uptime, reconnect count |

Metrics are delivered to the control plane as **batch POST requests** (JSON array, gzip-compressed) at `report_interval` (default 60s) or when `batch_size` (default 100 data points) is reached, whichever comes first. There is no local Prometheus or OpenTelemetry exposition endpoint — all metrics flow exclusively to the control plane.

## Config

`Config` holds metrics collection and reporting parameters.

| Field             | Type            | Default | Description                                          |
|-------------------|-----------------|---------|------------------------------------------------------|
| `Enabled`         | `bool`          | `true`  | Whether metrics collection is active                 |
| `CollectInterval` | `time.Duration` | `15s`   | Interval between collection cycles (min 5s)          |
| `ReportInterval`  | `time.Duration` | `60s`   | Interval between reporting to control plane (min 10s)|
| `BatchSize`       | `int`           | `100`   | Max metric points per report batch (must be > 0)     |
| `LocalEndpoint`   | `api.LocalEndpointConfig` | _(zero)_ | Optional local endpoint for dual-destination delivery (see below) |

```go
cfg := metrics.Config{}
cfg.ApplyDefaults() // Enabled=true, CollectInterval=15s, ReportInterval=60s, BatchSize=100
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
| `BatchSize`       | > 0                          | `metrics: config: BatchSize must be > 0`                   |

When `Enabled=false`, validation is skipped entirely (including `LocalEndpoint` validation).

### Local Endpoint

> For a step-by-step setup guide, see [Setting Up Local Endpoint Delivery](../../how-to/local-endpoint-setup.md).

`LocalEndpoint` allows metrics to be sent to an additional local endpoint alongside the control plane. The type is `api.LocalEndpointConfig`, defined once in `internal/api/types.go` and shared across all three observability pipelines.

| Field                    | Type     | YAML Key                     | Description                                        |
|--------------------------|----------|------------------------------|----------------------------------------------------|
| `URL`                    | `string` | `local_endpoint.url`         | HTTPS endpoint URL. Empty means not configured.    |
| `SecretKey`              | `string` | `local_endpoint.secret_key`  | Auth credential. Required when URL is set. Redacted in config dumps. |
| `TLSInsecureSkipVerify`  | `bool`   | `local_endpoint.tls_insecure_skip_verify` | Disable TLS certificate verification. |

**Validation rules** (applied only when `Enabled=true` and `URL` is non-empty):

| Rule                       | Error Message                                                       |
|----------------------------|---------------------------------------------------------------------|
| URL must be parseable      | `metrics: config: local_endpoint: invalid URL "<url>"`              |
| Scheme must be `https`     | `metrics: config: local_endpoint: URL must be HTTPS, got "<scheme>"`|
| SecretKey must be non-empty| `metrics: config: local_endpoint: SecretKey is required when URL is set` |

A zero-valued `LocalEndpointConfig` (all fields empty/false) is valid and means "not configured".

```yaml
metrics:
  enabled: true
  collect_interval: 15s
  report_interval: 60s
  batch_size: 100
  local_endpoint:
    url: https://metrics.local:9090/ingest
    secret_key: local-metrics-token
    tls_insecure_skip_verify: false
```

## Collector

Interface for subsystem-specific metric collection. Each collector returns a slice of `api.MetricPoint`.

```go
type Collector interface {
    Collect(ctx context.Context) ([]api.MetricPoint, error)
}
```

### Metric Groups

| Constant       | Value       | Collector              | Description                          |
|----------------|-------------|------------------------|--------------------------------------|
| `GroupSystem`  | `"system"`  | `SystemCollector`      | CPU, memory, disk, network, load avg |
| `GroupTunnel`  | `"tunnel"`  | `TunnelCollector`      | Per-peer tunnel health + packet loss |
| `GroupLatency` | `"latency"` | `LatencyCollector`     | Per-peer round-trip latency          |
| `GroupAgent`   | `"agent"`   | `AgentStatsCollector`  | Go runtime, uptime, reconnects       |

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
    LoadAvg1         float64 `json:"load_avg_1"`
    LoadAvg5         float64 `json:"load_avg_5"`
    LoadAvg15        float64 `json:"load_avg_15"`
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
  "network_tx_bytes": 524288,
  "load_avg_1": 1.5,
  "load_avg_5": 1.2,
  "load_avg_15": 0.9
}
```

On reader error, returns `nil, fmt.Errorf("metrics: system: %w", err)`.

### LinuxSystemReader

Concrete `SystemReader` implementation for Linux, reading from `/proc` and `syscall.Statfs`.

```go
func NewLinuxSystemReader(mountPoint, netIface string) *LinuxSystemReader
```

| Parameter    | Default | Description                                              |
|--------------|---------|----------------------------------------------------------|
| `mountPoint` | `"/"`   | Filesystem path for disk stats via `syscall.Statfs`      |
| `netIface`   | `""`    | Network interface for rx/tx bytes; empty sums all (excl. lo) |

**Data Sources:**

| Field              | Source                | Method                                    |
|--------------------|-----------------------|-------------------------------------------|
| `CPUUsagePercent`  | `/proc/stat`          | Two samples 100ms apart, delta busy/total |
| `MemoryUsedBytes`  | `/proc/meminfo`       | `MemTotal - MemAvailable`                 |
| `MemoryTotalBytes` | `/proc/meminfo`       | `MemTotal` (kB × 1024)                   |
| `DiskUsedBytes`    | `syscall.Statfs`      | `(Blocks - Bfree) × Bsize`               |
| `DiskTotalBytes`   | `syscall.Statfs`      | `Blocks × Bsize`                         |
| `NetworkRxBytes`   | `/proc/net/dev`       | Sum of rx bytes (field 0) per interface   |
| `NetworkTxBytes`   | `/proc/net/dev`       | Sum of tx bytes (field 8) per interface   |
| `LoadAvg1/5/15`    | `/proc/loadavg`       | First three space-separated fields        |

Build-tagged `//go:build linux`.

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
    HandshakeStale     bool      `json:"handshake_stale"`
    PacketLossPercent  float64   `json:"packet_loss_percent"`
}
```

`PacketLossPercent` is provided by the `TunnelStatsReader` implementation. When packet loss measurement is unavailable, the value is `-1`.

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
  "handshake_succeeded": true,
  "handshake_stale": false,
  "packet_loss_percent": 0.5
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

## AgentStatsCollector

Collects Go runtime and agent health metrics.

### ReconnectCounter

```go
type ReconnectCounter interface {
    ReconnectCount() int
}
```

### AgentStats

```go
type AgentStats struct {
    GoroutineCount int     `json:"goroutine_count"`
    HeapAllocBytes uint64  `json:"heap_alloc_bytes"`
    HeapSysBytes   uint64  `json:"heap_sys_bytes"`
    GCPauseTotalNs uint64  `json:"gc_pause_total_ns"`
    GCNumGC        uint32  `json:"gc_num_gc"`
    UptimeSeconds  float64 `json:"uptime_seconds"`
    ReconnectCount int     `json:"reconnect_count"`
}
```

### Constructor

```go
func NewAgentStatsCollector(startTime time.Time, reconnects ReconnectCounter, logger *slog.Logger) *AgentStatsCollector
```

The `reconnects` parameter may be nil if reconnect counting is not available; `reconnect_count` defaults to 0.

### Collect Behavior

Returns a single `MetricPoint` with `Group="agent"`. Uses `runtime.NumGoroutine()` and `runtime.ReadMemStats()` for Go runtime metrics. Uptime is calculated as `time.Since(startTime)`.

**Example JSON data:**

```json
{
  "goroutine_count": 42,
  "heap_alloc_bytes": 8388608,
  "heap_sys_bytes": 16777216,
  "gc_pause_total_ns": 1500000,
  "gc_num_gc": 12,
  "uptime_seconds": 3600.5,
  "reconnect_count": 3
}
```

## MetricReporter

Interface abstracting the metrics reporting API. It is satisfied by the package's
`PlatformReporter` (the control-plane leg, which flattens each batch to
`[]api.MetricSample` and posts it through the package's `IngestClient` seam —
which `api.ControlPlane` satisfies), `LocalReporter` (the local leg), and
`MultiReporter` (both).

```go
type MetricReporter interface {
    ReportMetrics(ctx context.Context, nodeID string, batch api.MetricBatch) error
}
```

## LocalReporter

`LocalReporter` implements `MetricsReporter` by POSTing metric batches to a locally-configured HTTPS endpoint with bearer-token authentication. It operates independently from the control plane client—with its own `http.Client`, TLS settings, and credential cache.

### Constructor

```go
func NewLocalReporter(cfg api.LocalEndpointConfig, fetcher SecretFetcher, nsk []byte, nodeID string, logger *slog.Logger) *LocalReporter
```

| Parameter | Description |
|-----------|-------------|
| `cfg` | Local endpoint configuration (URL, secret key, TLS settings) |
| `fetcher` | SecretFetcher for retrieving encrypted credentials (satisfied by `api.ControlPlane`) |
| `nsk` | Node secret key bytes for AES-256-GCM decryption via `nodeapi.DecryptSecret` |
| `nodeID` | Node identifier passed to `SecretFetcher.FetchSecret` |
| `logger` | Structured logger (`log/slog`) |

### SecretFetcher

```go
type SecretFetcher interface {
    FetchSecret(ctx context.Context, nodeID, name string, version int) (*api.SecretEnvelope, error)
}
```

Defined in the `metrics` package. The `api.ControlPlane` client satisfies this interface.

### HTTP Client

Each `LocalReporter` creates its own `http.Client` at construction time:

| Setting | Value | Notes |
|---------|-------|-------|
| Timeout | 10s | Per-request timeout including connection, TLS handshake, and response body |
| TLS | Configurable | `TLSInsecureSkipVerify` controls certificate validation for this client only |
| Compression | None | Batches are sent as uncompressed JSON (unlike the gzip-compressed control plane client) |

### Credential Resolution

On each `ReportMetrics` call, `LocalReporter` resolves a bearer token via the following flow:

1. **Check cache** (read lock): if `cachedToken` is non-empty and `fetchedAt` is within the 5-minute TTL, return the cached token immediately.
2. **Acquire write lock** and double-check the cache (another goroutine may have refreshed it).
3. **Fetch secret**: call `SecretFetcher.FetchSecret(ctx, nodeID, secretKey, 0)` to retrieve the current version's encrypted envelope.
4. **Decrypt**: call `nodeapi.DecryptSecret(nsk, resp.Data)` to obtain the plaintext token.
5. **Update cache**: store the plaintext token and current timestamp.

**Failure modes:**

| Scenario | Behavior |
|----------|----------|
| Fetch or decrypt fails, stale cache exists | Log warning, return stale cached token |
| Fetch or decrypt fails, no cache | Return error, no HTTP POST is made |

The cache is protected by `sync.RWMutex` with a double-checked locking pattern, making it safe for concurrent `ReportMetrics` calls.

### ReportMetrics Behavior

```go
func (r *LocalReporter) ReportMetrics(ctx context.Context, nodeID string, batch api.MetricBatch) error
```

1. Resolve bearer token (see above)
2. JSON-marshal the `MetricBatch`
3. `POST` to `cfg.URL` with headers:
   - `Content-Type: application/json`
   - `Authorization: Bearer {token}`
4. Return `nil` on 2xx response; return error containing the status code on non-2xx

## MultiReporter

`MultiReporter` implements `MetricsReporter` by dispatching to both a platform and a local reporter concurrently. It is the adapter that enables dual-destination delivery without modifying the `Manager`.

### Constructor

```go
func NewMultiReporter(platform, local MetricsReporter, logger *slog.Logger) *MultiReporter
```

| Parameter | Description |
|-----------|-------------|
| `platform` | Primary reporter (typically `api.ControlPlane`) — its error is returned to the caller |
| `local` | Secondary reporter (typically `LocalReporter`) — its error is logged but not returned |
| `logger` | Structured logger (`log/slog`) |

### Error Semantics

`ReportMetrics` dispatches to both reporters in parallel goroutines and waits for both to complete.

| Platform result | Local result | Return value | Side effect |
|-----------------|--------------|--------------|-------------|
| success | success | `nil` | — |
| error | success | platform error | — |
| success | error | `nil` | Local error logged as warning |
| error | error | platform error | Local error logged as warning |

Only the platform error is returned. This is critical because the `Manager` uses the return value to decide whether to retain the batch in its buffer for retry. Local endpoint failures must not trigger batch retention.

### Concurrency

A slow or hanging local endpoint does **not** delay the availability of the platform result. Both goroutines run independently; `MultiReporter` waits for both via `sync.WaitGroup` before returning.

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

The control-plane leg of the pipeline (`PlatformReporter`) flattens each buffered
`MetricPoint` into one or more `api.MetricSample` records and POSTs them as a
**JSON array**. The request stamps an `X-Plexsphere-Sent-At` header (RFC 3339,
nanosecond precision, UTC) and is gzip-compressed when the body exceeds 1 KiB.
Success is `202 Accepted` with an `IngestReceipt`.

**Request body** (`[]api.MetricSample`):

```json
[
  {
    "group": "node_resources",
    "name": "cpu_usage_percent",
    "value": 42.5,
    "timestamp": "2026-02-12T10:30:00Z"
  },
  {
    "group": "tunnel_health",
    "name": "rx_bytes",
    "value": 104857600,
    "labels": { "peer_id": "peer-abc-123" },
    "timestamp": "2026-02-12T10:30:00Z"
  },
  {
    "group": "peer_latency",
    "name": "rtt_seconds",
    "value": 0.015,
    "labels": { "peer_id": "peer-abc-123" },
    "timestamp": "2026-02-12T10:30:00Z"
  }
]
```

**MetricSample fields:**

| Field       | Type                | JSON Tag             | Description                                              |
|-------------|---------------------|----------------------|----------------------------------------------------------|
| `Group`     | `string`            | `"group"`            | Wire group: `node_resources`, `tunnel_health`, `peer_latency`, or `agent_stats` |
| `Name`      | `string`            | `"name"`             | Sample name (see the flattening table)                   |
| `Value`     | `float64`           | `"value"`            | Sample value                                             |
| `Labels`    | `map[string]string` | `"labels,omitempty"` | Dimensions such as `peer_id`; omitted when the sample has none |
| `Timestamp` | `time.Time`         | `"timestamp"`        | The originating point's collection time (RFC 3339)       |

#### Flattening

`PlatformReporter` expands every numeric field of a `MetricPoint`'s data struct
into its own sample, carrying the point's timestamp and the wire group for the
point's internal group. A non-finite value (`NaN`/`Inf`) is skipped individually
with a Debug log so one bad field does not fail the whole batch.

| Internal group | Wire group       | Sample names | Labels |
|----------------|------------------|--------------|--------|
| `system`  | `node_resources` | `cpu_usage_percent`, `memory_used_bytes`, `memory_total_bytes`, `disk_used_bytes`, `disk_total_bytes`, `network_rx_bytes`, `network_tx_bytes`, `load_avg_1`, `load_avg_5`, `load_avg_15` | — |
| `tunnel`  | `tunnel_health`  | `rx_bytes`, `tx_bytes`, `handshake_succeeded` (0/1), `handshake_stale` (0/1), `packet_loss_percent`, `last_handshake_timestamp_seconds` (Unix seconds, `0` for a zero time) | `peer_id` |
| `latency` | `peer_latency`   | `rtt_seconds` (`rtt_nano / 1e9`; the `-1` ping-failure sentinel is carried through as `-1`) | `peer_id` |
| `agent`   | `agent_stats`    | `goroutine_count`, `heap_alloc_bytes`, `heap_sys_bytes`, `gc_pause_total_ns`, `gc_num_gc`, `uptime_seconds`, `reconnect_count` | — |

#### Response — IngestReceipt (`202 Accepted`)

```json
{ "accepted_at": "2026-02-12T10:30:00.123456789Z", "records": 17 }
```

| Field        | Type        | JSON Tag        | Description                                  |
|--------------|-------------|-----------------|----------------------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | When the control plane accepted the batch    |
| `Records`    | `int`       | `"records"`     | Number of records accepted from the batch    |

A batch that flattens to zero samples is never sent (the ingest contract rejects
an empty array).

#### Ingest errors

| Status | Problem `code` | Meaning | `PlatformReporter` reaction |
|--------|----------------|---------|-----------------------------|
| `400 Bad Request` | `ingest_batch_malformed` | Body is not a non-empty JSON array, or a record carries an out-of-set `group`, empty `name`, or zero `timestamp` | Drops the batch — a verdict on the bytes, which no retry changes |
| `400 Bad Request` | `ingest_sent_at_invalid` | `X-Plexsphere-Sent-At` is missing or not an RFC 3339 timestamp | Returned for retry — the header is re-stamped on every attempt, so it clears once the node's clock converges |
| `413 Payload Too Large` | — | Batch exceeds the server-side size limit | Halves the batch and re-sends each half; a single sample still refused is dropped |
| `415 Unsupported Media Type` | `ingest_encoding_unsupported` | `Content-Encoding` is neither `gzip` nor `identity` | Returned for retry — a property of the deployment, not of the batch |
| `501 Not Implemented` | `observability_ingest_not_provisioned` | Observability ingest is not provisioned | Drops the batch quietly (a one-time Info log on the transition, another on recovery) rather than re-buffering it |

Any other error is returned to `Manager.flush`, which retains and retries the
batch.

Every sample the reporter discards — an unconvertible point, a dropped batch, a
sample over the size limit — is added to a running count that is summarized in a
`dropping metric samples` Warn at most once every five minutes. `Manager.flush`
takes its success path for a dropped batch, so this log is the only signal that
metrics are being lost.

### Internal / local-endpoint format: MetricPoint

The in-memory buffer and the optional [local endpoint](#local-endpoint)
(`LocalReporter`) keep the richer `MetricPoint` shape; only the control-plane leg
flattens to `MetricSample`.

**Example body** (`api.MetricBatch = []api.MetricPoint`):

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
      "network_tx_bytes": 524288,
      "load_avg_1": 1.5,
      "load_avg_5": 1.2,
      "load_avg_15": 0.9
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
      "handshake_succeeded": true,
      "handshake_stale": false,
      "packet_loss_percent": 0.5
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

#### MetricPoint Schema

```go
type MetricPoint struct {
    Timestamp time.Time       `json:"timestamp"`
    Group     string          `json:"group"`              // "system", "tunnel", "latency", "agent"
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
| `Warn` | Using cached credential    | `component`, `error` |
| `Warn` | Local metrics report failed| `component`, `error` |
| `Info` | Local endpoint enabled     | `pipeline`, `url`  |

## Integration Points

### With api.ControlPlane

`api.ControlPlane` is the control-plane ingest client; the pipeline reaches it
through a `PlatformReporter`, which flattens each batch to `[]api.MetricSample`
and posts it via the client:

```go
controlPlane, _ := api.NewControlPlane(apiCfg, "1.0.0", logger)

// PlatformReporter is the control-plane leg; controlPlane satisfies its IngestClient seam.
reporter := metrics.NewPlatformReporter(controlPlane, logger)
mgr := metrics.NewManager(cfg, collectors, reporter, nodeID, logger)
mgr.Run(ctx)
```

### With LocalReporter and MultiReporter

When `LocalEndpoint.URL` is configured, the pipeline manager receives a `MultiReporter` that wraps both the `PlatformReporter` and a `LocalReporter`. When not configured, the `PlatformReporter` is used directly—no extra goroutines, no `SecretFetcher` calls, no `MultiReporter` wrapping.

```go
nsk := []byte(identity.NodeSecretKey)

var metricsReporter metrics.MetricsReporter = metrics.NewPlatformReporter(controlPlane, logger)
if cfg.Metrics.LocalEndpoint.URL != "" {
    localReporter := metrics.NewLocalReporter(cfg.Metrics.LocalEndpoint, controlPlane, nsk, identity.NodeID, logger)
    metricsReporter = metrics.NewMultiReporter(metricsReporter, localReporter, logger)
    logger.Info("local endpoint enabled", "pipeline", "metrics", "url", cfg.Metrics.LocalEndpoint.URL)
}
mgr := metrics.NewManager(cfg.Metrics, collectors, metricsReporter, identity.NodeID, logger)
```

### Integration Tests

See [Local Endpoint Integration Tests](../development/local-endpoint-integration-tests.md) for the full integration test suite covering dual delivery, error isolation, credential resolution, and TLS skip-verify across all three pipelines.

### With wireguard.Manager

`wireguard.Manager.PeerIndex()` can serve as the basis for a `PeerLister` implementation, providing the list of active peer IDs to the `LatencyCollector`.
