---
title: Log Forwarding
package: internal/logfwd
feature: PXD-0017
---

# Log Forwarding

The `internal/logfwd` package forwards system and application logs from plexd mesh nodes to the control plane via `POST /v1/nodes/{node_id}/logs`. All log sources are abstracted behind injectable interfaces for testability.

The `Forwarder` runs two independent ticker loops in a single goroutine: one for collection and one for reporting. Collected log entries are buffered in memory and flushed to the control plane at the configured report interval.

## Log Format and Delivery

Logs are collected from the configured sources and delivered to the control plane as **batch POST requests** using JSON Lines format, gzip-compressed. Batches are flushed at `report_interval` (default 30s) or when `batch_size` (default 200 entries) is reached.

Each log line is serialized as:

```json
{
  "timestamp": "2025-01-15T10:30:00.123Z",
  "source": "journald",
  "unit": "plexd",
  "message": "reconciliation completed, 0 drifts corrected",
  "severity": "info",
  "hostname": "web-01"
}
```

- **Filtering:** Severity-level filters (`min_severity`), unit inclusion lists (`include_units`), and unit exclusion lists (`exclude_units`) are applied before batching.
- **File patterns:** Glob patterns in `file_patterns` specify additional log files to monitor beyond journald.
- **Source availability:** The journald source is only registered on Linux hosts that actually have `journalctl`. On a host without it — a container image without systemd, typically — `plexd up` logs `journald not available, journald log source disabled` once at startup and forwards from the configured `file_patterns` only.
- **Offline buffering:** When the control plane is unreachable, log entries are buffered internally. Buffered entries are drained on reconnection.

## Config

`Config` holds log forwarding parameters.

| Field             | Type            | Default | Description                                    |
|-------------------|-----------------|---------|------------------------------------------------|
| `Enabled`         | `bool`          | `true`  | Whether log forwarding is active               |
| `CollectInterval` | `time.Duration` | `10s`   | Interval between collection cycles (min 5s)    |
| `ReportInterval`  | `time.Duration` | `30s`   | Interval between reporting to control plane    |
| `BatchSize`       | `int`           | `200`   | Maximum log entries per report batch (min 1)   |
| `FilePatterns`    | `[]string`      | `nil`   | Glob patterns for file-based log collection    |
| `Filter`          | `FilterConfig`  | _(empty)_ | Log filtering rules (see LogFilter section)  |
| `LocalEndpoint`   | `api.LocalEndpointConfig` | _(zero)_ | Optional local endpoint for dual-destination delivery (see below) |

```go
cfg := logfwd.Config{}
cfg.ApplyDefaults() // Enabled=true, CollectInterval=10s, ReportInterval=30s, BatchSize=200
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

`ApplyDefaults` sets `Enabled=true` on a zero-valued Config. To disable log forwarding, set `Enabled=false` after calling `ApplyDefaults`.

### Validation Rules

| Field             | Rule                 | Error Message                                               |
|-------------------|----------------------|-------------------------------------------------------------|
| `CollectInterval` | >= 5s                | `logfwd: config: CollectInterval must be at least 5s`       |
| `ReportInterval`  | >= `CollectInterval` | `logfwd: config: ReportInterval must be >= CollectInterval` |
| `BatchSize`       | >= 1                 | `logfwd: config: BatchSize must be at least 1`              |

When `Enabled=false`, validation is skipped entirely (including `LocalEndpoint` validation).

### Local Endpoint

> For a step-by-step setup guide, see [Setting Up Local Endpoint Delivery](../../how-to/local-endpoint-setup.md).

`LocalEndpoint` allows logs to be sent to an additional local endpoint alongside the control plane. The type is `api.LocalEndpointConfig`, defined once in `internal/api/types.go` and shared across all three observability pipelines.

| Field                    | Type     | YAML Key                     | Description                                        |
|--------------------------|----------|------------------------------|----------------------------------------------------|
| `URL`                    | `string` | `local_endpoint.url`         | HTTPS endpoint URL. Empty means not configured.    |
| `SecretKey`              | `string` | `local_endpoint.secret_key`  | Auth credential. Required when URL is set. Redacted in config dumps. |
| `TLSInsecureSkipVerify`  | `bool`   | `local_endpoint.tls_insecure_skip_verify` | Disable TLS certificate verification. |

**Validation rules** (applied only when `Enabled=true` and `URL` is non-empty):

| Rule                       | Error Message                                                       |
|----------------------------|---------------------------------------------------------------------|
| URL must be parseable      | `logfwd: config: local_endpoint: invalid URL "<url>"`               |
| Scheme must be `https`     | `logfwd: config: local_endpoint: URL must be HTTPS, got "<scheme>"` |
| SecretKey must be non-empty| `logfwd: config: local_endpoint: SecretKey is required when URL is set` |

A zero-valued `LocalEndpointConfig` (all fields empty/false) is valid and means "not configured".

```yaml
log_fwd:
  enabled: true
  collect_interval: 10s
  report_interval: 30s
  batch_size: 200
  local_endpoint:
    url: https://logs.local:9090/ingest
    secret_key: local-logs-token
    tls_insecure_skip_verify: false
```

## LogSource

Interface for subsystem-specific log collection. Each source returns a slice of `api.LogEntry`.

```go
type LogSource interface {
    Collect(ctx context.Context) ([]api.LogEntry, error)
}
```

## LogReporter

Interface abstracting the log reporting API. It is satisfied by the package's
`PlatformReporter` (the control-plane leg, which converts each batch to
`[]api.LogLine` and posts it through the package's `IngestClient` seam — which
`api.ControlPlane` satisfies), `LocalReporter` (the local leg), and
`MultiReporter` (both).

```go
type LogReporter interface {
    ReportLogs(ctx context.Context, nodeID string, batch api.LogBatch) error
}
```

## LocalReporter

`LocalReporter` implements `LogReporter` by POSTing log batches to a locally-configured HTTPS endpoint with bearer-token authentication. It operates independently from the control plane client—with its own `http.Client`, TLS settings, and credential cache.

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

Defined in the `logfwd` package. The `api.ControlPlane` client satisfies this interface.

### HTTP Client

| Setting | Value | Notes |
|---------|-------|-------|
| Timeout | 10s | Per-request timeout |
| TLS | Configurable | `TLSInsecureSkipVerify` controls certificate validation for this client only |
| Compression | None | Batches are sent as uncompressed JSON |

### Credential Resolution

Same flow as `metrics.LocalReporter`: check cache (5-minute TTL) → `FetchSecret` → `DecryptSecret` → update cache. Falls back to stale cached token on fetch/decrypt failure. Protected by `sync.RWMutex` with double-checked locking.

### ReportLogs Behavior

```go
func (r *LocalReporter) ReportLogs(ctx context.Context, nodeID string, batch api.LogBatch) error
```

1. Resolve bearer token
2. JSON-marshal the `LogBatch` (identical JSON body to what the platform receives)
3. `POST` to `cfg.URL` with `Content-Type: application/json` and `Authorization: Bearer {token}`
4. Return `nil` on 2xx; return error containing the status code on non-2xx

## MultiReporter

`MultiReporter` implements `LogReporter` by dispatching to both a platform and a local reporter concurrently.

### Constructor

```go
func NewMultiReporter(platform, local LogReporter, logger *slog.Logger) *MultiReporter
```

### Error Semantics

| Platform result | Local result | Return value | Side effect |
|-----------------|--------------|--------------|-------------|
| success | success | `nil` | — |
| error | success | platform error | — |
| success | error | `nil` | Local error logged as warning |
| error | error | platform error | Local error logged as warning |

Only the platform error is returned. The `Forwarder` uses the return value for retry/retain decisions—local failures must not trigger batch retention.

## JournalReader

Interface abstracting systemd journal access for testability.

```go
type JournalReader interface {
    ReadEntries(ctx context.Context) ([]JournalEntry, error)
}
```

### JournalEntry

```go
type JournalEntry struct {
    Timestamp time.Time
    Message   string
    Priority  int
    Unit      string
}
```

## JournaldSource

Collects log entries from the systemd journal via an injectable `JournalReader`.

### Constructor

```go
func NewJournaldSource(reader JournalReader, hostname string, logger *slog.Logger) *JournaldSource
```

| Parameter  | Description                                        |
|------------|----------------------------------------------------|
| `reader`   | JournalReader implementation for reading entries   |
| `hostname` | Node hostname included in every log entry          |
| `logger`   | Structured logger (`log/slog`)                     |

### Field Mapping

| Journal Field          | LogEntry Field | Description                            |
|------------------------|----------------|----------------------------------------|
| `MESSAGE`              | `Message`      | Log message content                    |
| `PRIORITY`             | `Severity`     | Mapped from integer to severity string |
| `_SYSTEMD_UNIT`        | `Unit`         | Systemd unit name (empty if absent)    |
| `__REALTIME_TIMESTAMP` | `Timestamp`    | Entry timestamp                        |
| _(constant)_           | `Source`       | Always `"journald"`                    |
| _(constructor)_        | `Hostname`     | Set at construction time               |

### Priority-to-Severity Mapping

| Priority | Severity    |
|----------|-------------|
| 0        | `emerg`     |
| 1        | `alert`     |
| 2        | `crit`      |
| 3        | `err`       |
| 4        | `warning`   |
| 5        | `notice`    |
| 6        | `info`      |
| 7        | `debug`     |

Out-of-range priority values default to `"info"`.

### Collect Behavior

Returns one `api.LogEntry` per journal entry. On reader error, returns `nil, fmt.Errorf("logfwd: journald: %w", err)`. Returns `nil, nil` when no entries are available.

## JournalctlReader

Concrete `JournalReader` implementation for Linux that reads entries by running the `journalctl` subprocess with JSON output.

```go
func NewJournalctlReader() *JournalctlReader
```

Build-tagged `//go:build linux`.

### Availability Probe

```go
func JournalctlAvailable() bool
```

Reports whether `journalctl` is present in `$PATH`. A missing binary is a property of the host rather than a transient failure, so `plexd up` probes once at startup and omits the journald source entirely instead of letting every collect cycle fail with `journalctl not found`.

### Cursor Tracking

On the first call, reads entries from the last 60 seconds (`--since=60 seconds ago`). Subsequent calls use `--after-cursor=<cursor>` to avoid re-reading entries. The cursor is extracted from the `__CURSOR` field of each JSON entry.

### journalctl Invocation

```
journalctl --output=json --no-pager -n 1000 [--since=60 seconds ago | --after-cursor=<cursor>]
```

### JSON Field Parsing

| journalctl JSON Field      | JournalEntry Field | Parsing                                   |
|----------------------------|--------------------|--------------------------------------------|
| `MESSAGE`                  | `Message`          | Direct string                              |
| `_SYSTEMD_UNIT`            | `Unit`             | Direct string                              |
| `PRIORITY`                 | `Priority`         | String → int via `strconv.Atoi`            |
| `__REALTIME_TIMESTAMP`     | `Timestamp`        | Microseconds since epoch → `time.Time`     |
| `__CURSOR`                 | _(internal)_       | Stored for next call                       |

Malformed JSON lines are silently skipped. If timestamp parsing fails, `time.Now()` is used as fallback. Returns error if `journalctl` is not found (`exec.ErrNotFound`).

## FileSource

Reads new lines from log files matching a glob pattern, with offset tracking and rotation detection.

### Constructor

```go
func NewFileSource(pattern, hostname string, logger *slog.Logger) *FileSource
```

| Parameter  | Description                                           |
|------------|-------------------------------------------------------|
| `pattern`  | Glob expression (e.g., `"/var/log/app/*.log"`)       |
| `hostname` | Node hostname included in every log entry             |
| `logger`   | Structured logger (`log/slog`)                        |

### Collect Behavior

1. Expand glob pattern to matching files
2. For each file, check inode and size against tracked state
3. **Rotation detection**: if inode changed or file is smaller than stored offset, reset offset to 0
4. Read new lines from the stored offset using `bufio.Scanner`
5. Lines exceeding 16 KiB are truncated with `[truncated]` suffix
6. Empty lines are skipped
7. Each line produces an `api.LogEntry` with `Source="file"`, `Unit=<filepath>`, `Severity="info"`
8. Update stored offset after reading

### Log Entry Fields

| Field       | Value                                     |
|-------------|-------------------------------------------|
| `Timestamp` | `time.Now()` at read time                |
| `Source`    | `"file"`                                  |
| `Unit`      | Full file path                            |
| `Message`   | Line content (truncated at 16 KiB)       |
| `Severity`  | `"info"` (always)                         |
| `Hostname`  | Set at construction time                  |

### Error Handling

- Glob errors return an error
- Individual file read failures are logged at warn level; other files continue
- Partial results are returned on context cancellation

## LogFilter

The `FilteringSource` wraps a `LogSource` and applies filter rules to its output. The `Forwarder` automatically wraps all sources with `FilteringSource` when `Config.Filter` is non-empty.

### FilterConfig

```go
type FilterConfig struct {
    MinSeverity  string    // Drop entries below this severity level (empty = no filter)
    IncludeUnits []string  // Only pass entries matching these unit names (empty = all)
    ExcludeUnits []string  // Drop entries matching any of these unit names
}
```

Configured via `Config.Filter`:

```go
cfg := logfwd.Config{
    Filter: logfwd.FilterConfig{
        MinSeverity:  "warning",
        IncludeUnits: []string{"plexd.service", "sshd.service"},
        ExcludeUnits: []string{"systemd-resolved.service"},
    },
}
```

### Severity Filtering

Uses syslog priority ordering (lower number = more severe):

| Priority | Severity  | Passes `MinSeverity="warning"`? |
|----------|-----------|---------------------------------|
| 0        | `emerg`   | yes                             |
| 1        | `alert`   | yes                             |
| 2        | `crit`    | yes                             |
| 3        | `err`     | yes                             |
| 4        | `warning` | yes (threshold)                 |
| 5        | `notice`  | no                              |
| 6        | `info`    | no                              |
| 7        | `debug`   | no                              |

Unknown severity values default to `"info"` priority (6).

### Filter Evaluation Order

1. **Severity filter**: if `MinSeverity` is set and entry severity is less severe, drop
2. **Include filter**: if `IncludeUnits` is non-empty and entry unit is not in the list, drop
3. **Exclude filter**: if entry unit matches any `ExcludeUnits`, drop
4. Entry passes all filters → included in output

### Constructor

```go
func NewFilteringSource(inner LogSource, config FilterConfig) *FilteringSource
```

When `FilterConfig.IsEmpty()` returns true (all fields are zero/empty), the filter is a no-op passthrough.

## Forwarder

Orchestrates log collection and reporting via two independent ticker loops.

### Constructor

```go
func NewForwarder(cfg Config, sources []LogSource, reporter LogReporter, nodeID string, hostname string, logger *slog.Logger) *Forwarder
```

| Parameter  | Description                                        |
|------------|----------------------------------------------------|
| `cfg`      | Log forwarding configuration                       |
| `sources`  | Slice of LogSource implementations to run each cycle |
| `reporter` | LogReporter for sending batches to control plane   |
| `nodeID`   | Node identifier included in report requests        |
| `hostname` | Node hostname (passed to sources at construction)  |
| `logger`   | Structured logger (`log/slog`)                     |

### RegisterSource

```go
func (f *Forwarder) RegisterSource(s LogSource)
```

Adds a log source after construction. Must be called before `Run`; not safe for concurrent use.

### Run Method

```go
func (f *Forwarder) Run(ctx context.Context) error
```

Blocks until the context is cancelled. Returns `ctx.Err()` on cancellation.

### Lifecycle

```go
journalSrc := logfwd.NewJournaldSource(journalReader, hostname, logger)

fwd := logfwd.NewForwarder(cfg, []logfwd.LogSource{journalSrc}, controlPlane, nodeID, hostname, logger)

// Blocks until ctx is cancelled
err := fwd.Run(ctx)
// err == context.Canceled (normal shutdown)
```

### Run Sequence

1. If `Enabled=false`: log info, return nil immediately
2. Run an immediate first collection cycle
3. Start collect ticker (`CollectInterval`) and report ticker (`ReportInterval`)
4. On collect tick: call each source's `Collect` with panic recovery, append results to mutex-protected buffer, log errors per-source but continue
5. On report tick: swap buffer under lock, send via `ReportLogs` in chunks of `BatchSize`, log errors but continue
6. On context cancellation: best-effort flush of remaining buffer using `context.Background()`, return `ctx.Err()`

### Buffer Management

- Collected `LogEntry` values are appended to an internal buffer protected by `sync.Mutex`
- Buffer capacity is bounded at `2 * BatchSize` entries
- When the buffer exceeds capacity, the oldest entries are dropped and a warning is logged with the count of dropped entries
- On report tick, the buffer is swapped out atomically (lock, copy reference, set to nil, unlock)
- Empty buffers skip the report call entirely
- Large batches are split into multiple API calls of at most `BatchSize` entries each
- On reporter error, unsent entries are retained in the buffer for the next report cycle
- On shutdown, remaining buffered entries are flushed with a background context

## API Contract

### POST /v1/nodes/{node_id}/logs

The control-plane leg of the pipeline (`PlatformReporter`) converts each buffered
`LogEntry` into a wire `api.LogLine` and POSTs the batch as **NDJSON** — one JSON
object per line (`Content-Type: application/x-ndjson`). The request stamps an
`X-Plexsphere-Sent-At` header (RFC 3339, nanosecond precision, UTC) and is
gzip-compressed when the body exceeds 1 KiB. Success is `202 Accepted` with an
`IngestReceipt`.

**Request body** (NDJSON of `api.LogLine`):

```
{"severity":"info","unit":"plexd.service","hostname":"node-01.example.com","message":"tunnel established with peer-abc-123","timestamp":"2026-02-12T10:30:00Z"}
{"severity":"warning","unit":"sshd.service","hostname":"node-01.example.com","message":"Failed password for root from 192.168.1.100","timestamp":"2026-02-12T10:30:01Z"}
```

**LogLine fields:**

| Field       | Type        | JSON Tag             | Description                                   |
|-------------|-------------|----------------------|-----------------------------------------------|
| `Severity`  | `string`    | `"severity"`         | Syslog severity (see the accepted set below)  |
| `Unit`      | `string`    | `"unit,omitempty"`   | Systemd unit; omitted when unknown            |
| `Hostname`  | `string`    | `"hostname,omitempty"`| Origin hostname; omitted when unknown        |
| `Message`   | `string`    | `"message"`          | Log message (non-empty)                       |
| `Timestamp` | `time.Time` | `"timestamp"`        | Entry time (RFC 3339)                         |

The internal `LogEntry.Source` field has no wire counterpart and is dropped.

**Accepted severities** (closed set): `emerg`, `alert`, `crit`, `err`, `warning`,
`notice`, `info`, `debug`.

#### Conversion and skip rules

`PlatformReporter` applies these rules before sending:

- An entry with an **empty message** is skipped with a Debug log (the contract
  requires a non-empty message and would reject the whole batch otherwise).
- A `severity` **outside the accepted set** is coerced to `info` (defensive; no
  current producer emits one).
- When no lines survive, the client is not called (the ingest contract rejects an
  empty array).

#### Response — IngestReceipt (`202 Accepted`)

```json
{ "accepted_at": "2026-02-12T10:30:00.123456789Z", "records": 2 }
```

| Field        | Type        | JSON Tag        | Description                                  |
|--------------|-------------|-----------------|----------------------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | When the control plane accepted the batch    |
| `Records`    | `int`       | `"records"`     | Number of records accepted from the batch    |

#### Ingest errors

| Status | Problem `code` | Meaning | `PlatformReporter` reaction |
|--------|----------------|---------|-----------------------------|
| `400 Bad Request` | `ingest_batch_malformed` | Body has no non-blank lines, an undecodable line, or a record with an out-of-set `severity`, empty `message`, or zero `timestamp` | Drops the batch — a verdict on the bytes, which no retry changes |
| `400 Bad Request` | `ingest_sent_at_invalid` | `X-Plexsphere-Sent-At` is missing or not an RFC 3339 timestamp | Returned for retry — the header is re-stamped on every attempt, so it clears once the node's clock converges |
| `413 Payload Too Large` | — | Batch exceeds the server-side size limit | Halves the batch and re-sends each half; a single line still refused is dropped |
| `415 Unsupported Media Type` | `ingest_encoding_unsupported` | `Content-Encoding` is neither `gzip` nor `identity` | Returned for retry — a property of the deployment, not of the batch |
| `501 Not Implemented` | `observability_ingest_not_provisioned` | Observability ingest is not provisioned | Drops the batch quietly (a one-time Info log on the transition, another on recovery) rather than re-buffering it |

Any other error is returned to `Forwarder.flush`, which retains and retries the
batch.

Every line the reporter discards — a skipped entry, a dropped batch, a line over
the size limit — is added to a running count that is summarized in a `dropping
log lines` Warn at most once every five minutes. `Forwarder.flush` takes its
success path for a dropped batch, so this log is the only signal that log lines
are being lost.

### Internal / local-endpoint format: LogEntry

The in-memory buffer and the optional [local endpoint](#local-endpoint)
(`LocalReporter`) keep the `LogEntry` shape; only the control-plane leg converts
to `LogLine`.

**Example body** (`api.LogBatch = []api.LogEntry`):

```json
[
  {
    "timestamp": "2026-02-12T10:30:00Z",
    "source": "journald",
    "unit": "plexd.service",
    "message": "tunnel established with peer-abc-123",
    "severity": "info",
    "hostname": "node-01.example.com"
  },
  {
    "timestamp": "2026-02-12T10:30:01Z",
    "source": "journald",
    "unit": "sshd.service",
    "message": "Failed password for root from 192.168.1.100",
    "severity": "warning",
    "hostname": "node-01.example.com"
  }
]
```

#### LogEntry Schema

```go
type LogEntry struct {
    Timestamp time.Time `json:"timestamp"`
    Source    string    `json:"source"`
    Unit     string    `json:"unit"`
    Message  string    `json:"message"`
    Severity string    `json:"severity"`
    Hostname string    `json:"hostname"`
}
```

| Field       | Type        | Description                                              |
|-------------|-------------|----------------------------------------------------------|
| `Timestamp` | `time.Time` | When the log entry was recorded (RFC 3339)              |
| `Source`    | `string`    | Log source identifier (e.g. `"journald"`)               |
| `Unit`      | `string`    | Systemd unit name (empty if not from a unit)            |
| `Message`   | `string`    | Log message content                                      |
| `Severity`  | `string`    | Syslog severity string (see priority mapping table)     |
| `Hostname`  | `string`    | Originating node hostname                                |

## Error Handling

| Scenario                        | Behavior                                                     |
|---------------------------------|--------------------------------------------------------------|
| Source returns error            | Log warn, skip source, continue with others                  |
| Source panics                   | Recover panic, log error, continue with other sources        |
| Reporter returns error          | Log warn, retain unsent entries in buffer, retry next cycle  |
| All sources fail                | Empty buffer, report tick is a no-op                         |
| Buffer exceeds capacity         | Drop oldest entries, log warn with dropped count             |
| Context cancelled (shutdown)    | Best-effort flush, return `ctx.Err()`                        |
| Log forwarding disabled         | Return nil immediately, no goroutines started                |

## Logging

All log entries use `component=logfwd`.

| Level  | Event                              | Keys                        |
|--------|------------------------------------|-----------------------------|
| `Info` | Log forwarding disabled            | `component`                 |
| `Warn` | Source failed                      | `component`, `error`        |
| `Warn` | Log report failed                  | `component`, `error`        |
| `Warn` | Buffer overflow, dropping entries  | `component`, `dropped`      |
| `Warn` | Using cached credential            | `component`, `error`        |
| `Warn` | Local log report failed            | `component`, `error`        |
| `Info` | Local endpoint enabled             | `pipeline`, `url`           |

## Integration Points

### With api.ControlPlane

`api.ControlPlane` is the control-plane ingest client; the `Forwarder` reaches it
through a `PlatformReporter`, which converts each batch to `[]api.LogLine` and
posts it via the client:

```go
controlPlane, _ := api.NewControlPlane(apiCfg, "1.0.0", logger)

// PlatformReporter is the control-plane leg; controlPlane satisfies its IngestClient seam.
reporter := logfwd.NewPlatformReporter(controlPlane, logger)
fwd := logfwd.NewForwarder(cfg, sources, reporter, nodeID, hostname, logger)
fwd.Run(ctx)
```

### With LocalReporter and MultiReporter

When `LocalEndpoint.URL` is configured, the `Forwarder` receives a `MultiReporter` that wraps both the `PlatformReporter` and a `LocalReporter`:

```go
var logReporter logfwd.LogReporter = logfwd.NewPlatformReporter(controlPlane, logger)
if cfg.LogFwd.LocalEndpoint.URL != "" {
    localReporter := logfwd.NewLocalReporter(cfg.LogFwd.LocalEndpoint, controlPlane, nsk, identity.NodeID, logger)
    logReporter = logfwd.NewMultiReporter(logReporter, localReporter, logger)
    logger.Info("local endpoint enabled", "pipeline", "logfwd", "url", cfg.LogFwd.LocalEndpoint.URL)
}
fwd := logfwd.NewForwarder(cfg.LogFwd, sources, logReporter, identity.NodeID, hostname, logger)
```

When `LocalEndpoint.URL` is empty, no `MultiReporter` is created and behavior is identical to the single-reporter pipeline.

### Integration Tests

See [Local Endpoint Integration Tests](../development/local-endpoint-integration-tests.md) for the full integration test suite covering dual delivery, error isolation, credential resolution, and TLS skip-verify across all three pipelines.
