---
title: Log Forwarding
quadrant: backend
package: internal/logfwd
feature: PXD-0017
---

# Log Forwarding

The `internal/logfwd` package forwards system and application logs from plexd mesh nodes to the control plane via `POST /v1/nodes/{node_id}/logs`. All log sources are abstracted behind injectable interfaces for testability.

The `Forwarder` runs two independent ticker loops in a single goroutine: one for collection and one for reporting. Collected log entries are buffered in memory and flushed to the control plane at the configured report interval.

## Config

`Config` holds log forwarding parameters.

| Field             | Type            | Default | Description                                    |
|-------------------|-----------------|---------|------------------------------------------------|
| `Enabled`         | `bool`          | `true`  | Whether log forwarding is active               |
| `CollectInterval` | `time.Duration` | `10s`   | Interval between collection cycles (min 5s)    |
| `ReportInterval`  | `time.Duration` | `30s`   | Interval between reporting to control plane    |
| `BatchSize`       | `int`           | `200`   | Maximum log entries per report batch (min 1)   |

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

When `Enabled=false`, validation is skipped entirely.

## LogSource

Interface for subsystem-specific log collection. Each source returns a slice of `api.LogEntry`.

```go
type LogSource interface {
    Collect(ctx context.Context) ([]api.LogEntry, error)
}
```

## LogReporter

Interface abstracting the control plane log reporting API. Satisfied by `api.ControlPlane`.

```go
type LogReporter interface {
    ReportLogs(ctx context.Context, nodeID string, batch api.LogBatch) error
}
```

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

Reports a batch of log entries to the control plane.

**Request body** (`api.LogBatch = []api.LogEntry`):

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

### LogEntry Schema

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

## Integration Points

### With api.ControlPlane

`api.ControlPlane` satisfies the `LogReporter` interface directly:

```go
controlPlane, _ := api.NewControlPlane(apiCfg, "1.0.0", logger)

// controlPlane.ReportLogs matches LogReporter.ReportLogs
fwd := logfwd.NewForwarder(cfg, sources, controlPlane, nodeID, hostname, logger)
fwd.Run(ctx)
```
