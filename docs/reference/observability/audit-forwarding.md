---
title: Audit Forwarding
package: internal/auditfwd
feature: PXD-0018
---

# Audit Forwarding

The `internal/auditfwd` package collects and forwards audit data from plexd mesh nodes to the control plane via `POST /v1/nodes/{node_id}/audit`. On Linux nodes it integrates with auditd; on Kubernetes it collects Kubernetes audit logs. All audit sources are abstracted behind injectable interfaces for testability.

The `Forwarder` runs two independent ticker loops in a single goroutine: one for collection and one for reporting. Collected audit entries are buffered in memory and flushed to the control plane at the configured report interval.

## Collection Sources and Format

- **auditd:** plexd opens a Netlink socket (`AF_AUDIT`) to receive real-time audit events from the Linux kernel. This avoids file-based polling and ensures no events are missed.
- **Kubernetes:** plexd tails the Kubernetes audit log file, auto-detected via the kubelet configuration (typically `/var/log/kubernetes/audit/audit.log`). The path can be overridden in the config.

All audit events are normalized into a unified JSON schema:

```json
{
  "timestamp": "2025-01-15T10:30:00.456Z",
  "source": "auditd",
  "event_type": "SYSCALL",
  "subject": { "uid": 1000, "pid": 4523, "comm": "sshd" },
  "object": { "path": "/etc/shadow" },
  "action": "open",
  "result": "denied",
  "hostname": "web-01",
  "raw": "..."
}
```

Delivery follows the same batch model as log forwarding: **batch POST** (JSON Lines, gzip-compressed) at `report_interval` (default 15s) with its own independent buffer for offline operation.

## Config

`Config` holds audit forwarding parameters.

| Field             | Type            | Default | Description                                    |
|-------------------|-----------------|---------|------------------------------------------------|
| `Enabled`         | `bool`          | `true`  | Whether audit forwarding is active             |
| `CollectInterval` | `time.Duration` | `5s`    | Interval between collection cycles (min 1s)    |
| `ReportInterval`  | `time.Duration` | `15s`   | Interval between reporting to control plane    |
| `BatchSize`       | `int`           | `500`   | Maximum audit entries per report batch (min 1) |
| `LocalEndpoint`   | `api.LocalEndpointConfig` | _(zero)_ | Optional local endpoint for dual-destination delivery (see below) |

```go
cfg := auditfwd.Config{}
cfg.ApplyDefaults() // Enabled=true, CollectInterval=5s, ReportInterval=15s, BatchSize=500
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

`ApplyDefaults` sets `Enabled=true` on a zero-valued Config. To disable audit forwarding, set `Enabled=false` after calling `ApplyDefaults`.

### Validation Rules

| Field             | Rule                 | Error Message                                                 |
|-------------------|----------------------|---------------------------------------------------------------|
| `CollectInterval` | >= 1s                | `auditfwd: config: CollectInterval must be at least 1s`       |
| `ReportInterval`  | >= `CollectInterval` | `auditfwd: config: ReportInterval must be >= CollectInterval` |
| `BatchSize`       | >= 1                 | `auditfwd: config: BatchSize must be at least 1`              |

When `Enabled=false`, validation is skipped entirely (including `LocalEndpoint` validation).

### Local Endpoint

`LocalEndpoint` allows audit data to be sent to an additional local endpoint alongside the control plane. The type is `api.LocalEndpointConfig`, defined once in `internal/api/types.go` and shared across all three observability pipelines.

| Field                    | Type     | YAML Key                     | Description                                        |
|--------------------------|----------|------------------------------|----------------------------------------------------|
| `URL`                    | `string` | `local_endpoint.url`         | HTTPS endpoint URL. Empty means not configured.    |
| `SecretKey`              | `string` | `local_endpoint.secret_key`  | Auth credential. Required when URL is set. Redacted in config dumps. |
| `TLSInsecureSkipVerify`  | `bool`   | `local_endpoint.tls_insecure_skip_verify` | Disable TLS certificate verification. |

**Validation rules** (applied only when `Enabled=true` and `URL` is non-empty):

| Rule                       | Error Message                                                        |
|----------------------------|----------------------------------------------------------------------|
| URL must be parseable      | `auditfwd: config: local_endpoint: invalid URL "<url>"`              |
| Scheme must be `https`     | `auditfwd: config: local_endpoint: URL must be HTTPS, got "<scheme>"`|
| SecretKey must be non-empty| `auditfwd: config: local_endpoint: SecretKey is required when URL is set` |

A zero-valued `LocalEndpointConfig` (all fields empty/false) is valid and means "not configured".

```yaml
audit_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 15s
  batch_size: 500
  local_endpoint:
    url: https://audit.local:9090/ingest
    secret_key: local-audit-token
    tls_insecure_skip_verify: false
```

## AuditSource

Interface for subsystem-specific audit collection. Each source returns a slice of `api.AuditEntry`.

```go
type AuditSource interface {
    Collect(ctx context.Context) ([]api.AuditEntry, error)
}
```

## AuditReporter

Interface abstracting the control plane audit reporting API. Satisfied by `api.ControlPlane`.

```go
type AuditReporter interface {
    ReportAudit(ctx context.Context, nodeID string, batch api.AuditBatch) error
}
```

## LocalReporter

`LocalReporter` implements `AuditReporter` by POSTing audit batches to a locally-configured HTTPS endpoint with bearer-token authentication. It operates independently from the control plane client—with its own `http.Client`, TLS settings, and credential cache.

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
    FetchSecret(ctx context.Context, nodeID, key string) (*api.SecretResponse, error)
}
```

Defined in the `auditfwd` package. The `api.ControlPlane` client satisfies this interface.

### HTTP Client

| Setting | Value | Notes |
|---------|-------|-------|
| Timeout | 10s | Per-request timeout |
| TLS | Configurable | `TLSInsecureSkipVerify` controls certificate validation for this client only |
| Compression | None | Batches are sent as uncompressed JSON |

### Credential Resolution

Same flow as `metrics.LocalReporter`: check cache (5-minute TTL) → `FetchSecret` → `DecryptSecret` → update cache. Falls back to stale cached token on fetch/decrypt failure. Protected by `sync.RWMutex` with double-checked locking.

### ReportAudit Behavior

```go
func (r *LocalReporter) ReportAudit(ctx context.Context, nodeID string, batch api.AuditBatch) error
```

1. Resolve bearer token
2. JSON-marshal the `AuditBatch`—`Subject` and `Object` fields (`json.RawMessage`) are preserved unchanged through serialization
3. `POST` to `cfg.URL` with `Content-Type: application/json` and `Authorization: Bearer {token}`
4. Return `nil` on 2xx; return error containing the status code on non-2xx

## MultiReporter

`MultiReporter` implements `AuditReporter` by dispatching to both a platform and a local reporter concurrently.

### Constructor

```go
func NewMultiReporter(platform, local AuditReporter, logger *slog.Logger) *MultiReporter
```

### Error Semantics

| Platform result | Local result | Return value | Side effect |
|-----------------|--------------|--------------|-------------|
| success | success | `nil` | — |
| error | success | platform error | — |
| success | error | `nil` | Local error logged as warning |
| error | error | platform error | Local error logged as warning |

Only the platform error is returned. The `Forwarder` uses the return value for retry/retain decisions—local failures must not trigger batch retention. The `Forwarder.Status()` method reflects platform-level error counts only, not local.

## AuditdReader

Interface abstracting Linux auditd access for testability.

```go
type AuditdReader interface {
    ReadEvents(ctx context.Context) ([]AuditdEntry, error)
}
```

### AuditdEntry

```go
type AuditdEntry struct {
    Timestamp time.Time
    Type      string
    UID       int
    GID       int
    PID       int
    Syscall   string
    Object    string
    Path      string
    Success   bool
    Raw       string
}
```

## AuditdSource

Collects audit entries from the Linux audit subsystem via an injectable `AuditdReader`.

### Constructor

```go
func NewAuditdSource(reader AuditdReader, hostname string, logger *slog.Logger) *AuditdSource
```

| Parameter  | Description                                          |
|------------|------------------------------------------------------|
| `reader`   | AuditdReader implementation for reading events       |
| `hostname` | Node hostname included in every audit entry          |
| `logger`   | Structured logger (`log/slog`)                       |

### Field Mapping

| AuditdEntry Field   | AuditEntry Field | Description                                                    |
|----------------------|------------------|----------------------------------------------------------------|
| `Type`               | `EventType`      | Audit event type (e.g. `SYSCALL`, `USER_AUTH`)                |
| `UID`, `GID`, `PID`  | `Subject`        | JSON object `{"uid":1000,"gid":1000,"pid":4321}`              |
| `Object`             | `Object`         | JSON-marshalled string (e.g. `"/etc/passwd"`)                 |
| `Syscall`            | `Action`         | Syscall name; falls back to `Type` if empty                   |
| `Success`            | `Result`         | Mapped to `"success"` (true) or `"failure"` (false)           |
| `Raw`                | `Raw`            | Original raw audit line                                        |
| `Timestamp`          | `Timestamp`      | Entry timestamp                                                |
| _(constant)_         | `Source`         | Always `"auditd"`                                              |
| _(constructor)_      | `Hostname`       | Set at construction time                                       |

### Collect Behavior

Returns one `api.AuditEntry` per auditd entry. `Subject` is serialized as a `json.RawMessage` containing a structured JSON object with `uid`, `gid`, and `pid` fields. `Object` is serialized as a `json.RawMessage` containing a JSON-encoded string. `Action` uses the `Syscall` field, falling back to `Type` when `Syscall` is empty. `Result` maps `Success=true` to `"success"` and `Success=false` to `"failure"`. On reader error, returns `nil, fmt.Errorf("auditfwd: auditd: %w", err)`. Returns `nil, nil` when no entries are available.

## K8sAuditReader

Interface abstracting Kubernetes audit log access for testability.

```go
type K8sAuditReader interface {
    ReadEvents(ctx context.Context) ([]K8sAuditEntry, error)
}
```

### K8sUser

```go
type K8sUser struct {
    Username string   `json:"username"`
    Groups   []string `json:"groups,omitempty"`
}
```

### K8sObjectRef

```go
type K8sObjectRef struct {
    Resource  string `json:"resource"`
    Namespace string `json:"namespace,omitempty"`
    Name      string `json:"name,omitempty"`
}
```

### K8sAuditEntry

```go
type K8sAuditEntry struct {
    Timestamp      time.Time
    Verb           string
    User           K8sUser
    ObjectRef      K8sObjectRef
    RequestURI     string
    ResponseStatus int
    Raw            string
}
```

## K8sAuditSource

Collects audit entries from Kubernetes audit logs via an injectable `K8sAuditReader`.

### Constructor

```go
func NewK8sAuditSource(reader K8sAuditReader, hostname string, logger *slog.Logger) *K8sAuditSource
```

| Parameter  | Description                                          |
|------------|------------------------------------------------------|
| `reader`   | K8sAuditReader implementation for reading events     |
| `hostname` | Node hostname included in every audit entry          |
| `logger`   | Structured logger (`log/slog`)                       |

### Field Mapping

| K8sAuditEntry Field           | AuditEntry Field | Description                                                    |
|-------------------------------|------------------|----------------------------------------------------------------|
| `Verb`                        | `EventType`      | Kubernetes API verb (e.g. `"create"`, `"delete"`)              |
| `User`                        | `Subject`        | JSON object with `username` and `groups` fields                |
| `ObjectRef.Namespace/Resource/Name` | `Object`  | JSON-marshalled formatted string (see below)                   |
| `Verb`                        | `Action`         | Same as EventType                                              |
| `ResponseStatus`              | `Result`         | Mapped: 2xx -> `"success"`, non-2xx -> `"failure"`             |
| `Raw`                         | `Raw`            | Original raw audit event JSON                                  |
| `Timestamp`                   | `Timestamp`      | Entry timestamp                                                |
| _(constant)_                  | `Source`         | Always `"k8s-audit"`                                           |
| _(constructor)_               | `Hostname`       | Set at construction time                                       |

### Object Reference Formatting

The `Object` field is built from `ObjectRef.Namespace`, `ObjectRef.Resource`, and `ObjectRef.Name`:

| Namespace | Resource | Name    | Formatted Object              |
|-----------|----------|---------|-------------------------------|
| `prod`    | `pods`   | `web-1` | `"prod/pods/web-1"`           |
| _(empty)_ | `nodes`  | _(empty)_ | `"nodes"`                   |
| `default` | `configmaps` | `cfg` | `"default/configmaps/cfg"` |

### Collect Behavior

Returns one `api.AuditEntry` per K8s audit entry. `Subject` is serialized as a `json.RawMessage` containing a JSON object with `username` and optional `groups` fields. `Object` is serialized as a `json.RawMessage` containing a JSON-encoded formatted string. `Result` maps HTTP status codes: 2xx (200-299) to `"success"`, all other codes to `"failure"`. On reader error, returns `nil, fmt.Errorf("auditfwd: k8s-audit: %w", err)`. Returns `nil, nil` when no entries are available.

## Forwarder

Orchestrates audit data collection and reporting via two independent ticker loops.

### Constructor

```go
func NewForwarder(cfg Config, sources []AuditSource, reporter AuditReporter, nodeID string, hostname string, logger *slog.Logger) *Forwarder
```

| Parameter  | Description                                          |
|------------|------------------------------------------------------|
| `cfg`      | Audit forwarding configuration                       |
| `sources`  | Slice of AuditSource implementations to run each cycle |
| `reporter` | AuditReporter for sending batches to control plane   |
| `nodeID`   | Node identifier included in report requests          |
| `hostname` | Node hostname (passed to sources at construction)    |
| `logger`   | Structured logger (`log/slog`)                       |

### RegisterSource

```go
func (f *Forwarder) RegisterSource(s AuditSource)
```

Adds an audit source after construction. Must be called before `Run`; not safe for concurrent use.

### Run Method

```go
func (f *Forwarder) Run(ctx context.Context) error
```

Blocks until the context is cancelled. Returns `ctx.Err()` on cancellation.

### Lifecycle

```go
auditdSrc := auditfwd.NewAuditdSource(auditdReader, hostname, logger)
k8sSrc := auditfwd.NewK8sAuditSource(k8sReader, hostname, logger)

fwd := auditfwd.NewForwarder(cfg, []auditfwd.AuditSource{auditdSrc, k8sSrc}, controlPlane, nodeID, hostname, logger)

// Blocks until ctx is cancelled
err := fwd.Run(ctx)
// err == context.Canceled (normal shutdown)
```

### Run Sequence

1. If `Enabled=false`: log info, return nil immediately
2. Run an immediate first collection cycle
3. Start collect ticker (`CollectInterval`) and report ticker (`ReportInterval`)
4. On collect tick: call each source's `Collect` with panic recovery, append results to mutex-protected buffer, log errors per-source but continue
5. On report tick: swap buffer under lock, send via `ReportAudit` in chunks of `BatchSize`, log errors but continue
6. On context cancellation: best-effort flush of remaining buffer using `context.Background()`, return `ctx.Err()`

### Buffer Management

- Collected `AuditEntry` values are appended to an internal buffer protected by `sync.Mutex`
- Buffer capacity is bounded at `bufferCapacityMultiplier * BatchSize` entries (multiplier = 2)
- When the buffer exceeds capacity, the oldest entries are dropped and a warning is logged with the count of dropped entries
- On report tick, the buffer is swapped out atomically (lock, copy reference, set to nil, unlock)
- Empty buffers skip the report call entirely
- Large batches are split into multiple API calls of at most `BatchSize` entries each
- On reporter error, unsent entries are retained in the buffer for the next report cycle
- On shutdown, remaining buffered entries are flushed with a background context

## API Contract

### POST /v1/nodes/{node_id}/audit

Reports a batch of audit entries to the control plane.

**Request body** (`api.AuditBatch = []api.AuditEntry`):

```json
[
  {
    "timestamp": "2026-02-12T10:30:00Z",
    "source": "auditd",
    "event_type": "SYSCALL",
    "subject": {"uid": 1000, "gid": 1000, "pid": 4321},
    "object": "/etc/passwd",
    "action": "open",
    "result": "success",
    "hostname": "node-01.example.com",
    "raw": "type=SYSCALL msg=audit(1718452800.000:100): arch=c000003e syscall=2"
  },
  {
    "timestamp": "2026-02-12T10:30:01Z",
    "source": "k8s-audit",
    "event_type": "create",
    "subject": {"username": "system:serviceaccount:default:deployer", "groups": ["system:serviceaccounts"]},
    "object": "production/pods/web-abc123",
    "action": "create",
    "result": "success",
    "hostname": "k8s-node-01.example.com",
    "raw": "{\"apiVersion\":\"audit.k8s.io/v1\",\"kind\":\"Event\"}"
  }
]
```

### AuditEntry Schema

```go
type AuditEntry struct {
    Timestamp time.Time       `json:"timestamp"`
    Source    string          `json:"source"`
    EventType string          `json:"event_type"`
    Subject   json.RawMessage `json:"subject"`
    Object    json.RawMessage `json:"object"`
    Action    string          `json:"action"`
    Result    string          `json:"result"`
    Hostname  string          `json:"hostname"`
    Raw       string          `json:"raw"`
}
```

| Field       | Type              | Description                                                    |
|-------------|-------------------|----------------------------------------------------------------|
| `Timestamp` | `time.Time`       | When the audit event was recorded (RFC 3339)                  |
| `Source`    | `string`          | Audit source identifier (`"auditd"` or `"k8s-audit"`)        |
| `EventType` | `string`          | Event type (auditd type or K8s verb)                          |
| `Subject`   | `json.RawMessage` | Who performed the action (structured JSON object)             |
| `Object`    | `json.RawMessage` | What was acted upon (JSON-encoded string)                     |
| `Action`    | `string`          | Action performed (syscall/type fallback or K8s verb)          |
| `Result`    | `string`          | Outcome: `"success"` or `"failure"`                           |
| `Hostname`  | `string`          | Originating node hostname                                      |
| `Raw`       | `string`          | Original raw audit record                                      |

## Error Handling

| Scenario                        | Behavior                                                       |
|---------------------------------|----------------------------------------------------------------|
| Source returns error            | Log warn, skip source, continue with others                    |
| Source panics                   | Recover panic, log error, continue with other sources          |
| Reporter returns error          | Log warn, retain unsent entries in buffer, retry next cycle    |
| All sources fail                | Empty buffer, report tick is a no-op                           |
| Buffer exceeds capacity         | Drop oldest entries, log warn with dropped count               |
| Context cancelled (shutdown)    | Best-effort flush, return `ctx.Err()`                          |
| Audit forwarding disabled       | Return nil immediately, no goroutines started                  |

## Logging

All log entries use `component=auditfwd`.

| Level  | Event                              | Keys                        |
|--------|------------------------------------|-----------------------------|
| `Info` | Audit forwarding disabled          | `component`                 |
| `Warn` | Source failed                      | `component`, `error`        |
| `Warn` | Audit report failed                | `component`, `error`        |
| `Warn` | Buffer overflow, dropping entries  | `component`, `dropped`      |
| `Warn` | Using stale cached credential      | `component`, `error`        |
| `Warn` | Local audit report failed          | `component`, `error`        |
| `Info` | Local endpoint enabled             | `pipeline`, `url`           |

## Integration Points

### With api.ControlPlane

`api.ControlPlane` satisfies the `AuditReporter` interface directly:

```go
controlPlane, _ := api.NewControlPlane(apiCfg, "1.0.0", logger)

// controlPlane.ReportAudit matches AuditReporter.ReportAudit
fwd := auditfwd.NewForwarder(cfg, sources, controlPlane, nodeID, hostname, logger)
fwd.Run(ctx)
```

### With LocalReporter and MultiReporter

When `LocalEndpoint.URL` is configured, the `Forwarder` receives a `MultiReporter` instead of the control plane client directly:

```go
var auditReporter auditfwd.AuditReporter = controlPlane
if cfg.AuditFwd.LocalEndpoint.URL != "" {
    localReporter := auditfwd.NewLocalReporter(cfg.AuditFwd.LocalEndpoint, controlPlane, nsk, identity.NodeID, logger)
    auditReporter = auditfwd.NewMultiReporter(controlPlane, localReporter, logger)
    logger.Info("local endpoint enabled", "pipeline", "auditfwd", "url", cfg.AuditFwd.LocalEndpoint.URL)
}
fwd := auditfwd.NewForwarder(cfg.AuditFwd, sources, auditReporter, identity.NodeID, hostname, logger)
```

When `LocalEndpoint.URL` is empty, no `MultiReporter` is created and behavior is identical to the single-reporter pipeline.
