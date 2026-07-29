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

> For a step-by-step setup guide, see [Setting Up Local Endpoint Delivery](../../how-to/local-endpoint-setup.md).

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

Interface abstracting the audit reporting API. It is satisfied by the package's
`PlatformReporter` (the control-plane leg, which converts each batch to
`[]api.AuditEvent` and posts it through the package's `IngestClient` seam — which
`api.ControlPlane` satisfies), `LocalReporter` (the local leg), and
`MultiReporter` (both).

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
    FetchSecret(ctx context.Context, nodeID, name string, version int) (*api.SecretEnvelope, error)
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

The control-plane leg of the pipeline (`PlatformReporter`) converts each buffered
`AuditEntry` into a wire `api.AuditEvent` and POSTs the batch as **NDJSON** — one
JSON object per line (`Content-Type: application/x-ndjson`). The request stamps
an `X-Plexsphere-Sent-At` header (RFC 3339, nanosecond precision, UTC) and is
gzip-compressed when the body exceeds 1 KiB. Success is `202 Accepted` with an
`IngestReceipt`.

**Request body** (NDJSON of `api.AuditEvent`):

```
{"source":"auditd","action":"open","outcome":"failure","timestamp":"2026-02-12T10:30:00Z"}
{"source":"k8s","action":"create","outcome":"success","timestamp":"2026-02-12T10:30:01Z"}
```

**AuditEvent fields:**

| Field       | Type        | JSON Tag      | Description                                    |
|-------------|-------------|---------------|-----------------------------------------------|
| `Source`    | `string`    | `"source"`    | Wire source, closed set: `auditd` or `k8s`    |
| `Action`    | `string`    | `"action"`    | Action performed (non-empty)                  |
| `Outcome`   | `string`    | `"outcome"`   | Outcome, taken from the entry's `Result` (non-empty) |
| `Timestamp` | `time.Time` | `"timestamp"` | Event time (RFC 3339)                         |

The internal `event_type`, `subject`, `object`, `hostname`, and `raw` fields have
no wire counterpart and are dropped.

> **The platform leg is a source/action/outcome stream, not a full audit trail.**
> `AuditEvent` carries no actor and no target, so the control plane records
> *that* an `open` failed on a node at a time — not which uid, pid, process, or
> path. Two denied opens on different files collapse into indistinguishable
> records upstream. Incident attribution and correlation therefore need the full
> `AuditEntry`, which only reaches the [local endpoint](#localreporter);
> configure `local_endpoint` on every node whose audit trail has to support it.

#### Source mapping and skip rules

`PlatformReporter` maps the internal source to the wire source and drops entries
that fall outside the contract:

| Internal `source` | Wire `source` |
|-------------------|---------------|
| `auditd`    | `auditd` |
| `k8s-audit` | `k8s`    |
| `process`   | *(none — skipped)* |

The wire enum is closed at `auditd` and `k8s`. A record naming anything else
does not fail on its own line: it refuses the **whole batch** with
`400 ingest_batch_malformed`, taking every valid record with it.

plexd's own `process_start` entry therefore has no platform representation. It
used to travel under a `plexd` source the contract has never defined, which
refused every batch it appeared in — and since `ProcessSource` is the only audit
source `plexd up` wires, that was every batch. The entry still reaches a
configured `local_endpoint`, which carries plexd's own richer entry shape rather
than the platform's four wire fields.

::: warning No platform audit traffic by default
With only `ProcessSource` wired, the platform leg of audit forwarding carries
nothing at all. Restoring it needs either a contract-legal source on the agent
(an `auditd` or Kubernetes audit reader — both source types exist in this
package but nothing constructs them in `plexd up`) or a `plexd` value added to
the platform's audit source enum.
:::

- An entry whose source is **not** in the table above is skipped with a Warn log.
- An entry with an **empty action or result** is skipped with a Debug log (the
  contract requires both non-empty and would reject the whole batch otherwise).
- When no events survive, the client is not called (the ingest contract rejects an
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
| `400 Bad Request` | `ingest_batch_malformed` | Body has no non-blank lines, an undecodable line, or a record with an out-of-set `source`, empty `action`, empty `outcome`, or zero `timestamp` | Drops the batch — a verdict on the bytes, which no retry changes |
| `400 Bad Request` | `ingest_sent_at_invalid` | `X-Plexsphere-Sent-At` is missing or not an RFC 3339 timestamp | Returned for retry — the header is re-stamped on every attempt, so it clears once the node's clock converges |
| `413 Payload Too Large` | — | Batch exceeds the server-side size limit | Halves the batch and re-sends each half; a single event still refused is dropped |
| `415 Unsupported Media Type` | `ingest_encoding_unsupported` | `Content-Encoding` is neither `gzip` nor `identity` | Returned for retry — a property of the deployment, not of the batch |
| `501 Not Implemented` | `observability_ingest_not_provisioned` | Observability ingest is not provisioned | Drops the batch quietly (a one-time Info log on the transition, another on recovery) rather than re-buffering it |

Any other error is returned to `Forwarder.flush`, which retains and retries the
batch.

Every record the reporter discards — an entry whose source is outside the
contract, a dropped batch, an event over the size limit — is added to a running
count that is summarized in a `dropping audit records` Warn at most once every
five minutes. `Forwarder.flush` takes its success path for a dropped batch, so
this log is the only signal that the audit trail is incomplete.

### Internal / local-endpoint format: AuditEntry

The in-memory buffer and the optional [local endpoint](#local-endpoint)
(`LocalReporter`) keep the richer `AuditEntry` shape; only the control-plane leg
converts to `AuditEvent`.

**Example body** (`api.AuditBatch = []api.AuditEntry`):

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

#### AuditEntry Schema

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

`api.ControlPlane` is the control-plane ingest client; the `Forwarder` reaches it
through a `PlatformReporter`, which converts each batch to `[]api.AuditEvent` and
posts it via the client:

```go
controlPlane, _ := api.NewControlPlane(apiCfg, "1.0.0", logger)

// PlatformReporter is the control-plane leg; controlPlane satisfies its IngestClient seam.
reporter := auditfwd.NewPlatformReporter(controlPlane, logger)
fwd := auditfwd.NewForwarder(cfg, sources, reporter, nodeID, hostname, logger)
fwd.Run(ctx)
```

### With LocalReporter and MultiReporter

When `LocalEndpoint.URL` is configured, the `Forwarder` receives a `MultiReporter` that wraps both the `PlatformReporter` and a `LocalReporter`:

```go
var auditReporter auditfwd.AuditReporter = auditfwd.NewPlatformReporter(controlPlane, logger)
if cfg.AuditFwd.LocalEndpoint.URL != "" {
    localReporter := auditfwd.NewLocalReporter(cfg.AuditFwd.LocalEndpoint, controlPlane, nsk, identity.NodeID, logger)
    auditReporter = auditfwd.NewMultiReporter(auditReporter, localReporter, logger)
    logger.Info("local endpoint enabled", "pipeline", "auditfwd", "url", cfg.AuditFwd.LocalEndpoint.URL)
}
fwd := auditfwd.NewForwarder(cfg.AuditFwd, sources, auditReporter, identity.NodeID, hostname, logger)
```

When `LocalEndpoint.URL` is empty, no `MultiReporter` is created and behavior is identical to the single-reporter pipeline.

### Integration Tests

See [Local Endpoint Integration Tests](../development/local-endpoint-integration-tests.md) for the full integration test suite covering dual delivery, error isolation, credential resolution, and TLS skip-verify across all three pipelines.
