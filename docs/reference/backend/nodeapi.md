---
title: Local Node API
quadrant: backend
package: internal/nodeapi
feature: PXD-0004
---

# Local Node API

The `internal/nodeapi` package exposes node state to local consumers (sidecar agents, CLI tools, monitoring) via a Unix domain socket and an optional TCP listener. It provides read access to metadata, data entries, and secrets, plus read-write access to local report entries that are synced to the control plane. The cache is kept current via SSE events and the reconciliation loop.

## Config

`Config` holds server parameters passed to the `Server` constructor. Config loading is the caller's responsibility.

| Field             | Type            | Default                    | Description                                  |
|-------------------|-----------------|----------------------------|----------------------------------------------|
| `SocketPath`      | `string`        | `/var/run/plexd/api.sock`  | Path to the Unix domain socket               |
| `HTTPEnabled`     | `bool`          | `false`                    | Enable the optional TCP listener             |
| `HTTPListen`      | `string`        | `127.0.0.1:9100`           | TCP listen address                           |
| `HTTPTokenFile`   | `string`        | —                          | Path to file containing HTTP bearer token    |
| `DebouncePeriod`  | `time.Duration` | `5s`                       | Debounce period for report sync coalescing   |
| `ShutdownTimeout` | `time.Duration` | `5s`                       | Maximum time to wait for graceful shutdown   |
| `DataDir`         | `string`        | —                          | Data directory for cache persistence (required) |

```go
cfg := nodeapi.Config{
    DataDir: "/var/lib/plexd",
}
cfg.ApplyDefaults() // sets SocketPath, HTTPListen, DebouncePeriod, ShutdownTimeout
if err := cfg.Validate(); err != nil {
    log.Fatal(err) // DataDir is required; DebouncePeriod and ShutdownTimeout must be positive
}
```

## NodeAPIClient

Interface combining the control plane methods needed by the server. `*api.ControlPlane` satisfies this interface.

```go
type NodeAPIClient interface {
    SecretFetcher
    ReportSyncClient
}
```

### SecretFetcher

```go
type SecretFetcher interface {
    FetchSecret(ctx context.Context, nodeID, key string) (*api.SecretResponse, error)
}
```

### ReportSyncClient

```go
type ReportSyncClient interface {
    SyncReports(ctx context.Context, nodeID string, req api.ReportSyncRequest) error
}
```

## Server

### Constructor

```go
func NewServer(cfg Config, client NodeAPIClient, nsk []byte, logger *slog.Logger) *Server
```

- Applies config defaults via `cfg.ApplyDefaults()`
- Creates a `StateCache` eagerly so that `RegisterEventHandlers` and `ReconcileHandler` can be called before `Start`
- Logger tagged with `component=nodeapi`
- `nsk` is the 32-byte node secret key used for AES-256-GCM secret decryption

### Methods

| Method                  | Signature                                                        | Description                                                         |
|-------------------------|------------------------------------------------------------------|---------------------------------------------------------------------|
| `Start`                 | `(ctx context.Context, nodeID string) error`                     | Blocking; runs listeners and syncer until context cancelled         |
| `RegisterEventHandlers` | `(dispatcher *api.EventDispatcher)`                              | Registers SSE handlers for cache updates (call before SSE start)    |
| `ReconcileHandler`      | `() reconcile.ReconcileHandler`                                  | Returns a handler that updates cache on metadata/data/secret drift  |

### Lifecycle

```go
logger := slog.Default()

// Create control plane client (satisfies NodeAPIClient).
cpClient, _ := api.NewControlPlane(apiCfg, "1.0.0", logger)
cpClient.SetAuthToken(identity.NodeSecretKey)

// Create server.
srv := nodeapi.NewServer(nodeapi.Config{
    DataDir: "/var/lib/plexd",
}, cpClient, []byte(identity.NodeSecretKey), logger)

// Register SSE event handlers with the dispatcher.
srv.RegisterEventHandlers(dispatcher)

// Register reconcile handler.
reconciler.RegisterHandler(srv.ReconcileHandler())

// Start blocks until context cancelled.
ctx, cancel := context.WithCancel(context.Background())
go func() {
    if err := srv.Start(ctx, nodeID); err != nil && err != context.Canceled {
        logger.Error("node API server failed", "error", err)
    }
}()

// Graceful shutdown.
cancel()
```

### Start Sequence

1. **Validate config** — returns error if `DataDir` is empty or durations are non-positive
2. **Load cache** — reads persisted state from `{DataDir}/state/` (creates directories if absent)
3. **Start ReportSyncer** — background goroutine for debounced report sync
4. **Build HTTP handler** — registers all 11 routes, wraps with report-notify middleware
5. **Open Unix socket** — removes stale socket, creates directory, listens
6. **Open TCP listener** — only if `HTTPEnabled`; reads token from `HTTPTokenFile`, wraps with `BearerAuthMiddleware`
7. **Serve** — blocks until context cancelled
8. **Graceful shutdown** — shuts down HTTP servers with `ShutdownTimeout`, stops syncer, removes socket

### Error Handling

| Error Source              | Behavior                                      |
|---------------------------|-----------------------------------------------|
| Config validation failure | `Start` returns error immediately             |
| Cache load failure        | `Start` returns error immediately             |
| Token file read failure   | `Start` returns error, closes Unix listener   |
| TCP listen failure        | `Start` returns error, closes Unix listener   |
| Unix listen failure       | `Start` returns error                         |
| Context cancelled         | Graceful shutdown, returns `ctx.Err()`        |

### Logging

All log entries use structured keys with `component=nodeapi`:

| Key              | Description                          |
|------------------|--------------------------------------|
| `component`      | Always `"nodeapi"`                   |
| `socket`         | Unix socket path                     |
| `http_enabled`   | Whether TCP listener is active       |
| `http_listen`    | TCP listen address                   |
| `node_id`        | Node identifier                      |

## StateCache

In-memory cache of node state with file persistence under `{DataDir}/state/`. All methods are thread-safe via `sync.RWMutex`. All reads return deep copies.

### Constructor

```go
func NewStateCache(dataDir string) *StateCache
```

Creates a cache with empty maps. The state subdirectory tree is created on `Load`.

### Persistence Layout

```
{data_dir}/state/
├── metadata.json       (0600) — map[string]string
├── secrets.json        (0600) — []api.SecretRef
├── data/
│   ├── {key}.json      (0600) — api.DataEntry per key
│   └── ...
└── report/
    ├── {key}.json      (0600) — ReportEntry per key
    └── ...
```

All files are written atomically (temp file + fsync + rename). Directories are created with `0700` permissions.

### Methods

| Method             | Signature                                                                    | Description                                                   |
|--------------------|------------------------------------------------------------------------------|---------------------------------------------------------------|
| `Load`             | `() error`                                                                   | Reads persisted state from disk; creates directories if absent|
| `UpdateMetadata`   | `(m map[string]string)`                                                      | Replaces metadata; persists to `metadata.json`                |
| `UpdateData`       | `(entries []api.DataEntry)`                                                  | Replaces data entries; persists each to `data/{key}.json`; removes stale files |
| `UpdateSecretIndex`| `(refs []api.SecretRef)`                                                     | Replaces secret index; persists to `secrets.json`             |
| `GetMetadata`      | `() map[string]string`                                                       | Returns copy of metadata map                                  |
| `GetMetadataKey`   | `(key string) (string, bool)`                                               | Returns single metadata value                                 |
| `GetData`          | `() map[string]api.DataEntry`                                               | Returns copy of data map                                      |
| `GetDataEntry`     | `(key string) (api.DataEntry, bool)`                                        | Returns single data entry                                     |
| `GetSecretIndex`   | `() []api.SecretRef`                                                         | Returns copy of secret index                                  |
| `GetReports`       | `() map[string]ReportEntry`                                                  | Returns copy of reports map                                   |
| `GetReport`        | `(key string) (ReportEntry, bool)`                                          | Returns single report entry                                   |
| `PutReport`        | `(key, contentType string, payload json.RawMessage, ifMatch *int) (ReportEntry, error)` | Creates/updates report with optimistic locking       |
| `DeleteReport`     | `(key string) error`                                                         | Removes report entry and its file                             |

### ReportEntry

| Field         | Type              | JSON Tag         | Description                         |
|---------------|-------------------|------------------|-------------------------------------|
| `Key`         | `string`          | `"key"`          | Report key identifier               |
| `ContentType` | `string`          | `"content_type"` | MIME type of the payload            |
| `Payload`     | `json.RawMessage` | `"payload"`      | Arbitrary JSON payload              |
| `Version`     | `int`             | `"version"`      | Starts at 1, increments on update   |
| `UpdatedAt`   | `time.Time`       | `"updated_at"`   | Last update timestamp               |

### Optimistic Locking

`PutReport` supports optimistic concurrency via the `ifMatch` parameter:

- `nil` — no version check; always succeeds
- `*int` matching current version — update proceeds, version incremented
- `*int` not matching — returns `ErrVersionConflict`
- New entry with `ifMatch` != 0 — returns `ErrVersionConflict`

### Sentinel Errors

```go
var ErrVersionConflict = errors.New("nodeapi: version conflict")
var ErrNotFound        = errors.New("nodeapi: not found")
```

## ReportSyncer

Buffers report mutations and syncs them to the control plane via `SyncReports`, debouncing rapid updates to reduce API calls.

### Constructor

```go
func NewReportSyncer(client ReportSyncClient, nodeID string, debouncePeriod time.Duration, logger *slog.Logger) *ReportSyncer
```

### Methods

| Method         | Signature                                                 | Description                                    |
|----------------|-----------------------------------------------------------|------------------------------------------------|
| `NotifyChange` | `(entries []api.ReportEntry, deleted []string)`           | Buffers changes and signals the run loop       |
| `Run`          | `(ctx context.Context) error`                             | Blocking loop; returns `ctx.Err()` on cancel   |

### Debounce and Retry Behavior

1. **Notification** — `NotifyChange` appends entries/deletions to internal buffers and sends a non-blocking signal
2. **Debounce** — after receiving a signal, waits `DebouncePeriod` (default 5s) to coalesce further changes
3. **Flush** — drains buffers and calls `SyncReports` with all accumulated entries and deleted keys
4. **Retry on failure** — if `SyncReports` fails, entries are re-buffered and a new signal is sent, triggering another debounce-then-flush cycle
5. **Success** — logged at info level with entry and deletion counts

### Report Notify Middleware

The server wraps the HTTP mux with middleware that automatically notifies the syncer after successful report mutations:

- `PUT /v1/state/report/{key}` returning 200 — notifies with the updated entry
- `DELETE /v1/state/report/{key}` returning 204 — notifies with the deleted key

## DecryptSecret

```go
func DecryptSecret(nsk []byte, ciphertext string, nonce string) (string, error)
```

Decrypts an AES-256-GCM encrypted secret value.

- `nsk` — 32-byte node secret key (raw bytes)
- `ciphertext` — base64-encoded (standard encoding) ciphertext
- `nonce` — base64-encoded (standard encoding) GCM nonce
- Returns plaintext string on success
- Returns a generic `"nodeapi: decryption failed"` error on any failure to avoid leaking cryptographic details

## BearerAuthMiddleware

```go
func BearerAuthMiddleware(token string) func(http.Handler) http.Handler
```

Returns HTTP middleware that validates `Authorization: Bearer {token}` headers. Applied only to the TCP listener; Unix socket requests bypass authentication.

- Expects header format `Bearer <token>` (case-insensitive scheme)
- Uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks
- Returns `401 Unauthorized` with `{"error": "unauthorized"}` on failure

## HTTP API Endpoints

All endpoints return `Content-Type: application/json`. Error responses use the format `{"error": "<message>"}`.

### GET /v1/state

Returns a summary of all cached state.

**Response** `200 OK`:

```json
{
  "metadata": {"key": "value"},
  "data_keys": [{"key": "k", "version": 1, "content_type": "text/plain"}],
  "secret_keys": [{"key": "k", "version": 1}],
  "report_keys": [{"key": "k", "version": 1}]
}
```

### GET /v1/state/metadata

Returns the full metadata map.

**Response** `200 OK`:

```json
{"region": "us-east-1", "env": "production"}
```

### GET /v1/state/metadata/{key}

Returns a single metadata value.

**Response** `200 OK`:

```json
{"key": "region", "value": "us-east-1"}
```

| Status | Condition      |
|--------|----------------|
| `200`  | Key found      |
| `404`  | Key not found  |

### GET /v1/state/data

Returns a list of data entry summaries (key, version, content_type).

**Response** `200 OK`:

```json
[{"key": "config", "version": 2, "content_type": "application/json"}]
```

### GET /v1/state/data/{key}

Returns a full data entry.

**Response** `200 OK`: `api.DataEntry` JSON

| Status | Condition      |
|--------|----------------|
| `200`  | Key found      |
| `404`  | Key not found  |

### GET /v1/state/secrets

Returns the secret reference index (keys and versions, not values).

**Response** `200 OK`:

```json
[{"key": "db-password", "version": 1}]
```

### GET /v1/state/secrets/{key}

Fetches, decrypts, and returns a secret value. The secret is fetched from the control plane on each request, decrypted with the node secret key, and returned as plaintext.

**Response** `200 OK`:

```json
{"key": "db-password", "value": "s3cret", "version": 1}
```

| Status | Condition                          |
|--------|------------------------------------|
| `200`  | Secret fetched and decrypted       |
| `404`  | Secret not found on control plane  |
| `500`  | Decryption failed                  |
| `503`  | Control plane unavailable          |

### GET /v1/state/report

Returns a list of report entry summaries (key, version).

**Response** `200 OK`:

```json
[{"key": "health", "version": 3}]
```

### GET /v1/state/report/{key}

Returns a full report entry.

**Response** `200 OK`: `ReportEntry` JSON

| Status | Condition      |
|--------|----------------|
| `200`  | Key found      |
| `404`  | Key not found  |

### PUT /v1/state/report/{key}

Creates or updates a report entry with optional optimistic locking.

**Request**:

```json
{"content_type": "application/json", "payload": {"status": "healthy"}}
```

**Headers** (optional): `If-Match: <version>` — integer version for optimistic locking

**Response** `200 OK`: the created/updated `ReportEntry`

| Status | Condition                               |
|--------|-----------------------------------------|
| `200`  | Created or updated                      |
| `400`  | Invalid JSON, missing `content_type`, invalid `payload`, or non-integer `If-Match` |
| `409`  | Version conflict (optimistic lock)      |
| `500`  | Internal error                          |

### DELETE /v1/state/report/{key}

Deletes a report entry and its persisted file.

| Status | Condition      |
|--------|----------------|
| `204`  | Deleted        |
| `404`  | Key not found  |
| `500`  | Internal error |

## SSE Event Handlers

`RegisterEventHandlers` registers two SSE event handlers with an `api.EventDispatcher`:

| Event Type             | Handler                      | Cache Update                           |
|------------------------|------------------------------|----------------------------------------|
| `node_state_updated`   | `HandleNodeStateUpdated`     | `UpdateMetadata` + `UpdateData`        |
| `node_secrets_updated` | `HandleNodeSecretsUpdated`   | `UpdateSecretIndex`                    |

### Event Payloads

**node_state_updated**:

```go
type NodeStateUpdatePayload struct {
    Metadata map[string]string `json:"metadata"`
    Data     []api.DataEntry   `json:"data"`
}
```

**node_secrets_updated**:

```go
type NodeSecretsUpdatePayload struct {
    SecretRefs []api.SecretRef `json:"secret_refs"`
}
```

Parse errors are logged at error level and returned as handler errors.

## Integration Points

### EventDispatcher

Register SSE handlers before starting the SSE manager:

```go
srv := nodeapi.NewServer(cfg, cpClient, nsk, logger)
srv.RegisterEventHandlers(sseManager.Dispatcher())
```

When `node_state_updated` or `node_secrets_updated` events arrive, the cache is updated in-memory and persisted to disk automatically.

### ReconcileHandler

Register the reconcile handler before starting the reconciliation loop:

```go
reconciler.RegisterHandler(srv.ReconcileHandler())
```

The handler updates the cache when drift is detected in:

| Diff Field          | Cache Update         |
|---------------------|----------------------|
| `MetadataChanged`   | `UpdateMetadata`     |
| `DataChanged`       | `UpdateData`         |
| `SecretRefsChanged` | `UpdateSecretIndex`  |

### ControlPlane Client

The server uses two control plane methods via the `NodeAPIClient` interface:

| Method         | Used By                                       | Purpose                               |
|----------------|-----------------------------------------------|---------------------------------------|
| `FetchSecret`  | `GET /v1/state/secrets/{key}` handler         | Fetches encrypted secret on demand    |
| `SyncReports`  | `ReportSyncer` (background)                   | Syncs report mutations to control plane|
