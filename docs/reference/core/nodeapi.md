---
title: Local Node API
package: internal/nodeapi
feature: PXD-0004
---

# Local Node API

The `internal/nodeapi` package exposes node state to local consumers (sidecar agents, CLI tools, monitoring) via a Unix domain socket and an optional TCP listener. It provides read access to metadata, data entries, and secrets, plus read-write access to local report entries that are synced to the control plane. The cache is kept current via SSE events and the reconciliation loop.

## Config

`Config` holds server parameters passed to the `Server` constructor. Config loading is the caller's responsibility.

| Field             | Type            | Default                    | Description                                  |
|-------------------|-----------------|----------------------------|----------------------------------------------|
| `SocketPath`      | `string`        | `/var/run/plexd/api.sock` (Linux, macOS) | Path to the Unix domain socket ([per platform](configuration.md#platform-defaults)) |
| `HTTPEnabled`     | `bool`          | `false`                    | Enable the optional TCP listener             |
| `HTTPListen`      | `string`        | `127.0.0.1:9100`           | TCP listen address                           |
| `HTTPTokenFile`   | `string`        | —                          | Path to file containing HTTP bearer token    |
| `DebouncePeriod`  | `time.Duration` | `5s`                       | Debounce period for report sync coalescing   |
| `ShutdownTimeout` | `time.Duration` | `5s`                       | Maximum time to wait for graceful shutdown   |
| `SecretAuthEnabled`| `bool`         | `false`                    | SO_PEERCRED-based auth for secret routes     |
| `DataDir`         | `string`        | —                          | Data directory for cache persistence (required) |

> The TCP listener serves the authenticated `/v1` routes only. The Kubernetes probe endpoints `/healthz` and `/readyz` come from a separate, unauthenticated health listener configured by the top-level `health` block (default `:9101`). That listener is enabled and bound independently of `HTTPEnabled`. See the [Configuration Reference](configuration.md#health).

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
    FetchSecret(ctx context.Context, nodeID, name string, version int) (*api.SecretEnvelope, error)
}
```

### ReportSyncClient

```go
type ReportSyncClient interface {
    PutStateReport(ctx context.Context, nodeID, key string, req api.NodeStateReportRequest) (*api.NodeStateReportResponse, error)
    DeleteStateReport(ctx context.Context, nodeID, key string) error
}
```

## Server

### Constructor

```go
func NewServer(cfg Config, client NodeAPIClient, nsk []byte, logger *slog.Logger) *Server
```

- Applies config defaults via `cfg.ApplyDefaults()`
- Creates a `StateCache` eagerly so that `ReconcileHandler` can be called before `Start`
- Logger tagged with `component=nodeapi`
- `nsk` is the 32-byte node secret key used for AES-256-GCM secret decryption

### Methods

| Method                  | Signature                                                        | Description                                                         |
|-------------------------|------------------------------------------------------------------|---------------------------------------------------------------------|
| `Start`                 | `(ctx context.Context, nodeID string) error`                     | Blocking; runs listeners and syncer until context cancelled         |
| `ReconcileHandler`      | `() reconcile.ReconcileHandler`                                  | Returns a handler that feeds the cache from the snapshot `state` block |
| `PublishReport`         | `(key, contentType string, payload json.RawMessage) error`       | Writes a report through the cache and notifies the syncer; holds `key`/`payload` to the same grammar and 4096-byte cap as the local HTTP API |
| `ReportPayload`         | `(key string) (json.RawMessage, bool)`                           | Returns the payload currently stored under `key`; internal producers compare against it so a report another local caller overwrote or deleted is re-asserted |

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

// Register reconcile handler (feeds the cache from the state pull).
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

Reconciles per-key report changes to the control plane via `PutStateReport` /
`DeleteStateReport`, debouncing rapid updates to reduce API calls. Changes are
held in a dirty map keyed by report key (a `nil` value marks a pending delete);
the last local write to a key wins.

### Constructor

```go
func NewReportSyncer(client ReportSyncClient, debouncePeriod time.Duration, logger *slog.Logger) *ReportSyncer
```

The node ID is supplied later to `Run` because the syncer is constructed in
`NewServer`, before the node has registered and its ID is known.

### Methods

| Method         | Signature                                                 | Description                                    |
|----------------|-----------------------------------------------------------|------------------------------------------------|
| `NotifyChange` | `(entries []ReportEntry, deleted []string)`               | Merges changes into the dirty map and signals the run loop |
| `Run`          | `(ctx context.Context, nodeID string) error`              | Blocking loop; returns `ctx.Err()` on cancel   |

### Debounce and Per-Key Sync Behavior

1. **Notification** — `NotifyChange` merges entries (pending PUTs) and deleted keys (pending deletes) into the dirty map and sends a non-blocking signal.
2. **Debounce** — after a signal, waits `DebouncePeriod` (default 5s) to coalesce a burst before flushing.
3. **Flush** — snapshots the dirty map and reconciles each key **in ascending key order**, one at a time: a `nil` entry is a `DELETE`, otherwise a `PUT`. A key is cleared only if it still holds the snapshotted version, so a write that raced the flush stays dirty for the next round.
4. **Retryable failure** — a key left dirty by a transient error is re-flushed on a **30-second** timer, without waiting for a new local mutation.
5. **`DELETE` 404** — `report_not_found` is treated as success (the report is already absent upstream).
6. **`PUT` 400** — `invalid_report` is a permanent refusal; the key is dropped with a Warn (unreachable once the local API enforces the same grammar and cap, kept as defense in depth).
7. **Not provisioned (501)** — a `reports_not_provisioned` refusal aborts the flush and **suppresses every HTTP attempt for 5 minutes**, logging the transition once; the keys stay dirty until the window elapses.

### Report Notify Middleware

The server wraps the HTTP mux with middleware that automatically notifies the syncer after successful report mutations:

- `PUT /v1/state/report/{key}` returning 200 — notifies with the updated entry
- `DELETE /v1/state/report/{key}` returning 204 — notifies with the deleted key

## DecryptSecret

```go
func DecryptSecret(nsk []byte, envelope []byte) (string, error)
```

Opens the raw AES-256-GCM secret envelope under the NSK.

- `nsk` — 32-byte node secret key (raw bytes)
- `envelope` — the raw envelope bytes `<12-byte nonce> || <ciphertext + 16-byte GCM tag>` (the `Data` field of an `api.SecretEnvelope`)
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

Fetches, decrypts, and returns a secret value. The secret is fetched from the
control plane on each request, decrypted with the node secret key, and returned
as plaintext. An optional `?version=N` query (a positive integer) selects an
older version; omitting it returns the current version.

**Response** `200 OK`:

```json
{"key": "db-password", "value": "s3cret", "version": 1}
```

| Status | Condition                          |
|--------|------------------------------------|
| `200`  | Secret fetched and decrypted       |
| `400`  | `?version` is not a positive integer, or the key is outside the grammar `^[a-z][a-z0-9_-]{0,62}$` |
| `403`  | Node not authorized to access this secret |
| `404`  | Secret — or the requested version — not found on the control plane |
| `429`  | Upstream rate limit; a `Retry-After` header copies the upstream wait in seconds |
| `500`  | Decryption failed                  |
| `503`  | Control plane unavailable          |

### GET /v1/state/report

Returns a list of report entry summaries (key, version).

**Response** `200 OK`:

```json
[{"key": "health", "version": 3}]
```

> plexd itself publishes a set of `status.*` reports — `status.mesh`,
> `status.bridge`, `status.user-access`, `status.ingress`, and
> `status.site-to-site` — through `Server.PublishReport` at heartbeat cadence, so
> these keys appear here alongside workload-written reports. This is by design:
> the same per-key syncer ships them to the control plane. They live in the same
> flat, workload-writable keyspace, so every tick compares the sampled status
> against the value actually stored under the key (`Server.ReportPayload`) rather
> than against a private memory of the last publish: a `status.*` report another
> local caller overwrote or deleted is re-asserted on the next tick instead of
> standing until the sampled value happens to change.

### GET /v1/state/report/{key}

Returns a full report entry.

**Response** `200 OK`: `ReportEntry` JSON

| Status | Condition      |
|--------|----------------|
| `200`  | Key found      |
| `404`  | Key not found  |

### PUT /v1/state/report/{key}

Creates or updates a report entry with optional optimistic locking. `{key}` must
match the report key grammar `^[a-z][a-z0-9._-]{0,127}$` (shared by the `GET`,
`PUT`, and `DELETE` report routes), and the serialized `payload` is capped at
4096 bytes — both limits mirror what the control plane accepts.

::: warning Breaking change
This grammar is stricter than the earlier one (which accepted any non-empty key
other than `.`/`..` without a path separator). Keys valid under the old rule but
not the new one — uppercase (`Health`), a leading digit (`9-checks`), or over 128
bytes — are rejected by all three report routes. On startup any such report
persisted under `data_dir/state/report/<key>.json` is dropped from the cache with
a `Warn` log naming the file, so the listing stays in lockstep with what the
routes serve. The file itself is left in place; delete it by hand once the report
is no longer needed. A previous release may have synced the report to the control
plane, where no local route can reach it any more, so the server also queues a
`DELETE /v1/nodes/{id}/state/reports/{key}` for each dropped key — the delete is
idempotent, so a key that was never synced simply answers `404`.
:::

**Request**:

```json
{"content_type": "application/json", "payload": {"status": "healthy"}}
```

**Headers** (optional): `If-Match: <version>` — integer version for optimistic locking

**Response** `200 OK`: the created/updated `ReportEntry`

| Status | Condition                               |
|--------|-----------------------------------------|
| `200`  | Created or updated                      |
| `400`  | Invalid report key, invalid JSON, missing `content_type`, invalid `payload`, `payload` over 4096 bytes, or non-integer `If-Match` |
| `409`  | Version conflict (optimistic lock)      |
| `500`  | Internal error                          |

### DELETE /v1/state/report/{key}

Deletes a report entry and its persisted file.

| Status | Condition      |
|--------|----------------|
| `204`  | Deleted        |
| `404`  | Key not found  |
| `500`  | Internal error |

### GET /v1/policies

Returns the active merged policy block — a single
`{revision_id, fingerprint, rules[]}` object, not an array. Returns an empty
object `{}` when no policy is active (or no policy provider is wired).

**Response** `200 OK`:

```json
{
  "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1",
  "fingerprint": "j7Hn2mF0oQ9rXcV8yZ1aB4cD6eF8gH0iJ2kL4mN6oM=",
  "rules": [
    { "action": "allow", "protocol": "tcp", "source_cidr": "10.99.0.0/24", "destination_cidr": "0.0.0.0/0", "ports": { "from": 443, "to": 443 } }
  ]
}
```

## Cache Updates

The node API no longer registers its own SSE handlers. The cache metadata map and
the versioned data store are refreshed by the reconcile handler (below) whenever
the pulled state snapshot changes; `node_state_updated` SSE events drive this
indirectly by dispatching to `TriggerReconcile()`, which re-pulls the snapshot.
The secret index is updated through the `UpdateSecretIndex` cache method, which no
longer rides an SSE event.

## Integration Points

### ReconcileHandler

Register the reconcile handler before starting the reconciliation loop:

```go
reconciler.RegisterHandler(srv.ReconcileHandler())
```

The handler runs when `diff.StateChanged` and feeds the cache from the snapshot
`state` block:

| Snapshot input          | Cache Update       | Conversion                                                        |
|-------------------------|--------------------|-------------------------------------------------------------------|
| `state.metadata` bucket | `UpdateMetadata`   | Entry `key`/`value` pairs become the metadata map                 |
| `state.data` bucket     | `UpdateData`       | Each opaque string `value` is JSON-encoded into a `DataEntry` payload with content type `text/plain; charset=utf-8` |

A `null` `state` block authoritatively clears both the metadata map and the data
entries. The secret index is **not** fed here — it no longer rides the snapshot, and the
`node_secrets_updated` SSE event that once fed it has been removed.
`UpdateSecretIndex` remains a cache method.

### ControlPlane Client

The server uses these control plane methods via the `NodeAPIClient` interface:

| Method              | Used By                                       | Purpose                             |
|---------------------|-----------------------------------------------|-------------------------------------|
| `FetchSecret`       | `GET /v1/state/secrets/{key}` handler         | Fetches encrypted secret on demand  |
| `PutStateReport`    | `ReportSyncer` (background)                    | Upserts a report entry per key      |
| `DeleteStateReport` | `ReportSyncer` (background)                    | Deletes a report entry per key      |

## Kubernetes: PlexdNodeState CRD

On Kubernetes, plexd manages a `PlexdNodeState` custom resource for metadata, data, and report entries. Workloads interact with non-secret state through the standard Kubernetes API. For secrets, plexd exposes a node-local decryption API -- Kubernetes Secrets referenced by the CRD contain only NSK-encrypted ciphertext, not plaintext.

### CRD Definition

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: plexdnodestates.plexd.plexsphere.com
spec:
  group: plexd.plexsphere.com
  names:
    kind: PlexdNodeState
    listKind: PlexdNodeStateList
    plural: plexdnodestates
    singular: plexdnodestate
    shortNames:
      - pns
  scope: Namespaced
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                nodeId:
                  type: string
                meshIp:
                  type: string
                metadata:
                  type: object
                  additionalProperties:
                    type: string
                data:
                  type: array
                  items:
                    type: object
                    properties:
                      key:
                        type: string
                      contentType:
                        type: string
                      payload:
                        x-kubernetes-preserve-unknown-fields: true
                      version:
                        type: integer
                      updatedAt:
                        type: string
                        format: date-time
                secretRefs:
                  type: array
                  items:
                    type: object
                    properties:
                      key:
                        type: string
                      secretName:
                        type: string
                      version:
                        type: integer
            status:
              type: object
              properties:
                report:
                  type: array
                  items:
                    type: object
                    properties:
                      key:
                        type: string
                      contentType:
                        type: string
                      payload:
                        x-kubernetes-preserve-unknown-fields: true
                      version:
                        type: integer
                      updatedAt:
                        type: string
                        format: date-time
      subresources:
        status: {}
      additionalPrinterColumns:
        - name: Node ID
          type: string
          jsonPath: .spec.nodeId
        - name: Mesh IP
          type: string
          jsonPath: .spec.meshIp
        - name: Data Entries
          type: integer
          jsonPath: .spec.data[*].key
        - name: Age
          type: date
          jsonPath: .metadata.creationTimestamp
```

### Example PlexdNodeState CR

```yaml
apiVersion: plexd.plexsphere.com/v1alpha1
kind: PlexdNodeState
metadata:
  name: node-n-abc123
  namespace: plexd-system
  labels:
    plexd.plexsphere.com/node-id: n_abc123
spec:
  nodeId: n_abc123
  meshIp: 10.100.1.5
  metadata:
    environment: production
    region: eu-west-1
    role: worker
  data:
    - key: database-config
      contentType: application/json
      payload:
        host: db.internal
        port: 5432
        database: myapp
      version: 3
      updatedAt: "2025-01-15T10:30:00Z"
    - key: feature-flags
      contentType: application/json
      payload:
        enable_new_ui: true
        max_connections: 100
      version: 7
      updatedAt: "2025-01-15T11:00:00Z"
  secretRefs:
    - key: tls-cert
      secretName: plexd-secret-n-abc123-tls-cert
      version: 2
    - key: api-token
      secretName: plexd-secret-n-abc123-api-token
      version: 1
status:
  report:
    - key: app-health
      contentType: application/json
      payload:
        status: healthy
        checked_at: "2025-01-15T10:30:00Z"
      version: 12
      updatedAt: "2025-01-15T10:30:00Z"
```

### K8s Secret Structure

Secrets are stored as native Kubernetes Secrets with `ownerReferences` pointing to the `PlexdNodeState` resource. This ensures secrets are garbage-collected when the node state is deleted. **Important:** The Kubernetes Secret contains the NSK-encrypted ciphertext, not the plaintext value. Reading the Secret directly yields unusable encrypted data.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: plexd-secret-n-abc123-tls-cert
  namespace: plexd-system
  ownerReferences:
    - apiVersion: plexd.plexsphere.com/v1alpha1
      kind: PlexdNodeState
      name: node-n-abc123
      uid: <uid>
  annotations:
    plexd.plexsphere.com/encrypted: "true"
    plexd.plexsphere.com/encryption-algorithm: AES-256-GCM
type: Opaque
data:
  value: <base64-encoded-NSK-encrypted-ciphertext>
  nonce: <base64-encoded-GCM-nonce>
```

The `PlexdNodeState` `.spec.secretRefs` array lists the secret names and versions. To obtain plaintext values, workloads must call plexd's node-local decryption API rather than reading the Kubernetes Secret directly.

### Node-Local Decryption API

On Kubernetes, plexd's DaemonSet pod exposes a decryption endpoint for workloads on the same node. This follows the same pattern as node-local DNS or kube-proxy:

| Access method | Configuration | Use case |
|---|---|---|
| Host-network socket | `/var/run/plexd/api.sock` mounted via `hostPath` | Pods with host path access |
| Node-local HTTP | `http://<node-ip>:9100/v1/state/secrets/{key}` via `hostPort` | General pod access, requires bearer token |

Workloads call `GET /v1/state/secrets/{key}` on the node-local endpoint. plexd verifies the caller's authorization (bearer token or ServiceAccount identity), fetches the encrypted value from the control plane in real-time, decrypts with the NSK, and returns the plaintext. Like on bare-metal, the call fails with `503` if the control plane is unreachable.

```bash
# From a pod on the same node (using the Kubernetes node internal IP)
curl -H "Authorization: Bearer $(cat /var/run/secrets/plexd/token)" \
  http://${NODE_IP}:9100/v1/state/secrets/tls-cert
```

plexd validates the bearer token against the Kubernetes TokenReview API to verify the caller's ServiceAccount and namespace before serving the decrypted secret.

### RBAC Roles

```yaml
# Read access to PlexdNodeState spec (metadata, data, secretRefs)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: plexd-state-reader
  namespace: plexd-system
rules:
  - apiGroups: ["plexd.plexsphere.com"]
    resources: ["plexdnodestates"]
    verbs: ["get", "list", "watch"]

---
# Write access to PlexdNodeState status (report entries)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: plexd-state-reporter
  namespace: plexd-system
rules:
  - apiGroups: ["plexd.plexsphere.com"]
    resources: ["plexdnodestates/status"]
    verbs: ["get", "patch"]

---
# Read access to plexd-managed secrets (encrypted ciphertext only -- plaintext requires decryption API)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: plexd-secrets-reader
  namespace: plexd-system
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: []  # Scoped to specific secret names by the operator
    verbs: ["get"]
```

> **Note:** The `plexd-secrets-reader` role grants access to the Kubernetes Secret objects, but these contain only NSK-encrypted ciphertext. For plaintext access, workloads must call plexd's node-local decryption API with a valid bearer token. This two-layer model ensures that neither Kubernetes RBAC alone nor socket/network access alone is sufficient to read secret values.

The `.spec` (including `nodeId`, `meshIp`, `metadata`, `data`, `secretRefs`) is managed exclusively by plexd. Workloads write upstream data by patching `.status.report` via the status subresource, which has separate RBAC from the main resource.

## Data Sync Protocol

### Downstream Sync (Control Plane to Node)

1. On initial connect, plexd fetches the node state from `GET /v1/nodes/{node_id}/state` (the reconciliation endpoint). The `NodeStateSnapshot` `state` block feeds the cache: its `metadata` bucket becomes the metadata map and its `data` bucket becomes the cached data entries. Secret references no longer ride the snapshot.
2. During steady state, the control plane emits a `node_state_updated` SSE event when node state changes. Its payload is opaque: the agent responds by triggering a reconcile, which re-pulls the snapshot and refreshes the cache. There is no separate secrets SSE event.
3. Secret names and versions are held in the local secret index (`UpdateSecretIndex`), so the listing endpoints reflect the current state without carrying any secret values - **never plaintext nor ciphertext**.
4. Secret values are fetched **on demand** when a consumer requests them via `GET /v1/state/secrets/{key}`. plexd proxies to `GET /v1/nodes/{node_id}/secrets/{key}` on the control plane, which returns the NSK-encrypted ciphertext. plexd decrypts with the local NSK and returns the plaintext to the authorized caller. No plaintext is persisted.
5. The reconciliation loop compares the local state cache (metadata and data, from the snapshot `state` block) against the control plane, correcting any drift. The secret index no longer has an SSE event, and secret values are always fetched live.

### Upstream Sync (Node to Control Plane)

1. When a workload writes a report entry (via Unix socket API or CRD status patch), plexd buffers the change locally.
2. After a debounce period (default 5s), plexd syncs each dirty report key to the control plane one at a time — `PUT /v1/nodes/{node_id}/state/reports/{key}` for an upsert, `DELETE` for a removal — flushing keys in ascending order.
3. If the control plane is unreachable, report entries are buffered in `data_dir/state/report/` and drained when connectivity is restored; a key left dirty by a transient error is retried on a 30-second timer.
4. plexd itself publishes `status.*` reports (the mesh and bridge status blocks) through `Server.PublishReport` on the same per-key syncer.

### Offline Behavior

- The local state cache in `data_dir/state/` survives agent restarts and control plane outages
- Workloads can read cached metadata and data entries even when the control plane is unreachable
- **Secrets are unavailable offline** -- since secret values are fetched in real-time from the control plane and never cached in plaintext, `GET /v1/state/secrets/{key}` returns `503 Service Unavailable` when the control plane is unreachable. This is an explicit security trade-off.
- Report entries are buffered locally and synced when connectivity is restored
- On Kubernetes, the `PlexdNodeState` resource (metadata, data, report) persists in etcd independently of the control plane. Kubernetes Secrets contain only encrypted ciphertext and remain in etcd, but cannot be decrypted without the control plane (since decryption requires a live fetch to verify authorization).

## File Cache Structure

```
data_dir/state/
├── metadata.json          # Cached metadata key-value pairs
├── data/
│   ├── database-config.json
│   └── feature-flags.json
├── secrets.json           # Secret index only (names + versions, NO values)
└── report/
    └── app-health.json    # Locally written, pending sync
```

> **Note:** Secret values are never written to the file cache. Only the secret index (names and versions) is persisted for the listing endpoint. Plaintext values exist only in memory during the brief window between decryption and response delivery.

## Socket API vs CRD Comparison

| Aspect | Unix Socket API | PlexdNodeState CRD |
|---|---|---|
| **Platform** | Bare-metal, VM | Kubernetes |
| **Read access** | `curl --unix-socket` / HTTP client | `kubectl get pns` / client-go / watch |
| **Write access (report)** | `PUT /v1/state/report/{key}` | Status subresource patch |
| **Secret access** | Real-time fetch via plexd proxy, `plexd-secrets` group or bearer token | Real-time fetch via plexd node-local API, bearer token (K8s Secrets contain only NSK-encrypted ciphertext) |
| **Access control** | File permissions (groups) | Kubernetes RBAC |
| **Offline resilience** | File cache in `data_dir/state/` | CRD persists in etcd |
| **Change notification** | Poll or watch `Last-Modified` header | Kubernetes watch on CRD |
| **Concurrency control** | `If-Match` header (optimistic) | Kubernetes resource version (optimistic) |

## Security Considerations

- **Envelope encryption (NSK)** - All secret values are encrypted with a per-node AES-256-GCM key (Node Secret Key) before leaving the control plane. The NSK is generated during registration and delivered to the node over authenticated TLS. Even if TLS is compromised or an attacker gains access to the Unix socket, CRD, or Kubernetes Secret objects, they only see ciphertext without the NSK.
- **No plaintext at rest** - Secret values are never written to disk or etcd in plaintext. The file cache stores only the secret index (names + versions). On Kubernetes, Secret objects contain NSK-encrypted ciphertext. Plaintext exists only transiently in plexd's process memory during decryption and response delivery.
- **Real-time fetch** - Secret values are fetched from the control plane on every access, not cached. This ensures the control plane remains the authoritative source and can enforce access policies, audit access, and revoke secrets in real-time. The trade-off is that secrets are unavailable when the control plane is unreachable (503).
- **Two-layer access control** - Access to decrypted secrets requires both: (1) authorization at the plexd API level (Unix socket group membership or bearer token), and (2) live connectivity to the control plane. Neither layer alone is sufficient. On Kubernetes, even RBAC access to the K8s Secret objects only yields encrypted ciphertext.
- **Transport security** - All control plane communication (state fetch, secret fetch, report sync) uses TLS-encrypted HTTPS. The NSK encryption layer provides defense-in-depth: secrets remain protected even if TLS is compromised. The Unix socket is local-only and protected by filesystem permissions.
- **Least privilege** - The CRD splits `.spec` (plexd-managed) from `.status` (workload-writable) using the Kubernetes status subresource. Workloads that need to write reports do not need write access to the node's metadata, data, or secret references.
- **Secret rotation** - Secret values are fetched in real-time, so the next access automatically returns the new value after a rotation on the control plane. No local cache invalidation is needed.
- **NSK rotation** - The NSK is rotated together with mesh keys via the `rotate_keys` flow, or independently via a dedicated `rotate_nsk` control plane API. During rotation, the control plane re-encrypts all secrets for the node with the new NSK.
- **Owner references** - On Kubernetes, plexd-managed Secrets have `ownerReferences` to the `PlexdNodeState` resource, ensuring cleanup on node deregistration.
- **Cache integrity** - The file cache in `data_dir/state/` inherits the `data_dir` permissions (`0700`, owned by `plexd` user). The NSK is stored in `data_dir` with `0600` permissions, accessible only to the plexd process.
