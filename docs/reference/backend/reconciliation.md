---
title: Configuration Reconciliation
quadrant: backend
package: internal/reconcile
feature: PXD-0003
---

# Configuration Reconciliation

The `internal/reconcile` package implements the core convergence loop that keeps every node aligned with desired state. It periodically fetches desired state from the control plane, computes a diff against a local snapshot, invokes pluggable handlers to correct drift, and reports corrections back to the control plane.

## Config

`Config` holds reconciliation parameters passed to the `Reconciler` constructor. No file I/O occurs in this package.

| Field      | Type            | Default | Description                        |
|------------|-----------------|---------|------------------------------------|
| `Interval` | `time.Duration` | `60s`   | Time between reconciliation cycles |

```go
cfg := reconcile.Config{
    Interval: 30 * time.Second,
}
cfg.ApplyDefaults() // sets Interval to 60s if zero
if err := cfg.Validate(); err != nil {
    log.Fatal(err) // rejects negative or sub-second intervals
}
```

## StateFetcher

Interface for control plane communication. `*api.ControlPlane` satisfies this interface.

```go
type StateFetcher interface {
    FetchState(ctx context.Context, nodeID string) (*api.StateResponse, error)
    ReportDrift(ctx context.Context, nodeID string, req api.DriftReport) error
}
```

## ReconcileHandler

Function type invoked when drift is detected. Each handler receives the full desired state and the computed diff.

```go
type ReconcileHandler func(ctx context.Context, desired *api.StateResponse, diff StateDiff) error
```

Handlers are invoked sequentially in registration order. Errors and panics in one handler do not prevent subsequent handlers from running.

## Reconciler

### Constructor

```go
func NewReconciler(client StateFetcher, cfg Config, logger *slog.Logger) *Reconciler
```

- Applies config defaults via `cfg.ApplyDefaults()`
- Initializes an empty state snapshot
- Creates a buffered trigger channel (size 1) for coalescing

### Methods

| Method             | Signature                                                   | Description                                        |
|--------------------|-------------------------------------------------------------|----------------------------------------------------|
| `RegisterHandler`  | `(handler ReconcileHandler)`                                | Adds a handler invoked on drift (call before `Run`) |
| `TriggerReconcile` | `()`                                                        | Requests immediate cycle; rapid calls are coalesced |
| `Run`              | `(ctx context.Context, nodeID string) error`                | Blocking loop; returns `ctx.Err()` on cancellation |

### Lifecycle

```go
logger := slog.Default()

client, _ := api.NewControlPlane(apiCfg, "1.0.0", logger)
client.SetAuthToken(identity.NodeSecretKey)

r := reconcile.NewReconciler(client, reconcile.Config{}, logger)

// Register handlers before Run (future features plug in here)
r.RegisterHandler(func(ctx context.Context, desired *api.StateResponse, diff reconcile.StateDiff) error {
    // S005: apply WireGuard peer changes
    return nil
})
r.RegisterHandler(func(ctx context.Context, desired *api.StateResponse, diff reconcile.StateDiff) error {
    // S008: apply network policy changes
    return nil
})

// Run blocks until context cancelled
ctx, cancel := context.WithCancel(context.Background())
go func() {
    if err := r.Run(ctx, nodeID); err != nil && err != context.Canceled {
        logger.Error("reconciler failed", "error", err)
    }
}()

// Trigger immediate reconciliation (e.g., after SSE reconnection)
r.TriggerReconcile()

// Graceful shutdown
cancel()
```

### Reconciliation Cycle

Each cycle follows this sequence:

1. **FetchState** — `GET /v1/nodes/{node_id}/state` via `StateFetcher`
2. **ComputeDiff** — compare desired state against local snapshot
3. **Skip if empty** — no handlers invoked, no drift reported
4. **Invoke handlers** — each handler called with panic recovery
5. **BuildDriftReport** — one `DriftCorrection` per drift item
6. **ReportDrift** — `POST /v1/nodes/{node_id}/drift` via `StateFetcher`
7. **Update snapshot** — only if all handlers succeeded

### Error Handling

| Error Source       | Behavior                                              |
|--------------------|-------------------------------------------------------|
| `FetchState` error | Logged at warn, tick skipped, loop continues          |
| Handler error      | Logged at error, other handlers still run             |
| Handler panic      | Recovered with stack trace, treated as error          |
| `ReportDrift` error| Logged at warn, loop continues                       |
| Context cancelled  | `Run` returns `ctx.Err()` immediately                |

### Logging

All log entries use structured keys with `component=reconcile`:

| Key              | Description                          |
|------------------|--------------------------------------|
| `component`      | Always `"reconcile"`                 |
| `node_id`        | Node identifier                      |
| `interval`       | Configured reconciliation interval   |
| `drift_count`    | Number of corrections in the cycle   |
| `duration`       | Cycle execution time                 |
| `handler_failed` | Whether any handler returned error   |
| `error`          | Error details (on warn/error levels) |

## StateDiff

Describes drift between desired and current state across all categories.

```go
type StateDiff struct {
    PeersToAdd         []api.Peer
    PeersToRemove      []string        // peer IDs
    PeersToUpdate      []api.Peer      // peers with changed fields

    PoliciesToAdd      []api.Policy
    PoliciesToRemove   []string        // policy IDs

    SigningKeysChanged bool
    NewSigningKeys     *api.SigningKeys

    MetadataChanged    bool
    DataChanged        bool
    SecretRefsChanged  bool
}
```

### ComputeDiff

```go
func ComputeDiff(desired *api.StateResponse, current *api.StateResponse) StateDiff
```

Comparison logic by category:

| Category     | Match Key     | Detect Add/Remove | Detect Update                                  |
|--------------|---------------|-------------------|-------------------------------------------------|
| Peers        | `Peer.ID`     | Yes               | Endpoint, PublicKey, MeshIP, AllowedIPs, PSK   |
| Policies     | `Policy.ID`   | Yes               | —                                               |
| SigningKeys  | —             | nil ↔ non-nil     | Current or Previous string changed              |
| Metadata     | map key       | —                 | `reflect.DeepEqual` on full map                 |
| Data         | `DataEntry.Key`| Yes              | Version changed                                 |
| SecretRefs   | `SecretRef.Key`| Yes              | Version changed                                 |

AllowedIPs comparison is order-independent (sorted before comparison).

### IsEmpty

```go
func (d StateDiff) IsEmpty() bool
```

Returns `true` when all slices are empty and all `Changed` booleans are `false`.

## StateSnapshot

In-memory cache of the last known desired state, protected by `sync.RWMutex`.

| Method                                         | Description                                     |
|------------------------------------------------|-------------------------------------------------|
| `NewStateSnapshot() *stateSnapshot`            | Creates empty snapshot                          |
| `Get() api.StateResponse`                      | Returns deep copy of current state              |
| `Update(desired *api.StateResponse)`           | Atomically replaces all fields (deep copy)      |
| `UpdatePartial(desired, categories ...string)` | Selectively updates specified categories        |

Categories for `UpdatePartial`: `"peers"`, `"policies"`, `"signing_keys"`, `"metadata"`, `"data"`, `"secret_refs"`.

All methods deep-copy data to prevent aliasing between snapshot and caller.

## BuildDriftReport

```go
func BuildDriftReport(diff StateDiff) api.DriftReport
```

Generates one `api.DriftCorrection` per drift item:

| Diff Field           | Correction Type         | Detail Format           |
|----------------------|-------------------------|-------------------------|
| `PeersToAdd`         | `peer_added`            | `"peer {id}"`          |
| `PeersToRemove`      | `peer_removed`          | `"peer {id}"`          |
| `PeersToUpdate`      | `peer_updated`          | `"peer {id}"`          |
| `PoliciesToAdd`      | `policy_added`          | `"policy {id}"`        |
| `PoliciesToRemove`   | `policy_removed`        | `"policy {id}"`        |
| `SigningKeysChanged` | `signing_keys_updated`  | `"signing keys rotated"`|
| `MetadataChanged`    | `metadata_updated`      | `"metadata updated"`   |
| `DataChanged`        | `data_updated`          | `"data updated"`       |
| `SecretRefsChanged`  | `secret_refs_updated`   | `"secret refs updated"`|

`DriftReport.Timestamp` is set to `time.Now()`. Empty diff produces an empty (non-nil) corrections slice.

## Integration Points

### SSE Reconnection

When `SSEManager` reconnects after a disconnection, call `TriggerReconcile()` to catch up on missed events:

```go
// In the SSE reconnection callback
reconciler.TriggerReconcile()
```

### Heartbeat Reconcile Flag

When a heartbeat response contains `reconcile: true`, trigger an immediate cycle:

```go
resp, err := client.Heartbeat(ctx, nodeID, req)
if err == nil && resp.Reconcile {
    reconciler.TriggerReconcile()
}
```

### Future Handler Implementations

| Feature | Handler Responsibility                          |
|---------|------------------------------------------------|
| S005    | Apply WireGuard peer add/remove/update         |
| S008    | Apply nftables policy add/remove               |
| S010    | Update signing key store on key rotation        |
