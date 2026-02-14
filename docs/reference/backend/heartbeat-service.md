---
title: Heartbeat Service
quadrant: backend
package: internal/agent
feature: PXD-0025
---

# Heartbeat Service

The `internal/agent` package implements the `HeartbeatService`, which sends periodic heartbeat requests to the control plane and processes directive flags from the response.

## Config

| Field      | Type            | Default | Description                    |
|------------|-----------------|---------|--------------------------------|
| `Interval` | `time.Duration` | `30s`   | Heartbeat send interval        |
| `NodeID`   | `string`        | —       | Node identifier (required)     |

## Heartbeat Loop

`HeartbeatService.Run(ctx)` operates as follows:

1. Send one heartbeat immediately on start
2. Start a ticker at the configured interval (default 30s)
3. On each tick, build and send a `HeartbeatRequest`
4. Process the `HeartbeatResponse` directive flags
5. Continue until context is cancelled

`Run()` always returns nil.

## Request Payload

The heartbeat request is built by an optional `buildRequest` function. If not set, a zero-valued `HeartbeatRequest` is sent. The builder typically collects runtime state:

```go
type HeartbeatRequest struct {
    NodeID         string     `json:"node_id"`
    Timestamp      time.Time  `json:"timestamp"`
    Status         string     `json:"status"`
    Uptime         int64      `json:"uptime"`
    BinaryChecksum string     `json:"binary_checksum"`
    MeshInfo       *MeshInfo  `json:"mesh_info,omitempty"`
    NATInfo        *NATInfo   `json:"nat_info,omitempty"`
    BridgeInfo     *BridgeInfo `json:"bridge_info,omitempty"`
}
```

## Response Handling

The control plane returns a `HeartbeatResponse` with directive flags:

```go
type HeartbeatResponse struct {
    Reconcile  bool `json:"reconcile"`
    RotateKeys bool `json:"rotate_keys"`
}
```

| Flag          | Action                                              |
|---------------|-----------------------------------------------------|
| `reconcile`   | Call `ReconcileTrigger.TriggerReconcile()`           |
| `rotate_keys` | Call the `onRotateKeys` callback                    |

## Error Handling

### 401 Unauthorized

When the heartbeat receives a 401 error (`api.ErrUnauthorized`), the `onAuthFailure` callback is invoked. In production (`plexd up`), this triggers re-registration:

1. Call `registrar.Register(ctx)` to obtain a new identity
2. Update the control plane client auth token via `client.SetAuthToken()`
3. Log the re-registration result

If re-registration fails, the error is logged and the heartbeat continues retrying on the next tick.

### Other Errors

Non-401 errors are logged at error level. The heartbeat loop continues on the next tick interval.

## Callbacks

| Method                | Signature      | Description                                |
|-----------------------|----------------|--------------------------------------------|
| `SetReconcileTrigger` | `ReconcileTrigger` | Reconciler to trigger on `reconcile=true` |
| `SetOnAuthFailure`    | `func()`       | Called on 401 Unauthorized                 |
| `SetOnRotateKeys`     | `func()`       | Called on `rotate_keys=true`               |
| `SetBuildRequest`     | `func() HeartbeatRequest` | Custom request builder          |

## Integration Wiring

In `plexd up`, the heartbeat service is wired as follows:

```
HeartbeatService
├── client: ControlPlane (sends heartbeat RPCs)
├── reconcileTrigger: Reconciler (triggers state reconciliation)
├── onAuthFailure: re-registers → updates auth token
└── onRotateKeys: triggers reconcile (fetches new signing keys)
```

## Interfaces

```go
type HeartbeatClient interface {
    Heartbeat(ctx context.Context, nodeID string, req HeartbeatRequest) (*HeartbeatResponse, error)
}

type ReconcileTrigger interface {
    TriggerReconcile()
}
```

Both interfaces are small and testable. The `HeartbeatClient` is satisfied by `*api.ControlPlane`, and `ReconcileTrigger` is satisfied by `*reconcile.Reconciler`.
