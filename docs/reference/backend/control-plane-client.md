---
title: Control Plane Client
quadrant: backend
package: internal/api
feature: PXD-0001
---

# Control Plane Client

The `internal/api` package provides the Go client for communicating with the Plexsphere control plane. It handles HTTPS request/response calls, SSE event streaming, automatic reconnection with exponential backoff, and event dispatching.

## Config

`Config` holds connection parameters passed to the client constructor. No file I/O occurs in this package — config loading is the caller's responsibility.

| Field                   | Type            | Default | Description                                    |
|-------------------------|-----------------|---------|------------------------------------------------|
| `BaseURL`               | `string`        | —       | Control plane API base URL (required)          |
| `TLSInsecureSkipVerify` | `bool`          | `false` | Disable TLS certificate verification           |
| `ConnectTimeout`        | `time.Duration` | `10s`   | TCP connection timeout                         |
| `RequestTimeout`        | `time.Duration` | `30s`   | Full HTTP request/response timeout             |
| `SSEIdleTimeout`        | `time.Duration` | `90s`   | Max idle time before SSE reconnect             |

```go
cfg := api.Config{
    BaseURL:               "https://api.plexsphere.io",
    TLSInsecureSkipVerify: false,
}
cfg.ApplyDefaults() // sets zero-valued timeouts to defaults
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

## ControlPlane

`ControlPlane` is the core HTTP client. It manages authentication, JSON serialization, gzip compression, and error mapping.

### Constructor

```go
func NewControlPlane(cfg Config, version string, logger *slog.Logger) (*ControlPlane, error)
```

- Applies config defaults and validates
- Configures TLS, connect timeout, request timeout
- Sets `User-Agent: plexd/{version}` on all requests
- Gzip-compresses request bodies larger than 1 KiB
- Transparently decompresses gzip responses

### Authentication

```go
client.SetAuthToken("node-identity-token")
```

Thread-safe via `sync.RWMutex`. The token is injected as `Authorization: Bearer {token}` on every request. Call `SetAuthToken` after registration to switch from bootstrap token to node identity token.

### API Methods

All methods accept a `context.Context` for cancellation and return typed responses.

| Method                | HTTP            | Path                                              | Request Type         | Response Type         |
|-----------------------|-----------------|---------------------------------------------------|----------------------|-----------------------|
| `Register`            | `POST`          | `/v1/register`                                    | `RegisterRequest`    | `*RegisterResponse`   |
| `Heartbeat`           | `POST`          | `/v1/nodes/{node_id}/heartbeat`                   | `HeartbeatRequest`   | `*HeartbeatResponse`  |
| `Deregister`          | `POST`          | `/v1/nodes/{node_id}/deregister`                  | —                    | —                     |
| `FetchState`          | `GET`           | `/v1/nodes/{node_id}/state`                       | —                    | `*StateResponse`      |
| `ConnectSSE`          | `GET`           | `/v1/nodes/{node_id}/events`                      | —                    | `*http.Response`      |
| `RotateKeys`          | `POST`          | `/v1/keys/rotate`                                 | `KeyRotateRequest`   | `*KeyRotateResponse`  |
| `UpdateCapabilities`  | `PUT`           | `/v1/nodes/{node_id}/capabilities`                | `CapabilitiesPayload`| —                     |
| `ReportEndpoint`      | `PUT`           | `/v1/nodes/{node_id}/endpoint`                    | `EndpointReport`     | `*EndpointResponse`   |
| `ReportDrift`         | `POST`          | `/v1/nodes/{node_id}/drift`                       | `DriftReport`        | —                     |
| `FetchSecret`         | `GET`           | `/v1/nodes/{node_id}/secrets/{key}`               | —                    | `*SecretResponse`     |
| `SyncReports`         | `POST`          | `/v1/nodes/{node_id}/report`                      | `ReportSyncRequest`  | —                     |
| `AckExecution`        | `POST`          | `/v1/nodes/{node_id}/executions/{id}/ack`         | `ExecutionAck`       | —                     |
| `ReportResult`        | `POST`          | `/v1/nodes/{node_id}/executions/{id}/result`      | `ExecutionResult`    | —                     |
| `ReportMetrics`       | `POST`          | `/v1/nodes/{node_id}/metrics`                     | `MetricBatch`        | —                     |
| `ReportLogs`          | `POST`          | `/v1/nodes/{node_id}/logs`                        | `LogBatch`           | —                     |
| `ReportAudit`         | `POST`          | `/v1/nodes/{node_id}/audit`                       | `AuditBatch`         | —                     |
| `FetchArtifact`       | `GET`           | `/v1/artifacts/plexd/{version}/{os}/{arch}`        | —                    | `io.ReadCloser`       |

### Generic Helpers

```go
func (c *ControlPlane) Ping(ctx context.Context) error
func (c *ControlPlane) PostJSON(ctx context.Context, path string, body any, result any) error
func (c *ControlPlane) GetJSON(ctx context.Context, path string, result any) error
```

## Error Types

HTTP errors are mapped to structured `*APIError` values supporting `errors.Is` and `errors.As`.

| Sentinel           | Status | Description                          |
|--------------------|--------|--------------------------------------|
| `ErrBadRequest`    | 400    | Invalid request                      |
| `ErrUnauthorized`  | 401    | Authentication failure               |
| `ErrForbidden`     | 403    | Access denied (permanent)            |
| `ErrNotFound`      | 404    | Resource not found (permanent)       |
| `ErrConflict`      | 409    | Conflict                             |
| `ErrPayloadTooLarge`| 413   | Request body too large               |
| `ErrRateLimit`     | 429    | Rate limited (has `RetryAfter`)      |
| `ErrServer`        | 5xx    | Server error (matches any 5xx)       |

```go
resp, err := client.FetchState(ctx, nodeID)
if errors.Is(err, api.ErrUnauthorized) {
    // re-authenticate
} else if errors.Is(err, api.ErrRateLimit) {
    var apiErr *api.APIError
    errors.As(err, &apiErr)
    time.Sleep(apiErr.RetryAfter)
}
```

## SSEManager

`SSEManager` is the top-level orchestrator that wires together SSE streaming, reconnection, verification, and event dispatching.

### Lifecycle

```go
logger := slog.Default()
mgr := api.NewSSEManager(client, nil, logger) // nil verifier = NoOpVerifier

// Register handlers before Start
mgr.RegisterHandler("peer_added", func(ctx context.Context, env api.SignedEnvelope) error {
    // handle peer addition
    return nil
})
mgr.RegisterHandler("policy_updated", func(ctx context.Context, env api.SignedEnvelope) error {
    // handle policy change
    return nil
})

// Start blocks until context cancelled, Shutdown called, or permanent error
ctx, cancel := context.WithCancel(context.Background())
go func() {
    if err := mgr.Start(ctx, nodeID); err != nil {
        log.Printf("SSE manager stopped: %v", err)
    }
}()

// Later: graceful shutdown
mgr.Shutdown()
```

### Methods

| Method                 | Description                                                    |
|------------------------|----------------------------------------------------------------|
| `NewSSEManager`        | Creates manager with client, optional verifier, logger         |
| `RegisterHandler`      | Registers an event handler by type (call before `Start`)       |
| `Start(ctx, nodeID)`   | Blocking SSE loop with automatic reconnection                  |
| `Shutdown()`           | Cancels internal context, causes `Start` to return             |
| `SetPollFunc(fn)`      | Overrides the default polling function (`FetchState`)          |
| `SetReconnectIntervals`| Configures backoff base and max intervals                      |
| `SetPollingFallback`   | Configures polling fallback threshold and interval             |

## EventVerifier

Pluggable interface for verifying signed event envelopes. The default `NoOpVerifier` accepts all events. A concrete Ed25519 implementation will be provided by feature S010.

```go
type EventVerifier interface {
    Verify(ctx context.Context, envelope SignedEnvelope) error
}
```

## EventDispatcher

Routes verified events to registered handlers by `event_type`.

- Multiple handlers per event type (invoked sequentially in registration order)
- Handler errors are logged but do not block subsequent handlers
- Unhandled event types are logged at debug level and discarded
- Thread-safe handler registration via `sync.RWMutex`

## Event Type Constants

All 12 SSE event types from the control plane:

| Constant                    | Value                     |
|-----------------------------|---------------------------|
| `EventPeerAdded`            | `peer_added`              |
| `EventPeerRemoved`          | `peer_removed`            |
| `EventPeerKeyRotated`       | `peer_key_rotated`        |
| `EventPeerEndpointChanged`  | `peer_endpoint_changed`   |
| `EventPolicyUpdated`        | `policy_updated`          |
| `EventActionRequest`        | `action_request`          |
| `EventSessionRevoked`       | `session_revoked`         |
| `EventSSHSessionSetup`      | `ssh_session_setup`       |
| `EventRotateKeys`           | `rotate_keys`             |
| `EventSigningKeyRotated`    | `signing_key_rotated`     |
| `EventNodeStateUpdated`     | `node_state_updated`      |
| `EventNodeSecretsUpdated`   | `node_secrets_updated`    |

## ReconnectEngine

Manages SSE reconnection with exponential backoff and polling fallback.

### Backoff Parameters

| Parameter       | Default | Description                           |
|-----------------|---------|---------------------------------------|
| Base interval   | 1s      | Initial backoff delay                 |
| Multiplier      | 2x      | Exponential growth factor             |
| Max interval    | 60s     | Backoff cap                           |
| Jitter          | ±25%    | Random variation on each delay        |
| Polling fallback| 5 min   | Time before switching to polling      |
| Poll interval   | 60s     | How often to poll during fallback     |

### Failure Classification

| Error Type         | Action                                          |
|--------------------|-------------------------------------------------|
| Network / 5xx      | `RetryTransient` — exponential backoff          |
| 401 Unauthorized   | `RetryAuth` — invoke callback, stop             |
| 429 Rate Limited   | `RespectServer` — use Retry-After header        |
| 403 / 404          | `PermanentFailure` — stop reconnection          |

### State Machine

```
Disconnected → Connecting → Connected → (drop) → Connecting
                         ↘ Backoff → Connecting
                                   ↘ Polling → Connecting (periodic SSE retry)
```

## SSE Parser

W3C-compliant `text/event-stream` line protocol parser.

- Handles `event:`, `data:`, `id:`, `retry:` fields
- Multi-line `data:` fields concatenated with `\n`
- Comment lines (`:` prefix) ignored (used as keepalives)
- Tracks `Last-Event-ID` for reconnection replay
- `retry:` field updates reconnection interval via callback

## SSE Stream

`SSEStream` wraps the parser with HTTP connectivity, envelope parsing, verification, and dispatching.

- Connects via `ControlPlane.ConnectSSE` with `Accept: text/event-stream`
- Sends `Last-Event-ID` header on reconnection
- Parses each `data:` payload as a `SignedEnvelope`
- Passes envelope through `EventVerifier` before dispatching
- Malformed events are logged and skipped without disconnecting
