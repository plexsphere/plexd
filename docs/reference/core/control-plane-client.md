---
title: Control Plane Client
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
| `RequestTimeout`        | `time.Duration` | `30s`   | Full HTTP request/response timeout; bounds only the setup of the SSE stream |
| `SSEIdleTimeout`        | `time.Duration` | `90s`   | Max idle time before SSE reconnect; the only bound on an open stream. Must not be negative |
| `SSEReprobeInterval`    | `time.Duration` | `10m`   | How often pull-only delivery re-probes a descoped SSE endpoint |

```go
cfg := api.Config{
    BaseURL:               "https://api.plexsphere.com",
    TLSInsecureSkipVerify: false,
}
cfg.ApplyDefaults() // sets zero-valued timeouts to defaults
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

## ControlPlane

`ControlPlane` is the core HTTP client. It manages authentication, JSON serialization, request/response compression, and error mapping.

### Constructor

```go
func NewControlPlane(cfg Config, version string, logger *slog.Logger) (*ControlPlane, error)
```

- Applies config defaults and validates
- Configures TLS, connect timeout, request timeout (`ConnectSSE` sends through a copy without the request timeout, see [SSE Stream](#sse-stream))
- Sets `User-Agent: plexd/{version}` on all requests
- Gzip-compresses request bodies larger than 1 KiB **on the three observability ingest operations only** — they are the ones whose contract accepts `Content-Encoding: gzip`. Every other handler decodes the body as it arrives, so a compressed one is read as JSON and refused with `400`, naming the gzip magic byte as `invalid character '\x1f'`.
- Transparently decompresses gzip responses

### Authentication

```go
bearer, err := identity.BearerToken()
// ...
client.SetAuthToken(bearer)
```

Thread-safe via `sync.RWMutex`. The token is injected as `Authorization: Bearer {token}` on every request. After registration the registrar arms the client with the NSK bearer envelope (`nsk_<env>_<base64url(node_id || nsk)>`, see the [registration reference](registration.md#bearertoken)) — never the raw NSK, which the control plane refuses with `401`.

The registrar is the sole owner of this credential: it arms the client on both of its paths (resumed identity and fresh registration), and no other production code calls `SetAuthToken`. One client is shared by every post-registration consumer — heartbeat, SSE, reconciler, key rotator, peer exchange, actions, node API, and the platform reporters — so a later assignment does not degrade one caller, it mutes all of them at once.

When the heartbeat parks on a credential the control plane keeps refusing, `plexd up` marks the client with `SetCredentialRefused(true)` through the heartbeat's credential-refused callback (see [Heartbeat Service](heartbeat-service.md#credential-park)), and `CredentialRefused()` reports the mark. While it is set, every request that would present the bearer fails with `ErrCredentialRefused` before any I/O: `newRequest` checks the mark first, and `ConnectSSE`, which builds its own request, checks it too. Three calls pass: `POST /v1/register` carries no bearer, `UploadExecutionOutput` sends to a presigned URL without the bearer, and the heartbeat is the probe whose acceptance clears the mark again. `ErrCredentialRefused` is not an `*APIError`, so `errors.Is(err, ErrUnauthorized)` is false for it.

### API Methods

All methods accept a `context.Context` for cancellation and return typed responses.

| Method                | HTTP            | Path                                              | Request Type         | Response Type         |
|-----------------------|-----------------|---------------------------------------------------|----------------------|-----------------------|
| `Register`            | `POST`          | `/v1/register`                                    | `RegisterRequest`    | `*RegisterResponse`   |
| `Heartbeat`           | `POST`          | `/v1/nodes/{node_id}/heartbeat`                   | `HeartbeatRequest`   | `*HeartbeatResponse`  |
| `FetchState`          | `GET`           | `/v1/nodes/{node_id}/state`                       | —                    | `*NodeStateSnapshot`  |
| `ConnectSSE`          | `GET`           | `/v1/nodes/{node_id}/events`                      | —                    | `*http.Response`      |
| `RotateKeys`          | `POST`          | `/v1/keys/rotate`                                 | `KeyRotateRequest`   | `*KeyRotateResponse`  |
| `UpdateCapabilities`  | `PUT`           | `/v1/nodes/{node_id}/capabilities`                | `CapabilityManifestRequest`| —               |
| `ReportEndpoint`      | `PUT`           | `/v1/nodes/{node_id}/endpoint`                    | `EndpointRequest`    | `*EndpointResponse`   |
| `ReportEndpointCandidates` | `PUT`      | `/v1/nodes/{node_id}/endpoint-candidates`          | `EndpointCandidatesRequest` | `*EndpointCandidatesResponse` |
| `FetchSecret`         | `GET`           | `/v1/nodes/{node_id}/secrets/{name}` (optional `?version=N`) | —          | `*SecretEnvelope`     |
| `FetchEdgePSK`        | `GET`           | `/v1/nodes/{node_id}/peers/{peer_node_id}/psk`     | —                    | `*EdgePSKEnvelope`    |
| `PutStateReport`      | `PUT`           | `/v1/nodes/{node_id}/state/reports/{key}`          | `NodeStateReportRequest` | `*NodeStateReportResponse` |
| `DeleteStateReport`   | `DELETE`        | `/v1/nodes/{node_id}/state/reports/{key}`          | —                    | — (`204 No Content`)  |
| `ExecutionCallback`   | `POST`          | `/v1/nodes/{node_id}/executions/{execution_id}`    | `ExecutionCallbackRequest` | `*ExecutionCallbackResponse` |
| `UploadExecutionOutput` | `PUT`         | presigned URL (no bearer token)                    | `[]byte`             | —                     |
| `ReportMetrics`       | `POST`          | `/v1/nodes/{node_id}/metrics`                     | `[]MetricSample` (JSON array) | `*IngestReceipt`   |
| `ReportLogs`          | `POST`          | `/v1/nodes/{node_id}/logs`                        | `[]LogLine` (NDJSON)  | `*IngestReceipt`      |
| `ReportAudit`         | `POST`          | `/v1/nodes/{node_id}/audit`                       | `[]AuditEvent` (NDJSON)| `*IngestReceipt`     |
| `ReportSessionActivity` | `POST`        | `/v1/nodes/{node_id}/sessions/{session_id}`        | `SessionActivityRequest` | — (`204 No Content`) |
| `ReportIntegrityViolations` | `POST`    | `/v1/nodes/{node_id}/integrity-violations`         | `IntegrityViolationsRequest` | —            |
| `ReportHandshakes`    | `POST`          | `/v1/nodes/{node_id}/handshakes`                   | `HandshakeReportRequest` | `*HandshakeReportResponse` |

`FetchEdgePSK` takes the node ID and the peer's node ID, path-escapes both, and returns the envelope only when the body is exactly `EdgePSKEnvelopeSize` (60) bytes and both the `X-Plexsphere-PSK-KID` and `X-Plexsphere-PSK-Epoch` headers are present. The body is key material, so no error it returns quotes it. See [API Types](api-types.md#edge-psk) for the envelope.

`ReportEndpointCandidates` path-escapes the node ID and sends a nil `Candidates` as `[]`, on a copy, because the contract refuses `null`. A report with more than `MaxEndpointCandidates` (8) entries returns `api: report endpoint candidates: <n> candidates:` wrapping `ErrEndpointCandidatesTooMany`, without a request. See [API Types](api-types.md#endpoint-candidates).

### Generic Helpers

```go
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
    // the credential was refused; only the heartbeat decides whether to
    // park (see Authentication)
} else if errors.Is(err, api.ErrCredentialRefused) {
    // no request was sent; retry on the next cycle
} else if errors.Is(err, api.ErrRateLimit) {
    var apiErr *api.APIError
    errors.As(err, &apiErr)
    time.Sleep(apiErr.RetryAfter)
}
```

`IsSessionRevokedOrExpired(err error) bool` classifies the answers to `ReportSessionActivity`. It extracts the `*APIError` with `errors.As`, so a wrapped error is classified too, and reports true for a `409` carrying `session_already_revoked` or `session_expired`. Everything else is false, including a `400` `malformed_session_activity`, which is a verdict on the row rather than on the session; a `501` `access_session_not_provisioned`, which faults the callback endpoint rather than the session, and that endpoint may be provisioned mid-session; and a `404` `session_not_found`, which is not a terminal state but the `sessions` block and the session store disagreeing — two separate reads, so a lagging replica or a record written after the block was rendered produces it, and the entry standing in the block is the control plane still asking for the session. All three stay retryable. A true answer is the control plane's verdict that the session has reached a terminal state, and the node reads it as the drain signal: the entry leaves the `sessions` block on a following pull and the block drain performs the teardown. The answer itself never closes a session.

`IsHandshakeReportNotServed(err error) bool` classifies the answers to `ReportHandshakes`. It is true for an `*APIError` with status `404`, whatever its code, and for a `501` carrying `handshakes_not_provisioned`: both mean the control plane does not serve the operation yet. Everything else is false, including a `501` with another code. The [handshake reporter](heartbeat-service.md#handshake-reporter) logs a true answer once at Info and keeps reporting every interval.

`IsEdgePSKNotServed(err error) bool` classifies the answers to `FetchEdgePSK`. It is true for an `*APIError` with status `404` and any code but `peer_not_found`, and for a `501` carrying `psk_delivery_not_provisioned`: a control plane older than the operation has no route for it, and its router answers `404` with whatever code its not-found handler writes. A `404` `peer_not_found` is the operation's own answer while the peer has not landed in the Domain yet, so it is false, and the [edge PSK store](../networking/wireguard.md#edge-psks) retries it on the next pull. The store logs a true answer once at Info and sends at most one request per pull until the control plane serves edge PSKs.

`IsEndpointCandidatesNotServed(err error) bool` classifies the answers to `ReportEndpointCandidates`. It is true for an `*APIError` with status `404` and any code but `endpoint_peer_not_found`, and for a `501` carrying `endpoint_candidates_not_provisioned`: a control plane older than the operation has no route for it, and its router answers `404` with whatever its not-found handler writes. A `404` `endpoint_peer_not_found` is the operation's own answer when the node reports before the control plane has registered it as a peer, which a later cycle heals, so it is false. The [candidate publisher](../networking/nat-traversal.md#local-endpoint-candidates) logs a true answer once at Info and keeps reporting every cycle.

`APIError.CorrelationID` carries the `correlation_id` member of the control plane's problem document; when the document has no id, the client falls back to the `X-Correlation-Id` header of that same response. Both sources are read only from an `application/problem+json` response, so an id minted by a proxy or gateway that answered in place of the control plane is not presented as a control-plane id. The header itself is not authenticated, so that gate is the whole guarantee: a tracing proxy that passes the control plane's problem document through untouched and stamps its own `X-Correlation-Id` on it is indistinguishable, and a fallback id may be that proxy's request id rather than one the control-plane log keys. The field also stays empty for an id longer than 256 bytes, which is dropped rather than truncated because a truncated id keys nothing, and any unprintable rune is stripped — from the message the error string renders alongside the id as well — so a hostile intermediary cannot forge a log line or emit a terminal escape through the error string. `APIError.Code`, the third response-derived field the error string renders, is guarded by rejection rather than stripping: a code longer than 128 bytes or carrying any unprintable rune is dropped whole, because stripping a rune out of it could collapse a forged code onto a live one the classifiers branch on. A set id is appended to the error string as a trailing ` (correlation_id=...)` segment, so every logged failure line carries it. The id keys the control-plane log, so an operator can quote it there.

## SSEManager

`SSEManager` is the top-level orchestrator that wires together SSE streaming, reconnection, verification, and event dispatching.

### Lifecycle

```go
logger := slog.Default()
mgr := api.NewSSEManager(client, nil, logger) // nil verifier = NoOpVerifier

// Register handlers before Start
mgr.RegisterHandler("node_state_updated", func(ctx context.Context, env api.Envelope) error {
    // request a reconcile — the state pull is authoritative
    return nil
})
mgr.RegisterHandler("policy_updated", func(ctx context.Context, env api.Envelope) error {
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
| `SetIdleTimeout(d)`    | Sets the SSE idle timeout used for connections opened by `Start` |
| `SetReprobeInterval(d)`| Sets how often pull-only mode re-probes the SSE endpoint (non-positive ignored) |
| `SetReconcileTrigger(t)`| Sets the trigger fired once after every successful SSE connect to cover replay gaps |
| `Mode()`               | Returns the current `DeliveryMode` (`streaming`, `pull_only`, `degraded_polling`) |
| `SetOnModeChange(fn)`  | Registers a callback invoked on every delivery-mode transition |

## EventVerifier

Pluggable interface for verifying signed event envelopes. The default `NoOpVerifier` accepts all events; the production `Ed25519Verifier` checks the signature.

```go
type EventVerifier interface {
    Verify(ctx context.Context, envelope Envelope) error
}
```

`Ed25519Verifier` is keyed by signing key id: it is built from the persisted `signing_key_id`/`signing_public_key` (the key registration returned, or a key a state pull installed later) and selects the verifying key by the envelope's `key_id`. The current key id is always accepted; a previous key id is accepted only during the rotation grace window (until `transition_expires`). The `signing_key_rotated` event installs a new current key via `Rotate`. `Install(key NodeStateSigningKey) (bool, error)` applies the `signing_key` block of a state pull: a key whose id and bytes equal the current pair changes nothing, and any other key replaces the current key and drops the grace entry, because a node trusts exactly one key of its Domain. `plexd up` calls it from a [dispatch handler](reconciliation.md#registered-dispatch-handlers) on every successful pull, keeps the installed key when the block is `null` or `Install` refuses the pulled key, and persists an accepted key that differs from the one on disk with `registration.CommitSigningKey`, so a restart starts from it. The signature covers `SignedMessage(env)`, the 64-byte SHA-512 digest of `CanonicalBytes(env)`, not the canonical bytes themselves. See [Event Verification](event-verification.md) for the full envelope shape, canonical form, staleness window, and rotation rules.

## EventDispatcher

Routes verified events to registered handlers by the envelope's `type`.

- Multiple handlers per event type (invoked sequentially in registration order)
- Handler errors are logged but do not block subsequent handlers
- Unhandled event types are logged at debug level and discarded
- Thread-safe handler registration via `sync.RWMutex`

## Event Type Constants

The SSE event set is organized in two tiers. Payloads of the reconcile-driving
types are opaque: the reconciler's state pull is authoritative, so those events
only request a reconcile.

**Contract** — currently emitted by the control plane per the OpenAPI events document:

| Constant                   | Value                   | Dispatch target                             |
|----------------------------|-------------------------|---------------------------------------------|
| `EventNodeStateUpdated`    | `node_state_updated`    | `TriggerReconcile()`                        |
| `EventPolicyUpdated`       | `policy_updated`        | `policy.HandlePolicyUpdated` → reconcile    |
| `EventBridgeConfigUpdated` | `bridge_config_updated` | `bridge.HandleBridgeConfigUpdated` → reconcile |
| `EventActionRequest`       | `action_request`        | `TriggerReconcile()`                        |
| `EventSessionSetup`        | `session_setup`         | `TriggerReconcile()`                        |
| `EventPeerEndpointChanged` | `peer_endpoint_changed` | `TriggerReconcile()`                        |

`action_request` carries no dispatch of its own: action executions are delivered
in the `executions` block of the state pull, so the event only pulls the next
reconcile forward and the resulting pull carries the dispatch. `session_setup` is
the same optimisation for mediated access: the session is delivered in the
`sessions` block of that pull, and the event only pulls it forward.
`peer_endpoint_changed` works the same way for peer endpoints: each peer's direct
endpoint rides the `peers` block of the state pull as `SnapshotPeer.Endpoint`, and
plexd never decodes the event's payload.

**Documented-coming** — named now so the agent can subscribe once the platform's 14-type taxonomy starts emitting them:

| Constant                   | Value                   | Dispatch target             |
|----------------------------|-------------------------|-----------------------------|
| `EventPeerRegistered`      | `peer_registered`       | `TriggerReconcile()`        |
| `EventPeerPSKAssigned`     | `peer_psk_assigned`     | `TriggerReconcile()`        |
| `EventPeerDeregistered`    | `peer_deregistered`     | `TriggerReconcile()`        |
| `EventPeerKeyRotated`      | `peer_key_rotated`      | `TriggerReconcile()`        |
| `EventRotateKeys`          | `rotate_keys`           | key rotator's `RotateNow`   |
| `EventSigningKeyRotated`   | `signing_key_rotated`   | `Ed25519Verifier.Rotate`    |
| `EventSessionRevoked`      | `session_revoked`       | `TriggerReconcile()`        |

`session_revoked` carries no teardown of its own: a session leaving the `sessions`
block of the state pull is what closes it, so the event only pulls the observing
reconcile forward.

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

| Error Type                                | Action                                          |
|-------------------------------------------|-------------------------------------------------|
| Network / 5xx                             | `RetryTransient` — exponential backoff          |
| 401 Unauthorized                          | `RetryAuth` — invoke callback, stop             |
| 429 Rate Limited                          | `RespectServer` — use Retry-After header        |
| 403 / 404                                 | `PermanentFailure` — stop reconnection          |
| 501 `signed_event_bus_not_provisioned`    | `RetryDescoped` — switch to pull-only delivery  |
| `ErrCredentialRefused`                    | `RetryAuth` — invoke callback, stop             |

`ErrCredentialRefused` is classified ahead of the check for an `*APIError`, which would otherwise read it as a transient network error. It stands for the `401` the heartbeat already saw, so the stream stops on it as on a `401` instead of backing off into the polling fallback.

A 501 carrying `signed_event_bus_not_provisioned` is classified ahead of the generic 5xx match: it is a durable descope of the event stream, not a transient error, so it is answered by pull-only delivery rather than backoff. A 501 with any other code, a 503 `event_stream_unavailable`, and network errors stay on the transient path.

### Delivery Modes

`SSEManager.Mode()` reports which channel currently delivers control-plane state, and `SetOnModeChange` fires on every transition:

| Mode               | Meaning                                                                                     |
|--------------------|---------------------------------------------------------------------------------------------|
| `streaming`        | The SSE event stream is attached and live.                                                  |
| `pull_only`        | The event stream is descoped (`RetryDescoped`). The engine stops polling entirely; the reconciler's own loop is the delivery channel, and SSE is re-probed once per `SSEReprobeInterval` (default 10m). |
| `degraded_polling` | The legacy transient fallback: after 5 minutes of failing SSE, the engine polls state every 60s while re-probing SSE. |

On a descope the engine enters `pull_only` immediately, with no backoff and no 5-minute polling-fallback window. A successful re-probe returns to `streaming` and resets backoff. During pull-only re-probes, auth failures and 403/404 still propagate as permanent; any other error keeps the engine in pull-only at the re-probe cadence.

### Reconnect-Triggered Pull and Cursor Reset

The server replays only sequences strictly greater than the client's `Last-Event-ID` cursor and never backfills an absent cursor. The client covers gaps itself: `SetReconcileTrigger` fires exactly one `TriggerReconcile()` after every successful SSE connect (HTTP 200). On a 400 while a cursor was set, the stream clears the cursor so the next connect tails from now — the reconcile pull covers the gap. The cursor is in-memory only, so a restart tails from now and the reconciler's first cycle covers the gap.

### State Machine

```mermaid
stateDiagram-v2
    [*] --> Disconnected
    Disconnected --> Connecting
    Connecting --> Connected
    Connecting --> Backoff : transient error
    Connecting --> PullOnly : 501 descope
    Connected --> Connecting : connection dropped
    Backoff --> Connecting : delay elapsed
    Backoff --> Polling : threshold exceeded (5 min)
    Polling --> Connecting : periodic SSE retry
    PullOnly --> Connecting : re-probe (every SSEReprobeInterval)
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
- `RequestTimeout` bounds only the setup: the wait for the response headers and, on a non-2xx answer, the read of its problem body. Headers that do not arrive in time fail with `ErrSSEConnectTimeout`, which `ClassifyError` treats as `RetryTransient`. A problem body that stalls still yields the status as an `*APIError`; its `code` is lost if it had not arrived, so a stalled `501` is classified as transient rather than descoped. An open stream is not cut by `RequestTimeout`: it ends when the control plane closes it, when the caller's context ends, when the body is closed, or when no byte arrives within the idle timeout (`SSEIdleTimeout`, 90s by default). The control plane's keep-alive comments, every 25s, keep a healthy stream from going idle
- Sends `Last-Event-ID` header on reconnection
- Parses each `data:` payload as an `Envelope`
- Passes envelope through `EventVerifier` before dispatching
- Dispatches on the verified envelope's `type`, not the frame's `event:` field
- Malformed events are logged and skipped without disconnecting
