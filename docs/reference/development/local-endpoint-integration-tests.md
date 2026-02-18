---
title: Local Endpoint Integration Tests
package: internal/metrics, internal/logfwd, internal/auditfwd
feature: PXD-0048
---

# Local Endpoint Integration Tests

Integration tests that validate the full path from `LocalEndpoint` configuration through credential resolution to dual HTTP delivery across all three observability pipelines (metrics, logfwd, auditfwd). These tests catch wiring bugs that unit tests cannot detect — for example, incorrect parameter passing in `up.go` or mismatched interface implementations.

## Running the Tests

```bash
# All three pipelines
go test -race ./internal/metrics/ ./internal/logfwd/ ./internal/auditfwd/ -run TestIntegration

# Single pipeline
go test -race ./internal/metrics/ -run TestIntegration

# Skip integration tests (short mode)
go test -short ./internal/metrics/
```

All integration tests check `testing.Short()` and skip automatically when `-short` is passed.

## Test Infrastructure

Each pipeline's `integration_test.go` is a white-box test (same package) to access internal types like `mockSecretFetcher`, `testNSK()`, and `encryptTestSecret()`.

### HTTP Capture

A thread-safe HTTP request recorder used for the local endpoint mock:

```go
type httpCapture struct {
    mu       sync.Mutex
    requests []capturedRequest
}

type capturedRequest struct {
    Method      string
    ContentType string
    Auth        string
    Body        []byte
}
```

The `handler(status int)` method returns an `http.Handler` that records every request and responds with the given status code. Each pipeline has its own prefixed variant (`logHTTPCapture`, `auditHTTPCapture`) to avoid name collisions.

### Mock Servers

Tests use `httptest.NewTLSServer` for the local endpoint mock. This provides self-signed TLS certificates, which enables testing both `TLSInsecureSkipVerify=true` (successful connection) and `TLSInsecureSkipVerify=false` (TLS handshake failure).

The platform reporter uses an in-memory mock (`mockReporter`/`mockLogReporter`/`mockAuditReporter`) rather than an HTTP server, since integration tests focus on verifying the local endpoint wiring path.

### Credential Helpers

Each pipeline reuses the `testNSK()` and `encryptTestSecret()` helpers from `local_reporter_test.go` to create properly encrypted secret responses:

```go
fetcher := newTestFetcher("my-bearer-token")  // metrics
fetcher := newLogTestFetcher("my-bearer-token")  // logfwd
fetcher := newAuditTestFetcher("my-bearer-token")  // auditfwd
```

These construct a `mockSecretFetcher` with a pre-encrypted `api.SecretResponse` that decrypts to the given plaintext token.

### Polling Helper

`waitFor(t, timeout, cond, msg)` polls a condition function at 5ms intervals until it returns true or the timeout expires. Used to wait for asynchronous batch delivery in tests that run the full `Manager.Run` / `Forwarder.Run` loop.

## Test Coverage Matrix

| Scenario | Metrics | LogFwd | AuditFwd | Requirements |
|----------|---------|--------|----------|--------------|
| Dual delivery happy path (full run loop) | `TestIntegration_DualDelivery_BothReceiveSameBatch` | `TestIntegration_DualDelivery_BothReceiveSameLogBatch` | `TestIntegration_DualDelivery_BothReceiveSameAuditBatch` | REQ-001, REQ-003, REQ-008 |
| Credential resolution (bearer token in header) | `TestIntegration_DualDelivery_CredentialResolution` | `TestIntegration_DualDelivery_CredentialResolution` | `TestIntegration_DualDelivery_CredentialResolution` | REQ-005, REQ-008 |
| Platform-only when URL empty | `TestIntegration_PlatformOnly_WhenURLEmpty` | — | — | REQ-002 |
| Conditional wiring pattern | `TestIntegration_ConditionalWiring_Pattern` | — | — | REQ-002 |
| Local endpoint returns HTTP 500 | `TestIntegration_LocalDown_PlatformUnaffected` | — | — | REQ-004, REQ-009 |
| Local HTTP 500 with full run loop | `TestIntegration_LocalHTTP500_PlatformUnaffected` | `TestIntegration_LocalDown_PlatformReceivesLogs` | `TestIntegration_LocalDown_PlatformReceivesAudit` | REQ-004, REQ-009 |
| Credential failure, platform unaffected | `TestIntegration_CredentialFailure_PlatformStillReceives` | `TestIntegration_CredentialFailure_LogFwd` | `TestIntegration_CredentialFailure_AuditFwd` | REQ-005, REQ-009 |
| TLS skip-verify succeeds (self-signed) | `TestIntegration_TLSSkipVerify_SelfSignedSucceeds` | `TestIntegration_TLSSkipVerify_LogFwd` | `TestIntegration_TLSSkipVerify_AuditFwd` | REQ-006, REQ-010 |
| TLS strict verify rejects self-signed | `TestIntegration_TLSStrictVerify_SelfSignedFails` | `TestIntegration_TLSStrictVerify_LogFwd` | `TestIntegration_TLSStrictVerify_AuditFwd` | REQ-006, REQ-010 |

The metrics pipeline carries extra coverage for platform-only wiring (REQ-002) and the conditional wiring pattern from `up.go` since the pattern is identical across all three pipelines.

## Test Patterns

### Dual Delivery (Full Run Loop)

Tests that validate the complete collection → buffer → flush → dual delivery path:

1. Create `httptest.NewTLSServer` with `httpCapture` for the local endpoint
2. Create an in-memory `mockReporter` for the platform
3. Wire `LocalReporter` → `MultiReporter` wrapping both
4. Configure `Manager`/`Forwarder` with short intervals (25ms collect, 60ms report)
5. Run in a goroutine with `context.WithCancel`
6. Poll with `waitFor` until both targets receive at least one batch
7. Cancel context and drain the goroutine
8. Assert identical batch sizes and valid JSON payloads

### Error Isolation

Tests that verify platform delivery is unaffected by local failures:

1. Configure the local mock to return HTTP 500 (or use a failing `mockSecretFetcher`)
2. Call `ReportMetrics`/`ReportLogs`/`ReportAudit` via `MultiReporter`
3. Assert return value is `nil` (platform succeeded)
4. Assert platform mock received exactly one call
5. For credential failures: assert local mock received zero requests (no HTTP POST without a token)

### TLS Skip-Verify

Tests that exercise real TLS behavior using `httptest.NewTLSServer` (self-signed certs):

- **`skip_verify=true`**: `LocalReporter` creates its own `http.Client` with `InsecureSkipVerify=true` → POST succeeds
- **`skip_verify=false`**: Default `http.Client` rejects the self-signed cert → TLS handshake fails, local capture count is 0, platform is unaffected

### Conditional Wiring Pattern

Validates the exact wiring logic from `up.go`:

```go
var reporter MetricsReporter = platform
if cfg.LocalEndpoint.URL != "" {
    local := NewLocalReporter(cfg.LocalEndpoint, fetcher, nsk, nodeID, logger)
    reporter = NewMultiReporter(platform, local, logger)
}
```

The test asserts the resulting type: `*MultiReporter` when URL is configured, `*mockReporter` (the platform directly) when URL is empty.

## File Locations

| File | Contents |
|------|----------|
| `internal/metrics/integration_test.go` | 9 integration tests covering all scenarios for the metrics pipeline |
| `internal/logfwd/integration_test.go` | 7 integration tests for log forwarding dual delivery |
| `internal/auditfwd/integration_test.go` | 7 integration tests for audit forwarding dual delivery |

## Design Decisions

**White-box tests (same package)**: Integration tests are in the same package as the production code to reuse internal helpers (`testNSK`, `encryptTestSecret`, `discardLogger`, mock types). This avoids duplicating cryptographic test infrastructure across packages.

**In-memory platform mock**: The platform reporter uses a simple struct with a mutex-protected call slice rather than an HTTP server. This keeps tests focused on the local endpoint path — the platform HTTP transport is already tested in `api/` package tests.

**Short ticker intervals**: Tests use 25ms collect and 60ms report intervals to keep integration tests fast (< 3s). The `waitFor` helper provides a 3-second safety timeout.

**`-short` skip**: All integration tests respect `testing.Short()` so that quick CI feedback loops can skip the heavier tests when needed.
