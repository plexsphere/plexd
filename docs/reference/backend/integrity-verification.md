---
title: Integrity Verification
quadrant: backend
package: internal/integrity
feature: PXD-0010
---

# Integrity Verification

The `internal/integrity` package verifies the integrity of the plexd binary and hook scripts using SHA-256 checksums. It computes checksums on startup, re-verifies periodically, verifies hook scripts before execution, and reports integrity violations to the control plane.

## Data Flow

```
Startup
   │
   ▼
┌─────────────────┐
│ Verifier.Run    │
│  VerifyBinary   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────┐
│ HashFile(binary)│────▶│ Store.Get   │
│ (crypto/sha256) │     │  (baseline) │
└────────┬────────┘     └──────┬──────┘
         │                     │
         ▼                     ▼
   ┌───────────────────────────────┐
   │        Compare checksums      │
   └──────────┬──────────┬─────────┘
              │          │
      match   │          │ mismatch
              ▼          ▼
        ┌─────────┐  ┌──────────────────┐
        │ Log OK  │  │ ViolationReporter│
        └─────────┘  │  .ReportViolation│
                     └──────────────────┘
                              │
                              ▼
                     POST /v1/nodes/{id}/
                       integrity/violations

   ─── periodic ticker at VerifyInterval ───
              │
              ▼
        Re-run VerifyBinary
```

### Startup Sequence

1. `Verifier.VerifyBinary` computes SHA-256 of the binary via `HashFile`
2. Loads baseline from `Store.Get(binaryPath)`
3. No baseline (first run): stores computed checksum via `Store.Set`, returns success
4. Match: logs info, returns success
5. Mismatch: logs error, reports violation via `ViolationReporter`, returns success (non-fatal)

### Periodic Re-verification

1. `Verifier.Run` starts a `time.Ticker` at `Config.VerifyInterval`
2. Each tick calls `VerifyBinary` to detect runtime tampering
3. Loop exits cleanly on context cancellation

### Hook Verification

1. `Verifier.VerifyHook` calls `VerifyFile` with `requireChecksum=true`
2. Empty expected checksum returns error (hooks must have a control-plane-provided checksum)
3. Match: returns `true` (safe to execute)
4. Mismatch: reports violation, returns `false` (must not execute)

## Config

`Config` holds integrity verification parameters.

| Field            | Type            | Default | Description                              |
|------------------|-----------------|---------|------------------------------------------|
| `Enabled`        | `bool`          | `true`  | Whether integrity verification is active |
| `BinaryPath`     | `string`        | —       | Path to the plexd binary to verify       |
| `HooksDir`       | `string`        | —       | Directory containing hook scripts        |
| `VerifyInterval` | `time.Duration` | `5m`    | Interval between periodic re-checks      |

```go
cfg := integrity.Config{
    BinaryPath: "/usr/local/bin/plexd",
}
cfg.ApplyDefaults() // Enabled=true, VerifyInterval=5m
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

`ApplyDefaults` uses zero-value detection: on a fully zero-valued `Config`, `VerifyInterval == 0` triggers all defaults including `Enabled = true`. If `VerifyInterval` is already set (indicating explicit construction), `Enabled` is left as-is.

### Validation Rules

| Field            | Rule                        | Error Message                                                         |
|------------------|-----------------------------|-----------------------------------------------------------------------|
| `VerifyInterval` | >= 30s when `Enabled=true`  | `integrity: config: VerifyInterval must be at least 30s when enabled` |

Validation is skipped entirely when `Enabled` is `false`.

## CheckResult

Outcome of a file integrity check.

```go
type CheckResult struct {
    Path     string // filesystem path that was verified
    Expected string // hex-encoded SHA-256 that was expected
    Actual   string // hex-encoded SHA-256 that was computed
    OK       bool   // true when Expected matches Actual (or baseline establishment)
}
```

## HashFile

Computes the SHA-256 checksum of a file using streaming I/O (`io.Copy` into `crypto/sha256`). Files are never loaded entirely into memory.

```go
func HashFile(path string) (string, error)
```

Returns the hex-encoded SHA-256 digest. Errors wrap `os.ErrNotExist` for missing files.

## VerifyFile

Computes SHA-256 and compares against an expected checksum.

```go
func VerifyFile(path, expectedChecksum string, requireChecksum bool) (CheckResult, error)
```

| `expectedChecksum` | `requireChecksum` | Behavior                                                |
|--------------------|-------------------|---------------------------------------------------------|
| non-empty          | any               | Compares computed hash against expected                 |
| empty              | `true`            | Returns error (`integrity: expected checksum is required`) |
| empty              | `false`           | Returns computed hash as baseline with `OK=true`        |

## Store

Persists known-good checksums as a JSON file (`checksums.json`) in the agent's data directory.

### Constructor

```go
func NewStore(dataDir string) (*Store, error)
```

Loads existing `checksums.json` or creates an empty store. Missing file on first run is not an error.

### Methods

| Method   | Signature                              | Description                                       |
|----------|----------------------------------------|---------------------------------------------------|
| `Get`    | `(path string) string`                 | Returns stored checksum or empty string            |
| `Set`    | `(path, checksum string) error`        | Updates checksum and persists atomically           |
| `Remove` | `(path string) error`                  | Removes entry and persists atomically              |

### Persistence

- Writes use `fsutil.WriteFileAtomic` for crash-safe persistence
- Concurrent access protected by `sync.RWMutex`
- File format: `{"<path>": "<hex-sha256>", ...}`

## ViolationReporter

Interface abstracting control plane violation reporting for testability.

```go
type ViolationReporter interface {
    ReportViolation(ctx context.Context, nodeID string, report api.IntegrityViolationReport) error
}
```

A production implementation wraps `api.ControlPlane.ReportIntegrityViolation`.

## Verifier

Central orchestrator for integrity verification.

### Constructor

```go
func NewVerifier(cfg Config, store *Store, reporter ViolationReporter, logger *slog.Logger) *Verifier
```

| Parameter  | Description                                |
|------------|--------------------------------------------|
| `cfg`      | Integrity verification configuration       |
| `store`    | Checksum persistence store                 |
| `reporter` | Violation reporter (control plane adapter) |
| `logger`   | Structured logger (`log/slog`)             |

Logger is tagged with `component=integrity`.

### Methods

| Method           | Signature                                                              | Description                                            |
|------------------|------------------------------------------------------------------------|--------------------------------------------------------|
| `VerifyBinary`   | `(ctx context.Context, nodeID string) error`                           | Verify binary against stored baseline                  |
| `VerifyHook`     | `(ctx context.Context, nodeID, hookPath, expectedChecksum string) (bool, error)` | Verify hook against control-plane checksum   |
| `BinaryChecksum` | `() string`                                                            | Thread-safe getter for last computed binary checksum   |
| `Run`            | `(ctx context.Context, nodeID string) error`                           | Periodic re-verification loop (blocks until cancelled) |

### VerifyBinary

1. Computes SHA-256 of `Config.BinaryPath` via `HashFile`
2. Updates `BinaryChecksum()` value under mutex
3. Loads baseline from `Store.Get`
4. No baseline: stores as new baseline via `Store.Set`
5. Match: logs info
6. Mismatch: logs error, reports violation via `ViolationReporter`

Violations are non-fatal: the agent continues running after reporting.

### VerifyHook

1. Calls `VerifyFile(hookPath, expectedChecksum, true)`
2. Empty expected checksum: returns error (hooks require a checksum from the control plane)
3. Match: returns `true` (hook is safe to execute)
4. Mismatch: reports violation, returns `false` (hook must not be executed)

### BinaryChecksum

Thread-safe getter protected by `sync.Mutex`. Returns empty string before any verification has run. Used for `HeartbeatRequest.BinaryChecksum`.

```go
heartbeat := api.HeartbeatRequest{
    BinaryChecksum: verifier.BinaryChecksum(),
}
```

### Run

When `Config.Enabled` is `false`, returns immediately. Otherwise starts a `time.Ticker` at `Config.VerifyInterval` and calls `VerifyBinary` on each tick. Blocks until the context is cancelled.

### Lifecycle

```go
logger := slog.Default()

store, err := integrity.NewStore(dataDir)
if err != nil {
    log.Fatal(err)
}

verifier := integrity.NewVerifier(cfg, store, reporter, logger)

// Initial verification
if err := verifier.VerifyBinary(ctx, nodeID); err != nil {
    log.Fatal(err)
}

// Periodic re-verification (blocks)
err := verifier.Run(ctx, nodeID)

// Hook verification before execution
ok, err := verifier.VerifyHook(ctx, nodeID, hookPath, expectedChecksum)
if !ok {
    // Do not execute hook
}
```

## API Types

Types defined in `internal/api` for integrity violation reporting.

### IntegrityViolationReport

```go
type IntegrityViolationReport struct {
    Type             string    `json:"type"`              // "binary" or "hook"
    Path             string    `json:"path"`              // file path
    ExpectedChecksum string    `json:"expected_checksum"` // expected hex SHA-256
    ActualChecksum   string    `json:"actual_checksum"`   // computed hex SHA-256
    Detail           string    `json:"detail"`            // human-readable description
    Timestamp        time.Time `json:"timestamp"`         // UTC detection time
}
```

**Endpoint**: `POST /v1/nodes/{node_id}/integrity/violations`

### HeartbeatRequest.BinaryChecksum

The `BinaryChecksum` field in `api.HeartbeatRequest` (line 47 of `types.go`) is populated from `Verifier.BinaryChecksum()`. This allows the control plane to track which binary version each node is running.

## Integration Points

### With api.ControlPlane

`api.ControlPlane.ReportIntegrityViolation` satisfies the `ViolationReporter` interface when wrapped in an adapter:

```go
type controlPlaneReporter struct {
    client *api.ControlPlane
}

func (r *controlPlaneReporter) ReportViolation(ctx context.Context, nodeID string, report api.IntegrityViolationReport) error {
    return r.client.ReportIntegrityViolation(ctx, nodeID, report)
}
```

### With internal/fsutil

`Store` uses `fsutil.WriteFileAtomic` for crash-safe checksum persistence. Concurrent readers never see a partially written file.

### With internal/registration

`Config.BinaryPath` is typically resolved from `os.Executable()` followed by `filepath.EvalSymlinks` during agent bootstrap, matching the pattern in `internal/registration`.

## Error Handling

| Scenario                       | Behavior                                        |
|--------------------------------|-------------------------------------------------|
| Binary file unreadable         | `VerifyBinary` returns error, logged at error   |
| Hook file unreadable           | `VerifyHook` returns error                      |
| Violation report fails         | Logged at warn level, agent continues           |
| Store persistence fails        | Error returned from `Set`/`Remove`              |
| Empty expected checksum (hook) | Error returned (hooks require checksum)         |
| Context cancelled              | `Run` loop exits cleanly, no goroutine leaks    |
| Disabled config                | `Run` returns immediately, no checksums computed|

## Logging

All log entries use `component=integrity`.

| Level   | Event                         | Keys                                     |
|---------|-------------------------------|------------------------------------------|
| `Info`  | Binary baseline established   | `path`, `checksum`                       |
| `Info`  | Binary verified               | `path`, `checksum`                       |
| `Info`  | Hook verified                 | `path`, `checksum`                       |
| `Info`  | Verification disabled         | —                                        |
| `Error` | Binary integrity violation    | `path`, `expected_checksum`, `actual_checksum` |
| `Error` | Hook integrity violation      | `path`, `expected_checksum`, `actual_checksum` |
| `Error` | Binary hash failed            | `path`, `error`                          |
| `Error` | Periodic verification failed  | `error`                                  |
| `Warn`  | Failed to report violation    | `error`                                  |
