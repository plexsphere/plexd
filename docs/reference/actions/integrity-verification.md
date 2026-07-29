---
title: Integrity Verification
package: internal/integrity
feature: PXD-0010
---

# Integrity Verification

The `internal/integrity` package verifies the integrity of the plexd binary, hook scripts, and the SSH host key. It computes checksums on startup, re-verifies periodically, verifies hook scripts before execution, and reports integrity violations to the control plane.

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
        ┌─────────┐  ┌───────────────────┐
        │ Log OK  │  │ ViolationReporter │
        └─────────┘  │  .ReportViolations│
                     └───────────────────┘
                              │
                              ▼
                     POST /v1/nodes/{id}/
                      integrity-violations

   ─── periodic ticker at VerifyInterval ───
              │
              ▼
   Re-run VerifyBinary, VerifyHooksDir,
             VerifyHostKey
```

### Startup Sequence

1. `Verifier.VerifyBinary` computes SHA-256 of the binary via `HashFile`
2. Loads baseline from `Store.Get(binaryPath)`
3. No baseline (first run): stores computed checksum via `Store.Set`, returns success
4. Match: logs info, returns success
5. Mismatch: logs error, reports violation via `ViolationReporter`, returns success (non-fatal)

### Periodic Re-verification

1. `Verifier.Run` starts a `time.Ticker` at `Config.VerifyInterval`
2. Each tick calls `VerifyBinary`, `VerifyHooksDir`, and `VerifyHostKey` to detect runtime tampering
3. Loop exits cleanly on context cancellation

### Host Key Verification

1. `Verifier.VerifyHostKey` parses the key at `Config.HostKeyPath` and renders its `SHA256:<base64>` fingerprint
2. No baseline (first run): stores the fingerprint via `Store.Set`
3. Match: logs info
4. Mismatch: logs error and reports an `ssh_host_key` violation

The check compares fingerprints rather than file digests, because the fingerprint identifies the key: the same key re-serialised produces different bytes and the same identity, and the identity is what a peer pins. An unset `HostKeyPath` or an absent file is a no-op, so a node that never started the tunnel reports nothing.

The SSH server keeps serving the key it loaded at startup, so a key that changes on disk under a running agent is the tamper signal this detects.

### Hook Verification

1. `Verifier.VerifyHook` calls `VerifyFile` with `requireChecksum=true`
2. Empty expected checksum returns error (hooks must have a digest pinned at discovery)
3. Match: returns `true` (safe to execute)
4. Mismatch: reports violation, returns `false` (must not execute)

The expected checksum is the digest the executor **pinned** the first time this
process discovered the hook, not the one `HookWatcher` last recomputed. It does
**not** come from the control plane — an action dispatch carries no checksum on
the wire — so this check answers "are these still the bytes the node discovered
and reported to the control plane?", catching a swap between discovery and
execution.

The pin matters because `HookWatcher` re-hashes a hook on every write and pushes
the new digest into the executor. Verifying against that live digest would
compare the file with a hash of itself and pass for any bytes on disk, so the
executor records a hook's digest once and never updates it: a hook whose bytes
change after discovery is refused, files a violation, and stays unrunnable until
the agent restarts and re-attests it. Changing a hook in place therefore requires
an agent restart before it can be dispatched again.

The pin is process-local, so re-attestation on restart is both the recovery path
for a legitimate hook change and the limit of the control: a restart re-anchors
the pin to whatever bytes are on disk at that moment. Write access to `HooksDir`
must therefore be treated as equivalent to code execution with the agent's
privileges — the pin narrows the window between discovery and execution, it does
not make an untrusted hooks directory safe.

## Config

`Config` holds integrity verification parameters.

| Field            | Type            | Default | Description                              |
|------------------|-----------------|---------|------------------------------------------|
| `Enabled`        | `bool`          | `true`  | Whether integrity verification is active |
| `BinaryPath`     | `string`        | —       | Path to the plexd binary to verify       |
| `HooksDir`       | `string`        | —       | Directory containing hook scripts        |
| `HostKeyPath`    | `string`        | —       | SSH host key to verify. Not a YAML key: `AgentConfig.ApplyDefaults` derives it from the data dir via `tunnel.HostKeyPath` |
| `VerifyInterval` | `time.Duration` | `5m`    | Interval between periodic re-checks      |
| `WatchEnabled`   | `bool`          | `true`  | Enable inotify file watching on HooksDir |

```go
cfg := integrity.Config{
    BinaryPath: "/usr/local/bin/plexd",
}
cfg.ApplyDefaults() // Enabled=true, WatchEnabled=true, VerifyInterval=5m
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
- File format: `{"<path>": "<hex-sha256>", ...}`, with the host key entry holding its `SHA256:<base64>` fingerprint instead of a digest

## ViolationReporter

Interface abstracting control plane violation reporting for testability.

```go
type ViolationReporter interface {
    ReportViolations(ctx context.Context, nodeID string, reports []api.IntegrityViolationReport) error
}
```

A production implementation wraps `api.ControlPlane.ReportIntegrityViolations`.

The interface takes a batch because the endpoint does: a directory sweep that finds three tampered hooks delivers them as one request, and the control plane records them in one transaction so an operator sees one alert per tampering event. `Verifier` splits anything over `api.MaxIntegrityViolationsPerBatch` and sends nothing at all for an empty slice.

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
| `VerifyHook`     | `(ctx context.Context, nodeID, hookPath, expectedChecksum string) (bool, error)` | Verify hook against its pinned digest        |
| `VerifyHooksDir` | `(ctx context.Context, nodeID string)`                                 | Sweep the hooks directory against stored baselines     |
| `VerifyHostKey`  | `(ctx context.Context, nodeID string) error`                           | Verify the SSH host key's fingerprint                  |
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
2. Empty expected checksum: returns error (hooks require the digest pinned at discovery)
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

When `Config.Enabled` is `false`, returns immediately. Otherwise starts a `time.Ticker` at `Config.VerifyInterval` and calls `VerifyBinary`, `VerifyHooksDir`, and `VerifyHostKey` on each tick. Blocks until the context is cancelled.

### Detectors

Every violation names the detector that surfaced it, from the contract's closed set:

| Report site                       | `detected_by`  |
|-----------------------------------|----------------|
| `VerifyBinary`                    | `startup_scan` |
| `VerifyHostKey`                   | `startup_scan` |
| `VerifyHooksDir`                  | `startup_scan` |
| the hooks-directory fsnotify watcher | `inotify`   |
| `VerifyHook`, before a hook runs  | `pre_dispatch` |

The watcher and the sweep share one code path, so the detector travels as an argument rather than being derived from the report site. The enum has no value for a periodic re-scan, so the interval-driven sweeps report `startup_scan`.

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

### IntegrityViolationsRequest

```go
type IntegrityViolationsRequest struct {
    Violations []IntegrityViolationReport `json:"violations"` // 1..128 entries
}

type IntegrityViolationReport struct {
    Kind                IntegrityViolationKind `json:"kind"`
    DetectedBy          IntegrityDetector      `json:"detected_by"`
    ArtifactID          string                 `json:"artifact_id"`
    ObservedChecksum    string                 `json:"observed_checksum,omitempty"`
    ExpectedChecksum    string                 `json:"expected_checksum,omitempty"`
    ObservedFingerprint string                 `json:"observed_fingerprint,omitempty"`
    ExpectedFingerprint string                 `json:"expected_fingerprint,omitempty"`
}
```

**Endpoint**: `POST /v1/nodes/{node_id}/integrity-violations`

`Kind` is one of `binary_checksum`, `hook_checksum`, `ssh_host_key`; `DetectedBy` is one of `startup_scan`, `inotify`, `pre_dispatch`. Both are named string types rather than plain strings, so a call site cannot reach the wire with a value the control plane refuses.

`Kind` also decides which digest pair is legal. A checksum kind carries the two checksums as 32 raw bytes in standard-padded base64 (`integrity.WireChecksum` converts the hex the package works in); the host-key kind carries the two `SHA256:<base64>` fingerprints. An entry that crosses them is refused with 400 `integrity_violation_kind_mismatch`, which is why the four digest fields are `omitempty`: an unset one is absent from the JSON rather than present and empty.

A digest that will not convert drops its own entry rather than the batch it travels in, the rule the capability manifest's `declared_hooks` already uses. The control plane validates every entry and refuses the whole request on any bad one, so a single unconvertible digest would otherwise cost every violation sent with it.

### HeartbeatRequest.BinaryChecksum

The `BinaryChecksum` field in `api.HeartbeatRequest` (line 47 of `types.go`) is populated from `Verifier.BinaryChecksum()`. This allows the control plane to track which binary version each node is running.

## Integration Points

### With api.ControlPlane

`api.ControlPlane.ReportIntegrityViolations` satisfies the `ViolationReporter` interface when wrapped in an adapter:

```go
type controlPlaneReporter struct {
    client *api.ControlPlane
}

func (r *controlPlaneReporter) ReportViolations(ctx context.Context, nodeID string, reports []api.IntegrityViolationReport) error {
    return r.client.ReportIntegrityViolations(ctx, nodeID, api.IntegrityViolationsRequest{Violations: reports})
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
