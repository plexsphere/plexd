---
title: Integrity Verification
package: internal/integrity
feature: PXD-0010
---

# Integrity Verification

The `internal/integrity` package verifies the integrity of the plexd binary, hook scripts, and the SSH host key. It computes checksums on startup, re-verifies periodically, verifies hook scripts before execution, and reports integrity violations to the control plane.

## Data Flow

![Two triggers start the same pass: the start of Verifier.Run and every tick of its ticker at VerifyInterval. One pass runs VerifyBinary on the SHA-256 of BinaryPath, VerifyHooksDir on each hook in HooksDir and VerifyHostKey on the fingerprint of HostKeyPath, and Store.Get supplies the baseline of each path. The observed value is compared with the baseline. A match is logged as binary verified or host key verified. With no baseline, Store.Set stores the observed value as the baseline. A mismatch goes to ViolationReporter.ReportViolations, which posts it to the control plane at POST /v1/nodes/{id}/integrity-violations. When the control plane accepts the report, Store.Set makes the observed value the baseline; on an error the baseline stays and the next pass reports again.](../../diagrams/actions-integrity-verification.svg)

### Startup Sequence

`plexd up` starts `Verifier.Run` in its own goroutine, step 20c of `runAgent`, after registration has returned the node ID and the tunnel has loaded or generated the SSH host key, and ends it by cancelling its context. `Run` makes its first pass at once, before its ticker starts. The pass begins with the binary:

1. `Verifier.VerifyBinary` computes SHA-256 of the binary via `HashFile`
2. Loads baseline from `Store.Get(binaryPath)`
3. No baseline: stores the computed checksum via `Store.Set` and reports nothing
4. Match: logs `binary verified`
5. Mismatch: logs `binary integrity violation` at Error and reports a `binary_checksum` violation via `ViolationReporter`. Once the control plane accepts the report, the computed checksum becomes the baseline, so the change is reported once. A failed report keeps the old baseline, and the next pass reports the change again.

`VerifyHooksDir` and `VerifyHostKey` follow in the same pass. A mismatch never stops `plexd up`, and neither does a binary that cannot be read: `Run` logs `binary verification failed` and goes on with the next check.

Every change of the binary files one `binary_checksum` violation and then becomes the baseline. That includes an upgrade by `service.upgrade`, which plexd performs itself, as well as one done outside plexd. With `binary_path` unset, the baseline is keyed by the resolved path of the running executable, so an install that moves the binary to a new resolved path, a new Nix store path for instance, starts a new baseline and reports nothing.

Earlier releases never ran these checks, so a node upgraded from one has no baselines yet: its first pass stores them and reports nothing.

### Periodic Re-verification

1. After the first pass, `Verifier.Run` starts a `time.Ticker` at `Config.VerifyInterval`
2. Each tick runs the same pass: `VerifyBinary`, `VerifyHooksDir`, and `VerifyHostKey`, in that order
3. Loop exits cleanly on context cancellation

A divergence found on a tick is handled as one found at start: reported once, adopted as the baseline once the control plane accepts the report, and reported again on the next pass while the report fails. A change therefore costs one report, not one per tick.

### Hooks Directory Sweep

The sweep and its watcher are opt-in. They run only where `integrity.hooks_dir` or `PLEXD_HOOKS_DIR` names a directory; nothing copies `actions.hooks_dir` into `HooksDir`, so a node that sets neither sweeps no hooks and starts no watcher. Where one is set, `VerifyHooksDir` hashes every file in the directory on every pass and compares each with its baseline, and unless `WatchEnabled` is false the watcher re-runs the sweep 200 ms after the last change in the directory.

An in-place edit of a hook there files one `hook_checksum` violation and then becomes the baseline. Adopting it moves no executor pin: where the directory is also `actions.hooks_dir`, as `PLEXD_HOOKS_DIR` makes it, the executor still refuses the edited hook until the agent restarts (see [Hook Verification](#hook-verification)).

### Host Key Verification

1. `Verifier.VerifyHostKey` parses the key at `Config.HostKeyPath` and renders its `SHA256:<base64>` fingerprint
2. No baseline: stores the fingerprint via `Store.Set`
3. Match: logs `host key verified`
4. Mismatch: logs `host key integrity violation` at Error and reports an `ssh_host_key` violation. Once the control plane accepts it, the new fingerprint becomes the baseline; a failed report keeps the old one, and the next pass reports again.

The check runs last in every pass, the first one at start included, so a key replaced while the agent was stopped is reported at start.

The check compares fingerprints rather than file digests, because the fingerprint identifies the key: the same key re-serialised produces different bytes and the same identity, and the identity is what a peer pins. An unset `HostKeyPath` or an absent file is a no-op, so a node that never started the tunnel reports nothing.

The SSH server keeps serving the key it loaded at startup, so a key that changes on disk under a running agent is the tamper signal this detects.

### Hook Verification

1. `Verifier.VerifyHook` calls `VerifyFile` with `requireChecksum=true`
2. Empty expected checksum returns error (every hook the executor runs has a pin)
3. Match: returns `true` (safe to execute)
4. Mismatch: reports violation, returns `false` (must not execute)

For a hook in `actions.hooks_dir`, the expected checksum is the digest the executor
**pinned** the first time this process discovered the hook, not the one
`HookWatcher` last recomputed. It does **not** come from the dispatch, because an
action dispatch carries no checksum on the wire. This check therefore answers
"are these still the bytes the node discovered?", catching a swap between
discovery and execution.

For a hook the control plane rolled out into `<data_dir>/hooks`, the expected
checksum is the one the pull's `hooks` block delivered for the installed version,
in hex. plexd installed the script only after its SHA-256 matched that checksum
and the Domain-signed payload of the version, so this check answers "are these
still the bytes the control plane published?". A rolled-out hook is never trusted
on first use, and a new version moves the pin when plexd installs it, with no
restart. A mismatch files the same `hook_checksum` violation, detected
`pre_dispatch`, with the path in the rollout directory as `artifact_id`. A
restart does not re-anchor this pin: the installer restores it from its record,
`hook_rollouts.json`, so an edited rolled-out hook stays refused until the control
plane rolls out another version or withdraws the hook. Deleting the edited script
also clears it: a recorded hook whose script is gone counts as not installed, so
the next pass fetches the listed version again and pins it to the same delivered
checksum. See
[Rolled-out Hooks](remote-actions-hooks.md#rolled-out-hooks).

A fetched version that fails its checks before install files no violation: it
never reached the disk, and plexd reports it as a `verification_failed` rollout
error in the capability manifest instead.

The pin matches the first report of the hook to the control plane only. Later
capability manifests carry the digest the watcher last computed, so after an edit
the manifest and the pin differ. That is how the control plane sees the drift.

The pin matters because `HookWatcher` re-hashes a hook on every write and pushes
the new digest into the executor. Verifying against that live digest would
compare the file with a hash of itself and pass for any bytes on disk, so the
executor records a hook's digest once and never updates it: a hook whose bytes
change after discovery is refused, files a violation, and stays unrunnable until
the agent restarts and re-attests it. `plexd hooks reload` re-hashes the hooks
through the same watcher and moves no pin, so changing a hook in place requires
an agent restart, not a reload, before it can run again.

The pin of a hook in `actions.hooks_dir` is process-local, so re-attestation on restart
is both the recovery path for a legitimate hook change and the limit of the
control: a restart re-anchors the pin to whatever bytes are on disk at that
moment. Write access to `actions.hooks_dir`
must therefore be treated as equivalent to code execution with the agent's
privileges — the pin narrows the window between discovery and execution, it does
not make an untrusted hooks directory safe.

## Config

`Config` holds integrity verification parameters.

| Field            | Type            | Default | Description                              |
|------------------|-----------------|---------|------------------------------------------|
| `Enabled`        | `*bool`         | `true`  | Whether `Run` makes its baseline checks. `nil` means `true`. `VerifyHook` ignores it |
| `BinaryPath`     | `string`        | —       | Path to the plexd binary to verify. With integrity enabled, `plexd up` fills an empty value with `SelfPath()`, the running executable with symlinks resolved ([With internal/registration](#with-internal-registration)) |
| `HooksDir`       | `string`        | —       | Directory of hook scripts to sweep and watch. Opt-in: empty sweeps and watches nothing ([Hooks Directory Sweep](#hooks-directory-sweep)) |
| `HostKeyPath`    | `string`        | —       | SSH host key to verify. Not a YAML key: `AgentConfig.ApplyDefaults` derives it from the data dir via `tunnel.HostKeyPath` |
| `VerifyInterval` | `time.Duration` | `5m`    | Interval between the passes after the first one at start |
| `WatchEnabled`   | `*bool`         | `true`  | Enable inotify file watching on HooksDir. `nil` means `true` |

```go
cfg := integrity.Config{
    BinaryPath: "/usr/local/bin/plexd",
}
cfg.ApplyDefaults() // VerifyInterval=5m; IsEnabled() and IsWatchEnabled() report true
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

`Enabled` and `WatchEnabled` are tri-state: `IsEnabled()` and `IsWatchEnabled()` read `nil` as `true`, and `ApplyDefaults` leaves both alone, so an explicit `false` survives defaulting. `MarshalYAML` renders the effective value of each, so `config.dump` shows `enabled: true` and `watch_enabled: true` for an omitted key rather than `null`. `ApplyDefaults` only fills a zero `VerifyInterval` with `DefaultVerifyInterval`.

### Validation Rules

| Field            | Rule                        | Error Message                                                         |
|------------------|-----------------------------|-----------------------------------------------------------------------|
| `VerifyInterval` | >= 30s when `IsEnabled()`   | `integrity: config: VerifyInterval must be at least 30s when enabled` |

Validation is skipped entirely when `IsEnabled()` is `false`.

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

The file stays renamable while it is read. On Windows `os.Open` does not share delete access, which would make a rename of the file fail, so `HashFile` opens it with `CreateFile` and read, write and delete sharing instead. That keeps a pass over the running binary from failing a `service.upgrade`, which moves the running image aside with a rename.

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
| `Run`            | `(ctx context.Context, nodeID string) error`                           | One pass at start, then one per tick (blocks until cancelled) |

### VerifyBinary

1. Computes SHA-256 of `Config.BinaryPath` via `HashFile`
2. Updates `BinaryChecksum()` value under mutex
3. Loads baseline from `Store.Get`
4. No baseline: stores as new baseline via `Store.Set`
5. Match: logs `binary verified`
6. Mismatch: logs `binary integrity violation` at Error and hands the violation to `reportAndAdopt`, which reports it via `ViolationReporter` and moves the baseline once the report is accepted

Violations are non-fatal: the agent continues running after reporting. A binary that cannot be hashed returns the error after logging `binary hash failed`.

### Report Once, Then Adopt

`VerifyBinary`, `VerifyHooksDir`, and `VerifyHostKey` hand every mismatch to `reportAndAdopt`, together with the artifact's path, which is its store key, and the observed value: the hex digest, or the `SHA256:<base64>` fingerprint of the host key. `reportAndAdopt` reports them in the chunks [ViolationReporter](#violationreporter) describes and settles each chunk on its own:

- **Chunk accepted** (`ReportViolations` returns nil): calls `Store.Set(path, observed)` for every entry of the chunk and logs `integrity baseline updated`. The next pass finds a match and reports nothing.
- **Chunk failed**: logs `failed to report integrity violations` at Warn and moves none of its baselines. The next pass finds the same divergence and reports it again, until a report goes through.
- **`Store.Set` failed** after an accepted report: logs `failed to store integrity baseline` at Warn. `Set` updates its map before it writes the file, so this process stays quiet, and the next start, which reads the old file, reports the divergence once more.

A mismatch whose digest will not convert to the wire form cannot be reported on any pass, so the check adopts the observed value directly and logs `integrity baseline updated`.

The three checks hold one mutex, `checkMu`, for their whole body, so the watcher's sweep and a tick that find the same change report it once. `BinaryChecksum()` takes a separate mutex and never waits on a report.

`VerifyHook` does not adopt: its expected value is the executor's pin, not a store entry, so it reports a mismatch and writes nothing to the store.

### VerifyHook

1. Calls `VerifyFile(hookPath, expectedChecksum, true)`
2. Empty expected checksum: returns error (hooks require a pin: the digest pinned at discovery, or the checksum delivered for a rolled-out hook)
3. Match: returns `true` (hook is safe to execute)
4. Mismatch: reports violation, returns `false` (hook must not be executed)

### BinaryChecksum

Thread-safe getter protected by `sync.Mutex`. Returns the hex checksum the last `VerifyBinary` computed, and an empty string before the first pass has hashed the binary. `plexd up` does not read it: the heartbeat and the capability manifest carry the checksum computed once at start (see [HeartbeatRequest.BinaryChecksum](#heartbeatrequest-binarychecksum)).

### Run

When `IsEnabled()` is `false`, logs `integrity verification disabled` and returns immediately. Otherwise makes one pass at once, calling `VerifyBinary`, `VerifyHooksDir`, and `VerifyHostKey` in that order, then starts a `time.Ticker` at `Config.VerifyInterval` and makes the same pass on each tick. An error from `VerifyBinary` or `VerifyHostKey` is logged at Error as `binary verification failed` or `host key verification failed` and stops neither the pass nor the loop. Blocks until the context is cancelled.

When `IsWatchEnabled()` is true and `HooksDir` is set, `Run` also watches `HooksDir`, set up through `fsutil.WatchDir`. A hook that vanishes while the watch is set up makes it set the watch up again, up to 10 attempts; a set-up failure is logged at Warn and the periodic sweep keeps running. `Run` returns only after the watcher has returned, so a caller that waits for `Run` waits for the watcher too.

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

// One pass at once, then one per VerifyInterval, until ctx is cancelled.
// wg.Wait() after the cancel also waits for the hooks-directory watcher.
wg.Add(1)
go func() {
    defer wg.Done()
    _ = verifier.Run(ctx, nodeID)
}()

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

The `BinaryChecksum` field in `api.HeartbeatRequest` carries the SHA-256 of the running binary, so the control plane can track which binary each node runs. `plexd up` computes it once at start with `integrity.SelfChecksum()`, which hashes `os.Executable()`, converts it with `integrity.WireChecksum` into standard-padded base64, and sends that value in every heartbeat and as `binary_checksum` in the capability manifest. A binary that cannot be hashed fails the start with `plexd up: binary checksum: ...`.

The value does not follow `Verifier.BinaryChecksum()`. A binary replaced under a running agent keeps the old checksum in the heartbeat and the manifest until the agent restarts; the next pass reports the change as a `binary_checksum` violation instead.

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

`Store` uses `fsutil.WriteFileAtomic` for crash-safe checksum persistence. Concurrent readers never see a partially written file. The hooks-directory watcher sets up its watch with `fsutil.WatchDir`.

### With internal/registration

A report needs the node ID that `registrar.Register` returns and the bearer token it sets on the control plane client, so `plexd up` starts `Run` only after registration. Before that, at step 9, it fills an empty `Config.BinaryPath` when integrity is enabled:

```go
func SelfPath() (string, error)
```

`SelfPath` returns `os.Executable()` followed by `filepath.EvalSymlinks`, each error wrapped as `integrity: self path: ...`. `plexd up` stores the result in `BinaryPath` before `integrity.NewVerifier` and fails with `plexd up: integrity binary path: ...` when it cannot resolve the path. A configured `binary_path` is used as written. The resolved path is the store key and the report's `artifact_id`.

## Error Handling

| Scenario                       | Behavior                                        |
|--------------------------------|-------------------------------------------------|
| Binary file unreadable         | `VerifyBinary` returns error, logged at error; `Run` logs `binary verification failed` and goes on with the pass |
| Host key unparsable            | `VerifyHostKey` returns error, logged at error; `Run` logs `host key verification failed`, and the next tick still runs |
| Hook file unreadable           | `VerifyHook` returns error                      |
| Violation report fails         | Logged at warn level, agent continues; the baseline stays and the next pass reports again |
| Store persistence fails        | Error returned from `Set`/`Remove`; after an accepted report, logged as `failed to store integrity baseline` |
| Empty expected checksum (hook) | Error returned (hooks require checksum)         |
| Digest will not convert        | No report; the observed value becomes the baseline |
| Context cancelled              | `Run` loop exits cleanly after the watcher has returned, no goroutine leaks |
| Disabled config                | `Run` returns immediately, no baseline check runs; `VerifyHook` still checks every hook before it runs |

## Logging

All log entries use `component=integrity`.

| Level   | Event                         | Keys                                     |
|---------|-------------------------------|------------------------------------------|
| `Info`  | binary baseline established   | `path`, `checksum`                       |
| `Info`  | binary verified               | `path`, `checksum`                       |
| `Info`  | hook baseline established     | `path`, `checksum`                       |
| `Info`  | hook verified                 | `path`, `checksum`                       |
| `Info`  | host key baseline established | `path`, `fingerprint`                    |
| `Info`  | host key verified             | `path`, `fingerprint`                    |
| `Info`  | integrity baseline updated    | `path`                                   |
| `Info`  | integrity verification disabled | —                                      |
| `Error` | binary integrity violation    | `path`, `expected_checksum`, `actual_checksum` |
| `Error` | hook integrity violation      | `path`, `expected_checksum`, `actual_checksum` |
| `Error` | host key integrity violation  | `path`, `expected_fingerprint`, `observed_fingerprint` |
| `Error` | binary hash failed            | `path`, `error`                          |
| `Error` | host key fingerprint failed   | `path`, `error`                          |
| `Error` | binary verification failed    | `error`                                  |
| `Error` | host key verification failed  | `error`                                  |
| `Warn`  | failed to report integrity violations | `count`, `error`                 |
| `Warn`  | failed to store integrity baseline | `path`, `error`                     |
| `Warn`  | failed to store hook baseline | `path`, `error`                          |
| `Warn`  | integrity: a hook vanished while the watch was set up; retrying | `path`, `error` |
| `Warn`  | integrity: failed to watch hooks dir | `path`, `error`                   |
