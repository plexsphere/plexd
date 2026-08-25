---
title: Remote Actions and Hooks
package: internal/actions
feature: PXD-0019
---

# Remote Actions and Hooks

The `internal/actions` package enables platform-triggered remote action execution on plexd mesh nodes. It supports built-in operations (diagnostics, connectivity checks) and custom hook scripts with SHA-256 integrity verification. Action results are reported back to the control plane.

## Delivery Model

Action dispatches are **pulled**, not pushed. The control plane queues an execution into the `executions` block of `GET /v1/nodes/{node_id}/state`; plexd consumes that block on every successful reconciliation pull. The block is a delivery queue, not desired state: an entry keeps reappearing on every pull until its execution reaches a terminal status through the execution callback, so the node is responsible for suppressing the re-observations.

The `action_request` SSE event is a push-latency optimisation only. Its payload is opaque and it merely triggers a reconcile — the resulting pull carries the dispatch. A node with no event stream (descoped or disconnected) still executes every dispatch, just at the reconciliation cadence instead of within milliseconds.

## Data Flow

```text
Control Plane
       │  executions block of GET /v1/nodes/{id}/state
       ▼
┌──────────────────────┐
│ Reconciler dispatch  │  reconcile.DispatchHandler, invoked after every
│  stage               │  successful FetchState and BEFORE the diff
└──────────┬───────────┘
           │ *api.NodeStateSnapshot
           ▼
┌──────────────────────┐
│ Dispatcher.Handle    │  per entry, in block order
│  (dispatch.go)       │
└──────────┬───────────┘
           │
     ┌─────┴──────────────────────────────────────┐
     │ 1. no execution_id?    → drop, no callback │
     │ 2. already handled?    → skip              │
     │ 3. run still active?   → skip              │
     │ 4. budget short of one? → stop, next pull  │
     │ 5. expires_at absent/lapsed? → skip        │
     │ 6. status pending/ack  → Executor.Execute  │
     │    (actions disabled   → reject)           │
     │ 7. status started      → FailOrphan        │
     └──────────┬─────────────────────────────────┘
                │ status pending | ack
                ▼
┌──────────────────────┐
│ Executor.Execute     │
│  (executor.go)       │
└──────────┬───────────┘
           │
     ┌─────┴──────────────────────────────────────────┐
     │ 1. shuttingDown / active id / MaxConcurrent    │
     │    → ErrDispatchDeferred (no callback, retry)  │
     │ 2. Look up action in the registry the entry's  │
     │    type names → unknown_action rejects, an     │
     │    unknown type → unsupported_action_type      │
     │ 3. Claim: post ack (only when status is        │
     │    pending), then started — both before the run│
     └──────────┬─────────────────────────────────────┘
                │ if accepted
                ▼
        ┌───────────────┐
        │  goroutine    │
        │  runAction    │
        └───┬───────┬───┘
            │       │
   builtin  │       │ hook
            ▼       ▼
     ┌─────────┐ ┌─────────────────────────────┐
     │runBuiltin│ │runHook                      │
     │ call fn  │ │ 1. Path traversal check     │
     └────┬────┘ │ 2. Discovery-snapshot lookup │
          │      │ 3. File existence check      │
          │      │ 4. Verify vs pinned digest   │
          │      │ 5. exec.CommandContext        │
          │      │ 6. Capture stdout/stderr      │
          │      │ 7. Truncate to MaxOutputBytes │
          │      └──────────┬──────────────────────┘
          │                 │
          └────────┬────────┘
                   │
                   ▼
          ┌──────────────────────┐
          │ ExecutionCallback    │  POST /v1/nodes/{id}/executions/{eid}
          │ (terminal)           │  (ack → started → succeeded|failed|cancelled)
          └──────────────────────┘
```

## Config

`Config` holds configuration for remote action execution.

| Field              | Type            | Default | Description                              |
|--------------------|-----------------|---------|------------------------------------------|
| `Enabled`          | `bool`          | `true`  | Whether action execution is active       |
| `HooksDir`         | `string`        | `/etc/plexd/hooks` (Linux) | Directory containing hook scripts ([per platform](../core/configuration.md#platform-defaults)) |
| `MaxConcurrent`    | `int`           | `5`     | Max simultaneous action executions       |
| `MaxActionTimeout` | `time.Duration` | `10m`   | Max duration for a single action         |
| `MaxOutputBytes`   | `int64`         | `1 MiB` | Max output capture size per action       |

```go
cfg := actions.Config{
    HooksDir: "/etc/plexd/hooks",
}
cfg.ApplyDefaults() // Enabled=true, HooksDir=/etc/plexd/hooks (Linux), MaxConcurrent=5, MaxActionTimeout=10m, MaxOutputBytes=1MiB
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

`ApplyDefaults` uses zero-value detection: on a fully zero-valued `Config`, all numeric fields being zero triggers all defaults including `Enabled = true`. If any numeric field is already set (indicating explicit construction), `Enabled` is left as-is.

### Validation Rules

| Field              | Rule                     | Error Message                                           |
|--------------------|--------------------------|---------------------------------------------------------|
| `MaxConcurrent`    | >= 1 when `Enabled=true` | `actions: config: MaxConcurrent must be at least 1`     |
| `MaxActionTimeout` | >= 10s when `Enabled=true`| `actions: config: MaxActionTimeout must be at least 10s`|
| `MaxOutputBytes`   | >= 1024 when `Enabled=true`| `actions: config: MaxOutputBytes must be at least 1024`|

Validation is skipped entirely when `Enabled` is `false`.

## Dispatcher

Consumes the `executions` block of the reconciliation pull and turns each entry into an execution on the `Executor`. It is registered on the reconciler in `cmd/plexd/cmd/up.go`:

```go
dispatcher := actions.NewDispatcher(executor, identity.NodeID, logger)
reconciler.RegisterDispatchHandler(dispatcher.Handle)
```

### Constructor

```go
func NewDispatcher(executor *Executor, nodeID string, logger *slog.Logger) *Dispatcher
```

### Handle

```go
func (d *Dispatcher) Handle(ctx context.Context, desired *api.NodeStateSnapshot)
```

The signature matches `reconcile.DispatchHandler`. A `Dispatcher` is **not** safe for concurrent use: `Handle` is invoked only from the reconcile goroutine, one cycle at a time.

### Decision Table

Each entry of the block is evaluated in block order:

| Condition                                    | Outcome                                                                  | Callbacks |
|----------------------------------------------|--------------------------------------------------------------------------|-----------|
| `execution_id` is empty                      | Dropped, never run: there is no callback route and no identity to deduplicate, cancel, or audit on | none |
| Execution id already settled by this dispatcher | Skipped                                                                | none      |
| The executor is still running that execution | Marked settled again; the executor, not the settled set, is authoritative on in-flight runs | none |
| Less than one settlement (15s) of the pass budget (20s) is left | The remaining entries are left for the next pull, logged at warn | none |
| `expires_at` is absent (the zero time)       | Refused and marked settled, logged at warn — never folded into the lapsed case below, which would silently discard every dispatch | none |
| `expires_at` is not after now                | Skipped; expiry is the control plane's move                              | none      |
| `status` is `pending` or `ack`, `Config.Enabled` is `false` | Fail-fast rejection with `error=actions_disabled`           | `ack` → `started` → `failed` |
| `status` is `pending` or `ack`               | `Executor.Execute`                                                       | see [Execute Flow](#execute-flow) |
| `status` is `started`                        | `Executor.FailOrphan`: the run was lost to an agent restart; an undelivered report is retried on the next pull, at most 5 times | `failed`  |
| any other `status`                            | Logged at warn and marked settled                                        | none      |

There is no `timeout` wire status: a lapsed entry is dropped without a callback because the control plane sets the timeout itself.

The `Config.Enabled` gate sits **inside** the `pending`/`ack` case, not ahead of the status switch: a status this build cannot place must not be driven through a rejection walk, which would guess a transition path from a state the node does not understand.

The pass budget bounds the whole of `Handle`, which runs on the reconcile goroutine ahead of peer, policy, and bridge convergence. Block size is the control plane's to choose and nothing caps it, so without a budget a degraded control plane pins the reconciliation cycle open for the length of the block. Entries the pass never reaches are redelivered by the next pull, so an exhausted budget only defers work — and the entry it stopped on is named in the log line.

The budget gates which entries the pass *starts*, never how long a settlement already under way may take: a callback sequence handed what is left of the budget as its deadline would fail on that deadline rather than on the control plane, and the next pass would repeat the failure. Every sequence therefore keeps its own per-leg deadline, and an entry is started only while a whole settlement — the three-leg rejection walk, 15s — of the budget is left. That leaves a 5s window in which entries start and bounds the pass at the 20s budget instead of at the budget plus one entire settlement.

### Handled Set

The dispatcher keeps a set of settled execution ids — dispatched, rejected, expired, or reported lost — so a re-observed entry is a no-op. An id is forgotten the moment its entry drains from the block: the control plane only drains a settled execution, so the id can never be re-observed. That bounds the set by the size of the block.

The set is a hint, not the run state. `Executor.IsActive` is authoritative on whether a run is still in flight, and the dispatcher consults it before doing anything else with an entry: a block that transiently omits an entry prunes its id, and without that check the next pull would report a live run lost or dispatch it a second time.

An entry whose `Execute` or rejection walk returned `ErrDispatchDeferred` is deliberately **not** marked settled, so the next pull retries it. That covers both local backpressure and a transient control-plane failure that cut a callback sequence short: in either case the execution is still unresolved, and suppressing the entry would strand it until the control plane's own expiry fires.

An undelivered **orphan report** is retried the same way, but only 5 times. An unsettled entry is retried at the head of the block on every pull and each attempt spends part of the pass budget, so a report the control plane keeps refusing would starve every entry queued behind it for the execution's whole expiry window — up to `max_action_timeout` (10 minutes by default), or ten consecutive cycles at the default 60s interval. Once the cap is reached the entry is settled locally at error level and the execution is left to the server-side expiry an undeliverable report ends at anyway. The counter is per execution id and is forgotten alongside the settled id when the entry drains from the block.

### Resume After a Restart

plexd keeps no execution state across a restart, so the entry's `status` is what resumes it:

| Status on the pull | Meaning                                                | Node's move                                                        |
|--------------------|--------------------------------------------------------|--------------------------------------------------------------------|
| `pending`          | Dispatched, never acknowledged                         | Run it; `ack` is the first callback                                 |
| `ack`              | Acknowledged before the restart, never started         | Run it **without** re-acking; `started` is the first callback       |
| `started`          | The run was in flight and did not survive the restart  | Report `failed` with `error=execution lost to an agent restart`; **never** re-execute |

Actions are not idempotent, which is why a `started` entry is reported lost rather than repeated. `started` → `failed` is a legal edge, so the single terminal callback settles the execution.

## Executor

Central orchestrator for action execution, concurrency control, and result reporting.

### Constructor

```go
func NewExecutor(cfg Config, reporter ActionReporter, verifier HookVerifier, logger *slog.Logger) *Executor
```

| Parameter  | Description                                |
|------------|--------------------------------------------|
| `cfg`      | Actions configuration                      |
| `reporter` | Control plane adapter for acks and results |
| `verifier` | Hook integrity verification adapter        |
| `logger`   | Structured logger (`log/slog`)             |

Logger is tagged with `component=actions`.

### Methods

| Method            | Signature                                                                       | Description                                          |
|-------------------|---------------------------------------------------------------------------------|------------------------------------------------------|
| `RegisterBuiltin` | `(name, description string, params []api.ActionParam, fn BuiltinFunc)`         | Register a built-in action                           |
| `SetHooks`        | `(hooks []api.HookInfo)`                                                        | Set the discovered hooks snapshot                    |
| `Capabilities`    | `() ([]api.ActionInfo, []api.HookInfo)`                                         | Return registered builtins and hooks for reporting   |
| `Execute`         | `(ctx context.Context, nodeID string, entry api.NodeStateExecution) error`      | Main entry point for action execution                |
| `FailOrphan`      | `(ctx context.Context, nodeID, executionID string)`                             | Report a run lost to an agent restart as `failed`    |
| `Shutdown`        | `(ctx context.Context)`                                                         | Cancel all running executions, reject new ones       |
| `ActiveCount`     | `() int`                                                                         | Number of currently running actions                  |
| `IsActive`        | `(executionID string) bool`                                                      | Whether that execution is running right now          |

### Execute Flow

`Execute` takes the pull entry itself. It returns `ErrDispatchDeferred` when local backpressure prevents the run from starting, and `nil` once the execution has been accepted or settled with a callback.

1. **Check shutting down**: if `shuttingDown`, defer with `reason=shutting_down`
2. **Check duplicate**: if the execution id is already active, defer with `reason=already_active`
3. **Check concurrency**: if `len(active) >= MaxConcurrent`, defer with `reason=max_concurrent_reached`
4. **Look up action**: the entry's `type` picks the registry — `builtin` resolves **only** against the builtins map, `hook` **only** against the discovered hooks snapshot. A mistyped entry is unresolvable rather than silently routed to the other kind
5. **Unknown action**: reject with `reason=unknown_action`; a `type` outside `builtin`/`hook` rejects with `reason=unsupported_action_type`, because the action itself may well be registered and naming the wrong cause sends the operator auditing the action registry instead of the `type` field
6. **Claim**: post `ExecutionCallbackRequest{Status: "ack"}` — but only when the entry's `status` is `pending`, since an entry the pull already reports at `ack` has that transition recorded and repeating it would be a non-terminal self-edge answered `409` — then post `{Status: "started"}`. Both legs run **synchronously, before the run**, under a 5s deadline for the whole handshake
7. **Execute**: launch goroutine calling `runAction` with timeout context

`started` is a hard precondition for running, which is what keeps the pull's `ack` status unambiguous: an entry the block still reports at `ack` has not executed, so redelivering it after a restart cannot repeat a non-idempotent action. A transient failure on either leg therefore aborts the dispatch with `ErrDispatchDeferred` — nothing runs, the execution stays where the control plane had it, and the next pull redelivers it.

#### Deferral vs. fail-fast

The two failure shapes are deliberately different, because the pull redelivers:

|                    | Deferral (steps 1–3 and 6)                           | Fail-fast rejection (step 5, plus `actions_disabled`)   |
|--------------------|------------------------------------------------------|----------------------------------------------------------|
| Cause              | Local backpressure, or a transient failure of the claim handshake — either way the execution is unresolved | The node will never run this action — permanent |
| Callbacks          | **None** for backpressure; a cut-short claim may have delivered `ack` | The full legal sequence to `failed`             |
| Return value       | `ErrDispatchDeferred`                                | `nil`                                                    |
| Dispatcher's move  | Leaves the entry unsettled; the next pull retries it | Marks the entry settled                                  |

Reporting a deferral would fail an execution the control plane is about to redeliver, so a deferral is logged at warn and nothing else.

A rejection walk returns `ErrDispatchDeferred` too when a transient failure cuts it short: the leg that failed was never recorded, so continuing the walk would only earn a `409` on the next one. The entry stays unsettled and the next pull retries the walk from whatever status the control plane now reports.

A fail-fast rejection walks **every legal edge** from the status the pull entry declared, because the control plane reaches a terminal status only from `started`:

| Entry status | Callback sequence                    |
|--------------|--------------------------------------|
| `pending`    | `ack` → `started` → `failed(reason)` |
| `ack`        | `started` → `failed(reason)`         |
| `started`    | `failed(reason)`                     |

A two-step `ack` → `failed` is **not** legal: the control plane answers it `409 invalid_state_transition`.

When a callback is refused — a problem response whose `code` is `nsk_node_mismatch`, `invalid_state_transition`, or `execution_already_terminal` — plexd aborts without running or terminal-reporting the execution, because running it anyway would double-report. plexd keys that decision on the `code`, not on the bare `403`/`409` status: an intermediary's `403` is a transient failure, and treating it as a refusal would silently drop an action that then never runs and is never reported. A refusal settles the execution; a transient failure leaves it unsettled for the next pull.

### runAction (goroutine)

1. Derive the run deadline as `min(time.Until(entry.ExpiresAt), Config.MaxActionTimeout)` — the entry carries an absolute deadline, not a relative timeout, so the run gets whatever is left of it, clamped to the configured maximum. A deadline that lapses mid-run reports `failed` with `error="action timed out"`. A deadline with **nothing left of it** — the claim handshake ahead of the run is synchronous, so a slow control plane can consume the whole remainder — reports `failed` with `error="execution deadline lapsed before the run started"` without running anything: an already-lapsed context would kill a hook at `Start` while a builtin that does not watch its context would run to completion and report `succeeded` past its own deadline
2. Dispatch to `runBuiltin` or `runHook`
3. Determine the terminal status via `terminalOutcome`: `succeeded` (exit 0), `failed` (non-zero exit, timeout, or run error), or `cancelled` (parent context cancelled)
4. Build the terminal `ExecutionCallbackRequest` with `Status`, `ExitCode`, `Error`, and `Output` (base64 inline when ≤ 16 KiB, otherwise the declare → upload → object-key leg)
5. Post the terminal callback via `ActionReporter.ExecutionCallback`, retrying a transient failure up to three times with exponential backoff (500 ms, 1 s) — the terminal callback is the only transition out of `started`, so giving up after one attempt would pin the invocation there forever. A coded refusal stops the retry immediately.
6. Remove from active map

### runHook

1. **Path traversal prevention**: reject names containing `/`, `\`, or `..`
2. **Discovery-snapshot lookup**: find the hook in the discovered hooks snapshot. A hook absent from it fails the run — `Execute` already gated this, so it is the backstop for a snapshot that changed in between
3. **File existence**: `os.Stat` the resolved path
4. **Integrity verification**: call `HookVerifier.VerifyHook(ctx, nodeID, hookPath, pinnedChecksum)`, where `pinnedChecksum` is the digest this process recorded the **first** time it discovered the hook — **not** a wire field, and **not** the digest `HookWatcher` last recomputed (see [Hook Integrity Pinning](#hook-integrity-pinning))
5. **Execute**: `exec.CommandContext` with `WaitDelay=500ms`
6. **Environment**: minimal env (`PATH`, `HOME`, `PLEXD_NODE_ID`, `PLEXD_EXECUTION_ID`) plus `PLEXD_PARAM_*` vars
7. **Output capture**: stdout and stderr each captured in a buffer truncated to `MaxOutputBytes`; the joined body is truncated back to `MaxOutputBytes` so a hook saturating both streams stays within the per-action cap

#### Hook Integrity Pinning

The pull entry carries **no** checksum, so hook trust anchors on a digest the node pins itself: the one recorded the **first** time this process discovered the hook — the same digest it reports to the control plane in its capabilities.

The pin is what makes the check meaningful. `HookWatcher` re-hashes a hook on every write and pushes the new digest through `SetHooks`, so verifying against the live snapshot would compare a file with a hash of itself and pass for whatever bytes are on disk — including an attacker's, since the integrity callback only logs. A pin is therefore never updated and never dropped for the life of the process: a hook whose bytes change after discovery fails verification, files an integrity violation, and stays unrunnable until the agent restarts and re-attests it. That is also why a legitimately edited hook needs an agent restart before it can be dispatched again.

Upstream integrity — whether this node should run this hook at all — is the control plane's server-side dispatch gating, not a field the node re-checks.

### Shutdown

1. Sets `shuttingDown = true` under mutex
2. Collects all active cancel functions
3. Calls each cancel function to cancel running contexts
4. Subsequent `Execute` calls return `ErrDispatchDeferred` with `reason=shutting_down`, so the pull redelivers them to the next agent process

## ErrDispatchDeferred

```go
var ErrDispatchDeferred = errors.New("actions: dispatch deferred")
```

Reports that a dispatch has **not** been settled: local backpressure prevented it — shutdown, a run already in flight under the same id, or a saturated concurrency slot — or a transient control-plane failure cut a callback sequence short before it resolved the execution. It is **not** a failure of the execution: the pull's `executions` block redelivers the entry, so the caller must retry it on a later cycle instead of suppressing it.

## ActionReporter

Interface abstracting control plane communication for testability.

```go
type ActionReporter interface {
    ExecutionCallback(ctx context.Context, nodeID, executionID string, req api.ExecutionCallbackRequest) (*api.ExecutionCallbackResponse, error)
    UploadExecutionOutput(ctx context.Context, uploadURL string, output []byte) error
}
```

A production implementation wraps `api.ControlPlane.ExecutionCallback` and `api.ControlPlane.UploadExecutionOutput`.

## HookVerifier

Interface abstracting hook integrity verification for testability.

```go
type HookVerifier interface {
    VerifyHook(ctx context.Context, nodeID, hookPath, expectedChecksum string) (bool, error)
}
```

The production implementation is `integrity.Verifier`, which computes SHA-256 of the hook file and compares it against the digest plexd recorded when it discovered the hook on disk.

## BuiltinFunc

Signature for built-in action implementations.

```go
type BuiltinFunc func(ctx context.Context, params map[string]string) (stdout string, stderr string, exitCode int, err error)
```

Built-in actions do not require integrity verification (they are compiled into the binary).

## NodeInfoProvider

Interface for reading mesh state, injected into built-in actions.

```go
type NodeInfoProvider interface {
    NodeID() string
    MeshIP() string
    PeerCount() int
}
```

## Built-in Actions

### diagnostics.collect

Collects system diagnostics (hostname, OS, architecture, CPU count, memory, disk, load average, kernel version, network interfaces, processes) and returns them as JSON. Gracefully handles missing `/proc` data by using fallback values.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `include_network` | bool | no | `true` | Include network interface info |
| `include_processes` | bool | no | `true` | Include process listing |

```json
{
  "hostname": "edge-us-west-42",
  "os": "linux",
  "arch": "amd64",
  "cpu_count": 4,
  "memory_total": 8589934592,
  "disk_total": 107374182400,
  "load_avg": "1.50 1.20 0.90 2/150 12345",
  "kernel_version": "6.1.0-amd64",
  "network_interfaces": "...",
  "processes": "..."
}
```

Two fields are read per platform:

| Field | Unix | Windows |
|---|---|---|
| `disk_total` | `statfs` of `/` | `GetDiskFreeSpaceEx` of `%SystemDrive%\` |
| `kernel_version` | the `uname` release (e.g. `6.1.0-amd64`) | `major.minor.build` from `RtlGetVersion` (e.g. `10.0.19045`) |

When the `uname` call fails, `kernel_version` falls back to `<GOOS>/<GOARCH>`.

### diagnostics.ping_peer

Pings a mesh peer and reports latency. Uses the system `ping` command with `-c <count> -W 3`.

| Parameter | Type   | Required | Default | Description              |
|-----------|--------|----------|---------|--------------------------|
| `peer_id` | string | yes      | —       | Peer mesh IP address     |
| `count`   | string | no       | `1`     | Number of pings (max 10) |

Returns ping output in stdout. Exit code 0 on success, 1 on failure (unreachable or invalid IP).

### diagnostics.traceroute_peer

Traceroute to a mesh peer. Uses the system `traceroute` command with `-n -m <max_hops> -w 3` flags.

| Parameter  | Type   | Required | Default | Description              |
|------------|--------|----------|---------|--------------------------|
| `peer_id`  | string | yes      | —       | Peer mesh IP address     |
| `max_hops` | string | no       | `15`    | Maximum number of hops   |

Returns traceroute output in stdout. Exit code 1 if `traceroute` is not installed.

### service.restart

Asks the host's service manager to restart plexd: `systemctl restart plexd` on Linux, `launchctl kickstart -k system/com.plexsphere.plexd` on macOS, a detached `Restart-Service plexd` on Windows. No parameters required.

The action returns exit code 1 with the error `service manager not available` when the manager cannot be driven from the daemon's process, and exit code 1 with the manager's own error on stderr when the restart is refused.

### service.reload_config

Sends `SIGHUP` to the current process to trigger a configuration reload.

```json
{
  "status": "reload_signal_sent",
  "pid": 12345
}
```

No parameters required.

Windows has no signal that maps to a reload, so on Windows the action fails with exit code 1 and the error `actions: reload config: reload signal not supported on windows; restart the service instead`. Restart the service instead.

### service.upgrade

Upgrades plexd to a specified version from the release channel. The action downloads the release binary for the platform it runs on, verifies its SHA-256 against the dispatched `checksum`, downloads and verifies the release's Sigstore bundle **offline**, and only then replaces the current binary and restarts through the host's service manager. It never fetches the binary from the control plane.

| Parameter  | Type   | Required | Description                                      |
|------------|--------|----------|--------------------------------------------------|
| `version`  | string | yes      | Target version (e.g. `1.5.0`)                    |
| `checksum` | string | yes      | Expected SHA-256 checksum (hex, optional `sha256:` prefix) |

**Order of operations:**

1. Download `plexd-{GOOS}-{GOARCH}` — with a `.exe` suffix on Windows — from `{upgrade.release_base_url}/{tag}/…` (`{tag}` is the `v`-prefixed version) into a temporary file, streaming its SHA-256.
2. Compare the SHA-256 to the dispatched `checksum`. On a mismatch the action ends with `checksum_mismatch` (exit 1); the running binary is untouched.
3. Download the release's Sigstore bundle (`plexd-{GOOS}-{GOARCH}.sigstore.json`, or `plexd-windows-{GOARCH}.exe.sigstore.json` on Windows). A release with no bundle asset fails this download and is refused (the action fails with a download error rather than a terminal status object).
4. Verify the bundle offline against the embedded Sigstore public-good trusted root: the certificate identity must satisfy `upgrade.signing_issuer` / `upgrade.signing_identity_regexp`, and the signed artifact digest must match the downloaded binary. On failure the action ends with `bundle_verification_failed` (exit 1), the temporary file is removed, and the running binary is untouched.
5. `chmod 0755`, replace the current binary, then restart through the host's service manager. On Linux and macOS the replacement is a single rename over the running executable. Windows refuses to rename over a running image, so the running binary is renamed to `plexd.exe.old` first; a failed swap puts it back, and the leftover is removed by the next upgrade or by `plexd uninstall`.

**Terminal statuses:**

| Status | Exit | Meaning |
|--------|------|---------|
| `upgraded` | 0 | Binary replaced and the service manager restarted plexd |
| `upgraded_restart_pending` | 0 | Binary replaced but the service manager is unavailable; restart is manual |
| `upgraded_restart_failed` | 1 | Binary replaced but the restart failed |
| `checksum_mismatch` | 1 | Download SHA-256 differs from the dispatched `checksum`; binary untouched |
| `bundle_verification_failed` | 1 | Sigstore bundle verification failed; binary untouched |

On checksum mismatch, the upgrade is aborted and the original binary is preserved:

```json
{
  "status": "checksum_mismatch",
  "message": "expected abc123..., got def456...",
  "version": "1.5.0"
}
```

On success:

```json
{
  "status": "upgraded",
  "version": "1.5.0",
  "message": "binary replaced and service restarted"
}
```

### system.info

Reports OS, kernel, hardware, and runtime info as JSON.

```json
{
  "hostname": "edge-us-west-42",
  "os": "linux",
  "arch": "amd64",
  "go_version": "go1.26.0",
  "mesh_ip": "10.100.0.5",
  "peer_count": 12,
  "node_id": "node-abc123"
}
```

No parameters required.

### health.check

Reports the node's health status.

| Parameter       | Type | Required | Default | Description              |
|-----------------|------|----------|---------|--------------------------|
| `include_peers` | bool | no       | `true`  | Include per-peer status  |

```json
{
  "tunnel_count": 3,
  "connected_peers": 5,
  "uptime": "2h30m15s",
  "last_heartbeat": "2026-02-15T10:30:00Z",
  "last_reconcile": "2026-02-15T10:25:00Z",
  "status": "healthy"
}
```

Status is `"healthy"` if `tunnel_count > 0`, otherwise `"degraded"`.

### mesh.reconnect

Triggers mesh reconnection via the reconciler. On success, returns `{"status": "reconnected"}`. On failure, returns exit code 1 with `{"status": "failed", "error": "..."}`.

No parameters required.

### config.dump

Returns the current effective configuration with sensitive values redacted. Returns the config string in stdout. No parameters required.

### logs.snapshot

Captures recent logs from the in-memory ring buffer and returns them as newline-separated text.

| Parameter | Type   | Required | Default | Description                              |
|-----------|--------|----------|---------|------------------------------------------|
| `lines`   | string | no       | `100`   | Number of lines (max: 10000)             |
| `since`   | string | no       | —       | Duration filter (e.g. `5m`, `1h`)        |

Returns newline-separated log lines in stdout.

## HookWatcher

Monitors a hooks directory for filesystem changes using `fsnotify`. Replaces the one-time `DiscoverHooks` call with a continuous watch loop.

### Constructor

```go
func NewHookWatcher(hooksDir string, onChange HookChangeCallback, onIntegrity IntegrityAlertCallback, logger *slog.Logger) *HookWatcher
```

| Parameter     | Description                                          |
|---------------|------------------------------------------------------|
| `hooksDir`    | Directory containing hook scripts                    |
| `onChange`    | Callback invoked with the full hooks list on change  |
| `onIntegrity` | Callback invoked when a hook's checksum changes     |
| `logger`      | Structured logger (`log/slog`)                      |

### Callbacks

```go
type HookChangeCallback func(hooks []api.HookInfo)
type IntegrityAlertCallback func(hookName, oldChecksum, newChecksum string)
```

### Methods

| Method  | Signature                                 | Description                                       |
|---------|-------------------------------------------|---------------------------------------------------|
| `Watch` | `(ctx context.Context) error`             | Monitor directory; blocks until ctx is cancelled   |
| `Hooks` | `() []api.HookInfo`                       | Return sorted snapshot of current hooks            |

### Watch Lifecycle

1. Create hooks directory if it does not exist
2. Perform initial scan: read all executable files, compute checksums, call `onChange`
3. Start `fsnotify` watcher on the hooks directory
4. On file create/write/chmod: debounce (200ms), then re-read file, compute checksum, update hooks map, call `onChange`
5. On file remove/rename: debounce, remove from hooks map, call `onChange`
6. On `.json` sidecar change: debounce, re-read the parent hook's metadata
7. On checksum change for an existing hook: call `onIntegrity` with old and new checksums
8. On context cancellation: stop all timers, return nil

### Integration with Executor

In `cmd/plexd/cmd/up.go`, the watcher is wired to the executor:

```go
hookWatcher := actions.NewHookWatcher(cfg.Actions.HooksDir, executor.SetHooks, onIntegrityAlert, logger)
```

When hooks change, `executor.SetHooks` is called, updating `Capabilities()` output. It does **not** move the integrity anchor of a hook the executor has already seen — see [Hook Integrity Pinning](#hook-integrity-pinning). The `Hooks()` method satisfies the `nodeapi.HookReloader` interface.

## Local API Endpoints

The node API server (`internal/nodeapi`) exposes action and hook management endpoints over the Unix socket.

### GET /v1/actions

Lists all registered built-in actions and hooks.

**Response:**

```json
{
  "builtin_actions": [
    {"name": "diagnostics.collect", "description": "Collect system diagnostics"}
  ],
  "hooks": [
    {"name": "deploy.sh", "source": "local", "checksum": "sha256:abc...", "description": "Deploy"}
  ]
}
```

### POST /v1/actions/run

Runs a built-in action synchronously and returns the result. The action provider must implement the `LocalActionRunner` interface (satisfied by `Executor`).

**Request:**

```json
{
  "action": "diagnostics.collect",
  "parameters": {}
}
```

**Response:**

```json
{
  "status": "success",
  "exit_code": 0,
  "stdout": "{...}",
  "stderr": ""
}
```

Status values: `success` (exit 0), `failed` (non-zero exit), `error` (internal error).

### GET /v1/hooks

Lists all registered hooks (subset of GET /v1/actions response).

### POST /v1/hooks/reload

Triggers a re-scan of hooks via the `HookReloader` interface (satisfied by `HookWatcher.Hooks()`).

**Response:**

```json
{
  "status": "reloaded",
  "hooks": [...]
}
```

## CLI Commands

### plexd actions

Lists available actions via `GET /v1/actions` over Unix socket. Output is a tab-separated table with TYPE, NAME, and DESCRIPTION columns.

### plexd actions run \<name\>

Runs an action via `POST /v1/actions/run`. Accepts `--param key=value` flags for passing parameters.

### plexd hooks list

Lists hooks via `GET /v1/hooks`. Shows NAME, SOURCE, CHECKSUM (truncated to 12 chars), and DESCRIPTION.

### plexd hooks verify

Reads hooks via `GET /v1/hooks` and checks that each hook has a checksum. Reports `OK` or `WARN` per hook.

### plexd hooks reload

Triggers a hook re-scan via `POST /v1/hooks/reload`. Reports the status and hook count.

## DiscoverHooks

Scans a directory for executable hook scripts and builds metadata.

```go
func DiscoverHooks(hooksDir string, logger *slog.Logger) ([]api.HookInfo, error)
```

1. Returns empty slice (not nil) if `hooksDir` is empty or does not exist
2. Skips directories, non-executable files, and `.json` sidecar files
3. Computes SHA-256 via `integrity.HashFile` for each executable
4. Parses optional `.json` sidecar for metadata (description, parameters, timeout, sandbox)
5. Results sorted by name
6. Individual file errors logged at warn level; valid hooks still returned

### Sidecar Metadata Format

A hook named `deploy` can have a sidecar file `deploy.json`:

```json
{
  "description": "Deploy to production",
  "parameters": [
    {
      "name": "target",
      "type": "string",
      "required": true,
      "description": "Target address"
    }
  ],
  "timeout": "30s",
  "sandbox": "none"
}
```

## Parameter Passing

The entry's `parameters` is an arbitrary JSON object (or `null`, which flattens to an empty map). Each value is kept as raw JSON rather than decoded into an `any`, because the state response is decoded with a plain decoder: a number in an `any` becomes a `float64`, which silently rewrites every integer past 2^53 (an epoch in nanoseconds, a snowflake id) before it ever reaches the action.

The object is flattened to the flat string map builtins and hooks consume: a JSON **string** is unquoted so an ordinary parameter keeps its exact text, and every other value — number, bool, `null`, array, object — travels as the JSON text the control plane sent.

| JSON value        | Flattened string |
|-------------------|------------------|
| `"s3://bucket"`   | `s3://bucket`    |
| `30`              | `30`             |
| `true`            | `true`           |
| `null`            | `null`           |
| `["a","b"]`       | `["a","b"]`      |
| `{"k":"v"}`       | `{"k":"v"}`      |

The flattened parameters are passed to hook scripts as environment variables with the `PLEXD_PARAM_` prefix.

| Original Name     | Environment Variable        |
|--------------------|-----------------------------|
| `target`           | `PLEXD_PARAM_TARGET`       |
| `region`           | `PLEXD_PARAM_REGION`       |
| `my-param.name!`   | `PLEXD_PARAM_MY_PARAM_NAME_` |

Sanitization: non-alphanumeric characters (except underscore) are replaced with underscore, then uppercased.

Additional environment variables always set:

| Variable               | Description                    |
|------------------------|--------------------------------|
| `PATH`                 | Inherited from agent process   |
| `HOME`                 | Inherited from agent process   |
| `PLEXD_NODE_ID`        | Node ID of the executing node  |
| `PLEXD_EXECUTION_ID`   | Execution ID from the pull entry |

## Execution Status Values

The terminal callback carries one of three statuses, chosen by `terminalOutcome`:

| Status      | Meaning                                                                                       |
|-------------|-----------------------------------------------------------------------------------------------|
| `succeeded` | Action completed with exit code 0                                                              |
| `failed`    | Non-zero exit, a timeout (`error="action timed out"`), or a run error (message in `error`)     |
| `cancelled` | Parent context was cancelled (e.g., during shutdown)                                          |

## Rejection Reasons

Three reasons reach the control plane, each as the `error` of the `failed` terminal that closes the fail-fast sequence:

| Reason                    | Trigger                                                                     |
|---------------------------|------------------------------------------------------------------------------|
| `unknown_action`          | Action name not in the registry the entry's `type` names                      |
| `unsupported_action_type` | `type` outside `builtin`/`hook` — the action itself may well be registered    |
| `actions_disabled`        | `Config.Enabled` is `false`                                                   |

Three more are **deferral** reasons: they are logged locally at warn and produce **no callback at all**, because the pull redelivers the entry.

| Reason                   | Trigger                                     |
|--------------------------|---------------------------------------------|
| `shutting_down`          | Agent is shutting down                      |
| `already_active`         | Execution id already in progress            |
| `max_concurrent_reached` | Active executions >= `Config.MaxConcurrent` |

## API Types

Types defined in `internal/api/types.go`.

### NodeStateExecution

One entry of the `executions` block of `GET /v1/nodes/{node_id}/state`.

```go
type NodeStateExecution struct {
    ExecutionID string                     `json:"execution_id"`
    Action      string                     `json:"action"`
    Type        string                     `json:"type"`
    Parameters  map[string]json.RawMessage `json:"parameters"`
    Status      string                     `json:"status"`
    RequestedAt time.Time                  `json:"requested_at"`
    ExpiresAt   time.Time                  `json:"expires_at"`
}
```

`ExpiresAt` is an absolute UTC deadline, not a relative timeout; a missing or `null` value decodes to the zero time, which the dispatcher refuses rather than treats as lapsed. `Parameters` is nullable: a JSON `null` decodes to a nil map, and each value is held as raw JSON so a large integer reaches the action with every digit intact. The entry carries no callback URL and no hook checksum.

### ActionKind constants

```go
const (
    // ActionKindBuiltin dispatches an action built into plexd.
    ActionKindBuiltin = "builtin"
    // ActionKindHook dispatches a hook registered by the node.
    ActionKindHook = "hook"
)
```

### ExecutionStatusPending

```go
const (
    // ExecutionStatusPending marks an execution the control plane has dispatched
    // and the node has not yet acknowledged. It appears in the executions block
    // of the node state snapshot and is never reported by a node on the
    // execution callback.
    ExecutionStatusPending = "pending"
)
```

### ExecutionCallbackRequest

The single callback posted to `POST /v1/nodes/{node_id}/executions/{execution_id}`,
once per lifecycle transition. `Status` is one of the `ExecutionStatus*` values.

```go
type ExecutionCallbackRequest struct {
    Status              string           `json:"status"`
    ExitCode            *int             `json:"exit_code,omitempty"`
    Error               string           `json:"error,omitempty"`
    DeclaredOutputBytes int64            `json:"declared_output_bytes,omitempty"`
    Output              *ExecutionOutput `json:"output,omitempty"`
}
```

### ExecutionOutput

Carries an execution's captured output on a terminal callback. `Inline` is the
base64-encoded body, used only when it is at most 16 KiB; `ObjectKey` and `SHA256`
describe an already-uploaded over-ceiling output.

```go
type ExecutionOutput struct {
    Inline    string `json:"inline,omitempty"`
    ObjectKey string `json:"object_key,omitempty"`
    SHA256    string `json:"sha256,omitempty"`
}
```

### ExecutionCallbackResponse

The `200` response to a callback. `OutputUploadURL` is a presigned PUT URL present
only on the first callback that declares an over-ceiling output.

```go
type ExecutionCallbackResponse struct {
    Status          string `json:"status"`
    OutputUploadURL string `json:"output_upload_url,omitempty"`
}
```

### ExecutionStatus constants

```go
const (
    // ExecutionStatusAck acknowledges receipt of the action request.
    ExecutionStatusAck = "ack"
    // ExecutionStatusStarted reports that the action has begun running.
    ExecutionStatusStarted = "started"
    // ExecutionStatusSucceeded is the terminal callback for a successful run.
    ExecutionStatusSucceeded = "succeeded"
    // ExecutionStatusFailed is the terminal callback for a failed run.
    ExecutionStatusFailed = "failed"
    // ExecutionStatusCancelled is the terminal callback for a cancelled run.
    ExecutionStatusCancelled = "cancelled"
)
```

### CapabilitiesPayload

Sent to `PUT /v1/nodes/{node_id}/capabilities`.

```go
type CapabilitiesPayload struct {
    Binary         *BinaryInfo  `json:"binary,omitempty"`
    BuiltinActions []ActionInfo `json:"builtin_actions"`
    Hooks          []HookInfo   `json:"hooks"`
}
```

## Integration Points

### With internal/api

- `api.NodeStateExecution` is the pull entry the dispatcher consumes
- `api.ControlPlane.ExecutionCallback` and `UploadExecutionOutput` are the production implementations of `ActionReporter`
- `api.ControlPlane.UpdateCapabilities` sends discovered capabilities

### With internal/integrity

- `integrity.Verifier` implements `HookVerifier` for SHA-256 hook verification
- `integrity.HashFile` is used by `DiscoverHooks` for computing hook checksums

### With internal/reconcile

`Dispatcher.Handle` satisfies `reconcile.DispatchHandler` and is registered with `RegisterDispatchHandler`, so it runs after every successful state pull and before the diff. The `action_request` SSE event is registered on the shared `triggerReconcile` closure instead, alongside `node_state_updated` and the peer family.

## Lifecycle

```go
// 1. Create config
cfg := actions.Config{HooksDir: "/etc/plexd/hooks"}
cfg.ApplyDefaults()

// 2. Create executor
exec := actions.NewExecutor(cfg, reporter, verifier, logger)

// 3. Register built-in actions. svcCtl is a *packaging.Service over the host's
//    service manager: packaging.NewService(packaging.NewServiceManager(logger),
//    packaging.InstallConfig{})
exec.RegisterBuiltin("diagnostics.collect", "Collect system diagnostics", collectParams, actions.DiagnosticsCollect())
exec.RegisterBuiltin("diagnostics.ping_peer", "Ping a mesh peer", peerIDParam, actions.PingPeer(nodeInfo))
exec.RegisterBuiltin("diagnostics.traceroute_peer", "Traceroute to peer", peerIDParam, actions.DiagnosticsTraceroutePeer(nodeInfo))
exec.RegisterBuiltin("service.restart", "Restart service", nil, actions.ServiceRestart(svcCtl))
exec.RegisterBuiltin("service.reload_config", "Reload config", nil, actions.ServiceReloadConfig())
exec.RegisterBuiltin("service.upgrade", "Upgrade plexd binary", upgradeParams, actions.ServiceUpgrade(upgradeFetcher, upgradeVerifier, svcCtl))
exec.RegisterBuiltin("system.info", "Report system and runtime info", nil, actions.SystemInfo(nodeInfo))
exec.RegisterBuiltin("health.check", "Check health", healthParams, actions.HealthCheck(healthProvider))
exec.RegisterBuiltin("mesh.reconnect", "Reconnect mesh", nil, actions.MeshReconnect(reconnector))
exec.RegisterBuiltin("config.dump", "Dump config", nil, actions.ConfigDump(configProvider))
exec.RegisterBuiltin("logs.snapshot", "Snapshot logs", snapshotParams, actions.LogsSnapshot(logProvider))

// 4. Register the dispatcher on the reconciler; it consumes the pull's
//    executions block on every successful cycle
dispatcher := actions.NewDispatcher(exec, nodeID, logger)
reconciler.RegisterDispatchHandler(dispatcher.Handle)

// 5. Create hook watcher (replaces one-time DiscoverHooks)
watcher := actions.NewHookWatcher(cfg.HooksDir, exec.SetHooks, onIntegrityAlert, logger)

// 6. Wire to nodeapi
nodeAPISrv.SetActionProvider(exec)
nodeAPISrv.SetHookReloader(watcher)

// 7. Start watcher goroutine
go watcher.Watch(ctx)

// 8. On shutdown
exec.Shutdown(ctx)
```

## Error Handling

| Scenario                     | Behavior                                        |
|------------------------------|-------------------------------------------------|
| Entry without an `execution_id` | Dropped at error level; never run — there is no callback route |
| Entry without an `expires_at` | Refused at warn level, marked settled; no callback |
| Entry past its `expires_at`  | Skipped; no callback — the control plane owns the timeout |
| Entry with an unexpected `status` | Logged at warn, marked settled; no callback |
| Dispatch pass budget spent   | The remaining entries are logged at warn and left for the next pull |
| Backpressure (shutting down, id already active, `MaxConcurrent` saturated) | No callback; the next pull redelivers the entry |
| Actions disabled             | Fail-fast: the legal sequence to a `failed` terminal with `error=actions_disabled` |
| Unknown action               | Fail-fast: the legal sequence to a `failed` terminal with `error=unknown_action`   |
| `type` outside `builtin`/`hook` | Fail-fast: the legal sequence to a `failed` terminal with `error=unsupported_action_type` |
| Deadline lapsed during the claim handshake | `failed` terminal with `error=execution deadline lapsed before the run started`; nothing runs |
| Run lost to an agent restart | One `failed` terminal with `error=execution lost to an agent restart`; never re-executed |
| Orphan report undelivered    | Retried on the next pull, at most 5 passes; then logged at error level and left to server-side expiry |
| Hook file missing            | `ack` + `started`, then `failed` terminal with `error` carrying the run error (e.g. `hook not found: <name>`) |
| Hook integrity failure       | `failed` terminal with the integrity error message |
| Hook timeout                 | Process killed; `failed` terminal with `error=action timed out` (there is no `timeout` wire status — the server sets timeout itself) |
| Hook non-zero exit           | `failed` terminal with the actual `exit_code`   |
| Terminal callback fails      | Retried up to 3 times with exponential backoff, then logged at warn level; agent continues |
| Ack/started callback transport error | Logged at warn level; the dispatch is deferred — nothing runs and the next pull redelivers the entry |
| Rejection-walk callback transport error | Logged at warn level; the walk stops and the entry stays unsettled for the next pull |
| Callback refused (`nsk_node_mismatch`, `invalid_state_transition`, `execution_already_terminal`) | Execution aborted: no run, no terminal callback; a terminal refusal is not retried |
| Panic in action              | Recovered; `failed` terminal with `error=panic: <value>` |

## Logging

All log entries use `component=actions`.

| Level   | Event                         | Keys                                        |
|---------|-------------------------------|---------------------------------------------|
| `Info`  | execution expired; leaving the timeout to the control plane | `execution_id`, `action`, `expires_at` |
| `Info`  | Action completed              | `execution_id`, `status`, `duration`        |
| `Warn`  | dispatch deferred             | `execution_id`, `action`, `reason`          |
| `Warn`  | Action rejected               | `execution_id`, `action`, `reason`          |
| `Warn`  | execution lost to an agent restart; reporting failed | `execution_id`       |
| `Warn`  | unexpected execution status in the pull block | `execution_id`, `action`, `status` |
| `Warn`  | execution carries no expires_at; refusing to dispatch | `execution_id`, `action`     |
| `Warn`  | dispatch budget exhausted; the remaining entries wait for the next pull | `execution_id`, `budget` |
| `Warn`  | claim callback failed; deferring the dispatch | `execution_id`, `status`, `error` |
| `Warn`  | execution deadline lapsed before the run started | `execution_id`, `expires_at` |
| `Warn`  | failed to send terminal callback | `execution_id`, `attempts`, `error`      |
| `Warn`  | failed to send callback for rejected execution | `execution_id`, `status`, `error` |
| `Error` | execution entry carries no execution_id; dropping | `action`                |
| `Error` | orphan report undelivered across repeated pulls; leaving the execution to server-side expiry | `execution_id`, `passes` |
| `Error` | claim callback refused; aborting execution | `execution_id`, `status`, `error` |
| `Error` | callback refused for rejected execution | `execution_id`, `status`, `error` |
| `Error` | panic in action execution     | `execution_id`, `panic`, `stack`            |

## Dispatch Delivery: the `executions` block

The control plane queues a dispatch into the `executions` block of
`GET /v1/nodes/{node_id}/state`. The block is always present (`[]` when empty,
never `null`) and ordered by `requested_at`, then `execution_id`.

### Entry

```json
{
  "execution_id": "exec_a1b2c3d4",
  "action": "diagnostics.collect",
  "type": "builtin",
  "parameters": {
    "include_network": true,
    "include_processes": true
  },
  "status": "pending",
  "requested_at": "2026-07-27T10:30:00Z",
  "expires_at": "2026-07-27T10:35:00Z"
}
```

| Field | Type | Description |
|---|---|---|
| `execution_id` | string | Unique identifier for this execution |
| `action` | string | Action name (e.g. `diagnostics.collect`, `backup`) |
| `type` | string | `builtin` or `hook`; selects the registry the name is resolved against |
| `parameters` | object | Parameters passed to the action; nullable |
| `status` | string | `pending`, `ack`, or `started` — the status the control plane currently holds |
| `requested_at` | timestamp | When the control plane dispatched the execution |
| `expires_at` | timestamp | Absolute UTC deadline, **not** a relative timeout |

There is no `callback_url` (the callback path is derived from the node and
execution ids) and no `checksum` (hook integrity anchors on the digest the node
pinned at first discovery).

### SSE Event: `action_request`

`action_request` is a contract-tier event whose payload plexd treats as **opaque**.
It carries no dispatch: like `node_state_updated`, it only triggers a reconcile,
and the resulting pull delivers the `executions` block. It exists purely to cut
the latency between dispatch and execution. Like all SSE events it is wrapped in a
signed envelope and verified before processing.

## Execution Callback Contract

Every lifecycle transition is a single `POST` to
`/v1/nodes/{node_id}/executions/{execution_id}` carrying an
`ExecutionCallbackRequest`. The server drives a closed state machine:
`ack` → `started` → `succeeded` | `failed` | `cancelled`.

The roster is closed, and a terminal status is reachable **only from `started`**:

| From        | Legal next                                  |
|-------------|---------------------------------------------|
| `pending`   | `ack`                                        |
| `ack`       | `started`                                    |
| `started`   | `succeeded`, `failed`, `cancelled` — plus `started` again, but only to declare an over-ceiling output size |
| terminal    | nothing                                      |

`ack` → `failed` and `ack` → `cancelled` are **not** legal edges; the control plane
answers them `409 invalid_state_transition`. That is why a node that refuses to run
an action walks the whole way to `started` before failing it.

The server refuses an illegal advance with `409 invalid_state_transition`, a
callback on an already-settled invocation with `409 execution_already_terminal`, a
foreign node's callback with `403 nsk_node_mismatch`, and inline output over 16
KiB with `413 inline_output_too_large`. When the `ack` or `started` callback is
refused with one of the three refusal codes above, plexd aborts the execution —
it never runs or double-reports it. plexd matches on the problem `code`, not the
`403`/`409` status, so an intermediary's `403` or an unrelated `409` stays a
transient error: it is logged and tolerated like any other callback failure.

### Ack

```json
{ "status": "ack" }
```

Sent only when the pull entry's `status` is `pending`. An entry already at `ack`
has that transition recorded upstream, so its first callback is `started`.

A rejected action (unknown action or actions disabled) walks the remaining legal
edges to a `failed` terminal whose `error` is the reason — for a `pending` entry
that is three callbacks:

```json
{ "status": "ack" }
{ "status": "started" }
{ "status": "failed", "error": "unknown_action" }
```

Backpressure is **not** a rejection: shutdown, a duplicate in-flight id, and a
saturated concurrency slot produce no callback at all, because the pull redelivers
the entry.

### Orphaned run

An entry the pull reports at `started` belonged to a run that did not survive an
agent restart. plexd posts one terminal callback and never re-executes it:

```json
{ "status": "failed", "error": "execution lost to an agent restart" }
```

### Terminal with inline output

Output at most 16 KiB travels base64-encoded in `output.inline` on the terminal
callback:

```json
{
  "status": "succeeded",
  "exit_code": 0,
  "output": { "inline": "aGVsbG8gd29ybGQK" }
}
```

### Terminal with uploaded output

Output larger than 16 KiB is not sent inline. plexd re-posts `started` declaring
the byte count:

```json
{ "status": "started", "declared_output_bytes": 524288 }
```

The `200` response carries a one-time presigned PUT URL:

```json
{
  "status": "started",
  "output_upload_url": "https://blob.plexsphere.com/exec-output/exec_a1b2c3d4?token=b1c2d3e4"
}
```

plexd derives the object key from the URL path, `PUT`s the raw bytes to that URL
with `Content-Type: application/octet-stream` and no bearer token, then sends the
terminal callback referencing the object by key and lowercase-hex SHA-256.
Captured output routinely contains configuration and credentials, so the upload
leg is pinned: the URL may not be less secure than the configured control-plane
base URL (an `https` control plane can never downgrade an upload to `http`), and
redirects are not followed — a `3xx` fails the upload rather than re-sending the
body to the host it names. The URL itself is a bearer credential and is never
written to a log, not even inside a wrapped transport error.

```json
{
  "status": "succeeded",
  "exit_code": 0,
  "output": {
    "object_key": "exec-output/exec_a1b2c3d4",
    "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
  }
}
```

If any step of that upload leg fails, plexd falls back to truncated inline output
on the terminal callback.

## Retry

- The terminal callback is retried up to three times with exponential backoff (500 ms, 1 s). A coded refusal stops the retry immediately, and so does a cancelled context.
- `ack` and `started` callbacks are not retried: a transient failure there is logged and the execution continues, because the terminal callback still settles the invocation.
- Callbacks are not persisted across a restart — a node that dies mid-execution leaves the invocation for the control plane to time out.

## Capability Announcement

When plexd registers or when its capabilities change (e.g. hooks added/removed, binary updated), it announces its full capability set to the control plane.

### Registration Flow

During `POST /v1/register`, the `capabilities` field is included in the registration payload:

```json
{
  "token": "plx_enroll_a8f3c7...",
  "public_key": "...",
  "hostname": "web-01",
  "metadata": { },
  "capabilities": {
    "binary": {
      "version": "1.4.2",
      "checksum": "sha256:a1b2c3d4e5f6..."
    },
    "builtin_actions": [
      {
        "name": "diagnostics.collect",
        "description": "Collect system diagnostics",
        "parameters": [
          { "name": "include_network", "type": "bool", "required": false, "default": "true" },
          { "name": "include_processes", "type": "bool", "required": false, "default": "true" }
        ]
      }
    ],
    "hooks": [
      {
        "name": "backup",
        "description": "Run incremental backup of application data",
        "source": "script",
        "checksum": "sha256:f7e8d9c0b1a2...",
        "parameters": [
          { "name": "target", "type": "string", "required": true },
          { "name": "compress", "type": "bool", "required": false, "default": "true" }
        ],
        "timeout": "300s",
        "sandbox": "namespaced"
      },
      {
        "name": "db-backup",
        "description": "PostgreSQL backup to S3",
        "source": "crd",
        "checksum": "sha256:abc123...",
        "parameters": [
          { "name": "bucket", "type": "string", "required": true },
          { "name": "compress", "type": "bool", "required": false, "default": "true" }
        ],
        "timeout": "600s",
        "privileged": false
      }
    ]
  }
}
```

### Runtime Capability Update

```
PUT /v1/nodes/{node_id}/capabilities
```

Used when capabilities change after initial registration (e.g. hook files added/removed/modified, `PlexdHook` CRs created/updated/deleted, plexd binary updated). Same `capabilities` payload structure as in the registration request.

### Data Model

| Type | Fields |
|---|---|
| `BinaryInfo` | `version`, `checksum` |
| `ActionCapability` | `name`, `description`, `parameters[]` |
| `HookCapability` | `name`, `description`, `source` (`script` or `crd`), `checksum`, `parameters[]`, `timeout`, `sandbox` (script) / `privileged` (crd) |
| `ParameterDef` | `name`, `type`, `required`, `default`, `description` |

## Kubernetes CRD Hooks

When plexd runs as a DaemonSet in Kubernetes, hooks are defined as `PlexdHook` custom resources instead of script files. On dispatching a hook execution, plexd creates a Kubernetes Job on the target node.

### Generated Job YAML

When an executions entry with `action: hooks/db-backup` is dispatched, plexd creates:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: plexd-db-backup-exec-a1b2c3d4
  namespace: plexd-system
  labels:
    plexd.plexsphere.com/hook: db-backup
    plexd.plexsphere.com/execution-id: exec_a1b2c3d4
  ownerReferences:
    - apiVersion: plexd.plexsphere.com/v1alpha1
      kind: PlexdHook
      name: db-backup
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 600
  template:
    spec:
      nodeSelector:
        kubernetes.io/hostname: worker-03
      serviceAccountName: plexd-hook-runner
      containers:
        - name: backup
          image: registry.example.com/tools/pg-backup:2.1@sha256:abc123...
          command: ["/usr/local/bin/pg-backup.sh"]
          env:
            - name: PLEXD_PARAM_BUCKET
              value: "s3://backups/prod"
            - name: PLEXD_PARAM_COMPRESS
              value: "true"
            - name: PLEXD_EXECUTION_ID
              value: "exec_a1b2c3d4"
            - name: PLEXD_ACTION_NAME
              value: "db-backup"
          resources:
            limits:
              cpu: "1"
              memory: 512Mi
          volumeMounts:
            - name: pgdata
              mountPath: /var/lib/postgresql
              readOnly: true
      volumes:
        - name: pgdata
          hostPath:
            path: /var/lib/postgresql
      restartPolicy: Never
```

plexd pins the Job to the target node via `nodeSelector`, injects parameters as `PLEXD_PARAM_*` environment variables, and sets an `ownerReference` to the `PlexdHook` CR for garbage collection.

### Result Mapping

plexd watches the Job and maps its status to the action callback:

| Job Condition | Callback Status | Notes |
|---|---|---|
| Succeeded | `succeeded` | Exit code 0 |
| Failed | `failed` | Exit code from container termination state |
| `activeDeadlineSeconds` exceeded | `failed` with `error="action timed out"` | Job killed by Kubernetes; there is no node-reported `timeout` status |

Stdout and stderr are captured from the pod logs via the Kubernetes API.

## Security Considerations

- **Authenticated delivery** -- Action dispatches arrive in the `executions` block of the NSK-authenticated state pull, so a dispatch is only ever as trustworthy as the control-plane connection itself; no SSE payload can inject one. Local action requests via Unix socket require a valid session JWT.
- **Signed delivery** -- All SSE events (including `action_request`, `node_state_updated`, `rotate_keys`, etc.) are signed with the control plane's Ed25519 key. plexd verifies every signature before processing.
- **Signature verification** -- Every SSE event carries `issued_at` (max staleness: 5 minutes) and is verified with a kid-indexed Ed25519 signature selected by the envelope's `key_id`. Signature and staleness checks are applied uniformly to all event types; there is no nonce.
- **Hook file permissions** -- plexd verifies that hook files are owned by root and not group- or other-writable before execution.
- **Symlink protection** -- Hook paths are resolved and validated to prevent symlink escape outside the configured hooks directory.
- **Checksum enforcement** -- Hook checksums are verified before every execution, against the digest plexd recorded when it discovered the hook (there is no checksum on the wire). Binary checksums are reported continuously. On Kubernetes, image digests serve as checksums -- hooks without pinned digest (`@sha256:...`) are rejected.
- **Resource isolation** -- Hooks run with cgroup limits at minimum; higher sandbox levels add namespace or container isolation. On Kubernetes, hooks always run as separate Pods with native resource limits.
- **CRD privilege control** -- Kubernetes hooks requiring host-level access (`hostPID`, `hostNetwork`, `privileged`) must declare `privileged: true` in the `PlexdHook` spec. The platform can enforce approval policies.
- **Session token scoping** -- JWTs are bound to a specific node (`node_id` claim) and a specific set of actions (`actions` claim). Tokens cannot be used on other nodes or for unauthorized actions.
- **Session revocation** -- When a session ends, the control plane drops its entry from the `sessions` block of the state pull; the next reconcile observes the absence and tears the session down. The `session_revoked` SSE event carries no teardown of its own -- its payload is never parsed and it only pulls the observing reconcile forward.
- **Local emergency access** -- `plexd actions run --local` requires root or plexd user, bypasses JWT authorization, but is logged as `local_emergency` and reported to the control plane.
