---
title: Remote Actions and Hooks
package: internal/actions
feature: PXD-0019
---

# Remote Actions and Hooks

The `internal/actions` package enables platform-triggered remote action execution on plexd mesh nodes. It supports built-in operations (diagnostics, connectivity checks), custom hook scripts with SHA-256 integrity verification, and, in a pod, [PlexdHook resources](#kubernetes-crd-hooks) run as Kubernetes Jobs. Action results are reported back to the control plane.

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
     │ 0. cancel requested, run active → Cancel   │
     │ 1. no execution_id?    → drop, no callback │
     │ 2. already handled?    → skip              │
     │ 3. run still active?   → skip              │
     │ 4. budget short of one? → stop, next pull  │
     │ 5. expires_at absent/lapsed? → skip        │
     │ 6. status pending/ack  → Executor.Execute  │
     │    (cancel requested   → not started)      │
     │    (actions disabled   → reject)           │
     │ 7. status started      → Resume a          │
     │    plexd_hook entry, else FailOrphan       │
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
     │    type names → unknown_action rejects; a      │
     │    plexd_hook entry is looked up by its run.   │
     │    Another type, or plexd_hook with no runner  │
     │    → unsupported_action_type                   │
     │ 3. Claim: post ack (only when status is        │
     │    pending), then started — both before the run│
     └──────────┬─────────────────────────────────────┘
                │ if accepted; a plexd_hook entry runs
                │ runPlexdHook instead (Kubernetes CRD Hooks)
                ▼
        ┌───────────────┐
        │  goroutine    │
        │  runAction    │
        │  hook sidecar │
        │  runBound     │
        └───┬───────┬───┘
            │       │
   builtin  │       │ hook
            ▼       ▼
     ┌──────────┐ ┌───────────────────────────────┐
     │runBuiltin│ │runHook                        │
     │ call fn  │ │ 1. Path traversal check       │
     └────┬─────┘ │ 2. Discovery-snapshot lookup  │
          │       │ 3. File checks: links, type,  │
          │       │    owner, mode                │
          │       │ 4. Verify vs pinned digest    │
          │       │ 5. exec.CommandContext in its │
          │       │    own process group          │
          │       │ 6. Capture stdout/stderr      │
          │       │ 7. Truncate to MaxOutputBytes │
          │       └─────────┬─────────────────────┘
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
| `Enabled`          | `*bool`         | `true`  | Whether action execution is active. `nil` means `true` |
| `RolloutsEnabled`  | `*bool`         | `true`  | Whether plexd installs the hooks the control plane rolls out. `nil` means `true`; `false` is the node owner's veto ([Switches and Platforms](#switches-and-platforms)) |
| `HooksDir`         | `string`        | `/etc/plexd/hooks` (Linux) | Directory containing hook scripts ([per platform](../core/configuration.md#platform-defaults)) |
| `RolloutHooksDir`  | `string`        | `<data_dir>/hooks` | Directory plexd installs [rolled-out hooks](#rolled-out-hooks) into. Not a YAML key: `AgentConfig.ApplyDefaults` derives it from `data_dir` |
| `MaxConcurrent`    | `int`           | `5`     | Max simultaneous action executions       |
| `MaxActionTimeout` | `time.Duration` | `10m`   | Hard ceiling on a run's deadline, over the entry's `expires_at` and the hook's declared `timeout` ([Run Deadline](#run-deadline)) |
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

`Enabled` and `RolloutsEnabled` are tri-state: `IsEnabled()` and `IsRolloutsEnabled()` read `nil` as `true`, and `ApplyDefaults` leaves both alone, so an explicit `false` survives defaulting. `MarshalYAML` renders the effective value of each, so `config.dump` shows `enabled: true` and `rollouts_enabled: true` for an omitted key rather than `null`. `ApplyDefaults` fills an empty `HooksDir` and each limit left at zero. It never sets `RolloutHooksDir`, which `AgentConfig.ApplyDefaults` sets to `filepath.Join(data_dir, "hooks")`, `/var/lib/plexd/hooks` on Linux. The path has no YAML key because plexd removes every file in that directory it did not write, and a configurable path could point that cleanup at an operator's files.

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

Each entry of the block is evaluated in block order. The first row is checked for every entry while the block's ids are collected, so it comes before every other row and outside the pass budget:

| Condition                                    | Outcome                                                                  | Callbacks |
|----------------------------------------------|--------------------------------------------------------------------------|-----------|
| `cancel_requested_at` is set and the executor is running that execution | `Executor.Cancel` stops the run, and the id is marked settled. Logged at info, once per execution | none from the dispatcher; the run sends its own terminal (see [Cancel](#cancel)) |
| `execution_id` is empty                      | Dropped, never run: there is no callback route and no identity to deduplicate, cancel, or audit on | none |
| Execution id already settled by this dispatcher | Skipped                                                                | none      |
| The executor is still running that execution | Marked settled again; the executor, not the settled set, is authoritative on in-flight runs | none |
| Less than one settlement (15s) of the pass budget (20s) is left | The remaining entries are left for the next pull, logged at warn | none |
| `expires_at` is absent (the zero time)       | Refused and marked settled, logged at warn — never folded into the lapsed case below, which would silently discard every dispatch | none |
| `expires_at` is not after now                | Skipped; expiry is the control plane's move                              | none      |
| `status` is `pending` or `ack`, `cancel_requested_at` is set | Not started and marked settled, logged at warn, whatever `Config.Enabled` says | none |
| `status` is `pending` or `ack`, `Config.Enabled` is `false` | Fail-fast rejection with `error=actions_disabled`           | `ack` → `started` → `failed` |
| `status` is `pending` or `ack`               | `Executor.Execute`                                                       | see [Execute Flow](#execute-flow) |
| `status` is `started`, `type` is `plexd_hook`, and a PlexdHook runner is set | `Executor.Resume` follows the run's Job and marks the id settled; a `cancel_requested_at` on the entry is forwarded in the same pass. While shutting down, with the id active, or at `MaxConcurrent`, the entry waits for the next pull, with no deferral counted (see [Resume After a Restart](#resume-after-a-restart)) | the terminal the Job's outcome maps to |
| `status` is `started`, any other entry       | `Executor.FailOrphan`: the run was lost to an agent restart; an undelivered report is retried on the next pull, at most 5 times | `failed`  |
| any other `status`                            | Logged at warn and marked settled                                        | none      |

There is no `timeout` wire status: a lapsed entry is dropped without a callback because the control plane sets the timeout itself.

The `Config.Enabled` gate sits **inside** the `pending`/`ack` case, not ahead of the status switch: a status this build cannot place must not be driven through a rejection walk, which would guess a transition path from a state the node does not understand.

A `pending` or `ack` entry that carries `cancel_requested_at` is stopped ahead of that gate, so it gets neither a run nor a rejection walk. The dispatcher logs `execution entry carries a cancel request but never started; not starting it` at warn, with `execution_id`, `action`, and `status`. The control plane never serves such an entry, because a cancel moves a `pending` or `ack` target to `cancelled` at once, and a claim on it would be answered `409 execution_already_terminal`.

The pass budget bounds the whole of `Handle`, which runs on the reconcile goroutine ahead of peer, policy, and bridge convergence. Block size is the control plane's to choose and nothing caps it, so without a budget a degraded control plane pins the reconciliation cycle open for the length of the block. Entries the pass never reaches are redelivered by the next pull, so an exhausted budget only defers work — and the entry it stopped on is named in the log line.

The budget gates which entries the pass *starts*, never how long a settlement already under way may take: a callback sequence handed what is left of the budget as its deadline would fail on that deadline rather than on the control plane, and the next pass would repeat the failure. Every sequence therefore keeps its own per-leg deadline, and an entry is started only while a whole settlement — the three-leg rejection walk, 15s — of the budget is left. That leaves a 5s window in which entries start and bounds the pass at the 20s budget instead of at the budget plus one entire settlement.

### Handled Set

The dispatcher keeps a set of settled execution ids (dispatched, resumed, rejected, expired, or reported lost), so a re-observed entry is a no-op. An id is forgotten the moment its entry drains from the block: the control plane only drains a settled execution, so the id can never be re-observed. That bounds the set by the size of the block.

The set is a hint, not the run state. `Executor.IsActive` is authoritative on whether a run is still in flight, and the dispatcher consults it before doing anything else with an entry: a block that transiently omits an entry prunes its id, and without that check the next pull would report a live run lost or dispatch it a second time.

A cancel request is forwarded before the settled check. A run in flight is in the set, and every later pull skips its entry at that check, so a forward placed after it would never read the request. The forward runs in the loop that collects the block's ids, ahead of the budgeted pass, so a pass that spends its budget never delays a cancel. Forwarding sends no callback.

When `Executor.Cancel` finds the run, the dispatcher also marks the id settled. Without the mark, a run whose id an earlier block pruned by briefly omitting the entry could report and leave the executor's active set before the pass reaches its entry, and the entry would then reach the `started` row and be reported lost.

A second set, `cancelled`, holds the ids whose cancel this dispatcher forwarded, so the info line `cancel requested; stopping the run` is written once per execution, with `execution_id`, `action`, and `cancel_requested_at`. A forward for an id already in it returns at once. A forward that finds no run records nothing and logs nothing, and the rows of the [Decision Table](#decision-table) decide what the entry needs. The set is pruned with the settled set when the entry drains.

An entry whose `Execute` or rejection walk returned `ErrDispatchDeferred` is deliberately **not** marked settled, so the next pull retries it. That covers both local backpressure and a transient control-plane failure that cut a callback sequence short: in either case the execution is still unresolved, and suppressing the entry would strand it until the control plane's own expiry fires.

An undelivered **orphan report** is retried the same way, but only 5 times. An unsettled entry is retried at the head of the block on every pull and each attempt spends part of the pass budget, so a report the control plane keeps refusing would starve every entry queued behind it for the execution's whole expiry window — up to `max_action_timeout` (10 minutes by default), or ten consecutive cycles at the default 60s interval. Once the cap is reached the entry is settled locally at error level and the execution is left to the server-side expiry an undeliverable report ends at anyway. The counter is per execution id and is forgotten alongside the settled id when the entry drains from the block.

### Resume After a Restart

plexd keeps no execution state across a restart, so the entry's `status` is what resumes it:

| Status on the pull | Meaning                                                | Node's move                                                        |
|--------------------|--------------------------------------------------------|--------------------------------------------------------------------|
| `pending`          | Dispatched, never acknowledged                         | Run it; `ack` is the first callback                                 |
| `ack`              | Acknowledged before the restart, never started         | Run it **without** re-acking; `started` is the first callback       |
| `started`          | The run was in flight when the agent stopped           | A `plexd_hook` entry is resumed: plexd follows its Job and reports the Job's outcome. Every other entry is reported `failed` with `error=execution lost to an agent restart`; **never** re-execute |

Actions are not idempotent, which is why a `started` entry is never run again. A built-in or a script hook died with the agent, so its entry is reported lost; `started` → `failed` is a legal edge, so the single terminal callback settles the execution. A PlexdHook's Job did not die with the agent: a [shutdown](#shutdown) leaves it running, and the next agent process follows it instead of reporting it lost.

The dispatcher's `started` case calls `Executor.Resume` first and acts on what it returns:

| `Resume` returns | Dispatcher's move |
|---|---|
| `nil` | The id is marked settled. `Resume` took an active slot, logged `resuming plexd hook run after a restart` at info, and started following the Job. When the entry carries `cancel_requested_at`, the cancel is forwarded in the same pass, so the resumed run deletes the Job and reports `cancelled` |
| `ErrDispatchDeferred` | Shutting down, the id already active, or `MaxConcurrent` reached. The entry is left for the next pull, as often as it takes: no deferral is counted, so the 5-pass cap of an undelivered orphan report does not apply |
| not resumable | The entry is not of type `plexd_hook`, or no PlexdHook runner is set, as on a host or in a pod whose runner could not be built. `FailOrphan` reports it lost |

A resumed run creates nothing and sends no `ack` or `started`, because the entry is at `started` already. Its run deadline is computed afresh, as for a new run: what is left of `expires_at`, capped by `MaxActionTimeout` from the moment of the resume. When that ceiling capped the original run, the Job's `activeDeadlineSeconds`, set from the original deadline, usually ends it first, and the run reports a timeout without its log. It sends only the terminal the Job's outcome maps to (see [Kubernetes CRD Hooks](#kubernetes-crd-hooks)). A Job that is gone reports `failed` with `error=execution lost to an agent restart`. `Resume` does not check `Config.Enabled`: it starts nothing, and reporting the Job lost would leave a run that is still going unobserved.

A `started` entry that carries `cancel_requested_at` and cannot be resumed is reported lost the same way, as `failed` with `error=execution lost to an agent restart`, not as `cancelled`. The contract keeps `cancelled` for a run the node stopped, and this process stopped nothing.

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
| `SetHooks`        | `(hooks []api.HookInfo)`                                                        | Set the snapshot of `hooks_dir`, pinning each hook not seen before |
| `SetRolloutHooks` | `(hooks []api.HookInfo)`                                                        | Set the snapshot of the rollout directory; pins nothing ([Running a Rolled-out Hook](#running-a-rolled-out-hook)) |
| `SwapRolloutHook` | `(name string, version int, checksum string, swap func() error) error`          | Run `swap` under the swap lock, then pin `name` to `version` and the hex `checksum`. A `swap` that succeeds also gives the hook's entry in the rollout snapshot that `checksum`. A nil `swap` pins alone; a failed one leaves the pin as it was |
| `RemoveRolloutHook` | `(name string, remove func() error) error`                                    | Run `remove` under the swap lock, then drop the pin of `name`. A failed `remove` leaves the pin as it was |
| `Capabilities`    | `() ([]api.ActionInfo, []api.HookInfo)`                                         | Return registered builtins, sorted by name, and the merged hook list for reporting |
| `SetPlexdHookRunner` | `(r PlexdHookRunner)`                                                        | Set the runner a `plexd_hook` entry runs through. `plexd up` calls it once, in a pod, before the reconciler starts. Without a runner such an entry is rejected with `unsupported_action_type` |
| `Execute`         | `(ctx context.Context, nodeID string, entry api.NodeStateExecution) error`      | Main entry point for action execution                |
| `Resume`          | `(ctx context.Context, nodeID string, entry api.NodeStateExecution) error`      | Follow the Job of a `started` `plexd_hook` entry after an agent restart (see [Resume After a Restart](#resume-after-a-restart)) |
| `FailOrphan`      | `(ctx context.Context, nodeID, executionID string)`                             | Report a run lost to an agent restart as `failed`    |
| `Cancel`          | `(executionID string) bool`                                                      | Stop that execution's run on a cancel request; false when no such run is active (see [Cancel](#cancel)) |
| `Shutdown`        | `(ctx context.Context)`                                                         | Cancel all running executions, reject new ones       |
| `ActiveCount`     | `() int`                                                                         | Number of currently running actions                  |
| `IsActive`        | `(executionID string) bool`                                                      | Whether that execution is running right now          |

### Execute Flow

`Execute` takes the pull entry itself. It returns `ErrDispatchDeferred` when local backpressure prevents the run from starting, and `nil` once the execution has been accepted or settled with a callback.

1. **Check shutting down**: if `shuttingDown`, defer with `reason=shutting_down`
2. **Check duplicate**: if the execution id is already active, defer with `reason=already_active`
3. **Check concurrency**: if `len(active) >= MaxConcurrent`, defer with `reason=max_concurrent_reached`
4. **Look up action**: the entry's `type` picks the registry. `builtin` resolves **only** against the builtins map, `hook` **only** against the merged hook list, which holds the hooks in `hooks_dir` and the pinned [rolled-out hooks](#rolled-out-hooks). A mistyped entry is unresolvable rather than silently routed to the other kind. A `plexd_hook` entry is looked up nowhere here: with a PlexdHook runner set, it counts as known, and its run looks the PlexdHook up, so no Kubernetes call runs on the reconcile goroutine (see [Kubernetes CRD Hooks](#kubernetes-crd-hooks))
5. **Unknown action**: reject with `reason=unknown_action`. A `type` outside `builtin`, `hook`, and `plexd_hook`, or a `plexd_hook` entry with no PlexdHook runner set, rejects with `reason=unsupported_action_type`, because the action itself may well be registered and naming the wrong cause sends the operator auditing the action registry instead of the `type` field
6. **Claim**: post `ExecutionCallbackRequest{Status: "ack"}` — but only when the entry's `status` is `pending`, since an entry the pull already reports at `ack` has that transition recorded and repeating it would be a non-terminal self-edge answered `409` — then post `{Status: "started"}`. Both legs run **synchronously, before the run**, under a 5s deadline for the whole handshake
7. **Execute**: launch goroutine calling `runAction` with timeout context, or `runPlexdHook` for a `plexd_hook` entry

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

1. Settle a lapsed deadline. The entry carries an absolute deadline, not a relative timeout, so the run gets whatever is left of it. A deadline with **nothing left of it** — the claim handshake ahead of the run is synchronous, so a slow control plane can consume the whole remainder — reports `failed` with `error="execution deadline lapsed before the run started"` without running anything: an already-lapsed context would kill a hook at `Start` while a builtin that does not watch its context would run to completion and report `succeeded` past its own deadline
2. Load the hook's declaration: for an entry of type `hook`, `loadHookDeclaration` reads the sidecar from disk and returns its timeout or a refusal (see [Sidecar at Run Time](#sidecar-at-run-time)). A builtin reads no sidecar, even one beside a hook of its name
3. Derive the run deadline with `runBound`: the smallest of what is left of `expires_at`, the hook's declared timeout, and `Config.MaxActionTimeout` (see [Run Deadline](#run-deadline))
4. Dispatch: a refused declaration skips `runHook` and fails the run with exit code 1 and the refusal as its error. Otherwise the run goes to `runBuiltin` or `runHook`
5. Determine the terminal status via `terminalOutcome`: `succeeded` (exit 0), `failed` (non-zero exit, timeout, refusal, or run error), or `cancelled` (a run error after the action context was cancelled, at `Shutdown` or on a [cancel request](#cancel)). A timeout's `error` names the limit that set the deadline, unless it was `expires_at`
6. Log `hook refused` at warn for a refused run, and `run deadline capped by max_action_timeout` at warn when the ceiling set the deadline of a run that was not refused
7. Build the terminal `ExecutionCallbackRequest` with `Status`, `ExitCode`, `Error`, and `Output` (base64 inline when ≤ 16 KiB, otherwise the declare → upload → object-key leg)
8. Post the terminal callback via `ActionReporter.ExecutionCallback`, retrying a transient failure up to three times with exponential backoff (500 ms, 1 s) — the terminal callback is the only transition out of `started`, so giving up after one attempt would pin the invocation there forever. A coded refusal stops the retry immediately.
9. Remove from active map

#### Run Deadline

`runBound(remaining, declared, ceiling time.Duration) (bound time.Duration, label string, capped bool)` returns the smallest of what is left of the entry's `expires_at`, the hook's declared `timeout`, and `Config.MaxActionTimeout`. A declared 0, which is also what a builtin passes, means none. The ceiling is hard: a declared `timeout` only shortens a run, so a hook that needs more than the default 10 minutes needs `max_action_timeout` raised on its node.

A run that reaches its deadline reports `failed`, and its `error` names the limit that set the deadline:

| Limit that set the deadline | Terminal `error` |
|---|---|
| The entry's `expires_at` | `action timed out` |
| The hook's declared `timeout` | `action timed out: hook timeout <d>`, such as `action timed out: hook timeout 30s` |
| `Config.MaxActionTimeout` | `action timed out: max_action_timeout <d>`, such as `action timed out: max_action_timeout 10m0s` |

`<d>` is the limit in Go's duration format. A tie keeps the earlier limit in the table, so `expires_at` wins every tie and a declared `timeout` equal to the ceiling is labelled as the hook's.

When the ceiling set the deadline, plexd logs `run deadline capped by max_action_timeout` at warn once the run is over, with `ceiling` and `requested`: what was left of `expires_at`, or the declared `timeout` when one is shorter. A refused run logs no such line, because it never started.

The run deadline covers the integrity check too, so a declared `timeout` shorter than the hash and its violation report can turn an integrity failure into a timeout, while the hook does not run either way and the manifest's digest still shows the drift.

### runHook

1. **Path traversal prevention**: reject names containing `/`, `\`, or `..`
2. **Discovery-snapshot lookup**: find the hook in the merged hook list. A hook absent from it fails the run — `Execute` already gated this, so it is the backstop for a snapshot that changed in between. The entry's `Source` picks the directory and the pin: `hooks_dir` and the first-discovery pin for a hand-placed hook, the rollout directory and the delivered checksum for a rolled-out one. From this lookup until the process has started, `runHook` holds the [swap lock](#running-a-rolled-out-hook) for reading
3. **File checks**: `checkHookFile(dir, entry.Action, e.hookOwnerUID)`, where `dir` is the directory the lookup picked, refuses a hook that leaves the hooks directory, is not a regular file, is not owned by root, or is group- or other-writable (see [Hook File Checks](#hook-file-checks)). A missing file, a dangling link among them, fails with `hook not found: <name>`
4. **Integrity verification**: call `HookVerifier.VerifyHook(ctx, nodeID, hookPath, pinnedChecksum)`, where `pinnedChecksum` is, for a hand-placed hook, the digest this process recorded the **first** time it discovered the hook — **not** a wire field, and **not** the digest `HookWatcher` last recomputed. For a rolled-out hook it is the checksum the pull delivered for the installed version (see [Hook Integrity Pinning](#hook-integrity-pinning)). A hook the file checks refused never gets here, so a wrong owner files no integrity violation
5. **Execute**: `exec.CommandContext` with `WaitDelay=500ms`, in a process group of its own (see [Process Group](#process-group)). `Start` runs under the swap lock, which is released once the process has started, so `Wait` and the rest of the run do not hold up a swap of the hook
6. **Environment**: minimal env (`PATH`, `HOME`, `PLEXD_NODE_ID`, `PLEXD_EXECUTION_ID`) plus `PLEXD_PARAM_*` vars
7. **Output capture**: stdout and stderr each captured in a buffer truncated to `MaxOutputBytes`; the joined body is truncated back to `MaxOutputBytes` so a hook saturating both streams stays within the per-action cap

#### Hook File Checks

`checkHookFile(hooksDir, name string, ownerUID uint32) error` decides whether plexd trusts a file in the hooks directory. It runs on every dispatch, for the hook in `runHook` and for its sidecar, when one exists, in [`loadHookDeclaration`](#sidecar-at-run-time). The sidecar gets the same checks because it gates the run and sits outside the digest, so an account that could write it could lift a refusal. The checks run in this order:

1. Resolve the hooks directory and the file with links followed, and require the file to stay inside the directory. The directory may itself be a link, and a link to another file in the directory or in a subdirectory of it passes
2. Require a regular file
3. Require owner uid 0
4. Require no group or other write bit

A file that does not exist returns an error matching `fs.ErrNotExist`, and the caller decides what that means: `runHook` fails with `hook not found: <name>`, and a missing sidecar declares nothing. Every other failure refuses the run:

| Failure | Terminal `error` |
|---|---|
| The path leaves the directory | `hook refused: <name> resolves outside the hooks directory` |
| Not a regular file | `hook refused: <name> is not a regular file` |
| Wrong owner | `hook refused: <name> is owned by uid <uid>, not root` |
| Group- or other-writable | `hook refused: <name> is group- or other-writable (mode <mode>)` |
| The owner cannot be read | `hook refused: <name>: owner unavailable` |
| Any other resolve or stat error, such as a link loop | `hook refused: <name>: <cause>` |

`<name>` is the file checked, so a sidecar reads `deploy.json`. `<mode>` is the permission bits in four octal digits, such as `0775`.

Owner means uid 0 exactly. There is no exception for the agent's own uid, so an agent that does not run as root, such as the published container image at uid 65534, runs root-owned hooks only. The checks read the disk on every dispatch, so `chown root` or `chmod go-w` takes effect on the next one, with no agent restart, and neither command moves the digest or the pin.

Discovery does not apply these checks. A refused hook stays in the capability manifest and on the local API, and the dispatch's `error` says why it did not run.

#### Process Group

`runHook` starts the hook in a process group of its own, and the end of the run's context, at the run deadline, on a [cancel request](#cancel), or on `Shutdown`, sends `SIGKILL` to the whole group, so the script's children end with it. `WaitDelay` then bounds how long `Wait` holds the output pipes open, so a child that left the group with `setsid` and escaped the kill cannot hold the run open. A hook that exits by itself is unchanged, and a background child it leaves behind keeps running.

A limit or a cancel request that lands after the script has exited, while a child still holds the output pipes, sends no group kill, because `exec.Cmd` has stopped watching the context by then.

#### Hook Integrity Pinning

The pull entry carries **no** checksum, so hook trust anchors on a digest the node pins itself: the one recorded the **first** time this process discovered the hook. The pin matches the first report of the hook to the control plane only. Later reports carry the digest the watcher last computed, which can differ from the pin after an edit, and that difference is how the control plane sees the drift.

The pin is what makes the check meaningful. `HookWatcher` re-hashes a hook on every write and pushes the new digest through `SetHooks`, so verifying against the live snapshot would compare a file with a hash of itself and pass for whatever bytes are on disk, including an attacker's, since the integrity callback only logs. A pin is therefore never updated and never dropped for the life of the process: a hook whose bytes change after discovery fails verification, files an integrity violation, and stays unrunnable until the agent restarts and re-attests it. That is also why a legitimately edited hook needs an agent restart before it can run again. `plexd hooks reload` is not a substitute: it re-scans the directory and moves no pin.

A [rolled-out hook](#rolled-out-hooks) is pinned differently. Its pin is the checksum the pull delivered for the version plexd installed, which plexd checked against the signed payload and the fetched script before it wrote a byte, so a rolled-out hook is never trusted on first use. `SwapRolloutHook` moves the pin when plexd installs a new version, so the new version runs with no agent restart and no acceptance at the control plane. `RemoveRolloutHook` drops it when the hook is withdrawn. `SetRolloutHooks`, which the rollout directory's watcher calls, never touches it, and neither does a reload.

A local edit of a rolled-out file fails verification like an edit of a hand-placed hook: the run fails with `integrity check failed for hook: <name>` and files one `hook_checksum` violation detected `pre_dispatch`. A restart does not clear it, because `Load` pins each recorded hook to the checksum the record holds rather than to the bytes on disk, and a pass does not fetch the version again while the edited script is there, because it compares the pull with that record. Deleting the edited script is the local way out: a recorded hook whose script is gone counts as not installed, so the next pass fetches the listed version again, writes the delivered bytes, and pins them to the same checksum. Otherwise the hook stays refused until the control plane rolls out another version or withdraws the hook.

Upstream integrity — whether this node should run this hook at all — is the control plane's server-side dispatch gating, not a field the node re-checks.

### Shutdown

1. Sets `shuttingDown = true` under mutex
2. Collects all active cancel functions
3. Calls each cancel function to cancel running contexts. A PlexdHook run then leaves its Job running: it logs `leaving the plexd hook job running; the next agent start resumes it` at info and sends no callback, so the entry stays at `started` and the next agent process [resumes](#resume-after-a-restart) it. A script hook is killed because it is plexd's child process; a Job is not
4. Subsequent `Execute` and `Resume` calls return `ErrDispatchDeferred` with `reason=shutting_down`, so the pull redelivers them to the next agent process

### Cancel

```go
func (e *Executor) Cancel(executionID string) bool
```

`Cancel` stops one run on a cancel request. It reads the run's cancel function from the active map under the mutex, records the id as cancel-requested, calls the function after unlocking, and reports whether it found one. The record is how a PlexdHook run tells a cancel request, which deletes its Job, from a [shutdown](#shutdown), which leaves the Job running; it goes when the run leaves the active map. An empty or unknown id returns false and does nothing. A second call for the same run does nothing more, because a cancel function is idempotent. `Cancel` leaves `shuttingDown` alone, so other dispatches go on.

The dispatcher calls it for an entry that carries `cancel_requested_at` (see [Handled Set](#handled-set)). `Cancel` sends no callback, and the run's own terminal callback says how the run ended:

| What the cancel finds | Terminal callback |
|---|---|
| A running hook | Its process group is killed with `SIGKILL`, with no grace period (see [Process Group](#process-group)). `cancelled` with exit code -1 and the output captured so far, inline or uploaded by the 16 KiB rule |
| A running built-in that reports the stop | `cancelled`, with the output the built-in returned (see [Built-in Actions](#built-in-actions)) |
| A running built-in that does not watch its context | The built-in finishes, and the run reports its real outcome |
| A PlexdHook run, while plexd creates or follows its Job | plexd reads the pod's log so far and deletes the Job, under a budget of 10 seconds. `cancelled` with that log, inline or uploaded by the 16 KiB rule. A delete that fails logs `plexd hook job delete failed` and reports `cancelled` without output (see [Kubernetes CRD Hooks](#kubernetes-crd-hooks)) |
| A run whose result is already computed | Its real outcome, because the report leg is detached from the action context. The dispatcher still logs `cancel requested; stopping the run` |

`cancelled` carries an empty `error`. The control plane takes `cancelled` from `started` only, from a node that stopped the run at its own shutdown or on a cancel request. A run that finished first reports its real outcome, and a run whose report never lands ends at the Execution's timeout. A `cancelled` report gets the retries of any terminal callback and is not sent again on a later pull.

plexd learns of a cancel on its next pull: at most `reconcile.interval` later (60 s by default), sooner when a heartbeat or an event triggers the pull. The control plane sends no event for a cancel.

A run started through the local API (`plexd actions run`) is not in the active map. It is bound to its HTTP request and has no Execution to cancel.

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

The production implementation is `integrity.Verifier`, which computes SHA-256 of the hook file and compares it against the hook's pin: the digest plexd recorded when it discovered a hand-placed hook on disk, or the checksum the pull delivered for a rolled-out one.

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

A built-in runs under the run's context, which the run deadline, a [cancel request](#cancel), and `Shutdown` end. Six built-ins pass that context on to a call and report a stop. When such a call fails while the context has ended, the built-in returns an error that wraps the context's own error, so `errors.Is` finds `context.Canceled` or `context.DeadlineExceeded` in it. A cancel of one of them then reports `cancelled`, and its deadline reports `failed` with `error` `action timed out`, or `action timed out: max_action_timeout <d>` when the ceiling set the deadline. A call that fails while the context is live returns what the built-in's section describes, with no error.

| Built-in | Output and exit code of a stopped run | Error returned |
|---|---|---|
| `diagnostics.collect` | The JSON collected so far on stdout, exit code 1 | `diagnostics collect: <cause>` |
| `diagnostics.ping_peer` | What `ping` printed before the kill, on stderr, with the exit code of the killed process, or 1 when the process never started | `ping <peer_id>: <cause>` |
| `diagnostics.traceroute_peer` | What the traceroute binary printed before the kill, in the same way | `traceroute <peer_id>: <cause>` |
| `service.restart` | The service manager's error on stderr, exit code 1 | `service restart: <cause>` |
| `service.upgrade`, in its restart step | The `upgraded_restart_failed` JSON on stdout, exit code 1 | `service upgrade: restart: <cause>` |
| `mesh.reconnect` | The `failed` JSON on stdout, exit code 1 | `mesh reconnect: <cause>` |

`<cause>` is `context canceled` or `context deadline exceeded`. The error never reaches the control plane, whose terminal callback carries the status, the exit code, and the output. Only the [local API](#post-v1-actions-run) shows it, in `stderr` with `status` `error`, and its request context ends only when the client has gone.

The other five built-ins, `system.info`, `health.check`, `config.dump`, `logs.snapshot`, and `service.reload_config`, take no notice of their context. A cancel or a deadline that meets one of them lets it finish, and the run reports its real outcome.

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

Six fields are read per platform:

| Field | Linux | macOS | Windows |
|---|---|---|---|
| `memory_total` | `MemTotal` from `/proc/meminfo` | `hw.memsize` | `GlobalMemoryStatusEx` |
| `load_avg` | the `/proc/loadavg` line | `vm.loadavg`, formatted as `1.50 2.00 2.50` | empty, Windows has no load average |
| `disk_total` | `statfs` of `/` | `statfs` of `/` | `GetDiskFreeSpaceEx` of `%SystemDrive%\` |
| `kernel_version` | the `uname` release (e.g. `6.1.0-amd64`) | the `uname` release (e.g. `24.6.0`) | `major.minor.build` from `RtlGetVersion` (e.g. `10.0.19045`) |
| `network_interfaces` | `ip addr show` | `/sbin/ifconfig -a` | `%SystemRoot%\System32\ipconfig.exe /all` |
| `processes` | `ps aux --no-headers` | `/bin/ps aux` | `%SystemRoot%\System32\tasklist.exe` |

When the `uname` call fails, `kernel_version` falls back to `<GOOS>/<GOARCH>`.

`memory_total` and `load_avg` come from the platform system reader (see [degraded readings](../observability/metrics-collection.md#degraded-readings)) where the `/proc` files do not exist. A reader error leaves both at the values the `/proc` reads produced, which is 0 and empty on those platforms. The same holds for a single source the reader could not read: it reports a zero field, and `load_avg` stays empty rather than reporting `0.00 0.00 0.00`.

The macOS and Windows commands are addressed by absolute path, as are the ping and traceroute binaries of the two peer diagnostics below. launchd starts the daemon with a minimal `PATH`, and the Windows service runs as `LocalSystem`, where a bare name would be resolved through the machine `PATH` and any entry ahead of `System32` would run with `SYSTEM` rights.

Linux resolves the same binaries from the system directories (`/usr/sbin`, `/sbin`, `/usr/bin`, `/bin`) first and only falls back to a `PATH` lookup for distributions that place them elsewhere. The daemon runs as root under systemd, so it must not take the first `PATH` match either: an entry ahead of those directories that an unprivileged account can write to — a unit drop-in extending `PATH`, an operator shell carrying `~/bin` — would otherwise run with root rights.

The platform reader's `ReadStats`, the network listing, and the process listing take the run's context. The built-in reports a stop only when one of those calls failed while the context had ended: it then returns the JSON collected so far with exit code 1, so a cancel request reports `cancelled` and the run deadline reports `failed` with `error` `action timed out`. A call that fails while the context is live leaves its field empty, with exit code 0. A run that collected everything returns exit code 0 and no error, even when the context ended after its last call.

### diagnostics.ping_peer

Pings a mesh peer and reports latency. The binary and its flags are picked per platform, because the flag letters and the unit of the wait differ:

| Platform | Command |
|---|---|
| Linux | `ping -c <count> -W 3` |
| macOS | `/sbin/ping -c <count> -W 3000` — BSD `ping` reads `-W` in milliseconds |
| Windows | `%SystemRoot%\System32\ping.exe -n <count> -w 3000` |

| Parameter | Type   | Required | Default | Description              |
|-----------|--------|----------|---------|--------------------------|
| `peer_id` | string | yes      | —       | Peer mesh IP address     |
| `count`   | string | no       | `1`     | Number of pings (max 10) |

Returns ping output in stdout. Exit code 0 on success, 1 on failure (unreachable or invalid IP).

The echo requests are traffic the node itself sends over the mesh, which its compiled policy governs (see [What the rules govern](../networking/pf-wfp-firewall.md#what-the-rules-govern)). The policy therefore needs a rule that allows ICMP from the node's mesh IP to the peer. On macOS the echo replies need a rule from the peer to the node as well, because pf keeps no state for the node's own ICMP. A Project's allow-all policy covers both. Without the outbound rule no echo request leaves the node, and the run fails as it does for an unreachable peer.

On Windows the exit status is not the whole answer: `ping.exe` exits 0 for any ICMP response, a router's `Destination host unreachable` and a `TTL expired in transit` included. The reply is therefore checked for the `TTL=` token of a real echo reply, the one part of the line Windows does not localize, and an answer without it is reported as exit code 1 with the output on stderr. `iputils` and BSD `ping` report the same case through the exit status, so their output is not read.

A cancel request or the run deadline kills `ping`. A cancel reports `cancelled`, and the deadline reports `failed` with `error` `action timed out`. Either report carries what `ping` printed before the kill, with the exit code of the killed process: -1 on Linux and macOS, where the kill is a signal, and 1 on Windows, where the kill ends `ping.exe` with exit status 1. A run stopped before `ping` started reports exit code 1.

### diagnostics.traceroute_peer

Traceroute to a mesh peer. The binary and its flags are picked per platform:

| Platform | Command |
|---|---|
| Linux | `traceroute -n -m <max_hops> -w 3`, resolved from the system directories, then `PATH` |
| macOS | `/usr/sbin/traceroute -n -m <max_hops> -w 3` |
| Windows | `%SystemRoot%\System32\tracert.exe -d -h <max_hops> -w 3000` — Windows has no `traceroute.exe`, and `-d` is its `-n` |

| Parameter  | Type   | Required | Default | Description              |
|------------|--------|----------|---------|--------------------------|
| `peer_id`  | string | yes      | —       | Peer mesh IP address     |
| `max_hops` | string | no       | `15`    | Maximum number of hops   |

Returns traceroute output in stdout. Exit code 1 with the error `traceroute not available` when neither the Linux system directories nor the `PATH` lookup hold the binary; macOS and Windows ship it at a fixed path.

The probes are traffic the node itself sends over the mesh, so they need a rule from the node's mesh IP to the peer, as `diagnostics.ping_peer` does. A rule that names no protocol covers the probes of every platform's binary. On macOS the replies need a rule from the peer to the node as well, because pf keeps no state for the node's own UDP and ICMP. A Project's allow-all policy covers both.

A cancel request or the run deadline kills the traceroute binary. A cancel reports `cancelled`, and the deadline reports `failed` with `error` `action timed out`. Either report carries what the binary printed before the kill, with the exit code of the killed process: -1 on Linux and macOS and 1 on Windows, as for `ping`. A run stopped before the binary started reports exit code 1.

### service.restart

Asks the host's service manager to restart plexd: `systemctl restart plexd` on Linux, `launchctl kickstart -k system/com.plexsphere.plexd` on macOS, a detached `Restart-Service plexd` on Windows. No parameters required.

The action returns exit code 1 with the error `service manager not available` when the manager cannot be driven from the daemon's process, and exit code 1 with the manager's own error on stderr when the restart is refused.

A restart that fails while the run's context has ended returns the same stderr and exit code 1, with an error that wraps the context's. A cancel request then reports `cancelled`, and the run deadline reports `failed` with `error` `action timed out`.

A restart through `systemctl restart plexd` stops plexd itself: systemd kills the `systemctl` child in plexd's cgroup, while the `SIGTERM` it sends plexd cancels plexd's root context and with it the run. The run's report, if it lands before plexd exits, usually reads `cancelled`: in the contract, a run the node stopped at its own shutdown. When plexd sees the `systemctl` child die before the shutdown has ended the run's context, the report reads `failed` with the manager's error on stderr, as before.

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

The restart step reports a stop the way [`service.restart`](#service-restart) does. A restart that fails while the run's context has ended comes after the new binary is in place, so stdout still carries the `upgraded_restart_failed` JSON, with the `message` `binary replaced, restart failed: <error>`, and the exit code is 1. The error returned wraps the context's, so a cancel request reports `cancelled` and the run deadline reports `failed` with `error` `action timed out`. The steps ahead of the restart return their errors as well, so a download that a cancel request or the deadline cuts short reports the same way. A restart through `systemctl restart plexd` stops plexd itself, as it does for `service.restart`, so the run's report, if it lands before plexd exits, usually reads `cancelled`, and reads `failed` when plexd sees the `systemctl` child die before the shutdown has ended the run's context.

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

A reconnect that fails because its context ended returns the same JSON and exit code 1, with an error that wraps the context's. A cancel request then reports `cancelled`, and the run deadline reports `failed` with `error` `action timed out`.

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

Monitors a hooks directory for filesystem changes using `fsnotify`, and re-scans it on demand through `Reload`. Replaces the one-time `DiscoverHooks` call with a continuous watch loop.

### Constructor

```go
func NewHookWatcher(hooksDir string, onChange HookChangeCallback, onIntegrity IntegrityAlertCallback, logger *slog.Logger) *HookWatcher
func NewRolloutHookWatcher(dir string, onChange HookChangeCallback, onIntegrity IntegrityAlertCallback, logger *slog.Logger) *HookWatcher
```

| Parameter     | Description                                          |
|---------------|------------------------------------------------------|
| `hooksDir`, `dir` | Directory containing hook scripts                |
| `onChange`    | Callback invoked with the full hooks list on change  |
| `onIntegrity` | Callback invoked when a hook's checksum changes     |
| `logger`      | Structured logger (`log/slog`)                      |

The two constructors build the same watcher and differ in the `Source` every hook it reports carries: `local` from `NewHookWatcher`, for `hooks_dir`, and `rollout` from `NewRolloutHookWatcher`, for the directory plexd installs [rolled-out hooks](#rolled-out-hooks) into. The directory decides the source, never the file. The rollout watcher therefore reports a file copied into the rollout directory by hand as `rollout`, and the executor leaves it out of the merged list, because it has no pin.

### Callbacks

```go
type HookChangeCallback func(hooks []api.HookInfo)
type IntegrityAlertCallback func(hookName, oldChecksum, newChecksum string)
```

### Methods

| Method   | Signature                                 | Description                                       |
|----------|-------------------------------------------|---------------------------------------------------|
| `Watch`  | `(ctx context.Context) error`             | Monitor directory; blocks until ctx is cancelled   |
| `Reload` | `() ([]api.HookInfo, error)`              | Re-scan the directory, replace the list, and return it; works with or without `Watch` running |
| `Hooks`  | `() []api.HookInfo`                       | Return sorted snapshot of current hooks            |

### Watch Lifecycle

1. Create hooks directory if it does not exist
2. Start the `fsnotify` watch with `fsutil.WatchDir`. A hook that vanishes while the watch is set up (macOS and the BSDs) makes it set the watch up again after 100 ms, up to 10 attempts. If set-up still fails, `Watch` runs the initial scan once and returns the error, so the hooks on disk stay registered without live updates
3. Perform the initial scan, the same scan `Reload` runs. It replaces the list, so it also prunes a hook removed since the boot scan. A scan that fails logs `actions: watcher: initial scan failed` and reports the current list once. The scan runs after the watch is in place, so a hook changed during start-up is in the scan, arrives as an event, or both
4. On file create/write/chmod: debounce (200ms), then stat the file. A file that is not a regular, executable file leaves the list. Otherwise compute the checksum, update the hooks map, and call `onChange`. A hook that fails to hash keeps its entry, and `actions: watcher: hash failed` is logged
5. On file remove/rename: debounce, remove from hooks map, call `onChange`
6. On `.json` sidecar create/write/chmod/remove/rename: debounce, then rebuild the parent hook's entry from disk, so a sidecar that went away takes its metadata with it. A `.json` file no hook owns changes nothing
7. On checksum change for an existing hook: call `onIntegrity` with old and new checksums
8. On context cancellation: stop all timers, return nil

The watch is not restarted when it fails: `plexd up` logs `hook watcher stopped`, the hook list stays as it was, and `plexd hooks reload` is how to refresh it on such a node.

### Reload

`Reload` runs the scan `DiscoverHooks` runs, replaces the list with the result, and returns it sorted by name. It reports through the same callbacks as a file event: `onIntegrity` once per hook whose digest changed, then `onChange`.

| Case | Result |
|------|--------|
| A file vanished since the last scan | It leaves the list |
| A file fails to hash | It keeps its last digest and a warning is logged. One transient read error must not remove a hook from the executor and the capability manifest, because no later event would bring it back. A file the watcher did not list stays unlisted |
| A file with an executable bit is not a regular file | It is skipped with the warning `actions: discovery: not a regular file`, because opening a FIFO to hash it would block the scan. A file with no executable bit is skipped silently, whatever it is. A symlink counts by its target: a link to a FIFO warns, and a link to an executable regular file stays a hook. A change to the target raises no file event, so it reaches the list through a reload or a restart, and until the restart the pin refuses a changed target at dispatch. A link that resolves outside the hooks directory stays listed, and a dispatch of it is [refused](#hook-file-checks) |
| The directory does not exist | An empty list and a nil error |
| The directory cannot be read | The error `actions: watcher: scan <dir>: <cause>`, the list left as it was, and no callback fired |

`Reload` moves no pin. `SetHooks` receives the new digest and leaves the [integrity anchor](#hook-integrity-pinning) where it was, so an edited hook runs again after an agent restart, not after a reload.

### Change Ordering

Debounce timers run on separate goroutines, so `Reload` and the timers take one lock, `changeMu`, across the change to the list and the `onChange` call that reports it. Concurrent reloads therefore run one at a time, and the last `onChange` always carries the newest list. The lock is held across `onChange`, which must not block.

### Integration with Executor

In `cmd/plexd/cmd/up.go`, the watcher is wired to the executor and the capability reporter:

```go
hookWatcher := actions.NewHookWatcher(cfg.Actions.HooksDir, func(hooks []api.HookInfo) {
    executor.SetHooks(hooks)
    capabilityReporter.Notify()
}, onIntegrityAlert, logger)
```

When hooks change, `executor.SetHooks` is called, updating `Capabilities()` output, and `Notify` asks the [capability reporter](#capability-announcement) for a new report. Neither blocks. `SetHooks` does **not** move the integrity anchor of a hook the executor has already seen; see [Hook Integrity Pinning](#hook-integrity-pinning). `Reload` satisfies the `nodeapi.HookReloader` interface.

When the rollout installer exists and `rollouts_enabled` is not `false`, `plexd up` builds a second watcher with `NewRolloutHookWatcher` for the rollout directory. Its `onChange` calls `executor.SetRolloutHooks` and `Notify`, and its integrity callback logs `hook integrity change detected` with `source` `rollout`. With rolled-out hooks refused there is no second watcher, because `Load` has emptied the directory and no pass writes to it.

`plexd up` hands the node API neither watcher. It wires an adapter, `hookDirsReloader`, whose `Reload` reloads `hooks_dir` and then the rollout directory, each even when the other failed, and answers with the executor's merged list rather than either watcher's: a rolled-out file is in it only once the installer pinned it, and a hand-placed hook shadows a rolled-out hook of its name. A failure of either scan returns both errors joined, and no list.

`plexd up` runs that `Reload` once before it starts anything that reads the hook list, so a dispatch the reconciler delivers does not meet an empty list, unless that scan fails or outlives its 10-second wait, and the first scan records the pins of the hand-placed hooks. One wait covers both directories. The installer's `Load` runs just before it, so the scan finds the rollout directory holding only files the record vouches for, each already pinned. Both `Watch` loops and the installer's `Run` start later, at step 20.

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

Lists all registered hooks (subset of GET /v1/actions response): the executor's merged list, sorted by name. A rolled-out entry carries `"source": "rollout"` and the `version` it was installed from; a hand-placed entry carries `"source": "local"` and no `version` key.

### POST /v1/hooks/reload

Re-scans `hooks_dir` and, while rolled-out hooks are on, the rollout directory via the `HookReloader` interface (satisfied by `plexd up`'s `hookDirsReloader`, see [Integration with Executor](#integration-with-executor)) and returns the executor's merged list. The route takes no input. It hashes every hook file, so it keeps the guards every route has: the socket's permissions, and the bearer token on the optional HTTP listener.

**Response:**

```json
{
  "status": "reloaded",
  "hooks": [...]
}
```

`hooks` is `[]` for an empty directory, never `null`.

| Status | Condition | Body |
|--------|-----------|------|
| `200`  | Scan finished | `status` and `hooks` as above |
| `500`  | A directory could not be read; its list stays as it was | `{"error": "actions: watcher: scan <dir>: <cause>"}`, one line per directory that failed |
| `503`  | No reloader is wired in | `{"error": "hook reloader not available"}` |

## CLI Commands

### plexd actions

Lists available actions via `GET /v1/actions` over Unix socket. Output is a tab-separated table with TYPE, NAME, and DESCRIPTION columns.

### plexd actions run \<name\>

Runs an action via `POST /v1/actions/run`. Accepts `--param key=value` flags for passing parameters.

### plexd hooks list

Lists hooks via `GET /v1/hooks`. Shows NAME, SOURCE, VERSION, CHECKSUM (truncated to 12 chars), and DESCRIPTION. SOURCE is `local` for a hand-placed hook and `rollout` for a [rolled-out hook](#rolled-out-hooks). VERSION is the published version a rolled-out hook was installed from, and empty for a hand-placed hook:

```text
NAME       SOURCE   VERSION  CHECKSUM         DESCRIPTION
backup-db  rollout  2        44403dc87411...  Dump the application database
deploy     local             9f86d081884c...  Deploy
```

The list shows what the executor runs, not what the control plane asked for: a version plexd could not install is reported to the control plane in `hook_rollout_errors` and does not appear here.

### plexd hooks verify

Reads hooks via `GET /v1/hooks` and checks that each hook has a checksum. Reports `OK` or `WARN` per hook.

### plexd hooks reload

Re-scans `hooks_dir` and, while rolled-out hooks are on, the rollout directory via `POST /v1/hooks/reload`. Prints the status and the hook count of the executor's merged list:

```text
Status: reloaded
Hooks:  2
```

A `500` makes the command exit non-zero with `plexd hooks reload: unexpected status 500: ...`. A reload moves no pin: an edited hand-placed hook runs again after an agent restart, not after a reload, and an edited rolled-out hook runs again as [Hook Integrity Pinning](#hook-integrity-pinning) describes.

## DiscoverHooks

Scans a directory for executable hook scripts and builds metadata.

```go
func DiscoverHooks(hooksDir string, logger *slog.Logger) ([]api.HookInfo, error)
```

1. Returns empty slice (not nil) if `hooksDir` is empty or does not exist
2. Skips directories, non-executable files, `.json` sidecar files, and anything that is not a regular file. A symlink to an executable regular file stays a hook, and the target's mode decides. The watch covers the directory and not a link's target, so a change to the target reaches the list only through a scan. A link that resolves outside the hooks directory stays a hook too, and a dispatch of it is [refused](#hook-file-checks)
3. Computes SHA-256 via `integrity.HashFile` for each executable
4. Parses optional `.json` sidecar for metadata (description, parameters, timeout, sandbox)
5. Results sorted by name
6. Individual file errors, an unreadable sidecar among them, logged at warn level; valid hooks still returned

Windows reports no executable bit on a regular file, so nothing is ever discovered there and no hook can be dispatched. Hook scripts are a Linux and macOS feature; see [Platform Support](../../guide/platform-support.md).

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

> **Warning**: A sidecar's content reaches the control plane and everyone who holds `read` there, and no setting keeps it on the node. A sidecar must hold no secret.

The capability manifest carries what the sidecar declares, under these keys and limits:

| Sidecar key | Manifest key | Type | Limit |
|---|---|---|---|
| `description` | `description` | string | At most 4096 characters |
| `parameters` | `parameters` | array of `ActionParam` | At most 64. Each `name` is not blank after trimming and is unique within the hook, compared raw, so `"a"` and `" a"` are two parameters. `name`, `type`, `default`, and `description` are at most 4096 characters each. `required` has no limit |
| `timeout` | `timeout_seconds` | `time.ParseDuration` string | 0 to 24 hours. The manifest carries whole seconds, rounded up, so `"1500ms"` reports 2 and `"500ms"` reports 1 rather than 0. `"0s"` or no key means none declared and leaves the manifest key off |
| `sandbox` | `sandbox_level` | string | At most 64 characters. The manifest takes any value, and a run refuses any but `none` and the empty string |

Characters are Unicode code points, and a NUL in any of these strings breaks its limit.

plexd reports `timeout` and `sandbox` as written and applies both when it runs the hook; see [Sidecar at Run Time](#sidecar-at-run-time). A `timeout` above `max_action_timeout` reports as written, and the run still ends at `max_action_timeout`.

A field that breaks a limit is left off the manifest with the warning `hook metadata omitted from the capability manifest`, and the hook stays with its other fields, because one field past a limit would otherwise cost the whole manifest. A `timeout` or `sandbox` left off this way still refuses every dispatch of the hook, because the run reads the same value and cannot use it. One parameter that breaks a rule leaves off the whole `parameters` list, because a form with a required parameter missing misleads. An empty `parameters` list stays off the manifest.

A missing sidecar logs nothing. A malformed one logs `sidecar parse failed` and an unreadable one logs `sidecar read failed`, and anything but a regular file counts as unreadable. A symlink counts as its target, so a dangling one reads as missing. In each case the hook stays listed with no metadata, and plexd keeps no earlier value of it. A dispatch tells them apart: a missing sidecar lets the hook run, and a malformed or unreadable one refuses the run.

### Sidecar at Run Time

A dispatch of a hook reads its sidecar from disk, not from the hook list, because the list cannot tell a missing sidecar from a malformed one, and only the missing one lets the hook run. `loadHookDeclaration(hooksDir, name string, ownerUID uint32) (hookDeclaration, error)` runs these steps in order, and the first that fails ends the run `failed` with exit code 1 before `runHook` starts:

1. The hook name passes the path traversal check `runHook` applies, or the run fails with `invalid hook name: <name>`
2. The sidecar passes the [file checks](#hook-file-checks) the hook gets. A sidecar that does not exist, a dangling link among them, declares nothing
3. The sidecar is read and parsed as JSON. A failure refuses the run with `hook refused: sidecar <name>.json: <cause>`. A 0-byte file fails here with `unexpected end of JSON input`, and a literal `null` or `{}` declares nothing
4. `sandbox` is empty or `none`. Any other value refuses the run with `hook refused: sandbox level "<value>" is not implemented; plexd runs hooks at level none only`; see [Sandbox Options](sandbox-options.md)
5. `timeout` is empty or a duration from 0 to 24 hours, by the rule the manifest applies. Any other value refuses the run with `hook refused: sidecar <name>.json declares an unusable timeout "<value>": want a duration from 0 to 24h`. A timeout above 0 joins the [run deadline](#run-deadline)

`<value>` is the sidecar's value cut to its first 64 characters and printed as a quoted Go string. A sidecar value has no length limit at this point, and the control plane answers `400` to an `error` over 4096 characters, which would strand the execution at `started`. The quoting also escapes a NUL, which a JSON string can carry.

Every refusal walks the claim first, so the control plane sees `ack`, `started`, and `failed`, the sequence an integrity failure shows. The hook stays listed, and plexd logs `hook refused` at warn with the same error. A fixed sidecar takes effect on the next dispatch with no agent restart, because a sidecar sits outside the hook's digest and the run reads it each time.

## Rolled-out Hooks

A Project can publish a script hook at the control plane as signed, numbered versions and roll one version out to a node. The pull's [`hooks` block](../core/api-endpoints.md#get-v1-nodes-node-id-state) lists the versions the node should run, and `actions.RolloutInstaller` (`internal/actions/rollout.go`) converges on it: it fetches each listed version it has not installed with the node's NSK, verifies the Domain signature and the checksum, installs the script into a directory plexd owns, and removes the rolled-out hooks the block no longer lists. The wire is the "Published hooks" section of plexsphere's agent contract (`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere).

A rolled-out hook's pin is the checksum the pull delivered, not the digest plexd first saw on disk. A new version therefore runs without an agent restart, and a local edit of a rolled-out file fails the pre-dispatch check and files an integrity violation, as an edit of a hand-placed hook does (see [Hook Integrity Pinning](#hook-integrity-pinning)).

```go
func NewRolloutInstaller(cfg Config, dataDir, nodeID string, fetcher HookVersionFetcher, verifier HookSignatureVerifier, executor *Executor, logger *slog.Logger) (*RolloutInstaller, error)
```

| Parameter  | Description |
|------------|-------------|
| `cfg`      | Actions configuration. `RolloutHooksDir` is the rollout directory, `HooksDir` the directory a [collision](#collision) is checked against |
| `dataDir`  | Directory of the record, `hook_rollouts.json` |
| `nodeID`   | Node the versions are fetched for |
| `fetcher`  | `HookVersionFetcher`, `FetchHookVersion(ctx, nodeID, name, version)`. `*api.ControlPlane` satisfies it |
| `verifier` | `HookSignatureVerifier`, `VerifySignature(env api.Envelope) error`. `*api.Ed25519Verifier` satisfies it |
| `executor` | The executor the installer pins each installed hook in |
| `logger`   | Structured logger, tagged `component=actions` |

The constructor returns an error for an empty `RolloutHooksDir` or `dataDir`, a nil `fetcher`, `verifier` or `executor`, and a rollout directory that is `HooksDir`: the same path once both are made absolute and cleaned, so a relative `HooksDir` counts, or, when both exist, the same directory by `os.SameFile` on what `os.Stat` returns, which follows a symlink. It refuses that directory because the installer removes every file it did not write from its directory, which there would be the operator's hand-placed hooks. `plexd up` logs the error as `rolled-out hooks disabled` and runs on without rolled-out hooks: builtins and hand-placed hooks are unaffected, no pull's `hooks` block is read, and the manifest carries no `hook_rollout_errors`.

| Method | Signature | Description |
|--------|-----------|-------------|
| `Load` | `() error` | Restore what the installer put on disk before this process started (see [Load at Start](#load-at-start)) |
| `Handle` | `(ctx context.Context, desired *api.NodeStateSnapshot)` | A `reconcile.DispatchHandler`: hand the pull's `hooks` block to `Run` and return |
| `Run` | `(ctx context.Context) error` | Run one [pass](#the-pass) per block handed over; returns nil when `ctx` ends |
| `Errors` | `() []api.HookRolloutError` | The rollout errors of the last pass, a copy, or nil when there are none |
| `SetOnChange` | `(fn func())` | Register `fn`, called on `Run`'s goroutine after a pass that changed the installed hooks or the errors |

### Directory and Record

| Path | Mode | Content |
|------|------|---------|
| `<data_dir>/hooks/` | `0755` | The rollout directory, `RolloutHooksDir`: `/var/lib/plexd/hooks` on Linux, created by `Load` and again by each install |
| `<data_dir>/hooks/<name>` | `0755` | The script, the bytes the fetch delivered |
| `<data_dir>/hooks/<name>.json` | `0644` | A sidecar in plexd's own [format](#sidecar-metadata-format), built from the signed payload: `description`, `parameters`, `timeout` as `"<timeout_seconds>s"` when `timeout_seconds` is above 0, and `sandbox` `"none"`. An empty field is left out |
| `<data_dir>/hook_rollouts.json` | `0600` | The record of what the installer put into the directory: `{"hooks":[{"name":"backup-db","version":2,"checksum":"<64 lowercase hex>"}]}`, sorted by name, the checksum being the delivered one in hex |

Every file goes through `fsutil.WriteFileAtomic`, a temporary `.tmp-<name>-<random>` file in the same directory renamed into place, so no reader sees a partial file. Under the systemd unit `plexd install` writes, `data_dir` is among the `ReadWritePaths`, so plexd can write the directory with no unit change.

plexd owns the rollout directory. Only the installer writes there, and `Load` removes every file it did not write. A subdirectory is left alone.

The installer compares the pull with its record, never with the bytes on disk. A recorded hook at the listed version and checksum whose script exists counts as installed, even when the script was edited, and a recorded hook whose script is gone counts as not installed and is fetched again. A record that cannot be read or decoded, or that holds a name outside the grammar, a version below 1, a checksum that is not a lowercase hex SHA-256 digest, or a name twice, is logged as `actions: rollout: record unreadable; starting empty` and treated as empty: `Load` then removes the files it no longer vouches for, and the next pass fetches the listed versions again. A missing record is an empty one and logs nothing.

### Load at Start

`plexd up` calls `Load` once, after it built the rollout watcher and before the boot hook scan, so the scan finds only recorded files and each is already pinned. `Load` does this:

1. Read the record.
2. Drop each entry whose script is missing.
3. Pin each remaining entry to its recorded version and checksum through `SwapRolloutHook` with a nil swap, which touches no file.
4. Save the record when step 2 dropped an entry.
5. Create the rollout directory with mode `0755`.
6. Remove every file of the directory that is neither a recorded script nor its sidecar, which covers the `.tmp-*` leftovers of a write a crash interrupted, and log `actions: rollout: stray file removed` for each.

With `rollouts_enabled: false` it removes every recorded hook and every other file of the directory instead, pins nothing, and saves an empty record. It does not create the directory. A recorded hook it cannot remove logs `actions: rollout: hook not removed` and still leaves the record, so no pass tries the removal again: the stray cleanup of the same `Load` tries once more, and so does every later start, each logging `actions: rollout: stray file not removed` while the removal fails. Nothing pins such a file, so it cannot run. On Windows it does nothing.

`Load` returns an error when the rollout directory cannot be created or read. `plexd up` logs it as `actions: rollout: load failed` and keeps starting. Every later pass creates the directory again before an install, or reports `install_failed` while it cannot.

### The Pass

`Handle` runs on the reconcile goroutine, on every successful pull, and fetches nothing. A pull whose `hooks` block is `null`, or a control plane that predates the block and leaves it out, logs `actions: rollout: pull carried no hooks block; keeping rolled-out hooks` at Debug and changes nothing: no pass runs, nothing is removed, and the rollout errors stay as they were. Any other block, `[]` included, is copied into a one-slot pending field, and `Handle` signals `Run` without blocking. `Run` takes the newest pending block for each signal, so blocks handed over while a pass runs collapse into one next pass. The fetches therefore never hold back the rest of the reconcile cycle, the `executions` block among it. A dispatch cannot name a rolled-out hook before the manifest reports it, so a version installed after the dispatches of the same cycle loses nothing.

A pass converges on the block, which is the node's full desired set, in four steps.

**1. Entry validation.** An entry whose name is outside `^[a-z0-9][a-z0-9_-]{0,62}$` (`invalid name`), whose version is below 1 (`invalid version`), or whose name an earlier entry already used (`duplicate name`) is dropped and logged as `actions: rollout: entry dropped` with `name`, `version` and `reason`, once, and not again until the set of dropped entries changes. It gets no rollout error, because the control plane refuses such an error, and with it the whole manifest. A dropped entry whose name is on the grammar still counts as listed in step 2, so it keeps an installed hook of that name. An entry whose `checksum` does not decode to 32 bytes of standard base64 gets `verification_failed` with the detail `pull entry checksum is not 32 bytes of standard base64`, fetches nothing, and keeps whatever is installed under its name.

**2. Removals.** Every recorded hook whose name the block does not list is removed first, so a withdrawn hook stops running even when the fetches take the rest of the pass. `RemoveRolloutHook` deletes the script, then the sidecar (one already gone is not a failure), then drops the pin, and the installer then drops the record entry and saves the record. plexd logs `actions: rollout: hook removed` with `name` and `version`. A failed unlink logs `actions: rollout: hook not removed`, keeps the pin and the record entry, and is tried again on the next pass. A run that started before the removal keeps its process; a later dispatch of the name is rejected with `unknown_action`.

**3. Per-entry decision.** For each entry that step 1 neither dropped nor failed, in block order, the first rule that matches wins:

| # | Rule | Outcome |
|---|------|---------|
| 1 | The node runs Windows | `install_failed`, `script hooks are not supported on Windows` |
| 2 | `actions.rollouts_enabled` is `false` | `install_failed`, `rolled-out hooks are disabled on this node` |
| 3 | `os.Lstat(<hooks_dir>/<name>)` finds an entry | `collision`, `hooks_dir holds a hook of this name`. A recorded copy of the name is removed as in step 2, and plexd logs `actions: rollout: name collision with hooks_dir`. See [Collision](#collision) |
| 3 | `os.Lstat` fails with any error but "does not exist" | `install_failed`, `check hooks_dir: <error>` |
| 4 | The record holds the name at the listed version, its checksum equals the pull checksum, and the script exists | Installed: nothing happens |
| 5 | `actions.enabled` is `false` | `install_failed`, `actions are disabled on this node` |
| 6 | The fetch fails | `fetch_failed`, with the error text less its `correlation_id` as the detail, and `actions: rollout: fetch failed` logged |
| 7 | A [verification](#verification) check fails | `verification_failed`, with the check named, `actions: rollout: verification failed` logged at Error, and nothing written |
| 8 | The payload's `sandbox_level` is neither empty nor `none` | `install_failed`, `sandbox level "<level>" is not implemented` |
| 8 | The payload's `timeout_seconds` is outside 0 to 86400 | `install_failed`, `timeout_seconds <n> is outside the range 0 to 86400` |
| 9 | The install fails | `install_failed`, with the error text, and `actions: rollout: install failed` logged |
| 9 | Otherwise | Installed, and `actions: rollout: hook installed` logged with `name` and `version` |

The fetch runs under a 30-second deadline of its own. Every way it fails reads `fetch_failed`: a transport error, the deadline, a body over the 4 MiB cap or one that is not JSON, and each problem answer, such as `404 hook_not_assigned`, `500 hook_version_signature_invalid` or `503 signing_unavailable`. The detail is the error's text, so `api: HTTP 404 (hook_not_assigned): <message>` names the problem code. It leaves out the ` (correlation_id=<id>)` a problem answer appends to that text: the control plane gives every request a new id, so with it a fetch that keeps failing the same way would change the rollout errors on every pass and send the manifest again each time. The `actions: rollout: fetch failed` line keeps the id in its `error`.

The install creates the rollout directory, then calls `SwapRolloutHook` with a swap that writes the sidecar and then the script, so the executor sees the new pin only once both files are in place (see [Running a Rolled-out Hook](#running-a-rolled-out-hook)). It then records the version and saves the record. A failure in the swap leaves the previous version pinned and runnable. A write that failed after the sidecar landed leaves the new sidecar beside the old script, and the next pass repeats the install. `fsutil.WriteFileAtomic` renames the script into place before it syncs the directory, so a script write can fail after the new bytes landed, at that sync. The install then hashes the file, and when it holds the delivered checksum it logs `actions: rollout: script written but not synced` at Warn and goes on: the version is pinned, recorded, and logged as installed, because the old pin would refuse the new bytes at every dispatch as tampered. Any other failed script write fails the install. A record that cannot be saved logs `actions: rollout: record not saved` at Error and keeps the record in memory and the pin, so the hook runs; the end of every pass tries the save again until it lands.

**4. Errors.** The pass replaces the rollout errors with its own, sorted by name. Past 64 it keeps the first 64 and logs `actions: rollout: too many rollout errors; reporting the first by name` with `errors` and `reported`. Each detail has every NUL replaced with U+FFFD and is cut to 1024 code points, because a detail often carries an error text from the network or the file system and an error the control plane cannot store would cost the whole manifest. An entry that was installed, or is installed now, has no error, so a fixed rollout clears its error on the next pass. A pass cut short because the agent stops leaves the errors as they were.

A pass that changed the installed hooks or the errors calls the `SetOnChange` function. The one `plexd up` registers rescans the rollout directory, which hands the new files to the executor, and calls the reporter's `Notify`, so a change to the errors alone also reaches the manifest. The manifest carries the errors in [`hook_rollout_errors`](#data-model).

A pass makes at most one fetch for each listed entry that is not installed, one at a time. Each successful pull that carries a non-null block starts a pass, or joins the next one while a pass runs: every `reconcile.interval` (60 s by default) and each triggered pull. A failing entry is tried again on each pass, with no backoff of its own.

### Verification

A fetched version is installed only when all of these hold, checked in this order. The first that fails ends the entry with `verification_failed`, a detail that names the check, and `actions: rollout: verification failed` at Error, and nothing is written:

| Check | Detail on failure |
|-------|-------------------|
| The envelope's `type` is `hook_version` | `envelope type "<type>" is not hook_version` |
| The payload decodes into `api.HookVersionPayload` | `payload does not decode: <cause>` |
| The payload's `name` and `version` are the pair plexd fetched | `payload names "<name>" version <v>, not the fetched "<name>" version <v>` |
| `VerifySignature` accepts the envelope | `signature: <cause>`, such as `signature: api: verifier: unknown signing key id` |
| `script_base64` decodes as standard base64 | `script_base64 does not decode: <cause>` |
| The payload's `checksum` decodes to 32 bytes of standard base64 | `payload checksum: <cause>` |
| The SHA-256 of the script equals the payload's `checksum` | `script SHA-256 does not match the payload checksum` |
| The payload's `checksum` equals the pull entry's `checksum` | `payload checksum does not match the pull checksum` |

`VerifySignature` is the signature check of [event verification](../core/event-verification.md#verifysignature) without its freshness window. A version's `issued_at` is the instant it was signed, often days before the fetch, so the 5-minute window would refuse every version. It selects the key by the envelope's `key_id` as event verification does: the current key, or the previous key while its rotation grace window is open. The signing-key dispatch handler, which runs first in every reconcile cycle, installs the pull's `signing_key` into the same verifier, so a version fetched after a key rotation verifies under the key the pull handed out. What keeps an old version from being installed is the pull, which names the version and the checksum the script has to match.

A version that fails verification is reported as a rollout error only. plexd sends no `POST /v1/nodes/{node_id}/integrity-violations` for it, because that operation's `detected_by` has no value for a fetch, and nothing reached the disk. The payload's `project_id` is not checked: the Domain signature already binds the version to the Domain.

### Error Codes

The manifest's `hook_rollout_errors` holds one `api.HookRolloutError` per listed version plexd could not install: the `name` and `version` the pull listed, a `code`, and a `detail`.

| `code` | plexd reports it when | `detail` |
|--------|-----------------------|----------|
| `collision` | `hooks_dir` holds an entry of the name | `hooks_dir holds a hook of this name` |
| `verification_failed` | The pull entry's checksum is not a SHA-256 digest, or a fetched version fails a [check](#verification) | `pull entry checksum is not 32 bytes of standard base64`, or the failed check |
| `fetch_failed` | The fetch returned an error | The error's text, without the `correlation_id` of a problem answer |
| `install_failed` | The platform or the configuration refuses rolled-out hooks, `hooks_dir` cannot be checked, the payload declares what plexd cannot apply, or a write failed | `script hooks are not supported on Windows`, `rolled-out hooks are disabled on this node`, `actions are disabled on this node`, `check hooks_dir: <error>`, `sandbox level "<level>" is not implemented`, `timeout_seconds <n> is outside the range 0 to 86400`, or the write's error |

An entry step 1 dropped gets no error, and an entry that is installed has none.

### Running a Rolled-out Hook

The rollout watcher reports the files of the rollout directory to `Executor.SetRolloutHooks`, and the executor merges them with the hand-placed hooks into the one list `Capabilities()`, `Execute` and the manifest use:

- Every hand-placed hook is in it, with `Source` `local`.
- A rolled-out file is in it only while it has a pin and no hand-placed hook uses its name. Its entry carries `Source` `rollout` and the `Version` of its pin. A file with no pin, a leftover or one an account other than plexd wrote, is not listed and cannot be dispatched.
- The list is sorted by name and recomputed on every change to either snapshot or to a pin.

An install that wrote new bytes also gives the hook's entry in the rollout snapshot, when it has one, the delivered checksum along with the pin. The merged entry, and with it the manifest, therefore moves to the new version and its digest together, instead of pairing the new version with the old file's digest until the rollout watcher rescans, which the control plane would read as drift. The watcher's next scan confirms that digest or shows an edit, and the entry's sidecar fields catch up at that scan. `Load`'s pin of a recorded hook writes nothing and leaves the snapshot alone.

A dispatch of a rolled-out hook reads its sidecar and its script from the rollout directory and verifies the script against the delivered checksum. The [file checks](#hook-file-checks) apply as to a hand-placed hook, so the script and its sidecar must be owned by uid 0. A plexd that runs as another user installs files it owns itself, and each dispatch of them is refused with `hook refused: <name>.json is owned by uid <uid>, not root`: a rolled-out hook always has a sidecar, and the sidecar is checked first.

`SwapRolloutHook` and `RemoveRolloutHook` hold the executor's swap lock for writing from the first file they touch until the pin is updated. `runHook` holds it for reading from the pin read through the file checks, the verification, and the process start, and releases it before it waits for the process. A dispatch that races an upgrade therefore verifies the old bytes against the old pin or the new bytes against the new pin, never a mix that would file a false tamper alert, and a swap never waits for a run that may last hours. The lock covers the integrity violation report a failed verification sends, which the run's context bounds. The sidecar is read before the lock is taken, so a dispatch that races an upgrade can start the new version under the old version's timeout; the next dispatch reads the new one.

### Collision

A name that `hooks_dir` holds blocks a rollout of that name. Any directory entry counts, found by `os.Lstat`, a dangling link and a directory included: the executor and the manifest prefer the hand-placed hook, so a rolled-out copy would never run, and removing the operator's entry is not plexd's call. For such an entry plexd fetches nothing, removes its own rolled-out copy of the name if it has one, reports `collision`, and logs `actions: rollout: name collision with hooks_dir` on every pass. The manifest lists the hand-placed hook as `local`, with no `source` key and its own digest.

A hand-placed hook that appears after a rollout installed its name takes over at once in the merged list, and the next pass removes the rolled-out copy. Once the hand-placed hook is gone, the next pass fetches and installs the listed version.

### Switches and Platforms

| Condition | Effect |
|-----------|--------|
| `actions.rollouts_enabled: false`, or `PLEXD_ACTIONS_ROLLOUTS_ENABLED=false` | The node owner's veto on delivered scripts. `Load` removes every rolled-out hook and every other file of the rollout directory and saves an empty record, `plexd up` builds no rollout watcher, and no version is fetched. Each listed version is reported `install_failed` with `rolled-out hooks are disabled on this node`. Builtins and hand-placed hooks keep working |
| `actions.enabled: false` | No version is fetched, and each listed version that is not installed is reported `install_failed` with `actions are disabled on this node`. An installed hook stays at its version and a withdrawn one is still removed, but none runs, because every dispatch is rejected with `actions_disabled` |
| Windows | Script hooks do not run there. `Load` does nothing, and each listed version is reported `install_failed` with `script hooks are not supported on Windows`, with no fetch |

The rules apply in the order of the [decision table](#the-pass): Windows first, then the veto, then a collision, then an installed version, then `actions.enabled`. `plexd up` logs the effective `rollouts_enabled` on its `starting plexd` line, and `config.dump` reports it under `actions.rollouts_enabled`. plexd reads both switches at start, so a change takes effect on the next start.

### Rollout Log Lines

The installer's lines carry `component=actions`. The lines `plexd up` logs for it carry no component.

| Message | Level | Attributes | Meaning |
|---|---|---|---|
| `actions: rollout: hook installed` | Info | `name`, `version` | A version was installed and pinned |
| `actions: rollout: hook removed` | Info | `name`, `version` | A withdrawn hook, a collision's copy, or a hook `Load` removed under the veto |
| `actions: rollout: stray file removed` | Info | `file` | `Load` removed a file of the rollout directory the record does not vouch for |
| `actions: rollout: pull carried no hooks block; keeping rolled-out hooks` | Debug | | A pull carried a `null` block; no pass ran |
| `actions: rollout: entry dropped` | Warn | `name`, `version`, `reason` | An entry with an invalid name or version, or a repeated name. Logged once until the set of dropped entries changes |
| `actions: rollout: name collision with hooks_dir` | Warn | `name`, `version` | `hooks_dir` holds the name. Logged on every pass |
| `actions: rollout: fetch failed` | Warn | `name`, `version`, `error` | The fetch failed; the entry reads `fetch_failed` |
| `actions: rollout: install failed` | Warn | `name`, `version`, `error` | A verified version could not be written |
| `actions: rollout: script written but not synced` | Warn | `name`, `version`, `error` | The script's write failed after its new bytes landed, at the directory sync. The file holds the delivered checksum, so the version is pinned and installed all the same |
| `actions: rollout: hook not removed` | Warn | `name`, `version`, `error` | A removal failed. A pass keeps the pin and the record entry and tries again on the next pass. Under the veto `Load` logs it for a recorded hook it could not remove, and no pass tries again: the stray cleanup does, in the same `Load` and at every later start ([Load at Start](#load-at-start)) |
| `actions: rollout: stray file not removed` | Warn | `file`, `error` | `Load` could not remove a stray file |
| `actions: rollout: record unreadable; starting empty` | Warn | `error` | The record could not be read, decoded, or trusted |
| `actions: rollout: too many rollout errors; reporting the first by name` | Warn | `errors`, `reported` | More than 64 errors |
| `actions: rollout: verification failed` | Error | `name`, `version`, `error` | A fetched version failed a check and was not installed |
| `actions: rollout: record not saved` | Error | `error` | The record could not be written; the hooks stay pinned and the save is tried again |
| `rolled-out hooks disabled` | Error | `error` | `NewRolloutInstaller` refused the configuration |
| `actions: rollout: load failed` | Error | `error` | `Load` could not create or read the rollout directory |
| `rolled-out hook rescan failed` | Warn | `error` | The rescan of the rollout directory after a pass failed |
| `rolled-out hook watcher stopped` | Error | `error` | The rollout directory's watch ended |
| `hook integrity change detected` | Warn | `hook`, `source`, `old_checksum`, `new_checksum` | The rollout watcher computed a new digest for a file; `source` is `rollout` |

### Downgrade

An older plexd leaves `<data_dir>/hooks` on disk, unrun. It neither watches that directory nor reads `hook_rollouts.json`, ignores the pull's `hooks` block, and never fetches a version. After a downgrade, every rolled-out hook therefore stops running: it leaves the manifest, and a dispatch of its name is rejected with `unknown_action`. Nothing removes the files. A release that implements rollouts restores the hooks from the record at its next start, each pinned to the checksum it was delivered with, and its first pass converges on the block the pull then carries.

To leave nothing behind, start the newer release once with `actions.rollouts_enabled: false` before the downgrade: `Load` then removes every rolled-out hook and every other file of the rollout directory and saves an empty record.

A control plane that predates published hooks never sends the block, so the installer runs no pass and keeps whatever it installed. Such a control plane refuses the `source`, `version` and `hook_rollout_errors` keys, and plexd falls back to the short manifest, in which a rolled-out hook reads as `local`; see [When Hook Metadata Is Refused](#when-hook-metadata-is-refused).

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
| `succeeded` | Action completed with exit code 0. A PlexdHook's Job completed; its exit code is 0 when plexd could not read one |
| `failed`    | Non-zero exit, a timeout (`error="action timed out"`, or with the limit after a colon, as in `"action timed out: hook timeout 30s"`; see [Run Deadline](#run-deadline)), a refused hook (`error` starts with `hook refused: `), or a run error (message in `error`). A built-in that reports a stop and reaches its deadline carries `error="action timed out"`, or `"action timed out: max_action_timeout <d>"` when the ceiling set the deadline (see [Built-in Actions](#built-in-actions)). A PlexdHook run fails when its Job fails, times out, or is deleted before it finished, or when its Job cannot be created (see [Kubernetes CRD Hooks](#kubernetes-crd-hooks)) |
| `cancelled` | The action context was cancelled, at `Shutdown` or on a [cancel request](#cancel), and the run ended with an error: a killed hook, or a built-in that reports the stop. A PlexdHook run reports it on a cancel request only, once plexd read the log and asked to delete its Job; at `Shutdown` it leaves the Job running and reports nothing. `error` is empty |

## Rejection Reasons

Three reasons reach the control plane, each as the `error` of the `failed` terminal that closes the fail-fast sequence:

| Reason                    | Trigger                                                                     |
|---------------------------|------------------------------------------------------------------------------|
| `unknown_action`          | Action name not in the registry the entry's `type` names                      |
| `unsupported_action_type` | `type` outside `builtin`, `hook`, and `plexd_hook`, or `plexd_hook` with no PlexdHook runner set, as on every plexd outside a pod. The action itself may well be registered |
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
    ExecutionID       string                     `json:"execution_id"`
    Action            string                     `json:"action"`
    Type              string                     `json:"type"`
    Parameters        map[string]json.RawMessage `json:"parameters"`
    Status            string                     `json:"status"`
    RequestedAt       time.Time                  `json:"requested_at"`
    ExpiresAt         time.Time                  `json:"expires_at"`
    CancelRequestedAt *time.Time                 `json:"cancel_requested_at,omitempty"`
}
```

`ExpiresAt` is an absolute UTC deadline, not a relative timeout; a missing or `null` value decodes to the zero time, which the dispatcher refuses rather than treats as lapsed. `Parameters` is nullable: a JSON `null` decodes to a nil map, and each value is held as raw JSON so a large integer reaches the action with every digit intact. The entry carries no callback URL and no hook checksum.

`CancelRequestedAt` is present only on a `started` entry, once an operator cancelled the Execution: the control plane moves a `pending` or `ack` target to `cancelled` at once, and that entry leaves the block. Its presence is the signal to stop the run (see [Cancel](#cancel)), and plexd never compares its value with its own clock. A JSON `null` and an absent key both decode to nil. A value that is not an RFC 3339 string fails the decode of the whole state response, as a malformed `expires_at` does.

### ActionKind constants

```go
// The three legal values of a NodeStateExecution.Type.
const (
    // ActionKindBuiltin dispatches an action built into plexd.
    ActionKindBuiltin = "builtin"
    // ActionKindHook dispatches a hook registered by the node.
    ActionKindHook = "hook"
    // ActionKindPlexdHook dispatches a PlexdHook resource of the node's
    // cluster. The entry's Action is the resource's metadata.name.
    ActionKindPlexdHook = "plexd_hook"
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

### CapabilityManifestRequest

Sent to `PUT /v1/nodes/{node_id}/capabilities` at boot and after each change; see [Capability Announcement](#capability-announcement). Defined in `internal/api/types.go`.

```go
type CapabilityManifestRequest struct {
    BinaryVersion         string                `json:"binary_version"`
    BinaryChecksum        string                `json:"binary_checksum"`
    SSHHostKeyFingerprint string                `json:"ssh_host_key_fingerprint,omitempty"`
    DeclaredHooks         []DeclaredHook        `json:"declared_hooks,omitempty"`
    PlexdHooks            []DiscoveredPlexdHook `json:"plexd_hooks,omitempty"`
    BuiltinActions        []ActionInfo          `json:"builtin_actions,omitempty"`
    HookRolloutErrors     []HookRolloutError    `json:"hook_rollout_errors,omitempty"`
}
```

## Integration Points

### With internal/api

- `api.NodeStateExecution` is the pull entry the dispatcher consumes
- `api.ControlPlane.ExecutionCallback` and `UploadExecutionOutput` are the production implementations of `ActionReporter`
- `api.ControlPlane.UpdateCapabilities` is the production implementation of `agent.CapabilityClient`, through which the capability reporter sends the manifest
- `api.NodeStateHook` is the entry of the pull's `hooks` block the rollout installer consumes, and `api.HookRolloutError` the entry it reports back in the manifest
- `api.ControlPlane.FetchHookVersion` is the production implementation of `HookVersionFetcher`, and `api.Ed25519Verifier.VerifySignature` of `HookSignatureVerifier`; both serve the [rollout installer](#rolled-out-hooks)

### With internal/integrity

- `integrity.Verifier` implements `HookVerifier` for SHA-256 hook verification
- `integrity.HashFile` is used by `DiscoverHooks` for computing hook checksums
- `integrity.HexChecksum` decodes the wire checksum a pull entry and a hook version payload carry into the hex form `HashFile` returns, so the installer pins and compares a delivered digest the way a computed one is

### With internal/fsutil

- `fsutil.WriteFileAtomic` writes every file of the rollout directory and the record, so no reader sees a partial script, sidecar, or record

### With internal/reconcile

`Dispatcher.Handle` satisfies `reconcile.DispatchHandler` and is registered with `RegisterDispatchHandler`, so it runs after every successful state pull and before the diff. The `action_request` SSE event is registered on the shared `triggerReconcile` closure instead, alongside `node_state_updated` and the peer family.

`RolloutInstaller.Handle` is a dispatch handler too. `plexd up` registers it after the node API's `SecretIndexDispatchHandler` and before `Dispatcher.Handle`, and only when the installer was built. It hands the `hooks` block to the installer's own goroutine and returns, so the fetches never hold back the `executions` block. The reconcile snapshot neither stores nor diffs the `hooks` block.

## Lifecycle

```go
// 1. Create config. RolloutHooksDir has no YAML key: AgentConfig.ApplyDefaults
//    derives it from data_dir, and Config.ApplyDefaults leaves it alone
cfg := actions.Config{HooksDir: "/etc/plexd/hooks", RolloutHooksDir: filepath.Join(dataDir, "hooks")}
cfg.ApplyDefaults()

// 2. Create executor
exec := actions.NewExecutor(cfg, reporter, verifier, logger)

// 3. Register built-in actions. svcCtl is a *packaging.Service over the host's
//    service manager: packaging.NewService(packaging.NewServiceManager(logger),
//    packaging.InstallConfig{}). sysReader is the platform metrics.SystemReader
//    from newSystemReader(logger), nil on a platform without a reader
exec.RegisterBuiltin("diagnostics.collect", "Collect system diagnostics", collectParams, actions.DiagnosticsCollect(sysReader))
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

// 3a. In a pod, give the executor the PlexdHook runner, once and before the
//     reconciler starts. kubeEnv is the result of DefaultDetector.Detect().
//     newPlexdHookRunner returns nil outside a cluster, and logs a warning
//     and returns nil when the runner cannot be built
if runner := newPlexdHookRunner(kubeEnv, nodeID, cfg.MaxOutputBytes, logger); runner != nil {
    exec.SetPlexdHookRunner(runner)
}

// 4. Create the rollout installer. signingVerifier is the *api.Ed25519Verifier
//    that checks envelopes. An error leaves rolled-out hooks off and installer
//    nil, not the agent
installer, err := actions.NewRolloutInstaller(cfg, dataDir, nodeID, client, signingVerifier, exec, logger)
if err != nil {
    logger.Error("rolled-out hooks disabled", "error", err)
}

// 5. Register the installer's Handle and then the dispatcher on the
//    reconciler. Handle only hands the pull's hooks block to installer.Run;
//    the dispatcher consumes the executions block on every successful cycle
if installer != nil {
    reconciler.RegisterDispatchHandler(installer.Handle)
}
dispatcher := actions.NewDispatcher(exec, nodeID, logger)
reconciler.RegisterDispatchHandler(dispatcher.Handle)

// 6. Create the capability reporter; buildManifest reads exec.Capabilities()
//    and installer.Errors()
reporter := agent.NewCapabilityReporter(nodeID, client, buildManifest, logger)

// 7. Create the hook watchers (they replace one-time DiscoverHooks): one for
//    hooks_dir, and one for the rollout directory while rolled-out hooks are on
watcher := actions.NewHookWatcher(cfg.HooksDir, func(hooks []api.HookInfo) {
    exec.SetHooks(hooks)
    reporter.Notify()
}, onIntegrityAlert, logger)
var rolloutWatcher *actions.HookWatcher
if installer != nil && cfg.IsRolloutsEnabled() {
    rolloutWatcher = actions.NewRolloutHookWatcher(cfg.RolloutHooksDir, func(hooks []api.HookInfo) {
        exec.SetRolloutHooks(hooks)
        reporter.Notify()
    }, onRolloutIntegrityAlert, logger)
}

// 8. After a pass that changed the installed hooks or the rollout errors,
//    rescan the rollout directory and notify the reporter
if installer != nil {
    installer.SetOnChange(func() {
        if rolloutWatcher != nil {
            if _, err := rolloutWatcher.Reload(); err != nil {
                logger.Warn("rolled-out hook rescan failed", "error", err)
            }
        }
        reporter.Notify()
    })
}

// 9. Restore the rolled-out hooks from the record, each pinned to its
//    delivered checksum, then scan both directories once, so the executor's
//    hook list and the boot manifest hold the hooks on disk before anything
//    reads them. hookDirsReloader is plexd up's adapter over both watchers
if installer != nil {
    if err := installer.Load(); err != nil {
        logger.Error("actions: rollout: load failed", "error", err)
    }
}
hookDirs := &hookDirsReloader{local: watcher, rollout: rolloutWatcher, executor: exec}
if _, err := hookDirs.Reload(); err != nil {
    logger.Warn("boot hook scan failed", "error", err)
}

// 10. Wire to nodeapi; POST /v1/hooks/reload rescans both directories
nodeAPISrv.SetActionProvider(exec)
nodeAPISrv.SetHookReloader(hookDirs)

// 11. Start the watchers, the installer, and the reporter goroutines
go watcher.Watch(ctx)
if rolloutWatcher != nil {
    go rolloutWatcher.Watch(ctx)
}
if installer != nil {
    go installer.Run(ctx)
}
go reporter.Run(ctx)

// 12. On shutdown
exec.Shutdown(ctx)
```

`plexd up` waits for the boot scan for at most 10 seconds rather than calling `Reload` inline; see [Integration with Executor](#integration-with-executor).

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
| `type` outside `builtin`, `hook`, and `plexd_hook`, or `plexd_hook` with no PlexdHook runner | Fail-fast: the legal sequence to a `failed` terminal with `error=unsupported_action_type` |
| Deadline lapsed during the claim handshake | `failed` terminal with `error=execution deadline lapsed before the run started`; nothing runs |
| Run lost to an agent restart | One `failed` terminal with `error=execution lost to an agent restart`; never re-executed. A `plexd_hook` entry is [resumed](#resume-after-a-restart) instead, and reported lost only when its Job is gone |
| No PlexdHook of the entry's `action` in plexd's namespace | `ack` + `started`, then `failed` terminal with `error=unknown_action` |
| PlexdHook image without a `sha256` digest | `ack` + `started`, then `failed` terminal with `error=plexd hook image is not pinned by a sha256 digest: <image>`; no Job is created |
| PlexdHook Job fails, times out, or is deleted | `failed` terminal mapped from the Job (see [Kubernetes CRD Hooks](#kubernetes-crd-hooks)) |
| Agent shutdown during a PlexdHook run | No callback; the Job keeps running and the next agent process resumes it |
| Orphan report undelivered    | Retried on the next pull, at most 5 passes; then logged at error level and left to server-side expiry |
| Hook file missing            | `ack` + `started`, then `failed` terminal with `error` carrying the run error (e.g. `hook not found: <name>`) |
| Hook integrity failure       | `failed` terminal with the integrity error message |
| Hook sidecar unreadable or malformed | Refused: `failed` terminal with `error=hook refused: sidecar <name>.json: <cause>` |
| Hook sidecar declares an unusable `timeout` | Refused: `failed` terminal with `error=hook refused: sidecar <name>.json declares an unusable timeout "<value>": want a duration from 0 to 24h` |
| Hook sidecar declares a sandbox level other than `none` | Refused: `failed` terminal with `error=hook refused: sandbox level "<value>" is not implemented; plexd runs hooks at level none only` |
| Hook or sidecar resolves outside the hooks directory | Refused: `failed` terminal with `error=hook refused: <name> resolves outside the hooks directory` |
| Hook or sidecar is not a regular file | Refused: `failed` terminal with `error=hook refused: <name> is not a regular file` |
| Hook or sidecar not owned by root | Refused: `failed` terminal with `error=hook refused: <name> is owned by uid <uid>, not root`; no integrity violation is filed |
| Hook or sidecar group- or other-writable | Refused: `failed` terminal with `error=hook refused: <name> is group- or other-writable (mode <mode>)` |
| Hook or sidecar owner cannot be read | Refused: `failed` terminal with `error=hook refused: <name>: owner unavailable` |
| Hook or sidecar fails to resolve or stat, such as a link loop | Refused: `failed` terminal with `error=hook refused: <name>: <cause>` |
| Hook reaches the entry's `expires_at` | Process group killed, unless the script had already exited (see [Process Group](#process-group)); `failed` terminal with `error=action timed out` (there is no `timeout` wire status — the server sets timeout itself) |
| Hook reaches its declared `timeout` | Process group killed, unless the script had already exited (see [Process Group](#process-group)); `failed` terminal with `error=action timed out: hook timeout <d>` |
| Run reaches `max_action_timeout` | For a hook, process group killed, unless the script had already exited (see [Process Group](#process-group)); `failed` terminal with `error=action timed out: max_action_timeout <d>`, and `run deadline capped by max_action_timeout` logged at warn |
| Hook non-zero exit           | `failed` terminal with the actual `exit_code`   |
| Terminal callback fails      | Retried up to 3 times with exponential backoff, then logged at warn level; agent continues |
| Ack/started callback transport error | Logged at warn level; the dispatch is deferred — nothing runs and the next pull redelivers the entry |
| Rejection-walk callback transport error | Logged at warn level; the walk stops and the entry stays unsettled for the next pull |
| Callback refused (`nsk_node_mismatch`, `invalid_state_transition`, `execution_already_terminal`) | Execution aborted: no run, no terminal callback; a terminal refusal is not retried |
| Panic in action              | Recovered; `failed` terminal with `error=panic: <value>` |

A refused hook walks `ack` and `started` first, then the `failed` terminal carries exit code 1, plexd logs `hook refused` at warn, and the hook neither starts nor reaches the integrity check. See [Hook File Checks](#hook-file-checks) and [Sidecar at Run Time](#sidecar-at-run-time) for the placeholders.

## Logging

All log entries use `component=actions`.

| Level   | Event                         | Keys                                        |
|---------|-------------------------------|---------------------------------------------|
| `Info`  | execution expired; leaving the timeout to the control plane | `execution_id`, `action`, `expires_at` |
| `Info`  | Action completed              | `execution_id`, `status`, `duration`        |
| `Info`  | cancel requested; stopping the run | `execution_id`, `action`, `cancel_requested_at` |
| `Info`  | resuming plexd hook run after a restart | `execution_id`, `action`           |
| `Info`  | leaving the plexd hook job running; the next agent start resumes it | `execution_id` |
| `Warn`  | plexd hook job delete failed  | `execution_id`, `error`                     |
| `Warn`  | dispatch deferred             | `execution_id`, `action`, `reason`          |
| `Warn`  | Action rejected               | `execution_id`, `action`, `reason`          |
| `Warn`  | execution lost to an agent restart; reporting failed | `execution_id`       |
| `Warn`  | unexpected execution status in the pull block | `execution_id`, `action`, `status` |
| `Warn`  | execution entry carries a cancel request but never started; not starting it | `execution_id`, `action`, `status` |
| `Warn`  | execution carries no expires_at; refusing to dispatch | `execution_id`, `action`     |
| `Warn`  | dispatch budget exhausted; the remaining entries wait for the next pull | `execution_id`, `budget` |
| `Warn`  | claim callback failed; deferring the dispatch | `execution_id`, `status`, `error` |
| `Warn`  | execution deadline lapsed before the run started | `execution_id`, `expires_at` |
| `Warn`  | hook refused                  | `execution_id`, `hook`, `error`             |
| `Warn`  | run deadline capped by max_action_timeout | `execution_id`, `action`, `ceiling`, `requested` |
| `Warn`  | failed to send terminal callback | `execution_id`, `attempts`, `error`      |
| `Warn`  | failed to send callback for rejected execution | `execution_id`, `status`, `error` |
| `Warn`  | actions: watcher: a hook vanished while the watch was set up; retrying | `error` |
| `Warn`  | actions: discovery: sidecar read failed | `file`, `error`                 |
| `Warn`  | actions: watcher: sidecar read failed | `file`, `error`                   |
| `Error` | execution entry carries no execution_id; dropping | `action`                |
| `Error` | orphan report undelivered across repeated pulls; leaving the execution to server-side expiry | `execution_id`, `passes` |
| `Error` | claim callback refused; aborting execution | `execution_id`, `status`, `error` |
| `Error` | callback refused for rejected execution | `execution_id`, `status`, `error` |
| `Error` | panic in action execution     | `execution_id`, `panic`, `stack`            |

The PlexdHook runner's own lines carry `component=plexdhook-jobs` and are listed under [PlexdHook CRD](plexdhook-crd.md#run-log-lines).

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
| `action` | string | Action name (e.g. `diagnostics.collect`, `backup`), or a PlexdHook's `metadata.name` |
| `type` | string | `builtin`, `hook`, or `plexd_hook`; selects the registry the name is resolved against, or for `plexd_hook` the [PlexdHook resource](#kubernetes-crd-hooks) in plexd's namespace |
| `parameters` | object | Parameters passed to the action; nullable |
| `status` | string | `pending`, `ack`, or `started` — the status the control plane currently holds |
| `requested_at` | timestamp | When the control plane dispatched the execution |
| `expires_at` | timestamp | Absolute UTC deadline, **not** a relative timeout |
| `cancel_requested_at` | timestamp | Optional. Present only on a `started` entry once an operator cancelled the Execution; plexd stops a run it holds (see [Cancel](#cancel)) and never compares the value with its own clock |

There is no `callback_url` (the callback path is derived from the node and
execution ids) and no `checksum` (a hand-placed hook's integrity anchors on the
digest the node pinned at first discovery, and a rolled-out hook's on the
checksum the pull's `hooks` block delivered for the installed version).

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
agent restart. plexd posts one terminal callback and never re-executes it. A
`plexd_hook` entry is [resumed](#resume-after-a-restart) instead, and gets this
callback only when its Job is gone:

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

plexd announces what it can run in the capability manifest it sends to
`PUT /v1/nodes/{node_id}/capabilities`. Registration itself carries no
capabilities. `agent.CapabilityReporter` (`internal/agent/capabilities.go`) owns
the manifest: it sends it at boot and keeps it current while the agent runs.

```json
{
  "binary_version": "v1.4.2",
  "binary_checksum": "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=",
  "ssh_host_key_fingerprint": "SHA256:6QGz1Q4iE2zG5p2N3oRZb8ZsT4nKqJgY3oZmP8eFvWk=",
  "declared_hooks": [
    {
      "name": "backup",
      "checksum": "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=",
      "description": "Back up the data directory",
      "parameters": [
        { "name": "target", "type": "string", "required": true, "description": "Target address" }
      ],
      "timeout_seconds": 300,
      "sandbox_level": "none"
    },
    {
      "name": "backup-db",
      "checksum": "REA9yHQRkMbFu76wJTDLSMvpMnUd9WeDatQzSknU1Qg=",
      "description": "Dump the application database to /var/backups.",
      "timeout_seconds": 600,
      "sandbox_level": "none",
      "source": "rollout",
      "version": 2
    }
  ],
  "plexd_hooks": [
    {
      "name": "db-backup",
      "image_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "parameters": { "bucket": "backups" },
      "sandbox": true
    }
  ],
  "builtin_actions": [
    {
      "name": "diagnostics.collect",
      "description": "Collect system diagnostics (CPU, memory, disk, network)",
      "parameters": [
        { "name": "include_network", "type": "bool", "required": false, "default": "true", "description": "Include network interface info" },
        { "name": "include_processes", "type": "bool", "required": false, "default": "true", "description": "Include process listing" }
      ]
    }
  ],
  "hook_rollout_errors": [
    { "name": "rotate-logs", "version": 1, "code": "fetch_failed", "detail": "api: HTTP 503 (signing_unavailable): ..." }
  ]
}
```

### Data Model

| Field | Source | Content |
|---|---|---|
| `builtin_actions` | `Executor.Capabilities()` | Every registered builtin, sorted by name: `name`, `description`, and `parameters[]` in registration order (`name`, `type`, `required`, `default`, `description`). A builtin without parameters carries no `parameters` key |
| `declared_hooks` | The executor's merged hook list: hook scripts in `hooks_dir`, the pinned [rolled-out hooks](#rolled-out-hooks), and their sidecars | `name` and the payload's SHA-256 as 32 bytes of standard-padded base64, plus what the sidecar declares: `description`, `parameters`, `timeout_seconds`, and `sandbox_level`, each left off when not declared. The digest is the one the watcher last computed, which can differ from the executor's pin after an edit. A rolled-out hook's entry also carries `"source": "rollout"` and the `version` installed; a hand-placed hook's entry carries neither key |
| `plexd_hooks` | `PlexdHook` resources in the ServiceAccount's namespace (Kubernetes only) | `name`, `image_digest`, `parameters` map, `sandbox`; see [PlexdHook CRD](plexdhook-crd.md#capability-manifest-reporting) |
| `hook_rollout_errors` | `RolloutInstaller.Errors()` | The versions the last pull listed that plexd could not install, at most 64, sorted by name: `name`, `version`, `code`, and `detail`; see [Error Codes](#error-codes). Left off when there are none, and when the installer was not built |

The control plane refuses a manifest whole when one entry breaks an invariant,
so plexd drops an entry it cannot report (a script hook without a usable digest,
a PlexdHook whose image is not pinned by a digest) with a warning instead of
sending it. Past 128 hooks of either kind it keeps the first 128 by name and logs
how many it dropped. The status codes are listed under
[API Endpoints](../core/api-endpoints.md#put-v1-nodes-node-id-capabilities).

Hook metadata follows the same rule one field at a time: a sidecar field past its
[limit](#sidecar-metadata-format) is left off with a warning, and the hook stays.
A manifest the control plane refuses anyway for its metadata goes out again in a
short form; see [When Hook Metadata Is Refused](#when-hook-metadata-is-refused).

The four metadata fields describe a hook. They gate nothing at the control plane
and sit outside its digest, so a sidecar edit changes the manifest and moves no
digest and no pin. plexd applies the sidecar's `timeout` and `sandbox` when it
runs the hook; see [Sidecar at Run Time](#sidecar-at-run-time). A
hook with no sidecar reports `name` and `checksum` alone. A sidecar's content
reaches the control plane and everyone who holds `read` there, so it must hold no
secret.

A rolled-out entry tells the control plane to take the published checksum of
that version as the hook's baseline instead of the first digest the node reported,
so a rolled-out hook is never trusted on first use and a new version moves the
baseline with no acceptance. A hand-placed entry is sent with no `source` key,
which the contract reads as `local`, so a Node with no rolled-out hook sends
exactly the manifest it sent before rollouts existed.

An absent key means none, because the control plane replaces its stored row on
every PUT. `declared_hooks` leaves the manifest when the last hook is removed, and
that is what clears the list at the control plane. `hook_rollout_errors` leaves it
when the last error clears, which clears the errors there.

### When the Manifest Is Sent

**At boot.** `plexd up` runs the PlexdHook boot list, builds the reporter, creates
the hook watcher, and runs the watcher's first scan with `Reload` before the
reporter starts, so the boot manifest carries the hooks on disk. Boot waits for
that scan for at most 10 seconds, because the scan hashes every hook and a hung
mount must not stop the agent. The hook list stays empty until a scan succeeds, so
a scan that fails or outlives the wait leaves the boot manifest without hooks, and
a dispatch in that window is rejected with `unknown_action`. A scan still running
also holds up the watch's initial scan and `plexd hooks reload`. A scan that
finishes late reports through `onChange`. A failed PlexdHook boot list leaves
`plexd_hooks` off that first manifest. With rolled-out hooks on, the rollout
installer's `Load` pins the recorded hooks first and the scan covers the rollout
directory too, so the boot manifest carries each rolled-out hook at its version.
The rollout errors live in memory and start empty, so they reach the control
plane once the first pass, which runs on the first pull, has finished.

**When something changes.** The hook watchers' `onChange`, the rollout
installer after a pass that changed its hooks or its errors, and the PlexdHook
[inventory](plexdhook-crd.md#keeping-the-list-current) call `Notify`, which never
blocks. So a script hook that is added, changed, or removed reaches the control
plane within seconds, and so does a sidecar's edit or removal and a change to the
PlexdHook resources in the agent's namespace. `plexd hooks reload` feeds the
reporter the same way.

A notification waits for a quiet period of 1 second, restarted by each further
notification and bounded at 10 seconds after the first one. A burst therefore
costs one PUT at a control plane that accepts the manifest, and a hook rewritten
in a loop is still reported. A control plane that refuses the hook metadata sees
the PUTs in the [cost table](#when-hook-metadata-is-refused). The quiet period
also gives a write in progress time to finish, but it does not replace an
[atomic install](../../how-to/custom-hook-scripts.md#step-3-deploy-to-the-hooks-directory).

**What it skips.** Each attempt builds the manifest and compares it with the one
last accepted. A send that matches is skipped, so a `touch` on a hook or its
sidecar sends nothing. The last accepted manifest lives in memory, so a restart
always sends once.

**No periodic re-send.** A manifest the control plane is known to hold is never
re-sent. plexd sends only when the manifest changed or a send is still owed,
because every accepted PUT that carries a drifted hook raises another integrity
alert at the control plane, whether or not the manifest changed. The one send
that no change and no failure asks for is the
[hourly attempt](#when-hook-metadata-is-refused), which runs only while plexd
holds back metadata the control plane has not seen. A refused attempt stores
nothing and raises no alert, and an accepted one delivers new content once. A
sidecar edit on a hook with a drifted digest raises one more alert, as any
accepted PUT does.

### Retries

A failed PUT is retried until one is accepted, the boot manifest included, unless
it was [refused for its hook metadata](#when-hook-metadata-is-refused). The
delay starts at 5 seconds and doubles with each failure up to 5 minutes (5, 10,
20, 40, 80, 160, then 300 seconds), and each delay moves by up to 25% either way,
so agents that failed together do not retry in step. A `429` whose `Retry-After`
gives a number of seconds longer than that delay waits that long, even past 5
minutes, because the control plane asked for that wait. plexd reads the header on
no other status.

Any other refusal is retried too. A refused PUT changes nothing at the control
plane, the delay holds it to about 12 attempts an hour, and an upgraded control
plane then clears the refusal with no agent restart.

| While a retry is pending | What happens |
|---|---|
| A notification changed the content | It sends once its quiet period ends. Another failure keeps doubling the delay, and the notification does not reset it |
| A notification changed nothing | The retry timer is left alone, so a looping `touch` cannot defeat the backoff |
| A `Retry-After` wait is running | Nothing sends until it ends, whatever changed, and the timer then delivers the newest content |
| The content is back to the accepted manifest | The retry stops and the backoff resets, because the control plane already holds it |

Every attempt calls the build function, so a retry carries the newest content.
The one exception is content the control plane refused for its hook metadata: a
retry of that content carries the short form.

A network error, a timeout, or a 5xx does not prove the PUT was not stored, since
a PUT that committed can lose its response. After one, plexd forgets what was last
accepted, so the next attempt always sends, even when the content is back to that
manifest. A 4xx stopped before the write, so plexd keeps what was last accepted.

A credential the heartbeat has parked fails before any I/O. That failure does not
grow the delay: the reporter retries about every 5 seconds and delivers within
about one such delay of the [mark lifting](../core/heartbeat-service.md#quiet-failure-logs).

### When Hook Metadata Is Refused

The control plane refuses a manifest whole, so a refusal of the hook metadata
would otherwise cost the Node its binary version, its digests, and every hook.
plexd answers by sending the short form of the manifest, whose `declared_hooks`
entries hold `name` and `checksum` and nothing else, and which carries no
`hook_rollout_errors`. The metadata is every declared-hook key past `name` and
`checksum`, a rolled-out hook's `source` and `version` among them, and the
`hook_rollout_errors` list, and any one of them alone is enough to fall back.
In the short form a rolled-out hook has no `source` and reads as `local` at the
control plane. A control plane that serves rollouts gets the short form too:
after a `413` for a manifest over its 1 MiB budget, and after a `400` with a
limit-drift code from the table below, `hook_rollout_errors_too_many` and
`hook_rollout_error_invalid` among them, which only such a control plane sends.
Until it accepts a wide form, it reads each of the Node's rolled-out hooks as
`local`, so its rollout status for the hook reads `collision`, and it holds none
of the Node's rollout errors. `api.IsHookMetadataRefused` names the refusals that
trigger this:

| Status | Problem `code` | Why it falls back |
|---|---|---|
| `400` | `malformed_capabilities_request` | A control plane that predates the metadata refuses its keys as unknown |
| `413` | Any, or none | The manifest is over budget, 1 MiB or 32 KiB on a control plane that predates the metadata, whichever layer said so. A proxy's own `413` carries no code |
| `400` | `declared_hook_invalid` or `declared_hooks_too_many` | plexd's copy of the limits has drifted from the control plane's, which must cost the metadata and not the manifest |
| `400` | `hook_rollout_errors_too_many` or `hook_rollout_error_invalid` | plexd's copy of the limits on `hook_rollout_errors` has drifted from the control plane's |

Only a manifest that carries metadata falls back. One that carries none has
nothing to drop, so the same refusal takes the backoff under [Retries](#retries).
Every other failure takes that backoff too, including a `400` with another code,
such as `binary_checksum_invalid`, which the short form would draw again.

The refusal is not a failure. It takes no backoff and arms no retry, so the short
form leaves at once, and plexd logs
`agent: capability report: hook metadata refused; sending names and digests`.
When the control plane already holds that short form, no second PUT goes out. A
short PUT that fails takes the backoff, and its retry carries the short form.

The Node comes back on its own. plexd tries the wide form again when the built
content changes, and otherwise about an hour after the last refusal: 45 to 75
minutes, because the timer carries the jitter of the backoff. An accepted wide PUT
ends the fallback, so an upgraded control plane clears it with no agent restart.
The refusal lives in memory, so a restart starts again from the wide form.

While the built manifest still carries metadata, a control plane that refuses it
sees these PUTs:

| Event | PUTs |
|---|---|
| Boot, or any agent restart | 2: wide refused, short accepted |
| Notification with nothing changed | 0 |
| Sidecar edit alone | 1: wide refused, and the short form equals what the control plane holds |
| Hook added, changed, or removed | 2: wide refused, short accepted |
| Hourly attempt with nothing changed | 1: wide refused |

Each hourly attempt that is refused leaves one audit row at the control plane. That
cost lasts as long as the control plane stays old or the manifest stays over
budget, and it stops at the first accepted wide PUT. A change that leaves no
metadata in the built manifest has no wide form to refuse, so it goes out as an
ordinary send, or sends nothing when the control plane already holds it.

plexd does not check the budget itself, because the control plane owns that
number. A refused manifest can be far larger than an accepted one: plexd marshals
it whole, and the upload ends when the control plane stops reading at its cap.
That costs one such upload per change or per hour, and the warning names the
refusal.

The fallback keys on a refusal, so a wide manifest that fails with no HTTP answer
keeps retrying wide. A link too slow to finish the upload within the request
timeout (`api.request_timeout`, 30 seconds by default) hits this limit, and so does
a proxy that cuts the upload with no answer. On such a path the manifest stops
updating until the wide form gets through. plexd accepts that cost because a
control-plane outage must not strip metadata from every Node on recovery, and a
count of unanswered PUTs cannot tell an outage from a path that cannot carry the
wide form.

### Log Lines

The three `agent: capability report:` lines carry `component=capability-report`; the others are logged by `plexd up` without it.

| Message | Level | Attributes | Meaning |
|---|---|---|---|
| `agent: capability report: accepted` | Info | `declared_hooks`, `plexd_hooks` (counts), `hook_metadata` (bool) | A PUT was accepted. `hook_metadata` says whether that manifest carried any |
| `agent: capability report: hook metadata refused; sending names and digests` | Warn | `error`, `wide_retry_in` | The control plane [refused the hook metadata](#when-hook-metadata-is-refused). `wide_retry_in` says when the hourly attempt runs. The line repeats with each refusal, which keeps the state visible |
| `agent: capability report: send failed` | Warn | `error`, `retry_in` | A PUT failed and a retry is armed. Logged at Debug for `api.ErrCredentialRefused`, and not at all for a cancelled context at shutdown |
| `boot hook scan failed` | Warn | `error` | The boot scan failed; boot carries on |
| `boot hook scan timed out; hooks are reported when it finishes` | Warn | `timeout` | The boot scan outlived its 10 seconds |
| `hooks beyond the capability manifest cap omitted` | Warn | `cap`, `dropped` | More than 128 script hooks |
| `hook omitted from the capability manifest` | Warn | `hook`, `error` | A hook's digest could not be converted to the wire form, or its name is blank or not valid UTF-8, which the control plane cannot store. The hook stays on the node |
| `hook metadata omitted from the capability manifest` | Warn | `hook`, `field`, `error` | A sidecar field breaks its [limit](#sidecar-metadata-format). `field` is the sidecar key. The hook and its other fields stay on the manifest. The line repeats on every attempt, because every attempt builds the manifest |
| `hook integrity change detected` | Warn | `hook`, `old_checksum`, `new_checksum`, and `source` from the rollout watcher | The watcher computed a new digest for a known hook. The rollout watcher's line carries `source` `rollout`; the line of the `hooks_dir` watcher carries no `source` |

The PlexdHook watch's lines are listed under
[PlexdHook CRD](plexdhook-crd.md#log-lines).

## Kubernetes CRD Hooks

When plexd runs as a DaemonSet in Kubernetes, a hook can also be a `PlexdHook` custom resource in plexd's namespace instead of a script file. The control plane dispatches one as an entry with `type` `plexd_hook`, whose `action` is the resource's `metadata.name` and whose `parameters` are the dispatch's own. plexd runs it as one Job per execution and Node, pinned to its own Node, and reports the Job's outcome and the pod's log through the execution callback. Creating a resource runs nothing. The [PlexdHook CRD](plexdhook-crd.md#running-a-hook) reference gives every field of the Job and the reason for it, and the Role the run needs.

The executor runs the entry through a `PlexdHookRunner`, which `plexd up` builds in a pod and hands over with `SetPlexdHookRunner`. Without one, as on every plexd outside a pod, the entry is rejected with `unsupported_action_type`. `internal/actions` defines the seam, and `internal/kubernetes` implements it as `HookJobRunner` (see [Kubernetes Deployment](../deployment/kubernetes-deployment.md#hookjobrunner)):

```go
type PlexdHookRun struct {
    ExecutionID string
    Hook        string            // the PlexdHook's metadata.name: the entry's action
    Parameters  map[string]string // the dispatch's parameters, through flattenParams
    Deadline    time.Duration     // the run's bound
}

type PlexdHookResult struct {
    Succeeded bool
    ExitCode  *int   // the hook container's exit code; nil when it never terminated
    TimedOut  bool
    Reason    string // why a run without an exit code failed
    Output    string // the pod's log
}

type PlexdHookRunner interface {
    // Start creates the run's Job. A Job that already exists is not an error.
    Start(ctx context.Context, run PlexdHookRun) error
    // Wait returns once the Job is over, or deletes it when bound runs out.
    Wait(ctx context.Context, executionID string, bound time.Duration) (PlexdHookResult, error)
    // Stop reads the log so far and deletes the Job.
    Stop(ctx context.Context, executionID string) (output string, err error)
}

var ErrPlexdHookNotFound = errors.New("actions: plexd hook not found")
var ErrPlexdHookJobNotFound = errors.New("actions: plexd hook job not found")
```

### runPlexdHook (goroutine)

`runPlexdHook` takes the place of [`runAction`](#runaction-goroutine) for a `plexd_hook` entry, with the same release of the active slot and the same panic report:

1. Settle a lapsed deadline: a fresh run whose claim used up what was left of `expires_at` reports `failed` with `error=execution deadline lapsed before the run started` and creates no Job
2. Derive the run deadline with `runBound(time.Until(expires_at), 0, MaxActionTimeout)`, as for every action kind (see [Run Deadline](#run-deadline)). A resumed run counts a lapsed `expires_at` as nothing left
3. A fresh run calls `Start` with that deadline. `ErrPlexdHookNotFound` reports `failed` with `error=unknown_action`. Any other error reports `failed` with the error's text and no exit code. A [resumed](#resume-after-a-restart) run skips this step
4. `Wait` follows the Job until it is over, or, when the deadline passes, reads the Job once more and then reads its log and deletes it unless the hook container has already ended. When the ceiling set the deadline, plexd logs `run deadline capped by max_action_timeout` at warn, with `requested` set to what was left of `expires_at`
5. Build the terminal callback from the result by the [table below](#result-mapping), with the pod's log as output, send it on a context detached from the run's, as `runAction` does, and log `action completed`

When the run's context ends during `Start` or `Wait`, plexd checks whether `Cancel` recorded the id. A [cancel request](#cancel) calls `Stop` under a budget of 10 seconds and reports `cancelled` with the log `Stop` read and an empty `error`. A [shutdown](#shutdown) leaves the Job running and reports nothing. A result `Wait` returned without an error is reported as it is, even when the context ended meanwhile. A read or delete of `Wait`'s own that the ended context cut short returns the context's error, so it takes the same two paths.

No step runs on the reconcile goroutine, so a PlexdHook that does not exist ends as `ack`, `started`, `failed` with `error=unknown_action`, the same three callbacks the rejection walk sends for an unknown script hook.

### Generated Job YAML

The PlexdHook `db-backup` names the image `registry.example.com/tools/pg-backup@sha256:<64 lowercase hex>`, the command `/usr/local/bin/pg-backup.sh`, the parameter `compress=true`, and no `privileged`. A dispatch of it with `{"bucket": "s3://backups/prod"}` and a run deadline of 300 seconds, to the Node `node-abc123`, whose plexd pod runs on the Kubernetes node `worker-03`, creates:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: plexdhook-<first 32 hex of sha256(node id, 0x00, execution id)>
  namespace: plexd-system
  labels:
    app.kubernetes.io/managed-by: plexd
  annotations:
    plexd.plexsphere.com/execution-id: exec_a1b2c3d4
    plexd.plexsphere.com/node-id: node-abc123
    plexd.plexsphere.com/hook: db-backup
  ownerReferences:
    - apiVersion: plexd.plexsphere.com/v1alpha1
      kind: PlexdHook
      name: db-backup
      uid: <uid of the PlexdHook>
      controller: true
      blockOwnerDeletion: false
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 330
  ttlSecondsAfterFinished: 3600
  template:
    metadata:
      labels:
        app.kubernetes.io/managed-by: plexd
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      tolerations:
        - operator: Exists
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchFields:
                  - key: metadata.name
                    operator: In
                    values: [worker-03]
      containers:
        - name: hook
          image: registry.example.com/tools/pg-backup@sha256:<64 lowercase hex>
          command: ["/usr/local/bin/pg-backup.sh"]
          env:
            - name: PLEXD_EXECUTION_ID
              value: exec_a1b2c3d4
            - name: PLEXD_HOOK_NAME
              value: db-backup
            - name: PLEXD_NODE_ID
              value: node-abc123
            - name: PLEXD_PARAM_BUCKET
              value: s3://backups/prod
            - name: PLEXD_PARAM_COMPRESS
              value: "true"
          securityContext:
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```

plexd pins the Job to its own Node with a required node affinity on the node's name, passes the parameters as `PLEXD_PARAM_*` variables, a dispatch parameter overriding the resource's value of the same name, mounts no ServiceAccount token, and sets an `ownerReference` to the PlexdHook, so deleting the resource deletes its Jobs. `activeDeadlineSeconds` is the run deadline plus 30 seconds, a backstop for a deadline that passes while no agent runs; plexd enforces the deadline itself. The Job sets no resource limits and mounts no volumes, because the CRD has no field for either. plexd refuses an image without a `sha256` digest before it creates anything.

### Result Mapping

plexd reads the Job at once and then every 2 seconds, and maps what `Wait` returns to the terminal callback:

| `Wait` returns | The Job | Callback Status | `exit_code` | `error` |
|---|---|---|---|---|
| `Succeeded` | `Complete` | `succeeded` | The `hook` container's exit code, or 0 when none was read | empty |
| `TimedOut` | Deleted by plexd at the run deadline, or `Failed` with reason `DeadlineExceeded` | `failed` | omitted | `action timed out`, then `: max_action_timeout <d>` when the ceiling set the deadline, then `; <Reason>` when the result carries one, such as `; hook container never started: ImagePullBackOff` |
| neither, with `ExitCode` | `Failed` | `failed` | `ExitCode` | empty, as for a script hook that exits non-zero |
| neither, without `ExitCode` | `Failed` | `failed` | omitted | `Reason`: `plexd hook job failed: <reason>: <message>` |
| `ErrPlexdHookJobNotFound` on a resumed run | Gone | `failed` | omitted | `execution lost to an agent restart` |
| `ErrPlexdHookJobNotFound` on a fresh run | Gone | `failed` | omitted | `plexd hook job deleted before it finished` |
| any other error, with the run's context alive | | `failed` | omitted | The error's text |

There is no node-reported `timeout` status: a Job the deadline ends reports `failed`. Every `error` of this path is cut to 1024 bytes on a rune boundary; the contract allows 4096 code points, and a kubelet image pull message alone runs to several hundred bytes.

The output is the pod's log, read through the Kubernetes API with `limitBytes` set to `MaxOutputBytes` plus one, so a longer log is cut to `MaxOutputBytes` and ends in `...[truncated]`. It travels inline up to 16 KiB and through the [upload leg](#terminal-with-uploaded-output) above that, and an empty log sends no `output`. A Job that `activeDeadlineSeconds` ended has no log left to read, because the Job controller deletes its pods at once; a run plexd ended at the deadline carries the log it read before the delete.

## Security Considerations

- **Authenticated delivery** -- Action dispatches arrive in the `executions` block of the NSK-authenticated state pull, so a dispatch is only ever as trustworthy as the control-plane connection itself; no SSE payload can inject one. Local action requests via Unix socket require a valid session JWT.
- **Signed delivery** -- All SSE events (including `action_request`, `node_state_updated`, `rotate_keys`, etc.) are signed with the control plane's Ed25519 key. plexd verifies every signature before processing.
- **Signature verification** -- Every SSE event carries `issued_at` (max staleness: 5 minutes) and is verified with a kid-indexed Ed25519 signature selected by the envelope's `key_id`. Signature and staleness checks are applied uniformly to all event types; there is no nonce.
- **Hook file permissions** -- plexd verifies that hook files are owned by root and not group- or other-writable before execution.
- **Symlink protection** -- Hook paths are resolved and validated to prevent symlink escape outside the configured hooks directory.
- **Checksum enforcement** -- Hook checksums are verified before every execution, against the digest plexd recorded when it discovered a hand-placed hook (the dispatch carries no checksum), or against the checksum the pull delivered for a rolled-out hook, which plexd verified under the Domain signature before it installed the script. Binary checksums are reported continuously. On Kubernetes, a PlexdHook's image digest serves as its checksum: plexd reports only a hook whose image is pinned by a `sha256` digest (`@sha256:...`) and refuses to run any other. The pull entry carries no digest, so plexd runs the image the resource names when it creates the Job, and the next manifest reports a changed one as drift.
- **Resource isolation** -- Script hooks run directly on the host as plexd's user, with no CPU or memory limit from plexd. plexd implements sandbox level `none` only and refuses a hook that declares any other (see [Sandbox Options](sandbox-options.md)), and it kills a hook's whole process group at the run deadline. On Kubernetes, a PlexdHook runs in a pod of its own, in a Job pinned to plexd's Node, with no ServiceAccount token and, unless it sets `privileged: true`, a read-only root filesystem and every capability dropped. plexd sets no CPU or memory limit on it either, because the CRD has no field for one.
- **CRD privilege control** -- A PlexdHook's container runs privileged only when its spec sets `privileged: true`. plexd never sets `hostPID`, `hostNetwork`, or a host volume on the Job, and does not veto the field: under managed push, the control plane's `domain#manage` gate decides who may set it. plexd's Job grants are a Role in its own namespace, so it can create Jobs and read pod logs there and nowhere else.
- **Session token scoping** -- JWTs are bound to a specific node (`node_id` claim) and a specific set of actions (`actions` claim). Tokens cannot be used on other nodes or for unauthorized actions.
- **Session revocation** -- A verified `session_revoked` SSE event closes the live session its payload names at once, reports the `terminated_by` the payload's `revoke_reason` maps to on that session's `session_ended` row (`operator_revoke` for an operator-driven reason, `ttl_expired` or `idle_timeout` for the control plane's sweeper), and then triggers a reconcile. When a session ends, the control plane also drops its entry from the `sessions` block of the state pull; the next reconcile observes the absence and tears down a session that is still open, so the drain stays the teardown for a revocation whose event never arrives.
- **Local emergency access** -- `plexd actions run --local` requires root or plexd user, bypasses JWT authorization, but is logged as `local_emergency` and reported to the control plane.
