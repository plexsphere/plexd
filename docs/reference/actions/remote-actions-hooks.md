---
title: Remote Actions and Hooks
package: internal/actions
feature: PXD-0019
---

# Remote Actions and Hooks

The `internal/actions` package enables platform-triggered remote action execution on plexd mesh nodes. It supports built-in operations (diagnostics, connectivity checks) and custom hook scripts with SHA-256 integrity verification. Action results are reported back to the control plane.

## Data Flow

```
Control Plane (SSE)
       │
       ▼
┌──────────────────────┐
│ HandleActionRequest  │  api.EventHandler for EventActionRequest
│  (handler.go)        │
└──────────┬───────────┘
           │ parse ActionRequest
           ▼
┌──────────────────────┐
│ Executor.Execute     │
│  (executor.go)       │
└──────────┬───────────┘
           │
     ┌─────┴──────────────────────────────────────┐
     │ 1. Check shuttingDown                      │
     │ 2. Check duplicate execution_id            │
     │ 3. Check MaxConcurrent                     │
     │ 4. Look up action (builtins → hooks)       │
     │ 5. Send ExecutionAck (accepted / rejected) │
     └──────────┬─────────────────────────────────┘
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
     └────┬────┘ │ 2. File existence check      │
          │      │ 3. integrity.VerifyHook       │
          │      │ 4. exec.CommandContext         │
          │      │ 5. Capture stdout/stderr       │
          │      │ 6. Truncate to MaxOutputBytes  │
          │      └──────────┬──────────────────────┘
          │                 │
          └────────┬────────┘
                   │
                   ▼
          ┌────────────────┐
          │ ReportResult   │  POST /v1/nodes/{id}/executions/{eid}/result
          └────────────────┘
```

## Config

`Config` holds configuration for remote action execution.

| Field              | Type            | Default | Description                              |
|--------------------|-----------------|---------|------------------------------------------|
| `Enabled`          | `bool`          | `true`  | Whether action execution is active       |
| `HooksDir`         | `string`        | `/etc/plexd/hooks` | Directory containing hook scripts        |
| `MaxConcurrent`    | `int`           | `5`     | Max simultaneous action executions       |
| `MaxActionTimeout` | `time.Duration` | `10m`   | Max duration for a single action         |
| `MaxOutputBytes`   | `int64`         | `1 MiB` | Max output capture size per action       |

```go
cfg := actions.Config{
    HooksDir: "/etc/plexd/hooks",
}
cfg.ApplyDefaults() // Enabled=true, HooksDir=/etc/plexd/hooks, MaxConcurrent=5, MaxActionTimeout=10m, MaxOutputBytes=1MiB
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
| `Execute`         | `(ctx context.Context, nodeID string, req api.ActionRequest)`                   | Main entry point for action execution                |
| `Shutdown`        | `(ctx context.Context)`                                                         | Cancel all running executions, reject new ones       |
| `ActiveCount`     | `() int`                                                                         | Number of currently running actions                  |

### Execute Flow

1. **Check shutting down**: if `shuttingDown`, reject with `reason=shutting_down`
2. **Check duplicate**: if `executionID` already active, reject with `reason=duplicate_execution_id`
3. **Check concurrency**: if `len(active) >= MaxConcurrent`, reject with `reason=max_concurrent_reached`
4. **Look up action**: search builtins map first, then hooks list
5. **Unknown action**: reject with `reason=unknown_action`
6. **Accept**: send `ExecutionAck{Status: "accepted"}` via `ActionReporter.AckExecution`
7. **Execute**: launch goroutine calling `runAction` with timeout context

### runAction (goroutine)

1. Parse timeout from `ActionRequest.Timeout` (capped by `Config.MaxActionTimeout`)
2. Dispatch to `runBuiltin` or `runHook`
3. Determine status: `success`, `failed` (non-zero exit), `timeout`, `cancelled`, `error`
4. Build `api.ExecutionResult` with `ExecutionID`, `Status`, `ExitCode`, `Stdout`, `Stderr`, `Duration`, `FinishedAt`, `TriggeredBy`
5. Report via `ActionReporter.ReportResult`
6. Remove from active map

### runHook

1. **Path traversal prevention**: reject names containing `/`, `\`, or `..`
2. **File existence**: `os.Stat` the resolved path
3. **Integrity verification**: call `HookVerifier.VerifyHook(ctx, nodeID, hookPath, checksum)`
4. **Execute**: `exec.CommandContext` with `WaitDelay=500ms`
5. **Environment**: minimal env (`PATH`, `HOME`, `PLEXD_NODE_ID`, `PLEXD_EXECUTION_ID`) plus `PLEXD_PARAM_*` vars
6. **Output capture**: stdout and stderr captured in buffers, truncated to `MaxOutputBytes`

### Shutdown

1. Sets `shuttingDown = true` under mutex
2. Collects all active cancel functions
3. Calls each cancel function to cancel running contexts
4. Subsequent `Execute` calls are rejected with `reason=shutting_down`

## HandleActionRequest

SSE event handler for `action_request` events. Follows the same closure pattern as `tunnel.HandleSSHSessionSetup`.

```go
func HandleActionRequest(executor *Executor, nodeID string, logger *slog.Logger) api.EventHandler
```

Returns an `api.EventHandler` that:

1. Parses `SignedEnvelope.Payload` into `api.ActionRequest`
2. Returns error on malformed JSON (no ack sent; logged by dispatcher)
3. Returns error on missing `execution_id`
4. When `Config.Enabled` is `false`: sends rejected ack with `reason=actions_disabled`
5. Otherwise: delegates to `Executor.Execute`

## ActionReporter

Interface abstracting control plane communication for testability.

```go
type ActionReporter interface {
    AckExecution(ctx context.Context, nodeID, executionID string, ack api.ExecutionAck) error
    ReportResult(ctx context.Context, nodeID, executionID string, result api.ExecutionResult) error
}
```

A production implementation wraps `api.ControlPlane.AckExecution` and `api.ControlPlane.ReportResult`.

## HookVerifier

Interface abstracting hook integrity verification for testability.

```go
type HookVerifier interface {
    VerifyHook(ctx context.Context, nodeID, hookPath, expectedChecksum string) (bool, error)
}
```

The production implementation is `integrity.Verifier`, which computes SHA-256 of the hook file and compares against the expected checksum from the control plane.

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

### gather_info

Collects system information and returns it as JSON in stdout.

```json
{
  "hostname": "edge-us-west-42",
  "os": "linux",
  "arch": "amd64",
  "go_version": "go1.24.0",
  "mesh_ip": "10.100.0.5",
  "peer_count": 12,
  "node_id": "node-abc123"
}
```

### ping

Tests connectivity to a target IP address. Requires a `target` parameter containing a valid IP address. Uses the system `ping` command with `-c 1 -W 3`.

| Parameter | Type   | Required | Description       |
|-----------|--------|----------|-------------------|
| `target`  | string | yes      | Target IP address |

Returns exit code 0 on success, 1 on failure.

### diagnostics.collect

Collects system diagnostics (hostname, OS, architecture, CPU count, memory, disk, load average, kernel version) and returns them as JSON. Gracefully handles missing `/proc` data by using fallback values.

```json
{
  "hostname": "edge-us-west-42",
  "os": "linux",
  "arch": "amd64",
  "cpu_count": 4,
  "memory_total": 8589934592,
  "disk_total": 107374182400,
  "load_avg": "1.50 1.20 0.90 2/150 12345",
  "kernel_version": "6.1.0-amd64"
}
```

No parameters required.

### diagnostics.traceroute_peer

Runs `traceroute` to a target IP address. Requires a `target` parameter containing a valid IP address. Uses `-n -m 15 -w 3` flags.

| Parameter | Type   | Required | Description       |
|-----------|--------|----------|-------------------|
| `target`  | string | yes      | Target IP address |

Returns traceroute output in stdout. Exit code 1 if `traceroute` is not installed.

### service.restart

Restarts the plexd service via `systemctl restart plexd.service`. No parameters required. Exit code 1 if `systemctl` is not available.

### service.reload_config

Sends `SIGHUP` to the current process to trigger a configuration reload.

```json
{
  "status": "reload_signal_sent",
  "pid": 12345
}
```

No parameters required.

### service.upgrade

Placeholder for in-place upgrade functionality. Currently returns a message indicating that in-place upgrade is not supported.

```json
{
  "status": "upgrade_not_available",
  "message": "in-place upgrade not supported; use package manager or control plane"
}
```

No parameters required.

### health.check

Reports the node's health status. Requires a `HealthProvider` dependency.

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

Status is `"healthy"` if `tunnel_count > 0`, otherwise `"degraded"`. No parameters required.

### mesh.reconnect

Triggers mesh reconnection via the `MeshReconnector` interface. On success, returns `{"status": "reconnected"}`. On failure, returns exit code 1 with `{"status": "failed", "error": "..."}`.

No parameters required.

### config.dump

Outputs the sanitized configuration via the `ConfigProvider` interface. Returns the config string in stdout. No parameters required.

### logs.snapshot

Retrieves recent log lines via the `LogProvider` interface.

| Parameter | Type   | Required | Description                    |
|-----------|--------|----------|--------------------------------|
| `lines`   | string | no       | Number of lines (default: 100, max: 10000) |

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

When hooks change, `executor.SetHooks` is called, updating `Capabilities()` output. The `Hooks()` method satisfies the `nodeapi.HookReloader` interface.

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

Parameters from `ActionRequest.Parameters` are passed to hook scripts as environment variables with the `PLEXD_PARAM_` prefix.

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
| `PLEXD_EXECUTION_ID`   | Execution ID from the request  |

## Execution Status Values

| Status      | Meaning                                              |
|-------------|------------------------------------------------------|
| `success`   | Action completed with exit code 0                    |
| `failed`    | Action completed with non-zero exit code             |
| `timeout`   | Action exceeded its timeout and was killed           |
| `cancelled` | Action was cancelled (e.g., during shutdown)         |
| `error`     | Internal error (integrity failure, file not found, etc.) |

## Ack Rejection Reasons

| Reason                     | Trigger                                           |
|----------------------------|---------------------------------------------------|
| `unknown_action`           | Action name not in builtins or hooks list          |
| `max_concurrent_reached`   | Active executions >= `Config.MaxConcurrent`        |
| `duplicate_execution_id`   | Execution ID already in progress                   |
| `shutting_down`            | Agent is shutting down                             |
| `actions_disabled`         | `Config.Enabled` is `false`                        |

## API Types

Types defined in `internal/api/types.go`.

### ActionRequest

SSE payload for `action_request` events.

```go
type ActionRequest struct {
    ExecutionID string            `json:"execution_id"`
    Action      string            `json:"action"`
    Parameters  map[string]string `json:"parameters,omitempty"`
    Timeout     string            `json:"timeout"`
    Checksum    string            `json:"checksum,omitempty"`
    TriggeredBy *TriggeredBy      `json:"triggered_by,omitempty"`
}
```

### ExecutionAck

Sent to `POST /v1/nodes/{node_id}/executions/{execution_id}/ack`.

```go
type ExecutionAck struct {
    ExecutionID string `json:"execution_id"`
    Status      string `json:"status"`   // "accepted" or "rejected"
    Reason      string `json:"reason"`   // populated when rejected
}
```

### ExecutionResult

Sent to `POST /v1/nodes/{node_id}/executions/{execution_id}/result`.

```go
type ExecutionResult struct {
    ExecutionID string       `json:"execution_id"`
    Status      string       `json:"status"`
    ExitCode    int          `json:"exit_code"`
    Stdout      string       `json:"stdout"`
    Stderr      string       `json:"stderr"`
    Duration    string       `json:"duration"`
    FinishedAt  time.Time    `json:"finished_at"`
    TriggeredBy *TriggeredBy `json:"triggered_by,omitempty"`
}
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

- `EventActionRequest` constant defines the SSE event type
- `api.ControlPlane.AckExecution` and `ReportResult` are the production implementations of `ActionReporter`
- `api.ControlPlane.UpdateCapabilities` sends discovered capabilities

### With internal/integrity

- `integrity.Verifier` implements `HookVerifier` for SHA-256 hook verification
- `integrity.HashFile` is used by `DiscoverHooks` for computing hook checksums

### With internal/api (EventDispatcher)

`HandleActionRequest` returns an `api.EventHandler` registered with the `EventDispatcher` for `EventActionRequest` events, following the same pattern as `tunnel.HandleSSHSessionSetup`.

## Lifecycle

```go
// 1. Create config
cfg := actions.Config{HooksDir: "/etc/plexd/hooks"}
cfg.ApplyDefaults()

// 2. Create executor
exec := actions.NewExecutor(cfg, reporter, verifier, logger)

// 3. Register built-in actions
exec.RegisterBuiltin("gather_info", "Collect system and mesh info", nil, actions.GatherInfo(nodeInfo))
exec.RegisterBuiltin("ping", "Test connectivity", targetParam, actions.Ping(nodeInfo))
exec.RegisterBuiltin("diagnostics.collect", "Collect diagnostics", nil, actions.DiagnosticsCollect())
exec.RegisterBuiltin("diagnostics.traceroute_peer", "Traceroute to peer", targetParam, actions.DiagnosticsTraceroutePeer(nodeInfo))
exec.RegisterBuiltin("service.restart", "Restart service", nil, actions.ServiceRestart())
exec.RegisterBuiltin("service.reload_config", "Reload config", nil, actions.ServiceReloadConfig())
exec.RegisterBuiltin("service.upgrade", "Upgrade (placeholder)", nil, actions.ServiceUpgrade())
exec.RegisterBuiltin("health.check", "Check health", nil, actions.HealthCheck(healthProvider))
exec.RegisterBuiltin("mesh.reconnect", "Reconnect mesh", nil, actions.MeshReconnect(reconnector))
exec.RegisterBuiltin("config.dump", "Dump config", nil, actions.ConfigDump(configProvider))
exec.RegisterBuiltin("logs.snapshot", "Snapshot logs", linesParam, actions.LogsSnapshot(logProvider))

// 4. Register SSE handler
sseMgr.RegisterHandler(api.EventActionRequest,
    actions.HandleActionRequest(exec, nodeID, logger))

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
| Malformed SSE payload        | Handler returns error (logged by dispatcher)    |
| Missing execution_id         | Handler returns error                           |
| Actions disabled             | Rejected ack with `reason=actions_disabled`     |
| Unknown action               | Rejected ack with `reason=unknown_action`       |
| Hook file missing            | Accepted ack, then error result                 |
| Hook integrity failure       | Accepted ack, then error result                 |
| Hook timeout                 | Process killed, result `status=timeout`         |
| Hook non-zero exit           | Result `status=failed` with actual exit code    |
| Result report fails          | Logged at warn level, agent continues           |
| Ack report fails             | Logged at warn level                            |
| Panic in action              | Recovered, error result reported                |

## Logging

All log entries use `component=actions`.

| Level   | Event                         | Keys                                        |
|---------|-------------------------------|---------------------------------------------|
| `Info`  | action_request received       | `execution_id`, `action`                    |
| `Info`  | Action completed              | `execution_id`, `status`, `duration`        |
| `Warn`  | Action rejected               | `execution_id`, `action`, `reason`          |
| `Warn`  | Failed to send ack            | `execution_id`, `error`                     |
| `Warn`  | Failed to report result       | `execution_id`, `error`                     |
| `Error` | Payload parse failed          | `event_id`, `error`                         |
| `Error` | Missing execution_id          | `event_id`                                  |
| `Warn`  | Actions disabled              | `execution_id`, `action`                    |
