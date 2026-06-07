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

Upgrades plexd to a specified version. Downloads the new binary from the control plane's artifact store (`GET /v1/artifacts/plexd/{version}/{os}/{arch}`), verifies the SHA-256 checksum, atomically replaces the current binary, and triggers a systemd restart.

| Parameter  | Type   | Required | Description                                      |
|------------|--------|----------|--------------------------------------------------|
| `version`  | string | yes      | Target version (e.g. `1.5.0`)                    |
| `checksum` | string | yes      | Expected SHA-256 checksum (hex, optional `sha256:` prefix) |

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
  "message": "binary replaced, restarting service"
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
exec.RegisterBuiltin("diagnostics.collect", "Collect system diagnostics", collectParams, actions.DiagnosticsCollect())
exec.RegisterBuiltin("diagnostics.ping_peer", "Ping a mesh peer", peerIDParam, actions.PingPeer(nodeInfo))
exec.RegisterBuiltin("diagnostics.traceroute_peer", "Traceroute to peer", peerIDParam, actions.DiagnosticsTraceroutePeer(nodeInfo))
exec.RegisterBuiltin("service.restart", "Restart service", nil, actions.ServiceRestart())
exec.RegisterBuiltin("service.reload_config", "Reload config", nil, actions.ServiceReloadConfig())
exec.RegisterBuiltin("service.upgrade", "Upgrade plexd binary", upgradeParams, actions.ServiceUpgrade(apiClient))
exec.RegisterBuiltin("system.info", "Report system and runtime info", nil, actions.SystemInfo(nodeInfo))
exec.RegisterBuiltin("health.check", "Check health", healthParams, actions.HealthCheck(healthProvider))
exec.RegisterBuiltin("mesh.reconnect", "Reconnect mesh", nil, actions.MeshReconnect(reconnector))
exec.RegisterBuiltin("config.dump", "Dump config", nil, actions.ConfigDump(configProvider))
exec.RegisterBuiltin("logs.snapshot", "Snapshot logs", snapshotParams, actions.LogsSnapshot(logProvider))

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

## SSE Event: `action_request`

The control plane sends an `action_request` event over the existing SSE stream to trigger an action on a node. Like all SSE events, it is wrapped in a signed envelope and verified before processing.

### Payload

```json
{
  "execution_id": "exec_a1b2c3d4",
  "action": "diagnostics.collect",
  "type": "builtin",
  "parameters": {
    "include_network": true,
    "include_processes": true
  },
  "timeout": "30s",
  "callback_url": "https://api.plexsphere.com/v1/nodes/n_abc123/executions/exec_a1b2c3d4"
}
```

| Field | Type | Description |
|---|---|---|
| `execution_id` | string | Unique identifier for this execution |
| `action` | string | Action name (e.g. `diagnostics.collect`, `hooks/backup`) |
| `type` | string | `builtin` or `hook` |
| `parameters` | object | Key-value parameters passed to the action |
| `timeout` | duration | Maximum execution time (default: 30s) |
| `callback_url` | string | URL for ACK/NACK and result delivery |

The `issued_at`, `nonce`, and `signature` fields are part of the signed event envelope and apply to all SSE events uniformly.

## ACK/NACK and Result Formats

### ACK/NACK (immediate)

```
POST {callback_url}/ack

{
  "execution_id": "exec_a1b2c3d4",
  "status": "accepted",       // or "rejected"
  "reason": ""                 // Reason if rejected (e.g. "unknown action", "integrity violation")
}
```

### Result (asynchronous)

```
POST {callback_url}/result

{
  "execution_id": "exec_a1b2c3d4",
  "status": "success",         // success, failure, timeout, cancelled
  "exit_code": 0,
  "stdout": "...",             // Truncated to 64 KiB
  "stderr": "...",             // Truncated to 64 KiB
  "duration": "2.34s",
  "finished_at": "2025-01-15T10:30:02Z"
}
```

## Retry and Persistence

- If the callback POST fails, plexd retries with exponential backoff (1s, 2s, 4s, ... up to 5 minutes).
- Pending results are persisted to `data_dir` and re-delivered when the SSE connection is re-established.

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

When plexd runs as a DaemonSet in Kubernetes, hooks are defined as `PlexdHook` custom resources instead of script files. On `action_request`, plexd creates a Kubernetes Job on the target node.

### Generated Job YAML

When `action_request` arrives with `action: hooks/db-backup`, plexd creates:

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
| Succeeded | `success` | Exit code 0 |
| Failed | `failure` | Exit code from container termination state |
| `activeDeadlineSeconds` exceeded | `timeout` | Job killed by Kubernetes |

Stdout and stderr are captured from the pod logs via the Kubernetes API.

## Security Considerations

- **Signed delivery** -- All SSE events (including `action_request`, `peer_added`, `peer_removed`, `rotate_keys`, etc.) are signed with the control plane's Ed25519 key. plexd verifies every signature before processing. Local action requests via Unix socket require a valid session JWT.
- **Replay protection** -- Every SSE event includes `issued_at` (max staleness: 5 minutes) and `nonce` (tracked in bounded set). Signature verification, staleness, and nonce checks are applied uniformly to all event types.
- **Hook file permissions** -- plexd verifies that hook files are owned by root and not group- or other-writable before execution.
- **Symlink protection** -- Hook paths are resolved and validated to prevent symlink escape outside the configured hooks directory.
- **Checksum enforcement** -- Hook checksums are verified before every execution. Binary checksums are reported continuously. On Kubernetes, image digests serve as checksums -- hooks without pinned digest (`@sha256:...`) are rejected.
- **Resource isolation** -- Hooks run with cgroup limits at minimum; higher sandbox levels add namespace or container isolation. On Kubernetes, hooks always run as separate Pods with native resource limits.
- **CRD privilege control** -- Kubernetes hooks requiring host-level access (`hostPID`, `hostNetwork`, `privileged`) must declare `privileged: true` in the `PlexdHook` spec. The platform can enforce approval policies.
- **Session token scoping** -- JWTs are bound to a specific node (`node_id` claim) and a specific set of actions (`actions` claim). Tokens cannot be used on other nodes or for unauthorized actions.
- **Session revocation** -- When an SSH session ends, the control plane pushes `session_revoked` via SSE. plexd maintains a local revocation set to reject tokens from terminated sessions.
- **Local emergency access** -- `plexd actions run --local` requires root or plexd user, bypasses JWT authorization, but is logged as `local_emergency` and reported to the control plane.
