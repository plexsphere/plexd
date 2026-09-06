---
title: Creating Custom Hook Scripts
package: internal/actions
feature: PXD-0019
---

# Creating Custom Hook Scripts

Hook scripts extend plexd's remote action capabilities without modifying the
binary. This guide walks through creating, deploying, and triggering a custom
hook on a plexd-managed node.

For the full reference of types and internals, see
[Remote Actions and Hooks Reference](../reference/actions/remote-actions-hooks.md).

## Prerequisites

1. **plexd is running** on a Linux or macOS node with actions enabled
   (default). Windows reports no executable bit on a regular file, so hooks
   are never discovered there; see
   [Platform Support](../guide/platform-support.md).

2. **Hooks directory** is configured. The default is `/etc/plexd/hooks` on
   Linux and `/Library/Application Support/plexd/hooks` on macOS. Set
   `hooks_dir` in the actions configuration to override.

3. **Shell access** to the node for deploying the script (or a deployment
   pipeline that places files in the hooks directory).

## Step 1: Create the Hook Script

Create a shell script that performs the desired operation. The script receives
parameters as `PLEXD_PARAM_` prefixed environment variables.

```bash
cat > /tmp/restart-service.sh << 'EOF'
#!/bin/sh
set -e

SERVICE="${PLEXD_PARAM_SERVICE}"
if [ -z "$SERVICE" ]; then
    echo "error: SERVICE parameter is required" >&2
    exit 1
fi

echo "Restarting service: $SERVICE"
systemctl restart "$SERVICE"
echo "Service $SERVICE restarted successfully"
EOF
```

### Available Environment Variables

Every hook script has access to the following environment variables:

| Variable               | Description                            |
|------------------------|----------------------------------------|
| `PATH`                 | Inherited from the plexd process       |
| `HOME`                 | Inherited from the plexd process       |
| `PLEXD_NODE_ID`        | ID of the node executing the hook      |
| `PLEXD_EXECUTION_ID`   | Unique execution ID for this invocation|
| `PLEXD_PARAM_<NAME>`   | Each parameter from the action request |

Parameter names are uppercased and non-alphanumeric characters (except
underscore) are replaced with underscores. For example, a parameter named
`service-name` becomes `PLEXD_PARAM_SERVICE_NAME`.

### Script Requirements

- Must have a shebang line (`#!/bin/sh`, `#!/bin/bash`, `#!/usr/bin/env python3`, etc.)
- Must be executable (`chmod +x`)
- Exit code 0 indicates success; non-zero indicates failure
- Stdout and stderr are captured and sent to the control plane
- Output is truncated at `MaxOutputBytes` (default 1 MiB)
- The script is killed if it exceeds the action timeout

## Step 2: Create an Optional Metadata Sidecar

A JSON sidecar file provides metadata about the hook to the control plane.
The sidecar file must have the same name as the hook script with a `.json`
extension.

```bash
cat > /tmp/restart-service.sh.json << 'EOF'
{
  "description": "Restart a systemd service on the node",
  "parameters": [
    {
      "name": "service",
      "type": "string",
      "required": true,
      "description": "Name of the systemd service to restart"
    }
  ],
  "timeout": "30s",
  "sandbox": "none"
}
EOF
```

### Sidecar Fields

| Field         | Type            | Description                                    |
|---------------|-----------------|------------------------------------------------|
| `description` | `string`        | Human-readable description of the hook         |
| `parameters`  | `[]ActionParam` | List of expected parameters with types         |
| `timeout`     | `string`        | Suggested default timeout (e.g. `"30s"`)       |
| `sandbox`     | `string`        | Sandbox mode hint (reserved for future use)    |

Each parameter entry:

| Field         | Type     | Description                           |
|---------------|----------|---------------------------------------|
| `name`        | `string` | Parameter name                        |
| `type`        | `string` | Type hint (`string`, `bool`, `int`)   |
| `required`    | `bool`   | Whether the parameter is required     |
| `default`     | `string` | Default value for optional parameters |
| `description` | `string` | Human-readable description            |

The sidecar file is optional. If missing or malformed, the hook is still
discovered but reported without metadata.

## Step 3: Deploy to the Hooks Directory

Copy the script and optional sidecar to the configured hooks directory and
ensure the script is executable.

```bash
# Copy files
sudo cp /tmp/restart-service.sh /etc/plexd/hooks/restart-service
sudo cp /tmp/restart-service.sh.json /etc/plexd/hooks/restart-service.json

# Set permissions
sudo chmod 755 /etc/plexd/hooks/restart-service
sudo chmod 644 /etc/plexd/hooks/restart-service.json

# Verify
ls -la /etc/plexd/hooks/
```

> **Note**: The hook name used in action requests is the filename (without
> extension). In this example, the action name is `restart-service`.

## Step 4: Hook Discovery

plexd automatically discovers new and changed hooks using the `HookWatcher`,
which monitors the hooks directory with `fsnotify`. Adding a hook needs no
restart. **Changing** one does: the digest a hook is executed against is pinned
at first discovery and the watcher cannot move it, so an edited hook is refused
until the agent restarts (see [Verify the Checksum](#verify-the-checksum)).

When a hook file is added, modified, or removed, plexd:

1. Detects the filesystem event (with debouncing)
2. Scans the file for executability
3. Computes the SHA-256 checksum
4. Parses the sidecar metadata file (if present)
5. Reports updated capabilities to the control plane

The initial scan at startup also follows this process for all existing hooks.

## Step 5: Verify Discovery

Check the agent logs to confirm the hook was discovered:

```bash
plexd logs | grep -i hook
```

`plexd logs` reads whatever log the host's service manager keeps, so the same
command works on Linux and macOS. Its Linux equivalent is
`journalctl -u plexd --since "1 minute ago"`.

You should see discovery-related log entries. The hook will appear in the
capabilities reported to the control plane with its computed checksum.

### Verify the Checksum

The control plane receives the hook's SHA-256 checksum. You can verify it
locally:

```bash
sha256sum /etc/plexd/hooks/restart-service
```

This is the digest plexd pins the first time it discovers the hook and
re-verifies before every execution. If the file on disk changes afterwards, the
hook fails integrity verification and will not run — and it keeps failing until
the agent restarts, because the watcher deliberately cannot move the pin. That is
what makes the check meaningful: a digest refreshed on every write would only
compare the file with a hash of itself.

To roll out a changed hook, deploy the new file and restart the agent, which
re-discovers it and re-reports the new checksum to the control plane.

The dispatch itself carries **no** checksum. Whether this node may run this hook
at all is decided upstream by the control plane's server-side dispatch gating; the
node's own check answers a narrower question: are these still the bytes it
discovered and reported?

## Step 6: Trigger from the Control Plane

The control plane triggers hook execution by queueing an entry in the `executions`
block of the node's state snapshot. plexd consumes that block on every successful
reconciliation pull:

```json
{
  "execution_id": "exec-abc-123",
  "action": "restart-service",
  "type": "hook",
  "parameters": {
    "service": "nginx"
  },
  "status": "pending",
  "requested_at": "2026-07-27T10:30:00Z",
  "expires_at": "2026-07-27T10:35:00Z"
}
```

The node will:

1. **Claim**: post an execution callback with `status=ack`, then one with `status=started` — both before anything runs, so an execution the control plane still holds at `ack` is known not to have executed
2. **Verify**: compare the hook's SHA-256 against the digest pinned at first discovery
3. **Run**: execute the script with `PLEXD_PARAM_SERVICE=nginx`
4. **Report**: post a terminal callback (`succeeded`, `failed`, or `cancelled`) with the exit code and captured output

Each step is one `POST /v1/nodes/{node_id}/executions/{execution_id}` callback.
The entry keeps reappearing on every pull until the terminal callback settles it.

An `action_request` SSE event may arrive alongside the dispatch, but it carries no
payload the node acts on — it only pulls the next reconcile forward, so the
execution starts in milliseconds instead of at the reconciliation cadence. A node
with no event stream still runs every dispatch.

For the full state machine, the 16 KiB inline-output rule, and the presigned
upload leg for larger output, see the
[Remote Actions and Hooks Reference](../reference/actions/remote-actions-hooks.md).

## Execution Lifecycle

```text
Control Plane                          Node (plexd)
     │                                      │
     │◀── GET /v1/nodes/{id}/state ─────────│── reconciliation pull
     │─── executions: [ entry ] ───────────▶│── dispatch stage
     │◀── callback: ack ────────────────────│── verify vs discovery digest
     │◀── callback: started ────────────────│── execute script
     │                                      │── capture stdout/stderr
     │◀── callback: succeeded ──────────────│── report terminal status + output
     │                                      │  (entry drains from the block)
```

## Troubleshooting

### Hook Not Discovered

| Symptom                    | Cause                                   | Fix                                                |
|----------------------------|-----------------------------------------|----------------------------------------------------|
| Hook missing from capabilities | File not executable              | `chmod +x /etc/plexd/hooks/my-hook`              |
| Hook missing from capabilities | `hooks_dir` not configured       | Set `hooks_dir` in actions config                   |
| Hook missing from capabilities | File has `.json` extension       | Remove `.json` extension from the script filename  |
| Hook missing from capabilities | File is in a subdirectory        | Move to the hooks directory root (subdirs skipped) |

### Hook Execution Fails

| Symptom                        | Cause                             | Fix                                                |
|--------------------------------|-----------------------------------|----------------------------------------------------|
| Status `error`, integrity fail | The file changed after the agent pinned its digest | Restart the agent so it re-discovers and re-attests the hook |
| Status `error`, file not found | Hook in capabilities but missing  | Verify file exists at `hooks_dir/<action-name>`     |
| Status `failed`, `error="action timed out"` | Script outran the run deadline, which is whatever is left of the entry's `expires_at`, capped by `max_action_timeout` | Optimize the script, or raise `max_action_timeout` and have the control plane dispatch a later `expires_at` |
| Status `failed`, exit code > 0 | Script returned non-zero exit     | Check stderr in result for error details           |
| Empty stdout                   | Script writes to file, not stdout | Write output to stdout (`echo`) for capture        |

### Parameter Issues

| Symptom                    | Cause                                    | Fix                                                |
|----------------------------|------------------------------------------|----------------------------------------------------|
| Empty parameter value      | Parameter name case mismatch             | Parameters are uppercased: `target` → `PLEXD_PARAM_TARGET` |
| Missing parameter          | Parameter not in the entry's `parameters`| Ensure control plane sends the parameter           |
| Garbled parameter name     | Special characters in name               | Non-alphanumeric chars become underscores          |

## Reference

For the full API type definitions, configuration fields, and implementation
details, see the
[Remote Actions and Hooks Reference](../reference/actions/remote-actions-hooks.md).
