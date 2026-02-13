---
title: Creating Custom Hook Scripts
quadrant: backend
package: internal/actions
feature: PXD-0019
---

# Creating Custom Hook Scripts

Hook scripts extend plexd's remote action capabilities without modifying the
binary. This guide walks through creating, deploying, and triggering a custom
hook on a plexd-managed node.

For the full reference of types and internals, see
[Remote Actions and Hooks Reference](../../reference/backend/remote-actions-hooks.md).

## Prerequisites

1. **plexd is running** on the node with actions enabled (default).

2. **Hooks directory** is configured. The default is empty (no hooks directory).
   Set `HooksDir` in the actions configuration to a directory path, e.g.
   `/etc/plexd/hooks`.

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

## Step 4: Restart plexd for Discovery

plexd discovers hooks at startup by scanning the hooks directory. Restart the
agent to pick up the new hook.

```bash
sudo systemctl restart plexd
```

On startup, plexd:

1. Scans the hooks directory for executable files
2. Computes the SHA-256 checksum for each hook
3. Parses sidecar metadata files
4. Reports capabilities (builtins + hooks) to the control plane

## Step 5: Verify Discovery

Check the agent logs to confirm the hook was discovered:

```bash
journalctl -u plexd --since "1 minute ago" | grep -i hook
```

You should see discovery-related log entries. The hook will appear in the
capabilities reported to the control plane with its computed checksum.

### Verify the Checksum

The control plane receives the hook's SHA-256 checksum. You can verify it
locally:

```bash
sha256sum /etc/plexd/hooks/restart-service
```

This checksum must match the value the control plane sends in the
`action_request` event's `checksum` field. If the checksums don't match at
execution time, the hook will fail integrity verification and will not run.

## Step 6: Trigger from the Control Plane

The control plane triggers hook execution by sending an `action_request` SSE
event to the node. The event payload contains:

```json
{
  "execution_id": "exec-abc-123",
  "action": "restart-service",
  "parameters": {
    "service": "nginx"
  },
  "timeout": "30s",
  "checksum": "a1b2c3d4e5f6..."
}
```

The node will:

1. **Ack**: send an `ExecutionAck` with `status=accepted`
2. **Verify**: compare the hook's SHA-256 against the provided `checksum`
3. **Execute**: run the script with `PLEXD_PARAM_SERVICE=nginx`
4. **Report**: send an `ExecutionResult` with stdout, stderr, exit code, and duration

## Execution Lifecycle

```
Control Plane                          Node (plexd)
     │                                      │
     │─── action_request (SSE) ────────────▶│
     │                                      │── parse ActionRequest
     │◀── ExecutionAck (accepted) ──────────│── verify checksum (SHA-256)
     │                                      │── execute script
     │                                      │── capture stdout/stderr
     │◀── ExecutionResult ─────────────────│── report result
     │                                      │
```

## Troubleshooting

### Hook Not Discovered

| Symptom                    | Cause                                   | Fix                                                |
|----------------------------|-----------------------------------------|----------------------------------------------------|
| Hook missing from capabilities | File not executable              | `chmod +x /etc/plexd/hooks/my-hook`              |
| Hook missing from capabilities | HooksDir not configured          | Set `HooksDir` in actions config                   |
| Hook missing from capabilities | File has `.json` extension       | Remove `.json` extension from the script filename  |
| Hook missing from capabilities | File is in a subdirectory        | Move to the hooks directory root (subdirs skipped) |

### Hook Execution Fails

| Symptom                        | Cause                             | Fix                                                |
|--------------------------------|-----------------------------------|----------------------------------------------------|
| Status `error`, integrity fail | Checksum mismatch                 | Re-deploy hook and wait for capability refresh     |
| Status `error`, file not found | Hook in capabilities but missing  | Verify file exists at `HooksDir/<action-name>`     |
| Status `timeout`               | Script exceeds timeout            | Optimize script or increase timeout in request     |
| Status `failed`, exit code > 0 | Script returned non-zero exit     | Check stderr in result for error details           |
| Empty stdout                   | Script writes to file, not stdout | Write output to stdout (`echo`) for capture        |

### Parameter Issues

| Symptom                    | Cause                                    | Fix                                                |
|----------------------------|------------------------------------------|----------------------------------------------------|
| Empty parameter value      | Parameter name case mismatch             | Parameters are uppercased: `target` → `PLEXD_PARAM_TARGET` |
| Missing parameter          | Parameter not in action request          | Ensure control plane sends the parameter           |
| Garbled parameter name     | Special characters in name               | Non-alphanumeric chars become underscores          |

## Reference

For the full API type definitions, configuration fields, and implementation
details, see the
[Remote Actions and Hooks Reference](../../reference/backend/remote-actions-hooks.md).
