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
   Linux and `/Library/Application Support/plexd/hooks` on macOS, and
   `plexd install` creates it. Set `hooks_dir` in the actions configuration to
   override. plexd's systemd unit keeps `/etc` read-only, so plexd cannot create
   a custom `hooks_dir` under `/etc` itself: create it before plexd starts.

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

A JSON sidecar file provides metadata about the hook. plexd lists it on the local
node API and reports it in the capability manifest, so the control plane can show
an operator what the hook does and what it expects. The sidecar file must have the
same name as the hook script with a `.json` extension.

> **Warning**: A sidecar's content reaches the control plane and everyone who holds
> `read` there, and no setting keeps it on the node. A sidecar must hold no secret,
> whether in a description or in a parameter's `default`.

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

| Field         | Manifest key      | Type            | Limit           | Description                                    |
|---------------|-------------------|-----------------|-----------------|------------------------------------------------|
| `description` | `description`     | `string`        | 4096 characters | Human-readable description of the hook         |
| `parameters`  | `parameters`      | `[]ActionParam` | 64 parameters   | List of expected parameters with types         |
| `timeout`     | `timeout_seconds` | `string`        | 24 hours        | Suggested default timeout in [`time.ParseDuration`](https://pkg.go.dev/time#ParseDuration) format (e.g. `"30s"`), reported in whole seconds, rounded up |
| `sandbox`     | `sandbox_level`   | `string`        | 64 characters   | Sandbox mode hint, free-form                   |

Characters are Unicode code points, and a NUL in any string breaks its limit. The
manifest as a whole has a 1 MiB budget, so sidecars inside every limit can still
be refused together; see
[When Hook Metadata Is Refused](../reference/actions/remote-actions-hooks.md#when-hook-metadata-is-refused).

`timeout` needs a unit, so `"30"` breaks the rule, and so does a negative value.
`"1500ms"` reports 2 and `"500ms"` reports 1. `"0s"` declares no timeout, and the
key stays off the manifest.

plexd reports `timeout` and `sandbox` as written and does not enforce them yet. A
script still runs until the action timeout, and a sandbox level changes nothing
about how it runs.

Each parameter entry:

| Field         | Type     | Limit           | Description                           |
|---------------|----------|-----------------|---------------------------------------|
| `name`        | `string` | 4096 characters | Parameter name, not blank after trimming and unique within the hook |
| `type`        | `string` | 4096 characters | Type hint (`string`, `bool`, `int`)   |
| `required`    | `bool`   | None            | Whether the parameter is required     |
| `default`     | `string` | 4096 characters | Default value for optional parameters |
| `description` | `string` | 4096 characters | Human-readable description            |

A parameter reaches the manifest under the same keys. One parameter that breaks a
rule leaves the whole `parameters` list off the manifest, because a form with a
required parameter missing misleads the operator who fills it in.

The sidecar file is optional. If it is missing, malformed, or unreadable, the hook
is still discovered but reported without metadata. A field that breaks a limit is
left off the manifest with a warning, and the hook stays with its other fields,
because the control plane refuses a manifest whole and one bad field would
otherwise cost every hook on the node.

## Step 3: Deploy to the Hooks Directory

Install the script atomically: write it, executable, to another path on the same
filesystem as the hooks directory, then `mv` it into the directory. A rename puts
the finished file in place in one step. `/tmp` is often a different filesystem,
where `mv` falls back to a copy, so stage the file beside the hooks directory.

```bash
# Copy the optional sidecar
sudo cp /tmp/restart-service.sh.json /etc/plexd/hooks/restart-service.json
sudo chmod 644 /etc/plexd/hooks/restart-service.json

# Stage the script on the same filesystem, executable
sudo install -m 755 /tmp/restart-service.sh /etc/plexd/restart-service.new

# Move it into place
sudo mv /etc/plexd/restart-service.new /etc/plexd/hooks/restart-service

# Verify
ls -la /etc/plexd/hooks/
```

> **Warning**: The first digest the control plane receives for a hook is pinned as
> its baseline. If plexd reports a half-written file, that digest becomes the
> baseline and the finished file counts as an edit, with the consequences under
> [What an Edit Does](#what-an-edit-does). plexd waits a quiet second before it
> reports, which covers a short write but does not replace an atomic install.

> **Note**: The hook name used in action requests is the filename (without
> extension). In this example, the action name is `restart-service`.

## Step 4: Hook Discovery

plexd automatically discovers new and changed hooks using the `HookWatcher`,
which monitors the hooks directory with `fsnotify`. Adding a hook needs no
restart. **Changing** one does: the digest a hook is executed against is pinned
at first discovery and the watcher cannot move it, so an edited hook is refused
until the agent restarts (see [What an Edit Does](#what-an-edit-does)).

When a hook file is added, modified, or removed, or its sidecar is edited or
removed, plexd:

1. Detects the filesystem event (with debouncing)
2. Checks that the file is a regular, executable file. Anything else is skipped,
   and a hook that stops being one leaves the list
3. Computes the SHA-256 checksum
4. Parses the sidecar metadata file (if present)
5. Reports the updated capability manifest to the control plane, within seconds

The report waits for a quiet second, so a burst of changes costs one report, and
it is skipped when the manifest matches the one last accepted, as it is after a
`touch` on a hook or its sidecar. A sidecar edit or removal changes the manifest,
so it is reported. A sidecar sits outside the hook's digest, so the change moves
no digest and needs no restart.

A report that fails is retried on a backoff until it lands; see
[Retries](../reference/actions/remote-actions-hooks.md#retries). A control plane
that refuses the hook metadata is the exception: plexd sends the hook's name and
digest at once, and tries the metadata again when the content changes and about
hourly. See
[When Hook Metadata Is Refused](../reference/actions/remote-actions-hooks.md#when-hook-metadata-is-refused).

The scan at startup follows the same process for all existing hooks, and it runs
before plexd sends its first manifest, so that manifest carries the hooks on disk.

`plexd hooks reload` runs the same scan on demand and prints the result. It is how
to refresh the list on a node that logged `hook watcher stopped`, because a watch
that failed is not restarted.

## Step 5: Verify Discovery

Check the agent logs to confirm the hook was discovered:

```bash
plexd logs | grep -i -E 'hook|capability report'
```

`plexd logs` reads whatever log the host's service manager keeps, so the same
command works on Linux and macOS. Its Linux equivalent is
`journalctl -u plexd --since "1 minute ago"`.

You should see `agent: capability report: accepted` with the new `declared_hooks`
count, usually within two seconds. The hook then appears in the capabilities the control plane
holds, with its computed checksum. `agent: capability report: send failed` means
the report has not landed yet and plexd is retrying it on its own.

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

The dispatch itself carries **no** checksum. Whether this node may run this hook
at all is decided upstream by the control plane's server-side dispatch gating; the
node's own check answers a narrower question: are these still the bytes it
discovered?

### What an Edit Does

The manifest carries the digest the watcher last computed, which can differ from
the digest plexd pinned, so an edit reaches the control plane within seconds as a
new digest for a known hook. Two checks then refuse the hook, one on each side:

- **The control plane** pinned the first digest it received as the hook's
  baseline. A later digest raises an integrity alert with the recommended action
  `quarantine_node` and refuses dispatch until the control plane accepts the new
  digest. Every accepted PUT that still carries the drifted digest raises another
  alert, which is why plexd has no periodic re-send of a manifest the control
  plane holds. A sidecar edit on such a hook is one more accepted PUT, so it raises
  one more alert.
- **The node** keeps the digest it pinned. An edited hook runs again after an
  agent restart, not after `plexd hooks reload`, which re-scans the directory and
  moves no pin.

To roll out a changed hook, install the new file atomically, as in
[Step 3](#step-3-deploy-to-the-hooks-directory), and restart the agent, which pins
the new bytes and reports the new digest. Replacing a hook with `mv` is still an
edit, and so is removing a hook and adding it back with other bytes, because a pin
outlives the file. The control plane refuses dispatch until it accepts the new
digest, whether or not the agent has restarted.

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
| Hook missing from capabilities | Not a regular file, such as a FIFO | Install a regular file; a symlink to an executable one is fine, but plexd watches the link and not its target, so run `plexd hooks reload` after changing the target |
| Hook missing from capabilities | `agent: capability report: send failed` in the log | plexd retries on its own; the `error` attribute names what to fix |
| Hook missing from capabilities | `hook watcher stopped` in the log | Fix the cause, then run `plexd hooks reload` or restart the agent |
| Hook reported without metadata | A field breaks a limit: `hook metadata omitted from the capability manifest` in the log | The `field` and `error` attributes name what to fix in the sidecar; the hook's other fields are still reported |
| Hook reported without metadata | The control plane refused it: `agent: capability report: hook metadata refused; sending names and digests` in the log | The `error` attribute names the refusal. Upgrade an older control plane, or trim the sidecars of a manifest over its 1 MiB budget. plexd tries again on its own when the content changes and about hourly |
| Hook reported without metadata | Sidecar unreadable: `sidecar read failed` in the log | Make the file the `file` attribute names a regular, readable file |
| Hook reported without metadata | Sidecar malformed: `sidecar parse failed` in the log | Fix the JSON in the file the `file` attribute names |

### Hook Execution Fails

| Symptom                        | Cause                             | Fix                                                |
|--------------------------------|-----------------------------------|----------------------------------------------------|
| Status `error`, integrity fail | The file changed after the agent pinned its digest | Restart the agent so it re-discovers and re-attests the hook; a reload does not clear this |
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
