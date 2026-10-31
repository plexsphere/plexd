---
title: PlexdHook CRD Reference
package: internal/kubernetes
feature: PXD-0030
---

# PlexdHook CRD Reference

The `PlexdHook` custom resource definition enables declarative hook execution as Kubernetes Jobs. Platform operators create `PlexdHook` resources to trigger operational tasks (maintenance, upgrades, diagnostics) on specific nodes. The PlexdHook controller watches these resources and creates Jobs with node pinning, owner references, and configurable security contexts.

## CRD metadata

| Property       | Value                            |
|----------------|----------------------------------|
| API group      | `plexd.plexsphere.com`           |
| Kind           | `PlexdHook`                      |
| Plural         | `plexdhooks`                     |
| Short name     | `ph`                             |
| Scope          | `Namespaced`                     |
| Version        | `v1alpha1`                       |
| Manifest       | `deploy/kubernetes/crds/plexdhook-crd.yaml` |

**Printer columns:** Hook Name, Privileged, Phase, Age.

## CRD schema

### spec

| Field          | Type                | Required | Default | Description                                      |
|----------------|---------------------|----------|---------|--------------------------------------------------|
| `hookName`     | `string`            | Yes      | —       | Name of the hook to execute. Must be non-empty.  |
| `jobTemplate`  | `object`            | No       | —       | Container image and command for the Job.          |
| `parameters`   | `array` of objects  | No       | `[]`    | Name/value pairs passed as environment variables. |
| `privileged`   | `boolean`           | No       | `false` | Run the Job container with elevated privileges.   |

#### jobTemplate

| Field     | Type              | Required | Description                        |
|-----------|-------------------|----------|------------------------------------|
| `image`   | `string`          | No       | Container image. Must be non-empty if set. |
| `command` | `array` of string | No       | Container entrypoint override.     |
| `args`    | `array` of string | No       | Arguments to the entrypoint.       |

When `jobTemplate` is omitted, the controller uses `busybox:latest` as the default image.

#### parameters

Each entry is an object with:

| Field   | Type     | Required | Description                |
|---------|----------|----------|----------------------------|
| `name`  | `string` | Yes      | Parameter name. Non-empty. |
| `value` | `string` | Yes      | Parameter value.           |

Parameters are converted to environment variables in the Job container with the prefix `PLEXD_PARAM_`. The parameter name is uppercased and non-alphanumeric characters (except underscore) are replaced with `_`. For example, a parameter named `disk-path` becomes `PLEXD_PARAM_DISK_PATH`.

### status (subresource)

| Field         | Type       | Description                                           |
|---------------|------------|-------------------------------------------------------|
| `jobName`     | `string`   | Name of the created Kubernetes Job.                   |
| `phase`       | `string`   | Execution phase: `Pending`, `Running`, `Succeeded`, or `Failed`. |
| `message`     | `string`   | Human-readable status message. Set on failure.        |
| `startedAt`   | `date-time`| Timestamp when the controller began processing.       |
| `completedAt` | `date-time`| Timestamp when the Job completed.                     |

## PlexdHookController

The `PlexdHookController` watches `PlexdHook` resources and creates Kubernetes Jobs for hook execution.

### Constructor

```go
func NewPlexdHookController(client KubeClient, cfg Config, namespace, nodeName string, logger *slog.Logger) *PlexdHookController
```

Config defaults are applied automatically.

### Lifecycle

```go
func (c *PlexdHookController) Start(ctx context.Context) error
func (c *PlexdHookController) Stop()
```

`Start` blocks, watching `PlexdHook` resources and processing events. Returns `ctx.Err()` when the context is cancelled, `nil` when the watch channel closes, or a wrapped error if the initial watch fails.

`Stop` cancels the internal context, causing `Start` to return.

### Watch-create-status cycle

1. Controller calls `WatchPlexdHooks` on the `KubeClient` for its namespace.
2. On each `ADDED` event, checks if `status.jobName` is already set — if so, skips (already processed).
3. Builds a `PlexdJob` via `buildJob` and calls `CreateJob`.
4. If `CreateJob` returns `ErrAlreadyExists`, the controller logs an info message and still updates status.
5. If `CreateJob` fails with another error, the controller logs at error level and sets `status.phase` to `Failed` with the error message.
6. On success, updates `status.jobName`, `status.phase` to `Pending`, and `status.startedAt`.

### Structured logging

All log entries use `component=plexdhook-controller`. Key events:

| Event                | Level  | Fields                              |
|----------------------|--------|-------------------------------------|
| Controller started   | Info   | `namespace`, `node`                 |
| Job created          | Info   | `hook`, `job`, `node`               |
| Job already exists   | Info   | `hook`, `job`                       |
| Job creation failed  | Error  | `hook`, `error`                     |
| Status update failed | Warn   | `hook`, `error`                     |

## Job creation details

### Node pinning

Each Job includes a `nodeSelector` with `kubernetes.io/hostname` set to the controller's node name. This ensures the hook runs on the same node as the plexd DaemonSet pod.

### Owner references

Jobs are created with an owner reference to the parent `PlexdHook` resource:

| Field                | Value                              |
|----------------------|------------------------------------|
| `apiVersion`         | `plexd.plexsphere.com/v1alpha1`   |
| `kind`               | `PlexdHook`                        |
| `name`               | PlexdHook resource name            |
| `uid`                | PlexdHook resource UID             |
| `controller`         | `true`                             |
| `blockOwnerDeletion` | `true`                             |

Deleting a `PlexdHook` resource cascades to delete the associated Job via Kubernetes garbage collection.

### Security context

The security context depends on the `spec.privileged` flag:

**Non-privileged (default):**

| Setting                  | Value   |
|--------------------------|---------|
| `readOnlyRootFilesystem` | `true`  |
| `dropCapabilities`       | `[ALL]` |

**Privileged:**

| Setting      | Value  |
|--------------|--------|
| `privileged` | `true` |

### Labels

Jobs are labeled for identification and querying:

| Label                            | Value                 |
|----------------------------------|-----------------------|
| `app.kubernetes.io/managed-by`   | `plexd`               |
| `plexd.plexsphere.com/hook-name` | Value of `spec.hookName` |

### Environment variables

Every Job container receives:

| Variable            | Value                          |
|---------------------|--------------------------------|
| `PLEXD_NODE_ID`     | Controller node name           |
| `PLEXD_HOOK_NAME`   | Value of `spec.hookName`       |
| `PLEXD_PARAM_{NAME}`| Parameter values (if any)      |

### Other settings

| Setting              | Value    |
|----------------------|----------|
| `serviceAccountName` | `plexd`  |
| `restartPolicy`      | `Never`  |
| Job name             | `plexdhook-{resource-name}` |

## RBAC permissions

The `plexd` ClusterRole includes the following permissions for PlexdHook operations:

| API Group              | Resource             | Verbs                         |
|------------------------|----------------------|-------------------------------|
| `plexd.plexsphere.com` | `plexdhooks`         | get, list, watch              |
| `plexd.plexsphere.com` | `plexdhooks/status`  | get, update, patch            |
| `batch`                | `jobs`               | create, get, list, watch      |

A consumer role `plexd-hook-reader` provides read-only access to PlexdHook resources:

| API Group              | Resource             | Verbs              |
|------------------------|----------------------|--------------------|
| `plexd.plexsphere.com` | `plexdhooks`         | get, list, watch   |

## Example

```yaml
apiVersion: plexd.plexsphere.com/v1alpha1
kind: PlexdHook
metadata:
  name: disk-check-node01
  namespace: plexd-system
spec:
  hookName: disk-check
  jobTemplate:
    image: alpine:3.19
    command: ["/bin/sh", "-c"]
    args: ["df -h /dev/sda1"]
  parameters:
    - name: disk-path
      value: /dev/sda1
    - name: threshold
      value: "90"
  privileged: false
```

This creates a non-privileged Job on the target node that runs `df -h /dev/sda1` with environment variables `PLEXD_PARAM_DISK_PATH=/dev/sda1` and `PLEXD_PARAM_THRESHOLD=90`.

## Capability manifest reporting

plexd reports the `PlexdHook` resources in the namespace its ServiceAccount runs in to the control plane, in the `plexd_hooks` field of its [capability manifest](remote-actions-hooks.md#capability-announcement). It lists them at boot, with a 10-second budget, and then follows a watch, so a resource created, changed, or deleted while the agent runs reaches the control plane within seconds, with no pod restart. The `plexdhooks` `list` and `watch` grants in the `plexd` ClusterRole cover both. The inventory only reads these resources: `plexd up` starts no `PlexdHookController` and runs no Job.

Discovery never blocks boot. When the CRD is not installed, the grant is missing, or the API server does not answer, plexd logs one warning and sends the first manifest without `plexd_hooks`. The watch loop keeps trying, and the list goes out with the next successful list.

Each reported entry is built from one resource:

| Manifest field    | Source                                                                  |
|-------------------|-------------------------------------------------------------------------|
| `name`            | `metadata.name`                                                         |
| `image_digest`    | The `sha256:<64 lowercase hex>` digest after the last `@` of the image the Job runs |
| `parameters`      | `spec.parameters` as a name-to-value map; a repeated name keeps the later value. A hook with a NUL character in a parameter stays out of the catalog with a warning, because the control plane cannot store one |
| `sandbox`         | `true` unless `spec.privileged` is set, matching the [security context](#security-context) the Job gets |
| `timeout_seconds` | Never sent: the CRD has no timeout field                                |

**Only digest-pinned images are reported.** The control plane accepts an image digest and nothing else, and plexd has no registry access to resolve a tag. A hook whose image is a tag, such as `alpine:3.19`, or that omits `jobTemplate` and so runs the `busybox:latest` default, stays out of the catalog, and plexd logs a warning naming the hook and its image. Pin the image by digest to have the hook reported:

```yaml
spec:
  hookName: disk-check
  jobTemplate:
    image: alpine@sha256:<64 lowercase hex>
```

Entries are sorted by name and capped at 128, the contract's limit; the warning for a larger set names how many were left out. Resources in other namespaces are not listed.

### Keeping the list current

The watch is only a change signal, and the list stays the source of truth, which needs no `resourceVersion` bookkeeping:

1. plexd opens a watch under a 10-minute limit and lists once. The list after every open catches a deletion that happened with no watch running.
2. An event starts a one-second wait, and every event in that second is discarded, so a burst costs one list. An open replays each existing resource as `ADDED`, so a healthy pod costs one held connection and about two lists per 10 minutes.
3. The 10-minute limit ends a stream that died silently. A stream that lived at least a minute reopens at once. A stream that ended sooner, a failed open, and a failed list all back off, from 5 seconds doubling to 5 minutes.
4. A failed open still lists, so a role that grants `list` and not `watch` gets a list about every 5 minutes.

The watch limit and the backoff carry 25% jitter, so a fleet does not stay in phase after an API server restart. Every list has the same 10-second budget as the boot list.

A successful list that returns the same `(name, resourceVersion)` pairs as the one before changes nothing, so a hook whose image has no digest logs its omission warning once per change and not after every watch. A list that differs replaces the snapshot and notifies the [capability reporter](remote-actions-hooks.md#when-the-manifest-is-sent). Deleting the last resource takes the `plexd_hooks` key off the manifest, which is how the control plane learns the list is empty.

A list that fails keeps the last good list and reports nothing. The control plane replaces its stored row on every PUT, so a missing key means none, and sending the manifest without `plexd_hooks` on a transient API server failure would erase every PlexdHook from that row. A failed boot list has no good list to keep, which is why it leaves `plexd_hooks` off the first manifest.

The control plane pins the first image digest it receives for a PlexdHook on a Node as that hook's baseline and never advances it, so changing a hook's image is drift. plexd reports the new digest within seconds, and that PUT and every later accepted PUT carrying it raises an integrity alert with the recommended action `quarantine_node`.

### Log lines

| Message                                                                | Level | Attributes                     | Meaning |
|------------------------------------------------------------------------|-------|--------------------------------|---------|
| `plexd hook discovery skipped: the ServiceAccount namespace is empty` | Warn  |                                | No namespace to list; no watch runs |
| `plexd hook discovery skipped`                                         | Warn  | `error`                        | The lister could not be built; no watch runs |
| `plexd hook discovery failed`                                          | Warn  | `namespace`, `error`           | The boot list failed; the first manifest goes out without `plexd_hooks` |
| `plexd hook watch failed`                                              | Warn  | `namespace`, `error`, `retry_in` | First failure of an outage: an open or a list failed. Repeats log at Debug |
| `plexd hook watch restored`                                            | Info  | `namespace`                    | An open and its list both succeeded after an outage |
| `plexd hook watch ended early`                                         | Debug | `namespace`, `retry_in`        | A stream ended within its first minute; the next open backs off |
| `plexd hook omitted from the capability manifest`                      | Warn  | `hook`, `image`, `reason`      | The image is not pinned by a digest, or a parameter contains a NUL character, which the control plane cannot store |
| `plexd hooks beyond the capability manifest cap omitted`               | Warn  | `cap`, `dropped`               | More than 128 reportable resources |

A cluster with no CRD logs one warning, `plexd hook discovery failed`, and nothing else above Debug. A role that grants `list` and not `watch` logs one `plexd hook watch failed` and never `plexd hook watch restored`, because its opens keep failing.

## See also

- [Kubernetes Deployment Reference](../deployment/kubernetes-deployment.md) — Manifests, RBAC, and DaemonSet configuration
- [Remote Actions and Hooks](remote-actions-hooks.md) — Control plane action execution system
