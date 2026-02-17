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

## See also

- [Kubernetes Deployment Reference](../deployment/kubernetes-deployment.md) — Manifests, RBAC, and DaemonSet configuration
- [Remote Actions and Hooks](remote-actions-hooks.md) — Control plane action execution system
