---
title: PlexdHook CRD Reference
package: internal/kubernetes
feature: PXD-0030
---

# PlexdHook CRD Reference

The `PlexdHook` custom resource describes an operational task (maintenance, upgrades, diagnostics) that plexd runs as a Kubernetes Job. A resource runs nothing by itself: plexd runs a PlexdHook only when the control plane dispatches it, as one Job per execution and Node, pinned to the Node of the plexd pod that received the dispatch. plexd reports the Job's outcome and its pod's log through the [execution callback](remote-actions-hooks.md#execution-callback-contract), deletes the Job on a cancel request, and follows it again after an agent restart. It also lists the resources in its [capability manifest](#capability-manifest-reporting), which tells the control plane which hooks it can dispatch.

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

**Printer columns:** Hook Name, Privileged, Phase, Age. Phase reads `status.phase`, which plexd never writes, so the column stays empty (see [status](#status-subresource)).

## CRD schema

### spec

| Field          | Type                | Required | Default | Description                                      |
|----------------|---------------------|----------|---------|--------------------------------------------------|
| `hookName`     | `string`            | Yes      | —       | Name of the hook to execute. Must be non-empty.  |
| `jobTemplate`  | `object`            | No       | —       | Container image and command for the Job.          |
| `parameters`   | `array` of objects  | No       | `[]`    | Name/value pairs passed as environment variables. A dispatch parameter of the same name overrides one. |
| `privileged`   | `boolean`           | No       | `false` | Run the Job container with elevated privileges.   |

#### jobTemplate

| Field     | Type              | Required | Description                        |
|-----------|-------------------|----------|------------------------------------|
| `image`   | `string`          | No       | Container image. Must be non-empty if set. |
| `command` | `array` of string | No       | Container entrypoint override.     |
| `args`    | `array` of string | No       | Arguments to the entrypoint.       |

When `jobTemplate` is omitted, the image is `busybox:latest`. That default carries no digest, and neither it nor any other image without a `sha256` digest runs: plexd leaves such a hook out of the capability manifest and refuses a dispatch of it (see [Image pinning](#image-pinning)).

#### parameters

Each entry is an object with:

| Field   | Type     | Required | Description                |
|---------|----------|----------|----------------------------|
| `name`  | `string` | Yes      | Parameter name. Non-empty. |
| `value` | `string` | Yes      | Parameter value.           |

Parameters are converted to environment variables in the Job container with the prefix `PLEXD_PARAM_`. The parameter name is uppercased and non-alphanumeric characters (except underscore) are replaced with `_`. For example, a parameter named `disk-path` becomes `PLEXD_PARAM_DISK_PATH`. The resource's parameters are defaults: a dispatch parameter of the same name overrides one (see [Environment](#environment)).

### status (subresource)

The CRD declares a status subresource with these fields. plexd writes none of them: a run's outcome goes to the control plane through the execution callback, so the status block stays empty and the Phase column of `kubectl get plexdhooks` stays blank. The fields stay because `deploy/kubernetes/crds/plexdhook-crd.yaml` is kept unchanged; plexsphere vendors copies of it.

| Field         | Type       | Declared as                                           |
|---------------|------------|-------------------------------------------------------|
| `jobName`     | `string`   | Name of a Kubernetes Job                              |
| `phase`       | `string`   | `Pending`, `Running`, `Succeeded`, or `Failed`        |
| `message`     | `string`   | Human-readable status message                         |
| `startedAt`   | `date-time`| Start time                                            |
| `completedAt` | `date-time`| Completion time                                       |

## Running a hook

plexd runs a PlexdHook only when the control plane dispatches it. Creating, changing, or deleting a resource creates no Job; it only changes the [capability manifest](#capability-manifest-reporting).

### When a run starts

A dispatch arrives as an entry of the pull's [`executions` block](remote-actions-hooks.md#dispatch-delivery-the-executions-block) with `type` `plexd_hook`. Its `action` is the PlexdHook's `metadata.name`, and its `parameters` are the dispatch's own. plexd runs it when all of these hold:

- plexd runs in a pod, and `plexd up` built the PlexdHook runner. It builds one only inside a cluster, and logs a warning and builds none when the ServiceAccount namespace is empty, when `MY_NODE_NAME` is not set, or when the Job client cannot be built (see [Run log lines](#run-log-lines)). Without a runner the entry is rejected with `error=unsupported_action_type`, as it is on a host.
- The resource is in the namespace plexd's ServiceAccount runs in, the one plexd lists for the manifest. A name with no resource there ends `failed` with `error=unknown_action`.
- The image is pinned by a `sha256` digest (see [Image pinning](#image-pinning)).
- The ServiceAccount holds the Role `plexd-hook-runner` (see [RBAC permissions](#rbac-permissions)).

The entry goes through the same [Execute Flow](remote-actions-hooks.md#execute-flow) as a builtin or a script hook. The `actions_disabled` gate, the three deferral reasons, and `actions.max_concurrent` apply unchanged, and plexd posts `ack` and `started` before it makes any Kubernetes call. The run's own goroutine then:

1. Reports `failed` with `error=execution deadline lapsed before the run started`, and creates no Job, when the claim used up what was left of `expires_at`.
2. Derives the run deadline from what is left of `expires_at`, capped by `actions.max_action_timeout`, as for every action kind (see [Run Deadline](remote-actions-hooks.md#run-deadline)).
3. Reads the PlexdHook, checks its image and its parameters, and creates the Job described below. A Job of that name that already exists is not an error.
4. Follows the Job until it is over or the run deadline passes (see [Following the Job](#following-the-job)).
5. Posts the terminal callback the [outcome table](#outcome) gives, with the pod's log as output, and logs `action completed`.

No Kubernetes call runs on the reconcile goroutine, so the dispatch pass budget is unchanged. A PlexdHook that does not exist therefore ends as `ack`, `started`, `failed` with `error=unknown_action`, the same three callbacks the rejection walk sends for an unknown script hook.

### The Job

plexd creates the Job in its own namespace:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: plexdhook-<32 hex>
  labels:
    app.kubernetes.io/managed-by: plexd
  annotations:
    plexd.plexsphere.com/execution-id: <execution id>
    plexd.plexsphere.com/node-id: <plexd node id>
    plexd.plexsphere.com/hook: <PlexdHook metadata.name>
  ownerReferences:
    - apiVersion: plexd.plexsphere.com/v1alpha1
      kind: PlexdHook
      name: <metadata.name>
      uid: <metadata.uid>
      controller: true
      blockOwnerDeletion: false
spec:
  backoffLimit: 0
  activeDeadlineSeconds: <run deadline in seconds, rounded up, + 30>
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
                    values: [<MY_NODE_NAME>]
      containers:
        - name: hook
          image: <spec.jobTemplate.image>
          command: <spec.jobTemplate.command, omitted when empty>
          args: <spec.jobTemplate.args, omitted when empty>
          env: <see Environment>
          securityContext: <see Security context>
```

| Field | Value | Why |
|---|---|---|
| `metadata.name` | `plexdhook-` and the first 32 hex characters of the SHA-256 over plexd's node id, one zero byte, and the execution id: 42 characters | An execution id names the Execution, not its target, so every plexd of a DaemonSet receives the same id for a dispatch to several Nodes, and they all create their Jobs in one namespace. The node id keeps the names apart, and the hash is a valid DNS label whatever the ids hold |
| Labels | `app.kubernetes.io/managed-by: plexd` on the Job and its pod | The pod never carries `app.kubernetes.io/name: plexd`, which the DaemonSet selects its own pods on |
| Annotations | The execution id, plexd's node id, and the PlexdHook's name | Lead from a Job back to its Execution, Node, and resource |
| `ownerReferences` | The PlexdHook, with `controller: true` and `blockOwnerDeletion: false` | Deleting the PlexdHook deletes its Jobs by background garbage collection. `blockOwnerDeletion: true` would need `update` on `plexdhooks/finalizers` on a cluster that enforces owner-reference permissions, and background collection does not need it |
| `backoffLimit` | `0` | A hook runs once; a failed pod fails the Job |
| `activeDeadlineSeconds` | The run deadline in seconds, rounded up, plus 30: `630` for 600 seconds, `32` for 1.2 seconds | plexd enforces the run deadline itself. This is the backstop for a deadline that passes while no agent runs. When it passes, the Job controller deletes the Job's pods at once, and their log with them, so plexd reads the log and deletes the Job itself first |
| `ttlSecondsAfterFinished` | `3600` | A finished Job stays for an hour, so its pod can be inspected and an agent that restarted before its report landed still finds the outcome |
| `restartPolicy` | `Never` | A container that exits is not restarted in place |
| `automountServiceAccountToken` | `false`, and no `serviceAccountName` | The hook pod holds no credentials for the Kubernetes API, and plexd's own ServiceAccount, which can read Secrets cluster-wide, never reaches it |
| `tolerations` | `operator: Exists` | Tolerates every taint, as the DaemonSet does, so the Job runs on every Node plexd runs on |
| `nodeAffinity` | Required, on the field `metadata.name`, with `MY_NODE_NAME` as the value | Pins the Job to the Node of the plexd pod that created it. The `kubernetes.io/hostname` label is not guaranteed to equal the node name, so plexd matches the field |
| Container `name` | `hook` | plexd reads the exit code and the log of this container |

The CRD has no field for resource limits, volumes, a ServiceAccount, or a hook timeout, so the Job sets no limits, mounts no volumes, and names no ServiceAccount. The run deadline comes from the dispatch's `expires_at` and `actions.max_action_timeout` alone, and a hook that needs the Kubernetes API has no way to get a token.

#### Security context

The container's security context depends on `spec.privileged`:

```yaml
# privileged: false (the default)
securityContext:
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```

```yaml
# privileged: true
securityContext:
  privileged: true
```

plexd does not veto `privileged: true`. The resource's field decides it, and under managed push the control plane's `domain#manage` gate decides who may set it. The capability manifest reports a privileged hook with `sandbox: false`.

#### Image pinning

plexd runs only an image pinned by a `sha256` digest. A resource whose image has none, such as the tag `alpine:3.19` or the `busybox:latest` default of a resource without `jobTemplate`, fails the run before any Job exists, with `error=plexd hook image is not pinned by a sha256 digest: <image>`. The check is `PlexdHookSpec.ImageDigest`, the same one the [capability manifest](#capability-manifest-reporting) uses, so the manifest and the run cannot disagree: a hook the manifest leaves out is one the control plane never admits a dispatch for.

The pull entry carries no digest. plexd runs the image the resource names when it creates the Job, so a resource changed between the control plane's integrity gate and that moment runs the new image, and the next manifest reports the drift.

### Environment

plexd sets these variables in the hook container, sorted by name. Kubernetes adds its own service variables, such as `KUBERNETES_SERVICE_HOST`, beside them:

| Variable             | Value                                                              |
|----------------------|--------------------------------------------------------------------|
| `PLEXD_EXECUTION_ID` | The dispatch's execution id                                        |
| `PLEXD_HOOK_NAME`    | `spec.hookName`                                                    |
| `PLEXD_NODE_ID`      | plexd's node id, not the Kubernetes node name                      |
| `PLEXD_PARAM_<NAME>` | One per parameter, the name sanitized as under [parameters](#parameters) |

plexd writes the resource's `spec.parameters` first, in list order, and then the dispatch's parameters in ascending name order. A later write to the same variable wins, so a dispatch parameter overrides a resource parameter of the same name, and a name repeated in the resource keeps its later value. Two names that sanitize to the same variable, such as `disk-path` and `disk_path`, collide the same way. A dispatch value reaches the hook [flattened](remote-actions-hooks.md#parameter-passing) as for every action kind: a JSON string unquoted, any other value as its JSON text.

For a resource with `target=/var/backups` and `retention=7d`, a dispatch with `{"target": "/srv", "disk-path": "/dev/sda"}` gives:

```text
PLEXD_EXECUTION_ID=<execution id>
PLEXD_HOOK_NAME=<spec.hookName>
PLEXD_NODE_ID=<plexd node id>
PLEXD_PARAM_DISK_PATH=/dev/sda
PLEXD_PARAM_RETENTION=7d
PLEXD_PARAM_TARGET=/srv
```

A NUL character in a parameter name or value, from the resource or from the dispatch, fails the run before any Job exists, with `error=plexd hook parameter <name> contains a NUL character`.

### Following the Job

plexd reads the Job at once and then every 2 seconds. At most `actions.max_concurrent` runs exist at a time, so the API server sees one read per run every 2 seconds, 2.5 a second at the default of 5. Each API call has a budget of 10 seconds.

| What plexd sees | What it does |
|---|---|
| The `Complete` condition | Reads the result and reports the run succeeded |
| The `Failed` condition with reason `DeadlineExceeded` | Reports a timeout with no exit code and no output: the Job controller has deleted the pods |
| The `Failed` condition with any other reason | Reads the result. Without an exit code, the run's reason is `plexd hook job failed: <reason>: <message>` |
| No Job (`404`) | Reports the Job deleted before it finished |
| A read that fails | Logs `plexd hook job status read failed` at warn, once per streak of failures, and keeps reading |
| The run deadline has passed | Reads the Job once more, because the last read may be up to 2 seconds old, and handles a Job that ended in that time as above. Otherwise reads the result: a `hook` container that has terminated by then is reported with its exit code and log, and its Job is left to `ttlSecondsAfterFinished`. A container that still runs or never started is a timeout: plexd deletes the Job. When the newest pod's container is waiting, the reason is `hook container never started: <waiting reason>`, such as `ImagePullBackOff`; when the Job has no pod, it is `hook container never started` |

plexd ignores the `FailureTarget` condition that comes ahead of `Failed`, and waits for `Failed`.

Reading the result lists the Job's pods by the label `job-name=<job>`, takes the newest, and reads the `hook` container's exit code from `state.terminated.exitCode` and its log with `limitBytes` set to `actions.max_output_bytes` plus one. A log longer than `max_output_bytes` is cut to that size and ends in `...[truncated]`, as for a script hook. When the pod list or the log read fails, plexd logs `plexd hook output unavailable` at warn and reports the outcome without output.

A delete asks for background propagation, so Kubernetes removes the Job's pod after it. A delete that fails logs `plexd hook job delete failed` at warn, and the Job's `activeDeadlineSeconds` still ends it.

When the run's context ends while plexd reads the result of a Job that is over, or reads and deletes one whose run deadline passed, and that read or delete fails for it, plexd does not report what it could not read. The run ends the way a cancel or a shutdown ends it (see [Cancel, shutdown, and resume](#cancel-shutdown-and-resume)): a cancel deletes the Job and reports `cancelled`, and a shutdown leaves the Job to the next agent, which reads the result in full.

### Outcome

| The Job | `status` | `exit_code` | `error` |
|---|---|---|---|
| `Complete` | `succeeded` | The `hook` container's exit code, or 0 when plexd could not read one | empty |
| `Failed`, with the container's exit code | `failed` | That exit code | empty, as for a script hook that exits non-zero |
| `Failed`, with no exit code | `failed` | omitted | `plexd hook job failed: <reason>: <message>` |
| Ended by the run deadline, or by `activeDeadlineSeconds` | `failed` | omitted | `action timed out`, then `: max_action_timeout <d>` when the ceiling set the deadline, then `; <reason>` when the container never started |
| Deleted before it finished | `failed` | omitted | `plexd hook job deleted before it finished` |
| Gone when a restarted agent [resumes](#cancel-shutdown-and-resume) the run | `failed` | omitted | `execution lost to an agent restart` |
| Never created: no PlexdHook of that name | `failed` | omitted | `unknown_action` |
| Never created: the claim used up `expires_at` | `failed` | omitted | `execution deadline lapsed before the run started` |
| Never created or not followed for another reason, such as an image without a digest, a NUL in a parameter, or an API call the server refused | `failed` | omitted | The error, such as `create job: kubernetes: create job in "plexd-system": status 403: kubernetes: unauthorized` |
| Deleted on a [cancel request](#cancel-shutdown-and-resume) | `cancelled` | omitted | empty |

A timeout reads, for example, `action timed out`, `action timed out: max_action_timeout 10m0s`, or `action timed out; hook container never started: ImagePullBackOff`. When the ceiling set the deadline, plexd also logs `run deadline capped by max_action_timeout` at warn once the run got as far as following the Job.

Every `error` is cut to 1024 bytes on a rune boundary. The contract allows 4096 code points, and a kubelet image pull message alone runs to several hundred bytes.

The output is the pod's log, sent like the output of every action kind: inline up to 16 KiB, through the upload leg above that, and left off when the log is empty (see [Execution Callback Contract](remote-actions-hooks.md#execution-callback-contract)). A run the deadline ended carries the log read before the delete; a Job `activeDeadlineSeconds` ended carries none.

### Cancel, shutdown, and resume

**Cancel.** An entry that carries `cancel_requested_at` makes the dispatcher call `Executor.Cancel` (see [Cancel](remote-actions-hooks.md#cancel)). plexd reads the log so far, deletes the Job, and reports `cancelled` with that log and an empty `error`. The read and the delete run under a budget of 10 seconds, of which the log read gets at most half, so a slow log read cannot keep the delete from running. A cancel that arrives while plexd is still creating the Job ends the same way. A log read that fails leaves the report without output. A delete that fails logs `plexd hook job delete failed` at warn, the run still reports `cancelled`, without output, and the Job runs on until it ends or its `activeDeadlineSeconds` passes. A result plexd has already read is reported as it is.

**Shutdown.** An agent shutdown leaves the Job running. plexd logs `leaving the plexd hook job running; the next agent start resumes it` at info and sends no callback, so the entry stays at `started`. A script hook dies with plexd because it is plexd's child process; a Job is not, so a rolling restart of the DaemonSet costs no run in flight.

**Resume.** The next agent process finds the entry at `started` on its pull. Instead of reporting it lost, the dispatcher hands a `plexd_hook` entry to `Executor.Resume`, which logs `resuming plexd hook run after a restart` at info and follows the same Job, found by the same name. Its run deadline is computed afresh, as for a new run: what is left of `expires_at`, capped by `actions.max_action_timeout` from the moment of the resume. When that ceiling capped the original run, the Job's `activeDeadlineSeconds`, set from the original deadline, usually ends it first, and the run then reports a timeout without its log. It creates nothing and sends no `ack` or `started`; its only callback is the terminal the Job's outcome maps to. A Job that is gone reports `failed` with `error=execution lost to an agent restart`. A finished Job stays for an hour, so an agent that restarted before its report landed still finds the outcome. The dispatcher's side is under [Resume After a Restart](remote-actions-hooks.md#resume-after-a-restart).

### Run log lines

The executor's lines carry `component=actions`:

| Message | Level | Attributes | Meaning |
|---|---|---|---|
| `resuming plexd hook run after a restart` | Info | `execution_id`, `action` | A restarted agent follows the Job of a `started` entry |
| `leaving the plexd hook job running; the next agent start resumes it` | Info | `execution_id` | The agent shuts down while the Job runs; no callback is sent |
| `plexd hook job delete failed` | Warn | `execution_id`, `error` | A cancel could not stop the Job. The run reports `cancelled` without output, and `activeDeadlineSeconds` still ends the Job |
| `run deadline capped by max_action_timeout` | Warn | `execution_id`, `action`, `ceiling`, `requested` | `actions.max_action_timeout` set the run deadline. `requested` is what was left of `expires_at` |
| `action completed` | Info | `execution_id`, `status`, `duration` | The terminal callback went out |

The runner's lines carry `component=plexdhook-jobs`:

| Message | Level | Attributes | Meaning |
|---|---|---|---|
| `plexd hook job created` | Info | `execution_id`, `hook`, `job`, `deadline_seconds` | The Job exists. `deadline_seconds` is the run deadline |
| `plexd hook job status read failed` | Warn | `execution_id`, `job`, `error` | A read of the Job failed. Logged once per streak of failures; plexd keeps reading |
| `plexd hook job delete failed` | Warn | `execution_id`, `job`, `error` | The Job could not be deleted at the run deadline; `activeDeadlineSeconds` still ends it |
| `plexd hook output unavailable` | Warn | `execution_id`, `job`, `error`, and `pod` for a failed log read | The pod list or the log read failed; the outcome is reported without output |

`plexd up` logs these without a component, once at boot, and runs no PlexdHook afterwards:

| Message | Level | Attributes | Meaning |
|---|---|---|---|
| `plexd hook runs disabled: the ServiceAccount namespace is empty` | Warn | | No namespace to create Jobs in |
| `plexd hook runs disabled: MY_NODE_NAME is not set` | Warn | | No Node to pin a Job to. The DaemonSet sets it through the downward API |
| `plexd hook runs disabled` | Warn | `error` | The Job client could not be built |

Outside a cluster `plexd up` builds no runner and logs nothing about it.

## RBAC permissions

The `plexd` ClusterRole grants the read the inventory and a run need:

| API Group              | Resource             | Verbs                         |
|------------------------|----------------------|-------------------------------|
| `plexd.plexsphere.com` | `plexdhooks`         | get, list, watch              |

A run reads its PlexdHook through this `get`. The Job grants sit in the Role `plexd-hook-runner` in plexd's namespace, `plexd-system`, which a RoleBinding of the same name binds to the `plexd` ServiceAccount:

| API Group | Resource   | Verbs               | Used for                                      |
|-----------|------------|---------------------|-----------------------------------------------|
| `batch`   | `jobs`     | create, get, delete | Creating, following, and deleting a run's Job |
| (core)    | `pods`     | list                | Finding the Job's pod                         |
| (core)    | `pods/log` | get                 | Reading the hook's log                        |

plexd creates Jobs only in the namespace where it lists PlexdHooks, and a cluster-wide `pods/log` grant would let one Node's agent read the log of every pod in the cluster. plexd writes no PlexdHook status and holds no `plexdhooks/status` grant. All of these are in `deploy/kubernetes/rbac.yaml`, which an existing deployment applies again with the release (see [Upgrading an existing deployment](../deployment/kubernetes-deployment.md#upgrading-an-existing-deployment)).

A consumer role `plexd-hook-reader` provides read-only access to PlexdHook resources:

| API Group              | Resource             | Verbs              |
|------------------------|----------------------|--------------------|
| `plexd.plexsphere.com` | `plexdhooks`         | get, list, watch   |

## Example

```yaml
apiVersion: plexd.plexsphere.com/v1alpha1
kind: PlexdHook
metadata:
  name: disk-check
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

The CRD accepts this resource, but its image is the tag `alpine:3.19`, so plexd leaves the hook out of the capability manifest and refuses a dispatch of it. With the image pinned by digest, as under [Capability manifest reporting](#capability-manifest-reporting), a dispatch of `disk-check` creates a non-privileged Job on the Node that received it. The Job runs `df -h /dev/sda1` with `PLEXD_PARAM_DISK_PATH=/dev/sda1` and `PLEXD_PARAM_THRESHOLD=90`, unless the dispatch passes its own value for either.

## Capability manifest reporting

plexd reports the `PlexdHook` resources in the namespace its ServiceAccount runs in to the control plane, in the `plexd_hooks` field of its [capability manifest](remote-actions-hooks.md#capability-announcement). It lists them at boot, with a 10-second budget, and then follows a watch, so a resource created, changed, or deleted while the agent runs reaches the control plane within seconds, with no pod restart. The `plexdhooks` `list` and `watch` grants in the `plexd` ClusterRole cover both. The inventory only reads these resources and starts no Job; a Job runs only when the control plane dispatches the hook (see [Running a hook](#running-a-hook)).

Discovery never blocks boot. When the CRD is not installed, the grant is missing, or the API server does not answer, plexd logs one warning and sends the first manifest without `plexd_hooks`. The watch loop keeps trying, and the list goes out with the next successful list.

Each reported entry is built from one resource:

| Manifest field    | Source                                                                  |
|-------------------|-------------------------------------------------------------------------|
| `name`            | `metadata.name`                                                         |
| `image_digest`    | The `sha256:<64 lowercase hex>` digest after the last `@` of the image the Job runs |
| `parameters`      | `spec.parameters` as a name-to-value map; a repeated name keeps the later value. A hook with a NUL character in a parameter stays out of the catalog with a warning, because the control plane cannot store one |
| `sandbox`         | `true` unless `spec.privileged` is set, matching the [security context](#security-context) the Job gets |
| `timeout_seconds` | Never sent: the CRD has no timeout field                                |

**Only digest-pinned images are reported.** The control plane accepts an image digest and nothing else, and plexd has no registry access to resolve a tag. A hook whose image is a tag, such as `alpine:3.19`, or that omits `jobTemplate` and so runs the `busybox:latest` default, stays out of the catalog, and plexd logs a warning naming the hook and its image. A dispatch of such a hook is refused the same way (see [Image pinning](#image-pinning)). Pin the image by digest to have the hook reported:

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
