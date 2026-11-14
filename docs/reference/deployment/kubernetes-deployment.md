---
title: Kubernetes DaemonSet Deployment Reference
package: internal/kubernetes
feature: PXD-0022
---

# Kubernetes DaemonSet Deployment Reference

Reference documentation for deploying plexd as a Kubernetes DaemonSet. Covers environment detection, configuration, CRD controller, the PlexdHook inventory and Job runner, audit log reader, authentication, and manifest structure.

## KubernetesEnvironment

`KubernetesEnvironment` holds metadata about the Kubernetes environment in which plexd is running. A `nil` value from `Detect()` indicates the process is not running inside a pod.

```go
type KubernetesEnvironment struct {
    InCluster           bool
    Namespace           string
    PodName             string
    NodeName            string
    ServiceAccountToken string
}
```

| Field                 | Source                                                      |
|-----------------------|-------------------------------------------------------------|
| `InCluster`           | `true` if `KUBERNETES_SERVICE_HOST` env var is set          |
| `Namespace`           | Read from `/var/run/secrets/kubernetes.io/serviceaccount/namespace` |
| `PodName`             | `HOSTNAME` env var                                          |
| `NodeName`            | `MY_NODE_NAME` env var (set via downward API)               |
| `ServiceAccountToken` | `/var/run/secrets/kubernetes.io/serviceaccount/token`       |

### EnvironmentDetector interface

```go
type EnvironmentDetector interface {
    Detect() *KubernetesEnvironment
}
```

`DefaultDetector` implements this interface using real environment variables and filesystem paths.

## Config

Configuration for Kubernetes integration. Passed as a constructor argument; no file I/O in this package.

| Field             | Type            | Default                                      | Description                                  |
|-------------------|-----------------|----------------------------------------------|----------------------------------------------|
| `Enabled`         | `bool`          | `false`                                      | Must be explicitly enabled                   |
| `CRDEnabled`      | `bool`          | `true` (when `Enabled`)                      | Whether CRD management is active             |
| `Namespace`       | `string`        | *(empty — auto-detected)*                    | Override namespace                           |
| `AuditLogPath`    | `string`        | `/var/log/kubernetes/audit/audit.log`        | Path to Kubernetes audit log                 |
| `CRDSyncInterval` | `time.Duration` | `10s`                                        | Interval for CRD state reconciliation        |
| `TokenPath`       | `string`        | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Path to service account token |

### Methods

- **`ApplyDefaults(env *KubernetesEnvironment)`** — Sets default values for zero-valued fields. When `env` is non-nil and `InCluster` is true, sets `Enabled=true`, `CRDEnabled=true`, and auto-detects `Namespace`.
- **`Validate() error`** — Skips validation when `Enabled` is `false`. Validates `Namespace` non-empty, `AuditLogPath` non-empty, `CRDSyncInterval >= 1s`, `TokenPath` non-empty.

## PlexdNodeState CRD

The `PlexdNodeState` custom resource definition exposes node state to the Kubernetes API.

```go
type PlexdNodeState struct {
    Name            string               `json:"name"`
    Namespace       string               `json:"namespace"`
    UID             string               `json:"uid,omitempty"`
    ResourceVersion string               `json:"resourceVersion,omitempty"`
    Labels          map[string]string    `json:"labels,omitempty"`
    Spec            PlexdNodeStateSpec   `json:"spec"`
    Status          PlexdNodeStateStatus `json:"status,omitempty"`
    LastUpdate      time.Time            `json:"lastUpdate"`
}

type PlexdNodeStateSpec struct {
    NodeID     string            `json:"nodeId"`
    MeshIP     string            `json:"meshIp,omitempty"`
    Metadata   map[string]string `json:"metadata,omitempty"`
    Data       []DataEntry       `json:"data,omitempty"`
    SecretRefs []SecretRef       `json:"secretRefs,omitempty"`
}

type PlexdNodeStateStatus struct {
    Report []DataEntry `json:"report,omitempty"`
}
```

**CRD manifest:** `deploy/kubernetes/crds/plexdnodestate-crd.yaml`

| Property       | Value                          |
|----------------|--------------------------------|
| API group      | `plexd.plexsphere.com`                |
| Kind           | `PlexdNodeState`               |
| Plural         | `plexdnodestates`              |
| Short name     | `pns`                          |
| Scope          | `Namespaced`                   |
| Version        | `v1alpha1`                     |

**Printer columns:** Node ID, Mesh IP, Age.

## KubeClient interface

Abstracts Kubernetes API interactions for testability. All state-modifying methods are idempotent.

```go
type KubeClient interface {
    GetNodeState(ctx context.Context, namespace, name string) (*PlexdNodeState, error)
    CreateNodeState(ctx context.Context, state *PlexdNodeState) error
    UpdateNodeState(ctx context.Context, state *PlexdNodeState) error
    DeleteNodeState(ctx context.Context, namespace, name string) error
    WatchNodeState(ctx context.Context, namespace, name string) (<-chan PlexdNodeStateEvent, error)
    CreateSecret(ctx context.Context, secret *KubeSecret) error
    UpdateSecret(ctx context.Context, secret *KubeSecret) error
    DeleteSecret(ctx context.Context, namespace, name string) error
}
```

The PlexdHook calls are not part of it: [HookLister](#hooklister) lists and watches the resources, and [JobClient](#jobclient) runs them.

### Sentinel errors

| Error              | Value                                  | Description                     |
|--------------------|----------------------------------------|---------------------------------|
| `ErrNotFound`      | `kubernetes: resource not found`       | Resource does not exist         |
| `ErrAlreadyExists` | `kubernetes: resource already exists`  | Resource already exists         |
| `ErrUnauthorized`  | `kubernetes: unauthorized`             | Client lacks valid credentials  |

## CRDController

Periodically syncs local node state to a `PlexdNodeState` CRD resource.

```go
type CRDController struct {
    client         KubeClient
    reportNotifier ReportNotifier
    cfg            Config
    namespace      string
    nodeID         string
    meshIP         string
    resourceName   string // "node-{node_id}"
    logger         *slog.Logger
}
```

### Constructor

```go
func NewCRDController(client KubeClient, cfg Config, nodeID, meshIP, namespace string, reportNotifier ReportNotifier, logger *slog.Logger) *CRDController
```

Config defaults are applied automatically.

### ReportNotifier interface

```go
type ReportNotifier interface {
    NotifyChange()
}
```

Called when the CRDController detects new or changed report entries in the status subresource.

### Start

```go
func (c *CRDController) Start(ctx context.Context) error
```

Creates or updates the PlexdNodeState resource and starts the status watcher goroutine. Blocks until `ctx` is cancelled.

### Start behavior

1. Ensures the CRD resource exists (create or update)
2. Starts a watch on the resource for status changes
3. When status report entries change, calls `ReportNotifier.NotifyChange()`
4. Blocks until context is cancelled

## K8sAuditLogReader

Implements `auditfwd.K8sAuditReader` by reading Kubernetes audit log files in JSON-lines format.

```go
type K8sAuditLogReader struct {
    path   string
    offset int64
    logger *slog.Logger
}
```

### Constructor

```go
func NewK8sAuditLogReader(path string, logger *slog.Logger) *K8sAuditLogReader
```

### ReadEvents

```go
func (r *K8sAuditLogReader) ReadEvents(ctx context.Context) ([]auditfwd.K8sAuditEntry, error)
```

**Behavior:**

- Reads from `r.offset` to end of file; only new entries since last call are returned
- If the file does not exist or cannot be opened, returns an error
- If the file was truncated (offset > file size), resets offset to 0 and reads from the beginning
- Malformed JSON lines are skipped with a warning log
- Timestamp is parsed from `stageTimestamp`, falling back to `requestReceivedTimestamp`
- `objectRef` and `responseStatus` may be nil in the audit event; handled gracefully

**Audit log format (JSON-lines):**

Each line is a Kubernetes audit event:

```json
{"kind":"Event","verb":"create","user":{"username":"admin"},"objectRef":{"resource":"pods","namespace":"default","name":"web-1"},"responseStatus":{"code":201},"stageTimestamp":"2025-01-15T10:30:01.000000Z"}
```

## TokenReviewAuthenticator

Validates Kubernetes service account tokens via the TokenReview API.

```go
type TokenReviewAuthenticator struct {
    client    TokenReviewClient
    logger    *slog.Logger
    audiences []string
}
```

### Constructor

```go
func NewTokenReviewAuthenticator(client TokenReviewClient, logger *slog.Logger, audiences []string) *TokenReviewAuthenticator
```

### Authenticate

```go
func (a *TokenReviewAuthenticator) Authenticate(ctx context.Context, token string) (*TokenReviewResult, error)
```

| Condition           | Result                                          |
|---------------------|--------------------------------------------------|
| Empty token         | Error: `kubernetes: authenticate: empty token`   |
| Client error        | Error: `kubernetes: authenticate: review failed` |
| Not authenticated   | Error: `kubernetes: authenticate: token not authenticated` |
| Audience mismatch   | Error: `kubernetes: authenticate: audience mismatch` |
| Success             | Returns `*TokenReviewResult`                     |

### HTTPTokenReviewClient

Production implementation that calls the Kubernetes API server:

```go
func NewHTTPTokenReviewClient(apiServer, saTokenPath string) *HTTPTokenReviewClient
```

- Posts to `{apiServer}/apis/authentication.k8s.io/v1/tokenreviews`
- Authenticates with the service account token read from `saTokenPath`
- Loads cluster CA from `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`
- TLS minimum version: 1.2

## HookLister

Lists and watches `PlexdHook` resources through the API server for the capability manifest. A list is one authenticated GET and a watch is one authenticated GET held open as a stream. Neither writes.

```go
func NewInClusterHookLister(env *KubernetesEnvironment) (*HookLister, error)
func (l *HookLister) ListPlexdHooks(ctx context.Context, namespace string) ([]PlexdHook, error)
func (l *HookLister) WatchPlexdHooks(ctx context.Context, namespace string) (<-chan PlexdHookEvent, error)
```

- Connects to `https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT`; construction fails when either variable is unset
- Trusts the cluster CA at `DefaultCACertPath`; construction fails when the bundle cannot be read or holds no certificate
- GETs `/apis/plexd.plexsphere.com/v1alpha1/namespaces/{namespace}/plexdhooks`; a watch adds `?watch=true` and no `resourceVersion`, so 410 Gone cannot occur and the API server starts by replaying every existing resource as `ADDED`
- Reads the service account token from `env.ServiceAccountToken` on every call and every watch open, because the kubelet rotates it
- Has no overall timeout, because a watch lasts as long as its stream; the caller's context bounds each call, and the transport allows 10 seconds each for the TLS handshake and for the response headers
- TLS minimum version: 1.2

| Response     | Result                                           |
|--------------|--------------------------------------------------|
| `200 OK`     | The resources or an empty slice, or for a watch the event channel |
| `401`, `403` | Error wrapping `ErrUnauthorized`                 |
| `404`        | Error wrapping `ErrNotFound` (CRD not installed) |
| Other status | Error naming the status                          |

The event channel delivers `ADDED`, `MODIFIED`, and `DELETED` frames with the metadata unnested and skips `BOOKMARK` frames. It closes when the stream ends, a frame does not decode, a frame has type `ERROR`, or the context ends. It carries no reason, because the answer to each of these is to open a new watch.

### PlexdHook inventory

`plexd up` runs `DefaultDetector.Detect()` before it builds the capability reporter. In a pod it lists the `PlexdHook` resources in the ServiceAccount's namespace with a 10-second budget and reports the digest-pinned ones as `plexd_hooks`. A goroutine then watches those resources for as long as the agent runs and reports the list again when it changes (see [PlexdHook CRD](../actions/plexdhook-crd.md#keeping-the-list-current)). The `plexdhooks` `get, list, watch` grant in the `plexd` ClusterRole covers both the list and the watch. Outside a cluster the step costs one environment variable check and no watch runs. Inside one, a missing grant, a missing CRD, a timeout, or an unreachable API server at boot logs one warning, and the first manifest goes out without `plexd_hooks`. The node boots either way, and the list reaches the control plane once a later list succeeds.

Right after the inventory, `plexd up` builds the [PlexdHook runner](#wiring-in-plexd-up), which runs a dispatched hook. The inventory itself only reads and starts no Job.

## JobClient

Reads a PlexdHook, creates, reads, and deletes the Jobs of its runs, and reads their pods, through the API server. Nothing else in plexd writes to the cluster for a PlexdHook.

```go
func NewInClusterJobClient(env *KubernetesEnvironment) (*JobClient, error)
```

`JobClient` and `HookLister` embed the unexported `apiServer`, which holds the base URL, the token path, and the HTTP client. `newAPIServer(host, port, caPath string, env *KubernetesEnvironment)` builds it, so the connection rules under [HookLister](#hooklister) hold for both: the same environment variables, cluster CA, TLS minimum, transport timeouts, and token read on every call.

| Method | Request | Notes |
|---|---|---|
| `GetPlexdHook(ctx, namespace, name) (*PlexdHook, error)` | `GET /apis/plexd.plexsphere.com/v1alpha1/namespaces/{namespace}/plexdhooks/{name}` | The metadata is unnested as in a list. `404` wraps `ErrNotFound` |
| `CreateJob(ctx, namespace string, job *HookJob) error` | `POST /apis/batch/v1/namespaces/{namespace}/jobs` | `409` wraps `ErrAlreadyExists` |
| `GetJob(ctx, namespace, name) (JobState, error)` | `GET /apis/batch/v1/namespaces/{namespace}/jobs/{name}` | `JobState` from the conditions of type `Complete` and `Failed` with status `True`. The `FailureTarget` condition, which comes ahead of `Failed`, is ignored |
| `DeleteJob(ctx, namespace, name) error` | `DELETE /apis/batch/v1/namespaces/{namespace}/jobs/{name}` with the body `{"propagationPolicy":"Background"}` | `404` is nil |
| `ListJobPods(ctx, namespace, jobName) ([]JobPod, error)` | `GET /api/v1/namespaces/{namespace}/pods?labelSelector=job-name%3D{jobName}` | An empty list is an empty slice. `ExitCode` and `WaitingReason` come from the `hook` container's `state.terminated.exitCode` and `state.waiting.reason` |
| `PodLog(ctx, namespace, pod string, limitBytes int64) (string, error)` | `GET /api/v1/namespaces/{namespace}/pods/{pod}/log?container=hook&limitBytes={n}` | Returns the first `n` bytes of the log |

```go
type JobState struct {
    Complete, Failed bool
    Reason, Message  string
}

type JobPod struct {
    Name          string
    CreatedAt     time.Time
    ExitCode      *int
    WaitingReason string
}
```

`HookJob` is a struct with `batch/v1` JSON tags for exactly the [Job document](../actions/plexdhook-crd.md#the-job) plexd creates. Every name in a path goes through `url.PathEscape`.

Each method makes its request through `apiServer.do(ctx, what, method, path, rawQuery, body)`, where `what` names the call, such as `create job in "plexd-system"`:

| Response | Result |
|---|---|
| Token unreadable | `kubernetes: <what>: read service account token: <cause>` |
| Transport error | `kubernetes: <what>: <cause>` |
| Any `2xx` | The response, for the method to decode |
| `401`, `403` | `kubernetes: <what>: status <code>: kubernetes: unauthorized`, wrapping `ErrUnauthorized` |
| `404` | `kubernetes: <what>: status 404: kubernetes: resource not found`, wrapping `ErrNotFound` |
| `409` | `kubernetes: <what>: status 409: kubernetes: resource already exists`, wrapping `ErrAlreadyExists` |
| Any other status | `kubernetes: <what>: unexpected status <code>: <message>`, where the message is the first 512 bytes of the `message` of the `metav1.Status` body, or `kubernetes: <what>: unexpected status <code>` when the body is not a `metav1.Status` with a message |

`HookLister` keeps its own list and watch requests, so its error texts are unchanged.

## HookJobRunner

Implements `actions.PlexdHookRunner` (see [Remote Actions and Hooks](../actions/remote-actions-hooks.md#kubernetes-crd-hooks)) over an unexported interface that holds the six `JobClient` methods. `internal/kubernetes` imports `internal/actions` for the interface's types; nothing under `internal/actions` imports `internal/kubernetes`.

```go
type HookJobConfig struct {
    Namespace   string // the ServiceAccount's namespace
    NodeName    string // MY_NODE_NAME
    NodeID      string // plexd's node id
    OutputLimit int64  // actions.max_output_bytes
}

func NewHookJobRunner(client hookJobAPI, cfg HookJobConfig, logger *slog.Logger) *HookJobRunner
```

The logger carries `component=plexdhook-jobs`. `Start`, `Wait`, and `Stop` address the Job as `hookJobName(cfg.NodeID, executionID)`: `plexdhook-` and the first 32 hex characters of the SHA-256 over the node id, one zero byte, and the execution id.

| Constant | Value | Meaning |
|---|---|---|
| `hookJobPollInterval` | `2s` | Time between two reads of the Job in `Wait` |
| `hookJobBackstop` | `30s` | Added to the run deadline for the Job's `activeDeadlineSeconds` |
| `hookJobRequestTimeout` | `10s` | Budget of each API call |
| `hookJobTTLSeconds` | `3600` | The Job's `ttlSecondsAfterFinished` |

The runner holds them in fields, so a test can shorten them.

### Start

1. `GetPlexdHook`. `ErrNotFound` becomes `actions.ErrPlexdHookNotFound`, and any other error is wrapped as `get plexd hook: <cause>`
2. `PlexdHookSpec.ImageDigest()`, the check the capability manifest uses too. An image without a `sha256` digest fails with `plexd hook image is not pinned by a sha256 digest: <image>`
3. A NUL character in a parameter name or value, from the resource or from the dispatch, fails with `plexd hook parameter <name> contains a NUL character`
4. `CreateJob` with the [Job document](../actions/plexdhook-crd.md#the-job). `ErrAlreadyExists` is nil, and any other error is wrapped as `create job: <cause>`
5. Log `plexd hook job created` at info with `execution_id`, `hook`, `job`, and `deadline_seconds`

### Wait

`Wait(ctx, executionID, bound)` calls `GetJob` at once and then every `hookJobPollInterval`. At most `actions.max_concurrent` runs exist at a time, so the API server sees one read per run every 2 seconds, 2.5 a second at the default of 5.

| `GetJob` answers | Result |
|---|---|
| `Complete` | Collect, and return `Succeeded` |
| `Failed` with reason `DeadlineExceeded` | `TimedOut` with no exit code and no output: the Job controller has deleted the pods |
| `Failed` with another reason | Collect. Without an exit code, `Reason` is `plexd hook job failed: <reason>: <message>` |
| `ErrNotFound` | `actions.ErrPlexdHookJobNotFound` |
| Any other error | Log `plexd hook job status read failed` at warn, once per streak of failures, and keep reading |

When `bound` has elapsed since `Wait` began, it calls `GetJob` once more, because the last read may be a poll interval old, and handles a Job that ended in that time by the table above. Otherwise it collects. A newest pod whose `hook` container has an exit code finished after the last read: `Wait` returns it as finished, `Succeeded` when the exit code is 0, and does not delete the Job. Anything else calls `DeleteJob` and returns `TimedOut`, with `Reason` `hook container never started: <WaitingReason>` when the newest pod is waiting, and `hook container never started` when the Job has no pod. A delete that fails logs `plexd hook job delete failed` at warn; the backstop still ends the Job. When `ctx` ends, `Wait` returns `ctx.Err()` and leaves the Job alone. So does a collect or a delete after the decision that fails because `ctx` ended: the executor then takes its cancel or shutdown path, instead of reporting a result without its exit code or log.

Collect is `ListJobPods`, the pod with the newest `CreatedAt`, its `ExitCode`, and `PodLog` with `OutputLimit + 1`, so the executor sees an over-limit log and marks the cut. A list or log read that fails logs `plexd hook output unavailable` at warn and yields a result without output.

### Stop

`Stop(ctx, executionID)` collects, then calls `DeleteJob`, and returns the log. The collect runs under at most half of what is left of `ctx`, so a log read the API server does not answer cannot spend the time the delete needs. A delete that fails is returned wrapped.

### Wiring in plexd up

`plexd up` builds the runner with `newPlexdHookRunner(env *kubernetes.KubernetesEnvironment, nodeID string, outputLimit int64, logger *slog.Logger) actions.PlexdHookRunner` in `cmd/plexd/cmd/plexd_hooks.go`, right after the [PlexdHook inventory](#plexdhook-inventory) and before it registers the action dispatcher, and hands it to the executor with `SetPlexdHookRunner`. Outside a cluster it returns nil and logs nothing. Inside one it logs one warning and returns nil:

| Condition | Warning |
|---|---|
| The ServiceAccount namespace is empty | `plexd hook runs disabled: the ServiceAccount namespace is empty` |
| `MY_NODE_NAME` is not set | `plexd hook runs disabled: MY_NODE_NAME is not set` |
| `NewInClusterJobClient` fails | `plexd hook runs disabled`, with `error` |

Without a runner, a `plexd_hook` dispatch is rejected with `unsupported_action_type`, and a `started` one is reported lost after a restart. The DaemonSet sets `MY_NODE_NAME` through the downward API.

## Kubernetes manifests

All manifests are in `deploy/kubernetes/`.

| File                    | Resources                                    |
|-------------------------|----------------------------------------------|
| `namespace.yaml`        | `Namespace` (plexd-system)                   |
| `crds/plexdnodestate-crd.yaml` | `CustomResourceDefinition` (PlexdNodeState) |
| `crds/plexdhook-crd.yaml`     | `CustomResourceDefinition` (PlexdHook)      |
| `serviceaccount.yaml`   | `ServiceAccount`                             |
| `rbac.yaml`             | `ClusterRole` + `ClusterRoleBinding`, `Role` + `RoleBinding` `plexd-hook-runner`, consumer roles |
| `daemonset.yaml`        | `DaemonSet` with host networking and capabilities |
| `secret.yaml`           | Example `Secret` template for bootstrap token |

### RBAC permissions

The `plexd` ClusterRole grants:

| API Group              | Resource                  | Verbs                                          |
|------------------------|---------------------------|-------------------------------------------------|
| `plexd.plexsphere.com` | `plexdnodestates`         | get, list, watch, create, update, patch, delete |
| `plexd.plexsphere.com` | `plexdnodestates/status`  | get, patch, update                             |
| (core)                 | `secrets`                 | create, get, update, delete                    |
| `plexd.plexsphere.com` | `plexdhooks`              | get, list, watch                               |
| `authentication.k8s.io`| `tokenreviews`            | create                                         |

The `plexd-hook-runner` Role in `plexd-system`, bound to the `plexd` ServiceAccount by the RoleBinding of the same name, grants what a [PlexdHook run](../actions/plexdhook-crd.md#running-a-hook) needs:

| API Group | Resource   | Verbs               |
|-----------|------------|---------------------|
| `batch`   | `jobs`     | create, get, delete |
| (core)    | `pods`     | list                |
| (core)    | `pods/log` | get                 |

The Job grants are namespaced, because plexd creates Jobs only in the namespace where it lists PlexdHooks, and a cluster-wide `pods/log` grant would let one Node's agent read the log of every pod in the cluster. plexd writes no PlexdHook status and holds no `plexdhooks/status` grant.

#### Upgrading an existing deployment

An existing deployment applies the new `deploy/kubernetes/rbac.yaml` with the release:

```sh
kubectl apply -f deploy/kubernetes/rbac.yaml
```

Until it does, the `plexd` ClusterRole still holds the old cluster-wide `batch` `jobs` grant (`create, get, list, watch`), and the Role does not exist. A PlexdHook run then still creates its Job and reports the Job's status, but without the container's exit code or output, because plexd can neither list the Job's pods nor read their log. A cancel request cannot delete the Job: plexd logs `plexd hook job delete failed`, and the Job runs on until it ends or its `activeDeadlineSeconds` passes.

Consumer RBAC roles:

| Role                    | Resources                 | Verbs              |
|-------------------------|---------------------------|--------------------|
| `plexd-state-reader`    | `plexdnodestates`         | get, list, watch   |
| `plexd-state-reporter`  | `plexdnodestates/status`  | get, patch         |
| `plexd-secrets-reader`  | `secrets`                 | get                |
| `plexd-hook-reader`     | `plexdhooks`              | get, list, watch   |

### DaemonSet configuration

| Setting               | Value                          | Reason                                |
|-----------------------|--------------------------------|---------------------------------------|
| `hostNetwork`         | `true`                         | WireGuard mesh requires host networking |
| `dnsPolicy`           | `ClusterFirstWithHostNet`      | Required with hostNetwork             |
| `priorityClassName`   | `system-node-critical`         | Ensures scheduling on resource pressure |
| `tolerations`         | `operator: Exists`             | Run on all nodes including control plane |
| `readOnlyRootFilesystem` | `true`                      | Security hardening                    |
| Capabilities          | `NET_ADMIN`, `NET_RAW`         | WireGuard interface management and the nftables policy chain. Without `NET_ADMIN`, `plexd up` fails its firewall pre-flight and exits before registering |

### Environment variables

| Variable                 | Source                          | Description                    |
|--------------------------|---------------------------------|--------------------------------|
| `MY_NODE_NAME`           | `fieldRef: spec.nodeName`       | Kubernetes node name (downward API) |
| `PLEXD_BOOTSTRAP_TOKEN`  | `secretKeyRef: plexd-bootstrap` | Bootstrap token from Secret    |

### Volume mounts

| Mount path                         | Source               | Access     |
|------------------------------------|----------------------|------------|
| `/etc/plexd`                       | ConfigMap `plexd-config` | read-only  |
| `/var/lib/plexd`                   | hostPath             | read-write |
| `/var/run/plexd`                   | hostPath             | read-write |
| `/var/log/kubernetes/audit`        | hostPath             | read-only  |

## Constants

| Constant                | Value                                                      |
|-------------------------|-------------------------------------------------------------|
| `ServiceAccountBasePath`| `/var/run/secrets/kubernetes.io/serviceaccount`            |
| `DefaultTokenPath`      | `{ServiceAccountBasePath}/token`                           |
| `DefaultNamespacePath`  | `{ServiceAccountBasePath}/namespace`                       |
| `DefaultCACertPath`     | `{ServiceAccountBasePath}/ca.crt`                          |
| `DefaultAuditLogPath`   | `/var/log/kubernetes/audit/audit.log`                      |
| `DefaultCRDSyncInterval`| `10s`                                                      |

## See also

- [Kubernetes Deployment Guide](../../how-to/kubernetes-deployment.md) — Step-by-step deployment guide
- [PlexdHook CRD Reference](../actions/plexdhook-crd.md) — PlexdHook resources, each dispatch run as a Kubernetes Job
- [Audit Forwarding Reference](../observability/audit-forwarding.md) — Audit data collection and forwarding
- [Local Node API Reference](../core/nodeapi.md) — Node state API
- [Registration Reference](../core/registration.md) — Node registration
