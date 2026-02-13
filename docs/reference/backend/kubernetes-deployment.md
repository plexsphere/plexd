---
title: Kubernetes DaemonSet Deployment Reference
quadrant: backend
package: internal/kubernetes
feature: PXD-0022
---

# Kubernetes DaemonSet Deployment Reference

Reference documentation for deploying plexd as a Kubernetes DaemonSet. Covers environment detection, configuration, CRD controller, audit log reader, authentication, and manifest structure.

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
| `Namespace`       | `string`        | *(empty — auto-detected)*                    | Override namespace                           |
| `AuditLogPath`    | `string`        | `/var/log/kubernetes/audit/audit.log`        | Path to Kubernetes audit log                 |
| `CRDSyncInterval` | `time.Duration` | `10s`                                        | Interval for CRD state reconciliation        |
| `TokenPath`       | `string`        | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Path to service account token |

### Methods

- **`ApplyDefaults()`** — Sets default values for zero-valued fields. Does not set `Enabled` to `true`.
- **`Validate() error`** — Skips validation when `Enabled` is `false`. Validates `AuditLogPath` non-empty, `CRDSyncInterval >= 1s`, `TokenPath` non-empty.

## PlexdNodeState CRD

The `PlexdNodeState` custom resource definition exposes node state to the Kubernetes API.

```go
type PlexdNodeState struct {
    Name       string            `json:"name"`
    Namespace  string            `json:"namespace"`
    NodeID     string            `json:"node_id"`
    MeshIP     string            `json:"mesh_ip"`
    Metadata   map[string]string `json:"metadata,omitempty"`
    Data       map[string]string `json:"data,omitempty"`
    Reports    map[string]string `json:"reports,omitempty"`
    PeerCount  int               `json:"peer_count"`
    Status     string            `json:"status"`
    LastUpdate time.Time         `json:"last_update"`
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

**Printer columns:** Node ID, Mesh IP, Status, Peers, Age.

## KubeClient interface

Abstracts Kubernetes API interactions for testability. All state-modifying methods are idempotent.

```go
type KubeClient interface {
    GetNodeState(ctx context.Context, namespace, name string) (*PlexdNodeState, error)
    CreateNodeState(ctx context.Context, state *PlexdNodeState) error
    UpdateNodeState(ctx context.Context, state *PlexdNodeState) error
    DeleteNodeState(ctx context.Context, namespace, name string) error
    ListNodeStates(ctx context.Context, namespace string) ([]PlexdNodeState, error)
}
```

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
    client    KubeClient
    provider  StateProvider
    cfg       Config
    namespace string
    name      string
    logger    *slog.Logger
}
```

### Constructor

```go
func NewCRDController(client KubeClient, provider StateProvider, cfg Config, namespace, name string, logger *slog.Logger) *CRDController
```

Config defaults are applied automatically.

### StateProvider interface

```go
type StateProvider interface {
    NodeID() string
    MeshIP() string
    GetMetadata() map[string]string
    GetPeerCount() int
    GetStatus() string
}
```

### Run

```go
func (c *CRDController) Run(ctx context.Context) error
```

Starts the CRD sync loop. First sync runs immediately; subsequent syncs run at `cfg.CRDSyncInterval`. Blocks until `ctx` is cancelled.

### Sync behavior

Each sync cycle:

1. Reads state from `StateProvider`
2. Builds a `PlexdNodeState` with current time as `LastUpdate`
3. Calls `GetNodeState` to check if the resource exists
4. If `ErrNotFound`: creates the resource; if create returns `ErrAlreadyExists` (race), falls back to update
5. If exists: updates the resource

Errors are logged but do not stop the loop.

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
- If the file does not exist, returns `nil, nil`
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

## Kubernetes manifests

All manifests are in `deploy/kubernetes/`.

| File                    | Resources                                    |
|-------------------------|----------------------------------------------|
| `namespace.yaml`        | `Namespace` (plexd-system)                   |
| `crds/plexdnodestate-crd.yaml` | `CustomResourceDefinition` (PlexdNodeState) |
| `serviceaccount.yaml`   | `ServiceAccount`                             |
| `rbac.yaml`             | `ClusterRole` + `ClusterRoleBinding` + consumer roles |
| `daemonset.yaml`        | `DaemonSet` with host networking and capabilities |
| `secret.yaml`           | Example `Secret` template for bootstrap token |

### RBAC permissions

The `plexd` ClusterRole grants:

| API Group              | Resource                  | Verbs                                          |
|------------------------|---------------------------|-------------------------------------------------|
| `plexd.plexsphere.com` | `plexdnodestates`         | get, list, watch, create, update, patch, delete |
| `plexd.plexsphere.com` | `plexdnodestates/status`  | get, patch, update                             |
| (core)                 | `secrets`                 | create, get, update, delete                    |
| `authentication.k8s.io`| `tokenreviews`            | create                                         |

Consumer RBAC roles:

| Role                    | Resources                 | Verbs              |
|-------------------------|---------------------------|--------------------|
| `plexd-state-reader`    | `plexdnodestates`         | get, list, watch   |
| `plexd-state-reporter`  | `plexdnodestates/status`  | get, patch         |
| `plexd-secrets-reader`  | `secrets`                 | get                |

### DaemonSet configuration

| Setting               | Value                          | Reason                                |
|-----------------------|--------------------------------|---------------------------------------|
| `hostNetwork`         | `true`                         | WireGuard mesh requires host networking |
| `dnsPolicy`           | `ClusterFirstWithHostNet`      | Required with hostNetwork             |
| `priorityClassName`   | `system-node-critical`         | Ensures scheduling on resource pressure |
| `tolerations`         | `operator: Exists`             | Run on all nodes including control plane |
| `readOnlyRootFilesystem` | `true`                      | Security hardening                    |
| Capabilities          | `NET_ADMIN`, `NET_RAW`         | WireGuard interface management        |

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

- [Kubernetes Deployment Guide](../../how-to/backend/kubernetes-deployment.md) — Step-by-step deployment guide
- [Audit Forwarding Reference](audit-forwarding.md) — Audit data collection and forwarding
- [Local Node API Reference](nodeapi.md) — Node state API
- [Registration Reference](registration.md) — Node registration
