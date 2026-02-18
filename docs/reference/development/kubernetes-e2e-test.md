---
title: Kubernetes E2E Test
package: test/e2e/kubernetes
feature: PXD-0039
---

# Kubernetes E2E Test

Validates that plexd deployed as a Kubernetes DaemonSet successfully registers, sends heartbeats, retrieves state, reports capabilities, detects drift, and forwards metrics, logs, and audit events to the Central API. The test uses [kind](https://kind.sigs.k8s.io/) to create a local single-node cluster, applies all production manifests from `deploy/kubernetes/`, deploys a mock-api as a ClusterIP Service, and polls the assertion endpoint to verify plexd's lifecycle calls.

## Cluster Topology

```
┌─────────────────────────────────────────────────┐
│              kind cluster (plexd-e2e)            │
│                                                  │
│  ┌──────────────┐       ┌──────────────────┐    │
│  │   mock-api   │◄──────│  plexd DaemonSet │    │
│  │  Deployment  │       │  (host network)  │    │
│  │  :8080 (HTTP)│       │  1 pod per node  │    │
│  │  :8443 (TLS) │       │                  │    │
│  └──────────────┘       └──────────────────┘    │
│  ClusterIP Service                               │
│  mock-api.plexd-e2e:8080, :8443                  │
└─────────────────────────────────────────────────┘
        │ port-forward :18080
        ▼
   localhost:18080/test/assertions
```

| Component | Image | Source | Purpose |
|-----------|-------|--------|---------|
| `mock-api` | `mockapi:e2e` | `test/e2e/mockapi/Dockerfile` | Fixture-based mock Central API, tracks call counters |
| `plexd` | `plexd:e2e` | `deploy/docker/Dockerfile` | Agent under test, deployed as DaemonSet |

## Test Phases

### 1. Pre-flight checks

Verifies that `kind`, `kubectl`, `docker`, `curl`, and `jq` are available on `$PATH`. Exits immediately if any tool is missing.

### 2. Cluster creation

Deletes any pre-existing cluster with the same name, then creates a new kind cluster with `--wait 60s` for node readiness.

### 3. Image build and load

Builds both Docker images from the repository root, then loads them into the kind cluster node with `kind load docker-image`. Both use `imagePullPolicy: Never` to avoid registry pulls.

### 4. Manifest application

Manifests are applied in dependency order:

| Order | Resource | Source | Notes |
|-------|----------|--------|-------|
| 1 | Namespace `plexd-e2e` | `kubectl create namespace` | Test-specific namespace |
| 2 | PlexdNodeState CRD | `deploy/kubernetes/crds/plexdnodestate-crd.yaml` | Cluster-scoped |
| 3 | PlexdHook CRD | `deploy/kubernetes/crds/plexdhook-crd.yaml` | Cluster-scoped |
| 4 | ServiceAccount | `deploy/kubernetes/serviceaccount.yaml` | Namespace patched via sed |
| 5 | RBAC | `deploy/kubernetes/rbac.yaml` | ClusterRoleBinding patched to test namespace |
| 6 | Bootstrap Secret | `kubectl create secret generic` | Token: `e2e-test-token` |
| 7 | ConfigMap | `kubectl create configmap` | Inline config pointing to mock-api |
| 8 | mock-api Deployment + Service | `test/e2e/kubernetes/mock-api-manifests.yaml` | ClusterIP on ports 8080 (HTTP) and 8443 (TLS) |
| 9 | plexd DaemonSet | `deploy/kubernetes/daemonset.yaml` | Image and namespace patched via sed |

The DaemonSet manifest is patched at apply time using `--dry-run=client -o yaml | sed` to substitute the namespace, image tag, and pull policy.

### 5. Readiness wait

- mock-api Deployment: `kubectl rollout status` with 60s timeout.
- plexd DaemonSet: `kubectl rollout status` with configurable timeout (default 120s).

### 6. Port-forward and initial assertions

Port-forward from `localhost:18080` to `svc/mock-api:8080` is started in the background. The script polls `GET /test/assertions` every 5 seconds for up to 60 seconds until all 8 counters are >= 1.

### 7. Request body validation

Uses `GET /test/last-request/{endpoint}` to verify the content of request payloads:

| Endpoint | Validated Fields |
|----------|-----------------|
| `register` | `token` (non-empty), `hostname` (non-empty) |
| `heartbeat` | Valid JSON with `timestamp` field |
| `capabilities` | `builtin_actions` (array with >= 1 entry) |

### 8. Periodic loop verification

Waits up to 60 seconds for `heartbeat_count` and `metrics_count` to reach >= 2, proving that self-generating periodic loops run continuously. Logs and audit are tested via pod restart.

### 9. Pod restart resilience

Deletes the plexd pod and waits for the DaemonSet controller to schedule a new pod. Verifies:
- New pod becomes ready within 60 seconds
- Heartbeat resumes (agent loads persisted identity from hostPath and enters steady state)
- `audit_count` increases (new `ProcessSource` fires `process_start` in the new pod)

Note: `registration_count` does not increase because the identity persists via the `hostPath` volume at `/var/lib/plexd`. This is correct production behavior — the agent reuses its existing registration.

### 10. Local endpoint delivery

Polls `GET /test/assertions` until `local_metrics_count`, `local_logs_count`, and `local_audit_count` are all >= 1 (timeout: 60s). Validates that the local endpoint credential chain works in Kubernetes: NSK from registration → secret fetch → AES-256-GCM decryption → Bearer token → HTTPS POST to `mock-api.plexd-e2e:8443`.

### 11. Cleanup

The `cleanup` function runs on `EXIT` trap (both success and failure). It kills the port-forward process, prints diagnostics, and deletes the kind cluster.

## Assertion Logic

The test polls `GET http://localhost:18080/test/assertions` which returns JSON counters:

```json
{
  "registration_count": 1,
  "heartbeat_count": 3,
  "state_count": 1,
  "capabilities_count": 1,
  "drift_count": 1,
  "metrics_count": 1,
  "logs_count": 1,
  "audit_count": 1,
  "local_metrics_count": 1,
  "local_logs_count": 1,
  "local_audit_count": 1
}
```

The test passes when all eight platform counters are >= 1 (initial assertions), and separately verifies that all three local endpoint counters are >= 1 (Phase 10):

| Counter | Meaning |
|---------|---------|
| `registration_count` | plexd called `POST /v1/register` |
| `heartbeat_count` | plexd called `POST /v1/nodes/{id}/heartbeat` |
| `state_count` | plexd called `GET /v1/nodes/{id}/state` |
| `capabilities_count` | plexd called `PUT /v1/nodes/{id}/capabilities` |
| `drift_count` | plexd called `POST /v1/nodes/{id}/drift` |
| `metrics_count` | plexd called `POST /v1/nodes/{id}/metrics` |
| `logs_count` | plexd called `POST /v1/nodes/{id}/logs` |
| `audit_count` | plexd called `POST /v1/nodes/{id}/audit` |
| `local_metrics_count` | plexd sent metrics to `POST /local/metrics` (TLS) |
| `local_logs_count` | plexd sent logs to `POST /local/logs` (TLS) |
| `local_audit_count` | plexd sent audit to `POST /local/audit` (TLS) |

## plexd Configuration

The ConfigMap is created inline by the test script (not from `deploy/kubernetes/plexd-config-configmap.yaml`) because the API URL must point to the in-cluster mock-api Service.

```yaml
api:
  base_url: http://mock-api.plexd-e2e:8080
registration:
  data_dir: /var/lib/plexd
node_api:
  data_dir: /var/lib/plexd
heartbeat:
  node_id: e2e-k8s-node
metrics:
  local_endpoint:
    url: https://mock-api.plexd-e2e:8443/local/metrics
    secret_key: local-bearer-token
    tls_insecure_skip_verify: true
log_fwd:
  local_endpoint:
    url: https://mock-api.plexd-e2e:8443/local/logs
    secret_key: local-bearer-token
    tls_insecure_skip_verify: true
audit_fwd:
  local_endpoint:
    url: https://mock-api.plexd-e2e:8443/local/audit
    secret_key: local-bearer-token
    tls_insecure_skip_verify: true
```

The bootstrap token is set via `kubectl create secret generic plexd-bootstrap --from-literal=token=e2e-test-token`.

## Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLUSTER_NAME` | `plexd-e2e` | Name of the kind cluster |
| `TIMEOUT` | `120s` | DaemonSet rollout timeout |

## Usage

```bash
make test-e2e-k8s
```

Or directly:

```bash
bash test/e2e/kubernetes/test.sh
```

Override configuration:

```bash
CLUSTER_NAME=my-cluster TIMEOUT=180s make test-e2e-k8s
```

### Prerequisites

- Docker
- [kind](https://kind.sigs.k8s.io/)
- `kubectl`
- `curl` and `jq` on the host

## Debugging Failures

**DaemonSet does not become ready:**

```bash
kubectl -n plexd-e2e describe daemonset/plexd
kubectl -n plexd-e2e logs -l app.kubernetes.io/name=plexd --tail=50
```

The DaemonSet uses `hostNetwork: true` with `dnsPolicy: ClusterFirstWithHostNet`. DNS resolution to the mock-api ClusterIP Service requires this policy. The plexd container also has `readOnlyRootFilesystem: true` and drops all capabilities except `NET_ADMIN` and `NET_RAW`. Since kind nodes lack the WireGuard kernel module, the test validates manifest correctness and API communication — not tunnel creation.

**Assertions not met (counters stay at 0):**

```bash
kubectl -n plexd-e2e logs -l app.kubernetes.io/name=plexd --tail=100
kubectl -n plexd-e2e logs -l app.kubernetes.io/name=mock-api --tail=50
```

Common causes:
- DNS resolution failure — verify `dnsPolicy: ClusterFirstWithHostNet` is set on the DaemonSet.
- ConfigMap not mounted — check that the plexd pod has `/etc/plexd/config.yaml` with the correct `api.base_url`.
- Missing bootstrap token — the `PLEXD_BOOTSTRAP_TOKEN` env var must resolve from the `plexd-bootstrap` Secret.

**Port-forward not reachable:**

The script waits 2 seconds after starting the port-forward. If `curl` fails, check that mock-api is healthy:

```bash
kubectl -n plexd-e2e get pods -l app.kubernetes.io/name=mock-api
```

**Cluster not cleaned up:**

The cleanup trap runs on `EXIT`, but if the script is killed with `SIGKILL`, run manually:

```bash
kind delete cluster --name plexd-e2e
```

## Diagnostics Output

On any failure, the `print_diagnostics` function outputs:

| Command | Purpose |
|---------|---------|
| `kubectl get pods -n plexd-e2e -o wide` | Pod status and node assignment |
| `kubectl describe daemonset/plexd -n plexd-e2e` | Scheduling events and conditions |
| `kubectl logs -l app.kubernetes.io/name=plexd --tail=50` | Recent plexd agent logs |
| `kubectl logs -l app.kubernetes.io/name=mock-api --tail=50` | Recent mock-api server logs |

## Key Files

| File | Purpose |
|------|---------|
| `test/e2e/kubernetes/test.sh` | Orchestration script (build, deploy, assert, cleanup) |
| `test/e2e/kubernetes/mock-api-manifests.yaml` | mock-api Deployment + ClusterIP Service |
| `test/e2e/mockapi/Dockerfile` | Mock API image |
| `test/e2e/mockapi/mockapi.go` | Mock API server with `/test/assertions` endpoint |
| `deploy/docker/Dockerfile` | plexd production image |
| `deploy/kubernetes/*.yaml` | Production manifests applied by the test |
| `Makefile` | `test-e2e-k8s` target |

## See also

- [Docker E2E Test](docker-e2e-test.md) — Docker Compose-based E2E test
- [Kubernetes DaemonSet Deployment Reference](../deployment/kubernetes-deployment.md) — Production manifest reference
