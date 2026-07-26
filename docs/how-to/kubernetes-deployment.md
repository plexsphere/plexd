---
title: Kubernetes Deployment Guide
---

# Kubernetes Deployment Guide

Step-by-step guide for deploying plexd as a DaemonSet on Kubernetes clusters.

## Prerequisites

- **Kubernetes cluster** (v1.24+) with `kubectl` access
- **Cluster admin** permissions (for CRD and ClusterRole creation)
- **Network connectivity** from cluster nodes to the Plexsphere control plane API
- **Bootstrap token** from the control plane for node enrollment

## Quick start

Apply all manifests in order:

```sh
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/crds/plexdnodestate-crd.yaml
kubectl apply -f deploy/kubernetes/serviceaccount.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/plexd-config-configmap.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

Create the bootstrap token secret:

```sh
kubectl create secret generic plexd-bootstrap \
  -n plexd-system \
  --from-literal=token=YOUR_BOOTSTRAP_TOKEN
```

## Step-by-step deployment

### 1. Create the namespace and CRD

```sh
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/crds/plexdnodestate-crd.yaml
```

This creates:

- `plexd-system` namespace
- `PlexdNodeState` CRD (`plexdnodestates.plexd.plexsphere.com`)

Verify:

```sh
kubectl get namespace plexd-system
kubectl get crd plexdnodestates.plexd.plexsphere.com
```

### 2. Create the service account and RBAC

```sh
kubectl apply -f deploy/kubernetes/serviceaccount.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
```

This creates:

- `plexd` ServiceAccount in `plexd-system`
- `plexd` ClusterRole with permissions for CRD management, Secrets, and TokenReview
- `plexd` ClusterRoleBinding
- Consumer roles: `plexd-state-reader`, `plexd-state-reporter`, `plexd-secrets-reader`, `plexd-hook-reader`

Verify:

```sh
kubectl get serviceaccount plexd -n plexd-system
kubectl get clusterrole plexd
```

### 3. Create the bootstrap token secret

Option A — from the command line:

```sh
kubectl create secret generic plexd-bootstrap \
  -n plexd-system \
  --from-literal=token=YOUR_BOOTSTRAP_TOKEN
```

Option B — from the template:

1. Copy `deploy/kubernetes/secret.yaml`
2. Replace `BASE64_ENCODED_TOKEN` with the base64-encoded token:

```sh
echo -n "your-token-here" | base64
```

3. Apply:

```sh
kubectl apply -f deploy/kubernetes/secret.yaml
```

### 4. Apply the configuration

```sh
kubectl apply -f deploy/kubernetes/plexd-config-configmap.yaml
```

This step is optional. The DaemonSet mounts the ConfigMap with `optional: true` and passes `/etc/plexd/config.yaml` to `--config`; without the ConfigMap plexd starts on its built-in defaults plus the environment and logs a warning that it found no config file at that path. Skip it and supply the registration inputs through the DaemonSet's `env` instead (see [Providing a config file](#providing-a-config-file) below). The `health` block in this ConfigMap spells out the listener that answers the DaemonSet's probes; it matches the defaults, so it documents the probe target rather than switching it on.

### 5. Deploy the DaemonSet

```sh
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

The DaemonSet runs one plexd pod on every node, including control plane nodes.

Verify rollout:

```sh
kubectl rollout status daemonset/plexd -n plexd-system
```

The shipped manifest pins `ghcr.io/plexsphere/plexd:latest`, which moves with every release. For a
cluster you want to update deliberately, pin a version instead. Each release publishes the same
multi-arch image (`linux/amd64`, `linux/arm64`) under all of these tags:

| Tag              | Example  | Moves                                          |
|------------------|----------|------------------------------------------------|
| `v<version>`     | `v0.2.0` | Never — the release version, spelled as the git tag and the GitHub release name |
| `<version>`      | `0.2.0`  | Never — the same image, without the `v` prefix |
| `<major>.<minor>`| `0.2`    | With each patch release in that minor series   |
| `<major>`        | `0`      | With each release in that major series         |
| `latest`         |          | With each release                              |
| `dev`            |          | With each push to `main` — unreleased, not for production |

`v<version>` and `<version>` resolve to the same manifest digest, so a value recorded from the
release version works as an image reference either way.

## Configuration

### Providing a config file

Create a ConfigMap with the plexd configuration:

```sh
kubectl create configmap plexd-config \
  -n plexd-system \
  --from-file=config.yaml=/path/to/your/config.yaml
```

The DaemonSet mounts this ConfigMap at `/etc/plexd` with `optional: true`, so the ConfigMap itself is optional — a pod that starts without it runs on plexd's built-in defaults plus the environment and logs a warning naming the config file it did not find. A file-less deployment supplies the registration inputs through the DaemonSet's `env` instead: add `PLEXD_API`, `PLEXD_PROJECT_ID`, and `PLEXD_RESOURCE_HANDLE`, since `PLEXD_BOOTSTRAP_TOKEN` is already injected from the `plexd-bootstrap` secret. Action execution is off on that path — without a file there is no `actions` block to honour, so plexd will not run control-plane actions or hooks unless the DaemonSet also sets `PLEXD_ACTIONS_ENABLED=true`. A custom ConfigMap needs no `health` block: the listener is on by default, precisely so that a config written without it still answers the DaemonSet's probes. Setting `health.enabled: false` leaves the probe target unbound and the pods restart in a loop, so remove the probes from the DaemonSet as well if you turn the listener off.

### Environment variables

The DaemonSet sets these environment variables automatically:

| Variable                | Source                 | Description                  |
|-------------------------|------------------------|------------------------------|
| `MY_NODE_NAME`          | Downward API           | Kubernetes node name         |
| `PLEXD_BOOTSTRAP_TOKEN` | `plexd-bootstrap` Secret | Bootstrap token            |

### Resource limits

Default resource requests and limits:

| Resource | Request | Limit  |
|----------|---------|--------|
| CPU      | 50m     | 200m   |
| Memory   | 64Mi    | 128Mi  |

Adjust in the DaemonSet manifest if needed for your workload.

## Verification

### Check pod status

```sh
kubectl get pods -n plexd-system -o wide
```

All pods should be `Running` with one pod per node.

### Check CRD state

```sh
kubectl get plexdnodestates -n plexd-system
```

Or using the short name:

```sh
kubectl get pns -n plexd-system
```

Expected output shows each node's ID, mesh IP, and age.

### View logs

```sh
# All plexd pods
kubectl logs -n plexd-system -l app.kubernetes.io/name=plexd --tail=50

# Specific node
kubectl logs -n plexd-system daemonset/plexd -c plexd --tail=100
```

### Health checks

The DaemonSet configures liveness and readiness probes:

| Probe      | Path       | Host        | Port | Interval |
|------------|------------|-------------|------|----------|
| Liveness   | `/healthz` | `127.0.0.1` | 9101 | 30s      |
| Readiness  | `/readyz`  | `127.0.0.1` | 9101 | 10s      |

Both endpoints are served by the health listener and need no credentials — which is why the listener binds loopback and the probes set `host: 127.0.0.1`. Under `hostNetwork: true` the kubelet probes from the host network namespace, the same namespace plexd listens in, so loopback reaches it while nothing on the node's NICs or on the mesh can.

`/healthz` returns `200` for as long as the process serves requests — it reports liveness, not control-plane reachability. `/readyz` returns `200` once the node holds a registered identity, its WireGuard interface and firewall baseline are up, its event delivery path to the control plane is working, and its long-running subsystems are still running; otherwise it returns `503` with a one-line reason (`not ready: registration pending`, `not ready: data plane not configured`, `not ready: data plane lost`, `not ready: event delivery stopped`, `not ready: event delivery degraded`, or `not ready: subsystem stopped`). A node in `pull_only` delivery counts as ready — it still reconciles on its interval — while `degraded_polling` does not. A restarted pod that finds its persisted identity reports ready without registering again.

Readiness keeps watching after startup: the WireGuard interface is re-checked every 5 seconds in the background, so a pod whose interface is deleted or brought down goes NotReady and recovers on its own once the interface returns, and a subsystem that exits before shutdown turns the pod NotReady for good — the pod log names which one. `/healthz` deliberately stays `200` in both cases, because a restart runs the drain path and deletes the interface and the firewall chain.

Because readiness covers the data plane, a node whose WireGuard interface fails to come up stays NotReady rather than reporting healthy without a tunnel. With `maxUnavailable: 1` that halts a rolling update on the first affected node instead of letting it sweep the fleet.

Check probe status:

```sh
kubectl describe pod -n plexd-system -l app.kubernetes.io/name=plexd | grep -A3 "Liveness\|Readiness"
```

## Updating

### Rolling update

Update the image tag in the DaemonSet:

```sh
kubectl set image daemonset/plexd -n plexd-system plexd=ghcr.io/plexsphere/plexd:v1.2.3
```

The update strategy is `RollingUpdate` with `maxUnavailable: 1`, so one node updates at a time.

Monitor the rollout:

```sh
kubectl rollout status daemonset/plexd -n plexd-system
```

### Rotating the bootstrap token

```sh
kubectl delete secret plexd-bootstrap -n plexd-system
kubectl create secret generic plexd-bootstrap \
  -n plexd-system \
  --from-literal=token=NEW_TOKEN
```

Restart the DaemonSet to pick up the new token:

```sh
kubectl rollout restart daemonset/plexd -n plexd-system
```

## Uninstalling

Remove all plexd resources:

```sh
kubectl delete daemonset plexd -n plexd-system
kubectl delete secret plexd-bootstrap -n plexd-system
kubectl delete configmap plexd-config -n plexd-system 2>/dev/null || true
kubectl delete -f deploy/kubernetes/rbac.yaml
kubectl delete -f deploy/kubernetes/serviceaccount.yaml
kubectl delete -f deploy/kubernetes/crds/plexdnodestate-crd.yaml
kubectl delete -f deploy/kubernetes/namespace.yaml
```

To also remove node data from host paths:

```sh
# Run on each node (or via a cleanup DaemonSet)
rm -rf /var/lib/plexd /var/run/plexd
```

## Troubleshooting

### Pods stuck in Pending

Check for node taints that may prevent scheduling:

```sh
kubectl describe nodes | grep Taints
```

The DaemonSet tolerates all taints by default. If pods are still pending, check resource availability:

```sh
kubectl describe pod -n plexd-system <pod-name> | grep -A5 Events
```

### Pods in CrashLoopBackOff

Check logs for the failing pod:

```sh
kubectl logs -n plexd-system <pod-name> --previous
```

Common causes:

- **Missing bootstrap token**: The `plexd-bootstrap` secret does not exist or the `token` key is missing
- **Control plane unreachable**: The node cannot reach the Plexsphere API. Check network policies and firewall rules
- **Invalid token**: The bootstrap token is expired or malformed

### CRD not updating

Verify the service account has permissions:

```sh
kubectl auth can-i update plexdnodestates --as=system:serviceaccount:plexd-system:plexd
```

Check the plexd logs for CRD sync errors:

```sh
kubectl logs -n plexd-system <pod-name> | grep "crd"
```

### Host networking issues

Since plexd uses `hostNetwork: true`, port conflicts can occur — a bind failure on the health listener aborts startup and the pod crash-loops. Verify that port 9101 (health endpoints) is free on the host, and port 9100 (local node API) as well if you set `node_api.http_enabled`:

```sh
kubectl exec -n plexd-system <pod-name> -- ss -tlnp | grep -E '9100|9101'
```

## See also

- [Kubernetes DaemonSet Deployment Reference](../reference/deployment/kubernetes-deployment.md) — Full reference for all types, interfaces, and manifests
- [Audit Forwarding Reference](../reference/observability/audit-forwarding.md) — Audit data collection
- [Bare-Metal Installation Guide](bare-metal-installation.md) — Bare-metal server installation
- [VM Deployment Guide](vm-deployment.md) — VM deployment
