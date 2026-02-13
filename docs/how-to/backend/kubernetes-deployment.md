---
title: Kubernetes Deployment Guide
quadrant: backend
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
- Consumer roles: `plexd-state-reader`, `plexd-state-reporter`, `plexd-secrets-reader`

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

### 4. Deploy the DaemonSet

```sh
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

The DaemonSet runs one plexd pod on every node, including control plane nodes.

Verify rollout:

```sh
kubectl rollout status daemonset/plexd -n plexd-system
```

## Configuration

### Providing a config file

Create a ConfigMap with the plexd configuration:

```sh
kubectl create configmap plexd-config \
  -n plexd-system \
  --from-file=config.yaml=/path/to/your/config.yaml
```

The DaemonSet mounts this ConfigMap at `/etc/plexd`. The ConfigMap is optional — if absent, plexd uses defaults.

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

Expected output shows each node's ID, mesh IP, status, and peer count.

### View logs

```sh
# All plexd pods
kubectl logs -n plexd-system -l app.kubernetes.io/name=plexd --tail=50

# Specific node
kubectl logs -n plexd-system daemonset/plexd -c plexd --tail=100
```

### Health checks

The DaemonSet configures liveness and readiness probes:

| Probe      | Path       | Port | Interval |
|------------|------------|------|----------|
| Liveness   | `/healthz` | 9100 | 30s      |
| Readiness  | `/readyz`  | 9100 | 10s      |

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

Since plexd uses `hostNetwork: true`, port conflicts can occur. Verify port 9100 (HTTP API) is not in use on the host:

```sh
kubectl exec -n plexd-system <pod-name> -- ss -tlnp | grep 9100
```

## See also

- [Kubernetes DaemonSet Deployment Reference](../../reference/backend/kubernetes-deployment.md) — Full reference for all types, interfaces, and manifests
- [Audit Forwarding Reference](../../reference/backend/audit-forwarding.md) — Audit data collection
- [Bare-Metal Installation Guide](bare-metal-installation.md) — Bare-metal server installation
- [Cloud VM Deployment Guide](cloud-vm-deployment.md) — Cloud VM deployment
