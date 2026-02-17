---
title: Sandbox Options
---

# Sandbox Options

Hooks can run in one of three sandbox levels, configured per hook:

## Sandbox Levels

| Level | Isolation | Description |
|---|---|---|
| `none` | Minimal | cgroup resource limits, runs as configured `user` |
| `namespaced` | Medium | PID and mount namespaces, read-only root filesystem, writable paths via whitelist |
| `container` | High | Ephemeral OCI container (requires container runtime on the node) |

## No Sandbox (`none`)

```yaml
sandbox: none
sandbox_options:
  cpu: "1.0"             # CPU limit (cgroup v2 cpu.max)
  memory: 512M           # Memory limit (cgroup v2 memory.max)
```

The hook process runs directly on the host as the configured `user`. Only cgroup-based resource limits (CPU, memory) are applied. The process has full access to the filesystem and network. Use this level only for trusted hooks that require broad system access.

## Namespace Sandbox (`namespaced`)

```yaml
sandbox: namespaced
sandbox_options:
  writable_paths:
    - /tmp
    - /var/backups
  mount_proc: true
  allowed_devices: []
```

The hook runs in isolated PID and mount namespaces. The root filesystem is mounted read-only; only explicitly listed `writable_paths` are bind-mounted as writable. `/proc` is optionally mounted (for process inspection). Network access is inherited from the host. cgroup limits are applied on top.

## Container Sandbox (`container`)

```yaml
sandbox: container
sandbox_options:
  image: ""              # OCI image (optional, uses host rootfs if empty)
  writable_paths:
    - /tmp
  network: none          # none | host (default: none)
  capabilities: []       # Additional Linux capabilities (e.g. NET_RAW)
```

The hook runs as an ephemeral OCI container using the container runtime available on the node (containerd, podman). If `image` is empty, the host root filesystem is used as the container's rootfs (read-only). Network isolation defaults to `none` (no network access). This provides the strongest isolation for untrusted or third-party hooks.

## Comparison: Script Hooks vs. CRD Hooks

| | Script Hooks (bare-metal/VM) | CRD Hooks (Kubernetes) |
|---|---|---|
| Definition | `config.yaml` + file in `hooks.d/` | `PlexdHook` custom resource |
| Isolation | Sandbox level (`none`/`namespaced`/`container`) | Always a separate Pod |
| Integrity | SHA-256 file checksum | Image digest (`@sha256:...`) |
| Cleanup | plexd kills process on timeout | Kubernetes GC via ownerReference + TTL |
| Observability | stdout/stderr capture | Native Pod logs + Events |
| Secrets | Environment variables from plexd | Native Kubernetes Secrets/ConfigMaps |
| Resource Limits | cgroup configuration | Native Kubernetes `resources` |
| Access Control | Unix user + file permissions | Kubernetes RBAC + ServiceAccount |
| Host Access | Sandbox options | `privileged: true` + securityContext |

## RBAC for CRD Hooks

The plexd DaemonSet ServiceAccount needs additional permissions for CRD-based hooks:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: plexd-hooks
rules:
  - apiGroups: ["plexd.plexsphere.com"]
    resources: ["plexdhooks"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list", "watch", "delete"]
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]
```
