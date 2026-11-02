---
title: Sandbox Options
---

# Sandbox Options

plexd runs a script hook at one sandbox level, `none`: it starts the hook directly on the host as plexd's own user. A hook names its level in the `sandbox` key of its [sidecar](remote-actions-hooks.md#sidecar-metadata-format), and plexd refuses to run a hook that names any other level rather than run it without the isolation it asks for.

## Sandbox Levels

| `sandbox` in the sidecar | What plexd does |
|---|---|
| `"none"`, `""`, no `sandbox` key, or no sidecar | Starts the hook directly on the host as plexd's user |
| `"namespaced"`, `"container"`, or any other value | Refuses the run |

A refused run still walks the claim, so the control plane sees `ack`, `started`, and then a `failed` terminal with exit code 1 and this `error`:

```text
hook refused: sandbox level "<value>" is not implemented; plexd runs hooks at level none only
```

`<value>` is the sidecar's value cut to its first 64 characters and printed as a quoted Go string, so a NUL in it prints escaped. The hook does not start, and plexd logs `hook refused` at warn. The hook stays listed in the capability manifest, whose `sandbox_level` reports the level the sidecar declares when it fits the manifest's limit of 64 characters with no NUL (see [Sidecar Metadata Format](remote-actions-hooks.md#sidecar-metadata-format)), so an operator sees what the hook asked for. Setting `"sandbox": "none"` or dropping the key lets the next dispatch run it, with no agent restart.

## Level `none`

```json
{
  "sandbox": "none"
}
```

The hook process runs directly on the host as the user plexd runs as, with what plexd has: its capabilities, its view of the filesystem, and its network. plexd adds no namespace, no container, and no CPU or memory limit. A run ends at its [run deadline](remote-actions-hooks.md#run-deadline), when plexd kills the hook's whole [process group](remote-actions-hooks.md#process-group).

Under plexd's systemd unit that user is root, held to the unit's limits:

| Unit setting | What it means for a hook |
|---|---|
| `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW` and `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW` | Root keeps these two capabilities and no other |
| `ProtectSystem=full` | `/usr`, the boot loader directories, and `/etc` are read-only, apart from the paths the unit lists in `ReadWritePaths` |
| `ProtectHome=true` | `/home`, `/root`, and `/run/user` are empty and cannot be reached |

Whatever user plexd runs as, the hook file and its sidecar must be owned by root and not group- or other-writable, or plexd refuses the run; see [Hook File Checks](remote-actions-hooks.md#hook-file-checks).

## Comparison: Script Hooks vs. CRD Hooks

| | Script Hooks (bare-metal/VM) | CRD Hooks (Kubernetes) |
|---|---|---|
| Definition | Executable file in `hooks_dir`, optional `<name>.json` sidecar | `PlexdHook` custom resource |
| Isolation | None: runs on the host as plexd's user (level `none` only) | Always a separate Pod |
| Integrity | SHA-256 file checksum | Image digest (`@sha256:...`) |
| Cleanup | plexd kills the hook's process group at the run deadline | Kubernetes GC via ownerReference + TTL |
| Observability | stdout/stderr capture | Native Pod logs + Events |
| Secrets | Environment variables from plexd | Native Kubernetes Secrets/ConfigMaps |
| Resource Limits | None set by plexd | Native Kubernetes `resources` |
| Access Control | Hook file and sidecar owned by root, not group- or other-writable | Kubernetes RBAC + ServiceAccount |
| Host Access | Whatever plexd's user has | `privileged: true` + securityContext |

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
