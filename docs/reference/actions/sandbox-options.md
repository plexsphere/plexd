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
| Definition | Executable file in `hooks_dir`, optional `<name>.json` sidecar | `PlexdHook` custom resource in plexd's namespace, run only when the control plane dispatches it |
| Isolation | None: runs on the host as plexd's user (level `none` only) | A pod of its own, in one Job per execution pinned to plexd's Node. Unless `privileged: true`, a read-only root filesystem and every capability dropped |
| Integrity | SHA-256 file checksum | Image pinned by a `sha256` digest (`@sha256:...`); plexd refuses any other image |
| Cleanup | plexd kills the hook's process group at the run deadline | plexd reads the log and deletes the Job at the run deadline or on a cancel request, and `activeDeadlineSeconds` ends it 30 seconds later as a backstop. A finished Job stays for an hour (`ttlSecondsAfterFinished: 3600`), and deleting the PlexdHook deletes its Jobs through the owner reference |
| Observability | stdout/stderr capture | The `hook` container's exit code and log in the execution callback; the Job and its pod stay an hour for `kubectl` |
| Secrets | Environment variables from plexd | None: the pod mounts no ServiceAccount token and no volume, and plexd adds only the `PLEXD_*` variables. Kubernetes still injects its service variables, such as `KUBERNETES_SERVICE_HOST` |
| Resource Limits | None set by plexd | None set by plexd: the CRD has no field for them |
| Access Control | Hook file and sidecar owned by root, not group- or other-writable | Whoever may write `PlexdHook` resources in plexd's namespace, and under managed push the control plane's `domain#manage` gate. The hook pod holds no credentials for the Kubernetes API |
| Host Access | Whatever plexd's user has | A privileged container with `privileged: true`; plexd sets no `hostPID`, `hostNetwork`, or host volume |

See [PlexdHook CRD](plexdhook-crd.md#running-a-hook) for the Job plexd creates.

## RBAC for CRD Hooks

plexd reads PlexdHook resources through the `plexdhooks` `get, list, watch` grant of its `plexd` ClusterRole. Running one needs the Role `plexd-hook-runner` in plexd's namespace and the RoleBinding of the same name, both in `deploy/kubernetes/rbac.yaml`, shown here without their labels:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: plexd-hook-runner
  namespace: plexd-system
rules:
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "delete"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: plexd-hook-runner
  namespace: plexd-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: plexd-hook-runner
subjects:
  - kind: ServiceAccount
    name: plexd
    namespace: plexd-system
```

The grants are namespaced. plexd creates Jobs only in the namespace where it lists PlexdHooks, and a cluster-wide `pods/log` grant would let one Node's agent read the log of every pod in the cluster. The `plexd` ClusterRole holds no Job grant and no `plexdhooks/status` grant, because plexd writes no PlexdHook status. See [PlexdHook CRD](plexdhook-crd.md#rbac-permissions) for what each grant is used for.
