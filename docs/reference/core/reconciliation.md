---
title: Configuration Reconciliation
package: internal/reconcile
feature: PXD-0003
---

# Configuration Reconciliation

The `internal/reconcile` package implements the core convergence loop that keeps every node aligned with desired state. It periodically fetches the `NodeStateSnapshot` envelope from the control plane, computes a diff against a local snapshot, and invokes pluggable handlers to converge local state toward the envelope.

The pull is one-way: plexd does not report drift corrections back to the control plane, except for the policy block, whose outcome (the ruleset plexd applied, the one it rejected and why, and what its default deny dropped) it sends as its [policy status report](../networking/network-policy.md#policy-status-report). `POST /v1/nodes/{node_id}/drift` no longer exists. Applied-correction visibility for the other blocks will return as node-authored state reports (issue #23).

The envelope carries the node's own mesh address as `mesh_ip`, and fifteen always-present blocks: `peers`, `reachability`, `policy`, `bridge`, `state`, `reports`, `executions`, `sessions`, `secrets`, `signing_key`, `hooks`, `dns`, `failure_detection`, `shared_subnets`, and `state_freshness`. A `null` block means "not populated" rather than "field absent", so the differ compares by presence: a `null` block and a populated block are distinct states, and switching between them drives convergence. `shared_subnets` is the exception: the control plane never sends it `null`, and the differ reads a `null`, an absent key and `[]` alike as no shared subnet.

`executions` and `sessions` are the exceptions: both are consumed by the dispatch stage on every successful pull and neither is stored in the local snapshot nor diffed. `executions` is a delivery queue rather than desired state; `sessions` is desired state, but state the tunnel dispatcher converges on itself rather than through the differ.

`signing_key` is consumed by the dispatch stage too, and is not desired state at all: it is the key the node's Domain signs envelopes and session tokens with, and the signing-key dispatch handler installs it on every successful pull. It is neither stored nor diffed. A `null` block means "keep the key you hold", never "drop it".

`mesh_ip` is consumed by the dispatch stage too, as `signing_key` is: the mesh address dispatch handler applies it on every successful pull, so a step that failed is tried again on the next pull without holding back the snapshot. It is neither stored nor diffed. A control plane that predates the member leaves it out, which decodes to the empty string and keeps the node's address.

`secrets` is consumed by the dispatch stage too. It is the node's secret inventory, names and versions only, and the node API's [`SecretIndexDispatchHandler`](nodeapi.md#secretindexdispatchhandler) replaces the secret index from it on every successful pull. It is neither stored nor diffed. A `null` block keeps the index; an empty block empties it.

`policy` is diffed and stored, but applied on the dispatch seam: the differ still reports a fingerprint change as `policy` drift in the cycle log, and no reconcile handler acts on it. The policy dispatch handler hands the block to the Enforcer on every successful pull, so a block the Enforcer could not apply is applied again on the next pull, and a failed apply never holds the snapshot back.

`state_freshness` is read by the reconciler itself, not by a handler: right after every successful fetch, before the dispatch handlers run, it takes the maximum age the block sets for the desired state (see [State freshness](#state-freshness)). It is neither stored in the snapshot nor diffed. A `null` block, or a key a control plane that predates the member never sends, keeps the limit the reconciler holds.

## Config

`Config` holds reconciliation parameters passed to the `Reconciler` constructor. No file I/O occurs in this package.

| Field      | Type            | Default | Description                        |
|------------|-----------------|---------|------------------------------------|
| `Interval` | `time.Duration` | `60s`   | Time between reconciliation cycles |

```go
cfg := reconcile.Config{
    Interval: 30 * time.Second,
}
cfg.ApplyDefaults() // sets Interval to 60s if zero
if err := cfg.Validate(); err != nil {
    log.Fatal(err) // rejects negative or sub-second intervals
}
```

## StateFetcher

Interface for control plane communication. `*api.ControlPlane` satisfies this interface. It is narrowed to the single pull method; there is no drift-report counterpart.

```go
type StateFetcher interface {
    FetchState(ctx context.Context, nodeID string) (*api.NodeStateSnapshot, error)
}
```

## ReconcileHandler

Function type invoked when drift is detected. Each handler receives the full desired snapshot and the computed diff.

```go
type ReconcileHandler func(ctx context.Context, desired *api.NodeStateSnapshot, diff StateDiff) error
```

Handlers are invoked sequentially in registration order. Errors and panics in one handler do not prevent subsequent handlers from running.

## DispatchHandler

Function type invoked on every successful pull, before the diff. Dispatch handlers consume the snapshot blocks the differ never sees, so an unchanged snapshot still delivers them.

```go
type DispatchHandler func(ctx context.Context, desired *api.NodeStateSnapshot)
```

They return nothing: a dispatch problem is the handler's own to report and never blocks the snapshot update. Panics are recovered and logged, and never count as a handler failure.

Two blocks are consumed on this seam. `executions` is a delivery queue: `actions.Dispatcher.Handle` redelivers each entry until its execution settles through the callback. `sessions` is desired state rather than a queue — an entry stands for as long as its session is valid, and its disappearance is the teardown signal — but `tunnel.Dispatcher.Handle` converges it here rather than behind the diff, because an entry a transient failure left unprovisioned has to be retried on the next pull whether or not the snapshot moved.

The [edge PSK store](../networking/wireguard.md#edge-psks) also runs on this seam, through `wireguard.EdgePSKDispatchHandler`, when the WireGuard interface came up, `wireguard.edge_psk` is not `false` and the node secret key decodes. It reads the `peers` block, which the differ sees as well, and fetches the edge PSK of a peer that first appears, of a peer whose `public_key` changed, and of every peer after this node's own key rotation. It runs here rather than behind the diff so that a failed fetch retries on every pull, drift or not, without failing the WireGuard reconcile handler and holding the snapshot back: the store logs the failure and retries on the next pull. Because dispatch handlers run before the reconcile handlers, a new peer's PSK is fetched before the WireGuard handler adds the peer in the same cycle.

The `failure_detection` block is consumed on this seam too, by `wireguard.FailureDetectionDispatchHandler`, which `cmd/plexd/cmd/up.go` registers only when the WireGuard interface came up, right before the WireGuard reconcile handler. Among the dispatch handlers it runs after `wireguard.EdgePSKDispatchHandler` and before `policy.DispatchHandler`. It decodes the block leniently and hands a positive `detect_after_seconds`, clamped to 5 to 180 s, to `Manager.SetFailureDetection`, which sets how long endpoint selection lets a relayed peer stay silent before it dials the next relay of the peer's set. A `null` block, or a pull without the key, keeps the value the manager holds and logs nothing, and a node that never received a value keeps the built-in timing of the [relay liveness probe](../networking/wireguard.md#relay-liveness-probe). A block that does not decode keeps the value and logs `wireguard: failure detection block malformed` at warn, once until a block decodes again. A `detect_after_seconds` of zero or less changes nothing, and a value outside 5 to 180 logs `wireguard: failure detection time out of range` at warn, once until a block carries another value. A new value logs `wireguard: failure detection time set` at info. It runs here because the block is neither stored nor diffed: it is taken on every successful pull, drift or not, and a pull whose only change is the block reports an empty diff and runs no reconcile handler. See [Failure detection time](../networking/wireguard.md#failure-detection-time).

The `signing_key` block is also consumed on this seam, by `signingKeyDispatchHandler` in `cmd/plexd/cmd/up.go`. It is registered first among the dispatch handlers, so the rest of the cycle already runs under the key the pull carried. A `null` block keeps the installed key and logs `state pull carried no signing key; keeping the installed one` at debug. Any other block goes to `api.Ed25519Verifier.Install` on the verifier that checks envelopes and ssh session tokens. A key `Install` refuses changes nothing and logs `signing key from state pull rejected` at warn (with `key_id` and `error`), once until a pull carries a different key. A new key logs `installed signing key from state pull` at info with `key_id` and `public_key`; that `public_key` is the value an operator sets as `tunnel.session_signing_public_key` for a session helper that pinned the previous key. A pulled key that differs from the pair the identity files hold is written there with `registration.CommitSigningKey`, so a restart seeds the verifier from it. A failed write logs `signing key not persisted; retrying on the next pull` at warn (with `key_id` and `error`) and is retried on every pull.

The `mesh_ip` member is consumed on this seam too, by `meshAddressDispatchHandler` in `cmd/plexd/cmd/mesh_address.go`, which `cmd/plexd/cmd/up.go` registers right after `signingKeyDispatchHandler`, ahead of the session dispatcher, the mesh DNS handler and the WireGuard reconcile handler, so the rest of the cycle already runs on the address the pull carried. An empty `mesh_ip` keeps the address and logs `state pull carried no mesh_ip; keeping the address` at debug. A value that is no usable IP address changes nothing and logs `mesh address from state pull refused` at warn (with `mesh_ip` and `error`), once per value. A new address goes to `wireguard.Manager.Readdress`, which replaces it on the live mesh interface, and then to the followers that hold a copy of it: the mesh resolver's listener, the tcp session listeners, on macOS the site-to-site tunnels and on a Windows bridge the in-process mesh source rewrite. The handler logs `mesh address changed from state pull` at info with `previous_mesh_ip` and `mesh_ip`, and writes the address to `identity.json` with `registration.CommitMeshIP`, so a restart brings the interface up with it. A step that fails logs `mesh address not applied; retrying on the next pull`, or `mesh address not persisted; retrying on the next pull` for the write, and is tried again on the next pull. See [Mesh address changes](../networking/wireguard.md#mesh-address-changes).

The `secrets` block is consumed on this seam too, by the node API's [`SecretIndexDispatchHandler`](nodeapi.md#secretindexdispatchhandler), which `cmd/plexd/cmd/up.go` registers right after `meshAddressDispatchHandler`. It replaces the secret index that `GET /v1/state/secrets` lists from the block on every successful pull, drift or not. A `null` block keeps the index and logs `state pull carried no secret inventory; keeping the secret index` at debug; an empty block empties it. `node_secrets_updated` only triggers a reconcile, so the pull is the one writer of the index.

On a bridge with public ingress the `secrets` block also feeds the ingress manager, through `bridge.IngressSecretInventoryHandler`, which `cmd/plexd/cmd/up.go` registers beside `bridge.IngressReconcileHandler` when the ingress manager exists. It hands the block to `IngressManager.SyncSecretInventory`, which fetches the certificate of a `terminate` rule in the version the block lists, replaces it when the block lists another version, and drops it when the block stops listing the name. A `null` block keeps the inventory the manager holds. It runs here because a pull whose only change is the `secrets` block reports an empty diff and runs no reconcile handler, so a Secret rotation reaches the bridge within one pull. Because dispatch handlers run before the reconcile handlers, a cycle that brings a new rule and its Secret hands the inventory over before `bridge.IngressReconcileHandler` applies the rule. See [Certificates from the Secret Store](../bridge/public-ingress.md#certificates-from-the-secret-store).

On a bridge with user access the `secrets` block also feeds the user access manager, through `bridge.UserAccessPullHandler`, which `cmd/plexd/cmd/up.go` registers after `bridge.IngressSecretInventoryHandler`, beside `bridge.UserAccessReconcileHandler`, when the user access manager exists. It hands the block to `UserAccessManager.SyncSecretInventory`, which replaces the inventory the `tailscale` and `netbird` providers take their join key's version from and then retries the providers that are down; a `null` block keeps the inventory and only retries. It runs here so that a provider that is down is retried on every successful pull, drift or not, and no reconcile cycle fails for one. See [UserAccessPullHandler](../bridge/user-access-integration.md#useraccesspullhandler).

On a bridge with site-to-site tunnels the `secrets` block also feeds the site-to-site manager, through `bridge.SiteToSitePullHandler`, which `cmd/plexd/cmd/up.go` registers after `bridge.UserAccessPullHandler`, beside `bridge.SiteToSiteReconcileHandler`, when the site-to-site manager exists. It hands the block to `SiteToSiteManager.SyncSecretInventory`, which replaces the inventory the tunnels take their Secret's version from, rebuilds a tunnel that is up when the inventory lists its Secret at a new version, and then retries the tunnels that are down; a `null` block keeps the inventory and only retries. It runs here so that a rotated Secret reaches a tunnel within one pull, and a tunnel that is down is retried on every successful pull, drift or not, without failing a reconcile cycle. See [Site-to-Site VPN](../bridge/site-to-site-vpn.md).

The `hooks` block is consumed on this seam as well, by `actions.RolloutInstaller.Handle`, which `cmd/plexd/cmd/up.go` registers after `SecretIndexDispatchHandler` and before the action dispatcher. The handler only copies the block into the installer's pending slot and returns: the installer fetches, verifies and installs on its own goroutine, because a fetch inside the cycle would hold back the `executions` block behind it. A `null` block keeps every rolled-out hook and logs `actions: rollout: pull carried no hooks block; keeping rolled-out hooks` at debug; an empty block removes every one. The block is neither stored nor diffed. See [Rolled-out Hooks](../actions/remote-actions-hooks.md#the-pass).

The `policy` block is consumed on this seam as well, by `policy.DispatchHandler`, which `cmd/plexd/cmd/up.go` registers on every node after every other dispatch handler but `bridge.IngressSecretInventoryHandler`, `bridge.UserAccessPullHandler` and `bridge.SiteToSitePullHandler`. It hands the block to `Enforcer.Sync`, which applies it when it is not the installed ruleset and records the outcome for the policy status report and `GET /v1/policies`. It runs here rather than behind the diff so that a block the Enforcer could not apply is applied again on every pull, drift or not, without failing a reconcile handler and holding the snapshot back. Because dispatch handlers run before the reconcile handlers, a new ruleset is installed before the WireGuard handler changes peers in the same cycle. The block is still diffed and stored, so a new fingerprint shows as `policy` drift in the cycle log. See [DispatchHandler](../networking/network-policy.md#dispatchhandler).

The `dns` block is consumed on this seam as well, by `meshdns.Manager.Handle`, which `cmd/plexd/cmd/up.go` registers after the reachability observer and before the edge PSK handler, and only on Linux, macOS and Windows when the mesh resolver listens. Every pull with a block rebuilds the names the resolver answers and the table it forwards with, and compares the registration it wants with the one the system resolver accepted last, systemd-resolved on Linux, configd on macOS and Dnscache on Windows, so a registration that failed is retried on the next pull, drift or not. A `null` block keeps the names, the forwarding and the registration and logs `state pull carries no dns block, keeping the names held` at info, once until a block arrives again. A block without its `forwarding` member keeps the member the manager holds and builds it anew against the block's records. When the manager holds one, it logs `dns block carries no forwarding member, keeping the forwarding held` at info, once until a member arrives again. The block is neither stored nor diffed. See [Mesh DNS](../networking/mesh-dns.md#following-the-state-pull).

## Reconciler

### Constructor

```go
func NewReconciler(client StateFetcher, cfg Config, logger *slog.Logger) *Reconciler
```

- Applies config defaults via `cfg.ApplyDefaults()`
- Initializes an empty state snapshot
- Creates a buffered trigger channel (size 1) for coalescing

### Methods

| Method             | Signature                                                   | Description                                        |
|--------------------|-------------------------------------------------------------|----------------------------------------------------|
| `RegisterHandler`  | `(handler ReconcileHandler)`                                | Adds a handler invoked on drift (call before `Run`) |
| `RegisterDispatchHandler` | `(handler DispatchHandler)`                          | Adds a handler invoked on every successful pull (call before `Run`) |
| `RegisterWithdrawHandler` | `(handler WithdrawHandler)`                          | Adds a handler invoked when the desired state passes its maximum age, before the reconcile handlers get the withdrawn snapshot (call before `Run`); see [Withdrawal](#withdrawal) |
| `SetCycleObserver` | `(fn DispatchHandler)`                                      | Sets the function invoked once at the end of every cycle whose fetch succeeded, with panic recovery (call before `Run`); see [Reconciliation Cycle](#reconciliation-cycle) |
| `SetMaxAgeSeconds` | `(v int64)`                                                 | Sets the maximum age of the desired state in seconds, counted from the last successful pull; a value below 1 clears it. For the reconcile goroutine, or before `Run`; see [State freshness](#state-freshness) |
| `MaxAgeSeconds`    | `() int64`                                                  | The maximum age as the control plane set it, before the floor and the cap; 0 for none. The state store records this value |
| `MaxAge`           | `() time.Duration`                                          | The maximum age the reconciler applies: at most ten years, at least three `Interval`s; 0 for none |
| `Restore`          | `(ctx context.Context, stored *api.NodeStateSnapshot, age time.Duration) bool` | Applies a stored desired state before the first pull and returns whether a reconcile handler failed (call once, before `Run`, from the goroutine that then calls `Run`); see [Stored state](#stored-state) |
| `TriggerReconcile` | `()`                                                        | Requests immediate cycle; rapid calls are coalesced |
| `Run`              | `(ctx context.Context, nodeID string) error`                | Blocking loop; returns `ctx.Err()` on cancellation |

### Lifecycle

```go
logger := slog.Default()

client, _ := api.NewControlPlane(apiCfg, "1.0.0", logger)
// Register arms the client with the NSK bearer envelope.
identity, _ := registration.NewRegistrar(client, regCfg, logger).Register(ctx)

r := reconcile.NewReconciler(client, reconcile.Config{}, logger)

// Register handlers before Run
r.RegisterHandler(func(ctx context.Context, desired *api.NodeStateSnapshot, diff reconcile.StateDiff) error {
    // apply WireGuard peer changes
    return nil
})
r.RegisterDispatchHandler(func(ctx context.Context, desired *api.NodeStateSnapshot) {
    // apply the network policy block of every successful pull
})
r.RegisterWithdrawHandler(func(ctx context.Context) error {
    // withdraw the policy once the desired state passes its maximum age
    return enforcer.Withdraw("plexd0")
})

// Store every successful pull at the end of its cycle
store := statestore.New(dataDir, identity.NodeID, logger)
r.SetCycleObserver(store.Observer(edgePSKs.Sealed, r.MaxAgeSeconds))

// Run blocks until context cancelled. A stored state is applied first, on
// the goroutine that then runs Run (plexd up checks its node and its age
// before; see Stored state).
ctx, cancel := context.WithCancel(context.Background())
go func() {
    if file, err := store.Load(); err == nil {
        r.SetMaxAgeSeconds(file.MaxAgeSeconds)
        r.Restore(ctx, &api.NodeStateSnapshot{
            Peers:            file.Peers,
            Policy:           file.Policy,
            Bridge:           file.Bridge,
            SharedSubnets:    file.SharedSubnets,
            FailureDetection: file.FailureDetection,
        }, time.Since(file.SavedAt))
    }
    if err := r.Run(ctx, identity.NodeID); err != nil && err != context.Canceled {
        logger.Error("reconciler failed", "error", err)
    }
}()

// Trigger immediate reconciliation (e.g., after SSE reconnection)
r.TriggerReconcile()

// Graceful shutdown
cancel()
```

### Reconciliation Cycle

Each cycle follows this sequence:

![One reconciliation cycle. A tick or a trigger starts FetchState. On an error the cycle logs at warn or debug level, skips the cycle, retries a pending withdrawal and waits for the next tick. On success it invokes the dispatch handlers and then ComputeDiff. If the diff is empty and no reapply is pending, it calls the cycle observer, through which the state store writes the pull, and waits for the next tick. Otherwise it invokes the handlers sequentially; a handler error is logged and the next handler runs. If any handler failed, the cycle calls the cycle observer; if none failed, it updates the snapshot and then calls the cycle observer. After the cycle observer it waits for the next tick.](../../diagrams/core-reconciliation-cycle.svg)

1. **FetchState** — `GET /v1/nodes/{node_id}/state` via `StateFetcher`, returning the `NodeStateSnapshot` envelope. On an error the cycle logs it, retries a pending [withdrawal](#withdrawal) and ends
2. **Take the pull** — the time of the pull becomes the reconciler's last successful pull, which the [maximum age](#state-freshness) counts from. A pending withdrawal is dropped, and a reapply (step 4) takes its place. The pull's `state_freshness` block is taken
3. **Invoke dispatch handlers** — each called with panic recovery, in registration order. This runs on **every** successful pull, before the diff, so an unchanged snapshot still redelivers the queued entries; the empty-diff short-circuit below can never skip it
4. **ComputeDiff** — compare the desired snapshot against the local snapshot. While a reapply is pending, every pulled peer the diff lists neither as an add nor as an update is appended to `PeersToAdd`, so the cycle writes every pulled peer again. A reapply is pending after a [restore](#restore-in-the-reconciler) on which a handler failed, and after a pull that dropped a pending withdrawal
5. **Skip if empty** — with an empty diff and no reapply pending, no reconcile handlers are invoked
6. **Invoke handlers** — each handler called with panic recovery, in registration order
7. **Update snapshot** — only if every handler succeeded, which also ends a reapply; a single handler failure holds the snapshot back so the same diff re-fires next cycle until it converges
8. **Call the cycle observer** — at the end of every cycle whose fetch succeeded: after an empty diff, after a snapshot update, and after a handler failed. A panic is recovered and logged as `cycle observer panicked` at error. `plexd up` sets the [state store](#stored-state)'s observer here, so a pulled state that kills the process while the handlers apply it is never stored

After every cycle `Run` arms a timer for the moment the last successful pull grows older than the maximum age, when a limit applies (see [Withdrawal](#withdrawal)).

### Error Handling

| Error Source       | Behavior                                              |
|--------------------|-------------------------------------------------------|
| `FetchState` error | Logged at warn, or at debug for `api.ErrCredentialRefused` while the heartbeat is parked (see [Quiet Failure Logs](heartbeat-service.md#quiet-failure-logs)); tick skipped, a pending withdrawal retried, loop continues |
| Handler error      | Logged at error, other handlers still run, snapshot held back |
| Handler panic      | Recovered with stack trace, treated as error          |
| Dispatch handler panic | Recovered with stack trace, logged at error; never counts as a handler failure and never holds the snapshot back |
| Cycle observer panic | Recovered with stack trace, logged at error as `cycle observer panicked`; the cycle and `Run` go on |
| Withdraw handler error or panic | Logged at error as `withdraw handler failed`, other withdraw handlers still run, the withdrawal stays pending (see [Withdrawal](#withdrawal)) |
| Context cancelled  | `Run` returns `ctx.Err()` immediately                |

### Logging

All log entries use structured keys with `component=reconcile`:

| Key              | Description                          |
|------------------|--------------------------------------|
| `component`      | Always `"reconcile"`                 |
| `node_id`        | Node identifier                      |
| `interval`       | Configured reconciliation interval   |
| `drift`          | Compact `diff.Summary()`, e.g. `"peers+1-0~2 policy bridge state reports shared_subnets"` (or `"none"`) |
| `duration`       | Cycle execution time                 |
| `handler_failed` | Whether any handler returned error   |
| `handler_index`  | Position of the failed handler in registration order |
| `age`            | Age of the desired state, from the last successful pull or the stored `saved_at` |
| `max_age`        | The maximum age the reconciler applies (`MaxAge`) |
| `max_age_seconds` | The maximum age a pull carried, in seconds |
| `applied`        | The maximum age applied in place of a value below the floor |
| `error`          | Error details (on warn/error levels, and on the debug-level `FetchState failed` for a refused credential) |

## StateDiff

Describes the drift between the desired and current `NodeStateSnapshot`. Peer changes are enumerated; the four block flags of the pointer blocks are presence-aware, so a `null` block and a populated block are distinct. `SharedSubnetsChanged` is not: a nil and an empty `shared_subnets` list both mean no shared subnet.

```go
type StateDiff struct {
    PeersToAdd    []api.SnapshotPeer
    PeersToRemove []string           // node IDs
    PeersToUpdate []api.SnapshotPeer // peers with changed fields

    PolicyChanged  bool
    BridgeChanged  bool
    StateChanged   bool
    ReportsChanged bool

    SharedSubnetsChanged bool
}
```

### ComputeDiff

```go
func ComputeDiff(desired, current *api.NodeStateSnapshot) StateDiff
```

Comparison logic by block:

| Block   | Match Key         | Detection                                                                 |
|---------|-------------------|---------------------------------------------------------------------------|
| Peers   | `SnapshotPeer.NodeID` | Add/remove by node ID; update when `MeshIP`, `PublicKey`, `Endpoint`, `FallbackEndpoint`, `FallbackEndpoints`, `EndpointCandidates`, or `RoutedSubnets` differs. Relays and candidates compare in order, because the order is the dial order, and routed subnets compare in order with `slices.Equal`, so a pull that changes only a peer's `routed_subnets` updates the peer; nil and empty compare equal |
| Policy  | —                 | Presence-aware; when both blocks are populated it compares **only** the `Fingerprint` byte-for-byte |
| Bridge  | —                 | Presence-aware; both populated → `reflect.DeepEqual`                       |
| State   | —                 | Presence-aware; both populated → `reflect.DeepEqual`                       |
| Reports | —                 | Presence-aware; both populated → `reflect.DeepEqual`                       |
| Shared subnets | —          | Not presence-aware: changed when the lists differ in length, in a `Subnet`, or in a `Bridges` list compared in order, because the order is the failover order. A nil and an empty list compare equal, as do a nil and an empty `Bridges`, so a pull that drops the key and one that carries `[]` read the same. A pull whose only change is the block still runs the WireGuard reconcile handler, which takes the block from the desired snapshot (see [Shared subnets](../networking/wireguard.md#shared-subnets)) |

The policy `Fingerprint` is a 44-char base64 SHA-256 that the server computes over its canonical rule stream. plexd treats it as an opaque comparison key and **never re-derives it from the rules**: a revision-only bump (same fingerprint, new `revision_id`) or any rule-array difference that keeps the fingerprint equal is **not** a change. The policy dispatch handler does not read the diff: `Enforcer.Sync` compares the fingerprint with the installed ruleset's the same way, so such a pull does not rebuild the ruleset either. `reachability` is the control plane's verdict about this node, not desired state, so it is never diffed or stored — the reachability observer decodes it on every successful pull and logs the verdict when it changes, and that is the whole of what plexd does with it. `executions` is a delivery queue whose entries are consumed once by the dispatch stage and settled through the execution callback, not converged on, so it too is never diffed or stored — there is no `ExecutionsChanged` flag, and a pull carrying only new executions still reports an empty diff. `signing_key` is not desired state either, so it is never diffed or stored: there is no `SigningKeyChanged` flag, the signing-key dispatch handler installs the key on every successful pull, and a pull whose only change is a new key reports an empty diff. `mesh_ip` is never diffed or stored either: there is no flag for it, the mesh address dispatch handler applies it on every successful pull, and a pull whose only change is the node's own address reports an empty diff. `secrets` is never diffed either, because its dispatch handlers consume it on every successful pull, the node API's secret-index dispatch handler and, on a bridge with public ingress, `bridge.IngressSecretInventoryHandler`: there is no `SecretsChanged` flag, and a pull whose only change is the `secrets` block reports an empty diff.

### Summary

```go
func (d StateDiff) Summary() string
```

Returns a compact description of the diff for the cycle log, e.g. `"peers+1-0~2 policy bridge state reports shared_subnets"`. Only changed parts are mentioned; an empty diff returns `"none"`. It is logged under the `drift` key.

### IsEmpty

```go
func (d StateDiff) IsEmpty() bool
```

Returns `true` when all peer slices are empty and all five flags, the four block flags and `SharedSubnetsChanged`, are `false`.

## StateSnapshot

In-memory cache of the last known desired state, protected by `sync.RWMutex`. The snapshot itself stays in memory. The [state store](#stored-state) keeps the `peers`, `policy`, `bridge`, `shared_subnets` and `failure_detection` blocks of the last successful pull in `<data_dir>/desired-state.json`, and at start `Restore` makes them the snapshot before the first pull, so the first pull diffs against the restored state.

| Method                                         | Description                                     |
|------------------------------------------------|-------------------------------------------------|
| `NewStateSnapshot() *stateSnapshot`            | Creates empty snapshot                          |
| `Get() api.NodeStateSnapshot`                  | Returns a deep copy of the current snapshot     |
| `Update(desired *api.NodeStateSnapshot)`       | Atomically replaces all blocks (deep copy)      |

All methods deep-copy data to prevent aliasing between snapshot and caller. The snapshot stores the blocks `ComputeDiff` compares: `peers`, `policy`, `bridge`, `state`, `reports` and `shared_subnets`, each entry's `bridges` cloned on `Update` and on `Get`, so the next pull compares against what the handlers applied and a caller that changes a copy changes nothing stored. `reachability` is not desired state, so `Get` always returns it as `nil` and `Update` never stores it; the reachability observer has already read and logged the block on the dispatch seam by the time `Update` runs. The same holds for `executions`: the dispatch stage has already consumed the block by the time `Update` runs, and storing it would make a redelivered entry look like drift. `signing_key` is not desired state either: `Get` always returns it as `nil` and `Update` never stores it, because the signing-key dispatch handler has already consumed the block by the time `Update` runs and the differ has nothing to converge on. Nor is `mesh_ip`: `Get` always returns it empty and `Update` never stores it, because the mesh address dispatch handler applies it on the dispatch seam. `secrets` is never stored either: `Get` always returns it as `nil` and `Update` never stores it, because the node API's secret-index dispatch handler has already handed the block to the secret index, and `bridge.IngressSecretInventoryHandler` to the ingress manager, by the time `Update` runs. Nor is `dns`: `Get` always returns it as `nil` and `Update` never stores it, because the mesh resolver's dispatch handler takes the block on the dispatch seam. Nor is `failure_detection`: `Get` always returns it as `nil` and `Update` never stores it, because the WireGuard manager's dispatch handler takes the block on the dispatch seam; the state store keeps it on disk on its own. Nor is `state_freshness`: `Get` always returns it as `nil` and `Update` never stores it, because the reconciler takes the block before the dispatch handlers run.

> Drift reporting has been removed. There is no `BuildDriftReport`, `DriftReport`, or `DriftCorrection`, and `POST /v1/nodes/{node_id}/drift` does not exist upstream. Node-authored state reports (issue #23) will carry applied-correction visibility instead.

## Stored state

`internal/statestore` keeps the desired state of the last successful pull in `<data_dir>/desired-state.json`, and `plexd up` applies it at start, before the reconciler's first pull. A node that restarts while the control plane is unreachable therefore comes back with the peers, the edge PSKs, the policy and the bridge block it last applied, and its first successful pull changes only what differs from them. A node that has never pulled has nothing stored and starts with no peers behind the default deny.

### The file

The file is one JSON document, `statestore.File`, written with [`fsutil.WriteFileAtomic`](../development/fsutil.md) (a temporary file, an fsync, a rename and a sync of the directory) with mode `0600`, beside the identity files:

| Member | Content |
|---|---|
| `version` | `1`. A file of another version is not restored, and the next successful pull overwrites it. An older plexd ignores the file |
| `node_id` | The node the state was pulled for |
| `saved_at` | When the file was written, in UTC. Under a maximum age the file is written on every successful pull, so `saved_at` is then the time of the last one |
| `max_age_seconds` | The maximum age the control plane set, as `MaxAgeSeconds` returns it, before the floor and the cap. Left out when no limit applies |
| `peers`, `policy`, `bridge`, `shared_subnets` | The blocks of the pull as it carried them |
| `secrets` | The pull's secret inventory, names and versions only, never a value. A pull whose block is `null` carries the stored inventory over, as the bridge managers keep the inventory they hold. Left out while no pull carried one |
| `failure_detection` | The pull's `failure_detection` block, raw. A pull whose block is absent or `null` carries the stored block over, as the WireGuard manager keeps the value it holds. Left out while none is held |
| `edge_psks` | One entry per edge PSK the [edge PSK store](../networking/wireguard.md#edge-psks) holds that is not stale, ordered by peer node ID: `peer_node_id`, `public_key`, `epoch`, and `envelope`, the 60-byte envelope as the control plane served it, still sealed under the NSK, in base64. Left out when edge PSKs are off or none is held |

Not stored: `mesh_ip` and `signing_key`, which the identity files hold; `state` and `reports`, which the node API cache persists under `<data_dir>/state/`; `reachability`; `executions`, `sessions` and `hooks`, whose replay would run actions twice or reopen listeners nobody can report (rolled-out hooks keep their own record, `hook_rollouts.json`); every Secret value; and `dns`. A stored catch-all resolver would send the host's DNS through records the control plane could not correct, so after a restart without the control plane the tunnels are up and the mesh names do not resolve until the first pull. A bridge part that needs a Secret value, such as the certificate of a `terminate` ingress rule, the auth key of a vendor provider or the key of a site-to-site tunnel, fetches it from the control plane when the restore applies the bridge block: the stored inventory says which version to fetch. With the control plane reachable the part comes up at the restore, as it would on a pull; without it the part stays down with its reason until a pull brings it up.

The restore marker `<data_dir>/desired-state.restoring`, an empty file of mode `0600`, exists only while a restore runs.

The cost is one atomic write, with an fsync of the file and a sync of the directory, per pull that changed the stored content and per pull under a maximum age. The file is about the size of the pull's `peers`, `policy` and `bridge` blocks, plus roughly 200 bytes per sealed PSK.

`plexd deregister --purge` removes the file with the rest of the data dir. Without `--purge` it stays, and the `node_id` check refuses it under the identity of a node that registers afresh; that node's first successful pull overwrites it.

### Writing the file

`Store.Observer(sealed, maxAgeSeconds)` returns the reconciler's cycle observer, which `plexd up` sets with `SetCycleObserver`, passing `EdgePSKs.Sealed` as `sealed` (nil when edge PSKs are off, which stores no envelope) and `Reconciler.MaxAgeSeconds`. It runs at the end of every cycle whose fetch succeeded, after the handlers, also when a handler failed (see [Reconciliation Cycle](#reconciliation-cycle)), so a pulled state that kills the process while the handlers apply it is never stored. It builds a `File` from the pull and writes it when its content, compared without `saved_at`, differs from what is on disk, and on every pull while a maximum age applies. A pull with no peers and `policy: null` is stored as it is. A failed write never fails the cycle, and the next pull tries again.

| Level | Message | Attributes | When |
|---|---|---|---|
| Warn | `stored state not written` | `error` | A write failed; once per run of failures |
| Info | `stored state written again` | none | The first write that succeeds after a failure |

Both lines carry `component=statestore`.

### The restore at start

`restoreStoredState` (`cmd/plexd/cmd/stored_state.go`) runs on the reconciler's goroutine (step 18 of `plexd up`) before `Run`. It applies the stored state first, so a blackholed control plane does not hold the data plane back for a request timeout. In order:

1. `Store.Load` reads the file. With no file the start goes on as on a node that never pulled. When the restore marker exists, the previous restore did not complete: the process died while it applied the stored state, which may well be the cause, so `Load` removes the file and the marker and nothing is restored. A file of another node, or one that cannot be read or decoded or has an unknown `version`, is not restored and stays until the next successful pull overwrites it.
2. `SetMaxAgeSeconds` takes the stored `max_age_seconds`, also when the state is then not restored, so the limit holds for the run until a pull says otherwise.
3. Under a maximum age, a state older than `MaxAge` is not restored, and neither is one whose `saved_at` lies more than 60 s ahead of the clock, the skew the control plane tolerates on a heartbeat: a clock that cannot measure the age cannot honor the limit. Without a limit the age is not checked.
4. `BeginRestore` writes the restore marker.
5. `EdgePSKs.Restore` opens the stored envelopes under the NSK, when edge PSKs are on (see [Stored envelopes](../networking/wireguard.md#stored-envelopes)).
6. The failure-detection dispatch handler, when the WireGuard interface came up, the policy dispatch handler and, on a bridge, the secret inventory handlers of the ingress, user access and site-to-site managers get the stored blocks, and then `Reconciler.Restore` hands them to the reconcile handlers (see [Restore in the reconciler](#restore-in-the-reconciler)). The bridge managers take the stored inventory before the stored bridge block, as a pull hands them its inventory first. No other dispatch handler runs. Against a control plane that does not answer, each Secret fetch the bridge block needs waits up to `api.request_timeout`; the peers and the policy are in place by then, since their handlers run first.
7. `EndRestore` removes the marker.

A restore is a pull's apply without the pull, so it does on a node what a pull would. Without the WireGuard interface no peer handler is registered, so a restore programs no peers, as a pull would not. The first successful pull diffs against the restored state, and the Enforcer finds the restored ruleset installed, so only what differs is applied.

| Level | Message | Attributes | When |
|---|---|---|---|
| Debug | `no stored state` | none | No file: the node never pulled, or the file was removed |
| Warn | `stored state discarded, the previous restore did not complete` | none | The restore marker exists; the file and the marker are removed |
| Warn | `stored state belongs to another node, not restored` | none | `node_id` names another node |
| Warn | `stored state unusable, not restored` | `error` | The file cannot be read or decoded, or its `version` is unknown; the file stays |
| Warn | `stored state older than the limit, not restored` | `age`, `max_age`, `saved_at` | Under a limit, the age exceeds `MaxAge` |
| Warn | `stored state is newer than the clock, not restored` | `age`, `max_age`, `saved_at` | Under a limit, `saved_at` lies more than 60 s ahead of the clock |
| Warn | `stored state not restored, the restore marker cannot be written` | `error` | `BeginRestore` failed |
| Warn | `stored state restore marker not removed, the next start discards the stored state` | `error` | `EndRestore` failed |
| Info | `stored state restored` | `peers`, `policy_fingerprint`, `edge_psks`, `saved_at`, `age`, `handler_failed` | The restore ran; `edge_psks` counts the PSKs restored |

These lines carry `component=statestore`. The restore also causes lines of other components: `stored state applied` (below), `state freshness limit set` when it takes a stored limit (see [State freshness](#state-freshness)), and `wireguard: edge psk: stored envelope does not open` for an envelope it skips.

### Restore in the reconciler

`Reconciler.Restore(ctx, stored, age)` applies a stored state as a pull's apply without the pull. It counts the state as a pull `age` old for the maximum age (a negative age counts as 0), diffs `stored` against the empty snapshot and, on drift, invokes the reconcile handlers. It runs no dispatch handler: those mean "a pull succeeded", and would log the absent `sessions` and `dns` blocks of a pull that never happened. `stored` becomes the snapshot whether or not a handler failed: the snapshot before a restore is empty, and keeping it would leave a later pull unable to remove a restored peer the control plane has dropped. A failure sets a reapply instead, so the next successful pull invokes the handlers even without drift and writes every peer it lists again (see [Reconciliation Cycle](#reconciliation-cycle)). A nil `stored` does nothing. `Restore` returns whether a handler failed.

| Level | Message | Attributes | When |
|---|---|---|---|
| Info | `stored state applied` | `drift`, `age`, `handler_failed` | `Restore` ran |

The line carries `component=reconcile`.

## State freshness

The control plane can bound how long a node acts on desired state it cannot correct. The state pull's `state_freshness` block sets a maximum age, counted from the node's last successful pull, and plexd honors it in two places: at start, a stored state older than the limit is not restored (see [The restore at start](#the-restore-at-start)), and while plexd runs, a node whose last successful pull is older than the limit withdraws its peers, its policy and its bridge block and waits behind the default deny until a pull succeeds (see [Withdrawal](#withdrawal)). Until a pull carries a limit, none applies. Serving the block is the control plane's half, plexsphere/plexsphere#1177.

```json
"state_freshness": { "max_age_seconds": 86400 }
```

`api.NodeStateSnapshot.StateFreshness` carries the block raw, as `FailureDetection` does, and the reconciler decodes it into `api.NodeStateFreshness` right after every successful fetch, before the dispatch handlers run, so a malformed block never fails the pull. Per pull:

- An absent key or `null` means the control plane did not say: the reconciler keeps the limit it holds, the stored one included, and logs nothing.
- A block without `max_age_seconds`, or with `"max_age_seconds": null`, removes the limit.
- A whole number of 1 or more is the limit in seconds.
- A block `json.Unmarshal` refuses, such as a string or a fraction, keeps the limit held and logs `state freshness block malformed`, once until a block decodes again.
- A number below 1 keeps the limit held and logs `state freshness limit out of range`, once per run of the same value.

The limit the reconciler applies, `MaxAge`, is `max(min(v, 315360000 s), 3 × reconcile.interval)`. A value above ten years reads as ten years, so no limit overflows a `time.Duration`. A value below three reconcile intervals (180 s at the default 60 s) is raised to three intervals, because under that floor a healthy node would withdraw its state between two pulls. `MaxAgeSeconds` keeps the value as the control plane set it, which the state store records.

| Level | Message | Attributes | When |
|---|---|---|---|
| Warn | `state freshness block malformed` | `error` | The block does not decode; once until a block decodes |
| Warn | `state freshness limit out of range` | `max_age_seconds` | `max_age_seconds` is below 1; once per run of the same value |
| Warn | `state freshness limit below three reconcile intervals` | `max_age_seconds`, `applied` | A new limit is raised to the floor |
| Info | `state freshness limit set` | `max_age` | The applied limit changed |
| Info | `state freshness limit removed` | none | A held limit was removed |

These lines carry `component=reconcile`. `SetMaxAgeSeconds` logs the last three, also when the restore at start takes the stored limit.

### Withdrawal

```go
type WithdrawHandler func(ctx context.Context) error
```

Under a limit, `Run` arms a timer after every cycle for the moment the last successful pull, or the restore, grows older than `MaxAge`. No limit, or no pull and no restore yet, arms nothing. When the timer fires, `Run` checks the age again and withdraws the desired state:

1. It logs `desired state passed its maximum age, withdrawing`.
2. It calls the withdraw handlers in registration order. `plexd up` registers one, which calls the Enforcer's [`Withdraw`](../networking/network-policy.md#withdraw) and so leaves the default deny alone in place: the policy lives on the dispatch seam, and no reconcile handler owns it.
3. On drift it hands the reconcile handlers the withdrawn snapshot: no peers, no shared subnets, no policy, the `state` and `reports` blocks as they are (a nil `state` would make the node API clear its cache), and a bridge block without `relay` and `ingress` whose `user_access` and `site_to_site` keep their providers and tunnels with `enabled: false`. The user access and site-to-site managers keep the key file of every provider and tunnel a block lists, whatever `enabled` says, and delete the others, so a bridge block without them would delete every bridge key. A nil bridge block stays nil.
4. When nothing failed it records the withdrawn snapshot, so the next successful pull adds every peer again. It logs `desired state withdrawn`.

`Run` serves the timer between two cycles, so a fetch in flight when the limit passes delays the withdrawal until the fetch returns, at most `api.request_timeout` (30 s by default) later. The timer is not armed again until a fetch succeeds, so a node whose pulls keep failing withdraws once. When a withdraw handler or a reconcile handler failed, the snapshot stays as it was and the withdrawal is pending: every later cycle whose fetch fails calls the same handlers with the same withdrawn snapshot and diff again, until none fails. A fetch that succeeds drops a pending withdrawal and sets a reapply, so that cycle removes what the pull no longer lists and writes every pulled peer again. The next successful pull after a withdrawal adds every peer again and arms the timer anew.

A withdrawal leaves the mesh DNS names, the mediated sessions, the rolled-out hooks, the secret index and the edge PSKs the store holds as they are. It does not write `desired-state.json` either, whose `saved_at` stays the time of the last successful pull, so the limit applies to it at the next start as well.

| Level | Message | Attributes | When |
|---|---|---|---|
| Warn | `desired state passed its maximum age, withdrawing` | `age`, `max_age` | The timer fired and the age passed `MaxAge` |
| Info | `desired state withdrawn` | `handler_failed` | The withdrawal ran; with `handler_failed=true` it is pending |
| Error | `withdraw handler failed` | `handler_index`, `error` | A withdraw handler returned an error or panicked |
| Debug | `withdrawal retried` | `handler_failed` | A cycle whose fetch failed applied a pending withdrawal again |

These lines carry `component=reconcile`. A reconcile handler that fails on the withdrawn snapshot logs `handler failed` at error, as it does in a cycle.

## Integration Points

### SSE Reconnection

When `SSEManager` reconnects after a disconnection, call `TriggerReconcile()` to catch up on missed events:

```go
// In the SSE reconnection callback
reconciler.TriggerReconcile()
```

### Heartbeat Reconcile Flag

When a heartbeat response contains `reconcile: true`, trigger an immediate cycle:

```go
resp, err := client.Heartbeat(ctx, nodeID, req)
if err == nil && resp.Reconcile {
    reconciler.TriggerReconcile()
}
```

### Registered Handlers

The agent registers these handlers (in `cmd/plexd/cmd/up.go`):

| Handler                          | Responsibility                                                        |
|----------------------------------|----------------------------------------------------------------------|
| `nodeapi` cache handler          | Feed the local state cache from the snapshot `state` block           |
| `wireguard.ReconcileHandler`     | Apply peer add/remove/update from the `peers` block, with each peer's [dial order](../networking/wireguard.md#dial-order) (on-link `endpoint_candidates`, the usable direct `endpoint`, off-link candidates, then the relays from `fallback_endpoints`, or from `fallback_endpoint` on a control plane that predates the set) and the edge PSK held for its current public key, and route the [routed subnets](../networking/wireguard.md#routed-subnets) the node accepts of each peer's `routed_subnets` through the mesh interface, removing the routes no peer lists any more. It takes the `shared_subnets` block and keeps each [shared subnet](../networking/wireguard.md#shared-subnets) on the allowed IPs of one bridge (registered only when the WireGuard interface came up) |
| bridge sub-handlers              | Reconcile relay, user-access, ingress, and site-to-site subtrees      |

Signing-key rotation is no longer a reconcile handler. Key material comes from registration, from the pull's `signing_key` block through the signing-key dispatch handler below, and from the `signing_key_rotated` SSE event.

### Registered Dispatch Handlers

| Handler                    | Responsibility                                                     |
|----------------------------|--------------------------------------------------------------------|
| `signingKeyDispatchHandler` | Install the pull's `signing_key` into the verifier that checks envelopes and ssh session tokens, and persist it into the identity files (registered first among the dispatch handlers; see [DispatchHandler](#dispatchhandler)) |
| `meshAddressDispatchHandler` | Apply the pull's `mesh_ip` to the mesh interface through `wireguard.Manager.Readdress`, hand it to the followers that hold a copy of the address, and persist it into `identity.json` with `registration.CommitMeshIP`; an empty `mesh_ip` keeps the address, and a step that failed is tried again on the next pull (registered right after `signingKeyDispatchHandler`, ahead of the session dispatcher, the mesh DNS handler and the WireGuard reconcile handler; see [Mesh address changes](../networking/wireguard.md#mesh-address-changes)) |
| `nodeAPISrv.SecretIndexDispatchHandler()` | Replace the node API's secret index from the pull's `secrets` block (registered right after `meshAddressDispatchHandler`; `node_secrets_updated` only pulls the block forward; see [SecretIndexDispatchHandler](nodeapi.md#secretindexdispatchhandler)) |
| `actions.RolloutInstaller.Handle` | Hand the pull's `hooks` block to the rollout installer, which fetches, verifies, installs and removes rolled-out hooks on its own goroutine, so the handler returns at once. A `null` block keeps every rolled-out hook and runs no pass (registered after `SecretIndexDispatchHandler` and before `actions.Dispatcher.Handle`, and only when the installer was built; see [Rolled-out Hooks](../actions/remote-actions-hooks.md#rolled-out-hooks)) |
| `actions.Dispatcher.Handle`| Turn each entry of the `executions` block into an action execution |
| `meshdns.Manager.Handle` | Build the names and the records the mesh resolver answers, and the table it forwards with, from the pull's `dns` block and keep the registration with the system resolver, systemd-resolved on Linux, configd on macOS and Dnscache on Windows, in step with them; a `null` block keeps the names, the records, the forwarding and the registration, a block without its `forwarding` member keeps the forwarding, and a registration that failed is retried on the next pull (registered after the reachability observer and before `wireguard.EdgePSKDispatchHandler`, and only on Linux, macOS and Windows when the resolver listens; see [Following the State Pull](../networking/mesh-dns.md#following-the-state-pull)) |
| `wireguard.EdgePSKDispatchHandler` | Fetch, open and install the edge PSKs the `peers` block makes due (registered only when the WireGuard interface came up, `wireguard.edge_psk` is not `false` and the node secret key decodes) |
| `wireguard.FailureDetectionDispatchHandler` | Hand the pull's `failure_detection` time to `Manager.SetFailureDetection`, which sets how long endpoint selection lets a relayed peer stay silent before it dials the next relay of its set; a `null` block or a missing key keeps the value held, a block that does not decode or a value of zero or less changes nothing, and a positive value outside 5 to 180 s is clamped to the nearer bound (registered only when the WireGuard interface came up, right before `wireguard.ReconcileHandler`, so after `wireguard.EdgePSKDispatchHandler` and before `policy.DispatchHandler`; see [Failure detection time](../networking/wireguard.md#failure-detection-time)) |
| `policy.DispatchHandler` | Hand the pull's `policy` block to `Enforcer.Sync`, which applies it when it is not the installed ruleset, applies a block it could not apply again on the next pull, and records the outcome for the policy status report and `GET /v1/policies` (registered on every node, after every other dispatch handler but `bridge.IngressSecretInventoryHandler`, `bridge.UserAccessPullHandler` and `bridge.SiteToSitePullHandler`; see [DispatchHandler](../networking/network-policy.md#dispatchhandler)) |
| `bridge.IngressSecretInventoryHandler` | Hand the pull's `secrets` block to `IngressManager.SyncSecretInventory`, which loads, replaces or drops the certificates of the `terminate` ingress rules; a `null` block keeps the inventory the manager holds (registered beside `bridge.IngressReconcileHandler`, after `policy.DispatchHandler`, and only when the ingress manager exists; see [IngressSecretInventoryHandler](../bridge/public-ingress.md#ingresssecretinventoryhandler)) |
| `bridge.UserAccessPullHandler` | Hand the pull's `secrets` block to `UserAccessManager.SyncSecretInventory`, which replaces the inventory the vendor user access providers read and retries the providers that are down; a `null` block keeps the inventory and only retries (registered beside `bridge.UserAccessReconcileHandler`, after `bridge.IngressSecretInventoryHandler`, and only when the user access manager exists; see [UserAccessPullHandler](../bridge/user-access-integration.md#useraccesspullhandler)) |
| `bridge.SiteToSitePullHandler` | Hand the pull's `secrets` block to `SiteToSiteManager.SyncSecretInventory`, which replaces the inventory the tunnels take their Secret's version from, rebuilds a tunnel that is up when the inventory lists its Secret at a new version, and retries the tunnels that are down; a `null` block keeps the inventory and only retries, and a nil snapshot changes nothing (registered beside `bridge.SiteToSiteReconcileHandler`, after `bridge.UserAccessPullHandler`, and only when the site-to-site manager exists; see [Site-to-Site VPN](../bridge/site-to-site-vpn.md)) |

See [Remote Actions and Hooks](/reference/actions/remote-actions-hooks) for the dispatcher's decision table.

### Withdraw Handler and Cycle Observer

`plexd up` registers one withdraw handler, right after `policy.DispatchHandler`: it calls `Enforcer.Withdraw` on the policy interface (see [Withdrawal](#withdrawal)). It then sets the state store's `Observer` as the cycle observer, with `EdgePSKs.Sealed` when edge PSKs are on and `Reconciler.MaxAgeSeconds` (see [Writing the file](#writing-the-file)). Step 18 calls `restoreStoredState` before `Run` (see [The restore at start](#the-restore-at-start)).
