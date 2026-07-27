---
title: Secure Access Tunneling
package: internal/tunnel
feature: PXD-0009
---

# Secure Access Tunneling

The `internal/tunnel` package provides platform-mediated access to mesh nodes through WireGuard tunnels without exposing services to the public internet. The control plane declares a node's live sessions in the `sessions` block of the reconciliation state pull; the node agent holds its listeners level with that block, opening a local TCP listener bound to the mesh IP for each entry it can provision, forwarding connections to the target host, and reporting activity back to the control plane.

The block is **desired state, not a delivery queue**: an entry stands for as long as its session is valid, and its disappearance is the teardown signal. Revocation and hard expiry both reach the node as that same absence — there is no revocation event to answer and no terminal status to report.

## Data Flow

```
Control Plane
      │
      │ GET /v1/nodes/{id}/state  →  sessions block
      ▼
┌─────────────────┐   ┌───────────────────┐
│    Reconciler   │──▶│ tunnel.Dispatcher │
│(internal/recon- │   │      Handle       │
│      cile)      │   └─────────┬─────────┘
└─────────────────┘             │
                                ▼
                        ┌───────────────┐
                        │ SessionManager │
                        │  CreateSession │
                        └───────┬───────┘
                                │
                        ┌───────┴───────┐
                        │    Session     │
                        │               │
                        │ ┌───────────┐ │
                        │ │  Listener  │ │  ← bound to meshIP:0
                        │ │ (TCP)     │ │
                        │ └─────┬─────┘ │
                        │       │       │
                        │ ┌─────┴─────┐ │
                        │ │ Forwarder  │ │  ← bidirectional io.Copy
                        │ └─────┬─────┘ │
                        └───────┼───────┘
                                │
                                ▼
                         Target Host
                         (e.g. sshd)
```

### Reconciliation Sequence

1. The reconciler pulls `GET /v1/nodes/{node_id}/state` on its cadence, or immediately when an SSE event — `session_setup` among them — triggers a cycle
2. `Dispatcher.Handle` runs on every successful pull, **before** the empty-diff short-circuit, so an unchanged snapshot still reconciles sessions
3. Teardown pass: every live session whose entry is no longer in the block is closed, with the reason derived from its capped local expiry
4. Provision pass, in block order: each entry not yet settled is validated and, if it is a `tcp` entry, handed to `SessionManager.CreateSession`, which opens a TCP listener on `meshIP:0`
5. Report pass: once the block is provisioned, `SessionActivityReporter.ReportSessionStarted` posts a `tcp` `session_started` row per listener whose row is still outstanding — with the target host and port and the `listener_endpoint` the listener actually bound. A row that does not land is re-posted on the next pull from the same listener, so `listener_endpoint` stays stable across attempts. The posts run concurrently and each is bounded, so a stalled control plane cannot hold the reconciler's single goroutine for the length of the block
6. A client connects through the mesh to that listener; `Session` forwards to the target
7. A session ends when its entry drains from the block, when its capped expiry fires, when its idle window elapses, or on `Shutdown`
8. The `SessionManager`'s on-closed callback fires `SessionActivityReporter.ReportSessionEnded`, posting a `tcp` `session_ended` row with byte counters and a `terminated_by` reason — for every close reason, `Shutdown` included

## Config

`Config` holds secure access tunneling parameters passed to the `SessionManager` constructor.

| Field            | Type            | Default | Description                                    |
|------------------|-----------------|---------|------------------------------------------------|
| `Enabled`        | `bool`          | `true`  | Whether tunneling is active                    |
| `MaxSessions`    | `int`           | `10`    | Maximum concurrent tunnel sessions             |
| `DefaultTimeout` | `time.Duration` | `30m`   | Default/maximum session timeout                |
| `SSHListenAddr`  | `string`        | —       | SSH mesh server listen address (empty = no SSH server) |
| `HostKeyDir`     | `string`        | —       | Directory for SSH host key (empty = transient key)     |

```go
cfg := tunnel.Config{
    MaxSessions: 5,
}
cfg.ApplyDefaults() // Enabled=true, DefaultTimeout=30m, MaxSessions stays 5
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

### Default Heuristic

`ApplyDefaults` uses zero-value detection: on a fully zero-valued `Config`, `MaxSessions == 0` triggers all defaults including `Enabled = true`. If `MaxSessions` is already set (indicating explicit construction), `Enabled` is left as-is. This allows `Config{Enabled: false}` to disable tunneling after `ApplyDefaults`.

### Validation Rules

| Field            | Rule                      | Error Message                                                 |
|------------------|---------------------------|---------------------------------------------------------------|
| `MaxSessions`    | Must be > 0 when enabled  | `tunnel: config: MaxSessions must be positive when enabled`   |
| `DefaultTimeout` | Must be >= 1m when enabled| `tunnel: config: DefaultTimeout must be at least 1m when enabled` |

Validation is skipped entirely when `Enabled` is `false`.

## Session

Represents an active tunnel session with a local TCP listener that forwards connections to a target host through the mesh.

### Fields

| Field        | Type              | Description                              |
|--------------|-------------------|------------------------------------------|
| `SessionID`  | `string`          | Unique session identifier                |
| `TargetHost` | `string`          | Target host to forward connections to    |
| `TargetPort` | `int`             | Target port                              |
| `MeshIP`     | `string`          | Mesh IP to bind the listener to          |

### Constructor

```go
func NewSession(sessionID, targetHost string, targetPort int, meshIP string, expiresAt time.Time, logger *slog.Logger) *Session
```

### Methods

| Method       | Signature                                  | Description                                              |
|--------------|--------------------------------------------|----------------------------------------------------------|
| `Start`      | `(ctx context.Context) (string, error)`    | Opens TCP listener on meshIP:0, starts accept loop and, when an idle window is armed, the idle monitor |
| `Close`      | `() error`                                 | Idempotent shutdown: cancels context, closes listener and connection, then waits (bounded) for the forwarding goroutines so the byte counters are complete |
| `IdleFor`    | `() time.Duration`                         | How long the session has gone without observed byte flow, measured monotonically |
| `ListenAddr` | `() string`                                | Returns listener address or empty string if not started  |

### Connection Lifecycle

1. `Start` binds a TCP listener to `meshIP:0` (ephemeral port, mesh-only interface) and derives the child context every goroutine it starts runs on, so `Close` cancels all of them
2. `acceptLoop` runs in a goroutine, accepting one connection at a time
3. Single-connection enforcement: if a connection is already active, new connections are rejected
4. `forward` dials the target, sets the active connection under mutex, and runs bidirectional `io.Copy` with `sync.Once` cleanup and `sync.WaitGroup` for completion
5. `Close` is idempotent via `sync.Mutex` + `closed` flag; cancels context, closes listener and active connection

### Security

- Listener binds to mesh IP only, never `0.0.0.0` or `localhost`. `SessionManager.CreateSession` parses the mesh IP and refuses to provision a session at all unless it is a bindable unicast address, because `net.Listen` on an empty or unspecified host binds every unicast address the host has. The check runs on the address `net.Listen` would actually bind — zone stripped and IPv4-mapped form unwrapped — so `::ffff:0.0.0.0` and `::%eth0` are refused as the wildcards they bind to, not accepted as the distinct addresses they parse to
- At most one active forwarded connection per session
- Context cancellation propagates to listener and active connection
- The forward itself is **not** authenticated: whichever client reaches the listener first takes the single connection slot. Reachability to the node's mesh IP is the only control (see [WireGuard Mesh](#wireguard-mesh-internal-wireguard))

## SessionManager

Central coordinator for tunnel session lifecycle.

### Constructor

```go
func NewSessionManager(cfg Config, meshIP string, logger *slog.Logger) *SessionManager
```

- Applies config defaults via `cfg.ApplyDefaults()`
- Logger is tagged with `component=tunnel`

### Methods

| Method           | Signature                                                          | Description                                              |
|------------------|--------------------------------------------------------------------|----------------------------------------------------------|
| `CreateSession`  | `(ctx context.Context, sess api.NodeStateSession) (string, error)` | Validates one entry of the `sessions` block, creates and starts its session, and returns the bound listener address |
| `CloseSession`   | `(sessionID string, reason string) *ClosedSessionInfo`             | Closes and removes a session by ID; returns session info |
| `Shutdown`       | `()`                                                               | Closes all active sessions, reporting each through the on-closed callback |
| `ActiveSessions` | `() map[string]time.Time`                                          | Snapshot of live session IDs and their **capped** local expiry; the dispatcher's teardown input |
| `ActiveCount`    | `() int`                                                           | Returns number of active sessions                        |

### CreateSession Validation

Only `tcp` entries are provisionable. The dispatcher filters the block before
calling in; the kind guard repeats the check so the manager is safe to call on its
own.

| Check                  | Condition                                   | Error                                              |
|------------------------|---------------------------------------------|-----------------------------------------------------|
| Tunneling disabled     | `cfg.Enabled == false`                      | `ErrTunnelingDisabled` (`tunnel: tunneling is disabled`) |
| Not provisionable      | `Kind != "tcp"`, or `Target.TCP == nil`     | `tunnel: session kind is not provisionable`         |
| Missing fields         | Empty ID, empty host, or port outside 1-65535 | `tunnel: invalid session setup: ...`              |
| Already expired        | `ExpiresAt` in the past                     | `tunnel: session already expired`                   |
| Duplicate ID           | Session ID already exists                   | `tunnel: duplicate session ID: {id}`                |
| Capacity               | `len(sessions) >= MaxSessions`              | `tunnel: max sessions reached ({n})`                |
| Invalid idle window    | `IdleTimeoutSeconds` negative or above 86400 | `tunnel: invalid idle_timeout_seconds: {n}`        |
| Unbindable mesh IP     | `meshIP` empty, not an IP address, multicast, or unspecified once the zone is stripped and the IPv4-mapped form unwrapped (`0.0.0.0`, `::`, `::ffff:0.0.0.0`, `::%eth0`) | `tunnel: mesh IP {ip} is not a bindable unicast address; refusing to bind a session listener` |

`ErrTunnelingDisabled` is a sentinel: the dispatcher matches it with `errors.Is`
to settle an entry permanently instead of retrying it on every pull.

### Expiry

- `ExpiresAt` is capped at `DefaultTimeout` from now (never exceeds maximum)
- `time.AfterFunc` schedules automatic `CloseSession(id, "expired")` at the capped expiry time. The timer closes over the session, not just its ID, so a timer armed for an earlier session cannot close the one that later took its ID
- A cap that truncates the granted `expires_at` is logged at warn: the control plane does not learn the node's local maximum from the pull, so a session granted more time than `DefaultTimeout` ends early — with a `ttl_expired` `session_ended` row — while its entry still stands in the block, and it is not provisioned a second time

### Idle Enforcement

An entry with `idle_timeout_seconds > 0` arms an idle monitor; `0` or an absent
value means the session has no idle window.

- `idle_timeout_seconds` is validated on the way in: a negative value, or one large enough to overflow the seconds-to-`Duration` multiplication, is rejected rather than silently read as "no idle window"
- Byte flow re-arms the window: every forwarded chunk stamps the session's last activity, so the monitor either closes the session or waits out the remaining window
- Activity is stamped as a monotonic offset, not a wall-clock time: an NTP step or a VM snapshot resume cannot stretch or collapse the window
- The listener bind counts as the first activity, so a listener no connection ever reaches idles out one window after `Start`
- The close runs through `CloseSession(id, "idle")` like any other, so the `session_ended` row still carries the byte counters and, via the reason, a `terminated_by` of `idle_timeout`
- The monitor is started by `Session.Start` on its own child context and exits when that context is cancelled, which every close reaches

### Lifecycle

```go
logger := slog.Default()

mgr := tunnel.NewSessionManager(tunnel.Config{}, "10.0.0.1", logger)

// Create a session from one entry of the pull's sessions block
addr, err := mgr.CreateSession(ctx, api.NodeStateSession{
    SessionID: "sess-abc",
    JTI:       "sess-abc",
    Kind:      api.SessionKindTCP,
    Target: api.SessionTarget{
        TCP: &api.SessionTargetTCP{Host: "127.0.0.1", Port: 22},
    },
    ExpiresAt:          time.Now().Add(10 * time.Minute),
    IdleTimeoutSeconds: 900,
})

// Close specific session
mgr.CloseSession("sess-abc", "drained")

// Graceful shutdown (closes all sessions)
mgr.Shutdown()
```

## Dispatcher

`Dispatcher` consumes the `sessions` block of the reconciliation pull and holds the
node's listeners level with it. `Handle` matches `reconcile.DispatchHandler`, so it
runs on every successful pull, before the diff.

```go
func NewDispatcher(manager *SessionManager, reporter SessionActivityReporter, logger *slog.Logger) *Dispatcher
func (d *Dispatcher) Handle(ctx context.Context, desired *api.NodeStateSnapshot)
```

A `Dispatcher` is **not** safe for concurrent use: `Handle` is invoked only from the
reconcile goroutine, one cycle at a time.

### Unpopulated Block

`Handle` returns immediately, touching nothing, when the snapshot's `sessions`
block is absent or `null` — `api.NodeStateSnapshot.Sessions` is a `*[]` so that
"the control plane says this node has no sessions" (`[]`) stays distinguishable
from "the control plane did not populate the block". Emptiness is destructive
here: reading a rolled-back control plane, a fleet instance predating the block,
or one degraded response as an empty block would kill every live operator forward
on every node that pulls from it. The refusal is logged once per such pull.

### Teardown Pass

The ID set of the whole block is collected first — absence from the block is what
drives teardown, so the set has to be complete before the first close. Every live
session whose ID is not in that set is closed — concurrently, because each close
blocks on the session drain and on a bounded activity post, and this pass runs
inline on the reconciler's single goroutine ahead of the diff and every reconcile
handler. The reason is derived from the session's **capped local** expiry, the
only discriminator the node has for why an entry left:

| Condition at teardown            | Close reason | Reported `terminated_by` |
|----------------------------------|--------------|---------------------------|
| Capped expiry is still in the future | `drained` | `plexd_close`         |
| Capped expiry has passed             | `expired` | `ttl_expired`             |

The node never reports `operator_revoke`. Only a lapsed local expiry is
self-evident; an entry that simply is not there may be a revocation, a lagging
read replica, a control plane mid-rollout, or a filtering gateway, and the node
cannot tell them apart. Asserting a human action in the audit trail on that
evidence would answer "who revoked this session?" confidently and wrongly.

### Provision Pass

Entries are handled in block order. A `known` set records every session ID the
dispatcher has already acted on while its entry stands — provisioned, observed
live, or permanently settled — so a settled entry is a no-op on every later pull:

| Entry state                                        | Outcome                                                                 | Settled |
|----------------------------------------------------|-------------------------------------------------------------------------|---------|
| Empty `session_id`                                 | Error log (`session entry carries no session_id; dropping`), entry dropped | n/a (never enters `known`) |
| Already in `known`                                 | No-op                                                                    | already |
| Live session with an outstanding `session_started` row | The row is re-posted from the address the listener already holds; no second setup | **no** |
| Live session not yet in `known`                    | Recorded as known; the listener is already bound, so no second setup     | yes     |
| `expires_at` is the zero time                      | Warning (`session carries no expires_at; refusing to provision`)          | yes     |
| `expires_at` is not in the future                  | Info (`session expired; waiting for the control plane to drain the entry`) | yes     |
| `kind` is `ssh` or `k8s`                           | One warning (`unsupported session kind; no listener provisioned`); no listener, no activity row | yes |
| `kind` is none of the three the contract names     | Warning (`unrecognised session kind; no listener provisioned`) — the target is fine, the kind is not one this build knows | yes |
| `tcp` entry without a `tcp` target, or with more than one target member set | Warning (`session target does not match kind`)  | yes     |
| Valid `tcp` entry, `CreateSession` succeeds        | Listener bound; `ReportSessionStarted` posts the `session_started` row with `listener_endpoint` | yes |
| The `session_started` row does not reach the control plane | Warning; the listener stays bound and the entry is left unsettled so the next pull re-posts the row from the same `listener_endpoint` | **no** |
| `CreateSession` returns `ErrTunnelingDisabled`     | Warning (`tunneling is disabled; no listener provisioned`) — configuration, not weather | yes |
| `CreateSession` fails otherwise                    | Warning (`session listener setup failed`); left unsettled so the next pull retries | **no** |

`ssh` and `k8s` entries are part of the contract but not of this agent's
mediation. They are settled rather than retried, so the warning is emitted once
per entry rather than once per pull.

An entry draining from the block also prunes its ID from `known` and from the
outstanding-row set, which bounds both by the size of the block. The pass carries
no dispatch budget: it is bounded by the live sessions `MaxSessions` caps plus the
length of the block, and its only network call is a single bounded activity post
per session whose started row is still outstanding.

### Registration

```go
mgr := tunnel.NewSessionManager(tunnel.Config{}, meshIP, logger)

sessionDispatcher := tunnel.NewDispatcher(mgr, reporter, logger)
reconciler.RegisterDispatchHandler(sessionDispatcher.Handle)
```

## SessionActivityReporter

Interface for reporting `tcp`-phase session activity rows to the control plane. Abstracted for testability.

```go
type SessionActivityReporter interface {
    ReportSessionStarted(ctx context.Context, sessionID, targetHost string, targetPort int, listenerEndpoint string) error
    ReportSessionEnded(ctx context.Context, sessionID, targetHost string, targetPort int, bytesIn, bytesOut int64, terminatedBy string)
}
```

A production implementation posts an `api.SessionActivityRequest` carrying a `tcp` `api.TCPActivity` to `api.ControlPlane.ReportSessionActivity` (`POST /v1/nodes/{node_id}/sessions/{session_id}`). `ReportSessionStarted` emits a `session_started` row carrying `listenerEndpoint` — the address the listener actually bound, so the control plane has somewhere to send the operator; `ReportSessionEnded` emits a `session_ended` row with the byte counters and a `terminated_by` reason.

`ReportSessionStarted` returns the post's error because the row is not merely an audit record: `listener_endpoint` is the operator's only route to the listener, so a row that does not land leaves a bound listener nobody can reach for the rest of the session. The dispatcher closes the listener again and leaves the entry unsettled, which bounds the outage at one pull instead of the whole TTL — including the case where a control plane that strict-decodes without the `listener_endpoint` field answers `400`. `ReportSessionEnded` returns nothing: it fires from the on-closed callback, the session is over either way, and a failed post is logged and dropped.

## API Types

Types defined in `internal/api` for tunnel communication with the control plane.

### NodeStateSession

One entry of the `sessions` block of `GET /v1/nodes/{node_id}/state`. `JTI` equals
the session ID: it is carried as an opaque value and **never** evaluated — the
node does not authorize connections by it. `ExpiresAt` is an absolute UTC
timestamp, not a relative timeout. `IdleTimeoutSeconds` `0` or absent means the
session has no idle window.

```go
type NodeStateSession struct {
    SessionID          string        `json:"session_id"`
    JTI                string        `json:"jti"`
    Kind               string        `json:"kind"`
    Target             SessionTarget `json:"target"`
    ExpiresAt          time.Time     `json:"expires_at"`
    IdleTimeoutSeconds int           `json:"idle_timeout_seconds,omitempty"`
}
```

### SessionTarget

Exactly one member is set, matching `Kind` — `SessionKindSSH` (`ssh`),
`SessionKindK8s` (`k8s`), or `SessionKindTCP` (`tcp`). Only `tcp` is provisionable
by this agent; `ssh` and `k8s` entries are decoded and settled as unsupported.

```go
type SessionTarget struct {
    SSH *SessionTargetSSH `json:"ssh,omitempty"`
    K8s *SessionTargetK8s `json:"k8s,omitempty"`
    TCP *SessionTargetTCP `json:"tcp,omitempty"`
}

type SessionTargetSSH struct {
    User            string   `json:"user"`
    AllowedCommands []string `json:"allowed_commands,omitempty"`
}

type SessionTargetK8s struct {
    User              string   `json:"user"`
    ImpersonateGroups []string `json:"impersonate_groups,omitempty"`
}

type SessionTargetTCP struct {
    Host string `json:"host"`
    Port int    `json:"port"`
}
```

### SessionActivityRequest

Posted by the node agent per session event. Exactly one of `SSH`, `K8s`, or `TCP`
is set, selecting the session kind. The tunnel subsystem is an opaque TCP
forwarder, so it always sets `TCP`; the `SSH` and `K8s` variants are carried by
the type and accepted by the control plane but not emitted by any current session
type.

```go
type SessionActivityRequest struct {
    SSH *SSHActivity `json:"ssh,omitempty"`
    K8s *K8sActivity `json:"k8s,omitempty"`
    TCP *TCPActivity `json:"tcp,omitempty"`
}
```

**Endpoint**: `POST /v1/nodes/{node_id}/sessions/{session_id}` (success: `204 No Content`)

### TCPActivity

The `tcp` member: a session lifecycle row. `Phase` is `session_started` or
`session_ended`. `ListenerEndpoint` is the node's bound listener address and is set
on `session_started` rows only. `BytesIn` (operator→target) and `BytesOut`
(target→operator) are pointers so a `session_ended` row carries explicit zeros
while a `session_started` row omits the byte counters. `TerminatedBy`, when set, is
one of the `TerminatedBy*` values.

```go
type TCPActivity struct {
    Phase            string `json:"phase"`
    TargetHost       string `json:"target_host,omitempty"`
    TargetPort       int    `json:"target_port,omitempty"`
    ListenerEndpoint string `json:"listener_endpoint,omitempty"`
    BytesIn          *int64 `json:"bytes_in,omitempty"`
    BytesOut         *int64 `json:"bytes_out,omitempty"`
    TerminatedBy     string `json:"terminated_by,omitempty"`
}
```

#### terminated_by mapping

`TerminatedByFromReason` maps the internal session close reason to the wire
`terminated_by` value reported on a `session_ended` row:

| Close reason   | Wire value (`terminated_by`) | Produced when                                                     |
|----------------|------------------------------|--------------------------------------------------------------------|
| `expired`      | `ttl_expired`                | The capped expiry timer fired, or the entry drained after it lapsed |
| `idle`         | `idle_timeout`               | The idle window elapsed with no byte flow                          |
| `drained`      | `plexd_close`                | The entry left the block while the session still had time on it     |
| `shutdown`     | `plexd_close`                | The node is going down                                              |

The reasons are constants in `internal/tunnel`, not bare literals: they are the
only input to this mapping, so producer and consumer share one vocabulary.
`operator_revoke` is never produced by the node.

The `session_ended` row is emitted by the `SessionManager`'s on-closed
callback for **every** close reason: TTL expiry, idle timeout, operator revocation,
and node shutdown alike. The row is the only carrier of a session's byte counters and
`terminated_by`, so skipping it on shutdown would leave the control plane's
audit record for every live session truncated — the node going offline says the
session ended, but not how much traffic it carried.

## Integration Points

### Reconciler (`internal/reconcile`)

`Dispatcher.Handle` is registered with `RegisterDispatchHandler`, alongside the
actions dispatcher. Dispatch handlers run on every successful pull and before the
empty-diff short-circuit, so a session is provisioned or torn down even when
nothing else in the snapshot moved.

### SSE Event Stream (`internal/api`)

The tunnel package registers **no** SSE handlers. Two event types relate to
sessions, and both are plain reconcile triggers whose payloads are never parsed:

| Event Type        | Tier              | Effect                                                                |
|-------------------|-------------------|------------------------------------------------------------------------|
| `session_setup`   | contract          | Triggers a reconcile; the resulting pull carries the session in its `sessions` block |
| `session_revoked` | documented-coming | Triggers a reconcile; the drain in the `sessions` block does the teardown |

Neither event is required for correctness — a node that misses one converges on
its own reconcile cadence. They exist only to shorten the window.

### Control Plane API (`internal/api`)

The node agent reports session activity via a single endpoint on `api.ControlPlane`:

| Method                  | Endpoint                             | When Called                                                            |
|-------------------------|--------------------------------------|------------------------------------------------------------------------|
| `ReportSessionActivity` | `POST /v1/nodes/{id}/sessions/{sid}` | Listener ready (`session_started`) and session close (`session_ended`) |

### WireGuard Mesh (`internal/wireguard`)

Tunnel listeners bind to the mesh IP assigned by the WireGuard interface. Connections arrive through the encrypted mesh — no ports are exposed on the public network. The `meshIP` parameter in `NewSessionManager` comes from `registration.NodeIdentity.MeshIP`, threaded through `NewMeshServer(cfg, meshIP, hostKey, verifier, logger)`.

That bind address is the whole of a session listener's reachability boundary:
the forward itself performs no authentication, accepting the first connection
that arrives. The address is copied verbatim from the control plane's
registration response into `identity.json`, so `CreateSession` parses it rather
than trusting it and refuses to provision anything unless it is a bindable
unicast address — on an empty, unparseable, or unspecified value (`0.0.0.0`,
`::`) `net.Listen` would bind every unicast address on the host and publish a
forward to an internal service on the node's public and LAN interfaces.

::: warning Trust boundary
Reaching a session listener means being routable to the node's mesh IP, which
every peer in the mesh is by construction. Nothing binds a forwarded connection
to the operator the control plane authorized: the session JWT is carried in the
block as an opaque value and is never presented on the forwarded connection.
Treat a live session as reachable by any mesh peer for its duration.
:::

### Graceful Shutdown

Call `SessionManager.Shutdown()` on context cancellation to close all active sessions:

```go
<-ctx.Done()
mgr.Shutdown()
```

## Access Flows

### Mediated TCP Access Flow

1. User requests access through the platform UI/CLI.
2. Control plane verifies RBAC permissions and issues the session, adding a `tcp` entry to the node's `sessions` block. It may also emit a `session_setup` event to pull the node's next reconcile forward.
3. On its next pull, plexd sees the entry, opens a TCP listener on the mesh interface, and reports a `session_started` row carrying the bound `listener_endpoint`.
4. Connections arriving on that listener are forwarded through the encrypted mesh to the target host and port.
5. The session ends when the control plane drops the entry from the block (`plexd_close`), when its capped expiry fires (`ttl_expired`), when its idle window elapses (`idle_timeout`), or on node shutdown (`plexd_close`). The `session_ended` row carries the byte counters and the reason.

### SSH and Kubernetes Sessions

`ssh` and `k8s` entries are part of the `sessions` contract and plexd decodes them,
but **this agent provisions no listener for them**: each is settled with a single
`unsupported session kind; no listener provisioned` warning and produces no
activity row, so there is nothing to tear down when the entry later drains.
Mediating those kinds from the block is follow-up work.

## Logging

All log entries use `component=tunnel`. Session-scoped entries add `session_id`.

| Level   | Event                          | Keys                                        |
|---------|--------------------------------|---------------------------------------------|
| `Info`  | Session started                | `listen_addr`, `target`                     |
| `Info`  | Session created                | `session_id`, `listen_addr`, `expires_at`   |
| `Info`  | Session closed                 | `session_id`, `reason`, `duration`          |
| `Info`  | All tunnel sessions closed     | —                                           |
| `Info`  | Session expired; waiting for the control plane to drain the entry | `session_id`, `kind`, `expires_at` |
| `Warn`  | Session carries no expires_at; refusing to provision | `session_id`, `kind`   |
| `Warn`  | Unsupported session kind; no listener provisioned | `session_id`, `kind`      |
| `Warn`  | Session target does not match kind | `session_id`, `kind`                    |
| `Warn`  | Tunneling is disabled; no listener provisioned | `session_id`                |
| `Warn`  | Session listener setup failed  | `session_id`, `error`                       |
| `Debug` | Connection rejected (duplicate)| —                                           |
| `Debug` | Session not found for close    | `session_id`                                |
| `Error` | Session entry carries no session_id; dropping | `kind`                       |
| `Error` | Failed to dial target          | `target`, `error`                           |
