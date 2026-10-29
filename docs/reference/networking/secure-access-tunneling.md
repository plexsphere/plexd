---
title: Secure Access Tunneling
package: internal/tunnel
feature: PXD-0009
---

# Secure Access Tunneling

The `internal/tunnel` package provides platform-mediated access to mesh nodes without exposing services to the public internet. The control plane declares a node's live sessions in the `sessions` block of the reconciliation state pull; the node agent holds its sessions level with that block, provisioning each entry it can serve, and reporting activity back to the control plane. A `tcp` entry gets a TCP listener bound to the mesh IP that forwards connections arriving through the WireGuard mesh to the target host. On Linux and macOS, an `ssh` entry gets an SSH session listener that binds no port: the control plane asks for each connection with a signed `session_connect` event, plexd opens that connection out to the control plane, and the listener serves the session's login on it, starting a shell or one command for the session's user (see [SSH Sessions](#ssh-sessions)).

The block is **desired state, not a delivery queue**: an entry stands for as long as its session is valid, and its disappearance is the teardown signal. Revocation and hard expiry both reach the node as that same absence, and there is no terminal status to report. A revocation the control plane also announces in a verified `session_revoked` event is closed when the event arrives, unless a pull drained it first (see [SSE Event Stream](#sse-event-stream-internal-api)); the absence stays the teardown for every revocation whose event never arrives.

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
4. Provision pass, in block order: each entry not yet settled is validated and, if it is a `tcp` entry or, on Linux and macOS, an `ssh` entry, handed to `SessionManager.CreateSession`. A `tcp` session opens a listener on `meshIP:0`. An `ssh` session binds nothing and needs no mesh address: it is ready to serve the connections the control plane asks for (see [Listener](#listener))
5. Report pass: once the block is provisioned, `SessionActivityReporter.ReportSessionStarted` posts a `session_started` row per session whose row is still outstanding. The `tcp` row carries the target host and port and the `listener_endpoint` the listener actually bound. The `ssh` lifecycle row carries the phase alone, no `listener_endpoint`, and means the session is ready to serve. A row that does not land is re-posted on the next pull from the same session, so a `tcp` row's `listener_endpoint` stays stable across attempts. The posts run concurrently and each is bounded, so a stalled control plane cannot hold the reconciler's single goroutine for the length of the block. A row answered with a terminal-state verdict (a `409` `session_already_revoked` or `session_expired`, classified by `api.IsSessionRevokedOrExpired`) is settled rather than re-posted and is logged at Info (`session no longer live server-side; awaiting the drain`); the listener stays up until the block drain, or a verified `session_revoked` event naming the session, closes it, and every pull that still carries the settled entry warns that the listener is forwarding for a session the platform has withdrawn. A `404` `session_not_found` is not a terminal state — the block and the session store are separate reads that can disagree — so it stays on the re-post path
6. A client connects through the mesh to a `tcp` listener, and `Session` forwards to the target. While bytes cross, the session posts `session_active` rows through `TCPActivityReporter.ReportSessionActive`, at most one per interval, so the control plane's idle sweeper does not revoke a tunnel in use (see [Activity Reports](#activity-reports)). A client of an `ssh` session attaches through the control plane, which sends a `session_connect` event for each connection; plexd opens it to the control plane, outside the reconcile cycle
7. A session ends when its entry drains from the block, when a verified `session_revoked` event names it (`Dispatcher.SessionRevokedHandler`), when its capped expiry fires, when its idle window elapses, or on `Shutdown`
8. The `SessionManager`'s on-closed callback fires the production reporter's `ReportSessionEnded`, posting a `session_ended` row with a `terminated_by` reason for every close reason, `Shutdown` included: the `tcp` row carries the byte counters, the `ssh` row picks its shape from `ClosedSessionInfo.Kind`. For a close caused by the drain or by a `session_revoked` event the platform already holds the session as revoked or expired, and it records the ending row of the session's current listener once instead of refusing it. A `409` to the ending row means the listener's end is already recorded, or a control plane that predates that rule; the row is fire-once and nothing re-posts it, so plexd warns (`tunnel session ended row refused; its counters are recorded only here`, or `ssh session ended row refused; its terminating reason is recorded only here` for an ssh session) and carries `terminated_by`, plus a `tcp` row's byte counters, into that line, which is where they survive

## Config

`Config` holds secure access tunneling parameters passed to the `SessionManager` constructor.

| Field            | Type            | Default | Description                                    |
|------------------|-----------------|---------|------------------------------------------------|
| `Enabled`        | `bool`          | `true`  | Whether tunneling is active                    |
| `MaxSessions`    | `int`           | `10`    | Maximum concurrent tunnel sessions             |
| `DefaultTimeout` | `time.Duration` | `30m`   | Default/maximum session timeout                |
| `SSHListenAddr`  | `string`        | —       | SSH mesh server listen address (empty = no SSH server) |
| `HostKeyDir`     | `string`        | —       | Directory for SSH host key (empty = transient key)     |
| `SSHSessionsEnabled` | `*bool`     | `true`  | `ssh_sessions_enabled`: whether the node serves mediated ssh sessions; read through `SSHSessionsAllowed()`, where nil means true |
| `SessionSigningPublicKey` | `string` | —     | `session_signing_public_key`: standard-base64 Ed25519 key the session helper verifies tokens against; empty means the helper pins the identity's key. Read only by Linux's socket-activated session helper; unused on macOS (see [Trust anchor](#trust-anchor)) |

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
| `SessionSigningPublicKey` | Empty, or standard base64 decoding to 32 bytes | `tunnel: config: session_signing_public_key: ...` |

The key is checked whatever `Enabled` says, because the session helper reads it either way. The other rules are skipped when `Enabled` is `false`.

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
| `Start`      | `(ctx context.Context) (string, error)`    | Opens TCP listener on meshIP:0, starts accept loop and, when an idle window is armed, the idle monitor and, when an activity reporter is wired, the activity report |
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

- Listener binds to mesh IP only, never `0.0.0.0` or `localhost`. `SessionManager.CreateSession` parses the mesh IP and refuses to provision a tcp session at all unless it is a bindable unicast address, because `net.Listen` on an empty or unspecified host binds every unicast address the host has. The check runs on the address `net.Listen` would actually bind — zone stripped and IPv4-mapped form unwrapped — so `::ffff:0.0.0.0` and `::%eth0` are refused as the wildcards they bind to, not accepted as the distinct addresses they parse to
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
| `CreateSession`  | `(ctx context.Context, sess api.NodeStateSession) (string, error)` | Validates one entry of the `sessions` block, creates and starts its session, and returns the bound listener address of a tcp session, or an empty address for an ssh session, which binds nothing |
| `ConnectSSHSession` | `(sessionID, connectionID string, dial func(context.Context) (net.Conn, error)) error` | Opens one connection of a live ssh session with `dial` and serves the session's login on it; the `session_connect` handler calls it (see [Listener](#listener)) |
| `SetSSHSessionDeps` | `(deps SSHSessionDeps)`                                         | Wires the host key, signing keys, command reporter and session launcher ssh sessions need; `plexd up` calls it on Linux and macOS |
| `SetTCPActivityReporter` | `(r TCPActivityReporter)`                                  | Wires the reporter tcp sessions post their `session_active` rows through. Until it is called, tcp sessions post none, and a session keeps the reporter it was created with; `plexd up` calls it (see [Activity Reports](#activity-reports)) |
| `CloseSession`   | `(sessionID string, reason string) *ClosedSessionInfo`             | Closes and removes a session by ID; returns session info |
| `Shutdown`       | `()`                                                               | Closes all active sessions, reporting each through the on-closed callback |
| `ActiveSessions` | `() map[string]time.Time`                                          | Snapshot of live session IDs and their **capped** local expiry; the dispatcher's teardown input |
| `ActiveCount`    | `() int`                                                           | Returns number of active sessions                        |

### CreateSession Validation

`tcp` entries are provisionable everywhere, `ssh` entries on Linux and macOS once
`SetSSHSessionDeps` wired them. The dispatcher filters the block before calling in;
the kind guard repeats the check so the manager is safe to call on its own. Both
kinds share one session map, so `MaxSessions` and the `DefaultTimeout` cap count
them together.

| Check                  | Condition                                   | Error                                              |
|------------------------|---------------------------------------------|-----------------------------------------------------|
| Tunneling disabled     | `cfg.Enabled == false`                      | `ErrTunnelingDisabled` (`tunnel: tunneling is disabled`) |
| Not provisionable      | `Kind` is neither `tcp` nor `ssh`, or the entry lacks the target of its kind | `tunnel: session kind is not provisionable` |
| Missing fields (`tcp`) | Empty ID, empty host, or port outside 1-65535 | `tunnel: invalid session setup: ...`              |
| Unsupported (`ssh`)    | Neither Linux nor macOS                     | `ErrSSHSessionsUnsupported` (`tunnel: ssh sessions are not supported on this platform`) |
| Refused (`ssh`)        | `ssh_sessions_enabled: false`               | `ErrSSHSessionsDisabled` (`tunnel: ssh sessions are disabled on this node`) |
| Missing user (`ssh`)   | Empty `target.ssh.user`                     | `tunnel: invalid session setup: ssh target user is required` |
| Not wired (`ssh`)      | Any `SSHSessionDeps` member is nil          | `tunnel: ssh sessions are not wired: host key, signing keys, command reporter and session launcher are required` |
| Missing ID (`ssh`)     | Empty `session_id`                          | `tunnel: invalid session setup: session_id is required` |
| Already expired        | `ExpiresAt` in the past                     | `tunnel: session already expired`                   |
| Duplicate ID           | Session ID already exists                   | `tunnel: duplicate session ID: {id}`                |
| Capacity               | `len(sessions) >= MaxSessions`              | `tunnel: max sessions reached ({n})`                |
| Invalid idle window    | `IdleTimeoutSeconds` negative or above 86400 | `tunnel: invalid idle_timeout_seconds: {n}`        |
| Unbindable mesh IP (`tcp`) | `meshIP` empty, not an IP address, multicast, or unspecified once the zone is stripped and the IPv4-mapped form unwrapped (`0.0.0.0`, `::`, `::ffff:0.0.0.0`, `::%eth0`) | `tunnel: mesh IP {ip} is not a bindable unicast address; refusing to bind a session listener` |

The mesh-IP check runs for `tcp` entries only. An `ssh` session binds no
listener, so an `ssh` entry never reads the mesh IP, and a manager built with an
empty or unbindable one still serves ssh sessions. That is what lets a node
whose WireGuard setup failed or never ran serve them (see
[Deployment notes](#deployment-notes)).

`ErrTunnelingDisabled` and `ErrSSHSessionsDisabled` are sentinels: the dispatcher
matches them with `errors.Is` to settle an entry permanently instead of retrying it
on every pull.

### Expiry

- `ExpiresAt` is capped at `DefaultTimeout` from now (never exceeds maximum)
- `time.AfterFunc` schedules automatic `CloseSession(id, "expired")` at the capped expiry time. The timer closes over the session, not just its ID, so a timer armed for an earlier session cannot close the one that later took its ID
- A cap that truncates the granted `expires_at` is logged at warn: the control plane does not learn the node's local maximum from the pull, so a session granted more time than `DefaultTimeout` ends early — with a `ttl_expired` `session_ended` row — while its entry still stands in the block, and it is not provisioned a second time

### Idle Enforcement

An entry with `idle_timeout_seconds > 0` arms an idle monitor; `0` or an absent
value means the session has no idle window.

- `idle_timeout_seconds` is validated on the way in: a negative value, or one large enough to overflow the seconds-to-`Duration` multiplication, is rejected rather than silently read as "no idle window"
- Byte flow re-arms the window: every forwarded chunk of a tcp session, and every SSH byte read from or written to any connection of an ssh session, stamps the session's last activity, so the monitor either closes the session or waits out the remaining window
- WebSocket ping and pong frames are not activity. The control plane pings each ssh session connection every 30 s, and those frames are answered inside the connection's `Read` and never reach the session, so they cannot hold an idle session open
- A kept shell's output while no client is attached is not activity: it goes into the replay buffer, not onto a connection, so a session whose shell no client reattached within the window closes with `idle_timeout` (see [Kept shell](#kept-shell))
- Activity is stamped as a monotonic offset, not a wall-clock time: an NTP step or a VM snapshot resume cannot stretch or collapse the window
- `Start` counts as the first activity (the listener bind of a tcp session, the start of an ssh session), so a session no connection ever reaches idles out one window after `Start`
- The close runs through `CloseSession(id, "idle")` like any other, so the `session_ended` row still carries the byte counters and, via the reason, a `terminated_by` of `idle_timeout`
- The monitor is started by `Session.Start` on its own child context and exits when that context is cancelled, which every close reaches

### Activity Reports

An operator's client dials a tcp session's listener over the mesh, so no
control-plane component sees a byte of the tunnel, and the control plane's idle
sweeper revokes a session whose `last_active_at` is `idle_timeout_seconds` old.
While a tcp tunnel forwards bytes, its session therefore posts the row
`{"tcp":{"phase":"session_active"}}` through
`TCPActivityReporter.ReportSessionActive`, and the control plane advances the
session's `last_active_at` to the instant it records the row. A quiet tunnel
posts nothing and still idles out, on the node and on the control plane. plexd
follows the rules of the
[TCP session activity](https://github.com/plexsphere/plexsphere/blob/4c954bd1416cdaeb34d3d84cad5c042a75baab53/docs/reference/api/plexd-agent-contract.md#tcp-session-activity)
section of plexsphere's agent contract:

- The interval is `min(60 s, idle_timeout_seconds / 4)`, with `idle_timeout_seconds` read from the session's entry in the pull, and 60 s when it is `0`. `activityReportInterval` divides the duration, not the seconds, so a 10 s window gives a 2.5 s interval. The control plane issues no session without an idle window, but a tcp session with `idle_timeout_seconds` `0` still reports, every 60 s, as the contract says
- The first row goes out as soon as a byte crosses after an interval without a row. After a row, one more row goes out at the end of each interval in which bytes crossed, and none once a whole interval passed without a byte. A tunnel therefore posts at most one row per interval, and the last bytes of a tunnel that goes quiet are still reported. Each interval is measured from the start of the post that opened it
- Each post is bounded by `sessionActiveReportTimeout`, 15 s, which stays above `api.DefaultConnectTimeout` for the reason `sessionStartedReportTimeout` documents. The post runs on the session's own goroutine, never on the reconciler's, so a slow post only delays that session's next row
- Only tcp sessions report. The control plane counts an ssh session's terminal traffic at its attach gateway, and plexd serves no k8s session
- Until `SessionManager.SetTCPActivityReporter` is called, tcp sessions post no row, and a session keeps the reporter it was created with. `plexd up` wires the production reporter (see [SessionActivityReporter](#sessionactivityreporter))

The answer to each post decides what the session does next. No answer closes
the tunnel:

| Answer | The session | Log line |
|--------|-------------|----------|
| `204` | The row is recorded | Debug `session_active row recorded` |
| `409` `session_already_revoked` or `session_expired` (`api.IsSessionRevokedOrExpired`) | The session is no longer live server-side, so it stops reporting. The tunnel stays up until the block drain, or a verified `session_revoked` event, closes it | Info `session no longer live server-side; stopping its activity reports`, with `error` |
| Any `400`, such as the `400 invalid_session_activity` of a control plane that predates the row | The row is not recorded and not retried: its bytes never change, so a re-post would draw the same answer. Later bytes still post, so a control plane rolled forward mid-session records the next row | Warn `control plane refused the session_active row; it revokes the tunnel one idle timeout after it started`, with `error`, on the session's first `400` only |
| Anything else: `401 nsk_invalid`, `404 session_not_found`, any `5xx`, a transport error, the 15 s bound running out, `api.ErrCredentialRefused` | The row is not recorded. The bytes are marked unreported again, so the end of the interval retries the row even when the tunnel went quiet | Warn `session activity report failed; retrying at the end of the interval`, with `error` |

A control plane that refuses the row with a `400` revokes the session one idle
timeout after its `session_started` row, whether or not the tunnel still
forwards bytes, which is what the Warn line says. A session with an idle window
stops retrying once its own idle close ends it, and a session that closes while
a post is in flight stops without a log line.

The reports cost one goroutine per tcp session with a wired reporter. `Start`
runs it on the child context it derives, like the idle monitor, so every close
stops it. Each forwarded chunk costs two atomic operations, plus a non-blocking
wake-up of that goroutine while the report is quiet, and a tunnel posts at most
one row per interval. To see the chunks, a session with a wired reporter wraps
both forwarding sources, as a session with an idle window does, and gives up the
`splice(2)` fast path `io.Copy` takes between two TCP connections. Every session
the control plane issues carries an idle window, so it has given that path up
already.

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
func (d *Dispatcher) SessionRevokedHandler(trigger api.ReconcileTrigger) api.EventHandler
func (d *Dispatcher) SessionConnectHandler(connector SessionConnector) api.EventHandler
```

`Handle` is **not** safe for concurrent use: it is invoked only from the
reconcile goroutine, one cycle at a time. The handlers `SessionRevokedHandler`
and `SessionConnectHandler` return (see [SSE Event Stream](#sse-event-stream-internal-api))
run on the SSE goroutine, concurrently with `Handle`; they touch only the
`SessionManager`, which locks for itself, and the `revoked` set, which a mutex
guards.

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

A session a verified `session_revoked` event already closed is no longer live
here, so this pass does not close it again: its `session_ended` row went out
with the `terminated_by` the event's `revoke_reason` maps to.

A drain does not report `operator_revoke`. Only a lapsed local expiry is
self-evident; an entry that simply is not there may be a revocation, a lagging
read replica, a control plane mid-rollout, or a filtering gateway, and the node
cannot tell them apart. Asserting a human action in the audit trail on that
evidence would answer "who revoked this session?" confidently and wrongly. The
node reports `operator_revoke` only for a close caused by a verified
`session_revoked` event, which is signed and names the session. A pull that
drains the entry before that event arrives still reports `plexd_close`, and the
late event finds no live session to close.

### Provision Pass

Entries are handled in block order. A `known` set records every session ID the
dispatcher has already acted on while its entry stands — provisioned, observed
live, or permanently settled — so a settled entry is a no-op on every later pull:

| Entry state                                        | Outcome                                                                 | Settled |
|----------------------------------------------------|-------------------------------------------------------------------------|---------|
| Empty `session_id`                                 | Error log (`session entry carries no session_id; dropping`), entry dropped | n/a (never enters `known`) |
| Already in `known`                                 | No-op                                                                    | already |
| In the `revoked` set (a verified `session_revoked` event named it) | Info (`session was revoked by a signed event; not provisioning it`); not provisioned, and an outstanding `session_started` row is dropped | yes |
| Valid entry the event revoked while `CreateSession` was binding its listener | Info (`session was revoked by a signed event while its listener came up; closing it`); the listener is closed at once with the event's reason and no `session_started` row is posted | yes |
| Live session with an outstanding `session_started` row | The row is re-posted, a `tcp` row from the address the listener already holds and an `ssh` row without one; no second setup | **no** |
| Live session not yet in `known`                    | Recorded as known; the session is already up, so no second setup         | yes     |
| `expires_at` is the zero time                      | Warning (`session carries no expires_at; refusing to provision`)          | yes     |
| `expires_at` is not in the future                  | Info (`session expired; waiting for the control plane to drain the entry`) | yes     |
| `kind` is `k8s`, or `ssh` off Linux and macOS      | One warning (`unsupported session kind; no listener provisioned`); no listener, no activity row | yes |
| `kind` is none of the three the contract names     | Warning (`unrecognised session kind; no listener provisioned`) — the target is fine, the kind is not one this build knows | yes |
| `tcp` or `ssh` entry without the target of its kind, or with more than one target member set | Warning (`session target does not match kind`)  | yes     |
| Valid `tcp` or `ssh` entry, `CreateSession` succeeds | A `tcp` listener bound, or an `ssh` session ready to serve; `ReportSessionStarted` posts the `session_started` row, a `tcp` row with `listener_endpoint` | yes |
| The `session_started` row does not reach the control plane | Warning; the session stays up and the entry is left unsettled so the next pull re-posts the row, a `tcp` row from the same `listener_endpoint` | **no** |
| The `session_started` row is answered `409 session_already_revoked` / `session_expired` | Info (`session no longer live server-side; awaiting the drain`); the session stays up, the entry is settled, the teardown waits for the block drain or a verified `session_revoked` event, and each later pull still carrying the entry warns | yes |
| `CreateSession` returns `ErrTunnelingDisabled`     | Warning (`tunneling is disabled; no listener provisioned`) — configuration, not weather | yes |
| `CreateSession` returns `ErrSSHSessionsDisabled`   | Warning (`ssh sessions are disabled on this node; no listener provisioned`) | yes |
| `CreateSession` fails otherwise                    | Warning (`session listener setup failed`); left unsettled so the next pull retries | **no** |

`k8s` entries are part of the contract but not of this agent's mediation, and
`ssh` entries are served on Linux and macOS only. Both are settled rather than
retried, so the warning is emitted once per entry rather than once per pull. An `ssh` entry
with an empty user, or one reaching a manager nobody wired, is a setup failure and
is retried.

The `revoked` set holds the IDs a verified `session_revoked` event named. The
control plane never makes a revoked session live again, but a pull rendered
before the revocation committed can still list its entry; that entry is settled
rather than provisioned, so the listener the event closed is not bound again.

An entry draining from the block also prunes its ID from `known`, from the
outstanding-row set and from the `revoked` set, which bounds all three by the
size of the block. The pass carries no dispatch budget: it is bounded by the
live sessions `MaxSessions` caps plus the length of the block, and its only
network call is a single bounded activity post per session whose started row is
still outstanding.

### Registration

```go
mgr := tunnel.NewSessionManager(tunnel.Config{}, meshIP, logger)

sessionDispatcher := tunnel.NewDispatcher(mgr, reporter, logger)
reconciler.RegisterDispatchHandler(sessionDispatcher.Handle)
sseMgr.RegisterHandler(api.EventSessionRevoked, sessionDispatcher.SessionRevokedHandler(reconciler))
sseMgr.RegisterHandler(api.EventSessionConnect, sessionDispatcher.SessionConnectHandler(connector))
```

`plexd up` registers the `session_connect` handler unconditionally, with a
`connector` that opens the connection through `api.ControlPlane.OpenSessionConnection`
under the identity's node id. A node with tunneling or ssh sessions off
therefore logs why it refuses the event instead of dropping it at Debug.

## SessionActivityReporter

Interface for reporting a session's `session_started` row to the control plane, beside `SSHCommandReporter` for an ssh session's command rows and `TCPActivityReporter` for a tcp session's `session_active` rows. Abstracted for testability.

```go
type SessionActivityReporter interface {
    ReportSessionStarted(ctx context.Context, entry api.NodeStateSession, listenerEndpoint string) error
}

type SSHCommandReporter interface {
    ReportSSHCommandStarted(ctx context.Context, sessionID, command string, startedAt time.Time) error
    ReportSSHCommandExited(ctx context.Context, sessionID, command string, exitCode int, startedAt, completedAt time.Time) error
}

type TCPActivityReporter interface {
    ReportSessionActive(ctx context.Context, sessionID string) error
}
```

The production implementation, `controlPlaneSessionReporter` in `cmd/plexd/cmd/up.go`, posts an `api.SessionActivityRequest` to `api.ControlPlane.ReportSessionActivity` (`POST /v1/nodes/{node_id}/sessions/{session_id}`). `listenerEndpoint` is a tcp listener's bound address and empty for an ssh session. For a `tcp` entry `ReportSessionStarted` emits a `tcp` `session_started` row with the target and `listenerEndpoint`, the address the listener actually bound, so the control plane has somewhere to send the operator; for an `ssh` entry it emits the `ssh` lifecycle row with the phase alone and ignores `listenerEndpoint`. `ReportSessionEnded(ctx, sessionID, info *ClosedSessionInfo, terminatedBy)` emits a `session_ended` row: the `tcp` row with the byte counters, or, when `info.Kind` is `ssh`, the `ssh` row with `terminated_by` only. `ReportSessionEnded` is not on the interface: it is fired from the `SessionManager`'s on-closed callback that `plexd up` wires with `SetOnClosed`. The same type implements `SSHCommandReporter`, whose two rows the ssh listener posts around every `exec` (see [Commands and activity rows](#commands-and-activity-rows)); both return the post's error. It also implements `TCPActivityReporter`, which `plexd up` wires with `SetTCPActivityReporter` so the rows keep the control plane's idle sweeper away from a tunnel in use: `ReportSessionActive(ctx, sessionID)` emits the `tcp` row `{"tcp":{"phase":"session_active"}}` and returns the post's error unchanged, because the answer decides whether the session stops reporting, warns, or retries the row at the end of its interval (see [Activity Reports](#activity-reports)).

`ReportSessionStarted` returns the post's error because the row is not merely an audit record. For a tcp session `listener_endpoint` is the operator's only route to the listener, and for an ssh session the row is what makes the control plane ask for connections, since it sends `session_connect` only for a session whose newest lifecycle row is `session_started`. Either way the dispatcher has to know whether the row landed. A terminal-state answer (`api.IsSessionRevokedOrExpired`: a `409` `session_already_revoked` or `session_expired`) settles the entry and is logged at Info; the session stays up until the block drain, or a verified `session_revoked` event naming the session, closes it. Every other error (a transport failure, a `400`, a `404` `session_not_found`, a `501` `access_session_not_provisioned`, a `5xx`) keeps the session up, leaves the entry unsettled, and re-posts the row on the next pull, a `tcp` row from the same `listener_endpoint`, logged at Warn. `ReportSessionEnded` returns nothing and is fire-once from the on-closed callback: a `409` is logged at Warn carrying `terminated_by` and, for a `tcp` row, the byte counters (the control plane records the ending row of a revoked or expired `ssh` or `tcp` session's current listener once, unless its newest lifecycle row is already a `session_ended`, so a `409` to it means the listener's end is already recorded, or a control plane that predates that rule; nothing re-posts the row, so the line is where that payload survives), any other failure at Error, and nothing is retried.

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
`SessionKindK8s` (`k8s`), or `SessionKindTCP` (`tcp`). This agent provisions `tcp`
entries, and `ssh` entries on Linux and macOS; `k8s` entries, and `ssh` entries
on Windows, are decoded and settled as unsupported. The ssh listener takes the allowed-command
list from the session token, not from `SessionTargetSSH.AllowedCommands`.

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
is set, selecting the session kind. A tcp session sets `TCP` and an ssh session
sets `SSH`; the `K8s` variant is carried by the type and accepted by the control
plane but not emitted.

```go
type SessionActivityRequest struct {
    SSH *SSHActivity `json:"ssh,omitempty"`
    K8s *K8sActivity `json:"k8s,omitempty"`
    TCP *TCPActivity `json:"tcp,omitempty"`
}
```

**Endpoint**: `POST /v1/nodes/{node_id}/sessions/{session_id}` (success: `204 No Content`)

### TCPActivity

The `tcp` member: a session lifecycle row, or a row reporting traffic. `Phase` is
`session_started` or `session_ended` on the two lifecycle rows, or
`session_active` on the rows a tunnel posts while it forwards bytes (see
[Activity Reports](#activity-reports)). A `session_active` row carries `Phase`
alone. `ListenerEndpoint` is the node's bound listener address and is set
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

### SSHActivity

The `ssh` member takes one of two shapes. A **lifecycle row** carries `Phase`
(`SSHPhaseSessionStarted` or `SSHPhaseSessionEnded`) plus `TerminatedBy` on
`session_ended`, and no command fields. An ssh session binds no listener, so
plexd sends no `ListenerEndpoint`; the field stays for the `session_started`
rows older agents post with one, which the control plane still admits. A
**command row** carries `Command` (1 to 1024 bytes), with `StartedAt` on the row
posted before the command runs and `ExitCode`, `StartedAt` and `CompletedAt` on
the row posted after it exited. plexd never posts an empty `Command`: the control
plane refuses a row that mixes the shapes.

```go
type SSHActivity struct {
    Command          string     `json:"command,omitempty"`
    ExitCode         *int       `json:"exit_code,omitempty"`
    StartedAt        *time.Time `json:"started_at,omitempty"`
    CompletedAt      *time.Time `json:"completed_at,omitempty"`
    Phase            string     `json:"phase,omitempty"`
    ListenerEndpoint string     `json:"listener_endpoint,omitempty"`
    TerminatedBy     string     `json:"terminated_by,omitempty"`
}
```

#### terminated_by mapping

`TerminatedByFromReason` maps the internal session close reason to the wire
`terminated_by` value reported on a `session_ended` row:

| Close reason   | Wire value (`terminated_by`) | Produced when                                                     |
|----------------|------------------------------|--------------------------------------------------------------------|
| `expired`      | `ttl_expired`                | The capped expiry timer fired, the entry drained after it lapsed, or a `session_revoked` event carried `revoke_reason` `ttl_expired` |
| `idle`         | `idle_timeout`               | The idle window elapsed with no byte flow, or a `session_revoked` event carried `revoke_reason` `idle_timeout` |
| `revoked`      | `operator_revoke`            | A `session_revoked` event carried an operator-driven `revoke_reason`, or an empty or unrecognised one |
| `drained`      | `plexd_close`                | The entry left the block while the session still had time on it     |
| `shutdown`     | `plexd_close`                | The node is going down                                              |

The reasons are constants in `internal/tunnel`, not bare literals: they are the
only input to this mapping, so producer and consumer share one vocabulary.
`operator_revoke` is produced only for `revoked`, which only the
`session_revoked` handler passes; a drain never produces it.

`closeReasonForRevocation` maps the `revoke_reason` of a verified
`session_revoked` event (see [SessionRevocation](#sessionrevocation)) to the
close reason the handler passes to `CloseSession`:

| `revoke_reason`           | Constant                                 | Close reason | Wire value (`terminated_by`) |
|---------------------------|------------------------------------------|--------------|------------------------------|
| `operator_request`        | `api.RevokeReasonOperatorRequest`        | `revoked`    | `operator_revoke`            |
| `policy_violation`        | `api.RevokeReasonPolicyViolation`        | `revoked`    | `operator_revoke`            |
| `identity_compromise`     | `api.RevokeReasonIdentityCompromise`     | `revoked`    | `operator_revoke`            |
| `resource_decommissioned` | `api.RevokeReasonResourceDecommissioned` | `revoked`    | `operator_revoke`            |
| `ttl_expired`             | `api.RevokeReasonTTLExpired`             | `expired`    | `ttl_expired`                |
| `idle_timeout`            | `api.RevokeReasonIdleTimeout`            | `idle`       | `idle_timeout`               |
| Empty or unrecognised     | n/a                                      | `revoked`    | `operator_revoke`, with a Warn (`session_revoked carries an unrecognised revoke_reason; reporting operator_revoke`) |

The first four are operator-driven, supplied on the control plane's explicit
revoke call. The last two are set by the control plane's sweeper when the
session reaches its hard expiry or its idle timeout, so they keep the
`terminated_by` the node's own timers would report. An unrecognised value still
maps to `revoked`, because the close is still caused by the event.

The `session_ended` row is emitted by the `SessionManager`'s on-closed
callback for **every** close reason: TTL expiry, idle timeout, revocation
(closed by a verified `session_revoked` event or by the drain), and node
shutdown alike. The row is the only carrier of a session's byte counters and
`terminated_by`, so skipping it on shutdown would leave the control plane's
audit record for every live session truncated — the node going offline says the
session ended, but not how much traffic it carried.

### SessionRevocation

The payload of the `session_revoked` event: the revoked session, the revoked
token's `jti` (equal to the session ID), and when and why the control plane
revoked it. The contract names six `RevokeReason` values, the `RevokeReason*`
constants (see [terminated_by mapping](#terminated-by-mapping)).

```go
type SessionRevocation struct {
    SessionID    string    `json:"session_id"`
    JTI          string    `json:"jti"`
    RevokedAt    time.Time `json:"revoked_at"`
    RevokeReason string    `json:"revoke_reason"`
}
```

### SessionConnectRequest

The payload of the `session_connect` event: the ssh session a client attached
to, the one-time id of the connection the node is asked to open for it, and the
instant after which the control plane no longer accepts that connection. Its
shape is the control plane's `access.SessionConnectRequested` event, whose
`event_id` and `occurred_at` header members plexd does not read. plexd does not
judge `ExpiresAt` against its own clock either (see [Listener](#listener)).

```go
type SessionConnectRequest struct {
    SessionID    string    `json:"session_id"`
    ConnectionID string    `json:"connection_id"`
    ExpiresAt    time.Time `json:"expires_at"`
}
```

## Integration Points

### Reconciler (`internal/reconcile`)

`Dispatcher.Handle` is registered with `RegisterDispatchHandler`, alongside the
actions dispatcher. Dispatch handlers run on every successful pull and before the
empty-diff short-circuit, so a session is provisioned or torn down even when
nothing else in the snapshot moved.

### SSE Event Stream (`internal/api`)

The tunnel package provides two SSE handlers. `plexd up` registers the one
`Dispatcher.SessionRevokedHandler` returns for `session_revoked`, in place of a
plain reconcile trigger, and the one `Dispatcher.SessionConnectHandler` returns
for `session_connect`. Three event types relate to sessions:

| Event Type        | Tier              | Effect                                                                |
|-------------------|-------------------|------------------------------------------------------------------------|
| `session_setup`   | contract          | A plain reconcile trigger whose payload plexd does not parse; the resulting pull carries the session in its `sessions` block |
| `session_revoked` | contract          | `SessionRevokedHandler` closes the session the payload names, reporting the `terminated_by` its `revoke_reason` maps to, then triggers a reconcile |
| `session_connect` | contract          | `SessionConnectHandler` opens the connection the payload names for a live ssh session and serves the session's login on it (see [Listener](#listener)). It triggers no reconcile |

The SSE stream verifies the envelope's signature and freshness before any
handler runs. The `session_revoked` handler then:

1. Decodes the payload as `api.SessionRevocation`. A payload that does not decode, an empty `session_id`, or a `jti` that differs from `session_id` closes nothing: the handler triggers a reconcile and returns the error, which the event dispatcher logs at Error (`event handler failed`).
2. Maps `revoke_reason` to a close reason with `closeReasonForRevocation` (see [terminated_by mapping](#terminated-by-mapping)). An empty or unrecognised value is logged at Warn (`session_revoked carries an unrecognised revoke_reason; reporting operator_revoke`) and still closes the session as `revoked`.
3. Records the session ID in the dispatcher's `revoked` set, with the close reason, so a pull rendered before the revocation committed cannot provision the session again (see [Provision Pass](#provision-pass)). When such a pull is already binding the listener as the event lands, the handler's close finds no live session; `Handle` checks the set again once `CreateSession` returns and closes the listener it just bound with the event's reason, without posting its `session_started` row (`session was revoked by a signed event while its listener came up; closing it`).
4. On its own goroutine, calls `SessionManager.CloseSession` with that reason. The close blocks on the session's drain and on the bounded `session_ended` post, and the SSE stream dispatches its handlers one after another, so it does not run on the SSE goroutine. The `session_ended` row goes out through the on-closed callback like that of any other close. The handler logs Info `session_revoked closed the session` (`session_id`, `revoke_reason`, `terminated_by`), or Info `session_revoked names no live session; nothing to close` (`session_id`, `revoke_reason`) when the drain or a local timer closed the session first, or it was never provisioned on this node.
5. Triggers the reconcile only after the close returned, so the pull it starts cannot drain the session first and report it as `plexd_close`.

The event and the drain race. A pull that drains the entry before the event
arrives closes the session as `drained` and reports `plexd_close`, and a session
whose capped local expiry fires first reports `ttl_expired`; either way the late
event finds no live session and only triggers a pull.

The envelope verifier keeps no nonce, so a captured `session_revoked` can be
replayed. A replay can only name a session the control plane already revoked,
which never becomes live again, so it finds nothing to close and only triggers a
pull. A replayed `session_connect` makes the node open a connection the control
plane refuses with `404 session_connection_not_found` once the request expired,
and a login on any connection still needs the session token.

Neither `session_setup` nor `session_revoked` is required for correctness: a
node that misses one converges on its own reconcile cadence, and the drain in
the `sessions` block tears down a revoked session whose event never arrives.
`session_setup` exists only to shorten the window; `session_revoked` also
shortens it, and lets the node report why the session ended. `session_connect`
is different: an ssh session serves logins only on the connections it asks for,
so a missed event is an attach that fails, and the client attaching again is
the recovery.

### Control Plane API (`internal/api`)

The node agent reports session activity, and opens the connections of its ssh
sessions, via two methods of `api.ControlPlane`:

| Method                  | Endpoint                             | When Called                                                            |
|-------------------------|--------------------------------------|------------------------------------------------------------------------|
| `ReportSessionActivity` | `POST /v1/nodes/{id}/sessions/{sid}` | Session ready (`session_started`), at most once per interval while a tcp tunnel forwards bytes (`session_active`), session close (`session_ended`), and around every ssh `exec` (the two command rows) |
| `OpenSessionConnection` | `GET /v1/nodes/{id}/sessions/{sid}/connections/{cid}` (WebSocket upgrade) | A verified `session_connect` event names a connection of a live ssh session (see [Listener](#listener)) |

### WireGuard Mesh (`internal/wireguard`)

The listeners of tcp sessions bind to the mesh IP assigned by the WireGuard interface. Connections arrive through the encrypted mesh — no ports are exposed on the public network. The `meshIP` parameter in `NewSessionManager` comes from `registration.NodeIdentity.MeshIP`, threaded through `NewMeshServer(cfg, meshIP, hostKey, verifier, logger)`. An ssh session binds nothing on the mesh: its connections are the ones plexd opens to the control plane (see [Listener](#listener)).

That bind address is the whole of a tcp listener's reachability boundary:
the forward itself performs no authentication, accepting the first connection
that arrives. The address is copied verbatim from the control plane's
registration response into `identity.json`, so `CreateSession` parses it rather
than trusting it and refuses to provision a tcp session unless it is a bindable
unicast address — on an empty, unparseable, or unspecified value (`0.0.0.0`,
`::`) `net.Listen` would bind every unicast address on the host and publish a
forward to an internal service on the node's public and LAN interfaces.

::: warning Trust boundary
Reaching a tcp session's listener means being routable to the node's mesh IP, which
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
4. Connections arriving on that listener are forwarded through the encrypted mesh to the target host and port. plexd reports the traffic as it flows, in `session_active` rows, at most one per interval, so the control plane does not revoke the session as idle while the tunnel is in use; a quiet tunnel posts nothing (see [Activity Reports](#activity-reports)).
5. The session ends when the control plane drops the entry from the block (`plexd_close`), when a verified `session_revoked` event names it (`operator_revoke` for an operator-driven `revoke_reason`, `ttl_expired` or `idle_timeout` for the sweeper's), when its capped expiry fires (`ttl_expired`), when its idle window elapses (`idle_timeout`), or on node shutdown (`plexd_close`). The `session_ended` row carries the byte counters and the reason.

### Kubernetes Sessions

`k8s` entries are part of the `sessions` contract and plexd decodes them, but
**this agent provisions no listener for them**: each is settled with a single
`unsupported session kind; no listener provisioned` warning and produces no
activity row, so there is nothing to tear down when the entry later drains. No
kube-apiserver proxy contract exists yet. `ssh` entries get the same treatment on
Windows.

## SSH Sessions

On Linux and macOS, an `ssh` entry of the `sessions` block becomes an SSH-2
session listener that a client logs in to with the session's token, as the
`## SSH session listener` section of plexsphere's agent contract specifies.
Windows settles `ssh` entries as unsupported. A node owner refuses ssh sessions,
and keeps serving tcp ones, with `tunnel.ssh_sessions_enabled: false`.

### Listener

An ssh session's listener binds no port and needs no mesh address. The control
plane asks for each connection with a signed `session_connect` event, and plexd
opens that connection out to the control plane over HTTPS, the path its event
stream and its state pull already take, so no port opens on the node and the
session does not depend on the WireGuard data plane. `Start` logs
`ssh session ready`, and the session's started row is
`{"ssh":{"phase":"session_started"}}`: the session is ready to serve.

A connection opens in this order:

1. A client (the console's browser terminal or `plexctl ssh`) attaches to the session, and the control plane publishes a signed `session_connect` event to the node hosting it. It sends the event only for a session whose newest lifecycle row is `session_started`. The payload, an `api.SessionConnectRequest`, names the `session_id`, a one-time `connection_id`, and `expires_at`, the instant the control plane stops accepting the connection.
2. `Dispatcher.SessionConnectHandler` decodes the payload. One that does not decode, an absent payload included, returns `tunnel: session_connect payload: <cause>`, and a `null` payload, an empty `session_id` or an empty `connection_id` returns `tunnel: session_connect payload names no connection: session_id or connection_id is empty`. The event dispatcher logs either at Error (`event handler failed`), and nothing opens. Otherwise the handler returns at once and does the rest on its own goroutine, because the SSE stream runs its handlers one after another. It never triggers a reconcile: the event carries no desired state.
3. The goroutine calls `SessionManager.ConnectSSHSession(session_id, connection_id, dial)`, which refuses before `dial` runs when tunneling is off (`ErrTunnelingDisabled`), off Linux and macOS (`ErrSSHSessionsUnsupported`), under `ssh_sessions_enabled: false` (`ErrSSHSessionsDisabled`), when no live session has the id (`ErrSessionNotLive`, `tunnel: no live session with this id`), when the live session is not an ssh session (`ErrNotSSHSession`, `tunnel: the session is not an ssh session`), and when the session is at its connection limit (`ErrSSHConnectionLimit`, `tunnel: the ssh session is at its connection limit`).
4. `dial` calls the handler's `SessionConnector`, which `plexd up` backs with `api.ControlPlane.OpenSessionConnection`: a WebSocket to `GET /v1/nodes/{node_id}/sessions/{session_id}/connections/{connection_id}` with the node's NSK bearer, through the API client every other call uses (see [the route](../core/api-endpoints.md#get-v1-nodes-node-id-sessions-session-id-connections-connection-id)). The dial runs under `sessionConnectTimeout`, 15 s, which equals `sessionStartedReportTimeout` for the same reason: it covers the TCP connect, the TLS handshake and the upgrade, and stays above `api.DefaultConnectTimeout`. The timeout bounds the dial only, and the connection lives until it closes. A dial error comes back as `tunnel: open session connection: <cause>`.
5. The session serves its SSH login on the connection. Each binary message carries raw SSH bytes, and the control plane splices the client onto the node's socket, so SSH runs end to end between the client and plexd.

- A session holds at most 4 concurrent connections, and a dial in flight holds one of those slots, so a burst of events cannot open more sockets than the limit allows: an event beyond the limit is refused before its dial, and a dial that fails frees its slot. Each connection holds at most 10 open session channels (an eleventh is rejected with `resource shortage`). A handshake has 30 s, and a connection 3 authentication attempts.
- plexd does not judge `expires_at` against its own clock. The envelope verifier admits envelopes up to 5 minutes off while the control plane waits 10 s by default, so a node clock a few seconds ahead would drop every request. The control plane refuses a late connection with `404 session_connection_not_found`, which plexd logs.
- A failed open is not retried. Each attach mints a new `connection_id` and the control plane waits only for its own window, so the user attaching again is the recovery.
- Closing the session cancels a dial in flight, and a dial that returns a connection after the session closed gets that connection closed. Closing a connection never blocks its caller: the WebSocket close handshake, which waits up to 5 s for each close frame, runs on its own goroutine, so the session's close stays within its drain bound.
- The control plane pings every connection every 30 s. The pings are answered inside the connection and are not activity (see [Idle Enforcement](#idle-enforcement)).
- A connection's log lines name its `connection_id` instead of a remote address: the peer is always the control plane, and a dialed WebSocket reports no address of its own.
- It presents the node's SSH host key (`ssh_host_ed25519_key` in the data dir), whose fingerprint the capability manifest carries. Clients do not pin it (contract §d): the control plane accepted the connection from this node's NSK, and the token authenticates the pair.
- It identifies as `SSH-2.0-plexd`.
- The mesh `SSHServer` (`tunnel.ssh_listen_addr`) is a separate server that keeps serving `direct-tcpip`.

The handler logs exactly one line for each event it accepted, carrying
`session_id` and `connection_id`:

| Outcome | Level | Log line |
|---------|-------|----------|
| The connection opened and serves the session's login | Info | `session connection opened` |
| `ErrSessionNotLive`: no live session has the id, or the session closed before the dial | Info | `session_connect names no live ssh session; not connecting` |
| `ErrTunnelingDisabled`, `ErrSSHSessionsDisabled`, `ErrSSHSessionsUnsupported`, `ErrNotSSHSession` or `ErrSSHConnectionLimit` | Warn, with `error` | `session_connect cannot be served on this node; not connecting` |
| The session closed while the connection opened, and plexd closed the connection | Info | `session closed while its connection opened; closed the connection` |
| Any other error, which is a failed open | Warn, with `error` | `session connection to the control plane failed` |

A refused upgrade comes back as an `*api.APIError`, so the `error` of a failed
open names the status and the problem code: `403 nsk_node_mismatch`,
`404 session_connection_not_found`, `409 session_not_active`,
`426 upgrade_required`, `501 access_attach_not_provisioned` or
`502 session_connection_forward_failed`.

### Authentication

The client logs in as the entry's `target.ssh.user`, with the session token as
password; password is the only method offered. `VerifySessionToken` checks the
token against the keys the envelope verifier trusts at that moment: the current
signing key (registration's, or the one a later state pull or
`signing_key_rotated` event installed), plus the previous one during a
rotation's grace window. A pulled key that differs from the current one replaces
it and ends any grace window, because a node trusts exactly one key of its
Domain. The checks run in this order:

1. at most 8192 bytes of three raw-base64url segments whose header and claims are JSON objects
2. `alg` is `EdDSA`; `kid` is not consulted, since the contract binds the key and not its id
3. the Ed25519 signature
4. `kind` and `target.kind` are both `ssh`
5. `jti` is the session id
6. `nbf <= now < exp`, where a missing `exp` counts as expired; there is no clock-skew leeway
7. `target.user` is the login user

A refusal fails the handshake and is logged at Warn (`ssh login refused`). No log
line and no error carries the token. `iss` and `aud` are not checked.

### Requests

| Request | Answer |
|---------|--------|
| `session` channel | Accepted; one process per channel, except that a channel attached to the kept shell holds no process of its own |
| Any other channel type (`direct-tcpip`, `x11`, `auth-agent@openssh.com`) | Rejected with `administratively prohibited` |
| Global requests | `shell-state@plexsphere.com` is answered as [Kept shell](#kept-shell) describes. Every other one, `tcpip-forward` among them, is refused |
| `pty-req` | Allocates a pty sized from the request; terminal modes are ignored. Refused once a process started or a pty exists. A failed allocation answers false, and a later `shell` or `exec` runs without a pty |
| `window-change` | Resizes the pty, the kept shell's only while the channel is attached to it. The size it sets is the one a later reattach applies |
| `shell` | With a granted `pty-req`, starts the session's kept shell or reattaches to it; without one, starts the user's login shell bound to the channel. Refused when the token lists allowed commands |
| `exec` | Runs the command through the user's shell. Refused when it is empty, over 1024 bytes, or, under a non-empty allowed-command list, not byte-equal to one of its entries |
| `env`, `subsystem` (`sftp` included), `x11-req`, `auth-agent-req@openssh.com`, `signal`, anything else | Refused |

The allowed-command list comes from the verified token's `target` claim, not from
the pull entry, so the list plexd checks is the list the session helper enforces.

### Kept shell

An ssh session keeps one interactive shell on the node for as long as the
session lives, outside the connection that started it, and attaches a later
connection of the same session to that running shell. A closed browser
terminal, a reloaded page, a dropped network or an interrupted `plexctl ssh` no
longer ends the work running in it. plexd implements the agent side of the
kept-shell contract as plexsphere/plexsphere#948 defines it:

1. An interactive shell is a `shell` request on a channel whose `pty-req` plexd granted. The first one on a live session starts the session's kept shell, and a session has at most one: plexd serves the interactive `shell` requests of all its connections one at a time. A `shell` without a granted `pty-req`, and every `exec`, stay bound to their channel: closing the channel stops them, and nothing reattaches to them. A session whose token lists allowed commands refuses `shell`.
2. While the kept shell runs, a later interactive `shell` on any connection of the session reattaches to it. plexd applies that request's `pty-req` rows and columns to the shell's pty and ignores its terminal type and modes, so the shell keeps the `TERM` it started with. plexd writes the most recent output the shell produced, at most the last 65,536 bytes, to the channel, then relays live output, and answers the `shell` request with success. No output is lost or doubled between the replay and the live output. The attachment is recorded before the answer, so a `shell-state@plexsphere.com` request sent right after the answer finds it.
3. When a channel on another connection is attached to the kept shell at that moment, plexd first sends that older connection the global request `shell-taken-over@plexsphere.com` with `want_reply` false and an empty payload (RFC 4254 section 4). It then closes that connection, and only then answers the new `shell` request. The closed connection gives its slot of the four-connection limit back.
4. When the attached channel or its connection ends for any other reason, plexd logs `ssh kept shell detached`, and the shell keeps running with no client attached. Its output goes into the 64 KiB replay buffer, as it does while a client is attached.
5. plexd answers the global request `shell-state@plexsphere.com` (`want_reply` true, empty payload; plexd ignores the payload) with `SSH_MSG_REQUEST_SUCCESS` carrying exactly one SSH `string` (RFC 4251 section 5): `started` when a channel of this connection started the kept shell and is attached to it, `reattached` when a channel of this connection reattached and is attached. Every other case answers failure: no `shell` yet, a shell without a pty, an `exec`, a session whose token lists allowed commands, a channel that detached, a shell that exited.
6. The kept shell ends in three ways:
   - It exits on its own. The attached channel, if there is one, gets `exit-status` as a channel-bound shell's does, and a launch error reaches it as a `plexd: <error>` stderr line with exit status 1. The next interactive `shell` starts a new kept shell with an empty buffer.
   - The session closes, for any reason: the entry drains, `expires_at` passes, the idle window elapses, a `session_revoked` event names it, or plexd shuts down. The helper sends `SIGHUP` to the shell's process group and `SIGKILL` 2 s later, as for every process, and the kept shell does not change the `session_ended` row's `terminated_by`.
   - plexd stops. A kept shell does not survive a restart: the session helper stops the shell once plexd's connection to it closes, which plexd's exit does.
7. Only SSH bytes on a connection are activity, as for every ssh session. A detached shell's output is not, so a session whose shell no client reattached within `idle_timeout_seconds` closes with `idle_timeout`.

plexd sends the takeover's global request on its own goroutine and waits for it
at most `drainTimeout`, 2 s, before it closes the older connection, so an older
connection whose transport no longer drains, on a dropped network for instance,
cannot hold up the new client. plexd sends no `SSH_MSG_DISCONNECT`, because
`golang.org/x/crypto/ssh` has no API that sends one: the global request is
followed by the close, and the WebSocket under the connection closes with status
`1000`. plexd logs `ssh kept shell taken over` with the new connection's
`connection_id` and the older one's `previous_connection_id`. The request is
best effort during a key re-exchange: `golang.org/x/crypto/ssh` holds a packet
sent then until the exchange completes, and the close that follows ends the
exchange, so the older client sees the close alone.

When the attached channel belongs to the connection that sends the new
interactive `shell`, plexd closes that older channel without `exit-status`,
sends no global request, keeps the connection open, and reattaches the new
channel. Rule 3 covers another connection only, and closing the requester's
connection would end its own new channel. The `ssh kept shell taken over` line
then carries the same id as `connection_id` and `previous_connection_id`.

Five more rules keep one connection from holding the others up:

- While a channel's interactive `shell` request waits for its turn, plexd keeps reading that channel's other requests and answers them after the `shell` request, in the order they came: replies carry no id, so a client matches them to its requests by order. `golang.org/x/crypto/ssh` queues at most 16 requests per channel and reads the whole connection on one loop, so a channel whose requests went unread would stall its connection. Each `window-change` that wants no reply replaces the one before it. A channel that sends more than 64 requests meanwhile has its connection closed, and plexd logs `ssh channel sent too many requests while its shell request waited; closing the connection` at Warn.
- A `shell` request whose channel closed while it waited is refused (`ssh request refused`, reason `the channel closed`).
- The shell counts as exited as soon as its process is gone, while its last output may still be on the way to the attached channel. An interactive `shell` in that moment starts a new kept shell instead of taking the old one over, and the attached channel still gets the exit status.
- A `shell` request that waited for the session's turn on a connection a takeover closed meanwhile, or one that ended, is refused (`ssh request refused`, reason `the connection is closing`), so it cannot take the shell from the connection that just took it.
- Once the takeover is done, plexd writes the replay and the answer to the requesting connection. A connection that does not take them within `drainTimeout`, 2 s, is closed, and plexd logs `ssh kept shell request not answered within the drain bound; closing the connection` at Warn. The next interactive `shell` then proceeds.

A connection attached to the kept shell gives its slot back as soon as it ends.
A channel-bound process keeps its connection's slot until the process is gone,
so that a client that hangs up cannot start more processes than the limits
allow. The kept shell belongs to the session, at most one runs, and a reconnect
reattaches to it, so the same bound holds without the slot.

The replay buffer lives in plexd's memory only, never on disk: at most 65,536
bytes per session, freed when the shell ends, and `tunnel.max_sessions` bounds
the sessions. No log line carries the replay or any other output byte. plexd
keeps reading a detached shell's output into the buffer, so a shell that never
stops printing costs CPU until the session closes, which the idle window bounds
for a session that has one.

### Commands and activity rows

The session posts two lifecycle rows, `{"ssh":{"phase":"session_started"}}`
when it is ready to serve and `{"ssh":{"phase":"session_ended","terminated_by":"…"}}`
on close, and two command rows per `exec`. A shell posts no command rows.

An `exec` fails closed. plexd first posts the command row
`{"ssh":{"command":"…","started_at":"…"}}` and runs the command only once the
control plane accepted it. When the post fails, the client's stderr reads
`plexd: the control plane did not record this command; it was not run: <error>`
and the exit status is 1; a `409` `session_already_revoked` or `session_expired`
also closes the connection. After the command exits plexd sends its `exit-status`
and posts the command row again with `exit_code`, `started_at` and
`completed_at`. A lost exit row is logged at Warn and leaves the client's exit
status as it was. A launcher error reaches the client as a `plexd: <error>`
stderr line with exit status 1.

### Session helper

On Linux, plexd's unit bounds it to `CAP_NET_ADMIN CAP_NET_RAW` and hides `/home`, so a shell
plexd forked could not become the login user. Every process therefore starts in
the session helper, `plexd session-helper`:

- When `/run/plexd-session-helper.sock` exists, plexd connects to it. The `plexd-session-helper.socket` unit (`Accept=yes`) then starts one root instance of `plexd-session-helper@.service` per connection, outside plexd's sandbox. A connection the socket refuses is an error: plexd never falls back to a child helper there, because that would run the shell inside the sandbox.
- Without the socket, plexd starts its own binary as `plexd session-helper --child --trusted-key <key>…` over a socketpair, trusting the keys plexd trusts. The child has plexd's own privileges, which is no boundary, so it pins nothing; hosts without a sandbox (OpenWrt, containers) need no extra unit. Under systemd plexd warns once that the socket is not listening, since shells then cannot switch users.

On macOS there is no helper socket. plexd always starts its own binary as
`plexd session-helper --child --trusted-key <key>…` over a socketpair, trusting
the keys plexd trusts. plexd runs as root under launchd with no sandbox, so the
child switches users itself, and its token check is a consistency check, not a
boundary. When plexd runs as the launchd daemon, the child's log lines go
through the same writer as plexd's own, to `/Library/Logs/plexd/plexd.log`, so
they follow a newsyslog rotation.

The protocol is one request per connection. plexd sends one JSON line of at most
16 KiB, with the process's file descriptors as `SCM_RIGHTS`: the pty slave, or
stdin, stdout and stderr. The helper answers with one JSON line,
`{"exit_status":N}` or `{"error":"<reason>"}`, and closes. plexd closing its end
means "stop the process".

Whatever plexd checked, the helper:

1. verifies the token again: the socket-activated helper against its own trust anchor, a child helper (always on macOS) against the keys plexd passed it;
2. enforces the allowed-command list and the mode rules;
3. resolves the user:
   - on Linux from `/etc/passwd`, with supplementary groups from `/etc/group`; NSS sources such as LDAP are not consulted, and an empty shell field means `/bin/sh`;
   - on macOS from the local directory node, with `dscl -plist . -read /Users/<name> RecordName UniqueID PrimaryGroupID NFSHomeDirectory UserShell`. A name that is empty, `.`, `..` or contains `/` is refused before `dscl` runs. `dscl` also finds a record by any of its names and in any case, so the name must be the record's first `RecordName` exactly: `ROOT`, or `www` for `_www`, is refused as not existing. An account absent from the local node, such as an Active Directory or Open Directory network account, is refused as not existing. A missing `UserShell` means `/bin/sh`. Supplementary groups come from `getgrouplist`, and at most the first 16 apply (macOS's `NGROUPS_MAX`);
4. starts a login shell, or `<shell> -c <command>`, as that user in a new session and process group, in the home directory, with exactly `HOME`, `USER`, `LOGNAME`, `SHELL` and `PATH` in the environment, plus `TERM` with a pty, which it first hands to that user, as sshd does;
5. sends `SIGHUP` to the process group when plexd hangs up, and `SIGKILL` 2 s later;
6. once the process exits, kills what is left of its group and answers with the exit code, or 128 plus the signal for a death by signal.

No PAM session, no utmp, wtmp or lastlog record and no resource limit apply: plexd
links no libpam.

### Trust anchor

This section applies to Linux's socket-activated helper. On macOS the child
helper trusts the keys plexd passes and pins nothing, and
`tunnel.session_signing_public_key` is not read.

The socket-activated helper verifies tokens against one key:

1. `tunnel.session_signing_public_key` in `/etc/plexd/config.yaml`, when set; the pin file is then neither read nor written;
2. otherwise the key pinned at `/etc/plexd/session-signing-key`. On its first run the helper copies `signing_public_key` from `identity.json` there (mode 0644) and logs `pinned the session signing key` with the key's SHA-256; later runs trust only that file.

Both units make `/etc` read-only for plexd, so a compromised plexd cannot replace
the anchor, and without a token the control plane signed it cannot start a shell.
A malformed pin fails every login until it is fixed. The helper does not follow
signing-key rotations: once the Domain key rotates, it refuses every token until
an operator sets `tunnel.session_signing_public_key` to the new key or deletes
the pin. plexd rewrites `identity.json`'s signing key whenever a state pull
carries a new one, so a helper that has not pinned yet pins the key plexd last
persisted, and deleting the pin makes the next run pin that key. The same holds
once the node re-registers with another Domain: `plexd deregister` leaves the pin
in place, so set the new Domain's key there as well.

The trust model does not move: plexd could always rewrite its own
`identity.json`, and the boundary is the pin in read-only `/etc`. plexd logs each
key a state pull installs at Info as `installed signing key from state pull`,
with `key_id` and `public_key`; that `public_key` is the value to set in
`tunnel.session_signing_public_key`.

::: warning Nodes enrolled before the per-Domain signing key
A node enrolled before
[plexsphere/plexsphere#918](https://github.com/plexsphere/plexsphere/pull/918)
stored a static signing key that no signer holds, and a helper that ran before
plexd persisted the Domain key pinned that key. plexd learns the Domain key from
the state pull and accepts the login, but the helper refuses every shell and
command: the client's stderr reads
`plexd: tunnel: session helper refused: token refused: tunnel: session token: signature does not verify against a trusted key`.
Set `tunnel.session_signing_public_key` to the `public_key` of plexd's
`installed signing key from state pull` log line, or delete
`/etc/plexd/session-signing-key` so that the next run pins the key plexd
persisted. Delete the pin only once plexd has persisted the key, that is, once
it no longer logs `signing key not persisted; retrying on the next pull`.
:::

### Lifetime

An ssh session ends like a tcp one: when its entry drains (`plexd_close`), when a
verified `session_revoked` event names it (`operator_revoke` for an
operator-driven `revoke_reason`, `ttl_expired` or `idle_timeout` for the
sweeper's), when its capped expiry fires (`ttl_expired`), when its idle window
elapses (`idle_timeout`), or on shutdown (`plexd_close`). Any SSH byte on any of
its connections is activity; WebSocket pings are not. The close ends every connection within the drain bound
and stops each running process through its helper, the kept shell included,
whether or not a client is attached to it; under socket activation systemd also
kills the instance's cgroup. A restart of plexd ends the kept shell as well (see
[Kept shell](#kept-shell)).

The helper cannot see the sessions block, so it cannot honour a revocation: a
compromised plexd can reuse a token a client presented until that token's `exp`.
The listener itself closes on the drain, or earlier on a verified
`session_revoked` event.

### Deployment notes

- A Linux host installed before the helper units keeps its old `plexd.service` until `plexd install` runs again; `service.upgrade` does not rewrite units. Until then plexd uses the child helper and warns, and every login as a user other than root fails. `plexd install` writes the units and reloads systemd but neither enables nor starts the socket, so run `plexd install && systemctl restart plexd`: plexd pulls the socket in through `Wants=` when it starts.
- Nodes without a usable shell, such as the distroless Kubernetes DaemonSet and container images, should set `tunnel.ssh_sessions_enabled: false`: their listeners would come up, and every launch would fail.
- An ssh session needs no WireGuard data plane. It binds nothing on the mesh, so a node whose WireGuard setup failed or never ran, such as an agent in a Pod without `NET_ADMIN` and with `policy.enabled: false`, serves it too. Its connections leave the node as outbound HTTPS to the control plane, one WebSocket per open terminal.
- A node on this release behind a control plane that predates plexsphere/plexsphere#928 serves no ssh login: the session comes up and posts its `session_started` row, but nothing asks for a connection, and there is no fallback mesh listener for a client on a mesh-joined machine.
- On macOS the pf policy governs mesh traffic addressed to the node itself and ends in a default deny (see [What the rules govern](./pf-wfp-firewall.md#what-the-rules-govern)). A tcp session's listener is therefore reachable only where the node's compiled policy allows inbound mesh TCP to the node. Otherwise the `session_started` row is posted, but clients time out. plexd opens no port itself. An ssh session is not affected: its connections are outbound.
- macOS privacy protection (TCC) may keep processes plexd starts from reading protected folders such as Desktop, Documents and Downloads, unless plexd has Full Disk Access. Grant it in System Settings or through an MDM privacy profile.
- On macOS an `exec` runs with `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, so Homebrew's `/opt/homebrew/bin` is not on it. A login shell rebuilds `PATH` through `/etc/zprofile` (`path_helper`).
- A Mac upgraded to this release serves ssh sessions unless it sets `tunnel.ssh_sessions_enabled: false`.

## Logging

All log entries use `component=tunnel`. Session-scoped entries add `session_id`.

| Level   | Event                          | Keys                                        |
|---------|--------------------------------|---------------------------------------------|
| `Info`  | Session started                | `listen_addr`, `target`                     |
| `Info`  | Session created                | `session_id`, `kind`, `expires_at`, and `listen_addr` for a tcp session |
| `Info`  | Session closed                 | `session_id`, `kind`, `reason`, `duration`  |
| `Debug` | session_active row recorded    | `session_id`                                |
| `Info`  | session no longer live server-side; stopping its activity reports | `session_id`, `error` |
| `Warn`  | control plane refused the session_active row; it revokes the tunnel one idle timeout after it started | `session_id`, `error`; on the session's first `400` only |
| `Warn`  | session activity report failed; retrying at the end of the interval | `session_id`, `error` |
| `Info`  | ssh session ready              | `user`                                      |
| `Info`  | session connection opened      | `session_id`, `connection_id`               |
| `Info`  | session_connect names no live ssh session; not connecting | `session_id`, `connection_id` |
| `Info`  | session closed while its connection opened; closed the connection | `session_id`, `connection_id` |
| `Warn`  | session_connect cannot be served on this node; not connecting | `session_id`, `connection_id`, `error` |
| `Warn`  | session connection to the control plane failed | `session_id`, `connection_id`, `error` |
| `Info`  | ssh login accepted             | `connection_id`, `user`                     |
| `Info`  | ssh request refused            | `request`, `reason`                         |
| `Info`  | ssh process exited             | `mode`, `exit_status` (a number, never a signal name) |
| `Info`  | ssh kept shell started         | `connection_id`                             |
| `Info`  | ssh kept shell reattached      | `connection_id`, `replay_bytes`             |
| `Info`  | ssh kept shell taken over      | `connection_id`, `previous_connection_id` (equal when the attached channel was on the same connection) |
| `Info`  | ssh kept shell detached        | `connection_id`                             |
| `Info`  | ssh session revoked or expired server-side; closing the connection | — |
| `Info`  | ssh session closed             | `duration`                                  |
| `Warn`  | ssh login refused              | `connection_id`, `user`, `error`            |
| `Warn`  | ssh pty allocation failed      | `error`                                     |
| `Warn`  | ssh kept shell request not answered within the drain bound; closing the connection | `connection_id` |
| `Warn`  | ssh channel sent too many requests while its shell request waited; closing the connection | `connection_id` |
| `Warn`  | ssh command not recorded by the control plane; refusing to run it | `command`, `error` |
| `Warn`  | ssh command exit not recorded  | `command`, `exit_code`, `error`             |
| `Warn`  | ssh session launch failed      | `mode`, `error`                             |
| `Warn`  | ssh sessions are disabled on this node; no listener provisioned | `session_id` |
| `Warn`  | plexd-session-helper.socket is not listening; ssh sessions run inside plexd's own sandbox and cannot switch users | `socket` |
| `Warn`  | Timed out waiting for ssh handlers to drain | —                              |
| `Debug` | ssh handshake failed           | `connection_id`, `error`                    |
| `Debug` | ssh request not served         | `request`                                   |
| `Info`  | All tunnel sessions closed     | —                                           |
| `Info`  | Session expired; waiting for the control plane to drain the entry | `session_id`, `kind`, `expires_at` |
| `Warn`  | Session carries no expires_at; refusing to provision | `session_id`, `kind`   |
| `Warn`  | Unsupported session kind; no listener provisioned | `session_id`, `kind`      |
| `Warn`  | Session target does not match kind | `session_id`, `kind`                    |
| `Warn`  | Tunneling is disabled; no listener provisioned | `session_id`                |
| `Warn`  | Session listener setup failed  | `session_id`, `error`                       |
| `Info`  | Session was revoked by a signed event; not provisioning it | `session_id`      |
| `Info`  | Session was revoked by a signed event while its listener came up; closing it | `session_id` |
| `Info`  | session_revoked closed the session | `session_id`, `revoke_reason`, `terminated_by` |
| `Info`  | session_revoked names no live session; nothing to close | `session_id`, `revoke_reason` |
| `Warn`  | session_revoked carries an unrecognised revoke_reason; reporting operator_revoke | `session_id`, `revoke_reason` |
| `Debug` | Connection rejected (duplicate)| —                                           |
| `Debug` | Session not found for close    | `session_id`                                |
| `Error` | Session entry carries no session_id; dropping | `kind`                       |
| `Error` | Failed to dial target          | `target`, `error`                           |

The session helper logs to its own unit's journal (`journalctl -u 'plexd-session-helper@*'`)
under socket activation. In child mode it logs to plexd's stderr, which on macOS
is the daemon log file (`/Library/Logs/plexd/plexd.log`) when plexd runs as the
launchd daemon. Its lines are text: `session helper started process`
(`session_id`, `user`, `mode`, `command`, `pid`), `session helper process exited`
(`session_id`, `exit_status`) and `pinned the session signing key` (`path`,
`sha256`) at Info, and `session helper refused a request` (`session_id`,
`reason`) at Warn.
