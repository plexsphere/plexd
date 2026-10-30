---
title: NAT Relay
package: internal/bridge
feature: PXD-0012
---

# NAT Relay

The NAT relay extends bridge mode (`internal/bridge`) to forward WireGuard between two peers that cannot reach each other directly, such as two nodes behind symmetric NATs. A bridge relays when both its local config and its state pull allow it. It listens on the UDP port the pull names and forwards among the peers the same pull lists. It works out each datagram's destination from the WireGuard message header: a handshake initiation goes to the peer whose public key verifies its `mac1`, and every other message goes by its receiver index. The relay does not need to know either peer's public address in advance. It holds no private or preshared key, decrypts nothing and never answers a datagram.

## Data Flow

```
Peer A                                                        Peer B
(behind NAT)                                            (behind NAT)
    │  WireGuard datagram                  WireGuard datagram  ▲
    ▼                                                           │
┌──────────────────────────────────────────────────────────────────┐
│                       Bridge Node (Relay)                        │
│                                                                  │
│  ┌─────────────────┐   ┌────────────────┐   ┌─────────────────┐  │
│  │ UDP socket      │──▶│ parseWGMessage │──▶│ handshake:      │  │
│  │ (pulled         │   │ type, sender   │   │   CheckMAC1 per │  │
│  │  listen_port)   │   │ and receiver   │   │   listed peer   │  │
│  └─────────────────┘   │ index          │   │ every message:  │  │
│           ▲            └────────────────┘   │   indices table │  │
│           │                                 └────────┬────────┘  │
│           │           dispatch loop                  │           │
│           └──────────────────────────────────────────┘           │
│                                                                  │
│  state pull ──▶ RelayReconcileHandler ──▶ Configure / Stop       │
│  (bridge.relay, peers)                                           │
└──────────────────────────────────────────────────────────────────┘
```

1. A node dials the relay as the last entry of a peer's [dial order](../networking/wireguard.md#dial-order): the peer's `fallback_endpoint`, which the control plane points at a bridge that relays.
2. The relay reads every datagram from one UDP socket, bound on the `listen_port` of the bridge's state pull, and classifies it by its WireGuard header (see [Message Classification](#message-classification)).
3. It finds the destination: for a handshake initiation, the listed peer whose public key verifies the message's `mac1`; for every other message, the peer that owns the message's receiver index. It learns each peer's current address from the handshake and transport messages that peer sends.
4. It writes the datagram unchanged to that address from the same socket.

The reconcile loop drives the relay. On each pull that shows drift, the pull's `bridge.relay` block and `peers` list reach [`RelayReconcileHandler`](#relayreconcilehandler), which calls `Configure` or `Stop`.

## Consent

The relay listens only when both of these allow it:

| Switch | Source | Meaning |
|--------|--------|---------|
| `bridge.relay_enabled` (`Config.RelayEnabled`) | Local config file | The operator's consent. Default `false`. Requires `bridge.enabled: true`, otherwise validation fails with `bridge: config: relay requires bridge mode to be enabled`. Without it, `NewManager` creates no relay and `Manager.Relay()` returns nil |
| `bridge.relay.enabled` | State pull | The control plane's request. The same block's `listen_port` names the UDP port the relay listens on |

The pulled `listen_port` is authoritative: there is no local port, default or override. A pull that enables the relay on a bridge without local consent logs a Warn and opens no socket (see [RelayReconcileHandler](#relayreconcilehandler)). The local keys for a relay port, a relay session cap and a relay session TTL are removed. A config file that still sets them keeps loading, and they have no effect; see [Configuration Reference](../core/configuration.md#bridge).

plexd does not check that `listen_port` differs from the bridge's `wireguard.listen_port`. When the two collide, the bind fails with `bridge: relay: listen on :<port>: … address already in use`, and every pull retries it.

```go
cfg := bridge.Config{
    Enabled:         true,
    AccessInterface: "eth1",
    AccessSubnets:   []string{"10.0.0.0/24"},
    RelayEnabled:    true, // local consent; the port comes from the state pull
}
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

## Relay

`Relay` (`relay.go`) owns the UDP socket, the peer set and the index table. The `Manager` creates it; the reconcile handler starts, reconfigures and stops it.

```go
func NewRelay(logger *slog.Logger) *Relay // opens no socket
func (r *Relay) Configure(listenPort int, peers []api.SnapshotPeer) error
func (r *Relay) Stop() error // idempotent
func (r *Relay) Running() bool
func (r *Relay) Bound() (port int, at time.Time, ok bool)
func (r *Relay) ActiveCount() int
func (r *Relay) ListenAddr() net.Addr
```

| Method        | Description |
|---------------|-------------|
| `Configure`   | Binds `listenPort` when needed and replaces the peer set with `peers`; see [Configure](#configure) |
| `Stop`        | Closes the socket and clears all state; see [Stop](#stop) |
| `Running`     | Whether a socket is bound |
| `Bound`       | The port the socket is bound on and when `Configure` bound it; `ok` is false while the relay is not running. A call that only changes the peers keeps both, and a new port rebinds with a new instant. The [relay status report](#relay-status-report) reads it |
| `ActiveCount` | The number of distinct unordered peer pairs among session indices used within the last 180 s (`relayIndexTTL`) |
| `ListenAddr`  | The local address of the bound socket; nil while the relay is not running |

### Configure

1. A `listenPort` outside 1..65535 fails with `bridge: relay: listen_port <port> out of range`, and nothing is bound.
2. When the relay runs on another port, `Configure` stops it first, which logs `relay stopped`.
3. When the relay is not running, `Configure` binds UDP on the dual-stack wildcard address, `net.ListenUDP("udp", &net.UDPAddr{Port: listenPort})`, so IPv4 and IPv6 peers reach the same socket. A bind failure is wrapped as `bridge: relay: listen on :<port>: <cause>`, and the relay stays stopped. On success it creates a fresh handshake rate limiter, starts the dispatch goroutine and the sweeper goroutine, and logs `relay started` with `listen_port`.
4. `Configure` replaces the peer set with `peers`:
   - A peer whose `node_id` and `public_key` are unchanged keeps the address the relay learned for it.
   - A new peer, or a peer whose `public_key` changed, gets a fresh entry with no address.
   - A peer no longer listed is deleted, together with every index that names it.
   - A `public_key` that is not standard base64 of 32 bytes is skipped with the Warn `relay: skipping peer with invalid public key` and the peer's `peer_id`.
   - A `public_key` that a second node ID repeats is skipped with the Warn `relay: skipping peer with duplicate public key` and that peer's `peer_id`.

   A skipped peer never fails the call. A repeated call with the same port and peers changes nothing and does not rebind.

### Stop

`Stop` closes the socket, ends the dispatch and sweeper goroutines, closes the rate limiter, clears every peer and index, and logs `relay stopped`. It is idempotent: on a relay that is not running it returns nil and logs nothing, so a repeated disable stays quiet. A relay restart loses all state, and WireGuard's next handshake rebuilds it.

### Concurrency

- One mutex guards the running socket, the peers and the indices. The dispatch loop takes it for every datagram that passes classification and the rate limit, and releases it before it writes.
- A second mutex serializes `Configure` and `Stop`, so bridge teardown and the reconcile loop never interleave a start with a stop.
- `Stop` releases the first mutex before it waits for the goroutines, because the dispatch loop takes it, and closes the rate limiter only after the dispatch loop has returned.

## SSE Event Handling

There are no relay-specific SSE handlers. The control plane emits a single
`bridge_config_updated` event with an opaque payload; `bridge.HandleBridgeConfigUpdated`
dispatches it to `TriggerReconcile()`, and the `RelayReconcileHandler` below
applies the relay block from the authoritative state snapshot.

```go
dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventBridgeConfigUpdated,
    bridge.HandleBridgeConfigUpdated(reconciler))
```

## RelayReconcileHandler

```go
func RelayReconcileHandler(relay *Relay, status *RelayStatusTracker, logger *slog.Logger) reconcile.ReconcileHandler
```

Returns a `reconcile.ReconcileHandler` that runs the relay the pull's `bridge.relay` block asks for. `relay` is nil when local consent, `bridge.relay_enabled`, is off. `status` must not be nil: the handler records in it the state each branch leaves behind, which the [relay status report](#relay-status-report) sends to the control plane.

| Desired snapshot | What the handler does | Status it sets |
|------------------|-----------------------|----------------|
| `nil` | Returns nil | None |
| `bridge` is `null`, `bridge.relay` is `null`, or `enabled` is `false` | Stops the relay and returns nil. Logs `relay disabled by the control plane` at Info when a relay was running, so a second such snapshot logs nothing | `stopped`, also when `relay` is nil or not running, so a relay whose last bind failed reads `stopped` once the pull disables it |
| `enabled: true`, `relay` is nil | Logs the Warn `relay: the control plane enables the relay, but bridge.relay_enabled is false` with `listen_port`, and returns nil | `not_consented` |
| `enabled: true`, `relay` is set | Returns `relay.Configure(listen_port, peers)`, with the `peers` of the same snapshot | From `relay.Bound()`: `running` on its port and bind instant when the relay runs; otherwise `bind_failed` on `listen_port` when `Configure` failed and `listen_port` is in 1..65535; otherwise `stopped` |

The last row covers three cases. A bind failure leaves the relay stopped, since `Configure` stops a relay on another port before it binds, so the relay reads `bind_failed` on the pulled port. An out-of-range `listen_port` fails before anything changes: a relay running on its old port keeps reading `running` on that port, and one that was not running reads `stopped`, because the contract refuses `bind_failed` without a valid port. The handler returns `Configure`'s error in every case.

A `Configure` error, such as a bind failure, fails the reconcile cycle. The reconciler then holds its snapshot back, so the next pull sees the same drift and calls the handler again (see [Reconciliation Cycle](../core/reconciliation.md#reconciliation-cycle)).

Reconcile handlers run only on a cycle with drift. The differ compares the bridge block with `reflect.DeepEqual`, so a change of `enabled`, `listen_port` or an assignment is bridge drift. Any other drift, a changed peer included, runs the handler too, so the relay's peer set follows the pull.

### Registration

`plexd up` registers the handler whenever bridge mode runs, passing `bridgeMgr.Relay()`, which is nil without local consent, and `bridgeMgr.RelayStatusTracker()`. It also starts the [relay status reporter](#reporter) on the same tracker, at `heartbeat.interval`:

```go
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.RelayReconcileHandler(bridgeMgr.Relay(), bridgeMgr.RelayStatusTracker(), logger))

reporter := bridge.NewRelayStatusReporter(statusInterval, nodeID, client, bridgeMgr.RelayStatusTracker(), logger)
go reporter.Run(ctx)
```

The relay opens no socket at startup. It starts on the first reconcile cycle whose pull enables it, and stops when a pull disables it or the bridge tears down. The reporter starts with bridge mode and sends nothing until the handler first ran.

## Forwarding

### Message Classification

`parseWGMessage(b []byte) (wgMessage, bool)` (`relay_wire.go`) classifies a datagram. `wgMessage` holds the message type, the sender index and the receiver index. A datagram is WireGuard when `b[1:4]` is zero and its type and length match one of these rows. Indices are little-endian `uint32`. The sizes are wireguard-go's constants from `golang.zx2c4.com/wireguard/device`.

| Type | Message      | Length | Sender index | Receiver index |
|------|--------------|--------|--------------|----------------|
| 1    | Initiation   | exactly 148 bytes (`MessageInitiationSize`) | `b[4:8]` | — |
| 2    | Response     | exactly 92 bytes (`MessageResponseSize`) | `b[4:8]` | `b[8:12]` |
| 3    | Cookie reply | exactly 64 bytes (`MessageCookieReplySize`) | — | `b[4:8]` |
| 4    | Transport    | at least 32 bytes (`MessageTransportSize`) | — | `b[4:8]` |

Every other datagram is dropped with reason `not_wireguard`.

A handshake message carries a `mac1` keyed to its receiver's public key. Each relay peer holds a `device.CookieChecker`, initialized once with `Init(device.NoisePublicKey(key))`, and the relay checks a message against a peer with the checker's `CheckMAC1(msg)`. That is wireguard-go's own `mac1` check: the relay does not reimplement BLAKE2s.

### State

One mutex guards two maps:

- `peers` maps a public key to `relayPeer{nodeID, checker, addr, seen}`: the peer's node ID, its cookie checker, its last learned address and when that address was last set.
- `indices` maps a `uint32` index to `relayIndex{pending, owner, partner, src, used}`. A pending index records an initiation that has no response yet; a session index belongs to a completed handshake.

Every source address is unmapped (`Addr().Unmap()`) before use, so an IPv4 peer reads the same on the dual-stack socket. A peer's address is fresh while its `seen` is younger than `relayIndexTTL`.

| Constant | Value | Meaning |
|----------|-------|---------|
| `relayFanoutWindow` | 30 s | How long a pending initiation stays a [fan-out](#first-contact) target; no longer than the 30 s Linux conntrack timeout for an unanswered UDP flow |
| `relayFanoutMax` | 8 | The most addresses one initiation fans out to |
| `relayIndexTTL` | 180 s | WireGuard's `RejectAfterTime`: no session outlives it without a new handshake. Also how long a learned address stays fresh |
| `relaySweepInterval` | 30 s | How often the sweeper runs |
| `relayMaxIndices` | 65536 (`1 << 16`) | The most live indices |

### Forwarding Table

| Message | Accepted when | Sent to | State change |
|---|---|---|---|
| Initiation | the rate limiter allows the source IP, and `CheckMAC1` succeeds for exactly one peer T | T's address when fresh. Otherwise every distinct `src` of a pending index younger than `relayFanoutWindow` that is neither this datagram's source nor any peer's fresh address, newest first, at most `relayFanoutMax` | `indices[sender] = pending{partner: T, src, used: now}`, replacing an existing entry |
| Response | the rate limiter allows the source IP, `indices[receiver]` is pending, and `CheckMAC1` succeeds for a peer I other than that pending entry's T | the pending entry's `src` | T's address := source, I's address := pending `src`, `indices[receiver] = session{owner: I, partner: T}`, `indices[sender] = session{owner: T, partner: I}` |
| Cookie reply | `indices[receiver]` exists | a pending entry's `src`, or a session owner's address | none |
| Transport | `indices[receiver]` is a session index whose owner has an address | the owner's address | the partner's address := source, `used` := now |

The relay never sends a datagram back to its own source: a computed destination equal to the source is skipped. A datagram whose only destination is its own source changes no state and is dropped with reason `no_route`. An initiation with no fresh target and an empty fan-out still records its pending index, so a later initiation can fan out to it, and is dropped with reason `no_route`.

Every datagram the table does not accept is dropped and never answered. The relay logs it at Debug as `relay: dropped datagram` with `source` and `reason`:

| Reason | Dropped datagram |
|--------|------------------|
| `not_wireguard` | Fails [classification](#message-classification) |
| `rate_limited` | An initiation or response from a source IP over the [handshake rate limit](#rate-limit-and-cost) |
| `unknown_target` | An initiation whose `mac1` verifies for no listed peer, or a response whose `mac1` verifies for no listed peer other than the pending entry's target |
| `unknown_index` | A response, cookie reply or transport message whose receiver index the relay does not hold, or does not hold as the kind of index the [table](#forwarding-table) requires |
| `no_route` | Accepted, but no destination is left: an initiation with no fresh target and an empty fan-out, a cookie reply or transport message whose index owner has no address, or a datagram whose only destination is its own source |
| `index_table_full` | Would record a new index while the table is still full after a sweep; see [Index Table and Sweeper](#index-table-and-sweeper) |

### First Contact

Two peers A and B behind symmetric NATs meet on the relay like this:

1. A's initiation for B reaches the relay. Its `mac1` names B, but B has no fresh address and no other initiator is pending. The relay records A's sender index as pending, with A's source as `src`, and drops the datagram with reason `no_route`.
2. B's initiation for A reaches the relay. A has no fresh address either, so the relay fans the initiation out to the sources of pending indices younger than 30 s, A's among them. A's WireGuard accepts it.
3. A's response names B's sender index as its receiver, and its `mac1` names B. The relay sends it to B's source, sets A's and B's addresses, and records B's index and A's new sender index as session indices.
4. From then on every transport message goes by its receiver index, one map lookup, to the address of the peer that owns the index.

A fan-out reaches at most 8 addresses, each of which sent a `mac1`-valid initiation within the last 30 s. Only the real target's WireGuard accepts the initiation, because `mac1` is keyed to the target's public key, and the target's response then teaches the relay both addresses.

### Address Learning

Setting a peer's address clears that address from any other peer that held it, sets the peer's `seen`, and logs `relay: peer address learned` at Info with `peer_id` and `address` when the address changed. A transport message from a new source moves its sender to that source: when a NAT rebinds A to a new public port, A's next transport message teaches the relay the new address, and B's traffic follows it.

### Rate Limit and Cost

A transport datagram, the bulk of relayed traffic, costs one map lookup. A handshake message costs one `CheckMAC1` per listed peer. The rate limiter bounds that scan: it is wireguard-go's `ratelimiter.Ratelimiter`, 20 handshake messages per second per source IP with a burst of 5, the limit WireGuard itself applies to handshakes. Initiations and responses pass through it. Each start creates and initializes a fresh limiter, and `Stop` closes it.

### Index Table and Sweeper

The sweeper runs every 30 s (`relaySweepInterval`). It deletes pending indices older than 30 s (`relayFanoutWindow`) and session indices unused for 180 s (`relayIndexTTL`). When 65536 indices (`relayMaxIndices`) are live, recording a new one first runs the sweep. If the table is still full, the datagram is dropped with reason `index_table_full`, and `relay: index table full` is logged at Warn at most once a minute.

### Dispatch Loop

The dispatch goroutine reads with `ReadFromUDPAddrPort` into one 65535-byte buffer, classifies and rate-limits the datagram, updates state under the mutex, and writes after releasing it, so it copies nothing.

- A read error that satisfies `errors.Is(err, net.ErrClosed)` ends the loop; `Stop` closes the socket this way.
- Any other read error is logged at Debug as `relay: read failed`, and the loop continues.
- A write error is logged at Debug as `relay: forward failed` with `dst` and `error`, and the next datagram is forwarded as usual.

## Meeting on the Relay

Two peers behind hard NATs connect only when both are on the relay at the same time. [Endpoint selection](../networking/wireguard.md#the-trial) therefore holds a peer's `fallback_endpoint`, when it ends the dial order, as long as the entries before it took together, so two such windows always overlap or touch.

A node does not wait for a relayed peer's handshake to turn 180 s old before it dials a relay again:

- When a pull names a new `fallback_endpoint` for a peer on the old relay, the node dials the new relay at once. A peer the node reaches from the relay's address, or that is not connected, counts as on the relay; a peer that opened a direct path while the relay entry was programmed keeps that path. With a hostname `fallback_endpoint` the node cannot compare addresses, so the programmed entry decides and such a peer moves too. It removes the device peer and adds it again, because the new relay would drop every packet of the old session with reason `unknown_index`. The fresh device peer has no session, so its next send starts a handshake over the new relay. Both nodes do this once their pulls name the new relay, and [First Contact](#first-contact) pairs their new initiations.
- A peer that runs over the relay, which the node tells from the relay's address on the peer's packets, is probed once it has received nothing for one trial, 30 s by default. The probe is one datagram through the tunnel, which the peer's WireGuard answers on a live path. When the received-byte counter still has not moved 15 s later, the node dials the relay again the same way. A relay that restarted and lost its [index table](#index-table-and-sweeper) carries the pair again within about a minute.
- Such a peer stays on the relay after its connection fails. The node dials the relay again, at once and after each hold without a handshake, and never goes back to the direct entries, which already failed. It tries them again only when a pull drops the `fallback_endpoint` or the peer, when the peer's key rotates, or after a restart. A peer that WireGuard roamed off the relay to a direct path no longer counts as on the relay, and walks its dial order again when that path fails.

See [Relay liveness probe](../networking/wireguard.md#relay-liveness-probe) for the timing.

Versions mix: a node on an older plexd dials the relay with the old 30 s trial and holds a relayed peer until its handshake is 180 s old, and the relay serves it like any other peer. The probe is answered by the peer's WireGuard, not by its plexd, so it works against a node on any version. A bridge on an older plexd relays nothing.

## Relay Status Report

A bridge reports the state of its relay to the control plane with [`PUT /v1/nodes/{node_id}/relay-status`](../core/api-endpoints.md#relay-status), so the control plane stops assigning a relay that does not run. Without the report, a relay that cannot bind its socket stays every relayed pair's fallback while its bridge keeps heartbeating, although plexd knows the bind failed. Only a node in bridge mode reports. No configuration key turns the report on or off: a bridge reports at its `heartbeat.interval`.

### Reported States

The [reconcile handler](#relayreconcilehandler) records the state each of its branches leaves behind:

| State | Members sent | The handler sets it when |
|-------|--------------|--------------------------|
| `running` | `listen_port`, `bound_seconds` | The pull enables the relay and `Relay.Bound` reports a bound socket: after `Configure` succeeded, or after it refused an out-of-range `listen_port` while the relay kept running on its old port, which the report then names |
| `stopped` | none | The pull carries no `bridge` block, no `bridge.relay` block, or `enabled: false`, whether or not a relay exists or runs; or `Configure` refused an out-of-range `listen_port` on a relay that was not running |
| `bind_failed` | `listen_port` | The pull enables the relay on a `listen_port` in 1..65535, and `Configure` could not bind it |
| `not_consented` | none | The pull enables the relay, but `bridge.relay_enabled` is false, so the manager created no relay |

A bridge without relay consent reports too: `stopped` while the pull does not enable the relay, `not_consented` once it does. plexd also sends `stopped` once at [shutdown](#shutdown-report), without recording it.

### Status Tracker

`RelayStatusTracker` (`relay_status.go`) sits between the handler and the reporter. It holds the latest status and signals each change. The [manager](#manager-integration) always creates one, with or without local consent.

```go
type RelayStatus struct {
    State      string    // one of the api.RelayState* constants
    ListenPort int       // running and bind_failed; 0 otherwise
    BoundAt    time.Time // running; zero otherwise
}

func NewRelayStatusTracker() *RelayStatusTracker
func (t *RelayStatusTracker) Set(s RelayStatus)
func (t *RelayStatusTracker) Get() (RelayStatus, bool)
func (t *RelayStatusTracker) Changed() <-chan struct{}
```

- `Set` stores the status. When no status was held, or the new one differs from the held one, it signals on `Changed` without blocking. Two statuses are equal when `State` and `ListenPort` match and `BoundAt.Equal` holds, so the same instant in another `time.Location` is no change.
- `Changed` has a capacity of 1. Several `Set` calls before the reporter wakes collapse into one signal, and the reporter then reads the latest status.
- `Get` returns the held status, and false until the first `Set`.

A reconcile cycle that only changes the relay's peers sets an equal status and signals nothing.

### Reporter

`RelayStatusReporter` sends the report from a goroutine of its own, never from inside the reconcile handler, so a slow control plane never delays a reconcile cycle.

```go
type RelayStatusClient interface {
    ReportRelayStatus(ctx context.Context, nodeID string, req api.RelayStatusRequest) (*api.RelayStatusResponse, error)
}

func NewRelayStatusReporter(interval time.Duration, nodeID string, client RelayStatusClient, status *RelayStatusTracker, logger *slog.Logger) *RelayStatusReporter
func (r *RelayStatusReporter) Run(ctx context.Context) error // always returns nil
```

`*api.ControlPlane` satisfies `RelayStatusClient`. A non-positive `interval` becomes 30 s, the default `heartbeat.interval`. `Run` logs `relay status: reporter started` and then sends one report:

1. when the tracker signals a change, after which the interval restarts, so an unchanged state goes out once per interval and never twice in quick succession after a change;
2. on every tick of the interval, an unchanged state included;
3. once more as `stopped` when `ctx` ends (see [Shutdown Report](#shutdown-report)).

A send does nothing while the tracker holds no status, so plexd reports nothing before the handler first ran. Until then it does not know the relay's state, and a `stopped` sent at start, followed a moment later by `running` from the first reconcile, could move the relay's pairs away and back on every start. A bridge whose first pull carries no drift never runs the handler and sends nothing, which is harmless: the control plane reads the report only for an enabled relay, and enabling one is bridge drift.

Each send builds a fresh body from the held status. `listen_port` goes with `running` and `bind_failed`. For `running`, `bound_seconds` is the time since `BoundAt` in whole seconds, floored, 0 when negative and at most 315360000 (`api.MaxRelayStatusBoundSeconds`). Both instants come from `time.Now`, so the difference uses Go's monotonic clock, and a stepped wall clock does not move it.

A failed send is not retried within its tick. The control plane anchors `bound_seconds` on its receive time, so the next send builds a fresh body, and a lost report sent on a change reaches the control plane at the next tick, at most one interval later.

`plexd up` starts the reporter only in bridge mode, with the heartbeat's interval. It does not wait for the WireGuard interface, because the relay needs no WireGuard device. The cost is one `PUT` of under 100 bytes per bridge per interval, plus one per state change and one at shutdown.

### Answers

No answer stops the loop, and none touches the relay:

| Answer | Reporter behavior |
|--------|-------------------|
| `200 OK` | Debug `relay status: accepted`. Info `relay status: reported` for the first accepted status and for one that differs from the last reported one, so an unchanged re-send logs at Debug only. After a not-served phase, one Info `relay status: control plane accepts relay status reports` |
| `404` with any code but `relay_status_node_gone`, or `501 relay_status_not_provisioned` | The control plane does not serve the report, as `api.IsRelayStatusNotServed` classifies it. Info `relay status: control plane does not accept relay status reports, retrying every interval` on entering that state only. plexd keeps reporting every interval and keeps relaying as the pull says |
| `404 relay_status_node_gone` | The node was removed while the request ran. Warn `relay status: rejected, this node was removed` on every send. It does not enter the not-served state |
| `api.ErrCredentialRefused` | Debug `relay status: send failed`. The heartbeat parked the agent on a refused credential and names the cause once |
| Any error after `ctx` ended | Nothing, because that is the shutdown |
| Anything else, `400 malformed_relay_status` and `400 invalid_relay_status` included | Warn `relay status: send failed` |

### Shutdown Report

When `ctx` ends, the reporter sends `{"state":"stopped"}` once more under a context of its own, which the cancelled `ctx` does not reach, bounded by 5 s (`relayStatusShutdownTimeout`). It logs `relay status: reported stopped at shutdown` on success and the Warn `relay status: shutdown report failed` on any error. A control plane that does not answer within 5 s gives an error wrapping `context.DeadlineExceeded`. The reporter makes no shutdown send while the tracker holds no status or while the control plane does not serve the report.

The 5 s fit in the 30 s the shutdown of `plexd up` waits for every goroutine, and the shutdown sequence needs no step of its own: cancelling `ctx` triggers the report. The report can reach the control plane before the bridge teardown closes the relay socket, which only moves the pairs off a relay that is about to stop.

A bridge stopped for good gives up its pairs within about 15 s this way, instead of about 100 s until its heartbeat reads stale. The accepted cost: every restart and self-upgrade of a bridge moves its pairs away and back, and in a Domain with one bridge the pairs lose their `fallback_endpoint` until the restarted agent reports `running`.

### What the Control Plane Does

The control plane keeps the latest report per node and reads it only for a bridge whose relay is enabled. A relay whose report in force is anything but `running` on the pulled `listen_port` reads `not_running`, and the control plane stops assigning it: its pairs move to another bridge within about 15 s, or lose their `fallback_endpoint` when the Domain has no other bridge that relays. A report stays in force only while it is repeated within three heartbeat intervals, 90 s under the default policy, which is why plexd sends an unchanged state again once per interval. A report identical to the stored one only refreshes the instant it was last seen. A node that never reports, or whose last report aged out, keeps the behavior it had before the report existed: its relay is judged by the data path alone. A control plane that predates the report answers `404`, and plexd keeps relaying as the pull says. See [Relay status](https://github.com/plexsphere/plexsphere/blob/main/docs/reference/api/plexd-agent-contract.md#relay-status) in plexsphere's agent contract for the rules and the timing.

## Security Properties

- The bridge holds no private or preshared key of any peer and decrypts nothing. It reads only the message type and indices, and checks `mac1` with the peers' public keys.
- The relay never answers a datagram. Every drop is silent, and it sends only the datagrams it forwards, never back to their source.
- A handshake message whose `mac1` names no listed peer is dropped, so a sender that knows no peer's public key cannot get an initiation forwarded.
- A fan-out reaches at most 8 addresses, each of which sent a `mac1`-valid initiation within the last 30 s, and only the real target's WireGuard accepts the initiation.
- The handshake rate limit, 20 messages per second per source IP with a burst of 5, bounds the `mac1` scan. The index table holds at most 65536 entries.
- Not defended: a Domain node or an on-path attacker that forges WireGuard headers can make the relay misroute a pair, a denial of service, but never gets plaintext, and the next genuine packet restores the address.

## Manager Integration

`NewManager` creates the relay with `NewRelay(logger)` when `Config.RelayEnabled` is `true`. The relay opens no socket until the reconcile handler configures it. `NewManager` always creates a `RelayStatusTracker`, with or without `RelayEnabled`, because a bridge without local consent reports its relay's state too (see [Relay Status Report](#relay-status-report)).

| Method               | Signature                 | Description |
|----------------------|---------------------------|-------------|
| `Relay`              | `() *Relay`               | Returns the relay; nil without `RelayEnabled` |
| `RelayStatusTracker` | `() *RelayStatusTracker`  | Returns the relay's [status tracker](#status-tracker), which the reconcile handler sets and the reporter reads; never nil |

`Teardown()` calls `relay.Stop()` as part of bridge teardown. Errors are aggregated with other teardown errors. It leaves the status tracker as it was: the reporter sends the last `stopped` on its own when `ctx` ends.

### BridgeStatus with Relay

With a relay, `BridgeStatus()` reports whether it listens and how many pairs it relays:

```go
info := mgr.BridgeStatus()
// info.RelayEnabled = relay.Running()
// info.ActiveRelaySessions = relay.ActiveCount()
```

`BridgeStatus` is published as the `status.bridge` report (see [Local Node API](../core/nodeapi.md#get-v1-state-report)). Its keys `relay_enabled` and `active_relay_sessions` mean "listening" and "relayed pairs with traffic in the last 180 s".

### BridgeCapabilities with Relay

With `RelayEnabled`, `BridgeCapabilities()` includes `relay`, and no port, because the port comes from the pull:

```go
caps := mgr.BridgeCapabilities()
// caps["relay"] = "true"
```

### Full Lifecycle

```go
mgr := bridge.NewManager(ctrl, bridge.Config{
    Enabled:         true,
    AccessInterface: "eth1",
    AccessSubnets:   []string{"10.0.0.0/24"},
    RelayEnabled:    true,
}, logger)

// Setup bridge routing
mgr.Setup("plexd0")

// Register handlers; the relay starts when a pull enables it
r := reconcile.NewReconciler(client, reconcile.Config{}, logger)
r.RegisterHandler(bridge.RelayReconcileHandler(mgr.Relay(), mgr.RelayStatusTracker(), logger))

dispatcher := api.NewEventDispatcher(logger)
dispatcher.Register(api.EventBridgeConfigUpdated,
    bridge.HandleBridgeConfigUpdated(r))

// Report the relay's state on change and once per heartbeat interval
reporter := bridge.NewRelayStatusReporter(30*time.Second, nodeID, client, mgr.RelayStatusTracker(), logger)
go reporter.Run(ctx)

// Run reconciler
go r.Run(ctx, nodeID)

// Graceful shutdown; the reporter sends a last stopped within 5 s
<-ctx.Done()
mgr.Teardown() // stops relay, removes routes, disables forwarding
```

## API Types

### RelayConfig

The `bridge.relay` block of the state pull (`api.BridgeSnapshot.Relay`), the control plane's `NodeStateBridgeRelay`. The block is present-but-nullable: `null` stops a running relay.

```go
type RelayConfig struct {
    Enabled     bool              `json:"enabled"`
    ListenPort  int               `json:"listen_port"`
    Assignments []RelayAssignment `json:"assignments"`
}
```

| Field         | Description |
|---------------|-------------|
| `Enabled`     | Whether the control plane asks this bridge to relay |
| `ListenPort`  | The UDP port the relay listens on |
| `Assignments` | The peers whose `fallback_endpoint` names this bridge. Decoded and carried; the relay does not read it |

### RelayAssignment

```go
type RelayAssignment struct {
    PeerNodeID           string `json:"peer_node_id"`
    FallbackEndpoint     string `json:"fallback_endpoint"`
    FallbackEndpointPort int    `json:"fallback_endpoint_port"`
}
```

| Field                  | Description |
|------------------------|-------------|
| `PeerNodeID`           | Node ID of a peer whose fallback names this bridge |
| `FallbackEndpoint`     | The host of the fallback that peer dials |
| `FallbackEndpointPort` | The port of the fallback that peer dials |

```json
{
  "enabled": true,
  "listen_port": 51821,
  "assignments": [
    {
      "peer_node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1",
      "fallback_endpoint": "203.0.113.50",
      "fallback_endpoint_port": 51821
    }
  ]
}
```

### BridgeInfo Relay Fields

Published in the `status.bridge` report via `api.BridgeInfo`:

| Field                 | Type   | Description |
|-----------------------|--------|-------------|
| `RelayEnabled`        | `bool` | Whether the relay listens (`relay.Running()`) |
| `ActiveRelaySessions` | `int`  | Relayed pairs with traffic in the last 180 s (`relay.ActiveCount()`) |

### SSE Event Constants

Relay changes are delivered through the single bridge event constant; the
fine-grained `relay_*` constants have been removed.

| Constant                        | Value                     |
|---------------------------------|---------------------------|
| `api.EventBridgeConfigUpdated`  | `"bridge_config_updated"` |

## Removed: the Session-Based Relay

The relay this page replaces took a session list from the pull: each entry named two peers, an endpoint for each, and an expiry. It listened on a local port with a local session cap and session TTL, started once at startup, and admitted a packet only from one of an entry's two endpoints. A peer behind a symmetric NAT reaches the relay from a public port nobody reported in advance, so its packets were dropped. And the control plane sends `enabled`, `listen_port` and `assignments`, which decoded into an empty session list, so a bridge relayed nothing. The session type, the per-session methods, the manager's start and stop methods, the startup goroutine and the three local keys are gone. A config file that still sets the keys keeps loading; see [Configuration Reference](../core/configuration.md#bridge).

## Error Prefixes

| Source | Prefix |
|--------|--------|
| `Config.Validate` | `bridge: config: relay requires bridge mode to be enabled` |
| `Relay.Configure` (port) | `bridge: relay: listen_port <port> out of range` |
| `Relay.Configure` (bind) | `bridge: relay: listen on :<port>: ` |

## Logging

All relay log lines carry `component=bridge`.

| Level   | Message | Keys |
|---------|---------|------|
| `Info`  | `relay started` | `listen_port` |
| `Info`  | `relay stopped` | `listen_port` |
| `Info`  | `relay disabled by the control plane` | none |
| `Info`  | `relay: peer address learned` | `peer_id`, `address` |
| `Info`  | `relay status: reporter started` | `interval` |
| `Info`  | `relay status: reported` | `state`, and `listen_port` and `bound_seconds` when set; logged for the first accepted status and for one that differs from the last reported one |
| `Info`  | `relay status: control plane does not accept relay status reports, retrying every interval` | `status`, `code`; logged on entering the not-served state only |
| `Info`  | `relay status: control plane accepts relay status reports` | none; logged once after a not-served phase |
| `Info`  | `relay status: reported stopped at shutdown` | none |
| `Warn`  | `relay: the control plane enables the relay, but bridge.relay_enabled is false` | `listen_port` |
| `Warn`  | `relay: skipping peer with invalid public key` | `peer_id` |
| `Warn`  | `relay: skipping peer with duplicate public key` | `peer_id` |
| `Warn`  | `relay: index table full` | `max_indices`; logged at most once a minute |
| `Warn`  | `relay status: rejected, this node was removed` | `code`; logged on every send |
| `Warn`  | `relay status: send failed` | `error` |
| `Warn`  | `relay status: shutdown report failed` | `error` |
| `Debug` | `relay: dropped datagram` | `source`, `reason` (`not_wireguard`, `rate_limited`, `unknown_target`, `unknown_index`, `no_route` or `index_table_full`) |
| `Debug` | `relay: read failed` | `error` |
| `Debug` | `relay: forward failed` | `dst`, `error` |
| `Debug` | `relay status: accepted` | `state`, `accepted_at` |
| `Debug` | `relay status: send failed` | `error`; logged instead of the Warn while the client holds a refused credential (`api.ErrCredentialRefused`) |
