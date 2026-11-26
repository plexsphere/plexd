---
title: NAT Relay
package: internal/bridge
feature: PXD-0012
---

# NAT Relay

The NAT relay extends bridge mode (`internal/bridge`) to forward WireGuard between two peers that cannot reach each other directly, such as two nodes behind symmetric NATs. A bridge relays when both its local config and its state pull allow it. It listens on the UDP port the pull names and forwards among the peers the same pull lists. It works out each datagram's destination from the WireGuard message header: a handshake initiation goes to the peer whose public key verifies its `mac1`, and every other message goes by its receiver index. An initiation between two peers with a live session on this relay waits for its retry (see [Forwarding Table](#forwarding-table)). The relay does not need to know either peer's public address in advance. It holds no private or preshared key, decrypts nothing and never answers a datagram. On Linux 6.6 or newer it hands the transport datagrams of the sessions it placed to an eBPF program at the tcx ingress hook, which forwards them without the plexd process, while every decision stays in the process (see [Kernel Forwarding](#kernel-forwarding)).

## Data Flow

![Peer A and Peer B, each behind NAT, exchange WireGuard datagrams with the UDP socket of the relay on the bridge node, which is bound on the pulled listen_port. From the socket a datagram goes to parseWGMessage, which reads the message type and the sender and receiver index; then a handshake is checked with CheckMAC1 against each listed peer, and every message goes through the indices table; the dispatch loop leads back to the socket. Above the socket, on Linux 6.6 or newer, the transport datagrams of placed sessions pass between the two peers through relay_forward at tcx ingress, which looks them up in the relay_sessions table, and the indices table installs and forgets the entries of relay_sessions. Below, the state pull with bridge.relay and peers goes to RelayReconcileHandler, which calls Configure or Stop.](../../diagrams/bridge-nat-relay.svg)

1. A node dials the relays as the last entries of a peer's [dial order](../networking/wireguard.md#dial-order): the peer's relay set, `fallback_endpoints`, whose first entry is its `fallback_endpoint`. The control plane lists at most 4, each on a bridge that relays: the relay of the peer's assigned bridge first, then its standby relays. A control plane that predates the set sends only `fallback_endpoint`, which makes a set of one. A candidate or direct endpoint equal to a relay is not dialed before the relays, so the relays always end the order complete and in set order. The node dials a standby only for a peer last seen connected over a relay, when that relay fails (see [Meeting on the Relay](#meeting-on-the-relay)).
2. The relay reads the datagrams from one UDP socket, bound on the `listen_port` of the bridge's state pull, and classifies each by its WireGuard header (see [Message Classification](#message-classification)).
3. It finds the destination: for a handshake initiation, the listed peer whose public key verifies the message's `mac1`; for every other message, the peer that owns the message's receiver index. It learns each peer's current address from the handshake and transport messages that peer sends.
4. It writes the datagram unchanged to that address from the same socket. An initiation that waits for its retry is dropped and never written (see [Forwarding Table](#forwarding-table)).
5. On Linux 6.6 or newer, when the relay routes the first transport datagram of a session index itself, it writes the session into the kernel's table `relay_sessions` before it writes that datagram to the socket. The program `relay_forward` at tcx ingress then forwards the session's next transport datagrams to the owner, with the payload unchanged and the relay's address and port as their source, as the socket would send them. They never reach the socket, and every datagram the program does not take reaches it as before (see [Kernel Forwarding](#kernel-forwarding)).

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

`Relay` (`relay.go`) owns the UDP socket, the peer set, the index table and the pair table, and on Linux the [kernel path](#kernel-forwarding) of each run (`relay_kernel.go`). The `Manager` creates it; the reconcile handler starts, reconfigures and stops it.

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
3. When the relay is not running, `Configure` binds UDP on the dual-stack wildcard address, `net.ListenUDP("udp", &net.UDPAddr{Port: listenPort})`, so IPv4 and IPv6 peers reach the same socket. A bind failure is wrapped as `bridge: relay: listen on :<port>: <cause>`, and the relay stays stopped. On success:
   - It asks for 7 MiB (`relaySocketBuffer`) of receive buffer and of send buffer, the size wireguard-go asks for on its own sockets. On Linux it forces that size past `net.core.rmem_max` and `net.core.wmem_max` with `SO_RCVBUFFORCE` and `SO_SNDBUFFORCE`, which `CAP_NET_ADMIN` allows. It reads both sizes back and logs `relay: socket buffers set` at Debug with `receive_bytes` and `send_bytes`, or with `error` when the read-back fails. Linux reports twice the size set, so a forced socket reads 14,680,064 bytes each way, and a socket without `CAP_NET_ADMIN` twice the smaller of 7 MiB and the host's limit (`net.core.rmem_max`, `net.core.wmem_max`). A refused size never fails the bind: the socket keeps what the OS gave it, and the line shows it.
   - When `Manager.EnableRelayKernelForwarding` set the kernel path up (see [Manager Integration](#manager-integration)), it tries that path once for this start. It logs `relay: kernel forwarding started` at Info with `listen_port` and `mesh_interface`, or `relay: kernel forwarding unavailable, forwarding in the process` at Info with `error`, and goes on either way: the bind stands, and the run forwards in the process (see [When It Runs](#when-it-runs)).
   - It creates a fresh handshake rate limiter, starts the dispatch goroutine and the sweeper goroutine, and logs `relay started` with `listen_port`.
4. `Configure` replaces the peer set with `peers`:
   - A peer whose `node_id` and `public_key` are unchanged keeps the address the relay learned for it.
   - A new peer, or a peer whose `public_key` changed, gets a fresh entry with no address.
   - A peer no longer listed is deleted, together with every index that names it.
   - A `public_key` that is not standard base64 of 32 bytes is skipped with the Warn `relay: skipping peer with invalid public key` and the peer's `peer_id`.
   - A `public_key` that a second node ID repeats is skipped with the Warn `relay: skipping peer with duplicate public key` and that peer's `peer_id`.

   A skipped peer never fails the call. A repeated call with the same port and peers changes nothing and does not rebind.

### Stop

`Stop` closes the socket, ends the dispatch and sweeper goroutines, and closes the kernel path when the run has one, which detaches the program from every interface and writes back the mesh interface's IPv6 forwarding flag when the kernel path set it. A close error is logged at Debug as `relay: kernel forwarding close failed` and stops nothing. `Stop` then closes the rate limiter, clears every peer, index and pair, and logs `relay stopped`. It is idempotent: on a relay that is not running it returns nil and logs nothing, so a repeated disable stays quiet. A relay restart loses all state, and WireGuard's next handshake rebuilds it.

### Concurrency

- One mutex guards the running socket, the run's kernel path, the peers, the indices and the pairs. The dispatch loop takes it for every datagram that passes classification and the rate limit, and releases it before it writes.
- Every call into the kernel path runs under that mutex too: installing, forgetting and reading sessions, resolving the routes again, reading the counters and closing it. The kernel's table and the index table therefore change together.
- A second mutex serializes `Configure` and `Stop`, so bridge teardown and the reconcile loop never interleave a start with a stop.
- `Stop` releases the first mutex before it waits for the goroutines, because the dispatch loop takes it. It closes the kernel path and then the rate limiter only after both goroutines have returned.

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

One mutex guards three maps:

- `peers` maps a public key to `relayPeer{nodeID, checker, addr, seen}`: the peer's node ID, its cookie checker, its last learned address and when that address was last set.
- `indices` maps a `uint32` index to `relayIndex{pending, owner, partner, src, used, carried, kernel, kernelRetryAt}`. A pending index records an initiation that has no response yet; a session index belongs to a handshake the relay forwarded, and `carried` records that a transport message named it. `kernel` is the flow the [kernel path](#kernel-forwarding) holds a copy of for a session index, the partner's and the owner's address, and zero while it holds none. `kernelRetryAt` is the time before which the relay does not offer the index to the kernel again after the kernel refused it.
- `pairs` maps two peers' node IDs, in sorted order, to `relayPair{indices, heldAt}`: the session indices of their latest handshake, and when the relay last started to hold back an initiation of theirs, zero until it first does.

Every source address is unmapped (`Addr().Unmap()`) before use, so an IPv4 peer reads the same on the dual-stack socket. A peer's address is fresh while its `seen` is younger than `relayIndexTTL`.

| Constant | Value | Meaning |
|----------|-------|---------|
| `relayFanoutWindow` | 30 s | How long a pending initiation stays a [fan-out](#first-contact) target; no longer than the 30 s Linux conntrack timeout for an unanswered UDP flow |
| `relayFanoutMax` | 8 | The most addresses one initiation fans out to |
| `relayRetryMin` | 4 s | How long after the first initiation it holds back the relay forwards the next one. WireGuard repeats an unanswered initiation after its `RekeyTimeout` of 5 s plus up to 334 ms of jitter, and the 1 s margin absorbs network jitter |
| `relayHoldWindow` | 15 s | How long after that first initiation an initiation counts as a first one again. Two retries fit in it at WireGuard's largest jitter, and it ends well before the next 120 s rekey |
| `relayIndexTTL` | 180 s | WireGuard's `RejectAfterTime`: no session outlives it without a new handshake. Also how long a learned address stays fresh |
| `relaySweepInterval` | 30 s | How often the sweeper runs |
| `relayMaxIndices` | 65536 (`1 << 16`) | The most live indices. The kernel's session table `relay_sessions` holds as many, so the process never holds a session index the kernel has no room for |
| `relaySocketBuffer` | 7 MiB (`7 << 20`) | The receive and the send buffer the relay asks for on its socket, each way. Linux forces it past `net.core.rmem_max` and `net.core.wmem_max` with `SO_RCVBUFFORCE` and `SO_SNDBUFFORCE`, which `CAP_NET_ADMIN` allows |
| `relayKernelRetry` | 5 s | How long the relay waits before it offers the kernel a session again that the kernel refused |

### Forwarding Table

| Message | Accepted when | Sent to | State change |
|---|---|---|---|
| Initiation | the rate limiter allows the source IP, `CheckMAC1` succeeds for exactly one peer T, and the relay does not hold the initiation back for its retry (see below) | T's address when fresh. Otherwise every distinct `src` of a pending index younger than `relayFanoutWindow` that is neither this datagram's source nor any peer's fresh address, newest first, at most `relayFanoutMax` | `indices[sender] = pending{partner: T, src, used: now}`, replacing an existing entry |
| Response | the rate limiter allows the source IP, `indices[receiver]` is pending, and `CheckMAC1` succeeds for a peer I other than that pending entry's T | the pending entry's `src` | T's address := source, I's address := pending `src`, `indices[receiver] = session{owner: I, partner: T}`, `indices[sender] = session{owner: T, partner: I}`, `pairs[{I, T}] = {indices: [receiver, sender]}`, replacing an existing entry, which clears `heldAt` |
| Cookie reply | `indices[receiver]` exists | a pending entry's `src`, or a session owner's address | none |
| Transport | `indices[receiver]` is a session index whose owner has an address | the owner's address | the partner's address := source, `used` := now, `carried` := true |

The relay never sends a datagram back to its own source: a computed destination equal to the source is skipped. A datagram whose only destination is its own source changes no state and is dropped with reason `no_route`. An initiation with no fresh target and an empty fan-out still records its pending index, so a later initiation can fan out to it, and is dropped with reason `no_route`. An initiation the relay holds back records no pending index in any case, because nothing can answer it.

The relay holds back an initiation for its retry when its source is the address of a peer I other than T, and I and T have a session index that carried a transport message and was used within the last 180 s (`relayIndexTTL`). The first such initiation is dropped with reason `held_for_retry`, and so is each one after it for 4 s (`relayRetryMin`). An initiation 4 s or more after that first one is forwarded, and so is every later one, until a response replaces the pair's entry and clears `heldAt`. After 15 s (`relayHoldWindow`) with no response, an initiation counts as a first one again. An initiation from a source that matches no peer, between two peers the relay never carried, after a handshake that carried no transport message, which a device that re-dialed may have dropped, or for a session past `relayIndexTTL` goes out at once, so [First Contact](#first-contact) and a standby that takes over a pair are not delayed. See [Meeting on the Relay](#meeting-on-the-relay) for why.

Every datagram the table does not accept is dropped and never answered. The relay logs it at Debug as `relay: dropped datagram` with `source` and `reason`:

| Reason | Dropped datagram |
|--------|------------------|
| `not_wireguard` | Fails [classification](#message-classification) |
| `rate_limited` | An initiation or response from a source IP over the [handshake rate limit](#rate-limit-and-cost) |
| `unknown_target` | An initiation whose `mac1` verifies for no listed peer, or a response whose `mac1` verifies for no listed peer other than the pending entry's target |
| `unknown_index` | A response, cookie reply or transport message whose receiver index the relay does not hold, or does not hold as the kind of index the [table](#forwarding-table) requires |
| `no_route` | Accepted, but no destination is left: an initiation with no fresh target and an empty fan-out, a cookie reply or transport message whose index owner has no address, or a datagram whose only destination is its own source |
| `held_for_retry` | An initiation between two peers with a live session that the relay holds back for its retry, by the rule under the [table](#forwarding-table) |
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

A transport datagram, the bulk of relayed traffic, costs one map lookup. Where the [kernel path](#kernel-forwarding) runs, only the first transport datagram of a session index costs the process anything, and the program forwards the rest. A handshake message costs one `CheckMAC1` per listed peer. The rate limiter bounds that scan: it is wireguard-go's `ratelimiter.Ratelimiter`, 20 handshake messages per second per source IP with a burst of 5, the limit WireGuard itself applies to handshakes. Initiations and responses pass through it. Each start creates and initializes a fresh limiter, and `Stop` closes it.

An initiation that passes the limiter and its `mac1` check costs one more scan of the peers, to find its initiator. That scan is cheaper than the `CheckMAC1` scan before it, and the same limit bounds it. A rekey over the relay finishes about 5 s later, because its first initiation waits for the retry. That costs nothing while the old session lives on for up to 180 s.

### Index Table and Sweeper

The sweeper runs every 30 s (`relaySweepInterval`). It deletes pending indices older than 30 s (`relayFanoutWindow`), session indices unused for 180 s (`relayIndexTTL`) and pairs with neither of their indices left. When 65536 indices (`relayMaxIndices`) are live, recording a new one first runs the sweep. If the table is still full, the datagram is dropped with reason `index_table_full`, and `relay: index table full` is logged at Warn at most once a minute. While the kernel path runs, the sweep reads the kernel's ages before it expires anything, and afterwards has the kernel path resolve its routes again and logs its counters (see [How the Process Drives the Table](#how-the-process-drives-the-table)).

### Dispatch Loop

The dispatch goroutine reads with `ReadFromUDPAddrPort` into one 65535-byte buffer, classifies and rate-limits the datagram, updates state under the mutex, and writes after releasing it, so it copies nothing. While the kernel path runs, the loop reads only what the program passes to the socket: every handshake and cookie reply, the first transport datagram of each session index, and every transport datagram the program does not take (see [Fallback to the Process](#fallback-to-the-process)).

- A read error that satisfies `errors.Is(err, net.ErrClosed)` ends the loop; `Stop` closes the socket this way.
- Any other read error is logged at Debug as `relay: read failed`, and the loop continues.
- A write error is logged at Debug as `relay: forward failed` with `dst` and `error`, and the next datagram is forwarded as usual.

## Kernel Forwarding

In the process every relayed datagram costs two system calls and a wake-up on one core, and a relayed pair gets about 1.1 Gbit/s where the same path routed by the kernel carries 1.9 (see [Measured Throughput](#measured-throughput)). On Linux 6.6 or newer the relay therefore hands the transport datagrams of every session it placed to the eBPF program `relay_forward` at the tcx ingress hook of the interfaces the peers' datagrams arrive on, so they no longer pass through the plexd process. A placed session is one whose handshake the relay forwarded: its response made two session indices (see [Forwarding Table](#forwarding-table)).

Handshake routing, the hold of a repeated initiation, the handshake rate limit, address learning and the status report stay in the process. The process stays the only owner of the relay's state: the kernel holds a copy of the session table that the process writes and reads back, and learns nothing on its own. On macOS, on Windows and on Linux before 6.6 the relay forwards every datagram in the process, with the same socket buffers. macOS lowers the 7 MiB to `kern.ipc.maxsockbuf`, which is 8 MiB by default and less on a host with little memory.

### When It Runs

`plexd up` calls `Manager.EnableRelayKernelForwarding` right after bridge `Setup` succeeded and before the reconciler starts, so the first `Configure` already sees it. Without local consent the manager has no relay, and the call does nothing, so a node that is no relaying bridge never loads the program. `Setup` itself does not call it. On macOS and Windows the call only records the mesh interface's name.

Each start of the relay, a `Configure` that binds the socket, tries the kernel path once, after the bind:

1. It resolves the mesh interface by name.
2. It loads the program with the listen port and the mesh interface's index as constants.
3. It attaches the program to the loopback interface through tcx and detaches it at once. A kernel without tcx fails here, at the start, with `relaybpf: tcx attach probe:`, and since the session table is still empty, the probe forwards nothing.
4. It sets the mesh interface's IPv6 forwarding flag (see [The Linux Adapter](#the-linux-adapter)).

On success the relay logs `relay: kernel forwarding started` at Info with `listen_port` and `mesh_interface`. On an error it logs `relay: kernel forwarding unavailable, forwarding in the process` at Info with `error` and forwards in the process: the bind stands, and `Configure` returns nil. A relay that started without the kernel path forwards in the process until it stops and starts again, which a pull that disables and enables the relay, a new `listen_port` or a restart of plexd brings about.

No configuration key turns the kernel path on or off. The capability is the switch: without `CAP_BPF` the load fails with `operation not permitted`, the relay logs the line above once per start and relays as before. The shipped systemd unit grants `CAP_BPF`, and a unit an earlier release wrote needs the drop-in on the [packaging page](../deployment/bare-metal-packaging.md#unit-file-directives). The shipped Kubernetes DaemonSet does not add `BPF` (see [Kubernetes Deployment](../deployment/kubernetes-deployment.md#daemonset-configuration)).

### What the Program Forwards

`relay_forward` returns `TCX_NEXT` for every packet it does not forward, so the packet goes on to the next program and the stack untouched. It forwards a packet only when all of these hold, checked in this order:

1. The packet carries no VLAN tag in its metadata, it is IPv4 or IPv6, and its Ethernet, IP and UDP headers and the first 8 bytes of its payload lie in the packet's linear data.
2. IPv4: the header carries no options (`ihl` is 5), the protocol is UDP, and the packet is no fragment (`frag_off & htons(0x3fff)` is 0). IPv6: the next header is UDP.
3. The UDP destination port is the relay's listen port, the UDP length is at least 40, and the payload starts with a transport message: byte 0 is 4 and bytes 1 to 3 are 0.
4. `relay_sessions` holds the receiver index, `b[4:8]` of the payload. Otherwise counter `no_session`.
5. The entry's address family matches, the source address and port equal the partner's address and port in the entry, and the destination address equals the local address the partner sends to. Otherwise counter `mismatch`.
6. The packet is a single datagram: `gso_segs` is at most 1. Otherwise counter `gso`.
7. `bpf_fib_lookup` finds the route from the local address towards the owner, asked through the mesh interface, and answers `BPF_FIB_LKUP_RET_SUCCESS`. Otherwise counter `fib_fwd_disabled`, `fib_frag_needed` or `fib_no_neigh` for those results, and `fib_other` for any other.
8. That route leaves by the interface the process resolved for the owner when it installed the session. Otherwise counter `route_changed`.

The program then rewrites the datagram as the relay's socket would send it. The source becomes the local address this host uses towards the owner and the listen port, the destination the owner's address and port, and the TTL or hop limit 64. It updates the IPv4 header checksum and the UDP checksum, and an IPv4 datagram that carries no UDP checksum keeps none. TOS, DF and the IPv4 ID stay as the sender set them, and the payload is unchanged. It writes the Ethernet addresses the lookup returned, records the time in the entry, counts `forwarded`, and redirects the datagram out of the route's interface. It never sends a datagram back to its source, because the process installs no such entry: the [table](#forwarding-table) refuses a destination equal to the source before the session reaches the kernel. It never answers a datagram either.

The route lookup asks through the mesh interface, not through the interface the datagram arrived on. `bpf_fib_lookup` refuses with `BPF_FIB_LKUP_RET_FWD_DISABLED` when forwarding is off on the device it is asked about, and a bridge has IPv4 forwarding on for the mesh interface already (see [Setup Sequence](bridge-mode.md#setup-sequence)). The host therefore needs no forwarding on its public interface and does not become a router there.

### Fallback to the Process

The fallback is per datagram. Every packet the program does not forward reaches the relay's socket unchanged, where the code that handled it before the kernel path handles it: a roamed peer, an unknown index, a handshake, a fragment and an oversize datagram alike. A packet that fails one of the first three checks counts nowhere: every handshake, every cookie reply, every fragment and every packet for another port. The program's counters, in slot order:

| Counter | What it counts |
|---------|----------------|
| `forwarded` | A datagram the program forwarded |
| `no_session` | A transport datagram for the relay whose receiver index the table does not hold: the process has not installed the session yet, has forgotten it, or the kernel refused it |
| `mismatch` | A transport datagram whose index the table holds, from another source address or port, to another local address or in another address family than the entry names, such as from a peer that roamed. The process learns the new address, takes the peer's sessions out of the kernel and installs them again with their next datagrams |
| `fib_fwd_disabled` | The route lookup through the mesh interface answered that forwarding is off on it. The process forwards each such datagram, and the sweep logs a Warn |
| `fib_frag_needed` | The datagram is larger than the route's MTU. The socket sends it as it sends any datagram |
| `fib_no_neigh` | The kernel holds no link-layer address for the route's next hop yet. The socket sends the datagram |
| `fib_other` | Any other result of the route lookup, such as no route to the owner |
| `route_changed` | The route to the owner now leaves by another interface than the process resolved. The next sweep resolves the routes again and forgets the session, and its next datagram installs it with the new route |
| `gso` | A packet that holds several datagrams, such as a UDP GRO super-packet |

Each counter is the sum over the CPUs and starts at 0 with each start of the relay. The relay logs all nine after every sweep at Debug as `relay: kernel forwarding counters`, with the counter names as keys. They are not in the heartbeat or the `status.bridge` report.

When `fib_fwd_disabled` grew since the last sweep, the relay logs the Warn `relay: kernel forwarding passes datagrams to the process, forwarding is off on the mesh interface` with `mesh_interface`, at most once a minute. Writing `net.ipv4.ip_forward=0` together with `net.ipv4.conf.all.forwarding=0` resets the IPv4 flag of the mesh interface too, and then every IPv4 transport datagram falls back. Restarting plexd, whose bridge `Setup` writes the flag, or setting `net.ipv4.conf.<mesh interface>.forwarding` back to 1 ends it.

### How the Process Drives the Table

The process installs a session when it routes a transport datagram of the session index itself, before it writes that datagram to the socket. `routeTransport` offers the session to the kernel as its last step, with the datagram's source as the partner and the owner's address as the owner. It offers nothing while the kernel holds that flow for the index already, because then the kernel passed the datagram up for a reason of its own, and nothing for 5 s (`relayKernelRetry`) after the kernel refused the index. An installed session logs `relay: kernel session installed` at Debug with `partner_id` and `owner_id`. A refused one logs `relay: kernel session not installed` at Debug with `partner_id`, `owner_id` and `error`, and its datagrams go through the process until the retry. A refusal never ends the kernel path.

The process takes a session out of the kernel whenever its own table drops or changes the index:

- an index a new initiation or response reuses, so a new handshake takes the old session out of the kernel;
- an index the sweep expires;
- an index `Configure` deletes with its peer;
- every session index that names a peer whose address moved, as owner or partner, and every one that names the peer the address was taken from. The kernel matched and sent their datagrams by the old addresses. The next datagram of each such session reaches the process, which forwards it to the new address and installs the session again.

The datagrams the kernel forwards never move `used` in the process. The sweep, `ActiveCount` and the [hold decision](#forwarding-table) therefore read the kernel's ages first, the time the program last forwarded a datagram of each index. Each age raises the index's `used` to that time when it is later, and the partner's `seen` too while the partner still has the address the entry matched. The sweep and `ActiveCount` read the whole table in batches, and the hold decision reads only the pair's two indices. An index the kernel holds that the table does not hold as a session index installed in the kernel is a stray and is forgotten. Between two sweeps a peer's `seen` can lag the kernel by up to 30 s (`relaySweepInterval`). Only the freshness of a peer's address (see [State](#state)) reads `seen` without asking the kernel, and a peer's handshake, which always passes the process, refreshes `seen` at least every 120 s of traffic.

After its expiry the sweep has the kernel path resolve its routes again. Every session whose route, source address or interface changed, or no longer resolves, leaves the kernel, and its next transport datagram installs it with the new route. The sweep then logs the counters.

An error from reading the ages or the counters, or from taking a session out of the kernel, ends the kernel path of the run. The relay closes it, which detaches the program, clears its record of what the kernel held, and logs `relay: kernel forwarding stopped, forwarding in the process` at Warn with `error`. The run goes on in the process until the relay starts again. Without this rule a kernel the process cannot read would keep forwarding sessions whose `used` no longer moves, and the sweep would cut them after 180 s.

### The Linux Adapter

`relayKernelLinux` (`relay_kernel_linux.go`) implements the kernel path on Linux with the loader of package `relaybpf`. Before it writes a session, it checks it, and a failed check is the `error` of `relay: kernel session not installed`:

1. Partner and owner are in the same address family. Otherwise `bridge: relay: kernel forwarding: address families differ`.
2. Neither address is link-local. Otherwise `bridge: relay: kernel forwarding: link-local address <addr>`.
3. Both addresses have a route with a source address, which `netlink.RouteGet` returns and the adapter caches by address. The source towards the partner is the local address the partner sends to, and the source towards the owner becomes the forwarded datagram's source. A missing route or source fails with `bridge: relay: kernel forwarding: route to <addr>: <cause>`.
4. Both routes leave by an Ethernet interface, because the program reads and writes a 14-byte Ethernet header. Otherwise `bridge: relay: kernel forwarding: interface <name> is not Ethernet`.
5. The program is attached at tcx ingress of the partner's interface, which its datagrams arrive on when routing is symmetric. The first attach per interface logs `relay: kernel forwarding attached` at Info with `interface`. A failed attach is `bridge: relay: kernel forwarding: attach to <name>: <cause>`. A sweep that finds no session left through an interface, or finds it renamed or gone, drops it from the adapter's record, so the line appears again when a later session needs that interface. The program stays attached to an interface that still exists.
6. The session is written. A failed write is `bridge: relay: kernel forwarding: write session: <cause>`.

A datagram that arrives on another interface than the one the route to its sender leaves by stays in the process when the program is not attached there. That is correct, only not faster. Where the program is attached for another partner, it forwards the datagram when it matches its entry.

A datagram for a VLAN interface arrives first at ingress of the VLAN's parent device, where the kernel has already moved the tag into the packet's metadata. When another partner sends to the parent untagged, the program is attached there too. It passes every tagged packet, because a datagram redirected from the parent would leave with its tag still set and be lost, and the kernel then hands the datagram untagged to the VLAN interface, where the program checks it again like any other.

The links live in the plexd process, so the kernel detaches the program when plexd exits for any reason, a crash included. Nothing is pinned to bpffs, and nothing outlives the process: after the process exits, `bpftool net show` lists no program.

The program's IPv6 lookups ask the mesh interface too, which has IPv6 forwarding off unless something set it. The adapter therefore sets `net.ipv6.conf.<mesh interface>.forwarding` to 1 when it reads 0 there at the start, and writes 0 back when the kernel path closes, but only when it set the flag itself. A failed read or write logs `relay: ipv6 forwarding flag not set on the mesh interface` at Debug with `error` and fails nothing; every IPv6 transport datagram then falls back to the process and counts as `fib_fwd_disabled`. The per-interface flag does not make the host forward IPv6, which needs `net.ipv6.conf.all.forwarding`. A crash leaves the flag at 1, which has no effect beyond the program's lookup.

### Host Firewall

Datagrams the program forwards do not cross the host's netfilter rules, nftables and iptables alike: the program takes them at tc ingress and redirects them out of the owner's interface. A rule that starts to drop a peer therefore cuts a placed session only at its next handshake, which passes the socket and with it the rules. The session's transport datagrams flow through the kernel until then.

### Requirements

| Requirement | Without it |
|-------------|------------|
| Linux 6.6 or newer, for tcx | The load fails at the tcx probe with `relaybpf: tcx attach probe:`, and the relay forwards in the process |
| `CAP_BPF`, to create the program's maps | The load fails with `relaybpf: load: map <name>: map create: operation not permitted`, where `<name>` is the map the library happened to create first (`relay_sessions`, `relay_counters` or `.rodata`), and the relay forwards in the process |
| `CAP_NET_ADMIN`, to load the program and attach it | The load fails with `load program: operation not permitted`, and the relay forwards in the process |
| Ethernet interfaces towards both peers | The session stays in the process: a route through a PPP, tun or WireGuard interface has no Ethernet header |
| Both peers of a pair in the same address family | The session stays in the process |
| No link-local address on either side | The session stays in the process |
| Forwarding on for the mesh interface: IPv4 from bridge `Setup`, IPv6 from the adapter | Each datagram of that family falls back to the process and counts as `fib_fwd_disabled` |

The error of a load without `CAP_BPF` ends in `(MEMLOCK may be too low, consider rlimit.RemoveMemlock)`. That hint comes from the eBPF library and does not apply on the 6.6 or newer kernels the kernel path needs: the cause is the missing `CAP_BPF`. Under the unit's bounding set, raising `RLIMIT_MEMLOCK` fails and is not needed.

### The Program and Its Object

The program's source is `internal/bridge/relaybpf/relay.bpf.c`. `make bpf` compiles it in Docker, with clang, LLVM, libbpf and the Linux headers pinned to Alpine 3.22 packages, into `relay_bpfel.o`, which is committed and embedded in the binary, so `go build` needs no clang. The CI job `bpf` rebuilds the object and fails when it differs from the committed one (see [CI Workflow](../development/ci-workflow.md#bpf)). The source carries a `//go:build ignore` line, so the go tool does not take it for a cgo source of the package. The object declares the licence `Dual BSD/GPL`, because `bpf_fib_lookup` is restricted to GPL-compatible programs, and the source carries `SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)`.

| Object | Kind | Content |
|--------|------|---------|
| `relay_forward` | `tc` program | The checks and the rewrite above |
| `relay_sessions` | hash map | Key: the four receiver index bytes as they stand in the datagram. Value: the 88-byte `struct relay_session`, with the partner's address and port, the local address the partner sends to, the owner's address and port, the source towards the owner, the owner's interface, the time of the last forwarded datagram and the address family. At most 65,536 entries, as many as `relayMaxIndices` |
| `relay_counters` | per-CPU array | The nine counters, in the order of `relaybpf.CounterNames` |
| `relay_port`, `lookup_ifindex` | constants | The relay's listen port and the mesh interface's index, set when the program is loaded |

Package `relaybpf` loads the object with `github.com/cilium/ebpf` v0.22.0, which only files built for Linux import. Measured on 2026-11-26, the library adds 1.41 MB to the linux/amd64 binary and 1.51 MB to linux/mipsle.

### Measured Throughput

Measured on 2026-11-26 with a prototype of the kernel path, on Linux 6.8 on a Ryzen 9 6900HX. Two nodes with kernel WireGuard ran in network namespaces A and B, joined by veth pairs through a namespace R that either routed or ran plexd's relay, with `tx-udp-segmentation off` on all four veth ends. Each run was iperf3 TCP over 8 s, with the route caches flushed before it. R had IP forwarding off except in the first row, and its mesh interface was a WireGuard link with forwarding on.

| Path between the two nodes | 1 stream | 4 streams | Relay process | Retransmits, 1 and 4 streams | `UdpRcvbufErrors`, 1 and 4 streams |
|---|---|---|---|---|---|
| the kernel routes, no relay | 1.91 Gbit/s | 1.89 Gbit/s | none | 0 and 0 | 0 and 0 |
| relay in the process, default buffers | 1.14 Gbit/s | 1.12 Gbit/s | 1.33 to 1.37 cores | 1,346 and 6,457 | 1,969 and 10,207 |
| relay in the process, 7 MiB buffers | 1.08 Gbit/s | 1.08 Gbit/s | 1.49 cores | 0 and 688 | 0 and 991 |
| kernel path, IPv4 | 1.95 Gbit/s | 1.92 Gbit/s | 0.00 cores | 0 and 0 | 0 and 0 |
| kernel path, IPv6 between peers and relay | 1.88 Gbit/s | not run | 0.00 cores | 0 | 0 |
| program attached, forwarding off on the lookup device | 1.07 Gbit/s | 1.09 Gbit/s | 1.48 to 1.50 cores | 0 and 1,401 | 0 and 2,056 |

With the process off the path the relayed pair reaches the routed rate, with no retransmits and no measurable load from plexd. The 7 MiB buffers alone do not raise the rate: they remove the loss at the socket for one stream and cut it to about a tenth for four. On macOS, on Windows and on Linux before 6.6 the buffers are the whole change, and their effect on macOS and Windows was not measured. The last row is the cost of the per-datagram fallback when every lookup fails.

The same lab also measured the fallbacks:

- A node that moved to a new source port lost 0 of 40 pings: one datagram missed its entry, and the process learned the address and installed both entries again.
- With the link towards one node at 1,400 bytes, 5 of 5 pings of 1,392 bytes arrived: the lookup answered `BPF_FIB_LKUP_RET_FRAG_NEEDED` five times, and the socket sent them.
- With `net.ipv6.conf.<mesh interface>.forwarding` at 0, 20 of 20 pings over IPv6 arrived through the process, and the program forwarded none.

## Meeting on the Relay

Two peers behind hard NATs connect only when both are on the same relay at the same time. [Endpoint selection](../networking/wireguard.md#the-trial) therefore holds every relay of a peer's set, the first and each standby, as long as the entries before the first relay took together, so two such windows always overlap or touch. A peer that never connected only ever holds the first relay: after it, its walk starts over at the first entry, and it never dials a standby. A pull that changes a peer in this hold and does not move it to a new relay starts its walk over, a change of only a standby included.

A node does not wait for a relayed peer's handshake to turn 180 s old before it dials a relay:

- When a pull takes away the relay a peer is on, the node dials the pull's first relay at once. A pull that still names relays takes the relay away when the relay is not among them, or when the first relay changed to one other than the relay the peer is on. A peer the node reaches from the address of one of its relays counts as on that relay, whichever entry is programmed. The exception is a relayed peer that roamed there from another relay with no new handshake: it counts as on the relay programmed, and the node [moves it back](../networking/wireguard.md#the-trial), once per session. A peer that is not connected counts as on the relay programmed; a peer that opened a direct path while a relay entry was programmed keeps that path. When the set holds a hostname, the node cannot tell a direct path from that relay, so the programmed entry decides and such a peer moves too. It removes the device peer and adds it again, because the new relay would drop every packet of the old session with reason `unknown_index`. The fresh device peer has no session, so its next send starts a handshake over the new relay. Both nodes do this once their pulls name the new relay, and [First Contact](#first-contact) pairs their new initiations. A pair that returns to a relay it left under 180 s ago still has a live session there, so its handshake [waits one retry](#forwarding-table).
- A peer that runs over one of its relays, which the node tells from that relay's address on the peer's packets, gets a probe: one datagram through the tunnel, which the peer's WireGuard answers on a live path. A node that holds no failure-detection time probes the peer once it has received nothing for one trial, 30 s by default. When the received-byte counter still has not moved 15 s later, the node dials the next relay of the set the same way, and after the last relay the first again. With the defaults, such a node leaves a relay that stops forwarding 45 to 50 s after its last packet, up to 60 s. A node that holds the Domain's [failure-detection time](../networking/wireguard.md#failure-detection-time) probes the peer on every pass, whether or not the peer is silent, and dials the next relay the same way once it has received nothing from the peer for the time less one pass. At the Domain's default of 15 s that is 14 to 15 s after the relay's last packet. In a set of one the next relay is the same relay, so a relay that restarted and lost its [index table](#index-table-and-sweeper) carries the pair again after one such re-dial, within about a minute on a node that holds no failure-detection time.
- Such a peer stays on its relays after its connection fails and dials the next one. It does so at once and after each relay hold without a handshake, and stays off the direct entries, which already failed, until it tries them again. It tries them again in a [direct retry](../networking/wireguard.md#direct-retry) when a pull adds a direct entry that the peer's order did not hold and that did not leave it or fail a retry in the last 10 min, and when a change of the node's own local networks makes one of them on-link. A retry tries each direct entry for 10 s on a fresh device peer, which cuts the relayed session, and a handshake over a direct entry leaves the relay. On a node that holds no failure-detection time, whose pass runs every 5 s, a retry that fails costs the pair 10 to 15 s per entry, about 1 min with four entries and up to 2 min 15 s with nine. At the Domain's default of 15 s, with a pass every 1 s, it costs 10 to 11 s per entry, up to 44 s with four entries and 1 min 39 s with nine. Either way the handshake back over the relay takes about 5 s more, because the relay [holds back](#forwarding-table) its first initiation for one retry. The partner on the relay hears nothing meanwhile. A partner that holds no failure-detection time dials the next relay of its set after about 45 s, when its probe goes unanswered, and one that holds the default 15 s dials it after 14 to 15 s of silence. The peer also walks its direct entries again when a pull leaves it no relay or drops it, when its key rotates, or after a restart. A peer that WireGuard roamed from one relay of its set to another with a new handshake counts as on the relay that carries it. A peer that WireGuard roamed off its relays to a direct path no longer counts as on a relay, and walks its dial order again, up to its first relay, when that path fails.

Both nodes of a pair hold the same relay set for each other and detect a dead relay in the same window, so without a pull they move to the same standby. Every node of a Domain receives the same failure-detection time, so two nodes that hold it still detect a dead relay in the same window, and each counts the other's probes on every pass. With the defaults, the relay hold of at least 30 s and the 30 s a pending initiation stays a [fan-out](#first-contact) target together absorb the gap between the two sides. A standby relay carries the pair without an assignment for it, because a relay forwards among every peer of its pull. A relayed peer keeps a standby it moved to while the pull still lists that standby and names the same first relay, or names that standby first, so a pull that still names the dead relay first does not send it back.

See [Relay liveness probe](../networking/wireguard.md#relay-liveness-probe) and [Failure detection time](../networking/wireguard.md#failure-detection-time) for the timing.

A frozen bridge, such as a paused VM, can cut a pair that moved on when it resumes. Its socket queues the initiations the pair's WireGuard retries during the freeze. The guest's clock stops, so the session and the addresses still look fresh afterwards, and an initiation's timestamp is encrypted, so the relay cannot see its age. A re-dialed device peer has no recorded timestamp, so WireGuard accepts a queued initiation and moves the peer's endpoint to the resumed bridge, which drops the packets of the pair's new session with reason `unknown_index`. WireGuard repeats an unanswered initiation no sooner than 5 s later, and a backlog drains in milliseconds, so the relay [holds back the first initiation](#forwarding-table) of a pair it carries and forwards a later retry. Two paths stay open. When the freeze starts 4 s or more after the relay held back a rekey, and before its retry arrives, the queued initiations pass, which is roughly 1 % of pairs per freeze. A node that reached the standby by a roam kept its old keypair, so a queued transport packet, which the relay forwards by index, authenticates and moves it too. The node's [move back](../networking/wireguard.md#the-trial) bounds both at one pass: 5 s on a node that holds no failure-detection time, and 1 s at the Domain's default of 15 s. Holding back needs only the bridge upgraded, and the move back only the node. The cost: a pair that returns to a relay it left under 180 s ago, by that relay's clock, waits one retry.

Versions mix: a node on an older plexd dials the relay with the old 30 s trial and holds a relayed peer until its handshake is 180 s old, and the relay serves it like any other peer. Any older plexd dials only `fallback_endpoint`, the first relay, and never a standby. A pair with one side on an older plexd therefore fails over only when the control plane names a new first relay: the older side keeps dialing the first relay, and the newer side comes back to it each time it wraps around the set. A control plane without `fallback_endpoints` gives each peer at most one relay, which the node holds and dials again as described above. The probe is answered by the peer's WireGuard, not by its plexd, so it works against a node on any version. plexd v0.37.0 and older do not read the `failure_detection` block. Such a node, and a node that holds no failure-detection time because its control plane never sent a block, keeps the 30 s and 15 s windows of the probe, or the 180 s hold on a plexd that predates the probe. A failure-detection time of 15 s or more holds against a peer on any release. A peer that sends nothing on its own, such as an older plexd, a node that holds no failure-detection time or a plain WireGuard peer, answers a probe through its WireGuard's 10 s keepalive timer, so its answers arrive up to 11 s apart at 15 s, inside the 14 s of silence. A value under 15 s holds only once every node of the Domain runs a plexd that reads the block and has pulled the value. Until then, a relayed pair with a peer that sends nothing on its own dials a healthy relay again about once per `detect_after_seconds`, each time with a new handshake. plexd does not tell such a peer apart. A bridge on a plexd before v0.19.0 predates this relay and relays nothing (see [Removed: the Session-Based Relay](#removed-the-session-based-relay)).

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
- The relay never answers a datagram. Every drop is silent, an initiation it holds back for its retry included, and it sends only the datagrams it forwards, never back to their source.
- A handshake message whose `mac1` names no listed peer is dropped, so a sender that knows no peer's public key cannot get an initiation forwarded.
- A fan-out reaches at most 8 addresses, each of which sent a `mac1`-valid initiation within the last 30 s, and only the real target's WireGuard accepts the initiation.
- The handshake rate limit, 20 messages per second per source IP with a burst of 5, bounds the `mac1` scan. The index table holds at most 65536 entries, and so does the kernel's session table.
- The [kernel path](#kernel-forwarding) forwards only a transport datagram that matches an entry the process wrote: its receiver index, its source address and port, and the local address it was sent to. Every other packet passes to the socket unchanged. The program learns nothing, holds no key, answers nothing and never sends a datagram back to its source.
- Datagrams the kernel path forwards do not cross the host's netfilter rules. A rule that starts to drop a peer cuts a placed session only at its next handshake, which reaches the socket through the rules (see [Host Firewall](#host-firewall)).
- The kernel path needs `CAP_BPF`, which the systemd unit grants to plexd and with it to every hook plexd runs (see [Sandbox Options](../actions/sandbox-options.md)). The program's links close with the process, so nothing of it outlives plexd.
- Not defended: a Domain node or an on-path attacker that forges WireGuard headers can make the relay misroute a pair, a denial of service, but never gets plaintext, and the next genuine packet restores the address. A forged initiation from a peer's address can delay that pair's handshake by at most one retry, because the relay then holds back the pair's initiations for 4 s.

## Manager Integration

`NewManager` creates the relay with `NewRelay(logger)` when `Config.RelayEnabled` is `true`. The relay opens no socket until the reconcile handler configures it. `NewManager` always creates a `RelayStatusTracker`, with or without `RelayEnabled`, because a bridge without local consent reports its relay's state too (see [Relay Status Report](#relay-status-report)).

| Method               | Signature                 | Description |
|----------------------|---------------------------|-------------|
| `Relay`              | `() *Relay`               | Returns the relay; nil without `RelayEnabled` |
| `RelayStatusTracker` | `() *RelayStatusTracker`  | Returns the relay's [status tracker](#status-tracker), which the reconcile handler sets and the reporter reads; never nil |
| `EnableRelayKernelForwarding` | `()`             | Lets every later start of the relay try the [kernel path](#kernel-forwarding) through the mesh interface `Setup` received. Does nothing without `RelayEnabled`, and on macOS and Windows records only the interface's name. `plexd up` calls it right after `Setup`; `Setup` does not call it, so a test that sets `RelayEnabled` loads no program into the kernel of whoever runs it as root |

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

// Let the relay forward placed sessions in the kernel (Linux 6.6+)
mgr.EnableRelayKernelForwarding()

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
| `Assignments` | The peers whose first relay is this bridge. A peer that holds this bridge only as a standby relay is not listed, and the relay forwards for it all the same. Decoded and carried; the relay does not read it |

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
| `PeerNodeID`           | Node ID of a peer whose first relay is this bridge |
| `FallbackEndpoint`     | The host of that peer's first relay |
| `FallbackEndpointPort` | The port of that peer's first relay |

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
| Kernel path start (mesh interface) | `bridge: relay: kernel forwarding: mesh interface "<name>": ` |
| Kernel path start (load), and every read, forget and close of the kernel path | `bridge: relay: kernel forwarding: `, followed by an error of package `relaybpf` |
| Kernel path install (address families) | `bridge: relay: kernel forwarding: address families differ` |
| Kernel path install (link-local) | `bridge: relay: kernel forwarding: link-local address <addr>` |
| Kernel path install (route) | `bridge: relay: kernel forwarding: route to <addr>: ` |
| Kernel path install (interface) | `bridge: relay: kernel forwarding: interface <name> is not Ethernet` |
| Kernel path install (attach) | `bridge: relay: kernel forwarding: attach to <name>: ` |
| Kernel path install (write) | `bridge: relay: kernel forwarding: write session: ` |
| Kernel path close (IPv6 flag) | `bridge: relay: kernel forwarding: restore the ipv6 forwarding flag: ` |
| `relaybpf.Load` (object) | `relaybpf: read object: ` |
| `relaybpf.Load` (load) | `relaybpf: load: ` |
| `relaybpf.Load` (tcx probe) | `relaybpf: tcx attach probe: ` |
| `Forwarder.Attach` | `relaybpf: tcx attach: ` |
| `Forwarder.Put` (address families) | `relaybpf: session mixes address families` |
| `Forwarder.Put` | `relaybpf: write session: ` |
| `Forwarder.Delete` | `relaybpf: delete session: ` |
| `Forwarder.Age` | `relaybpf: read session: ` |
| `Forwarder.Ages` | `relaybpf: read sessions: ` |
| `Forwarder.Counters` | `relaybpf: read counter <name>: ` |
| `Forwarder.Put`, `Forwarder.Age` and `Forwarder.Ages` (clock) | `relaybpf: read clock: ` |
| `Forwarder.Close` | `relaybpf: tcx detach from interface <n>: ` |

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
| `Info`  | `relay: kernel forwarding started` | `listen_port`, `mesh_interface` |
| `Info`  | `relay: kernel forwarding unavailable, forwarding in the process` | `error`; logged once per start of the relay |
| `Info`  | `relay: kernel forwarding attached` | `interface`; logged for the first attach per interface, and again when a session needs an interface a sweep found unused, renamed or gone |
| `Warn`  | `relay: the control plane enables the relay, but bridge.relay_enabled is false` | `listen_port` |
| `Warn`  | `relay: skipping peer with invalid public key` | `peer_id` |
| `Warn`  | `relay: skipping peer with duplicate public key` | `peer_id` |
| `Warn`  | `relay: index table full` | `max_indices`; logged at most once a minute |
| `Warn`  | `relay status: rejected, this node was removed` | `code`; logged on every send |
| `Warn`  | `relay status: send failed` | `error` |
| `Warn`  | `relay status: shutdown report failed` | `error` |
| `Warn`  | `relay: kernel forwarding passes datagrams to the process, forwarding is off on the mesh interface` | `mesh_interface`; logged at most once a minute, when `fib_fwd_disabled` grew since the last sweep |
| `Warn`  | `relay: kernel forwarding stopped, forwarding in the process` | `error` |
| `Debug` | `relay: socket buffers set` | `receive_bytes`, `send_bytes`; or `error` when the sizes cannot be read back |
| `Debug` | `relay: kernel session installed` | `partner_id`, `owner_id` |
| `Debug` | `relay: kernel session not installed` | `partner_id`, `owner_id`, `error` |
| `Debug` | `relay: kernel forwarding counters` | `forwarded`, `no_session`, `mismatch`, `fib_fwd_disabled`, `fib_frag_needed`, `fib_no_neigh`, `fib_other`, `route_changed`, `gso`; logged after every sweep |
| `Debug` | `relay: kernel forwarding close failed` | `error` |
| `Debug` | `relay: ipv6 forwarding flag not set on the mesh interface` | `error` |
| `Debug` | `relay: dropped datagram` | `source`, `reason` (`not_wireguard`, `rate_limited`, `unknown_target`, `unknown_index`, `no_route`, `held_for_retry` or `index_table_full`) |
| `Debug` | `relay: read failed` | `error` |
| `Debug` | `relay: forward failed` | `dst`, `error` |
| `Debug` | `relay status: accepted` | `state`, `accepted_at` |
| `Debug` | `relay status: send failed` | `error`; logged instead of the Warn while the client holds a refused credential (`api.ErrCredentialRefused`) |
