---
title: Peer Endpoint Exchange
package: internal/peerexchange
feature: PXD-0007
---

# Peer Endpoint Exchange

The `internal/peerexchange` package orchestrates the exchange of discovered public endpoints between mesh peers. It wires together STUN-based NAT discovery (`internal/nat`) and control plane endpoint reporting (`internal/api`) into a single lifecycle component.

The Exchanger is a thin orchestration layer. It delegates STUN discovery and the refresh loop to `nat.Discoverer.Run` and endpoint reporting to `api.ControlPlane.ReportEndpoint`. No discovery or reporting logic is duplicated. The Exchanger covers the outbound half only: the endpoints of other peers reach this node on the reconciliation state pull, not through the Exchanger (see [Data Flow](#data-flow)).

Beside the STUN endpoint, `nat.CandidatePublisher` publishes the node's local interface addresses as endpoint candidates on `PUT /v1/nodes/{node_id}/endpoint-candidates`. It is not part of the Exchanger and runs on its own loop, independent of `peer_exchange.enabled` and of STUN: `plexd up` starts it when the WireGuard interface came up and `nat.local_candidates` is not `false`, so a node whose STUN discovery fails still publishes its local addresses. See [Local endpoint candidates](nat-traversal.md#local-endpoint-candidates).

## Config

`Config` embeds `nat.Config`, reusing all NAT traversal settings.

```go
type Config struct {
    nat.Config
}
```

`ApplyDefaults()` and `Validate()` delegate to the embedded `nat.Config` methods. See [NAT Traversal](nat-traversal.md) for the full configuration reference.

```go
cfg := peerexchange.Config{}
cfg.ApplyDefaults() // Enabled=true, default STUN servers, RefreshInterval=60s, Timeout=5s
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

To disable endpoint exchange (e.g., nodes with static public IPs), set `Enabled=false` after `ApplyDefaults`:

```go
cfg := peerexchange.Config{}
cfg.ApplyDefaults()
cfg.Enabled = false
```

When disabled, `Run` returns nil immediately. The node still receives the endpoints of peers that do use STUN, because those arrive on the reconciliation state pull.

## Exchanger

Central component managing the endpoint exchange lifecycle.

### Constructor

```go
func NewExchanger(
    discoverer *nat.Discoverer,
    cpClient   *api.ControlPlane,
    cfg        Config,
    logger     *slog.Logger,
) *Exchanger
```

| Parameter    | Description                                       |
|--------------|---------------------------------------------------|
| `discoverer` | NAT discoverer (advertises the WireGuard listen port in reported endpoints) |
| `cpClient`   | Control plane client (wrapped as `nat.EndpointReporter`) |
| `cfg`        | Endpoint exchange configuration                   |
| `logger`     | Structured logger (`log/slog`)                    |

`NewExchanger` calls `cfg.ApplyDefaults()` automatically.

### Methods

| Method             | Signature                                          | Description                                                        |
|--------------------|----------------------------------------------------|--------------------------------------------------------------------|
| `Run`              | `(ctx context.Context, nodeID string) error`       | Starts discovery + reporting loop (blocks until context cancelled)  |
| `LastResult`       | `() *nat.DiscoveryResult`                          | Most recent NAT info (thread-safe, nil before first discovery)     |

### Lifecycle

```go
// 1. Create dependencies
stunClient := &nat.UDPSTUNClient{Timeout: natCfg.Timeout}
discoverer := nat.NewDiscoverer(stunClient, natCfg, wgCfg.ListenPort, logger)
cpClient, _ := api.NewControlPlane(apiCfg, version, logger)

// 2. Create exchanger
cfg := peerexchange.Config{}
cfg.Config = natCfg
exchanger := peerexchange.NewExchanger(discoverer, cpClient, cfg, logger)

// 3. Run exchange loop (blocks until ctx done)
err := exchanger.Run(ctx, nodeID)
// returns ctx.Err() on cancellation
```

### Run

When `Enabled=true`:

1. Log info with `component=exchange` and `node_id`
2. Create a `controlPlaneReporter` adapter wrapping `cpClient`
3. Call `discoverer.Run(ctx, reporter, nodeID)` — blocks until context cancelled

When `Enabled=false`:

1. Log info indicating NAT traversal is disabled
2. Return nil immediately

The full discovery/report loop is handled by `nat.Discoverer.Run`:

1. Initial STUN discovery — returns error if all servers fail
2. Report the endpoint to the control plane; the response's `stale_after` schedules the next report
3. Deadline-driven loop: re-discover, report, reschedule from `stale_after`
4. Context cancellation stops the loop

### LastResult

Delegates to `nat.Discoverer.LastResult()`. Returns `*nat.DiscoveryResult`, which the heartbeat builder folds into `nat_summary`:

```go
summary := map[string]any{}
if info := exchanger.LastResult(); info != nil {
    summary["endpoint"] = info.Endpoint
    summary["nat_type"] = info.NATType.Wire()
}
```

## controlPlaneReporter

Internal adapter wrapping `*api.ControlPlane` to satisfy the `nat.EndpointReporter` interface.

```go
type controlPlaneReporter struct {
    client *api.ControlPlane
}

func (r *controlPlaneReporter) ReportEndpoint(ctx context.Context, nodeID string, req api.EndpointRequest) (*api.EndpointResponse, error) {
    return r.client.ReportEndpoint(ctx, nodeID, req)
}
```

The adapter is created inside `Run` with the `cpClient` from the Exchanger. The `nodeID` flows through the `nat.Discoverer.Run` call, which passes it to `EndpointReporter.ReportEndpoint` on each cycle.

## Data Flow

```
  Outbound (STUN report loop)
  ┌─────────────┐   ReportEndpoint    ┌──────────────┐
  │ Discoverer  │────────────────────▶│ Control Plane│
  │ (nat pkg)   │◀────────────────────│ (api pkg)    │
  └─────────────┘   stale_after        └──────────────┘
        ▲              deadline
        │ STUN
  ┌─────┴───────┐
  │ STUN Servers│
  └─────────────┘

  Inbound (reconciliation state pull)
  ┌──────────────┐  GET /v1/nodes/{id}/state  ┌──────────────┐  AddPeer,    ┌─────────────────┐
  │ Control Plane│───────────────────────────▶│ Reconciler   │  UpdatePeer  │ WireGuard       │
  │ (api pkg)    │  peers[].endpoint          │ (reconcile)  │─────────────▶│ Manager         │
  └──────┬───────┘                            └──────▲───────┘              │ (wireguard pkg) │
         │ peer_endpoint_changed (SSE)               │                      └─────────────────┘
         └───────────────────────────────────────────┘
           triggers a reconcile; the payload is never decoded
```

**Outbound path** (report loop): STUN discovery produces the node's public endpoint. The Exchanger reports it to the control plane via `controlPlaneReporter` and receives a `stale_after` freshness deadline that schedules the next report. The response no longer carries peer endpoints.

**Inbound path** (state pull): The endpoint a remote peer reports reaches this node as the `endpoint` member of that peer in `GET /v1/nodes/{node_id}/state`. The member is absent while the peer has no fresh observation. When a peer reports a new endpoint, the control plane pushes a `peer_endpoint_changed` SSE event. `plexd up` registers the event as a reconcile trigger and never decodes its payload, so the new endpoint arrives on the pull the event brings forward. The same pull carries the peer's `endpoint_candidates`: its peer-observed endpoints first, then its local candidates (see [Peer-observed endpoints](#peer-observed-endpoints)). The WireGuard reconcile handler builds the peer's dial order from its candidates, its usable direct endpoint and its `fallback_endpoint`, and endpoint selection keeps the first entry that completes a handshake (see [Dial order](wireguard.md#dial-order)).

### Peer-observed endpoints

A peer's `endpoint_candidates` can hold addresses the peer never reported: its peer-observed endpoints, which the control plane lists ahead of its local candidates. They come from other nodes' handshake reports. Every node's [handshake reporter](../core/heartbeat-service.md#handshake-reporter) sends the endpoint WireGuard used for each peer it completed a handshake with, so this node counts as one of a peer's observers while it has a direct handshake with that peer within the Domain's endpoint TTL. A handshake through the peer's relay fallback never counts. The rule that turns those reports into a candidate is under [State](../core/api-endpoints.md#get-v1-nodes-node-id-state).

The wire does not mark which entry is which, so plexd orders a peer-observed endpoint like any other candidate (see [Dial order](wireguard.md#dial-order)). A mapping is usually off-link, so it is tried after the peer's usable direct endpoint and before its fallback.

A peer-observed endpoint appears on a pull once a second node reports it, and leaves once fewer than two of those reports are within the Domain's endpoint TTL. Each change is a change to `endpoint_candidates`, so the differ updates the peer: a peer that runs over its relay, or ran over it before its connection failed, stays on the relay, another connected peer keeps the endpoint on its device, and any other peer restarts at the first entry of its dial order (see [Endpoint selection](wireguard.md#endpoint-selection)).

A wrong entry costs one trial, the keepalive interval plus 5 s (30 s by default), because WireGuard completes a handshake only with the holder of the peer's key. plexd holds every entry to the usability rules of the direct endpoint, the Domain mesh prefix check included, which the control plane does not apply.

`nat.local_candidates: false` withholds only this node's local candidates. Peers still receive its peer-observed endpoints, because those come from other nodes' reports.

## Integration Points

### With internal/nat

- `nat.Discoverer` performs STUN discovery and runs the report loop
- `nat.Config` provides all configuration (embedded in `peerexchange.Config`)
- `nat.EndpointReporter` interface satisfied by `controlPlaneReporter` adapter
- `nat.DiscoveryResult` is the return type of `LastResult`
- `nat.CandidatePublisher` runs beside the Exchanger, not inside it, and publishes the local endpoint candidates

### With internal/wireguard

The Exchanger does not program WireGuard. Inbound peer endpoints reach the device through `wireguard.ReconcileHandler`, which the reconciler runs when a state pull shows drift (a changed `endpoint`, `fallback_endpoint` or `endpoint_candidates` counts as a peer update). The handler builds each peer's dial order, and `Manager.RunEndpointSelection` tries it until a handshake completes (see [Endpoint selection](wireguard.md#endpoint-selection)).

### With internal/api

- `api.ControlPlane.ReportEndpoint` reports endpoints (wrapped by adapter)
- `api.SnapshotPeer.Endpoint` carries a peer's direct endpoint on the state pull, and `api.SnapshotPeer.EndpointCandidates` its endpoint candidates (peer-observed endpoints, then local candidates)
- `api.EventPeerEndpointChanged` is the event type `plexd up` registers as a reconcile trigger; the Exchanger registers no SSE handler

## Error Handling

| Scenario                        | Behavior                                               |
|---------------------------------|--------------------------------------------------------|
| All STUN servers fail (initial) | `Run` returns error from `nat.Discoverer.Run`          |
| STUN refresh failure            | Log warn, keep previous endpoint, retry next cycle     |
| Endpoint report failure         | Log warn, continue report loop                         |
| Context cancellation            | Clean abort, return `ctx.Err()`                        |
| NAT disabled                    | `Run` returns nil immediately                          |

## Logging

All log entries use `component=exchange`.

| Level   | Event                                 | Keys                        |
|---------|---------------------------------------|-----------------------------|
| `Info`  | Starting endpoint exchange            | `node_id`                   |
| `Info`  | NAT traversal disabled                | (none)                      |

Discovery and reporting logs use `component=nat` (from the `nat` package). See [NAT Traversal](nat-traversal.md) for those log entries.
