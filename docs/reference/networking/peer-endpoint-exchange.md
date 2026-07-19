---
title: Peer Endpoint Exchange
package: internal/peerexchange
feature: PXD-0007
---

# Peer Endpoint Exchange

The `internal/peerexchange` package orchestrates the exchange of discovered public endpoints between mesh peers. It wires together STUN-based NAT discovery (`internal/nat`), control plane endpoint reporting (`internal/api`), and WireGuard peer configuration (`internal/wireguard`) into a single lifecycle component.

The Exchanger is a thin orchestration layer. It delegates STUN discovery and the refresh loop to `nat.Discoverer.Run`, SSE event handling to `wireguard.HandlePeerEndpointChanged`, and endpoint reporting to `api.ControlPlane.ReportEndpoint`. No discovery, reporting, or WireGuard logic is duplicated.

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

When disabled, `Run` returns nil immediately. SSE handlers for inbound peer endpoint updates are still registered, so the node receives updates from peers that do use STUN.

## Exchanger

Central component managing the endpoint exchange lifecycle.

### Constructor

```go
func NewExchanger(
    discoverer *nat.Discoverer,
    wgManager  *wireguard.Manager,
    cpClient   *api.ControlPlane,
    cfg        Config,
    logger     *slog.Logger,
) *Exchanger
```

| Parameter    | Description                                       |
|--------------|---------------------------------------------------|
| `discoverer` | NAT discoverer (created with the WireGuard listen port) |
| `wgManager`  | WireGuard manager (applies inbound `peer_endpoint_changed` SSE updates) |
| `cpClient`   | Control plane client (wrapped as `nat.EndpointReporter`) |
| `cfg`        | Endpoint exchange configuration                   |
| `logger`     | Structured logger (`log/slog`)                    |

`NewExchanger` calls `cfg.ApplyDefaults()` automatically.

### Methods

| Method             | Signature                                          | Description                                                        |
|--------------------|----------------------------------------------------|--------------------------------------------------------------------|
| `RegisterHandlers` | `(sseManager *api.SSEManager)`                     | Registers `peer_endpoint_changed` SSE handler                      |
| `Run`              | `(ctx context.Context, nodeID string) error`       | Starts discovery + reporting loop (blocks until context cancelled)  |
| `LastResult`       | `() *nat.DiscoveryResult`                          | Most recent NAT info (thread-safe, nil before first discovery)     |

### Lifecycle

```go
// 1. Create dependencies
stunClient := &nat.UDPSTUNClient{Timeout: natCfg.Timeout}
discoverer := nat.NewDiscoverer(stunClient, natCfg, wgCfg.ListenPort, logger)
wgManager  := wireguard.NewManager(ctrl, wgCfg, logger)
cpClient, _ := api.NewControlPlane(apiCfg, version, logger)

// 2. Create exchanger
cfg := peerexchange.Config{}
cfg.Config = natCfg
exchanger := peerexchange.NewExchanger(discoverer, wgManager, cpClient, cfg, logger)

// 3. Register SSE handlers (before SSEManager.Start)
exchanger.RegisterHandlers(sseManager)

// 4. Run exchange loop (blocks until ctx done)
err := exchanger.Run(ctx, nodeID)
// returns ctx.Err() on cancellation
```

### RegisterHandlers

Registers `wireguard.HandlePeerEndpointChanged` for `peer_endpoint_changed` SSE events on the provided `SSEManager`. Must be called before `SSEManager.Start`.

Handlers are registered regardless of the `Enabled` flag. When NAT is disabled, the node still receives inbound endpoint updates from peers that use STUN.

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

  Inbound (SSE events)
  ┌──────────────┐  peer_endpoint_    ┌──────────────┐  UpdatePeer  ┌─────────────────┐
  │ Control Plane│  changed (SSE)     │ SSEManager   │─────────────▶│ WireGuard       │
  │ (api pkg)    │───────────────────▶│ (api pkg)    │              │ Manager         │
  └──────────────┘                    └──────────────┘              │ (wireguard pkg) │
                                                                    └─────────────────┘
```

**Outbound path** (report loop): STUN discovery produces the node's public endpoint. The Exchanger reports it to the control plane via `controlPlaneReporter` and receives a `stale_after` freshness deadline that schedules the next report. The response no longer carries peer endpoints.

**Inbound path** (SSE): When a remote peer discovers a new endpoint, the control plane pushes a `peer_endpoint_changed` SSE event. The registered `wireguard.HandlePeerEndpointChanged` handler updates WireGuard immediately, without waiting for the next report cycle. Once issue #20 lands, the reconciliation state pull carries peer endpoints too.

## Integration Points

### With internal/nat

- `nat.Discoverer` performs STUN discovery and runs the report loop
- `nat.Config` provides all configuration (embedded in `peerexchange.Config`)
- `nat.EndpointReporter` interface satisfied by `controlPlaneReporter` adapter
- `nat.DiscoveryResult` is the return type of `LastResult`

### With internal/wireguard

- `wireguard.Manager` applies inbound peer endpoint updates driven by the SSE handler
- `wireguard.HandlePeerEndpointChanged` provides the SSE event handler

### With internal/api

- `api.ControlPlane.ReportEndpoint` reports endpoints (wrapped by adapter)
- `api.SSEManager.RegisterHandler` registers the SSE handler
- `api.EventPeerEndpointChanged` is the event type constant

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
| `Debug` | SSE handler registered                | (none)                      |

Discovery and reporting logs use `component=nat` (from the `nat` package). See [NAT Traversal](nat-traversal.md) for those log entries.
