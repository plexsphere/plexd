---
title: Reading a Node's Event Delivery Mode
package: internal/api
feature: PXD-0025
---

# Reading a Node's Event Delivery Mode

plexd receives control-plane state over a signed SSE event stream. When that
stream is unavailable, plexd keeps a node converged through its reconcile loop
instead. This guide shows how to determine which channel a node is currently
using and how to interpret and tune it.

## Check the current mode

The active channel is published as the node-API metadata key `delivery_mode`.
Read it with `plexd status`:

```bash
plexd status
```

```
Metadata entries: 4
Data keys:        3
Secret keys:      0
Report keys:      4

Metadata:
  delivery_mode: streaming
  environment: production
  region: eu-central-1
  role: worker
```

To read just the mode:

```bash
plexd status | grep delivery_mode
```

```
  delivery_mode: pull_only
```

## Interpret the mode

| Mode               | What it means                                                                 |
|--------------------|-------------------------------------------------------------------------------|
| `streaming`        | The SSE event stream is attached and live. This is the normal steady state.   |
| `pull_only`        | The platform's signed event bus is not provisioned for this node. The node still reconciles on its interval and re-probes SSE periodically. |
| `degraded_polling` | The SSE stream has been failing transiently. The node polls state every 60s and keeps retrying SSE. |

### `pull_only`

The control plane answered the events endpoint with `501` and the problem code
`signed_event_bus_not_provisioned`. This is a durable descope, not a transient
error, so plexd does not back off against a channel that is not there. Instead:

- The reconciler's own loop (default 60s, plus heartbeat reconcile hints) is the
  delivery channel — the node stays converged.
- plexd re-probes the SSE endpoint once per `api.sse_reprobe_interval`
  (default `10m`). A successful re-probe returns the node to `streaming`.

A node in `pull_only` is healthy; it is simply not receiving push events. If you
expect this node to stream events, check that the event bus is provisioned for
it on the control plane.

### `degraded_polling`

This is the transient fallback: after 5 minutes of failing SSE connections
(network errors, generic 5xx, `503 event_stream_unavailable`), plexd polls the
state endpoint every 60s while continuing to retry SSE. A successful reconnect
returns the node to `streaming`. Persistent `degraded_polling` points at a
connectivity or gateway problem between the node and the control plane.

## Tune the re-probe cadence

`pull_only` re-probes SSE every `api.sse_reprobe_interval`. Shorten it if you
want a re-provisioned node to return to `streaming` sooner:

```yaml
api:
  base_url: https://api.plexsphere.com
  sse_reprobe_interval: 2m   # default 10m; must be at least 1s when set
```

A negative value is rejected at config validation
(`api: config: SSEReprobeInterval must not be negative`), and a non-zero value
below one second is rejected
(`api: config: SSEReprobeInterval must be at least 1s`).

## Grep the logs

Mode transitions and descopes are logged. Search the agent log for:

- The descope, logged when the node enters pull-only delivery:

  ```
  SSE events endpoint descoped, entering pull-only delivery; the reconciler loop owns the pull
  ```

- Every mode change, logged with the new mode:

  ```
  event delivery mode changed  mode=pull_only
  ```

- The transient fallback and its recovery:

  ```
  SSE unavailable, falling back to polling
  SSE reconnected from polling fallback
  ```
