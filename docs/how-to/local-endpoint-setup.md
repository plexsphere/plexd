---
title: Setting Up Local Endpoint Delivery
package: internal/api
feature: PXD-0050
---

# Setting Up Local Endpoint Delivery

plexd can forward observability data (metrics, logs, audit events) to a local
HTTPS endpoint **in addition to** the Plexsphere control plane. This
dual-delivery model lets you feed data into your own monitoring stack
(Prometheus, Grafana Loki, Elasticsearch, etc.) without disrupting the
platform pipeline.

This guide walks through configuring local endpoint delivery from start to
finish. For detailed field definitions and internal architecture, see the
reference pages linked at the bottom.

## Key Concepts

Before starting, understand these design properties:

- **Dual delivery.** When a local endpoint is configured, data is sent to both
  the control plane and the local endpoint concurrently and independently.
- **Error isolation.** Local endpoint failures are logged as warnings but
  **never** block or affect platform delivery. The control plane always
  receives its data regardless of local endpoint health.
- **Fire-and-forget.** Local endpoint delivery has no retry or backoff
  mechanism. If a POST fails, the batch is not retried — the next scheduled
  batch will be a fresh delivery.
- **Identical payloads.** The local endpoint receives the same JSON body that
  the control plane receives. No transformation or reformatting is applied.
- **Shared configuration type.** The `local_endpoint` block uses the same
  `LocalEndpointConfig` type across all three pipelines (metrics, log
  forwarding, audit forwarding).

## Prerequisites

1. **plexd is running** on the node and successfully communicating with the
   control plane.

2. **An HTTPS endpoint** is available to receive the data. The URL must use
   the `https://` scheme — plain HTTP is rejected during config validation.

3. **A bearer token** is stored as a secret in the Plexsphere control plane.
   This secret will be fetched and decrypted at runtime by plexd (see
   [How Credential Resolution Works](#how-credential-resolution-works) below).

4. **Shell access** to the node for editing the plexd configuration file
   (default: `/etc/plexd/config.yaml`).

## How Credential Resolution Works

The `secret_key` field is **not** a literal bearer token. It is the **name**
of a secret stored in the Plexsphere control plane. At runtime, plexd resolves
the actual token through the following flow:

1. **You create a secret** in the Plexsphere control plane containing the
   bearer token that your local endpoint expects.
2. **You set `secret_key`** in the YAML config to that secret's name.
3. **At runtime**, plexd calls `FetchSecret` via the control plane API to
   retrieve the encrypted secret.
4. **plexd decrypts** the response using the Node Secret Key (NSK) via
   AES-256-GCM.
5. **The plaintext** is used as a `Bearer` token in the `Authorization` header
   of every POST to the local endpoint.

### Token Caching

- Resolved tokens are cached in memory with a **5-minute TTL**.
- If a refresh fetch or decryption fails and a stale cached token exists, the
  stale token is used as a fallback and a warning is logged.
- If no cached token exists and the fetch fails, the delivery is skipped for
  that cycle.

## Step-by-Step Configuration

### Step 1: Create the Bearer Token Secret

In the Plexsphere control plane, create a secret containing the bearer token
that your local endpoint expects for authentication. Note the secret name you
choose — you will reference it in the plexd configuration.

### Step 2: Add the `local_endpoint` Block to the Pipeline Config

Edit `/etc/plexd/config.yaml` and add a `local_endpoint` section under the
pipeline(s) you want to configure.

#### Metrics

```yaml
metrics:
  enabled: true
  collect_interval: 15s
  report_interval: 60s
  batch_size: 100
  local_endpoint:
    url: https://metrics.local:9090/ingest
    secret_key: local-metrics-token
    tls_insecure_skip_verify: false
```

#### Log Forwarding

```yaml
log_fwd:
  enabled: true
  collect_interval: 10s
  report_interval: 30s
  batch_size: 200
  local_endpoint:
    url: https://logs.local:3100/loki/api/v1/push
    secret_key: local-logs-token
    tls_insecure_skip_verify: false
```

#### Audit Forwarding

```yaml
audit_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 15s
  batch_size: 500
  local_endpoint:
    url: https://audit.local:9200/_bulk
    secret_key: local-audit-token
    tls_insecure_skip_verify: false
```

You can configure one, two, or all three pipelines independently.

### Step 3: Restart plexd

```bash
sudo systemctl restart plexd
```

### Step 4: Verify Delivery

Check the plexd logs for confirmation that local endpoints are enabled:

```bash
journalctl -u plexd --no-pager | grep 'local endpoint enabled'
```

You should see one log line per configured pipeline:

```
level=INFO msg="local endpoint enabled" pipeline=metrics url=https://metrics.local:9090/ingest
level=INFO msg="local endpoint enabled" pipeline=logfwd url=https://logs.local:3100/loki/api/v1/push
level=INFO msg="local endpoint enabled" pipeline=auditfwd url=https://audit.local:9200/_bulk
```

If a local endpoint encounters errors, warnings appear in the logs:

```
level=WARN msg="local metrics report failed" component=metrics error="POST https://metrics.local:9090/ingest: 503"
```

These warnings do **not** affect platform delivery.

## Common Use Cases

### Forwarding Metrics to a Prometheus-Compatible Receiver

plexd sends metrics as a JSON array of `MetricPoint` objects — this is **not**
the Prometheus remote-write format. To ingest into Prometheus or Mimir, you
need an adapter that accepts plexd's JSON payload and converts it to the
remote-write protocol.

```yaml
metrics:
  local_endpoint:
    url: https://prom-adapter.internal:8443/ingest
    secret_key: prom-adapter-token
```

The JSON payload contains metric groups (`system`, `tunnel`, `latency`,
`agent`) with timestamped data points. For the full payload schema your
adapter must handle, see the
[Metrics Collection Reference — API Contract](../reference/observability/metrics-collection.md#api-contract).

### Forwarding Logs to Grafana Loki

plexd sends log batches as a JSON array of `LogEntry` objects. Loki expects
a different format, so you need a middleware or custom receiver that
transforms the plexd JSON into Loki's push API format.

```yaml
log_fwd:
  local_endpoint:
    url: https://log-receiver.internal:8443/ingest
    secret_key: loki-ingest-token
```

Each log entry includes `timestamp`, `source`, `unit`, `message`, `severity`,
and `hostname` fields. For the full payload schema your adapter must handle,
see the
[Log Forwarding Reference — API Contract](../reference/observability/log-forwarding.md#api-contract).

### Forwarding Audit Data to Elasticsearch or a SIEM

plexd sends audit batches as a JSON array of `AuditEntry` objects. For
Elasticsearch, you need a receiver that transforms the plexd JSON into the
Elasticsearch bulk API format.

```yaml
audit_fwd:
  local_endpoint:
    url: https://audit-receiver.internal:8443/ingest
    secret_key: siem-ingest-token
```

Each audit entry includes `timestamp`, `source`, `event_type`, `subject`,
`object`, `action`, `result`, `hostname`, and `raw` fields. For the full
payload schema your adapter must handle, see the
[Audit Forwarding Reference — API Contract](../reference/observability/audit-forwarding.md#api-contract).

::: tip Payload Format
All three pipelines send **identical JSON payloads** to the local endpoint and
the control plane. The local endpoint receives plexd-specific JSON — not a
standard format like Prometheus remote-write, OpenTelemetry, or Elasticsearch
bulk. Plan for a receiving adapter if your monitoring stack requires a specific
ingest format.
:::

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| TLS: `certificate signed by unknown authority` | Self-signed or internal CA cert | Install the CA cert on the node, or set `tls_insecure_skip_verify: true` (dev only) |
| TLS: `certificate is valid for X, not Y` | URL hostname doesn't match cert CN/SAN | Use the hostname matching the certificate, or set `tls_insecure_skip_verify: true` (dev only) |
| `credential fetch failed` | `secret_key` doesn't match any control plane secret | Verify the secret name matches `secret_key` exactly |
| `secret decryption failed` | NSK mismatch after key rotation | Re-create the secret or re-register the node |
| No `local endpoint enabled` log | `url` is empty or pipeline is disabled | Set `url` to a non-empty HTTPS URL and `enabled: true` |
| HTTP 401/403 from endpoint | Bearer token incorrect or expired | Update the secret in the control plane with the correct token |
| HTTP 4xx/5xx from endpoint | Endpoint rejected the request | Check the endpoint's own logs; verify the URL path |
| `local * report failed` warnings | Endpoint unreachable or returning errors | Check connectivity and endpoint health. Platform delivery is unaffected. |
| `using cached credential` warning | Token refresh failed; stale token in use | Check control plane connectivity. Cached token used until refresh succeeds. |

### Verifying End-to-End Delivery

1. **Check plexd logs** for the `local endpoint enabled` message at startup.
2. **Monitor your local endpoint** for incoming POST requests with
   `Content-Type: application/json` and `Authorization: Bearer <token>`.
3. **Verify payload content** by inspecting the JSON body — it should match
   the schemas documented in the pipeline reference pages.

## Reference

- [Metrics Collection Reference](../reference/observability/metrics-collection.md) — LocalReporter, MultiReporter, credential resolution, metric schemas
- [Log Forwarding Reference](../reference/observability/log-forwarding.md) — LocalReporter, MultiReporter, log entry schemas
- [Audit Forwarding Reference](../reference/observability/audit-forwarding.md) — LocalReporter, MultiReporter, audit entry schemas
- [Configuration Reference](../reference/core/configuration.md) — All `local_endpoint` field definitions across pipelines
- [Key Storage Reference](../reference/core/key-storage.md) — Node Secret Key (NSK) and key lifecycle
- [Local Endpoint Integration Tests](../reference/development/local-endpoint-integration-tests.md) — Test coverage for dual delivery, error isolation, and credential resolution
