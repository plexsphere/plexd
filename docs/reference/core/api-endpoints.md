---
title: Control Plane API Endpoints
---

# Control Plane API Endpoints

plexd requires the following API endpoints on the control plane. All endpoints use the `/v1` prefix and HTTPS. Authentication uses the node's identity token (received during registration) unless noted otherwise. Request and response bodies are JSON (`Content-Type: application/json`) unless noted otherwise.

## Endpoint Summary

| # | Method | Path | Purpose |
|---|---|---|---|
| 1 | `POST` | `/v1/register` | Node registration |
| 2 | `GET` | `/v1/nodes/{node_id}/events` | SSE event stream |
| 3 | `POST` | `/v1/nodes/{node_id}/heartbeat` | Heartbeat |
| 4 | `POST` | `/v1/nodes/{node_id}/deregister` | Graceful deregistration |
| 5 | `POST` | `/v1/keys/rotate` | Key rotation |
| 6 | `PUT` | `/v1/nodes/{node_id}/capabilities` | Capability update |
| 7 | `PUT` | `/v1/nodes/{node_id}/endpoint` | NAT endpoint reporting |
| 8 | `GET` | `/v1/nodes/{node_id}/state` | Full state pull (reconciliation) |
| 9 | `POST` | `/v1/nodes/{node_id}/drift` | Drift reporting |
| 10 | `GET` | `/v1/nodes/{node_id}/secrets/{key}` | Secret fetch (NSK-encrypted) |
| 11 | `POST` | `/v1/nodes/{node_id}/report` | Report entry sync |
| 12 | `POST` | `/v1/nodes/{node_id}/executions/{execution_id}/ack` | Action ACK/NACK |
| 13 | `POST` | `/v1/nodes/{node_id}/executions/{execution_id}/result` | Action result |
| 14 | `POST` | `/v1/nodes/{node_id}/metrics` | Metrics batch |
| 15 | `POST` | `/v1/nodes/{node_id}/logs` | Log batch |
| 16 | `POST` | `/v1/nodes/{node_id}/audit` | Audit batch |
| 17 | `GET` | `/v1/artifacts/plexd/{version}/{os}/{arch}` | Binary download |

## Registration & Identity

### POST /v1/register

Unauthenticated (`security: []`): the one-time bootstrap token travels in the
request body, not an `Authorization` header. plexd sends no `Authorization`
header for this call.

**Request body:**

```json
{
  "project_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0",
  "resource_handle": "edge-router-01",
  "bootstrap_token": "psb_prod_aebagbafaydqqbrhibbsa3kqaq_node_xxxxxxxxxxxxxxxxxxxxxxxxxx",
  "nonce": "f3f8c0b8-7a0a-8a0a-a0a0-a0a0a0a0a0a0",
  "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
}
```

`requested_resource_id` may be added as an optional field. `hostname`,
`metadata`, and `capabilities` are no longer sent — capabilities are published
after registration via `PUT /v1/nodes/{node_id}/capabilities`.

**Response** (`201 Created`):

```json
{
  "node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3",
  "mesh_ip": "100.64.0.1",
  "signing_public_key": "MCowBQYDK2VwAyEA0123456789abcdefghijklmnopqrstuvwxyz0123=",
  "signing_key_id": "did:web:plexsphere.com#key-2026-04",
  "nsk": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
  "peer_snapshot": [],
  "domain_mesh_cidr": "100.64.0.0/10"
}
```

Each `peer_snapshot` entry is a narrow `RegisterPeer` (`node_id`, `mesh_ip`,
`public_key`, optional `fallback_endpoint`) — no `psk`, `allowed_ips`, or
`endpoint`.

**Errors** are RFC 9457 `application/problem+json` bodies (`type`, `title`,
`status`, `detail`, `instance`, and an optional machine-readable `code`). plexd
classifies each failure on the HTTP status and `code`; unknown codes are
tolerated. The bootstrap token is **never consumed on an error branch**.

| Status | Problem `code`(s) | Meaning | plexd behavior |
|---|---|---|---|
| `201 Created` | — | Registration successful | — |
| `400 Bad Request` | `public_key_invalid` (or none) | Malformed public key, or an undecodable body | Stop |
| `401 Unauthorized` | — | Bootstrap token rejected | Stop |
| `403 Forbidden` | `kind_mismatch`, `project_mismatch`, `token_consumed`, `token_expired`, `token_revoked`, `nonce_collision` | Terminal denial: wrong token kind or project, spent/expired/revoked token, or replayed nonce | Stop |
| `404 Not Found` | `resource_not_found` | Resource handle could not be resolved | Stop |
| `409 Conflict` | — | Conflicting registration | Stop |
| `422 Unprocessable Entity` | — | Request invariant violation (empty/oversized field, non-UUID `project_id`) | Stop |
| `429 Too Many Requests` | — | Rate limited | Retry, honoring `Retry-After` |
| `503 Service Unavailable` | `pool_exhausted`, `subrange_exhausted`, `allocator_contention` | Address allocation temporarily unavailable | Retry with backoff |
| `500 Internal Server Error` | — | Server error | Retry with backoff |

## SSE Event Stream

### GET /v1/nodes/{node_id}/events

Long-lived SSE connection. Supports `Last-Event-ID` header for replay after reconnection. Each event is a signed envelope.

**Event types:**

| Event Type | Payload Summary |
|---|---|
| `peer_added` | Peer identity, public key, mesh IP, endpoint, allowed IPs, PSK |
| `peer_removed` | Peer ID |
| `peer_key_rotated` | Peer ID, new public key, new PSK |
| `peer_endpoint_changed` | Peer ID, new endpoint |
| `policy_updated` | Full policy ruleset (L3/L4 rules scoped to mesh IPs) |
| `action_request` | Execution ID, action name, type, parameters, timeout, callback URL |
| `session_revoked` | Session ID, revocation timestamp |
| `ssh_session_setup` | Session token, target configuration |
| `rotate_keys` | Key rotation trigger |
| `signing_key_rotated` | New signing public key, valid_from, transition period |
| `node_state_updated` | Updated metadata and data entries |
| `node_secrets_updated` | Updated secret names and versions (never values) |

| Response | Meaning |
|---|---|
| `200 OK` | SSE stream established (text/event-stream) |
| `401 Unauthorized` | Invalid node identity |
| `404 Not Found` | Unknown node ID |

## Heartbeat

### POST /v1/nodes/{node_id}/heartbeat

Sent at `heartbeat.interval` (default 30s).

**Request body:**

```json
{
  "client_now": "2026-07-19T19:32:35Z",
  "binary_checksum": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "binary_version": "1.2.3",
  "nat_summary": { "endpoint": "203.0.113.7:51820", "nat_type": "full_cone" }
}
```

- `client_now` — RFC 3339 UTC timestamp, stamped fresh per request. The server rejects a skew greater than 60s in either direction.
- `binary_checksum` — SHA-256 of the running binary, computed once at startup. Accepted as 64-char lowercase hex or 44-char standard base64 of 32 bytes.
- `binary_version` — build version (`dev` when unset); never empty.
- `nat_summary` — **always** a JSON object: `{}` before NAT discovery has produced a result, otherwise `{ "endpoint": <public endpoint>, "nat_type": <wire enum> }`. A `null` value is rejected.

**Response** (`200 OK`):

```json
{
  "accepted_at": "2026-07-19T19:32:35Z",
  "reconcile": false,
  "rotate_keys": false
}
```

`accepted_at` is the server receive time; the agent logs it next to the local send time to estimate clock skew. `reconcile` triggers an immediate reconciliation; `rotate_keys` also triggers a reconcile.

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning |
|---|---|---|
| `200 OK` | — | Heartbeat acknowledged |
| `400 Bad Request` | `malformed_heartbeat_request` | Strict-decode failure, or `nat_summary` absent, `null`, or not an object |
| `400 Bad Request` | `clock_skew` | `client_now` more than 60s from server time |
| `400 Bad Request` | `binary_checksum_empty` | `binary_checksum` missing or not a valid SHA-256 encoding |
| `400 Bad Request` | `binary_version_empty` | `binary_version` missing |
| `401 Unauthorized` | — | Node identity invalid, re-register |

## Deregistration

### POST /v1/nodes/{node_id}/deregister

Sent on shutdown or explicit `plexd deregister` command. No request body.

| Response | Meaning |
|---|---|
| `200 OK` | Deregistration acknowledged |
| `401 Unauthorized` | Invalid node identity |

## Key Management

### POST /v1/keys/rotate

Called after receiving a `rotate_keys` SSE event.

**Request body:**

```json
{
  "node_id": "n_abc123",
  "new_public_key": "base64-encoded-curve25519-public-key"
}
```

**Response** (`200 OK`):

```json
{
  "updated_peers": [
    {
      "id": "n_peer456",
      "public_key": "base64-encoded-curve25519-public-key",
      "mesh_ip": "10.100.1.2",
      "endpoint": "203.0.113.10:51820",
      "allowed_ips": ["10.100.1.2/32"],
      "psk": "base64-encoded-new-psk"
    }
  ]
}
```

## Capabilities

### PUT /v1/nodes/{node_id}/capabilities

Sent when capabilities change after registration (hooks added/removed, binary updated).

Request body: Same `capabilities` structure as in `POST /v1/register`.

| Response | Meaning |
|---|---|
| `200 OK` | Capabilities updated |
| `401 Unauthorized` | Invalid node identity |

## NAT Endpoint Discovery

### PUT /v1/nodes/{node_id}/endpoint

Called after STUN discovery, then on a deadline derived from the response (see below). The response no longer carries peer endpoints — those arrive via the `peer_endpoint_changed` SSE event.

**Request body:**

```json
{
  "endpoint": "203.0.113.7:51820",
  "nat_type": "full_cone",
  "reported_at": "2026-07-19T19:32:35Z"
}
```

- `endpoint` — the discovered public endpoint as `ip:port`.
- `nat_type` — one of `full_cone`, `restricted`, `port_restricted`, `symmetric`, `unknown`.
- `reported_at` — RFC 3339 UTC, stamped fresh per attempt.

**Response** (`200 OK`):

```json
{
  "accepted_at": "2026-07-19T19:32:35Z",
  "stale_after": "2026-07-19T19:37:35Z"
}
```

`stale_after` is the deadline after which the server considers the endpoint stale. The node re-reports 30s before `stale_after` (floored at `nat.min_report_interval`, default `10s`), capped by `nat.refresh_interval`; a zero or absent `stale_after` falls back to the refresh interval. A deadline that shortens the cadence below `refresh_interval` is logged at `Warn` on the node.

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning |
|---|---|---|
| `200 OK` | — | Endpoint accepted |
| `400 Bad Request` | `malformed_endpoint_request` | Strict-decode failure, or `nat_type` outside the enum |
| `400 Bad Request` | `endpoint_clock_skew` | `reported_at` more than 60s from server time |
| `400 Bad Request` | `endpoint_unparseable` | `endpoint` is not a routable `ip:port` (bad port, or loopback/link-local/unspecified host) |
| `404 Not Found` | `endpoint_peer_not_found` | Node is not a known peer; heals via re-registration |
| `410 Gone` | `endpoint_peer_gone` | Node was removed; heals via re-registration |
| `413 Payload Too Large` | `endpoint_body_too_large` | Body exceeds 4 KiB |

## Reconciliation & State

### GET /v1/nodes/{node_id}/state

Called at `reconcile.interval` (default 60s) and on SSE reconnection.

**Response** (`200 OK`):

```json
{
  "peers": [
    {
      "id": "n_peer456",
      "public_key": "...",
      "mesh_ip": "10.100.1.2",
      "endpoint": "203.0.113.10:51820",
      "allowed_ips": ["10.100.1.2/32"],
      "psk": "..."
    }
  ],
  "policies": [
    {
      "id": "pol_abc",
      "rules": [ { "src": "10.100.1.0/24", "dst": "10.100.1.5/32", "port": 443, "protocol": "tcp", "action": "allow" } ]
    }
  ],
  "signing_keys": {
    "current": "base64-encoded-ed25519-public-key",
    "previous": "base64-encoded-ed25519-public-key-or-null",
    "transition_expires": "2025-01-16T10:30:00Z"
  },
  "metadata": { "environment": "production", "region": "eu-west-1" },
  "data": [
    { "key": "database-config", "content_type": "application/json", "payload": { "host": "db.internal", "port": 5432 }, "version": 3, "updated_at": "2025-01-15T10:30:00Z" }
  ],
  "secret_refs": [
    { "key": "tls-cert", "version": 2 }
  ]
}
```

### POST /v1/nodes/{node_id}/drift

Reports what was corrected during reconciliation.

**Request body:**

```json
{
  "timestamp": "2025-01-15T10:31:00Z",
  "corrections": [
    { "type": "peer_added", "detail": "n_peer789 was missing from WireGuard config" },
    { "type": "policy_rule_removed", "detail": "Stale rule for 10.100.1.99/32 removed" }
  ]
}
```

## Secrets

### GET /v1/nodes/{node_id}/secrets/{key}

Called on-demand when a consumer requests a secret via the Local Node API. Returns the value encrypted with the node's AES-256-GCM Node Secret Key (NSK).

**Response** (`200 OK`):

```json
{
  "key": "tls-cert",
  "ciphertext": "base64-encoded-aes-256-gcm-ciphertext",
  "nonce": "base64-encoded-gcm-nonce",
  "version": 2
}
```

| Response | Meaning |
|---|---|
| `200 OK` | Encrypted secret value |
| `401 Unauthorized` | Invalid node identity |
| `403 Forbidden` | Node not authorized to access this secret |
| `404 Not Found` | Secret key does not exist |

## Reports

### POST /v1/nodes/{node_id}/report

Batched report sync with debounce (default 5s).

**Request body:**

```json
{
  "entries": [
    {
      "key": "app-health",
      "content_type": "application/json",
      "payload": { "status": "healthy", "checked_at": "2025-01-15T10:30:00Z" },
      "version": 12,
      "updated_at": "2025-01-15T10:30:00Z"
    }
  ],
  "deleted": ["old-report-key"]
}
```

| Response | Meaning |
|---|---|
| `200 OK` | Report entries accepted |
| `401 Unauthorized` | Invalid node identity |
| `409 Conflict` | Version conflict on one or more entries |

## Action Execution Callbacks

### POST /v1/nodes/{node_id}/executions/{execution_id}/ack

Sent immediately after receiving an `action_request`.

**Request body:**

```json
{
  "execution_id": "exec_a1b2c3d4",
  "status": "accepted",
  "reason": ""
}
```

`status` is `accepted` or `rejected`. When rejected, `reason` provides the cause.

### POST /v1/nodes/{node_id}/executions/{execution_id}/result

Sent after action execution completes. Retried with exponential backoff on failure.

**Request body:**

```json
{
  "execution_id": "exec_a1b2c3d4",
  "status": "success",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "...",
  "duration": "2.34s",
  "finished_at": "2025-01-15T10:30:02Z",
  "triggered_by": {
    "type": "control_plane",
    "session_id": "",
    "user_id": "",
    "email": ""
  }
}
```

`status` is `success`, `failure`, `timeout`, or `cancelled`. `stdout` and `stderr` are truncated to 64 KiB each.

## Observability

All three observability endpoints use **gzip-compressed** request body with `Content-Encoding: gzip`.

### POST /v1/nodes/{node_id}/metrics

`Content-Type: application/json`, `Content-Encoding: gzip`

```json
[
  {
    "timestamp": "2025-01-15T10:30:00Z",
    "group": "node_resources",
    "data": { "cpu_percent": 23.5, "memory_used": 4294967296, "memory_total": 8589934592 }
  },
  {
    "timestamp": "2025-01-15T10:30:00Z",
    "group": "tunnel_health",
    "peer_id": "n_peer456",
    "data": { "handshake_age_seconds": 15, "tx_bytes": 1048576, "rx_bytes": 524288, "packet_loss_percent": 0.1 }
  }
]
```

### POST /v1/nodes/{node_id}/logs

`Content-Type: application/x-ndjson`, `Content-Encoding: gzip`

```
{"timestamp":"2025-01-15T10:30:00.123Z","source":"journald","unit":"plexd","message":"reconciliation completed, 0 drifts corrected","severity":"info","hostname":"web-01"}
{"timestamp":"2025-01-15T10:30:01.456Z","source":"journald","unit":"sshd","message":"Accepted publickey for admin","severity":"info","hostname":"web-01"}
```

### POST /v1/nodes/{node_id}/audit

`Content-Type: application/x-ndjson`, `Content-Encoding: gzip`

```
{"timestamp":"2025-01-15T10:30:00.456Z","source":"auditd","event_type":"SYSCALL","subject":{"uid":1000,"pid":4523,"comm":"sshd"},"object":{"path":"/etc/shadow"},"action":"open","result":"denied","hostname":"web-01","raw":"..."}
```

| Response | Meaning |
|---|---|
| `202 Accepted` | Batch received and queued for processing |
| `401 Unauthorized` | Invalid node identity |
| `413 Payload Too Large` | Batch exceeds server-side size limit |
| `429 Too Many Requests` | Rate limit exceeded, retry with backoff |

## Artifacts

### GET /v1/artifacts/plexd/{version}/{os}/{arch}

Called during `service.upgrade` action execution. Returns the binary as an octet stream.

| Parameter | Example | Description |
|---|---|---|
| `version` | `1.5.0` | Target version |
| `os` | `linux` | Operating system |
| `arch` | `amd64` | CPU architecture |

Response: `200 OK` with `Content-Type: application/octet-stream`. The SHA-256 checksum is provided in the `action_request` parameters and verified by plexd after download.
