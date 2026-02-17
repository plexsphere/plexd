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

Authenticated via one-time bootstrap token (not node identity).

**Request body:**

```json
{
  "token": "plx_enroll_a8f3c7...",
  "public_key": "base64-encoded-curve25519-public-key",
  "hostname": "web-01",
  "metadata": { "os": "linux", "arch": "amd64", "kernel": "6.1.0" },
  "capabilities": {
    "binary": { "version": "1.4.2", "checksum": "sha256:a1b2c3d4e5f6..." },
    "builtin_actions": [ { "name": "...", "description": "...", "parameters": [] } ],
    "hooks": [ { "name": "...", "description": "...", "source": "script", "checksum": "sha256:...", "parameters": [], "timeout": "300s", "sandbox": "namespaced" } ]
  }
}
```

**Response** (`201 Created`):

```json
{
  "node_id": "n_abc123",
  "mesh_ip": "10.100.1.1",
  "signing_public_key": "base64-encoded-ed25519-public-key",
  "node_secret_key": "base64-encoded-aes-256-key",
  "peers": [
    {
      "id": "n_peer456",
      "public_key": "base64-encoded-curve25519-public-key",
      "mesh_ip": "10.100.1.2",
      "endpoint": "203.0.113.10:51820",
      "allowed_ips": ["10.100.1.2/32"],
      "psk": "base64-encoded-psk"
    }
  ]
}
```

| Response | Meaning |
|---|---|
| `201 Created` | Registration successful |
| `400 Bad Request` | Invalid payload (missing fields, malformed key) |
| `401 Unauthorized` | Invalid, expired, or already-used bootstrap token |
| `409 Conflict` | Node with this hostname already registered in the tenant |

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
  "node_id": "n_abc123",
  "timestamp": "2025-01-15T10:30:00Z",
  "status": "healthy",
  "uptime": "72h15m",
  "binary_checksum": "sha256:a1b2c3d4e5f6...",
  "mesh": {
    "interface": "plexd0",
    "peer_count": 12,
    "listen_port": 51820
  },
  "nat": {
    "public_endpoint": "203.0.113.10:51820",
    "type": "full_cone"
  }
}
```

| Response | Meaning |
|---|---|
| `200 OK` | Heartbeat acknowledged |
| `200 OK` + `{ "reconcile": true }` | Trigger immediate reconciliation |
| `200 OK` + `{ "rotate_keys": true }` | Trigger key rotation |
| `401 Unauthorized` | Node identity invalid, re-register |

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

Called after STUN discovery and periodically at `nat_traversal.refresh_interval` (default 60s).

**Request body:**

```json
{
  "public_endpoint": "203.0.113.10:51820",
  "nat_type": "full_cone"
}
```

**Response** (`200 OK`):

```json
{
  "peer_endpoints": [
    {
      "peer_id": "n_peer456",
      "endpoint": "198.51.100.5:51820"
    }
  ]
}
```

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
