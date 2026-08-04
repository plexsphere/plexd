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
| 4 | `POST` | `/v1/keys/rotate` | Key rotation |
| 5 | `PUT` | `/v1/nodes/{node_id}/capabilities` | Capability update |
| 6 | `PUT` | `/v1/nodes/{node_id}/endpoint` | NAT endpoint reporting |
| 7 | `GET` | `/v1/nodes/{node_id}/state` | State snapshot pull (reconciliation) |
| 8 | `GET` | `/v1/nodes/{node_id}/secrets/{key}` | Secret envelope fetch (NSK-encrypted octet-stream) |
| 9 | `PUT` | `/v1/nodes/{node_id}/state/reports/{key}` | Per-key state report upsert |
| 10 | `DELETE` | `/v1/nodes/{node_id}/state/reports/{key}` | Per-key state report delete |
| 11 | `POST` | `/v1/nodes/{node_id}/executions/{execution_id}` | Action execution callback |
| 12 | `POST` | `/v1/nodes/{node_id}/sessions/{session_id}` | Session activity record |
| 13 | `POST` | `/v1/nodes/{node_id}/metrics` | Metrics batch |
| 14 | `POST` | `/v1/nodes/{node_id}/logs` | Log batch |
| 15 | `POST` | `/v1/nodes/{node_id}/audit` | Audit batch |

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
`status`, `detail`, `instance`, an optional `correlation_id`, and an optional
machine-readable `code`). Every error response also carries the id on the
`X-Correlation-Id` response header; plexd reads the body member first and falls
back to the header, and reads neither from a response that is not
`application/problem+json`. plexd classifies each failure on the HTTP status and
`code`; unknown codes are tolerated. plexd carries the id it read into the error
string of the failed call, so an operator can quote it against the control-plane
log. The bootstrap token is **never consumed on an error branch**.

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
| `action_request` | Opaque; triggers a reconcile — the dispatch itself rides the `executions` block of the state pull |
| `session_setup` | Opaque; triggers a reconcile — the session itself rides the `sessions` block of the state pull |
| `session_revoked` | Opaque; triggers a reconcile — the session leaving the `sessions` block is what tears it down |
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

## Key Management

### POST /v1/keys/rotate

Called after a `rotate_keys` signal — the heartbeat `rotate_keys` flag or a
`rotate_keys` SSE event — to complete a pending mesh-key rotation. The request
carries no node id; the server identifies the rotating node from its NSK bearer
credential. The node stages a fresh keypair before submitting its public key.

**Request body:**

```json
{
  "new_public_key": "base64-encoded-curve25519-public-key"
}
```

**Response** (`200 OK`) is a rotation receipt — never a peer list. The propagated
peer and PSK changes arrive via the next state pull.

```json
{
  "rotation_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d1",
  "kid": "did:web:plexsphere.com#psk-2026-04",
  "wrap_key_version": 3
}
```

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning |
|---|---|---|
| `200 OK` | — | Rotation completed; an idempotent retry of a completed rotation replays the prior receipt |
| `400 Bad Request` | `malformed_keys_rotate_request` | Body is unreadable or fails strict decoding |
| `401 Unauthorized` | `unauthorized`, `nsk_invalid`, `nsk_revoked` | NSK bearer credential missing, invalid, or revoked |
| `403 Forbidden` | — | ReBAC denial |
| `404 Not Found` | `keys_rotate_peer_not_found` | Rotating node is not a known peer |
| `409 Conflict` | `keys_rotate_no_pending_rotation` | No rotation is pending for this node |
| `413 Payload Too Large` | `keys_rotate_body_too_large` | Body exceeds 4 KiB |
| `422 Unprocessable Entity` | `keys_rotate_public_key_invalid` | `new_public_key` is not 32 bytes or is all-zero |
| `422 Unprocessable Entity` | `keys_rotate_public_key_unchanged` | `new_public_key` is byte-identical to the node's current key |
| `500 Internal Server Error` | — | Rotation transaction rolled back |

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

Called at `reconcile.interval` (default 60s) and on SSE reconnection. Returns the
`NodeStateSnapshot` envelope. Every block key is always present; a `null` value
means "block not populated" — the differ compares by presence, not by field
absence.

**Response** (`200 OK`):

```json
{
  "peers": [
    {
      "node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1",
      "mesh_ip": "10.99.0.2",
      "public_key": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
      "fallback_endpoint": "203.0.113.1:51820"
    },
    {
      "node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2",
      "mesh_ip": "10.99.0.3",
      "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
    }
  ],
  "reachability": {
    "state": "healthy",
    "last_heartbeat_at": "2026-01-01T00:00:00Z",
    "changed_at": "2026-01-01T00:00:00Z"
  },
  "policy": {
    "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1",
    "fingerprint": "j7Hn2mF0oQ9rXcV8yZ1aB4cD6eF8gH0iJ2kL4mN6oM=",
    "rules": [
      { "action": "allow", "protocol": "any", "source_cidr": "10.99.0.0/24", "destination_cidr": "10.99.0.0/24" },
      { "action": "allow", "protocol": "tcp", "source_cidr": "10.99.0.0/24", "destination_cidr": "0.0.0.0/0", "ports": { "from": 443, "to": 443 } }
    ]
  },
  "bridge": {
    "relay": { "sessions": [] },
    "user_access": null,
    "ingress": null,
    "site_to_site": null
  },
  "state": {
    "metadata": [
      { "key": "environment", "value": "production" },
      { "key": "region", "value": "eu-west-1" }
    ],
    "data": [
      { "key": "app/config", "value": "{\"log_level\":\"info\",\"max_conns\":100}" }
    ],
    "reports": []
  },
  "reports": {
    "metadata": [],
    "data": [],
    "reports": []
  },
  "executions": [
    {
      "execution_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d1",
      "action": "diagnostics.collect",
      "type": "builtin",
      "parameters": { "include_network": true },
      "status": "pending",
      "requested_at": "2026-01-01T00:00:00Z",
      "expires_at": "2026-01-01T00:05:00Z"
    }
  ],
  "sessions": [
    {
      "session_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1",
      "jti": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1",
      "kind": "tcp",
      "target": { "tcp": { "host": "10.99.0.2", "port": 22 } },
      "expires_at": "2026-01-01T01:00:00Z",
      "idle_timeout_seconds": 900
    }
  ]
}
```

`reachability` is the control plane's own verdict about this node, derived from
the heartbeats it has admitted. `state` is one of `healthy`, `stale`,
`unreachable`, or `never_reported`; the set is the control plane's to grow, so
plexd carries an unknown value through rather than rejecting it.
`never_reported` is the verdict a node is born with — its first heartbeat has
never been admitted — and `last_heartbeat_at` is absent for exactly as long as
that holds. `changed_at` is always present. The block is a diagnostic
projection, never desired state: plexd logs the verdict whenever it changes and
neither stores nor converges on it. The same projection is served at
`GET /v1/nodes/{node_id}/reachability`, which plexd does not call because the
pull already carries it.

`executions` is the delivery channel for action dispatches, and the only block
that is a delivery queue rather than desired state. It is always an array — `[]` when empty, never `null` —
ordered by `requested_at`, then `execution_id`. An entry keeps reappearing on
every pull until its execution reaches a terminal status through the
[execution callback](#action-execution-callbacks), so a consumer
must tolerate re-observing the same `execution_id`. `expires_at` is an absolute
UTC deadline, not a relative timeout; the entry carries no callback URL and no
hook checksum. See [Remote Actions and Hooks](/reference/actions/remote-actions-hooks)
for how plexd consumes it.

`sessions` carries the node's live mediated-access sessions. It is desired state
rather than a queue: an entry stands for as long as its session is valid, and its
disappearance — on revocation or hard expiry — is the teardown signal, so there is
no revocation event to answer and no terminal status to report. It is always an
array (`[]` when empty, never `null`). `kind` is one of `ssh`, `k8s`, or `tcp` and
selects the single member of `target`; `jti` equals `session_id` and is carried
opaquely; `expires_at` is an absolute UTC timestamp; `idle_timeout_seconds` absent
or `0` means the session has no idle window. See
[Secure Access Tunneling](/reference/networking/secure-access-tunneling) for how
plexd consumes it.

## Secrets

### GET /v1/nodes/{node_id}/secrets/{key}

Called on-demand when a consumer requests a secret via the Local Node API. The
`{key}` is validated client-side against the name grammar
`^[a-z][a-z0-9_-]{0,62}$` **before any request is sent** — a name outside the
grammar fails locally without touching the control plane. An optional
`?version=N` query (`N` a positive integer) selects an older version; omitting it
returns the current version.

**Response** (`200 OK`) is `Content-Type: application/octet-stream`, not JSON:
the body is the raw AES-256-GCM envelope `<12-byte nonce> || <ciphertext +
16-byte GCM tag>`, opened with AES-256-GCM under the node's NSK. The ciphertext
is capped at 1 MiB (28 bytes of nonce + GCM-tag overhead on top). The metadata
rides in response headers rather than the body:

| Header | Meaning |
|---|---|
| `X-Plexsphere-Secret-Version` | Version of the returned secret (a positive integer) |
| `X-Plexsphere-Secret-KID` | Key id of the NSK the envelope was sealed under |
| `Cache-Control` | Always `no-store` — the plaintext is never cached |

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning |
|---|---|---|
| `200 OK` | — | Encrypted secret envelope (octet-stream) |
| `401 Unauthorized` | — | Invalid node identity |
| `403 Forbidden` | `permission_denied` | Node not authorized to access this secret |
| `404 Not Found` | `secret_not_found` | Secret name does not exist |
| `404 Not Found` | `secret_version_not_found` | The requested `?version` does not exist |
| `429 Too Many Requests` | `per_node_rate_limited` | Per-node fetch rate limit; honor `Retry-After` |
| `429 Too Many Requests` | `per_domain_rate_limited` | Per-domain fetch rate limit; honor `Retry-After` |
| `500 Internal Server Error` | — | Server error |
| `501 Not Implemented` | `secrets_not_provisioned` | Secret storage is not provisioned for this node |
| `503 Service Unavailable` | `openbao_unavailable` | Secret backend temporarily unavailable |

## Reports

The node publishes local report entries to the control plane one key at a time.
The Local Node API's per-key syncer flushes dirty keys in ascending order,
debounced (default 5s) to coalesce bursts. `{key}` follows the grammar
`^[a-z][a-z0-9._-]{0,127}$`, and the serialized `value` is capped at 4096 bytes.

### PUT /v1/nodes/{node_id}/state/reports/{key}

Upserts the report stored under `{key}`.

**Request body:**

```json
{
  "value": "{\"status\":\"healthy\",\"checked_at\":\"2025-01-15T10:30:00Z\"}",
  "workload_tag": "web"
}
```

- `value` — the opaque report payload; at most 4096 bytes.
- `workload_tag` — optional; attributes the report to a workload.

**Response** (`200 OK`):

```json
{
  "accepted_at": "2025-01-15T10:30:00Z",
  "key": "app-health"
}
```

| Status | Problem `code` | Meaning |
|---|---|---|
| `200 OK` | — | Report upserted |
| `400 Bad Request` | `invalid_report` | Key is outside the grammar, the body is malformed, or `value` exceeds 4096 bytes |
| `401 Unauthorized` | — | Invalid node identity |
| `501 Not Implemented` | `reports_not_provisioned` | State reports are not provisioned; the node suppresses report sync for 5 minutes |

### DELETE /v1/nodes/{node_id}/state/reports/{key}

Removes the report stored under `{key}`.

| Status | Problem `code` | Meaning |
|---|---|---|
| `204 No Content` | — | Report deleted |
| `400 Bad Request` | `invalid_report` | Key is outside the grammar |
| `404 Not Found` | `report_not_found` | No report exists for this key (the syncer treats this as success) |
| `501 Not Implemented` | `reports_not_provisioned` | State reports are not provisioned; the node suppresses report sync for 5 minutes |

## Action Execution Callbacks

### POST /v1/nodes/{node_id}/executions/{execution_id}

A single callback advances an execution through a closed state machine, posted
once per transition. The edge roster is closed and a terminal status is reachable
**only from `started`**:

```text
pending ──▶ ack ──▶ started ──▶ succeeded
                        │  ├──▶ failed
                        │  └──▶ cancelled
                        └──▶ started   (self-edge, only to declare an
                                        over-ceiling output size)
```

- `pending` — the status a freshly dispatched entry carries in the `executions`
  block. It is never reported by a node.
- `ack` — sent when the node picks up an entry the pull reports as `pending`; it
  opens the invocation. An entry the pull already reports at `ack` is **not**
  re-acked — repeating a recorded transition is answered `409`.
- `started` — sent when the action begins running.
- `succeeded` | `failed` | `cancelled` — the terminal callback.

`ack → failed` and `ack → cancelled` are **not** legal edges. A node that refuses
to run an action (unknown action, actions disabled) therefore walks every
remaining legal edge before failing it — three callbacks for a `pending` entry
(`ack` → `started` → `failed`), two for an `ack` entry, one for a `started` entry.

Local backpressure — shutting down, an id already in flight, a saturated
concurrency slot — produces **no callback at all**: the entry stays in the
`executions` block and the next pull redelivers it.

When a callback is refused with `403` or `409`, plexd stops without running or
terminal-reporting the execution; other callback errors are logged and tolerated.

**Request body** (`ack`):

```json
{ "status": "ack" }
```

**Response** (`200 OK`) carries the new invocation status:

```json
{ "status": "ack" }
```

**Request body** (terminal `succeeded` with inline output). Output at most 16 KiB
travels base64-encoded in `output.inline`; `exit_code` is an explicit number:

```json
{
  "status": "succeeded",
  "exit_code": 0,
  "output": { "inline": "aGVsbG8gd29ybGQK" }
}
```

**Request body** (terminal `failed` for a rejected action):

```json
{ "status": "failed", "error": "unknown_action" }
```

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning | plexd behavior |
|---|---|---|---|
| `200 OK` | — | Callback accepted; body carries the new status | — |
| `400 Bad Request` | `malformed_execution_callback` | Unreadable/strict-decode failure, status outside the reportable set, non-base64 inline output, or an `object_key`/`sha256` that does not match a received upload | Logged, tolerated |
| `403 Forbidden` | `nsk_node_mismatch` | Callback targets a node other than the caller's identity | Abort |
| `409 Conflict` | `invalid_state_transition` | Illegal lifecycle advance | Abort |
| `409 Conflict` | `execution_already_terminal` | Callback on an already-settled invocation | Abort |
| `413 Payload Too Large` | `inline_output_too_large` | `output.inline` decodes to more than 16 KiB | Logged, tolerated |

#### Over-ceiling output: declare, upload, reference

Output larger than 16 KiB does not travel inline. Instead the node re-posts
`started` declaring the byte count, uploads the raw bytes to a presigned URL, and
references the object on the terminal callback.

**Declaring callback** — re-post `started` with `declared_output_bytes`:

```json
{ "status": "started", "declared_output_bytes": 524288 }
```

**Response** (`200 OK`) carries a one-time presigned PUT URL. The node derives the
object key from the URL path:

```json
{
  "status": "started",
  "output_upload_url": "https://blob.plexsphere.com/exec-output/exec_a1b2c3d4?token=b1c2d3e4"
}
```

The node then `PUT`s the raw bytes to `output_upload_url` with
`Content-Type: application/octet-stream` and **no** bearer token — the presigned
URL carries its own authentication. That upload responds `404` for an unknown or
expired token, `409` if the URL has already been used, and `413` if the body
exceeds the declared size.

The node rejects an `output_upload_url` whose scheme is weaker than the
configured control-plane base URL, and does not follow redirects on the upload —
the body is captured action output and must not be re-sent in the clear or to a
host the control plane did not name directly.

**Terminal callback** — reference the uploaded object by key and lowercase-hex
SHA-256:

```json
{
  "status": "succeeded",
  "exit_code": 0,
  "output": {
    "object_key": "exec-output/exec_a1b2c3d4",
    "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
  }
}
```

If any step of the upload leg fails, plexd falls back to truncated inline output
on the terminal callback.

## Session Activity

### POST /v1/nodes/{node_id}/sessions/{session_id}

A one-of activity record carrying exactly one of `ssh`, `k8s`, or `tcp`. plexd's
tunnel subsystem is an opaque TCP forwarder, so it emits only `tcp` rows: a
`session_started` row when the listener comes up and a `session_ended` row on
close.

**Request body** (`session_started`). `listener_endpoint` is the address the node
actually bound, so the control plane has somewhere to send the operator; it is
set on started rows only:

```json
{
  "tcp": {
    "phase": "session_started",
    "target_host": "10.99.0.2",
    "target_port": 22,
    "listener_endpoint": "10.99.0.1:34567"
  }
}
```

**Request body** (`session_ended`). `bytes_in` (operator→target) and `bytes_out`
(target→operator) are explicit, present even when `0`; `terminated_by` is one of
`ttl_expired`, `idle_timeout`, `operator_revoke`, or `plexd_close`. plexd itself
never sends `operator_revoke`: a revoked session reaches the node as the absence
of its entry, which is indistinguishable from a control plane that failed to
serve the block, so a drained entry is reported as `plexd_close`:

```json
{
  "tcp": {
    "phase": "session_ended",
    "target_host": "10.99.0.2",
    "target_port": 22,
    "bytes_in": 4096,
    "bytes_out": 8192,
    "terminated_by": "plexd_close"
  }
}
```

| Response | Meaning |
|---|---|
| `204 No Content` | Activity record accepted |
| `400 Bad Request` (`malformed_session_activity`) | Body is unreadable, fails strict decoding, or violates the one-of contract |
| `403 Forbidden` (`nsk_node_mismatch`) | Record targets a node other than the caller's identity |

## Observability

All three ingest endpoints stamp an `X-Plexsphere-Sent-At` header (RFC 3339,
nanosecond precision, UTC) and gzip the request body when it exceeds 1 KiB
(`Content-Encoding: gzip`). Success is `202 Accepted` with an `IngestReceipt`
(`{ "accepted_at", "records" }`).

### POST /v1/nodes/{node_id}/metrics

`Content-Type: application/json` — a JSON array of `MetricSample`.

```json
[
  {
    "group": "node_resources",
    "name": "cpu_usage_percent",
    "value": 23.5,
    "timestamp": "2025-01-15T10:30:00Z"
  },
  {
    "group": "tunnel_health",
    "name": "rx_bytes",
    "value": 524288,
    "labels": { "peer_id": "n_peer456" },
    "timestamp": "2025-01-15T10:30:00Z"
  }
]
```

### POST /v1/nodes/{node_id}/logs

`Content-Type: application/x-ndjson` — one `LogLine` per line.

```
{"severity":"info","unit":"plexd","hostname":"web-01","message":"reconciliation completed, 0 drifts corrected","timestamp":"2025-01-15T10:30:00.123Z"}
{"severity":"info","unit":"sshd","hostname":"web-01","message":"Accepted publickey for admin","timestamp":"2025-01-15T10:30:01.456Z"}
```

### POST /v1/nodes/{node_id}/audit

`Content-Type: application/x-ndjson` — one `AuditEvent` per line.

```
{"source":"auditd","action":"open","outcome":"failure","timestamp":"2025-01-15T10:30:00.456Z"}
{"source":"k8s","action":"create","outcome":"success","timestamp":"2025-01-15T10:30:01.789Z"}
```

**Response** (`202 Accepted`):

```json
{ "accepted_at": "2025-01-15T10:30:00.123456789Z", "records": 2 }
```

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning |
|---|---|---|
| `202 Accepted` | — | Batch accepted; body is an `IngestReceipt` |
| `400 Bad Request` | `ingest_batch_malformed` | Body is not a well-formed batch, or a record fails the group/severity/source enum, required-field, or zero-timestamp checks |
| `400 Bad Request` | `ingest_sent_at_invalid` | `X-Plexsphere-Sent-At` missing or not an RFC 3339 timestamp |
| `401 Unauthorized` | — | Invalid node identity |
| `413 Payload Too Large` | — | Batch exceeds server-side size limit |
| `415 Unsupported Media Type` | `ingest_encoding_unsupported` | `Content-Encoding` other than `gzip` or `identity` |
| `429 Too Many Requests` | — | Rate limit exceeded, retry with backoff |
| `501 Not Implemented` | `observability_ingest_not_provisioned` | Observability ingest is not provisioned; the node drops the batch |
