---
title: Mock Central API Server
package: test/e2e/mockapi
feature: PXD-0037
---

# Mock Central API Server

A fixture-based mock of the Central API for end-to-end testing. Returns static responses that are wire-compatible with `internal/api` types, enabling CI pipelines to validate plexd's registration, heartbeat, reconciliation, and SSE logic without a production control plane.

## Configuration

| Option | Flag | Environment Variable | Default | Description |
|--------|------|---------------------|---------|-------------|
| Listen address | `-addr` | — | `:0` | TCP address (`host:port`) to listen on |
| TLS listen address | `-tls-addr` | — | `:8443` | TLS address (`host:port`) for local endpoint handlers |

The binary prints `MOCKAPI_ADDR=<address>` to stdout on startup, which allows test scripts to discover the dynamically assigned port when using `:0`.

## Endpoints

### `GET /v1/ping`

Health check probe. Returns immediately with no blocking operations.

**Response:** `200 OK`

```json
{}
```

**Content-Type:** `application/json`

### `POST /v1/register`

Enforces the full `POST /v1/register` contract (issue #18). Success is `201
Created`; every denial is an RFC 9457 `application/problem+json` body mirroring
the platform taxonomy. The bootstrap token's nonce is recorded (the token
"consumed") only on the `201` branch — never on an error branch.

**Validation order.** The handler checks in this sequence, returning at the
first failure:

1. **Body decode** → `400` (no `code`) if the body is not valid JSON.
2. **Invariants** → `422` (no `code`): empty `bootstrap_token`, `nonce`, or `resource_handle`; a `project_id` that is empty, the zero UUID, or not a UUID; any field longer than 4096 characters.
3. **Public key** → `400` `public_key_invalid` if `public_key` fails `^[A-Za-z0-9+/]{43}=$` or decodes to the all-zero key.
4. **Bootstrap token** → `403`: malformed token (fails `^psb_[a-z]+_[a-z2-7]+_(node|bridge)_[a-z2-7]{20,}$`) has no `code`; a `bridge`-kind token yields `kind_mismatch`; a trailing random segment containing `consumed`, `expired`, or `revoked` yields `token_consumed`, `token_expired`, or `token_revoked`.
5. **Project match** → `403` `project_mismatch` if `project_id` is not the mock project UUID.
6. **Nonce replay** → `403` `nonce_collision` if `(project_id, nonce)` was already recorded on a prior `201`.
7. **Resource resolution** → `404` `resource_not_found` for the reserved handle `unknown-resource`.
8. **Allocator / server triggers** → magic resource handles (below).
9. **Success** → `201` with the fixture below; the nonce is recorded.

**Magic triggers.** Reserved inputs force specific branches:

| Trigger | Where | Result |
|---------|-------|--------|
| `project_id` = `0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0` | request | Accepted project; any other UUID → `403` `project_mismatch` |
| bridge-kind token (`psb_..._bridge_...`) | `bootstrap_token` | `403` `kind_mismatch` |
| `consumed` / `expired` / `revoked` in the trailing random segment | `bootstrap_token` | `403` `token_consumed` / `token_expired` / `token_revoked` |
| `unknown-resource` | `resource_handle` | `404` `resource_not_found` |
| `exhausted-pool` | `resource_handle` | `503` `pool_exhausted` |
| `exhausted-subrange` | `resource_handle` | `503` `subrange_exhausted` |
| `contended-allocator` | `resource_handle` | `503` `allocator_contention` |
| `boom-internal` | `resource_handle` | `500` (no `code`) |

**Problem format.** Error bodies are `application/problem+json`:

```json
{
  "type": "https://api.plexsphere.com/problems/token_expired",
  "title": "Forbidden",
  "status": 403,
  "detail": "bootstrap_token expired",
  "instance": "/v1/register",
  "code": "token_expired"
}
```

`type` is `https://api.plexsphere.com/problems/<code>` when a `code` is present,
otherwise `about:blank` (and the `code` member is omitted); `title` is the HTTP
status text; `instance` is always `/v1/register`.

**Response:** `201 Created`

```json
{
  "node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3",
  "mesh_ip": "10.99.0.1",
  "signing_public_key": "<base64 Ed25519 public key, generated per server start>",
  "signing_key_id": "did:web:plexsphere.com#key-e2e",
  "nsk": "AAECAwQFBgcICQoLDA0OD4CRorPE1eb3+Onay7ytno8=",
  "peer_snapshot": [
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
  "domain_mesh_cidr": "10.99.0.0/24"
}
```

The `peer_snapshot` uses the narrow `RegisterPeer` shape (no `psk`,
`allowed_ips`, or `endpoint`); the second entry omits `fallback_endpoint`.

`nsk` is the mock NodeSecretKey in the standard-padded base64 form the
register contract specifies (44 characters). plexd decodes it back into the
32-byte AES-256-GCM key it uses to open secret envelopes.

**Content-Type:** `application/json`

**Counter:** Increments `registration_count` on each call.

**Nonce store.** Consumed nonces are held in an in-memory map keyed by
`project_id + "|" + nonce`, recorded only on the `201` branch and forgotten when
the server restarts.

**Error:** Denials use `application/problem+json` as described above. Returns
`405` if the HTTP method is not `POST`.

### `POST /v1/nodes/{id}/heartbeat`

Enforces the v1 heartbeat contract: strict JSON decoding (unknown fields
rejected), a required `nat_summary` **object**, clock-skew tolerance, and
checksum/version shape. `heartbeat_count` increments only when every check
passes, so invalid requests are not counted. The success response is the
configurable `HeartbeatResponse` fixture (defaults to `reconcile: true`,
`rotate_keys: false`) with a fresh `accepted_at` stamped per call.

**Validation order.** The handler returns at the first failure:

1. **Body decode** → `400` `malformed_heartbeat_request` if the body is unreadable or strict decoding fails.
2. **`nat_summary` object** → `400` `malformed_heartbeat_request` if `nat_summary` is absent, `null`, or not a JSON object. This is what proves the agent sends `{}` — not `null` — before NAT discovery has a result.
3. **Clock skew** → `400` `clock_skew` if `client_now` is more than 60s from server time in either direction.
4. **Binary checksum** → `400` `binary_checksum_empty` unless `binary_checksum` is a 64-char lowercase hex digest or the 44-char standard base64 of 32 bytes.
5. **Binary version** → `400` `binary_version_empty` if `binary_version` is empty.

**Response:** `200 OK`

```json
{
  "accepted_at": "2026-07-19T19:32:35Z",
  "reconcile": true,
  "rotate_keys": false
}
```

**Content-Type:** `application/json` (errors use `application/problem+json`).

**Counter:** Increments `heartbeat_count` only when every check passes.

**Error:** Denials use `application/problem+json` with the codes above. Returns `405` if the HTTP method is not `POST`.

### `POST /v1/keys/rotate`

Models the v1 key-rotation receipt contract (issue #21). The control plane
*arms* a pending rotation, the node submits its freshly staged public key, and
the mock answers a receipt — replaying the stored receipt on an idempotent
retry. `key_rotate_count` advances only on a completing rotation.

**Arming.** A rotation is armed from three sources, mirroring a control plane
that keeps signaling while a rotation is pending:

- `POST /test/configure-heartbeat` with `rotate_keys: true`;
- each served heartbeat response that carries `rotate_keys: true` re-arms;
- an injected `rotate_keys` SSE event (`POST /test/inject-event`).

A completing rotation disarms.

**Request body:** the node identifies itself through its NSK bearer credential,
so the body carries no node id.

```json
{ "new_public_key": "<44-char standard base64 X25519 public key>" }
```

**Response:** `200 OK`

```json
{
  "rotation_id": "e2e-rotation-0001",
  "kid": "did:web:plexsphere.com#psk-2026-04",
  "wrap_key_version": 1
}
```

`rotation_id` is `e2e-rotation-%04d`, `kid` is fixed, and `wrap_key_version`
equals the completion count.

**Served taxonomy.** The handler serves this subset:

| Status | Problem `code` | Trigger |
|--------|----------------|---------|
| `400 Bad Request` | `malformed_keys_rotate_request` | Body is unreadable or fails strict decoding |
| `413 Payload Too Large` | `keys_rotate_body_too_large` | Body exceeds 4 KiB |
| `422 Unprocessable Entity` | `keys_rotate_public_key_invalid` | `new_public_key` is not a non-zero 44-char standard base64 X25519 key |
| `422 Unprocessable Entity` | `keys_rotate_public_key_unchanged` | `new_public_key` matches the node's current key and no receipt is stored for it |
| `409 Conflict` | `keys_rotate_no_pending_rotation` | No rotation is armed |
| `200 OK` | — | Idempotent retry: replays the stored receipt without moving the counter |
| `200 OK` | — | Completion: mints and stores a fresh receipt, disarms, and increments `key_rotate_count` |

The mock deliberately does **not** model `404 keys_rotate_peer_not_found` or
`403` (ReBAC denial) — server states plexd cannot reach in e2e.

**Content-Type:** `application/json` (errors use `application/problem+json`).

**Counter:** Increments `key_rotate_count` only on a completing rotation.

### `PUT /v1/nodes/{id}/endpoint`

Enforces the v1 endpoint contract: a 4 KiB body cap, strict JSON decoding, a
closed `nat_type` enum, clock-skew tolerance, and a routable `ip:port`.
`endpoint_count` increments only when every check passes.

**Validation order.** The handler returns at the first failure:

1. **Body size** → `413` `endpoint_body_too_large` if the body exceeds 4 KiB.
2. **Body decode** → `400` `malformed_endpoint_request` if strict decoding fails.
3. **NAT type** → `400` `malformed_endpoint_request` if `nat_type` is outside `full_cone`, `restricted`, `port_restricted`, `symmetric`, `unknown`.
4. **Clock skew** → `400` `endpoint_clock_skew` if `reported_at` is more than 60s from server time in either direction.
5. **Routable endpoint** → `400` `endpoint_unparseable` if `endpoint` is not `ip:port` with a port in 1–65535 and a non-loopback, non-link-local, non-unspecified host.

**Request body:**

```json
{
  "endpoint": "203.0.113.7:51820",
  "nat_type": "full_cone",
  "reported_at": "2026-07-19T19:32:35Z"
}
```

**Response:** `200 OK`

```json
{
  "accepted_at": "2026-07-19T19:32:35Z",
  "stale_after": "2026-07-19T19:37:35Z"
}
```

`stale_after` is `accepted_at` plus the configured TTL (default 5m, set via
`POST /test/configure-endpoint`). The response carries no peer endpoints.

**Content-Type:** `application/json` (errors use `application/problem+json`).

**Counter:** Increments `endpoint_count` only when every check passes.

**Error:** Denials use `application/problem+json` with the codes above. Returns `405` if the HTTP method is not `PUT`.

### `GET /v1/nodes/{id}/state`

Returns the active `NodeStateSnapshot` fixture built by `newStateFixture`. By
default it is an enriched envelope containing two peers, a merged policy with two
rules, the `reachability` projection, all four bridge subtrees, and the `state`
and `reports` blocks (which mirror one another). The active fixture can be
replaced at runtime via `POST /test/configure-state`.

**Default fixture blocks:**

| Block | Default Value |
|-------|---------------|
| `peers` | 2 mesh peers (node_id ascending), no `psk`/`allowed_ips`/`endpoint` |
| `reachability` | opaque `{"state":"healthy", ...}` projection |
| `policy` | merged block: 2 rules, `fingerprint` from `policyFingerprint` |
| `bridge.relay` | 1 relay session assignment (`relay-sess-001`) |
| `bridge.user_access` | `enabled: true`, interface `wg-access0`, 1 peer |
| `bridge.ingress` | `enabled: true`, 1 rule (`ingress-001`, port 443) |
| `bridge.site_to_site` | `enabled: true`, 1 tunnel (`s2s-001`) |
| `state` / `reports` | `metadata` (2 entries), `data` (2 entries), `reports` (`[]`) |

The `fingerprint` is produced by the mock-internal `policyFingerprint` helper — a
44-char base64 SHA-256 over the compact-JSON encoding of the rules slice. This
canonicalization is mock-internal: plexd treats the fingerprint as an opaque
comparison key and never re-derives it from the rules.

**Response:** `200 OK`

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
  "reachability": {"state": "healthy", "changed_at": "2026-01-01T00:00:00Z"},
  "policy": {
    "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1",
    "fingerprint": "<44-char base64 SHA-256>",
    "rules": [
      {
        "action": "allow",
        "protocol": "any",
        "source_cidr": "10.99.0.0/24",
        "destination_cidr": "10.99.0.0/24"
      },
      {
        "action": "allow",
        "protocol": "tcp",
        "source_cidr": "10.99.0.0/24",
        "destination_cidr": "0.0.0.0/0",
        "ports": {"from": 443, "to": 443}
      }
    ]
  },
  "bridge": {
    "relay": {
      "sessions": [
        {
          "session_id": "relay-sess-001",
          "peer_a_id": "peer-001",
          "peer_a_endpoint": "203.0.113.1:51820",
          "peer_b_id": "peer-003",
          "peer_b_endpoint": "203.0.113.3:51820",
          "expires_at": "2099-12-31T23:59:59Z"
        }
      ]
    },
    "user_access": {
      "enabled": true,
      "interface_name": "wg-access0",
      "listen_port": 51821,
      "peers": [
        {
          "public_key": "ua-pub-key-001",
          "allowed_ips": ["10.100.0.1/32"],
          "label": "admin-laptop"
        }
      ]
    },
    "ingress": {
      "enabled": true,
      "rules": [
        {
          "rule_id": "ingress-001",
          "listen_port": 443,
          "target_addr": "10.99.0.2:8443",
          "mode": "tcp"
        }
      ]
    },
    "site_to_site": {
      "enabled": true,
      "tunnels": [
        {
          "tunnel_id": "s2s-001",
          "remote_endpoint": "198.51.100.1:51820",
          "remote_public_key": "s2s-remote-pub-key-001",
          "local_subnets": ["10.99.0.0/24"],
          "remote_subnets": ["172.16.0.0/16"],
          "interface_name": "wg-s2s0",
          "listen_port": 51822
        }
      ]
    }
  },
  "state": {
    "metadata": [
      {"key": "environment", "value": "e2e-test"},
      {"key": "region", "value": "mock-region-1"}
    ],
    "data": [
      {"key": "app/config", "value": "{\"log_level\":\"info\",\"max_conns\":100}"},
      {"key": "certs/ca", "value": "-----BEGIN CERTIFICATE-----\nmock-ca-cert\n-----END CERTIFICATE-----"}
    ],
    "reports": []
  },
  "reports": {
    "metadata": [
      {"key": "environment", "value": "e2e-test"},
      {"key": "region", "value": "mock-region-1"}
    ],
    "data": [
      {"key": "app/config", "value": "{\"log_level\":\"info\",\"max_conns\":100}"},
      {"key": "certs/ca", "value": "-----BEGIN CERTIFICATE-----\nmock-ca-cert\n-----END CERTIFICATE-----"}
    ],
    "reports": []
  }
}
```

**Content-Type:** `application/json`

**Counter:** Increments `state_count` on each call.

**Concurrency:** The active fixture is protected by `sync.RWMutex`. Reads never block other reads. A write via `POST /test/configure-state` blocks reads briefly during replacement. Readers always see a complete fixture (never a partial update).

### `GET /v1/nodes/{id}/metadata`

Returns a fixture metadata map with four key-value pairs.

**Response:** `200 OK`

```json
{
  "environment": "e2e-test",
  "region": "mock-region-1",
  "role": "worker",
  "version": "1.0.0-mock"
}
```

**Content-Type:** `application/json`

**Counter:** Increments `metadata_count` on each call.

### `GET /v1/nodes/{id}/events`

Server-Sent Events (SSE) endpoint. Sends an initial `SignedEnvelope` event, then registers the client on the server's broadcast list for injected events, and holds the connection open with periodic keep-alive comments until the client disconnects.

**Headers:**

| Header | Value |
|--------|-------|
| `Content-Type` | `text/event-stream` |
| `Cache-Control` | `no-cache` |
| `Connection` | `keep-alive` |

**Initial event:**

```
event: node_state_updated
id: evt-mock-001
data: {"event_type":"node_state_updated","event_id":"evt-mock-001","issued_at":"2025-01-01T00:00:00Z","nonce":"mock-nonce-001","payload":{"node_id":"node-mock-001"},"signature":"mock-signature-placeholder"}
```

**Keep-alive:** Sends `: keep-alive` comment every 15 seconds.

**Fan-out:** After the initial event, the client is registered on the server's broadcast list. Events injected via `POST /test/inject-event` are delivered to all registered clients. Each client has a buffered channel (capacity 16); slow clients that fall behind have events dropped silently to prevent blocking the injector.

**Disconnect:** The server detects client disconnect via context cancellation, removes the client from the broadcast list, and cleans up the goroutine.

### `POST /v1/nodes/{id}/executions/{eid}`

The v1 execution status callback. The mock enforces the node-id guard, a 64 KiB
body cap, strict decoding to the five node-reportable statuses (`ack`, `started`,
`succeeded`, `failed`, `cancelled`), the 16 KiB inline-output ceiling, and the
execution state machine.

**Legal transitions** — the mock tracks each execution's current status (absent
means never dispatched) and admits only these advances:

| Current state | Legal next status |
|---------------|-------------------|
| _(never seen)_ | `ack` |
| `ack` | `started`, `failed`, `cancelled` |
| `started` | `succeeded`, `failed`, `cancelled`, or `started` (only when `declared_output_bytes > 0`) |
| terminal (`succeeded` / `failed` / `cancelled`) | none |

The `ack` → `failed` / `cancelled` edges cover a pre-start rejection; the
`started` → `started` self-repeat is the declaring callback that mints the output
upload. A callback that declares an over-ceiling output (`started` with
`declared_output_bytes > 0`) is answered with a one-time presigned PUT URL in
`output_upload_url`; a terminal callback carrying an `object_key` is verified
against the uploaded bytes (existence, receipt, and `sha256`).

Every accepted callback increments `execution_callback_count` and returns `200`
with the new status. Denials are RFC 9457 `application/problem+json` bodies:

| Status | Problem `code` | Meaning |
|---|---|---|
| `200 OK` | — | Callback accepted; body carries the new status (and `output_upload_url` on a declaring callback) |
| `400 Bad Request` | `malformed_execution_callback` | Unreadable/strict-decode failure, status outside the reportable set, non-base64 inline, or an `object_key`/`sha256` that does not match a received upload |
| `403 Forbidden` | `nsk_node_mismatch` | `{id}` does not match the mock node identity |
| `409 Conflict` | `execution_already_terminal` | Callback on an already-settled invocation |
| `409 Conflict` | `invalid_state_transition` | Any other illegal advance |
| `413 Payload Too Large` | `inline_output_too_large` | `output.inline` decodes to more than 16 KiB |

### `PUT /exec-output/{eid}`

The one-time presigned output upload minted by a declaring execution callback. The
`token` query parameter identifies the upload; its recorded object key
(`exec-output/{eid}`) must match the path, it must be unused, and the body must
fit within the declared size. On success the mock records the bytes (for the
terminal callback's `sha256` check), increments `execution_upload_count`, and
returns `200`.

| Status | Condition |
|---|---|
| `200 OK` | Bytes accepted |
| `404 Not Found` | No upload for this token, or the token's key does not match the path |
| `409 Conflict` | The upload URL has already been used |
| `413 Payload Too Large` | Body exceeds the declared size |

The `404` / `409` / `413` problem bodies carry no machine `code`.

### `POST /v1/nodes/{id}/sessions/{sid}`

The v1 session activity record. The mock enforces the node-id guard, a 16 KiB body
cap, strict decoding, and the one-of `ssh` / `k8s` / `tcp` contract: exactly one
member must be set, and that member must satisfy its per-kind rules —
`ssh.command` non-empty and at most 1 KiB, `k8s.verb` non-empty, or `tcp.phase`
one of `session_started` / `session_ended` with a valid `terminated_by` when set.
A valid record increments `session_activity_count` and returns `204 No Content`.

| Status | Problem `code` | Meaning |
|---|---|---|
| `204 No Content` | — | Activity record accepted |
| `400 Bad Request` | `malformed_session_activity` | Unreadable body, strict-decode failure, or a one-of / per-kind violation |
| `403 Forbidden` | `nsk_node_mismatch` | `{id}` does not match the mock node identity |

### `GET /test/assertions`

Test-only endpoint returning a snapshot of all call counters. Not part of the `/v1/` API namespace.

**Response:** `200 OK`

```json
{
  "registration_count": 0,
  "heartbeat_count": 0,
  "state_count": 0,
  "metadata_count": 0,
  "deregister_count": 0,
  "key_rotate_count": 0,
  "capabilities_count": 0,
  "endpoint_count": 0,
  "secrets_count": 0,
  "report_count": 0,
  "execution_callback_count": 0,
  "execution_upload_count": 0,
  "metrics_count": 0,
  "logs_count": 0,
  "audit_count": 0,
  "artifact_count": 0,
  "session_activity_count": 0,
  "integrity_violation_count": 0,
  "inject_event_count": 0,
  "local_metrics_count": 0,
  "local_logs_count": 0,
  "local_audit_count": 0
}
```

**Content-Type:** `application/json`

### `POST /test/inject-event`

Broadcasts a `SignedEnvelope` to all connected SSE clients. The request body is a full `SignedEnvelope` JSON object. The server delivers it in SSE wire format (`id:`, `event:`, `data:` fields) to every registered client.

**Request body:**

```json
{
  "event_type": "action_request",
  "event_id": "evt-inject-001",
  "issued_at": "2025-01-01T00:00:00Z",
  "nonce": "test-nonce",
  "payload": {"action_id": "a1"},
  "signature": "mock-signature"
}
```

**Response:** `204 No Content`

**Behavior:**

- The envelope is broadcast to all connected SSE clients in SSE wire format
- If no SSE clients are connected, the call succeeds silently (no-op broadcast)
- Non-blocking send: slow clients with full channel buffers have the event dropped
- Increments `inject_event_count` on each call
- Request body is captured and retrievable via `GET /test/last-request/inject_event`

**Error:** Returns `400` if the request body is not valid JSON. Returns `405` if the HTTP method is not `POST`.

### `POST /test/configure-state`

Replaces the active `NodeStateSnapshot` fixture at runtime. Subsequent calls to `GET /v1/nodes/{id}/state` return the configured state instead of the default. The `state_count` counter continues to increment regardless of which fixture is active.

**Request body:** A full `api.NodeStateSnapshot` JSON object (same schema as the `GET /v1/nodes/{id}/state` response).

```json
{
  "peers": [],
  "reachability": null,
  "policy": null,
  "bridge": null,
  "state": {"metadata": [{"key": "custom", "value": "value"}], "data": [], "reports": []},
  "reports": null
}
```

**Response:** `204 No Content`

**Behavior:**

- The replacement is atomic — concurrent readers never see a partial update
- The state fixture is protected by `sync.RWMutex`
- Any valid `NodeStateSnapshot` JSON is accepted, including minimal objects with `null` blocks
- Request body is captured and retrievable via `GET /test/last-request/configure_state`

**Error:** Returns `400` if the request body is not valid JSON. Returns `405` if the HTTP method is not `POST`.

**Go API:** The `Server` also exposes `SetState(api.NodeStateSnapshot)` and `GetState() api.NodeStateSnapshot` methods for direct use in Go test code without HTTP.

### `PUT /test/state`

Alias for `POST /test/configure-state`. Same behavior.

**Response:** `204 No Content`

### `POST /test/configure-endpoint`

Sets the `stale_after` TTL applied by `PUT /v1/nodes/{id}/endpoint`. Lets a test
shorten the TTL below the refresh interval to exercise the deadline-driven
re-report path.

**Request body:**

```json
{ "ttl_seconds": 90 }
```

**Response:** `204 No Content` when `ttl_seconds` is positive.

**Behavior:**

- `ttl_seconds` must be greater than 0; otherwise the handler returns `400` with `{"error": "ttl_seconds must be positive"}`.
- The TTL defaults to 5 minutes and is protected by `sync.RWMutex`.
- Request body is captured and retrievable via `GET /test/last-request/configure_endpoint`.

**Error:** Returns `400` if the body is not valid JSON or `ttl_seconds` is not positive. Returns `405` if the HTTP method is not `POST`.

**Go API:** The `Server` also exposes `SetEndpointTTL(time.Duration)` for direct use in Go test code.

### `GET /test/last-request/{endpoint}`

Returns the raw request body captured from the last call to the specified endpoint. Useful for asserting that the client sent the correct payload.

**Path parameter:** `endpoint` — the capture key (e.g., `register`, `heartbeat`, `inject_event`).

**Response:** `200 OK` with `Content-Type: application/octet-stream` and the raw body bytes.

**Error:** Returns `404` if no request has been captured for the given endpoint.

## TLS Listener (Local Endpoints)

The server runs a second listener on the TLS address (`-tls-addr`, default `:8443`) with a self-signed ECDSA P-256 certificate (DNS names: `mock-api`, `localhost`). This listener serves local endpoint handlers that simulate a secondary on-premises HTTPS endpoint with Bearer token authentication.

The TLS certificate is generated at startup by `GenerateSelfSignedTLSConfig()` and is valid for 24 hours. Clients must use `tls_insecure_skip_verify: true` since the certificate is self-signed.

The TLS listener serves a separate `http.ServeMux` (`TLSHandler()`) with the following routes:

- `POST /local/metrics`
- `POST /local/logs`
- `POST /local/audit`
- `GET /test/assertions` (same counters as the HTTP listener)
- `GET /test/last-request/{endpoint}` (same capture store as the HTTP listener)

### `POST /local/metrics`

Accepts a metrics payload on the local endpoint. Requires Bearer token authentication.

**Authentication:** `Authorization: Bearer e2e-local-bearer-token`

**Response:** `204 No Content`

**Counter:** Increments `local_metrics_count` on each successful call.

**Error:** Returns `401 Unauthorized` if the `Authorization` header is missing, malformed, or contains the wrong token.

### `POST /local/logs`

Accepts a log payload on the local endpoint. Requires Bearer token authentication.

**Authentication:** `Authorization: Bearer e2e-local-bearer-token`

**Response:** `204 No Content`

**Counter:** Increments `local_logs_count` on each successful call.

**Error:** Returns `401 Unauthorized` if the `Authorization` header is missing, malformed, or contains the wrong token.

### `POST /local/audit`

Accepts an audit payload on the local endpoint. Requires Bearer token authentication.

**Authentication:** `Authorization: Bearer e2e-local-bearer-token`

**Response:** `204 No Content`

**Counter:** Increments `local_audit_count` on each successful call.

**Error:** Returns `401 Unauthorized` if the `Authorization` header is missing, malformed, or contains the wrong token.

### Bearer Token Resolution

The expected bearer token (`e2e-local-bearer-token`) is provisioned through the same credential chain that plexd uses in production:

1. **Registration** — `POST /v1/register` returns `nsk` as 44-char standard-padded base64; plexd decodes it into the 32-byte AES-256-GCM key
2. **Secret fetch** — `GET /v1/nodes/{id}/secrets/{key}` returns `ciphertext` and `nonce` (AES-256-GCM encrypted with the NSK)
3. **Decryption** — plexd decrypts the ciphertext using `nodeapi.DecryptSecret(nsk, ciphertext, nonce)` to recover the bearer token
4. **Authentication** — plexd sends `Authorization: Bearer e2e-local-bearer-token` on each request to the local endpoint

## Call Counters

The server tracks API calls using `sync/atomic.Int64` counters. Each endpoint increments its counter atomically before writing the response, ensuring accurate counts under concurrent access.

| Counter | Incremented By |
|---------|---------------|
| `registration_count` | `POST /v1/register` |
| `heartbeat_count` | `POST /v1/nodes/{id}/heartbeat` |
| `state_count` | `GET /v1/nodes/{id}/state` |
| `metadata_count` | `GET /v1/nodes/{id}/metadata` |
| `deregister_count` | `POST /v1/nodes/{id}/deregister` |
| `key_rotate_count` | `POST /v1/keys/rotate` (completed rotations only) |
| `capabilities_count` | `PUT /v1/nodes/{id}/capabilities` |
| `endpoint_count` | `PUT /v1/nodes/{id}/endpoint` |
| `secrets_count` | `GET /v1/nodes/{id}/secrets/{key}` |
| `report_count` | `POST /v1/nodes/{id}/report` |
| `execution_callback_count` | `POST /v1/nodes/{id}/executions/{eid}` (accepted callbacks only) |
| `execution_upload_count` | `PUT /exec-output/{eid}` (presigned output upload) |
| `metrics_count` | `POST /v1/nodes/{id}/metrics` |
| `logs_count` | `POST /v1/nodes/{id}/logs` |
| `audit_count` | `POST /v1/nodes/{id}/audit` |
| `artifact_count` | `GET /v1/artifacts/plexd/{version}/{os}/{arch}` |
| `session_activity_count` | `POST /v1/nodes/{id}/sessions/{sid}` |
| `integrity_violation_count` | `POST /v1/nodes/{id}/integrity/violations` |
| `inject_event_count` | `POST /test/inject-event` |
| `local_metrics_count` | `POST /local/metrics` (TLS) |
| `local_logs_count` | `POST /local/logs` (TLS) |
| `local_audit_count` | `POST /local/audit` (TLS) |

Query current values via `GET /test/assertions`.

## Wire Compatibility

All responses use the same JSON field names as the types in `internal/api`:

- `RegisterResponse` — `internal/api.RegisterResponse`
- `RegisterPeer` — `internal/api.RegisterPeer`
- `HeartbeatResponse` — `internal/api.HeartbeatResponse`
- `NodeStateSnapshot` — `internal/api.NodeStateSnapshot`
- `SnapshotPeer` — `internal/api.SnapshotPeer`
- `PolicySnapshot` / `PolicyRule` / `PortRange` — `internal/api.PolicySnapshot` / `internal/api.PolicyRule` / `internal/api.PortRange`
- `BridgeSnapshot` — `internal/api.BridgeSnapshot`
- `NodeStateBlock` / `StateEntry` — `internal/api.NodeStateBlock` / `internal/api.StateEntry`
- `SignedEnvelope` — `internal/api.SignedEnvelope`
- `Peer` — `internal/api.Peer`
- `RelayConfig` / `RelaySessionAssignment` — `internal/api.RelayConfig` / `internal/api.RelaySessionAssignment`
- `UserAccessConfig` / `UserAccessPeer` — `internal/api.UserAccessConfig` / `internal/api.UserAccessPeer`
- `IngressConfig` / `IngressRule` — `internal/api.IngressConfig` / `internal/api.IngressRule`
- `SiteToSiteConfig` / `SiteToSiteTunnel` — `internal/api.SiteToSiteConfig` / `internal/api.SiteToSiteTunnel`

## Dockerfile

Multi-stage build at `test/e2e/mockapi/Dockerfile`.

| Stage | Image | Purpose |
|-------|-------|---------|
| Builder | `golang:1.26-alpine` | Compile the mock server binary |
| Runtime | `gcr.io/distroless/static-debian12` | Minimal runtime with no shell |

### Build

From the repository root:

```bash
docker build -f test/e2e/mockapi/Dockerfile -t mockapi:latest .
```

Multi-platform build:

```bash
docker buildx build -f test/e2e/mockapi/Dockerfile \
    --platform linux/amd64,linux/arm64 \
    -t mockapi:latest .
```

### Runtime Details

| Property | Value |
|----------|-------|
| User | `65534:65534` (nobody) |
| Exposed ports | `8080` (HTTP), `8443` (TLS) |
| Entrypoint | `/usr/local/bin/mockapi` |
| Default CMD | `["-addr", ":8080"]` |

Override the listen address:

```bash
docker run -p 9090:9090 mockapi:latest -addr :9090
```

### Build Optimizations

- **Module cache layer**: `go.mod` and `go.sum` are copied and downloaded before the full source, so source-only changes reuse the cached module layer.
- **Static binary**: Built with `CGO_ENABLED=0` and ldflags `-s -w` for minimal size.
- **Distroless base**: No shell or package manager in the runtime image.

## Usage in Tests

```go
srv := mockapi.New()
ts := httptest.NewServer(srv.Handler())
defer ts.Close()

// Use ts.URL as the base URL for plexd's API client
```

For TLS local endpoint testing:

```go
srv := mockapi.New()
tlsCfg := mockapi.GenerateSelfSignedTLSConfig()
ts := httptest.NewUnstartedServer(srv.TLSHandler())
ts.TLS = tlsCfg
ts.StartTLS()
defer ts.Close()

// srv.NSK() returns the raw 32-byte node secret key (the response encodes it as base64)
// srv.ExpectedBearerToken() returns "e2e-local-bearer-token"
```

## Source

- Server: `test/e2e/mockapi/mockapi.go`
- CLI entry point: `test/e2e/mockapi/cmd/mockapi/main.go`
- Tests: `test/e2e/mockapi/mockapi_test.go`
- Dockerfile: `test/e2e/mockapi/Dockerfile`
