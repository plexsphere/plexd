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

## Authentication

Every route under `/v1/` is served behind a bearer-envelope gate, with two exemptions: `POST /v1/register` (`security: []` in the spec — a node has no credential before it registers) and `GET /v1/health` (the readiness probe the compose healthcheck dials). The `/test/`, `/releases/` and `/exec-output/` surfaces are fixture scaffolding and a presigned upload; none of them carries a bearer.

An authenticated route admits exactly one credential, the NSK bearer envelope the agent assembles after registration:

```
Authorization: Bearer nsk_<env>_<base64url(node_id_bytes(16) || nsk_bytes(32))>
```

The payload is unpadded base64url, whose alphabet includes `-` and `_` — the separator parse therefore splits on the first two underscores only. The `<env>` segment must be non-empty but is not otherwise checked: the gate's authority is the payload, which must name this node (`mockNodeID`) and carry its secret key (`mockNSK`). Anything else — no header, a non-Bearer scheme, the raw standard-base64 nsk, a padded or short payload, another node's id or key — is refused with `401` and an `application/problem+json` body, and increments `unauthorized_count`.

The gate exists because its absence hid a shipped defect: the mock used to admit any credential and check only the node id in the URL, so the whole suite stayed green through two releases in which the agent presented the raw nsk and every deployed node was refused by the real control plane (issues #56, #60). A fixture that accepts anything cannot fail on the one thing every deployed node depends on.

### Request validation the fixture enforces

The mock refuses what the real handlers refuse, because a fixture that accepts
more than the contract hides exactly the defects the suite exists to catch. Two
gates were added after a release shipped past both of them:

- **`PUT /v1/nodes/{id}/capabilities`** strict-decodes a `CapabilityManifestRequest`
  (`DisallowUnknownFields`) and enforces its invariants: a non-empty
  `binary_version`, a `binary_checksum` that decodes to exactly 32 bytes of
  standard-padded base64, a canonical `SHA256:<base64>` fingerprint when present,
  and `declared_hooks` that are unique, named, and carry a 32-byte digest. A hex
  digest decodes to 48 bytes and is refused with `binary_checksum_invalid`; a
  gzip-compressed body fails the decode, as it does upstream. The fixture used to
  decode into whatever shape the agent sent and count it.
- **`POST /v1/nodes/{id}/audit`** admits only the contract's closed source enum,
  `auditd` and `k8s`. The fixture used to also admit `plexd`, so a batch the real
  ingest gate refuses whole with `400 ingest_batch_malformed` was accepted here.

### `GET /test/bearer`

Returns the envelope an authenticated route admits, so a test script that drives one itself does not hardcode a base64 blob and the node id and secret keep a single definition.

**Response:** `200 OK`

```json
{ "bearer": "nsk_e2e_AZCouKDAegqKCqCgoKCgowABAgMEBQYHCAkKCwwNDg-AkaKzxNXm9_jp2su8rZ6P" }
```

Go callers reach the same value through `(*Server).BearerEnvelope()`. In-process tests that mean to exercise handlers rather than the gate serve the mock behind a shim that stamps this header when a request arrives without one.

## Endpoints

### `GET /v1/health`

Unauthenticated readiness probe (a readiness probe carries no credentials). Answers the control-plane `HealthStatus` shape — an overall status plus a list of named component checks — so the harness has a stable, contract-faithful liveness endpoint. The e2e suites poll this endpoint to gate on mock-api readiness.

**Response:** `200 OK`

```json
{
  "status": "ok",
  "checks": [
    { "name": "mock", "status": "ok", "detail": "" }
  ]
}
```

**Content-Type:** `application/json`

**Error:** Returns `405` if the HTTP method is not `GET`.

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
rules, the `reachability` projection, all four bridge subtrees, the `state`
and `reports` blocks (which mirror one another), and empty `executions` and
`sessions` blocks.
The active fixture can be replaced at runtime via `POST /test/configure-state`.

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
| `executions` | `[]` — no dispatch queued; phases configure entries explicitly |
| `sessions` | `[]` — no session issued; phases configure entries explicitly |

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
  },
  "executions": [],
  "sessions": []
}
```

**Content-Type:** `application/json`

**Counter:** Increments `state_count` on each call.

**Executions projection:** the `executions` block is not served verbatim from the
fixture. Each request projects the configured entries through the live callback
state machine:

| Configured entry | Served as |
|------------------|-----------|
| `expires_at` not in the future (including a missing `expires_at`) | filtered out |
| execution has reached a terminal status | drained — filtered out from the moment it settles |
| execution is tracked non-terminally | served with the **live** status, not the configured one |
| execution is untracked | served verbatim |

The result is a freshly allocated slice, so the configured entries are never
rewritten in place, and it is never `nil` — the block always serializes as `[]`
rather than `null`.

**Sessions projection:** the `sessions` block is filtered the same way, but there
is no status projection — sessions have no callback state machine, so an entry is
either served or not:

| Configured entry | Served as |
|------------------|-----------|
| `expires_at` in the future | served verbatim, on **every** pull for as long as it stands |
| `expires_at` not in the future (including a missing `expires_at`) | filtered out |

The block is desired state, so redelivery is the point rather than a retry: an
entry stands until it is drained. Revocation is expressed by re-posting the
fixture *without* the entry — see `POST /test/configure-state` below. Like
`executions`, the result is a freshly allocated slice and never `nil`.

**Concurrency:** The active fixture is protected by `sync.RWMutex`. Reads never block other reads. A write via `POST /test/configure-state` blocks reads briefly during replacement. Readers always see a complete fixture (never a partial update).

### `GET /v1/nodes/{id}/events`

Server-Sent Events (SSE) endpoint for the signed event stream. There is **no** unsolicited initial event: the stream tails from now unless a `Last-Event-ID` cursor asks to replay buffered envelopes. The connection is held open with periodic keep-alive comments until the client disconnects or the stream is descoped.

**Cursor (`Last-Event-ID`):**

| Header value | Behavior |
|--------------|----------|
| absent or empty | Tail from now — no replay |
| non-negative integer `N` | Replay every buffered envelope with sequence `> N`, in order, then tail live |
| anything else (non-integer or negative) | `400 Bad Request`, `application/problem+json` with `code: invalid_cursor`, no stream opened |

**Descope:** When the events endpoint is descoped (see `POST /test/configure-events`), it answers `501 Not Implemented`, `application/problem+json` with `code: signed_event_bus_not_provisioned`, without opening a stream. The mode is re-checked under lock so a descope that races the request never leaves a stream open.

**Headers on the `200` stream:**

| Header | Value |
|--------|-------|
| `Content-Type` | `text/event-stream` |
| `Cache-Control` | `no-cache` |
| `Connection` | `keep-alive` |
| `X-Plexsphere-API-Version` | `v1` |

**Frame format:** each broadcast envelope is delivered as an SSE frame carrying its monotonic stream sequence in the `id:` line:

```
id: 1
event: node_state_updated
data: {"id":"evt-inject-001","type":"node_state_updated","scope":"","key_id":"did:web:plexsphere.com#key-e2e","issued_at":"2026-01-01T00:00:00Z","payload":{"revision":42},"signature":"<base64-ed25519>"}
```

**Sequencing and ring buffer:** every broadcast is assigned the next stream sequence (the first is `1`) and recorded in a bounded replay ring (capacity 64; the oldest entry is dropped past that). Recording happens regardless of connected clients and regardless of descoped mode, so a later reconnect can replay from a cursor.

**Keep-alive:** Sends `: keep-alive` comment every 15 seconds (`KeepAliveInterval`).

**Fan-out:** Live clients are registered on the broadcast list. Events injected via `POST /test/inject-event` are delivered to all registered clients. Each client has a buffered channel (capacity 64); a client whose buffer is full has the event dropped silently to avoid blocking the broadcaster.

**Disconnect:** The server detects client disconnect via context cancellation (or a descope closing the stream's `done` channel), removes the client from the broadcast list, and cleans up the goroutine.

**Counter:** Increments `events_request_count` on every request, including descoped `501` and `400` cursor answers.

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
| `ack` | `started` |
| `started` | `succeeded`, `failed`, `cancelled`, or `started` (only when `declared_output_bytes > 0`) |
| terminal (`succeeded` / `failed` / `cancelled`) | none |

The roster is closed and mirrors the control plane: a terminal status is reachable
**only from `started`**, so `ack` → `failed` and `ack` → `cancelled` are refused
with `409 invalid_state_transition`. A node that will not run an action must
therefore walk to `started` before failing it. The `started` → `started`
self-repeat is the declaring callback that mints the output upload, which the node
can only send once the run has finished. A callback that declares an over-ceiling
output (`started` with
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

Strict decoding means the accepted `tcp` fields are exactly those of
`api.TCPActivity`, `listener_endpoint` among them — a node that reports the
address its listener bound on a `session_started` row is accepted, not `400`ed as
an unknown field. The value itself is not validated.

| Status | Problem `code` | Meaning |
|---|---|---|
| `204 No Content` | — | Activity record accepted |
| `400 Bad Request` | `malformed_session_activity` | Unreadable body, strict-decode failure, or a one-of / per-kind violation |
| `403 Forbidden` | `nsk_node_mismatch` | `{id}` does not match the mock node identity |

### `PUT /v1/nodes/{id}/state/reports/{key}`

The per-key state report upsert. The mock validates `{key}` against the
control-plane grammar `^[a-z][a-z0-9._-]{0,127}$`, strict-decodes the
`api.NodeStateReportRequest` body, caps `value` at 4096 bytes, and upserts the
entry into **both** mirrored reports buckets of the state fixture
(`state.reports` and `reports.reports`), keeping each sorted by key ascending.
Success is `200 OK`.

**Request body:**

```json
{ "value": "{\"status\":\"healthy\"}", "workload_tag": "web" }
```

**Response:** `200 OK`

```json
{ "accepted_at": "2026-07-19T19:32:35Z", "key": "status.mesh" }
```

| Status | Problem `code` | Meaning |
|---|---|---|
| `200 OK` | — | Report upserted into both mirrored buckets |
| `400 Bad Request` | `invalid_report` | Key is outside the grammar, the body fails strict decoding, or `value` exceeds 4096 bytes |

**Counter:** Increments `report_put_count` on each accepted upsert.

### `DELETE /v1/nodes/{id}/state/reports/{key}`

Removes the report stored under `{key}` from both mirrored reports buckets.

| Status | Problem `code` | Meaning |
|---|---|---|
| `204 No Content` | — | Report removed |
| `400 Bad Request` | `invalid_report` | Key is outside the grammar |
| `404 Not Found` | `report_not_found` | No report exists for this key |

**Counter:** Increments `report_delete_count` on each successful delete.

### `POST /v1/nodes/{id}/metrics`

The v1 metrics ingest. The mock enforces the shared ingest header gates,
strict-decodes a **non-empty JSON array** of `api.MetricSample`, and validates
each record's `group` (closed set: `node_resources`, `tunnel_health`,
`peer_latency`, `agent_stats`), non-empty `name`, and non-zero `timestamp`.
Success is `202 Accepted` with an `IngestReceipt` whose `records` is the batch
length.

**Ingest header gates** (shared by metrics, logs, and audit, checked in order):

1. **Encoding** → `415` `ingest_encoding_unsupported` if `Content-Encoding` is anything other than empty, `identity`, or `gzip`.
2. **Sent-at** → `400` `ingest_sent_at_invalid` if `X-Plexsphere-Sent-At` is missing or not an RFC 3339 timestamp.

**Response:** `202 Accepted`

```json
{ "accepted_at": "2026-07-19T19:32:35Z", "records": 2 }
```

| Status | Problem `code` | Meaning |
|---|---|---|
| `202 Accepted` | — | Batch accepted; body is an `IngestReceipt` |
| `400 Bad Request` | `ingest_batch_malformed` | Body is not a non-empty JSON array, or a record has an out-of-set `group`, empty `name`, or zero `timestamp` |
| `400 Bad Request` | `ingest_sent_at_invalid` | `X-Plexsphere-Sent-At` missing or not RFC 3339 |
| `415 Unsupported Media Type` | `ingest_encoding_unsupported` | `Content-Encoding` other than `gzip` or `identity` |

**Counter:** Increments `metrics_count` on each accepted batch.

### `POST /v1/nodes/{id}/logs`

The v1 logs ingest. After the shared header gates, the mock splits the NDJSON
body on newlines (skipping blank lines), strict-decodes each line into
`api.LogLine`, and validates the `severity` (closed set: `emerg`, `alert`,
`crit`, `err`, `warning`, `notice`, `info`, `debug`), non-empty `message`, and
non-zero `timestamp`. A batch with no non-blank lines is malformed. Success is
`202 Accepted` with a receipt whose `records` is the line count.

| Status | Problem `code` | Meaning |
|---|---|---|
| `202 Accepted` | — | Batch accepted; body is an `IngestReceipt` |
| `400 Bad Request` | `ingest_batch_malformed` | No non-blank lines, an undecodable line, or a record with an out-of-set `severity`, empty `message`, or zero `timestamp` |
| `400 Bad Request` | `ingest_sent_at_invalid` | `X-Plexsphere-Sent-At` missing or not RFC 3339 |
| `415 Unsupported Media Type` | `ingest_encoding_unsupported` | `Content-Encoding` other than `gzip` or `identity` |

**Counter:** Increments `logs_count` on each accepted batch.

### `POST /v1/nodes/{id}/audit`

The v1 audit ingest, mirroring the logs handler: shared header gates, NDJSON
split skipping blank lines, strict decode into `api.AuditEvent`, and validation
of the `source` (closed set: `auditd`, `k8s`), non-empty `action`, non-empty
`outcome`, and non-zero `timestamp`. Success is `202 Accepted` with a receipt
whose `records` is the line count.

| Status | Problem `code` | Meaning |
|---|---|---|
| `202 Accepted` | — | Batch accepted; body is an `IngestReceipt` |
| `400 Bad Request` | `ingest_batch_malformed` | No non-blank lines, an undecodable line, or a record with an out-of-set `source`, empty `action`, empty `outcome`, or zero `timestamp` |
| `400 Bad Request` | `ingest_sent_at_invalid` | `X-Plexsphere-Sent-At` missing or not RFC 3339 |
| `415 Unsupported Media Type` | `ingest_encoding_unsupported` | `Content-Encoding` other than `gzip` or `identity` |

**Counter:** Increments `audit_count` on each accepted batch.

### `GET /releases/{tag}/{asset}`

Plays the GitHub release channel the `service.upgrade` fetcher pulls from. It lives **outside** the `/v1` namespace, mirroring the real release host rather than the control-plane API. The served assets are byte-identical copies of the `internal/upgrade` verification fixtures, embedded into the binary, so the e2e upgrade path fetches and verifies exactly what the unit tests do.

Asset matching is arch-agnostic (CI runs amd64, Docker Desktop arm64): `{asset}` must be `plexd-linux-<arch>` (the binary) or `plexd-linux-<arch>.sigstore.json` (the Sigstore bundle); anything else is a `404`. The `{tag}` selects which fixture is served:

| Tag | Binary | Bundle |
|-----|--------|--------|
| `v9.9.9` | fixture blob | valid Sigstore bundle → verification succeeds |
| `v9.9.8` | fixture blob | garbage non-JSON bundle → bundle parse fails downstream |
| anything else | `404 Not Found` | `404 Not Found` |

**Content-Type:** `application/octet-stream` for the binary, `application/json` for the bundle.

**Fixtures:** `test/e2e/mockapi/testdata/fixture.bin` and `fixture.sigstore.json`, byte-identical copies of `internal/upgrade/testdata/`. Regenerate both sets together via `make upgrade-fixture` (keyless `cosign sign-blob`); the pinned signing identity in `test/e2e/docker/plexd-e2e.yaml` changes with the fixtures.

### `GET /test/assertions`

Test-only endpoint returning a snapshot of all call counters. Not part of the `/v1/` API namespace.

**Response:** `200 OK`

```json
{
  "registration_count": 0,
  "heartbeat_count": 0,
  "state_count": 0,
  "key_rotate_count": 0,
  "capabilities_count": 0,
  "endpoint_count": 0,
  "secrets_count": 0,
  "secrets_rate_limited_count": 0,
  "report_put_count": 0,
  "report_delete_count": 0,
  "execution_callback_count": 0,
  "execution_upload_count": 0,
  "metrics_count": 0,
  "logs_count": 0,
  "audit_count": 0,
  "session_activity_count": 0,
  "integrity_violation_count": 0,
  "inject_event_count": 0,
  "events_request_count": 0,
  "local_metrics_count": 0,
  "local_logs_count": 0,
  "local_audit_count": 0,
  "unauthorized_count": 0
}
```

**Content-Type:** `application/json`

### `POST /test/inject-event`

Broadcasts a signed `Envelope` to all connected SSE clients and records it in the replay ring. The caller supplies only the identifying fields; the mock stamps the rest and signs the envelope so the agent's verifier accepts it.

**Request body:** `id`, `type`, `scope`, and `payload`. Both `id` and `type` are required.

```json
{
  "id": "evt-inject-001",
  "type": "node_state_updated",
  "scope": "node:n_abc123",
  "payload": {"node_id": "e2e-node-1"}
}
```

Injecting `action_request` is possible too, but it delivers no dispatch: like
`node_state_updated` its payload is opaque and it only nudges the agent into an
immediate reconcile. The dispatch itself must be configured into the `executions`
block via `POST /test/configure-state`. `session_setup` and `session_revoked`
behave the same way — neither carries a session nor a teardown, so the session
must be configured into (or dropped from) the `sessions` block the same way.

**Fields the mock stamps:** `issued_at` (current time), `key_id` (`did:web:plexsphere.com#key-e2e`), the stream sequence (the `id:` frame line), and `signature` (a valid Ed25519 signature over the shared canonical form, `api.CanonicalBytes`).

**Response:** `204 No Content`

**Behavior:**

- The signed envelope is recorded in the replay ring and broadcast to all connected SSE clients in SSE wire format
- If no SSE clients are connected, the call still records the envelope in the ring (a later reconnect can replay it) and succeeds
- Non-blocking send: a client whose channel buffer is full has the event dropped
- A `rotate_keys` event additionally arms a pending key rotation for `POST /v1/keys/rotate`
- Increments `inject_event_count` on each call
- Request body is captured and retrievable via `GET /test/last-request/inject_event`

**Error:** Returns `400` if the request body is not valid JSON or is missing `id` or `type`. Returns `405` if the HTTP method is not `POST`.

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
  "reports": null,
  "executions": [
    {
      "execution_id": "exec-e2e-001",
      "action": "system.info",
      "type": "builtin",
      "parameters": null,
      "status": "pending",
      "requested_at": "2026-01-01T00:00:00Z",
      "expires_at": "2099-01-01T00:00:00Z"
    }
  ],
  "sessions": [
    {
      "session_id": "sess-e2e-001",
      "jti": "sess-e2e-001",
      "kind": "tcp",
      "target": {"tcp": {"host": "127.0.0.1", "port": 8080}},
      "expires_at": "2099-01-01T00:00:00Z"
    }
  ]
}
```

Because the call replaces the **whole** fixture, a test that only wants to queue a
dispatch reads the live snapshot, splices its `executions` array in, and posts the
result back — that is what the e2e helper `configure_executions` does. The
`sessions` key works the same way, spliced by `configure_sessions`.

**Response:** `204 No Content`

**Behavior:**

- The replacement is atomic — concurrent readers never see a partial update
- The state fixture is protected by `sync.RWMutex`
- Any valid `NodeStateSnapshot` JSON is accepted, including minimal objects with `null` blocks
- Decoding is **strict**: a misspelled or renamed key anywhere in the envelope is a `400`, not a `204` that silently stores a zero-valued block
- Each configured execution seeds the callback state machine (see below)
- Request body is captured and retrievable via `GET /test/last-request/configure_state`

**Execution seeding:** the configured `status` of each entry tells the mock what the
control plane already holds for that execution, so a phase can stage a mid-flight
execution rather than only a fresh one:

| Configured `status` | Seeds |
|---------------------|-------|
| `pending` | nothing — the execution stays untracked until the node's `ack` |
| `ack` / `started` | that status, so the node's next callback is validated against it |

Seeding is **seed-if-absent**: an execution the mock is already tracking is left
alone, so re-posting the same fixture can never regress an execution the node has
already advanced.

**Session issuance and revocation:** sessions seed nothing — there is no callback
state machine to stage. A configured entry is issued by the mere fact of being
served, and only while its `expires_at` is in the future: an entry with a zero or
past `expires_at` is never served at all, so it cannot be used to stage an expired
session. **Revocation is a re-post without the entry**: because the sessions block
is desired state, dropping an entry from the fixture drains it out of the next
pull, which is the node's teardown signal. There is no revocation endpoint.

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

### `POST /test/configure-secrets`

Arms the dials the secret handler reads: the served `current_version`, the count
of upcoming fetches that answer a `429` (`rate_limit_next`), and the
`Retry-After` seconds those `429`s carry (`retry_after_seconds`). Lets a test
exercise version selection and the armed rate-limit path without a live secret
backend.

**Request body:** strict-decoded — an unknown field is a `400`. Each field is
applied only when greater than 0, so a partial body leaves the other dials
untouched.

```json
{ "current_version": 3, "rate_limit_next": 2, "retry_after_seconds": 5 }
```

**Response:** `204 No Content`.

**Behavior:**

- `current_version` — the version served in `X-Plexsphere-Secret-Version` and the ceiling a `?version=N` selector is checked against (a higher `?version` yields `404` `secret_version_not_found`).
- `rate_limit_next` — arms the **next N** fetches to answer `429` `per_node_rate_limited` with a `Retry-After` header, decremented exactly once per fetch so that exactly N fetches are limited; each armed response increments `secrets_rate_limited_count`.
- `retry_after_seconds` — the value written into the `Retry-After` header of those armed `429`s.
- Request body is captured and retrievable via `GET /test/last-request/configure_secrets`.

**Error:** Returns `400` if the body is not valid JSON or contains an unknown field. Returns `405` if the HTTP method is not `POST`.

### `POST /test/configure-events`

Flips the event stream between `streaming` (the default) and `descoped`. Descoping
makes `GET /v1/nodes/{id}/events` answer the spec's `501`
`signed_event_bus_not_provisioned` and closes every open stream through its `done`
channel; `streaming` restores normal service. Lets a test exercise the agent's
pull-only delivery mode without a live control plane.

**Request body:** strict-decoded — an unknown field is a `400`. `mode` is a closed
enum: `streaming` or `descoped`.

```json
{ "mode": "descoped" }
```

**Response:** `204 No Content`.

**Behavior:**

- `descoped` — the events endpoint answers `501` `signed_event_bus_not_provisioned`, and every currently open stream is closed. The replay ring keeps recording injected envelopes while descoped.
- `streaming` — normal service is restored; new connections open streams again.
- Request body is captured and retrievable via `GET /test/last-request/configure_events`.

**Error:** Returns `400` if the body is not valid JSON, contains an unknown field, or carries a `mode` other than `streaming` or `descoped`. Returns `405` if the HTTP method is not `POST`.

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
2. **Secret fetch** — `GET /v1/nodes/{id}/secrets/{key}` returns the raw AES-256-GCM envelope (`<12-byte nonce> || <ciphertext + 16-byte GCM tag>`) as an `application/octet-stream` body, with the version and KID (`e2e-nsk-kid-1`) in the `X-Plexsphere-Secret-Version` / `X-Plexsphere-Secret-KID` headers and `Cache-Control: no-store`
3. **Decryption** — plexd opens the envelope with `nodeapi.DecryptSecret(nsk, envelope)` to recover the bearer token
4. **Authentication** — plexd sends `Authorization: Bearer e2e-local-bearer-token` on each request to the local endpoint

## Call Counters

The server tracks API calls using `sync/atomic.Int64` counters. Each endpoint increments its counter atomically before writing the response, ensuring accurate counts under concurrent access.

| Counter | Incremented By |
|---------|---------------|
| `registration_count` | `POST /v1/register` |
| `heartbeat_count` | `POST /v1/nodes/{id}/heartbeat` |
| `state_count` | `GET /v1/nodes/{id}/state` |
| `key_rotate_count` | `POST /v1/keys/rotate` (completed rotations only) |
| `capabilities_count` | `PUT /v1/nodes/{id}/capabilities` (accepted manifests only) |
| `endpoint_count` | `PUT /v1/nodes/{id}/endpoint` |
| `secrets_count` | `GET /v1/nodes/{id}/secrets/{key}` (served `200` envelopes only) |
| `secrets_rate_limited_count` | `GET /v1/nodes/{id}/secrets/{key}` (armed `429` responses only) |
| `report_put_count` | `PUT /v1/nodes/{id}/state/reports/{key}` (accepted upserts only) |
| `report_delete_count` | `DELETE /v1/nodes/{id}/state/reports/{key}` (successful deletes only) |
| `execution_callback_count` | `POST /v1/nodes/{id}/executions/{eid}` (accepted callbacks only) |
| `execution_upload_count` | `PUT /exec-output/{eid}` (presigned output upload) |
| `metrics_count` | `POST /v1/nodes/{id}/metrics` |
| `logs_count` | `POST /v1/nodes/{id}/logs` |
| `audit_count` | `POST /v1/nodes/{id}/audit` |
| `session_activity_count` | `POST /v1/nodes/{id}/sessions/{sid}` |
| `integrity_violation_count` | `POST /v1/nodes/{id}/integrity/violations` |
| `inject_event_count` | `POST /test/inject-event` |
| `events_request_count` | `GET /v1/nodes/{id}/events` (every request, including descoped `501` and `400`) |
| `local_metrics_count` | `POST /local/metrics` (TLS) |
| `local_logs_count` | `POST /local/logs` (TLS) |
| `local_audit_count` | `POST /local/audit` (TLS) |
| `unauthorized_count` | any authenticated route refused by the bearer-envelope gate |

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
- `Envelope` — `internal/api.Envelope`
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
