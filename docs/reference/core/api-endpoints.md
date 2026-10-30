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
| 16 | `POST` | `/v1/nodes/{node_id}/handshakes` | Per-peer WireGuard handshake report |
| 17 | `GET` | `/v1/nodes/{node_id}/peers/{peer_node_id}/psk` | Pairwise edge PSK (NSK-encrypted octet-stream) |
| 18 | `PUT` | `/v1/nodes/{node_id}/endpoint-candidates` | Local endpoint candidate reporting |
| 19 | `GET` | `/v1/nodes/{node_id}/sessions/{session_id}/connections/{connection_id}` | ssh session connection (WebSocket upgrade) |
| 20 | `PUT` | `/v1/nodes/{node_id}/relay-status` | Relay status report (bridges) |

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
  "signing_public_key": "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=",
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
| `peer_registered` | Opaque; triggers a reconcile. The new peer rides the state pull's `peers` block |
| `peer_deregistered` | Opaque; triggers a reconcile. The peer leaving the `peers` block is what removes it |
| `peer_psk_assigned` | Opaque; triggers a reconcile. The edge PSK itself comes from [`GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk`](#edge-psk) |
| `peer_key_rotated` | Opaque; triggers a reconcile. The new key rides the `public_key` member of the `peers` block, and the change makes plexd fetch the edge PSK again |
| `peer_endpoint_changed` | Opaque; triggers a reconcile. The endpoint itself rides the `endpoint` member of the state pull's `peers` block |
| `policy_updated` | Full policy ruleset (L3/L4 rules scoped to mesh IPs) |
| `action_request` | Opaque; triggers a reconcile — the dispatch itself rides the `executions` block of the state pull |
| `session_setup` | Opaque; triggers a reconcile — the session itself rides the `sessions` block of the state pull |
| `session_revoked` | The revoked session's `session_id`, `jti` (equal to `session_id`), `revoked_at`, and `revoke_reason`. plexd closes the named session when it is live, reports the `terminated_by` its `revoke_reason` maps to, then triggers a reconcile. A payload that does not decode, or whose `session_id` is empty or differs from its `jti`, closes nothing and only triggers the reconcile. The session leaving the `sessions` block stays the teardown for a revocation whose event never arrives |
| `session_connect` | The ssh session a client attached to (`session_id`), the one-time `connection_id` of the connection the node is asked to open for it, and `expires_at`, after which the control plane no longer accepts that connection; `event_id` and `occurred_at` ride along and plexd ignores them. plexd opens the connection with [`GET /v1/nodes/{node_id}/sessions/{session_id}/connections/{connection_id}`](#get-v1-nodes-node-id-sessions-session-id-connections-connection-id) when the session is a live ssh session, and triggers no reconcile. A payload that does not decode, or whose `session_id` or `connection_id` is empty, opens nothing |
| `rotate_keys` | Key rotation trigger |
| `signing_key_rotated` | New signing key (`key_id`, `public_key`), `previous_key_id`, `transition_expires`. The state pull's `signing_key` block also carries the key (see [`GET /v1/nodes/{node_id}/state`](#get-v1-nodes-node-id-state)) |
| `node_state_updated` | Updated metadata and data entries |
| `node_secrets_updated` | The node's full secret inventory (names and versions, never values). Opaque; triggers a reconcile, because the inventory rides the state pull's `secrets` block (see [`GET /v1/nodes/{node_id}/state`](#get-v1-nodes-node-id-state)) |

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
| `401 Unauthorized` | `unauthorized`, `nsk_invalid`, `nsk_revoked` | NSK bearer credential missing, invalid, or revoked. Three refused heartbeats with no accepted one between them park the agent (see [Credential Park](heartbeat-service.md#credential-park)) |

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
peer changes arrive via the next state pull. Once the rotation completes, plexd
fetches every edge PSK again from
[`GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk`](#edge-psk).

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

plexd sends its capability manifest once at boot, after registration. It is not
re-sent while the agent runs: a hook added, changed, or removed later is reported
at the next restart.

**Request body** (`CapabilityManifestRequest`):

```json
{
  "binary_version": "v1.4.2",
  "binary_checksum": "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=",
  "ssh_host_key_fingerprint": "SHA256:6QGz1Q4iE2zG5p2N3oRZb8ZsT4nKqJgY3oZmP8eFvWk=",
  "declared_hooks": [
    { "name": "post-install", "checksum": "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=" }
  ],
  "plexd_hooks": [
    {
      "name": "nightly-backup",
      "image_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "parameters": { "retention": "7d" },
      "sandbox": true
    }
  ],
  "builtin_actions": [
    {
      "name": "service.upgrade",
      "description": "Upgrade plexd to a specified version",
      "parameters": [
        { "name": "version", "type": "string", "required": true, "description": "Target version" },
        { "name": "checksum", "type": "string", "required": true, "description": "Expected SHA-256 checksum" }
      ]
    }
  ]
}
```

| Field | Required | Description |
|---|---|---|
| `binary_version` | Yes | Agent version, non-empty after trimming |
| `binary_checksum` | Yes | SHA-256 of the running binary: 32 bytes, standard-padded base64 |
| `ssh_host_key_fingerprint` | No | `SHA256:<base64>` host-key fingerprint |
| `declared_hooks` | No | Script hooks from the hooks directory, each a name and a 32-byte base64 payload digest; at most 128, unique names |
| `plexd_hooks` | No | `PlexdHook` resources discovered at boot in the ServiceAccount's namespace; at most 128, unique names. Absent outside Kubernetes |
| `builtin_actions` | No | The builtin actions the agent implements, sorted by name; at most 128 actions, at most 64 parameters each |

A `plexd_hooks` entry carries `name`, `image_digest` in canonical
`sha256:<64 lowercase hex>` form, and optionally `parameters` (a string map),
`timeout_seconds` (non-negative) and `sandbox`. plexd never sets
`timeout_seconds`, because the PlexdHook CRD has no timeout field. A
`builtin_actions` entry carries `name`, `description` and `parameters`; each
parameter carries `name`, `type`, `required`, `default` and `description`, in
the order the action registered them. An empty inventory is omitted, never sent
as `null` or `[]`.

The control plane refuses a manifest whole, binary version and checksum
included, so plexd sends only entries it knows are valid. A PlexdHook whose image
is not pinned by a digest is left out with a warning; see
[PlexdHook CRD](../actions/plexdhook-crd.md#capability-manifest-reporting).

**Responses.** The contract answers `200 OK` with a `CapabilityManifestResponse`
(`accepted_at`, `fields_changed`, `host_key_changed`); plexd does not read the
body. Errors are RFC 9457 `application/problem+json` bodies with a
machine-readable `code`. A structural failure is a `400`; an advertised inventory
entry that breaks an invariant is a `422`:

| Status | Problem `code` | Meaning |
|---|---|---|
| `400 Bad Request` | `malformed_capabilities_request` | Body is not valid JSON or carries an unknown field |
| `400 Bad Request` | `binary_version_empty` | `binary_version` is missing or blank |
| `400 Bad Request` | `binary_checksum_invalid` | `binary_checksum` does not decode to 32 bytes |
| `400 Bad Request` | `ssh_host_key_fingerprint_invalid` | The fingerprint is set but not `SHA256:<base64>` |
| `400 Bad Request` | `declared_hook_invalid` | A declared hook has an empty name or a checksum that is not 32 bytes |
| `400 Bad Request` | `declared_hook_duplicate` | Two declared hooks share a name |
| `400 Bad Request` | `declared_hooks_too_many` | More than 128 declared hooks |
| `401 Unauthorized` | `unauthorized`, `nsk_invalid`, `nsk_revoked` | NSK bearer credential missing, invalid, or revoked |
| `403 Forbidden` | `node_id_mismatch` | The NSK belongs to a different node than the path |
| `404 Not Found` | `capabilities_node_not_found` | No node row for the path |
| `413 Payload Too Large` | `capabilities_body_too_large` | Body exceeds 32 KiB |
| `422 Unprocessable Entity` | `plexd_hook_invalid` | A `plexd_hooks` entry has an empty name, a non-canonical `image_digest`, or a negative `timeout_seconds` |
| `422 Unprocessable Entity` | `plexd_hook_duplicate` | Two `plexd_hooks` entries share a name |
| `422 Unprocessable Entity` | `plexd_hooks_too_many` | More than 128 `plexd_hooks` entries |
| `422 Unprocessable Entity` | `builtin_action_invalid` | An action has an empty name, or a parameter with an empty or repeated name |
| `422 Unprocessable Entity` | `builtin_action_duplicate` | Two actions share a name |
| `422 Unprocessable Entity` | `builtin_actions_too_many` | More than 128 actions, or one action with more than 64 parameters |
| `500 Internal Server Error` | `internal` | Server error |
| `501 Not Implemented` | `capabilities_not_provisioned` | The control plane has not wired its capability store yet |

plexd logs a failed report as a warning and carries on. It does not retry the
report without the inventories: a control plane that refuses them has to be
upgraded.

## NAT Endpoint Discovery

### PUT /v1/nodes/{node_id}/endpoint

Called after STUN discovery, then on a deadline derived from the response (see below). The response carries no peer endpoints. Each peer's endpoint arrives as `endpoint` in the `peers` block of the [state pull](#get-v1-nodes-node-id-state), and a `peer_endpoint_changed` SSE event only brings that pull forward. The endpoint a node reports here is the one its peers receive for it.

**Request body:**

```json
{
  "endpoint": "203.0.113.7:51820",
  "nat_type": "full_cone",
  "port_mapping": "translated",
  "reported_at": "2026-07-19T19:32:35Z"
}
```

- `endpoint` — the discovered public endpoint as `ip:port`.
- `nat_type` — one of `full_cone`, `restricted`, `port_restricted`, `symmetric`, `unknown`.
- `port_mapping` — whether the NAT kept the STUN probe's source port. `preserved`: the published `endpoint` is what discovery observed. `translated`: the NAT assigned its own port, so `endpoint`, the observed address joined with the WireGuard listen port, holds only where the router forwards or preserves that port. Omitted when empty. The control plane refuses any other value, the empty string included, with `400 malformed_endpoint_request`. It stores the value and shows it beside the Node's endpoint on the Domain's mesh topology; peers never receive it on the state pull. The member needs a control plane with [plexsphere/plexsphere#892](https://github.com/plexsphere/plexsphere/issues/892). An older one strict-decodes the body and answers `400 malformed_endpoint_request` to every report, so the node's endpoint goes stale until the control plane is upgraded.
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
| `400 Bad Request` | `malformed_endpoint_request` | Strict-decode failure, or `nat_type` or `port_mapping` outside its enum |
| `400 Bad Request` | `endpoint_clock_skew` | `reported_at` more than 60s from server time |
| `400 Bad Request` | `endpoint_unparseable` | `endpoint` is not a routable `ip:port` (bad port, or loopback/link-local/unspecified host) |
| `404 Not Found` | `endpoint_peer_not_found` | Node is not a known peer; heals via re-registration |
| `410 Gone` | `endpoint_peer_gone` | Node was removed; heals via re-registration |
| `413 Payload Too Large` | `endpoint_body_too_large` | Body exceeds 4 KiB |

### PUT /v1/nodes/{node_id}/endpoint-candidates

Reports the node's local interface addresses, each joined with its WireGuard
listen port, as endpoint candidates. Each report replaces every candidate the
node reported before. Peers receive them as `endpoint_candidates` in the `peers`
block of the [state pull](#get-v1-nodes-node-id-state), after the node's
peer-observed endpoints, and try them in their
[dial order](../networking/wireguard.md#dial-order). When both together exceed
8, the pull leaves off the trailing candidates. The operation is separate
from [`PUT /v1/nodes/{node_id}/endpoint`](#put-v1-nodes-node-id-endpoint), and
plexd reports on it from a loop of its own, so a node whose STUN discovery fails
still publishes its local addresses. See
[Local endpoint candidates](../networking/nat-traversal.md#local-endpoint-candidates)
for how plexd gathers them.

**Request body** (`EndpointCandidatesRequest`, at most 4 KiB):

```json
{
  "candidates": ["10.0.0.5:51820", "[fd00:10::5]:51820"],
  "reported_at": "2026-10-21T10:15:30Z"
}
```

- `candidates`: required array of 0 to 8 distinct entries. Each is an IPv4
  address or a bracketed IPv6 address without a zone, joined with a port in
  1..65535. The host is not loopback, link-local, multicast or unspecified.
  `null` is refused, and `[]` withdraws every earlier candidate.
- `reported_at`: required, RFC 3339 UTC, within 60s of server time.

`ReportEndpointCandidates` sends a nil `Candidates` as `[]`, and refuses more
than `MaxEndpointCandidates` (8) entries with an error matching
`ErrEndpointCandidatesTooMany` before any request.

**Response** (`200 OK`, `EndpointCandidatesResponse`):

```json
{
  "accepted_at": "2026-10-21T10:15:30Z",
  "stale_after": "2026-10-21T10:20:30Z"
}
```

`stale_after` is the deadline after which the control plane drops the set.
plexd schedules its next report from it as it does the endpoint report: 30s
before `stale_after`, floored at `nat.min_report_interval` and capped by
`nat.refresh_interval`. A zero `stale_after`, and any failure, gives
`refresh_interval`.

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning | plexd behavior |
|---|---|---|---|
| `200 OK` | — | Set accepted; body is an `EndpointCandidatesResponse` | Logged at Debug; also at Info for the first accepted set and for a set that differs from the last accepted one, and once at Info after a not-served phase. The next report follows `stale_after` |
| `400 Bad Request` | `malformed_endpoint_candidates` | Body is not valid JSON, carries an unknown member or misses one; `candidates` is `null`, holds more than 8 entries or repeats an entry | Logged at Warn as `send failed`; retried next cycle |
| `400 Bad Request` | `endpoint_clock_skew` | `reported_at` more than 60s from server time | Logged at Warn as `rejected for clock skew`; retried next cycle |
| `400 Bad Request` | `endpoint_candidate_unparseable` | An entry is not a usable `host:port`; the `detail` names the entry index | Logged at Warn as `send failed`; retried next cycle |
| `401 Unauthorized` | `unauthorized`, `nsk_invalid`, `nsk_revoked` | NSK bearer credential missing, invalid, or revoked | Logged at Warn as `send failed`; retried next cycle |
| `403 Forbidden` | `node_id_mismatch` | The NSK belongs to a different node than the path | Logged at Warn as `send failed`; retried next cycle |
| `404 Not Found` | `endpoint_peer_not_found` | The control plane has not registered the node as a peer yet | Logged at Warn as `rejected, this node is not registered as a peer`; retried next cycle |
| `404 Not Found` | any other, or none | An older control plane that does not serve the operation | Logged once at Info as not served; plexd keeps reporting every cycle |
| `410 Gone` | `endpoint_peer_gone` | Node was removed | Logged at Warn as `rejected, this node is not registered as a peer`; retried next cycle |
| `413 Payload Too Large` | `endpoint_candidates_body_too_large` | Body exceeds 4 KiB | Logged at Warn as `send failed`; retried next cycle |
| `500 Internal Server Error` | — | Server error | Logged at Warn as `send failed`; retried next cycle |
| `501 Not Implemented` | `endpoint_candidates_not_provisioned` | The control plane has not provisioned the operation | Logged once at Info as not served; plexd keeps reporting every cycle |

`api.IsEndpointCandidatesNotServed` classifies the two not-served answers: a
`404` with any code but `endpoint_peer_not_found`, and a `501` carrying
`endpoint_candidates_not_provisioned`. A `404 endpoint_peer_not_found` is the
operation's own answer when the node reports before the control plane has
registered it as a peer, which a later cycle heals, so it is false. A `501` with
any other code is an ordinary failure and logged at Warn. Every failed report
waits `nat.refresh_interval` before the next one.

## Mesh Edge Health

### POST /v1/nodes/{node_id}/handshakes

Reports, for every mesh peer the node has completed a WireGuard handshake with,
the age of the latest handshake and the endpoint WireGuard used for it. The
control plane keeps the latest observation per directed edge and derives each
mesh edge's `status`, `mode`, `handshake_age_seconds` and `endpoint` from it.
When at least two live nodes report a direct handshake with the same peer at the
same endpoint within the Domain's endpoint TTL, the control plane also lists that
endpoint as a peer-observed endpoint at the head of the peer's
`endpoint_candidates` on the [state pull](#get-v1-nodes-node-id-state) of every
node of the Domain except the peer, unless it equals the peer's `endpoint`, its
`fallback_endpoint` or one of its local candidates. The report carries no
transfer counters: per-peer `rx_bytes` and `tx_bytes` travel as `tunnel_health`
samples on the [metrics batch](#observability).

**Request body** (`HandshakeReportRequest`):

```json
{
  "observed_at": "2026-10-21T10:15:30Z",
  "peers": [
    {
      "peer_node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a2",
      "last_handshake_age_seconds": 42,
      "endpoint": "198.51.100.7:51820"
    },
    {
      "peer_node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3",
      "last_handshake_age_seconds": 117,
      "endpoint": "[2001:db8::7]:51820"
    }
  ]
}
```

- `observed_at`: RFC 3339 UTC, the node's wall clock when it assembled the
  report. The server refuses a value more than 60s from its own time. The field
  only gates the request: the server anchors every age on its own receive time,
  so the node's clock never enters the edge status.
- `peers`: always an array, never `null`, with at most 4096 entries. It lists
  every peer the node has completed a handshake with and omits a peer with no
  handshake yet. An empty array is a valid report that records nothing.
- `peer_node_id`: the peer's node ID, a UUID that is not all zeros. No two
  entries may name the same peer. An ID that names the reporting node itself, an
  unknown node, a node of another Domain or a deregistered peer is counted as
  `ignored`, not refused.
- `last_handshake_age_seconds`: whole seconds since the latest completed
  handshake, measured when the report was assembled, between 0 and 2147483647.
- `endpoint`: the endpoint WireGuard currently uses for the peer, as `host:port`
  with an IPv6 host in brackets. The port is in 1..65535, the address is not
  unspecified, and the host carries no IPv6 zone.

Every `400` refuses the whole report, so one bad entry would cost every edge in
it. plexd therefore applies these rules before it sends: it leaves out an entry
whose node ID is not a non-zero UUID or whose endpoint cannot be sent, unmaps an
IPv4-mapped IPv6 address, strips an IPv6 zone, and keeps one entry per peer. See
[Handshake Reporter](heartbeat-service.md#handshake-reporter) for the full build
rules.

**Response** (`200 OK`, `HandshakeReportResponse`):

```json
{
  "accepted_at": "2026-10-21T10:15:30.123Z",
  "recorded": 2,
  "ignored": 0
}
```

`accepted_at` is the server receive time every age was anchored on. `recorded`
counts the entries stored as the latest observation of their edge, `ignored` the
entries naming any other ID.

**Cadence.** plexd reports once per `heartbeat.interval` (default 30s), from a
loop of its own rather than inside the heartbeat, and only when its WireGuard
interface came up. It sends nothing when the loop starts, since no handshake can
exist yet, and then reports on every tick, an empty `peers` array included.

**No replay.** Every attempt carries a freshly assembled body with a new
`observed_at` and new ages. A failed report is never re-sent: the server anchors
each age on its receive time, so a replayed age would make the handshake look
newer than it was. The next tick sends a fresh report instead. `ReportHandshakes`
has no internal retry, and Go's HTTP transport does not replay a `POST`.

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning | plexd behavior |
|---|---|---|---|
| `200 OK` | — | Report accepted; body is a `HandshakeReportResponse` | Logged at Debug; after a not-served phase, one Info line that the control plane accepts reports |
| `400 Bad Request` | `malformed_handshake_report` | Body is not valid JSON or carries an unknown field; `observed_at` or `peers` is missing; `peers` is `null` or holds more than 4096 entries; an entry misses `peer_node_id` or `last_handshake_age_seconds`, carries a zero `peer_node_id`, an age outside 0..2147483647, or a `peer_node_id` another entry already named | Logged at Warn; the next tick sends a fresh report |
| `400 Bad Request` | `handshake_clock_skew` | `observed_at` more than 60s from server time | Logged at Error, asking the operator to synchronize the system clock via NTP; the next tick sends a fresh report |
| `400 Bad Request` | `handshake_endpoint_unparseable` | An `endpoint` is not a `host:port` pair, its port is 0, its address is unspecified, or it carries an IPv6 zone; the `detail` names the entry index | Logged at Warn; the next tick sends a fresh report |
| `401 Unauthorized` | `unauthorized`, `nsk_invalid`, `nsk_revoked` | NSK bearer credential missing, invalid, or revoked | Logged at Warn; the next tick sends a fresh report |
| `403 Forbidden` | `node_id_mismatch` | The NSK belongs to a different node than the path | Logged at Warn; the next tick sends a fresh report |
| `404 Not Found` | any, or none | An older control plane that does not serve the operation | Logged once at Info as not served; plexd keeps reporting every interval |
| `413 Payload Too Large` | `handshake_report_too_large` | Body exceeds 1 MiB | Logged at Warn; the next tick sends a fresh report |
| `500 Internal Server Error` | `internal` | Server error, for example a failed write of the observations | Logged at Warn; the next tick sends a fresh report |
| `501 Not Implemented` | `handshakes_not_provisioned` | The control plane has not wired its handshake recording service | Logged once at Info as not served; plexd keeps reporting every interval |

`api.IsHandshakeReportNotServed` classifies the two not-served answers. A `501`
with any other code is an ordinary failure and logged at Warn.

## Relay Status

### PUT /v1/nodes/{node_id}/relay-status

Reports the state of a bridge's relay, so the control plane stops assigning a
relay that does not run. The control plane keeps the latest report per node and
reads it only for a bridge whose relay is enabled. A relay whose report in force
is anything but `running` on the pulled `listen_port` reads `not_running`, and
its pairs move to another bridge within about 15s, or lose their
`fallback_endpoint` when the Domain has no other bridge that relays. See
[Relay Status Report](../bridge/nat-relay.md#relay-status-report) for how plexd
derives the state from its relay.

**Request body** (`RelayStatusRequest`, at most 4 KiB) takes one of four shapes:

```json
{ "state": "running", "listen_port": 51821, "bound_seconds": 30 }
```

```json
{ "state": "stopped" }
```

```json
{ "state": "bind_failed", "listen_port": 51821 }
```

```json
{ "state": "not_consented" }
```

- `state`: required, one of `running`, `stopped`, `bind_failed` and
  `not_consented`. `running` means the relay socket is bound on `listen_port`;
  `stopped`, that the relay does not run because the pull does not enable it,
  names a `listen_port` outside 1..65535, or plexd shuts down; `bind_failed`,
  that plexd could not bind `listen_port`; and `not_consented`, that the pull
  enables a relay that `bridge.relay_enabled` does not consent to.
- `listen_port`: the relay's UDP port, 1..65535. Required for `running` and
  `bind_failed`, forbidden otherwise.
- `bound_seconds`: whole seconds since the relay socket was bound,
  0..315360000. Required for `running`, forbidden otherwise. The server anchors
  the seconds on its own receive time, so the node's clock never enters the
  relay's health.

The control plane decodes the body with unknown members refused. A member the
state requires or forbids answers `400 invalid_relay_status` with a `detail`
naming the member. An unknown member, an out-of-range value or a `null` member
answers `400 malformed_relay_status`. `ReportRelayStatus` validates nothing,
because plexd builds only these four shapes: it floors `bound_seconds` to whole
seconds, sends 0 for a socket bound less than a second ago, and clamps the
value to 315360000.

**Response** (`200 OK`, `RelayStatusResponse`):

```json
{
  "accepted_at": "2026-10-30T10:15:30.123Z"
}
```

`accepted_at` is the server receive time `bound_seconds` was anchored on. A
report identical to the stored one only refreshes the instant the control plane
last saw it.

**Cadence.** plexd reports from a loop of its own, never from inside the relay
reconcile handler, so a slow control plane never delays a reconcile cycle. It
sends a report when the relay's state changes, and again once per
`heartbeat.interval` (default 30s) while nothing changes. The interval restarts
after every report sent on a change, so an unchanged state never goes out twice
in quick succession. The re-send keeps the report in force: the control plane
counts a report not repeated within three heartbeat intervals, 90s under the
default policy, as absent. When plexd shuts down it sends a last `stopped`,
bounded by 5s, so a bridge stopped for good gives up its pairs within about 15s
instead of waiting for its heartbeat to read stale. plexd sends nothing before
the relay reconcile handler first ran, because until then it does not know the
relay's state, and a node outside bridge mode sends nothing at all.

**No replay.** Every attempt carries a freshly built body with a new
`bound_seconds`. A failed report is not retried within its tick: the server
anchors `bound_seconds` on its receive time, so a replayed body would date the
bind later than it happened. The next tick, at most one interval later, sends a
fresh report instead. `ReportRelayStatus` has no internal retry, and Go's HTTP
transport does not replay a `PUT`.

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning | plexd behavior |
|---|---|---|---|
| `200 OK` | — | Report accepted; body is a `RelayStatusResponse` | Logged at Debug; also at Info for the first accepted status and for one that differs from the last reported one, and once at Info after a not-served phase |
| `400 Bad Request` | `malformed_relay_status` | Body is not valid JSON, carries an unknown member or data after the report, or misses `state`; `state` is outside the four states, `listen_port` outside 1..65535 or `bound_seconds` outside 0..315360000; or `listen_port` or `bound_seconds` is `null` | Logged at Warn as `send failed`; the next tick sends a fresh report |
| `400 Bad Request` | `invalid_relay_status` | A member the state requires is missing, or one it forbids is present; the `detail` names the member | Logged at Warn as `send failed`; the next tick sends a fresh report |
| `401 Unauthorized` | `unauthorized`, `nsk_invalid`, `nsk_revoked` | NSK bearer credential missing, invalid, or revoked | Logged at Warn as `send failed`; the next tick sends a fresh report. Once the heartbeat has parked the agent on the refused credential, no request leaves and the failure is logged at Debug |
| `403 Forbidden` | `node_id_mismatch` | The NSK belongs to a different node than the path | Logged at Warn as `send failed`; the next tick sends a fresh report |
| `404 Not Found` | `relay_status_node_gone` | The node was removed while the request ran | Logged at Warn as `rejected, this node was removed` on every send; plexd keeps reporting every interval |
| `404 Not Found` | any other, or none | An older control plane that does not serve the operation | Logged once at Info as not served; plexd keeps reporting every interval and keeps relaying as the pull says |
| `413 Payload Too Large` | `relay_status_body_too_large` | Body exceeds 4 KiB | Logged at Warn as `send failed`; the next tick sends a fresh report |
| `500 Internal Server Error` | `internal` | Server error, for example a failed write of the report | Logged at Warn as `send failed`; the next tick sends a fresh report |
| `501 Not Implemented` | `relay_status_not_provisioned` | The control plane has not provisioned the operation | Logged once at Info as not served; plexd keeps reporting every interval and keeps relaying as the pull says |

`api.IsRelayStatusNotServed` classifies the two not-served answers: a `404`
with any code but `relay_status_node_gone`, and a `501` carrying
`relay_status_not_provisioned`. A `404 relay_status_node_gone` is the
operation's own answer, a verdict on the node rather than a missing route, so
it is false. A `501` with any other code is an ordinary failure and logged at
Warn. No answer stops the reporter, and none touches the relay. While the
control plane does not serve the report, plexd sends no `stopped` at shutdown.

## Edge PSK

### GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk

Returns the pairwise WireGuard preshared key (PSK) of the edge between the node
and the peer `{peer_node_id}`, sealed under the node's NSK. The state pull never
carries a PSK, so plexd fetches one per edge from this operation and programs it
on the peer. The request has no body.

**Response** (`200 OK`) is `Content-Type: application/octet-stream`, not JSON:
the body is exactly 60 bytes (`api.EdgePSKEnvelopeSize`), the AES-256-GCM
envelope `<12-byte nonce> || <32-byte PSK ciphertext> || <16-byte GCM tag>`.
plexd refuses a body of any other length. The metadata rides in response
headers, and plexd refuses a response that lacks either `X-Plexsphere-PSK-*`
header:

| Header | Meaning |
|---|---|
| `X-Plexsphere-PSK-KID` | Key id of the NSK the envelope was sealed under. plexd holds one NSK, so the value selects nothing |
| `X-Plexsphere-PSK-Epoch` | The epoch of the PSK, bound into the additional authenticated data and used verbatim |
| `Cache-Control` | Always `no-store` |

plexd opens the envelope with AES-256-GCM under its 32-byte NSK, the same key
and layout as a [secret envelope](#secrets), but with this additional
authenticated data (AAD):

```text
plexsphere/mesh/edge-psk/v1|<node_id>|<peer_node_id>|<epoch>
```

`<node_id>` is this node's ID and `<peer_node_id>` the peer's, each trimmed and
lowercased; `<epoch>` is the `X-Plexsphere-PSK-Epoch` value exactly as served.
Binding the two IDs keeps a secret envelope (sealed with no AAD) or another
edge's envelope from opening as this edge's PSK. Binding the epoch makes the
header a trustworthy statement of the envelope's age. An envelope that does not
open is logged at Warn and installs nothing.

**Epoch rule.** plexd keeps the highest epoch it has accepted for each edge and
refuses an envelope whose epoch sorts below it, with a Warn line. The
comparison is a plain string comparison, which the fixed-width UTC epoch format
makes chronological, and an equal epoch is accepted. A mesh key rotation does
not rotate the NSK, so an older envelope would still open and reinstall a
retired key. The floor survives a change of the peer's public key and is
dropped when the peer leaves the `peers` block. It lives in memory only: a
restarted node fetches every PSK again with no floor.

**Fetch rule.** plexd fetches a peer's PSK when the peer first appears in the
`peers` block of the [state pull](#get-v1-nodes-node-id-state), when its
`public_key` changes, and after this node completes its own key rotation. A
fetch that failed stays due, and once every peer's PSK is in hand, a pull with
an unchanged peer set sends no request. The fetches run on every successful
pull, in node ID order, before the reconcile handlers, so a new peer's PSK is
in hand when the WireGuard handler adds the peer in the same cycle. After its
own rotation, plexd keeps each old PSK on the device until the replacement
arrives. A `peer_psk_assigned` event only triggers a reconcile, and a fetch
that is still due runs on the pull it triggers.

When plexd has already programmed the peer under the public key the PSK was
fetched for, it installs the PSK by rewriting the peer's device entry with its
allowed IPs and the PSK, which leaves the device's endpoint for the peer as it
is. A failed install is logged at Warn and retried on the next pull without
another fetch. The WireGuard reconcile handler programs the PSK held for a
peer's current public key on every peer it adds or updates, so a PSK fetched
before its peer is programmed reaches the device that way. Keys, envelopes and
the NSK never reach a log line or an error.

plexd fetches edge PSKs only when its WireGuard interface came up and
[`wireguard.edge_psk`](configuration.md#wireguard) is true, the default. With
`edge_psk: false` it logs `edge psk disabled by wireguard.edge_psk` at Info and
programs no PSK. WireGuard needs the same PSK on both ends of a tunnel, and the
relay forwards UDP end to end, so an edge between a node that installs edge PSKs and one that
installs none fails, direct and relayed, until both ends match. During a
rolling upgrade, set `edge_psk: false` on the upgraded nodes and turn it back
on once every node of the Domain runs a plexd that installs edge PSKs.

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning | plexd behavior |
|---|---|---|---|
| `200 OK` | — | Edge PSK envelope (octet-stream) with the headers above | Checked against the epoch floor, opened and installed; logged at Info as `wireguard: edge psk fetched` with `peer_id` and `epoch`. After a not-served phase, one Info line that the control plane serves edge PSKs |
| `401 Unauthorized` | `unauthorized`, `nsk_invalid`, `nsk_revoked` | NSK bearer credential missing, invalid, or revoked | Logged at Warn; the pass goes on to the next peer, and the next pull fetches again |
| `403 Forbidden` | `node_id_mismatch`, `node_deregistered` | The NSK belongs to a different node than the path, or this node was deregistered | Terminal for any code: logged at Error, and plexd sends no edge PSK request again until it restarts |
| `404 Not Found` | `peer_not_found` | The peer does not resolve to a live peer of the node's Domain yet, for example right after it registered | Logged at Debug; the pass goes on to the next peer, and the next pull retries |
| `404 Not Found` | any other, or none | An older control plane that does not serve the operation | Logged once at Info as not served; the pass stops, so such a control plane sees one request per pull |
| `409 Conflict` | `psk_not_ready` | The PSK of the edge has not been provisioned yet | Logged at Debug; the pass goes on to the next peer, and the next pull retries |
| `429 Too Many Requests` | `per_node_rate_limited` | Per-node fetch rate limit | Logged at Warn; the pass stops, and no pull fetches until `Retry-After` has passed (at least 1s) |
| `500 Internal Server Error` | — | Server error | Logged at Warn; the pass goes on to the next peer, and the next pull fetches again |
| `501 Not Implemented` | `psk_delivery_not_provisioned` | The control plane has not wired its PSK delivery | Logged once at Info as not served; the pass stops, so such a control plane sees one request per pull |

`api.IsEdgePSKNotServed` classifies the two not-served answers. A `501` with any
other code, a body that is not 60 bytes, or a missing header is an ordinary
failure: plexd logs it at Warn and goes on to the next peer. A transport error,
such as a refused connection or a request timeout, is logged at Warn and stops
the pass: it would meet every remaining peer the same way, and the fetches run
before the reconcile handlers, so a control plane that hangs costs one request
timeout per pull rather than one per peer.

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
      "fallback_endpoint": "203.0.113.1:51820",
      "endpoint_candidates": ["192.0.2.10:51820"]
    },
    {
      "node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2",
      "mesh_ip": "10.99.0.3",
      "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
      "endpoint": "198.51.100.20:51820"
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
    "relay": {
      "enabled": true,
      "listen_port": 51820,
      "assignments": [
        {
          "peer_node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1",
          "fallback_endpoint": "203.0.113.1",
          "fallback_endpoint_port": 51820
        }
      ]
    },
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
  ],
  "secrets": [
    { "name": "api-token", "version": 1 },
    { "name": "db-password", "version": 2 }
  ],
  "signing_key": {
    "key_id": "signing-domain-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1-1767225600000000000",
    "public_key": "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
  }
}
```

A peer's `endpoint` is its direct WireGuard endpoint as `host:port` (an IPv6
host in brackets), the address the peer last reported through
[`PUT /v1/nodes/{node_id}/endpoint`](#put-v1-nodes-node-id-endpoint). It is
absent while the peer has no fresh NAT observation.

A peer's `endpoint_candidates` lists, as `host:port` strings, first the peer's
peer-observed endpoints, sorted by address and port. A peer-observed endpoint is
an address and port at which at least two live nodes of the Domain reported,
through [`POST /v1/nodes/{node_id}/handshakes`](#post-v1-nodes-node-id-handshakes),
a direct WireGuard handshake with the peer that completed within the Domain's
endpoint TTL. A handshake at the peer's `fallback_endpoint` never counts. The
control plane leaves one out when it equals the peer's `endpoint`, its
`fallback_endpoint`, one of its local candidates or an earlier entry, or when it
has port 0, a zone, or a loopback, link-local, multicast or unspecified address.
The peer's last accepted, unexpired local candidates from
[`PUT /v1/nodes/{node_id}/endpoint-candidates`](#put-v1-nodes-node-id-endpoint-candidates)
follow, in the order the peer sent them. The list holds at most 8 entries: when
both together exceed 8, the control plane drops the trailing local candidates.
Only nodes of the peer's Domain receive them. The member is absent when no entry
remains, and on every control plane that does not deliver it. A control plane
older than peer-observed endpoints lists only the local candidates.

The pull carries no PSK: plexd fetches the pairwise PSK of each edge from
[`GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk`](#edge-psk).

plexd tries a peer's endpoints in a fixed dial order and keeps the first one
that completes a WireGuard handshake: the candidates on a subnet this node is
also on, then `endpoint` when it is usable, then the remaining candidates, then
`fallback_endpoint`, the relay target. A direct endpoint or candidate is usable
when it parses as an IP address and a non-zero port, carries no IPv6 zone,
names an address that is not unspecified, loopback, multicast or link-local (an
IPv4-mapped IPv6 address is unmapped first), and lies outside the Domain mesh
prefix (the node's own mesh IP as a host /32 when registration returned no
usable `domain_mesh_cidr`). plexd leaves a refused one out of the order, and
logs a refused `endpoint` at Warn and refused candidates at Debug.
`fallback_endpoint` is not validated, since the contract allows a hostname
there. A change of `endpoint`, `fallback_endpoint` or `endpoint_candidates`,
the candidates' order included, is enough for the differ to update the peer.
plexd tries each entry for one trial, the WireGuard keepalive plus 5 s, and
holds the fallback longer: when `fallback_endpoint` is the last entry and other
entries come before it, plexd tries it as long as those entries took together.
Two nodes behind hard NATs are then on the relay at the same time. With the
default keepalive, a ten-entry order reaches the fallback after about 270 s,
stays on it for about 270 s, and starts over after about 540 s. A two-entry
order behaves as before. plexd never switches a peer connected on a direct
path, and follows three rules for the relay. A peer dialing
`fallback_endpoint` moves at once when the pull names another one, on a fresh
WireGuard session, unless it is connected over a direct path WireGuard roamed
to; plexd tells that path from the device's endpoint, which it can compare
only with a `fallback_endpoint` that is an address. A peer that runs over the
relay and received nothing for one trial gets a probe through the tunnel, and
plexd dials the relay again when nothing comes back within 15 s. Such a peer
stays on the relay after its connection fails, and plexd tries its direct
entries again only when the pull drops `fallback_endpoint` or the peer, its
key rotates, plexd restarts, or WireGuard roamed it to a direct path that then
failed.
See [Dial order](../networking/wireguard.md#dial-order),
[Endpoint selection](../networking/wireguard.md#endpoint-selection) and
[Relay liveness probe](../networking/wireguard.md#relay-liveness-probe).

`bridge.relay` asks a bridge to relay WireGuard for the peers whose
`fallback_endpoint` names it. A bridge listens only when its local
[`bridge.relay_enabled`](configuration.md#bridge) is true and the block carries
`enabled: true`. It then binds UDP `listen_port`, which is authoritative, and
forwards among the peers of the same pull's `peers` block, routing each
datagram by its WireGuard header. Without local consent it logs a Warn and
opens no socket. A `null` block, or `enabled: false`, stops a running relay.
`assignments` lists the peers that dial this bridge as their fallback, each as
`peer_node_id` with the `fallback_endpoint` host and `fallback_endpoint_port`
it dials. plexd decodes and carries it, and the relay does not read it. A change of `enabled`, `listen_port` or an assignment is bridge
drift. A node outside bridge mode ignores the block. See
[NAT Relay](../bridge/nat-relay.md).

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
no revocation callback to answer and no terminal status to report. A revocation
the control plane announces in a signed `session_revoked` event is normally closed by that
event first (see [SSE Event Stream](#sse-event-stream)). It is always an
array (`[]` when empty, never `null`). `kind` is one of `ssh`, `k8s`, or `tcp` and
selects the single member of `target`; `jti` equals `session_id` and is carried
opaquely; `expires_at` is an absolute UTC timestamp; `idle_timeout_seconds` absent
or `0` means the session has no idle window. See
[Secure Access Tunneling](/reference/networking/secure-access-tunneling) for how
plexd consumes it.

`signing_key` is the key the node's Domain signs event envelopes and session
tokens with, as the "Domain signing key" section of plexsphere's agent contract
(`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere)
describes it. `key_id` is the id the key signs under and `public_key` is the
32-byte Ed25519 public key in standard base64, the encodings `POST /v1/register`
uses for `signing_key_id` and `signing_public_key`. The block is `null` when the
control plane cannot say: the Domain has no key yet, or the control plane could
not reach its Signing Service. plexd then keeps the key it holds, as it does when
a control plane older than the block leaves the key out; `null` never means
"drop the key". plexd reads the block on every successful pull, drift or
not. A key that differs from the one it holds goes into the verifier that checks
both [event envelopes](event-verification.md) and ssh session tokens, replaces
the current key and ends any rotation grace window, since a node trusts exactly
one key of its Domain. plexd logs it at Info as
`installed signing key from state pull` with `key_id` and `public_key`. A pulled
key that differs from the pair plexd persisted is written into the
`signing_public_key` file and `identity.json` (see
[Key Storage](key-storage.md#ed25519-signing-public-key)), so a restart starts
from it. A failed write is logged at Warn as
`signing key not persisted; retrying on the next pull` and retried on every
pull. A key plexd cannot install (an empty `key_id`, or a `public_key` that is
not 32 bytes of standard base64) changes nothing and is logged at Warn as
`signing key from state pull rejected` once, and not again until a pull carries
a different key. The block is not desired state: the differ neither stores nor
compares it. A Linux session helper that already pinned a key keeps its pin; see
[Trust anchor](../networking/secure-access-tunneling.md#trust-anchor).

`secrets` is the node's secret inventory, as the "Secret inventory" section of
plexsphere's agent contract (`docs/reference/api/plexd-agent-contract.md` in
plexsphere/plexsphere) describes it: one entry per Secret the node may read,
with its `name` and current `version`, never its value. A `name` matches
`^[a-z][a-z0-9_-]{0,62}$`, the grammar of the [secret fetch](#secrets), and a
`version` is an integer of at least 1. Entries are ordered by `name` ascending.
The control plane sends `[]` when the node may read nothing, never `null`. plexd
reads the block on every successful pull, drift or not, and replaces the secret
index that [`GET /v1/state/secrets`](nodeapi.md#get-v1-state-secrets) lists:
each entry's `name` becomes the listing's `key`, its `version` is kept, and so
is the pull's order. `[]` empties the index. A `null` value, or a key missing
because the control plane predates the block, means the control plane did not
say, and plexd keeps the index it holds. When the index changes, plexd logs
`secret index updated` at Info with `count`. plexd drops an entry whose name is
outside the grammar (`invalid name`), whose version is below 1
(`invalid version`), or whose name an earlier kept entry already has
(`duplicate name`; the first entry is kept). It logs each at Warn as
`secret inventory entry dropped` with `name`, `version` and `reason`, once, and
not again until the set of dropped entries changes.

The pull, not the `node_secrets_updated` event, writes the index. The event
carries the same full inventory, but plexd treats its payload as opaque and only
triggers a reconcile, so an event that arrives late can never roll the index
back. The cost is one extra state pull per inventory change. A failed pull
leaves the index as it is. The index holds no values:
`GET /v1/state/secrets/{key}` fetches the value live from
[`GET /v1/nodes/{node_id}/secrets/{key}`](#secrets), and a `403` or `404` there
never removes the entry from the index. Only an inventory that leaves the name
out removes it. A name granted moments ago can answer `403` for a few seconds:
the control plane writes the grant's reader tuple a few seconds after the grant,
and the pull reads the grants themselves.

## Secrets

### GET /v1/nodes/{node_id}/secrets/{key}

Called on-demand when a consumer requests a secret via the Local Node API. The
local-endpoint reporters also call it to resolve their bearer token: a `403` or
`404` drops the token they cached, and every other failure keeps it. The
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

A one-of activity record carrying exactly one of `ssh`, `k8s`, or `tcp`. plexd
emits `tcp` rows for a tcp session: a `session_started` row when the listener
comes up, `session_active` rows while the tunnel forwards bytes, and a
`session_ended` row on close. It emits `ssh` rows for an ssh
session, served on Linux and macOS: the two lifecycle rows, `session_started` and
`session_ended`, with no `session_active` row, plus two command rows
around every `exec`. It emits no `k8s` rows.

**Request body** (tcp `session_started`). `listener_endpoint` is the address the node
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

**Request body** (tcp `session_ended`). `bytes_in` (operator→target) and `bytes_out`
(target→operator) are explicit, present even when `0`; `terminated_by` is one of
`ttl_expired`, `idle_timeout`, `operator_revoke`, or `plexd_close`. plexd sends
`operator_revoke` only for a session it closed because a verified
`session_revoked` event named it with an operator-driven `revoke_reason`
(`operator_request`, `policy_violation`, `identity_compromise`, or
`resource_decommissioned`) or with an empty or unrecognised one; the event's
`ttl_expired` and `idle_timeout` reasons are reported as `ttl_expired` and
`idle_timeout`. A revocation without the event reaches the node as the absence
of its entry, which is indistinguishable from a control plane that failed to
serve the block, so a drained entry is reported as `plexd_close`, also when a
pull drains it before the event arrives (the late event then finds no live
session to close):

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

**Request body** (tcp `session_active`). The row carries `phase` alone and says
that the tunnel forwarded bytes since the node's previous `session_active` row.
plexd posts the first one as soon as a byte crosses after an interval without a
row, then one at the end of each interval in which bytes crossed, and none once a
whole interval passed without a byte. The interval is
`min(60 s, idle_timeout_seconds / 4)`, or 60 s for an entry whose
`idle_timeout_seconds` is `0`. On a live session the control plane advances the
session's `last_active_at` and appends no row to its activity log (see
[Activity Reports](../networking/secure-access-tunneling.md#activity-reports)):

```json
{"tcp": {"phase": "session_active"}}
```

**Request body** (ssh `session_started` and `session_ended`). A lifecycle row
carries no command fields and no byte counters. An ssh session binds no
listener, so its started row carries no `listener_endpoint` and means the session
is ready to serve the connections the control plane asks for (see
[below](#get-v1-nodes-node-id-sessions-session-id-connections-connection-id));
the control plane still admits the started row with an endpoint that older
agents post:

```json
{"ssh": {"phase": "session_started"}}
```

```json
{"ssh": {"phase": "session_ended", "terminated_by": "idle_timeout"}}
```

**Request body** (ssh command rows). An `exec` fails closed: plexd posts the
first row before the command runs and runs it only once the row is accepted, and
the second once the command exited. Times are UTC:

```json
{"ssh": {"command": "uptime", "started_at": "2026-09-24T08:00:00Z"}}
```

```json
{
  "ssh": {
    "command": "uptime",
    "exit_code": 0,
    "started_at": "2026-09-24T08:00:00Z",
    "completed_at": "2026-09-24T08:00:03Z"
  }
}
```

| Response | Meaning |
|---|---|
| `204 No Content` | Activity record accepted |
| `400 Bad Request` (`malformed_session_activity`) | Body is unreadable, fails strict decoding, violates the one-of contract, mixes the ssh lifecycle and command shapes, or populates a member other than the session's kind |
| `403 Forbidden` (`nsk_node_mismatch`) | Record targets a node other than the caller's identity |
| `404 Not Found` (`session_not_found`) | No session resolves for this node and session id |
| `409 Conflict` (`session_already_revoked`) | The session has been revoked, and the row is not the one `session_ended` row such a session still records (see below) |
| `409 Conflict` (`session_expired`) | The session's `expires_at` has lapsed, and the row is not the one `session_ended` row such a session still records (see below) |

The two `409` answers are terminal states of the session: neither goes back to
live. A revoked or expired ssh or tcp session still records one row: the first
`session_ended` row of its current listener, reported in the member its kind
calls for, is accepted with `204`. Every other row on such a session, a second
`session_ended` row included, is a `409`. plexd classifies them with
`api.IsSessionRevokedOrExpired` and reads them as the drain signal rather than as
a retryable error — a `session_started` row answered this way is settled instead
of re-posted, and a `session_ended` row answered this way is logged at Warn
carrying its `terminated_by` and, for a `tcp` row, the byte counters it failed to
deliver. A close caused by a drain or by a
`session_revoked` event posts its `session_ended` row into a session the control
plane already holds as revoked or expired, so that row is normally accepted. A
`409` to it means the end of that listener is already recorded, or that the
control plane predates
[plexsphere/plexsphere#931](https://github.com/plexsphere/plexsphere/issues/931)
and refuses every row on a revoked or expired session. The answer never closes a
session: the teardown stays with the `sessions` block drain (or a verified
`session_revoked` event), and while the block keeps carrying an entry answered
this way, every pull warns that its listener is still forwarding. On an ssh command
row that precedes an `exec` the answer means the command does not run, and it
closes the client's connection.

The `404` is not classified with them. It is the `sessions` block and the session
store disagreeing — two separate reads, so a lagging replica, a session record
written after the block was rendered, or a failover window all produce it — and
the entry standing in the block is the control plane still asking for the
session. It therefore keeps the ordinary handling, as every other answer does: a
started row is re-posted on the next pull and an ended row is logged at Error and
dropped.

A tcp `session_active` row is posted by the tunnel's own reporter, not by the
pull, and plexd reads each answer to it this way: `204` means the row is
recorded; a `409` `session_already_revoked` or `session_expired` stops the
session's reports; a `400`, which a control plane that predates the row answers
as `400 invalid_session_activity`, is warned about once per session and not
retried, though later bytes still post; every other answer, a `401 nsk_invalid`,
the `404`, a `5xx`, a transport error or a timeout among them, is retried at the
end of the interval. None of them closes the tunnel.

### GET /v1/nodes/{node_id}/sessions/{session_id}/connections/{connection_id} {#get-v1-nodes-node-id-sessions-session-id-connections-connection-id}

The connection a verified `session_connect` event asks the node to open for one
of its ssh sessions, as plexsphere/plexsphere#928 defines it. `{session_id}` and
`{connection_id}` are the event payload's members, path-escaped. The request is
a WebSocket upgrade (RFC 6455) with no body, sent over HTTP/1.1 through the same
client, TLS settings and base URL as every other call, with
`Authorization: Bearer <NSK bearer>` and `User-Agent: plexd/<version>`.
Compression is off. The control plane splices the client that attached to the
session onto the socket, and each binary message carries raw SSH bytes in either
direction, so SSH runs end to end between the client and plexd.

The control plane pings the connection every 30 s. plexd answers the pings and
does not count them as session activity, so they cannot hold an idle session
open. A text message closes the connection with status `1003`, a close with
`1000` or `1001` ends it normally. plexd closes its side with `1000` when it
can: it cancels a read in flight first, which closes the socket, so the control
plane may see the connection end without a close frame.

plexd does not judge `expires_at` against its own clock: the envelope verifier
admits envelopes up to 5 minutes off while the control plane waits seconds for
the connection, so a node clock slightly ahead would drop every request. The
control plane refuses a connection that comes too late with the `404`. A failed
open is not retried, because each attach mints a new `connection_id`.
A refused upgrade is returned as an `*APIError` carrying the status and the
problem `code`, read from the first 1024 bytes of the body, and plexd logs it at
Warn (`session connection to the control plane failed`).

| Response | Meaning |
|---|---|
| `101 Switching Protocols` | Connection accepted; the WebSocket carries the session's SSH bytes until either side closes it |
| `401 Unauthorized` | Invalid node identity |
| `403 Forbidden` (`nsk_node_mismatch`) | The path names a node other than the caller's identity |
| `404 Not Found` (`session_connection_not_found`) | No pending connection with this id for this node's session: unknown, minted for another session, already opened, or past its `expires_at` |
| `409 Conflict` (`session_not_active`) | The session is no longer active |
| `426 Upgrade Required` (`upgrade_required`) | The request is not a WebSocket upgrade |
| `501 Not Implemented` (`access_attach_not_provisioned`) | The control plane does not serve session connections |
| `502 Bad Gateway` (`session_connection_forward_failed`) | The control plane could not forward the connection to the replica the client is attached to |

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
