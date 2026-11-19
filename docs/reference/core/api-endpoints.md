---
title: Control Plane API Endpoints
---

# Control Plane API Endpoints

plexd requires the following API endpoints on the control plane. All endpoints use the `/v1` prefix and HTTPS. Authentication uses the NSK bearer envelope, which plexd builds from the node ID and the NSK that registration returns (see [BearerToken](registration.md#bearertoken)), unless noted otherwise. Request and response bodies are JSON (`Content-Type: application/json`) unless noted otherwise.

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
| 21 | `GET` | `/v1/nodes/{node_id}/hooks/{name}/versions/{version}` | Published hook version fetch (signed envelope and script) |
| 22 | `PUT` | `/v1/nodes/{node_id}/policy-status` | Policy status report |
| 23 | `PUT` | `/v1/nodes/{node_id}/ingress-status` | Ingress status report, with the state of each ingress rule (bridges) |
| 24 | `PUT` | `/v1/nodes/{node_id}/site-to-site-status` | Site-to-site status report, with the state of each site-to-site tunnel (bridges) |

## Registration & Identity

### POST /v1/register

Unauthenticated (`security: []`): the bootstrap token travels in the
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
log. No error answer counts as a **redemption** of the bootstrap token.

| Status | Problem `code`(s) | Meaning | plexd behavior |
|---|---|---|---|
| `201 Created` | — | Registration successful | — |
| `400 Bad Request` | `public_key_invalid` (or none) | Malformed public key, or an undecodable body | Stop |
| `401 Unauthorized` | — | Bootstrap token rejected | Stop |
| `403 Forbidden` | `kind_mismatch`, `project_mismatch`, `token_consumed`, `token_expired`, `token_revoked`, `nonce_collision` | Terminal denial: wrong token kind or project, token that reached its redemption limit, expired/revoked token, or replayed nonce | Stop |
| `404 Not Found` | `resource_not_found` | Resource handle could not be resolved | Stop |
| `409 Conflict` | — | Conflicting registration | Stop |
| `422 Unprocessable Entity` | — | Request invariant violation (empty/oversized field, non-UUID `project_id`) | Stop |
| `429 Too Many Requests` | `token_rate_limited` | The rate limit of the token's BootstrapToken policy refused this redemption; the token is valid and the refusal did not count as a redemption | Wait `Retry-After` with no time limit, then send the same request again (see [Rate-limited bootstrap token](registration.md#rate-limited-bootstrap-token)) |
| `429 Too Many Requests` | any other, or none | Rate limited, for example by the per-IP limiter's `rate_limited` before any token is looked up | Retry within `max_retry_duration`, honoring `Retry-After` |
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

plexd sends its capability manifest at boot, after registration and its first
hook scan. It sends the manifest again when a script hook is added, changed, or
removed, when a hook's sidecar is edited or removed, when a pass of the rollout
installer changes the rolled-out hooks or the rollout errors, and when the
PlexdHook resources in its namespace change, within seconds of the change. A
send that matches the manifest last accepted is skipped. There is no periodic
re-send of a manifest the control plane holds, because every accepted PUT that
carries a drifted hook raises another integrity alert. The one timed send is the hourly
attempt after a refusal of the hook metadata, described below. See
[Capability Announcement](../actions/remote-actions-hooks.md#capability-announcement).

Each PUT is a snapshot: the control plane replaces its stored row with the body.
An absent `declared_hooks`, `plexd_hooks` or `hook_rollout_errors` key therefore
means none, never "unchanged".

**Request body** (`CapabilityManifestRequest`):

```json
{
  "binary_version": "v1.4.2",
  "binary_checksum": "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=",
  "ssh_host_key_fingerprint": "SHA256:6QGz1Q4iE2zG5p2N3oRZb8ZsT4nKqJgY3oZmP8eFvWk=",
  "declared_hooks": [
    {
      "name": "post-install",
      "checksum": "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=",
      "description": "Run after a package install",
      "parameters": [
        { "name": "package", "type": "string", "required": true, "description": "Package that was installed" }
      ],
      "timeout_seconds": 300,
      "sandbox_level": "none"
    },
    {
      "name": "backup-db",
      "checksum": "REA9yHQRkMbFu76wJTDLSMvpMnUd9WeDatQzSknU1Qg=",
      "sandbox_level": "none",
      "source": "rollout",
      "version": 2
    }
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
  ],
  "hook_rollout_errors": [
    { "name": "rotate-logs", "version": 1, "code": "collision", "detail": "hooks_dir holds a hook of this name" }
  ]
}
```

| Field | Required | Description |
|---|---|---|
| `binary_version` | Yes | Agent version, non-empty after trimming |
| `binary_checksum` | Yes | SHA-256 of the running binary: 32 bytes, standard-padded base64 |
| `ssh_host_key_fingerprint` | No | `SHA256:<base64>` host-key fingerprint |
| `declared_hooks` | No | Script hooks from the hooks directory and the rolled-out hooks plexd installed, each a name, a 32-byte base64 payload digest, and what its sidecar declares; at most 128, unique names. The digest is the one the hook watcher last computed, which can differ from the executor's pin after an edit. A rolled-out hook's entry also carries `source` and `version` |
| `plexd_hooks` | No | `PlexdHook` resources in the ServiceAccount's namespace; at most 128, unique names. Absent outside Kubernetes, and absent from the first manifest when the boot list failed |
| `builtin_actions` | No | The builtin actions the agent implements, sorted by name; at most 128 actions, at most 64 parameters each |
| `hook_rollout_errors` | No | The published hook versions the last pull listed that plexd could not install, sorted by name; at most 64. Absent when there are none |

A `declared_hooks` entry carries `name` and `checksum`, and optionally what the
hook's sidecar declares: `description` (at most 4096 characters), `parameters`
(at most 64, each shaped like a `builtin_actions` parameter, with a `name` that is
non-empty after trimming and unique within the hook, and `name`, `type`, `default`
and `description` at most 4096 characters each), `timeout_seconds` (0 to 86400;
0 or absent means none declared) and `sandbox_level` (at most 64 characters,
free-form). Characters are Unicode code points, and a NUL in any of these strings
is refused. These fields describe the hook: they gate nothing at the control plane
and sit outside its digest. plexd applies the sidecar's `timeout` and `sandbox`,
which they report as `timeout_seconds` and `sandbox_level`, when it runs the hook.
A sidecar's content is readable by everyone who holds `read` at the
control plane, so it must hold no secret.

A hook plexd installed from a published version adds two members to its entry:
`source`, always `rollout`, and `version`, the version installed, 1 to
2147483647. The control plane then takes that version's published checksum as
the hook's baseline instead of the first digest the node reported. A hand-placed
hook's entry carries neither member; the contract reads an absent `source` as
`local`. A `hook_rollout_errors` entry carries the `name` and `version` the pull
listed, a `code` matching `^[a-z0-9_]{1,64}$` (plexd sends `collision`,
`verification_failed`, `fetch_failed` or `install_failed`), and an optional
`detail` of at most 1024 code points with no NUL. See
[Rolled-out Hooks](../actions/remote-actions-hooks.md#error-codes).

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
[PlexdHook CRD](../actions/plexdhook-crd.md#capability-manifest-reporting). Past
128 hooks of either kind, plexd keeps the first 128 by name and logs how many it
dropped. A sidecar field past its limit is left off with a warning, and the hook
stays; see
[Sidecar Metadata Format](../actions/remote-actions-hooks.md#sidecar-metadata-format).

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
| `400 Bad Request` | `declared_hook_invalid` | A declared hook has an empty name or a checksum that is not 32 bytes, its metadata breaks a limit, its `source` is neither `local` nor `rollout`, or its `version` is missing on a `rollout` entry, set on any other, or outside 1 to 2147483647 |
| `400 Bad Request` | `declared_hook_duplicate` | Two declared hooks share a name |
| `400 Bad Request` | `declared_hooks_too_many` | More than 128 declared hooks, or one hook with more than 64 parameters |
| `400 Bad Request` | `hook_rollout_errors_too_many` | More than 64 `hook_rollout_errors` entries |
| `400 Bad Request` | `hook_rollout_error_invalid` | A `hook_rollout_errors` entry breaks a limit |
| `401 Unauthorized` | `unauthorized`, `nsk_invalid`, `nsk_revoked` | NSK bearer credential missing, invalid, or revoked |
| `403 Forbidden` | `node_id_mismatch` | The NSK belongs to a different node than the path |
| `404 Not Found` | `capabilities_node_not_found` | No node row for the path |
| `413 Payload Too Large` | `capabilities_body_too_large` | Body exceeds 1 MiB, or 32 KiB on a control plane that predates hook metadata |
| `422 Unprocessable Entity` | `plexd_hook_invalid` | A `plexd_hooks` entry has an empty name, a non-canonical `image_digest`, or a negative `timeout_seconds` |
| `422 Unprocessable Entity` | `plexd_hook_duplicate` | Two `plexd_hooks` entries share a name |
| `422 Unprocessable Entity` | `plexd_hooks_too_many` | More than 128 `plexd_hooks` entries |
| `422 Unprocessable Entity` | `builtin_action_invalid` | An action has an empty name, or a parameter with an empty or repeated name |
| `422 Unprocessable Entity` | `builtin_action_duplicate` | Two actions share a name |
| `422 Unprocessable Entity` | `builtin_actions_too_many` | More than 128 actions, or one action with more than 64 parameters |
| `500 Internal Server Error` | `internal` | Server error |
| `501 Not Implemented` | `capabilities_not_provisioned` | The control plane has not wired its capability store yet |

plexd logs a failed report as a warning and retries it until one is accepted. The
delay starts at 5 seconds and doubles up to 5 minutes, with 25% jitter, and a
`429`'s longer `Retry-After`, in seconds, wins. A refusal is retried too: a refused PUT stores nothing
and raises nothing, and an upgraded control plane then clears the refusal with no
agent restart. plexd never drops the inventories to get a refused manifest
through. See [Retries](../actions/remote-actions-hooks.md#retries).

The one exception is hook metadata, which includes a rolled-out hook's `source`
and `version` and the `hook_rollout_errors` list. A manifest that carries it and
draws a `413`, or a `400` with `malformed_capabilities_request`,
`declared_hook_invalid`, `declared_hooks_too_many`,
`hook_rollout_errors_too_many`, or `hook_rollout_error_invalid`, takes no
backoff: it goes out again at once in a short form, each `declared_hooks` entry
holding `name` and `checksum` alone, with no `hook_rollout_errors`. A control
plane that predates the metadata answers that `400 malformed_capabilities_request`
for the unknown keys. plexd tries the wide form again when the built content
changes and otherwise about hourly, 45 to 75 minutes with jitter, and each hourly
attempt that is refused leaves one audit row at the control plane. See
[When Hook Metadata Is Refused](../actions/remote-actions-hooks.md#when-hook-metadata-is-refused).

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
node of the Domain except the peer, unless it equals the peer's `endpoint`, one
of its relays or one of its local candidates. The report carries no
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

## Ingress Status

### PUT /v1/nodes/{node_id}/ingress-status

Reports whether a bridge's local configuration serves public ingress, so the
control plane refuses an ingress rule that no listener would serve, and the
state of each ingress rule: its listener, its certificate and the last dial to
its target. While a bridge's report reads `opted_out`, the control plane
answers a create or an update of an ingress rule on its bridge Resource with
`409 bridge_ingress_opted_out`. It keeps the rules stored before the opt-out,
keeps delivering them in the [`bridge.ingress`](#get-v1-nodes-node-id-state)
block with `enabled: true`, and allows a delete. A bridge that never reported
reads `not_reported` and accepts rules. See
[Ingress Status Report](../bridge/public-ingress.md#ingress-status-report) for
how plexd derives the state and each entry.

**Request body** (`IngressStatusRequest`, at most 256 KiB):

```json
{
  "state": "enabled",
  "rules": [
    { "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f1", "listener": "listening",
      "certificate": "ready", "dial": "failed", "dial_reason": "policy_denied", "dial_age_seconds": 12 },
    { "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f4", "listener": "not_listening", "listener_reason": "listen_failed" }
  ]
}
```

- `state`: required, one of `enabled` and `opted_out`. `enabled` means the
  local configuration serves the rules the pull enables:
  [`bridge.ingress_enabled`](configuration.md#bridge) is absent or `true`.
  `opted_out` means `bridge.ingress_enabled: false`: the bridge opens no public
  listener whatever the pull says.
- `rules`: optional, at most 1,024 entries (`IngressStatusRule`), one per rule
  of the bridge's last applied block, in the order of the pull. An absent
  `rules`, a `null` and an empty array all mean no entries. An `opted_out`
  report carries none, and plexd omits the member when it has no entry.
  Each entry carries `id`, the rule's UUID, and `listener`, `listening` or
  `not_listening`; then `listener_reason` exactly when `listener` is
  `not_listening`, `certificate` (`not_required`, `ready` or `not_ready`) and
  `dial` (`none`, `succeeded` or `failed`) exactly when it is `listening`,
  `certificate_reason` exactly when `certificate` is `not_ready`,
  `dial_reason` exactly when `dial` is `failed`, and `dial_age_seconds`, the
  whole seconds from the dial to the report from 0 to 2147483647, exactly when
  `dial` is `succeeded` or `failed`. A reason is a token matching
  `^[a-z][a-z0-9_]{0,62}$`; the tokens plexd sends are listed in
  [Rule Entries](../bridge/public-ingress.md#rule-entries).

The control plane decodes the body with unknown members refused, of the report
and of each entry. A body that is not one JSON object, an unknown member, data
after the report, a missing or `null` `state`, a value outside the two states,
more than 1,024 entries, and an entry with a missing, malformed or zero `id`,
without `listener`, with a facet outside its values, a reason outside the
grammar or a `dial_age_seconds` outside its range each answer
`400 malformed_ingress_status`. An `opted_out` report with entries, an `id`
that repeats an earlier entry, and an entry that breaks the presence rules
above each answer `400 invalid_ingress_status`. The `detail` names the entry by
index, as `rules[3] misses certificate while listener is listening`, and never
repeats an `id` or a reason of the body; a missing or `null` `state` carries
`state is missing`, and another value
`state is not one of enabled and opted_out`. `ReportIngressStatus` validates
nothing, because the reporter builds only the shapes the contract admits: it
skips a rule whose `id` is no UUID in canonical form or repeats an earlier one.

**Response** (`200 OK`, `IngressStatusResponse`):

```json
{
  "accepted_at": "2026-11-16T10:15:30.123Z"
}
```

`accepted_at` is the server receive time. Every answer carries
`Cache-Control: no-store`.

**Cadence.** plexd reports from a loop of its own, started in bridge mode,
whether or not the bridge opts out. It sends the report once right after each
start, without waiting for the first state pull and so without entries; on
every change of an entry, at most once per 5 s; and once per
`heartbeat.interval` (default 30s). The state comes from the local
configuration, which plexd reads once per start, so the send after each start
is the report on every change of the setting that the contract asks for: a
changed `bridge.ingress_enabled` takes effect, and is reported, with the
restart. A change sends only when the entries differ from those of the last
accepted report; a moving `dial_age_seconds` alone sends nothing. A failed
report is not retried within its tick; the next tick, at most one interval
later, sends the report as it then is. plexd sends nothing at shutdown, and a
node outside bridge mode sends nothing at all. A bridge sends at most one
report per 5 s on change and one per interval, each under 250 bytes per entry.

**Sticky state, aging entries.** The control plane keeps the latest state per
node and never ages it, unlike the [relay status report](#relay-status), so a
bridge that reported `opted_out` and went offline stays opted out until it
reports `enabled`. Each report replaces the rule entries of the one before,
and a bridge that has not reported for three heartbeat intervals has its rules
read `stale`. A report that repeats the stored state changes nothing: the stored
receive time stays that of the report that last changed the state. The report
never gates serving: a bridge serves as the pull says while a report fails or
the control plane does not serve the operation.

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning | plexd behavior |
|---|---|---|---|
| `200 OK` | — | Report accepted; body is an `IngressStatusResponse` | Logged at Debug as `accepted` on every send; also at Info as `reported` for the first accepted send, and once at Info after a not-served phase |
| `400 Bad Request` | `malformed_ingress_status` | Body is not one JSON object, carries an unknown member or data after the report, misses `state` or sends it as `null` (`detail` `state is missing`), names a `state` outside the two (`detail` `state is not one of enabled and opted_out`), carries more than 1,024 entries, or an entry whose member breaks its own rule (`detail` such as `rules[0].listener is not one of listening and not_listening`). A control plane that predates `rules` answers it to every `enabled` report with entries | Logged at Warn as `send failed` on every send; the next tick sends the report again. plexd has no fallback for a control plane that predates `rules` |
| `400 Bad Request` | `invalid_ingress_status` | An `opted_out` report with entries, an `id` that repeats an earlier entry, or an entry that breaks the presence rules (`detail` such as `rules[1].id repeats rules[0].id`) | Logged at Warn as `send failed`; the next tick sends the report again |
| `401 Unauthorized` | `unauthorized`, `nsk_invalid`, `nsk_revoked` | NSK bearer credential missing, invalid, or revoked | Logged at Warn as `send failed`; the next tick sends the report again. Once the heartbeat has parked the agent on the refused credential, no request leaves and the failure is logged at Debug |
| `403 Forbidden` | `node_id_mismatch` | The NSK belongs to a different node than the path | Logged at Warn as `send failed`; the next tick sends the report again |
| `404 Not Found` | `ingress_status_node_gone` | The node was removed while the request ran | Logged at Warn as `rejected, this node was removed` on every send; plexd keeps reporting every interval |
| `404 Not Found` | any other, or none | An older control plane that does not serve the operation | Logged once at Info as not served; plexd keeps reporting every interval and keeps serving as the pull says |
| `413 Payload Too Large` | `ingress_status_body_too_large` | Body exceeds 256 KiB | Logged at Warn as `send failed`; the next tick sends the report again |
| `500 Internal Server Error` | `internal` | Server error, for example a failed write of the report | Logged at Warn as `send failed`; the next tick sends the report again |
| `501 Not Implemented` | `ingress_status_not_provisioned` | The control plane has not provisioned the operation: its recording service is not wired | Logged once at Info as not served; plexd keeps reporting every interval and keeps serving as the pull says |

`api.IsIngressStatusNotServed` classifies the two not-served answers: a `404`
with any code but `ingress_status_node_gone`, and a `501` carrying
`ingress_status_not_provisioned`. A `404 ingress_status_node_gone` is the
operation's own answer, a verdict on the node rather than a missing route, so
it is false. A `501` with any other code is an ordinary failure and logged at
Warn. No answer stops the reporter, and none touches the listeners.

## User Access Status

### PUT /v1/nodes/{node_id}/user-access-status

Reports whether a bridge's local configuration serves user access, so the
control plane refuses a provider or a device that no bridge would serve, and
whether each user access provider of the bridge's pull is up. The report is
also how the public key of a `wireguard` provider's interface reaches the
control plane, which a device's configuration names as its peer's key. While a
bridge's report reads `opted_out`, the control plane answers a create or an
update of a provider, and a device admission, on its bridge Resource with
`409 bridge_user_access_opted_out`. It keeps the providers and devices stored
before the opt-out, keeps delivering them in the
[`bridge.user_access`](#get-v1-nodes-node-id-state) block with
`enabled: true`, and allows a delete. A bridge that never reported reads
`not_reported` and accepts providers and devices. The control plane's side is
[plexsphere/plexsphere#1108](https://github.com/plexsphere/plexsphere/pull/1108).
See [User Access Status Report](../bridge/user-access-integration.md#user-access-status-report)
for how plexd derives the state and each entry.

**Request body** (`UserAccessStatusRequest`, at most 64 KiB):

```json
{
  "state": "enabled",
  "providers": [
    { "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1", "health": "up",
      "public_key": "hT2bUq7k3mS0eQ4vJ9xR1nC6pW8aL5dF2gH7jK0zY3M=", "connected_devices": 1 },
    { "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2", "health": "down", "reason": "auth_secret_not_listed" }
  ]
}
```

- `state`: required, one of `enabled` and `opted_out`. `enabled` means the
  local configuration serves the providers the pull enables:
  [`bridge.user_access_enabled`](configuration.md#bridge) is absent or `true`.
  `opted_out` means `bridge.user_access_enabled: false`: the bridge serves no
  provider whatever the pull says.
- `providers`: optional, at most 256 entries (`UserAccessStatusProvider`), one
  per provider of the bridge's last applied block, in the order of the pull.
  An absent `providers`, a `null` and an empty array all mean no entries. An
  `opted_out` report carries none, and plexd omits the member when it has no
  entry. Each entry carries `id`, the provider's UUID, and `health`, `up` or
  `down`; then `reason` exactly when `health` is `down`, and, only when it is
  `up`, `public_key`, the public key of a `wireguard` provider's interface in
  44 characters of standard base64, and `connected_devices`, the provider's
  devices whose latest WireGuard handshake is at most 180 seconds old, from 0
  to 1024. plexd sends both for a `wireguard` provider that is up and neither
  for a `tailscale` or `netbird` one. A reason is a token matching
  `^[a-z][a-z0-9_]{0,62}$`; the tokens plexd sends are listed in
  [Reasons](../bridge/user-access-integration.md#reasons).

The control plane decodes the body with unknown members refused, of the report
and of each entry. A body that is not one JSON object, an unknown member, data
after the report, a missing or `null` `state`, a value outside the two states,
more than 256 entries, and an entry with a missing, malformed or zero `id`,
without `health`, with a `health` outside its values, a reason outside the
grammar, a malformed `public_key`, a `connected_devices` outside its range, or
a member the presence rules above forbid or require each answer
`400 malformed_user_access_status`. An `opted_out` report with entries and an
`id` that repeats an earlier entry each answer
`400 invalid_user_access_status`. The `detail` names the entry by index, as
`providers[3].reason is required while health is down`, and never repeats a
value of the body. A member of an entry sent as `null` reads as omitted.
`ReportUserAccessStatus` validates nothing, because the reporter builds only
the shapes the contract admits: it reports no provider whose `id` is no UUID in
canonical form or repeats an earlier one.

**Response** (`200 OK`, `UserAccessStatusResponse`):

```json
{
  "accepted_at": "2026-11-18T10:15:30.123Z"
}
```

`accepted_at` is the server receive time. Every answer carries
`Cache-Control: no-store`.

**Cadence.** plexd reports from a loop of its own, started in bridge mode,
whether or not the bridge opts out. It sends the report once right after each
start, without waiting for the first state pull and so without entries; on
every change of an entry's `id`, `health`, `reason` or `public_key`, at most
once per 5 s; and once per `heartbeat.interval` (default 30s). A moving
`connected_devices` alone sends nothing; the next tick carries it. The state
comes from the local configuration, which plexd reads once per start, so a
changed `bridge.user_access_enabled` takes effect, and is reported, with the
restart. A failed report is not retried within its tick. plexd sends nothing
at shutdown, and a node outside bridge mode sends nothing at all.

**Sticky state, aging entries.** The control plane keeps the latest state per
node and never ages it, so a bridge that reported `opted_out` and went offline
stays opted out until it reports `enabled`. Each report replaces the provider
entries of the one before, and a bridge that has not reported for three
heartbeat intervals of its Domain, 90 seconds under the default policy, has its
providers read `stale`. Every report renews that window, a repeat that changes
nothing included, so the report once per interval is load-bearing. An entry
whose `id` is no provider of the bridge Resource is ignored. The report never
gates serving: a bridge serves as the pull says while a report fails or the
control plane does not serve the operation.

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning | plexd behavior |
|---|---|---|---|
| `200 OK` | — | Report accepted; body is a `UserAccessStatusResponse` | Logged at Debug as `accepted` on every send; also at Info as `reported` for the first accepted send, and once at Info after a not-served phase |
| `400 Bad Request` | `malformed_user_access_status` | Body is not one JSON object, carries an unknown member or data after the report, misses `state` or sends it as `null` (`detail` `state is missing`), names a `state` outside the two (`detail` `state is not one of enabled and opted_out`), carries more than 256 entries (`detail` `providers carries more than 256 entries`), or an entry that breaks a member rule or the presence rules (`detail` such as `providers[0].health is not one of up and down`) | Logged at Warn as `send failed` on every send; the next tick sends the report again |
| `400 Bad Request` | `invalid_user_access_status` | An `opted_out` report with entries (`detail` `an opted-out bridge reports no providers`) or an `id` that repeats an earlier entry (`detail` such as `providers[1].id repeats providers[0].id`) | Logged at Warn as `send failed`; the next tick sends the report again |
| `401 Unauthorized` | `unauthorized`, `nsk_invalid`, `nsk_revoked` | NSK bearer credential missing, invalid, or revoked | Logged at Warn as `send failed`; the next tick sends the report again. Once the heartbeat has parked the agent on the refused credential, no request leaves and the failure is logged at Debug |
| `403 Forbidden` | `node_id_mismatch` | The NSK belongs to a different node than the path | Logged at Warn as `send failed`; the next tick sends the report again |
| `404 Not Found` | `user_access_status_node_gone` | The node was removed while the request ran | Logged at Warn as `rejected, this node was removed` on every send; plexd keeps reporting every interval |
| `404 Not Found` | any other, or none | An older control plane that does not serve the operation | Logged once at Info as not served; plexd keeps reporting every interval and keeps serving as the pull says |
| `413 Payload Too Large` | `user_access_status_body_too_large` | Body exceeds 64 KiB | Logged at Warn as `send failed`; the next tick sends the report again |
| `500 Internal Server Error` | `internal` | Server error, for example a failed write of the report | Logged at Warn as `send failed`; the next tick sends the report again |
| `501 Not Implemented` | `user_access_status_not_provisioned` | The control plane has not provisioned the operation: its recording service is not wired | Logged once at Info as not served; plexd keeps reporting every interval and keeps serving as the pull says |

`api.IsUserAccessStatusNotServed` classifies the two not-served answers: a
`404` with any code but `user_access_status_node_gone`, and a `501` carrying
`user_access_status_not_provisioned`. A `404 user_access_status_node_gone` is
the operation's own answer, a verdict on the node rather than a missing route,
so it is false. A `501` with any other code is an ordinary failure and logged at
Warn. No answer stops the reporter, and none changes what the bridge serves.

## Site-to-Site Status

### PUT /v1/nodes/{node_id}/site-to-site-status

Reports whether a bridge's local configuration serves site-to-site tunnels, so
the control plane refuses a tunnel that no bridge would serve, and whether each
site-to-site tunnel of the bridge's pull is up and answered by its remote site.
The report is also how the public key of a `wireguard` tunnel's interface
reaches the control plane, which the remote site's configuration names as its
peer's key. While a bridge's report reads `opted_out`, the control plane answers
a create or an update of a tunnel on its bridge Resource with
`409 bridge_site_to_site_opted_out`. It keeps the tunnels stored before the
opt-out, keeps delivering them in the
[`bridge.site_to_site`](#get-v1-nodes-node-id-state) block with
`enabled: true`, and allows a delete. A bridge that never reported reads
`not_reported` and accepts tunnels. A report moves no other node's pull: the
`routed_subnets` of the bridge's peer entry follow the stored tunnels whatever
the bridge reports. The control plane's side is
[plexsphere/plexsphere#1109](https://github.com/plexsphere/plexsphere/pull/1109).
See [Site-to-Site VPN](../bridge/site-to-site-vpn.md) for how plexd derives the
state and each entry.

**Request body** (`SiteToSiteStatusRequest`, at most 64 KiB):

```json
{
  "state": "enabled",
  "tunnels": [
    { "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1", "health": "up",
      "public_key": "hT2bUq7k3mS0eQ4vJ9xR1nC6pW8aL5dF2gH7jK0zY3M=", "established": true },
    { "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2", "health": "down", "reason": "kind_not_served" }
  ]
}
```

- `state`: required, one of `enabled` and `opted_out`. `enabled` means the
  local configuration serves the tunnels the pull enables:
  [`bridge.site_to_site_enabled`](configuration.md#bridge) is absent or `true`.
  `opted_out` means `bridge.site_to_site_enabled: false`: the bridge serves no
  tunnel whatever the pull says.
- `tunnels`: optional, at most 256 entries (`SiteToSiteStatusTunnel`), one per
  tunnel of the bridge's last applied block, in the order of the pull. An
  absent `tunnels`, a `null` and an empty array all mean no entries. An
  `opted_out` report carries none, and plexd omits the member when it has no
  entry. Each entry carries `id`, the tunnel's UUID, and `health`, `up` or
  `down`; then `reason` exactly when `health` is `down`, `established` exactly
  when it is `up`, and, only when it is `up`, `public_key`, the public key of a
  `wireguard` tunnel's interface in 44 characters of standard base64. plexd
  sends `public_key` for a `wireguard` tunnel that is up and never for an
  `ipsec` or `openvpn` one. `established` is `true` when the remote site
  answers: for a `wireguard` tunnel the latest handshake with the remote peer
  is at most 180 seconds old, for an `ipsec` tunnel the IKE and child security
  associations stand, and for an `openvpn` tunnel the peer is connected. A
  reason is a token matching `^[a-z][a-z0-9_]{0,62}$`; the tokens plexd sends
  are listed on [Site-to-Site VPN](../bridge/site-to-site-vpn.md). Besides the
  contract's tokens, plexd sends `invalid_tunnel`, `setup_failed` and
  `key_unavailable`, which the control plane stores verbatim like any token of
  the grammar.

The control plane decodes the body with unknown members refused, of the report
and of each entry. A body that is not one JSON object, an unknown member, data
after the report, a missing or `null` `state`, a value outside the two states,
more than 256 entries, and an entry with a missing, malformed or zero `id`,
without `health`, with a `health` outside its values, a reason outside the
grammar, a malformed `public_key`, an `established` that is not a boolean, or a
member the presence rules above forbid or require each answer
`400 malformed_site_to_site_status`. An `opted_out` report with entries and an
`id` that repeats an earlier entry each answer
`400 invalid_site_to_site_status`. The `detail` names the entry by index, as
`tunnels[3].reason is required while health is down`, and never repeats a
value of the body. A member of an entry sent as `null` reads as omitted.
`ReportSiteToSiteStatus` validates nothing, because the reporter builds only
the shapes the contract admits: it reports no tunnel whose `id` is no UUID in
canonical form or repeats an earlier one.

**Response** (`200 OK`, `SiteToSiteStatusResponse`):

```json
{
  "accepted_at": "2026-11-18T10:15:30.123Z"
}
```

`accepted_at` is the server receive time. Every answer carries
`Cache-Control: no-store`.

**Cadence.** plexd reports from a loop of its own, started in bridge mode,
whether or not the bridge opts out. It sends the report once right after each
start, without waiting for the first state pull and so without entries; on
every change of an entry's `id`, `health`, `reason`, `public_key` or
`established`, at most once per 5 s; and once per `heartbeat.interval`
(default 30s). A change of `established` alone raises no signal of its own, so
it reaches the control plane with the next pull or the next tick, at most one
interval late. The state comes from the local configuration, which plexd reads
once per start, so a changed `bridge.site_to_site_enabled` takes effect, and is
reported, with the restart. A failed report is not retried within its tick.
plexd sends nothing at shutdown, and a node outside bridge mode sends nothing
at all.

**Sticky state, aging entries.** The control plane keeps the latest state per
node and never ages it, so a bridge that reported `opted_out` and went offline
stays opted out until it reports `enabled`. Each report replaces the tunnel
entries of the one before, and a bridge that has not reported for three
heartbeat intervals of its Domain, 90 seconds under the default policy, has its
tunnels read `stale`. Every report renews that window, a repeat that changes
nothing included, so the report once per interval is load-bearing. An entry
whose `id` is no tunnel of the bridge Resource is ignored. The control plane
derives each tunnel's state from the latest report: `established` while the
tunnel is up and its remote site answers, `connecting` while it is up and the
remote site does not answer, `down` with the reason, `stale`, `not_reported` or
`opted_out`. The report never gates serving: a bridge serves as the pull says
while a report fails or the control plane does not serve the operation.

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning | plexd behavior |
|---|---|---|---|
| `200 OK` | — | Report accepted; body is a `SiteToSiteStatusResponse` | Logged at Debug as `accepted` on every send; also at Info as `reported` for the first accepted send, and once at Info after a not-served phase |
| `400 Bad Request` | `malformed_site_to_site_status` | Body is not one JSON object, carries an unknown member or data after the report, misses `state` or sends it as `null` (`detail` `state is missing`), names a `state` outside the two (`detail` `state is not one of enabled and opted_out`), carries more than 256 entries (`detail` `tunnels carries more than 256 entries`), or an entry that breaks a member rule or the presence rules (`detail` such as `tunnels[0].established is required while health is up`) | Logged at Warn as `send failed` on every send; the next tick sends the report again |
| `400 Bad Request` | `invalid_site_to_site_status` | An `opted_out` report with entries (`detail` `an opted-out bridge reports no tunnels`) or an `id` that repeats an earlier entry (`detail` such as `tunnels[1].id repeats tunnels[0].id`) | Logged at Warn as `send failed`; the next tick sends the report again |
| `401 Unauthorized` | `unauthorized`, `nsk_invalid`, `nsk_revoked` | NSK bearer credential missing, invalid, or revoked | Logged at Warn as `send failed`; the next tick sends the report again. Once the heartbeat has parked the agent on the refused credential, no request leaves and the failure is logged at Debug |
| `403 Forbidden` | `node_id_mismatch` | The NSK belongs to a different node than the path | Logged at Warn as `send failed`; the next tick sends the report again |
| `404 Not Found` | `site_to_site_status_node_gone` | The node was removed while the request ran | Logged at Warn as `rejected, this node was removed` on every send; plexd keeps reporting every interval |
| `404 Not Found` | any other, or none | An older control plane that does not serve the operation | Logged once at Info as not served; plexd keeps reporting every interval and keeps serving as the pull says |
| `413 Payload Too Large` | `site_to_site_status_body_too_large` | Body exceeds 64 KiB | Logged at Warn as `send failed`; the next tick sends the report again |
| `500 Internal Server Error` | `internal` | Server error, for example a failed write of the report | Logged at Warn as `send failed`; the next tick sends the report again |
| `501 Not Implemented` | `site_to_site_status_not_provisioned` | The control plane has not provisioned the operation: its recording service is not wired | Logged once at Info as not served; plexd keeps reporting every interval and keeps serving as the pull says |

`api.IsSiteToSiteStatusNotServed` classifies the two not-served answers: a
`404` with any code but `site_to_site_status_node_gone`, and a `501` carrying
`site_to_site_status_not_provisioned`. A `404 site_to_site_status_node_gone`
is the operation's own answer, a verdict on the node rather than a missing
route, so it is false. A `501` with any other code is an ordinary failure and
logged at Warn. No answer stops the reporter, and none changes what the bridge
serves.

## Policy Status

### PUT /v1/nodes/{node_id}/policy-status

Reports what the node did with the policy block of its
[state pulls](#get-v1-nodes-node-id-state): whether it enforces, which ruleset
it applied, which ruleset its latest apply failed on and why, and how many
packets and bytes its default deny dropped. Without the report the control
plane cannot tell a ruleset the node applied from one it refused, because a
node that refuses a revision keeps its previous ruleset while the pull goes on
serving the new one. The control plane keeps the latest report per node and
derives the node's policy status from it. A report that changes what the node
applied, rejected or enforces also appends a policy transition to the log of
the node's Project. See
[Policy status report](../networking/network-policy.md#policy-status-report)
for how plexd builds and sends it.

**Request body** (`PolicyStatusRequest`, at most 1 MiB):

```json
{
  "enforcement": "enforcing",
  "applied": {
    "fingerprint": "j7Hn2mF0oQ9rXcV8yZ1aB4cD6eF8gH0iJ2kL4mN6oM0=",
    "revisions": [
      { "policy_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d1", "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1" },
      { "policy_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d2", "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c7" }
    ]
  },
  "rejected": {
    "fingerprint": "q7vZ4Zx0d8nU1m3oW5bJk2pQ9rT6yH4sL0aE8cV1fG4=",
    "revisions": [
      { "policy_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d1", "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c2" },
      { "policy_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d2", "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c7" }
    ],
    "reason": "policy: enforce: policy: invalid ruleset: policy: rule 0: unsupported action \"deny\""
  },
  "drops": { "packets": 5, "bytes": 500 }
}
```

A node that applied a pull with `policy: null` sends `applied` without a
fingerprint, and a node with enforcement off sends `enforcement` alone:

```json
{ "enforcement": "enforcing", "applied": { "revisions": [] }, "drops": { "packets": 0, "bytes": 0 } }
```

```json
{ "enforcement": "disabled" }
```

- `enforcement`: required, one of `enforcing`, `disabled` and `unavailable`.
  `enforcing` means plexd programs the rulesets it applies, with its default
  deny after them; `disabled`, that `policy.enabled` is `false`; and
  `unavailable`, that enforcement is on but the platform has no firewall
  backend.
- `applied`: the ruleset the node applied last, as the `fingerprint` and the
  `revisions` of the pull's `policy` block, echoed byte for byte. `revisions` is
  required and holds at most 4096 pairs. `fingerprint` is absent, and
  `revisions` is `[]`, when the pull the node applied carried `policy: null`.
  `applied` is absent while the node has applied no pull's block since plexd
  started; plexd also leaves it out for an applied block without a fingerprint,
  which it cannot echo.
- `rejected`: the ruleset the node's latest apply failed on, as its
  `fingerprint` and `revisions`, and `reason`, all required. `reason` is
  plexd's error text, 1 to 1024 bytes of UTF-8 without control characters.
  plexd reports a ruleset its engine cannot translate and a failure of its
  firewall backend alike. Absent when the latest apply did not fail.
- `drops`: `packets` and `bytes`, both required integers of at least 0, that
  the node's default deny dropped since plexd last installed the ruleset. A
  counter below its previous value tells the control plane that the count
  restarted. Linux and macOS send it; Windows does not, because WFP keeps no
  per-filter counters. Absent too while nothing is installed.

Each pair of `revisions` is `{policy_id, revision_id}`, in strictly ascending
`policy_id`, as the pull lists them. plexd echoes the ids as strings and never
parses them.

The control plane decodes the body with unknown members refused. A member of
the wrong JSON type, an unknown member or data after the report answers
`400 malformed_policy_status`; a missing or `null` required member and a value
that breaks a rule answer `400 invalid_policy_status`, with a `detail` naming
the member. `ReportPolicyStatus` sends a nil `revisions` as `[]`, on a copy,
and validates nothing else, because plexd builds only the shapes the contract
admits.

**Response** (`200 OK`, `PolicyStatusResponse`):

```json
{
  "accepted_at": "2026-11-13T10:15:30.123Z",
  "status": "rejected"
}
```

`accepted_at` is the server receive time the report is stored with. `status`
is the policy status the report derives against the ruleset the pull serves at
that moment, by the first matching condition:

| Condition | `status` |
|---|---|
| `enforcement` is not `enforcing` | `not_enforced` |
| `rejected` is present, the pull serves a `policy` block, and the rejected `fingerprint` equals the served one | `rejected` |
| `applied` is present and its `fingerprint` equals the served one; an `applied` without a fingerprint equals a pull that still carries `policy: null` | `applied` |
| Otherwise: the node has not yet reported the ruleset the pull serves | `pending` |

plexd logs `status` with each accepted report and acts on none of it.

**Cadence.** plexd reports from a loop of its own, never from inside the
reconcile cycle, so a slow control plane never delays a pull. It sends a report
on every change of what the node applied, rejected or enforces. On a tick of
`heartbeat.interval` (default 30s) it sends only when the drop counters moved
since the report the control plane accepted last, or when the last send
failed. A quiet node sends nothing, so the age of its last report is no
liveness signal. plexd sends one report at a time, nothing before its first
state pull, and nothing at shutdown: the contract defines no shutdown report,
and the control plane keeps the last one.

**Fresh state.** Every attempt builds the body from the node's current record
and counters, so a send after a failure carries the latest state, not the one
that failed. `ReportPolicyStatus` has no internal retry, and Go's HTTP
transport does not replay a `PUT`.

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable `code`:

| Status | Problem `code` | Meaning | plexd behavior |
|---|---|---|---|
| `200 OK` | — | Report stored; body is a `PolicyStatusResponse` | Logged as `policy status: reported` at Info when what the node applied, rejected or enforces changed, at Debug when only the counters did; once at Info after a not-provisioned phase, that the control plane accepts reports |
| `400 Bad Request` | `malformed_policy_status` | The body is empty, is not one JSON object, carries a member of the wrong JSON type (a `policy_id` or `revision_id` that is not a UUID string, or a drop counter above the int64 range, included), an unknown member, or data after the report | Logged at Warn as `send failed`; the next tick sends again |
| `400 Bad Request` | `invalid_policy_status` | A required member is missing or `null`; `enforcement` is outside the three values; a `fingerprint` is not standard base64 of 32 bytes; a drop counter is negative; a `policy_id` or `revision_id` is zero; `revisions` are not strictly ascending by `policy_id` or hold more than 4096 pairs; or `reason` is empty, longer than 1024 bytes, not valid UTF-8, or carries a control character. The `detail` names the member | Logged at Warn as `send failed`; the next tick sends again |
| `401 Unauthorized` | `unauthorized`, `nsk_invalid`, `nsk_revoked` | NSK bearer credential missing, invalid, or revoked | Logged at Warn as `send failed`; the next tick sends again. Once the heartbeat has parked the agent on the refused credential, no request leaves and the failure is logged at Debug |
| `403 Forbidden` | `node_id_mismatch` | The NSK belongs to a different node than the path | Logged at Warn as `send failed`; the next tick sends again |
| `404 Not Found` | `policy_status_node_gone` | The node was removed while the report was in flight | Logged at Warn as `rejected, this node was removed` on every send; the next tick sends again |
| `404 Not Found` | any other, or none | A control plane that predates the report | Logged once at Info as not accepting reports; plexd sends no further report until it restarts, as the contract asks |
| `413 Payload Too Large` | `policy_status_body_too_large` | Body exceeds 1 MiB | Logged at Warn as `send failed`; the next tick sends again |
| `500 Internal Server Error` | `internal` | The report could not be recorded | Logged at Warn as `send failed`; the next tick sends again |
| `501 Not Implemented` | `policy_status_not_provisioned` | The control plane serves the operation, but its recording service is not wired | Logged once at Info as not provisioned; plexd sends again on every tick |
| `503 Service Unavailable` | `datastore_unavailable` | The control plane could not reach the store that holds the NSK; the answer carries `Retry-After` | Logged at Warn as `send failed`; the next tick sends again |

`api.IsPolicyStatusNotServed` classifies the `404` of a control plane without
the route: any code but `policy_status_node_gone`. Unlike the not-served
answers of the relay status report, that answer stops the reporter until plexd
restarts, as the contract asks.
`api.IsPolicyStatusNotProvisioned` classifies the `501` carrying
`policy_status_not_provisioned`, which does not stop it. A `501` with any other
code is an ordinary failure and logged at Warn.

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
      "fallback_endpoint": "203.0.113.2:51820",
      "fallback_endpoints": ["203.0.113.2:51820", "203.0.113.3:51820"],
      "endpoint_candidates": ["192.0.2.10:51820"],
      "routed_subnets": ["10.50.0.0/16"]
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
    "fingerprint": "j7Hn2mF0oQ9rXcV8yZ1aB4cD6eF8gH0iJ2kL4mN6oM0=",
    "rules": [
      { "protocol": "any", "source_cidr": "10.99.0.0/24", "destination_cidr": "10.99.0.0/24" },
      { "protocol": "tcp", "source_cidr": "10.99.0.0/24", "destination_cidr": "0.0.0.0/0", "ports": { "from": 443, "to": 443 }, "log": true },
      { "protocol": "tcp", "source_cidr": "fd00:99::/64", "destination_cidr": "fd00:99::/64", "ports": { "from": 443, "to": 443 } }
    ],
    "revisions": [
      { "policy_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d1", "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1" },
      { "policy_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d2", "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c7" }
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
  },
  "hooks": [
    { "name": "backup-db", "version": 2, "checksum": "REA9yHQRkMbFu76wJTDLSMvpMnUd9WeDatQzSknU1Qg=" },
    { "name": "rotate-logs", "version": 1, "checksum": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" }
  ],
  "dns": {
    "search_domain": "openstack.lab.internal",
    "zones": ["lab.internal", "openstack.lab.internal"],
    "hosts": [
      { "node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1", "fqdn": "db-1.openstack.lab.internal", "mesh_ip": "10.99.0.2" },
      { "node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2", "fqdn": "db-2.openstack.lab.internal", "mesh_ip": "10.99.0.3" },
      { "node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3", "fqdn": "web-1.openstack.lab.internal", "mesh_ip": "10.99.0.1" }
    ],
    "records": [
      { "fqdn": "_postgres._tcp.openstack.lab.internal", "type": "SRV", "target": "db.lab.internal", "priority": 0, "weight": 5, "port": 5432 },
      { "fqdn": "db.lab.internal", "type": "A", "address": "10.20.0.5" }
    ],
    "reverse_zones": ["0.99.10.in-addr.arpa"],
    "forwarding": {
      "forward_zones": [
        { "zone": "2.0.192.in-addr.arpa", "resolvers": ["10.1.2.3"] },
        { "zone": "corp.example.com", "resolvers": ["10.1.2.3", "10.1.2.4"] },
        { "zone": "corp.local", "resolvers": ["10.1.2.5"] }
      ],
      "catch_all": ["10.1.2.53"]
    }
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
endpoint TTL. A handshake at one of the peer's relays (see `fallback_endpoints`
below) never counts. The control plane leaves one out when it equals the peer's
`endpoint`, one of its relays, one of its local candidates or an earlier entry, or when it
has port 0, a zone, or a loopback, link-local, multicast or unspecified address.
The peer's last accepted, unexpired local candidates from
[`PUT /v1/nodes/{node_id}/endpoint-candidates`](#put-v1-nodes-node-id-endpoint-candidates)
follow, in the order the peer sent them. The list holds at most 8 entries: when
both together exceed 8, the control plane drops the trailing local candidates.
Only nodes of the peer's Domain receive them. The member is absent when no entry
remains, and on every control plane that does not deliver it. A control plane
older than peer-observed endpoints lists only the local candidates.

A peer's `fallback_endpoints` lists the peer's relays as `host:port` strings
(an IPv6 host in brackets), in dial order, at most 4. The first is the relay of
the peer's assigned bridge. The standby relays follow it, in the order the
control plane ranks them. `fallback_endpoint` is always the list's first entry,
and the only relay a control plane older than the list sends. Both nodes of a
pair receive the same list for each other, and the list never names this node.
When this node is the peer's assigned bridge, the list starts with the peer's
first standby relay.
Both members are absent when the list is empty. plexd takes a peer's relay set
from `fallback_endpoints` when the list holds an entry, and then ignores
`fallback_endpoint` without checking that the two agree. Otherwise the set is
`fallback_endpoint` alone, or empty. A `null` list reads as an absent one, and
a value that is not an array of strings fails the pull's decode. plexd does not
validate the entries, since the contract allows a hostname there, and does not
cap their number. It skips an empty or repeated entry. A change of the list,
its order included, is enough for the differ to update the peer, so a pull that
only changes a standby reaches the WireGuard handler.

A peer's `routed_subnets` lists, as CIDRs, the networks behind the site-to-site
tunnels of the peer's bridge Resource: the union of their `allowed_subnets`,
each prefix once, sorted by address and then by prefix length. Only the nodes
whose Resource belongs to the bridge Resource's Project receive it. The member
is absent when the list would be empty, follows the stored tunnels whatever the
bridge reports about them, and is never carried by the registration response,
so a node programs it from its first pull. plexd adds the entries it accepts to
the peer's allowed IPs, after the mesh address, and routes them through the
mesh interface; it removes both when a pull no longer lists them. It skips an
entry that is no IPv4 prefix or has host bits set, one that overlaps the Domain
mesh prefix, one inside a network of one of the host's interfaces and one that
repeats an earlier entry, each with a Warn. A route admits no traffic by
itself: a Policy rule whose `destination_cidr` lies inside the network does.
A change of the list, its order included, is enough for the differ to update
the peer. See [Routed subnets](../networking/wireguard.md#routed-subnets).

The pull carries no PSK: plexd fetches the pairwise PSK of each edge from
[`GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk`](#edge-psk).

plexd tries a peer's endpoints in a fixed dial order and keeps the first one
that completes a WireGuard handshake: the candidates on a subnet this node is
also on, then `endpoint` when it is usable, then the remaining candidates, then
the peer's relays in the order of its set. A candidate or `endpoint` equal to a
relay is left out, so the relays always end the order whole and in set order,
the same on both sides of a pair. A direct endpoint or candidate is usable
when it parses as an IP address and a non-zero port, carries no IPv6 zone,
names an address that is not unspecified, loopback, multicast or link-local (an
IPv4-mapped IPv6 address is unmapped first), and lies outside the Domain mesh
prefix (the node's own mesh IP as a host /32 when registration returned no
usable `domain_mesh_cidr`). plexd leaves a refused one out of the order, and
logs a refused `endpoint` at Warn and refused candidates at Debug.
A change of `endpoint`, `fallback_endpoint` or `endpoint_candidates`,
the candidates' order included, is enough for the differ to update the peer.
plexd tries each entry for one trial, the WireGuard keepalive plus 5 s, and
holds every relay longer: it tries each relay, the first and each standby, as
long as the entries before the first relay took together. Two nodes behind hard
NATs are then on the first relay at the same time. When the order starts with
the relays, each relay gets one trial. With the default keepalive, a peer with
nine entries before its first relay reaches that relay after about 270 s, stays
on it for about 270 s, and starts over after about 540 s. Only a relayed peer,
one last seen connected over one of its relays, dials the standbys. Any other
peer walks its order only up to and including the first relay.

plexd never switches a peer connected on a direct path. A peer that runs over a
relay and received nothing for one trial gets a probe through the tunnel.
plexd dials the next relay of a relayed peer's set, on a fresh WireGuard
session, when nothing comes back from the probe within 15 s, when the handshake
goes stale, or when a relay's hold passes without a handshake. The next relay
after the last is the first, and for a set of one it is the same relay again.
Both sides of a pair hold the same set and detect a dead relay in the same
window, so they reach the same standby without a pull. On a pull, a peer that
dials a relay and is relayed or not connected moves at once to the pull's first
relay, on a fresh WireGuard session, when the pull names relays but no longer
its relay, or names a new first relay that is not its relay. Otherwise, a relayed
peer whose relay the pull still names keeps it, connected or not, a standby it
moved to on its own included: a pull that still names the dead first relay
first does not move it back. A pull never moves a peer connected over a direct
path WireGuard roamed to; plexd tells that path from the device's endpoint,
which it can compare only with a relay that is an address. Any other peer that
is not connected starts its walk over when a pull changes it, even when the
pull only changes a standby. A relayed peer tries its direct entries again only
when the pull drops every relay or the peer, its key rotates, plexd restarts,
or WireGuard roamed it to a direct path that then failed. A plexd that predates
`fallback_endpoints` dials only `fallback_endpoint`, and dials it again when it
fails, so a pair with one such side fails over only when the control plane
names a new first relay.
See [Dial order](../networking/wireguard.md#dial-order),
[Endpoint selection](../networking/wireguard.md#endpoint-selection) and
[Relay liveness probe](../networking/wireguard.md#relay-liveness-probe).

`bridge.relay` asks a bridge to relay WireGuard for the pairs that hold it
among their relays. A bridge listens only when both its local
[`bridge.relay_enabled`](configuration.md#bridge) is true and the block carries
`enabled: true`. It then binds UDP `listen_port`, which is authoritative, and
forwards among the peers of the same pull's `peers` block, routing each
datagram by its WireGuard header. A standby relay therefore carries a pair
without holding its assignment. Without local consent a bridge logs a Warn and
opens no socket. A `null` block, or `enabled: false`, stops a running relay.
`assignments` lists the peers whose first relay is this bridge, each as
`peer_node_id` with the `fallback_endpoint` host and `fallback_endpoint_port`
it dials. A peer that holds this bridge only as a standby relay is not listed.
plexd decodes and carries the list, and the relay does not read it. A change of `enabled`, `listen_port` or an assignment is bridge
drift. A node outside bridge mode ignores the block. See
[NAT Relay](../bridge/nat-relay.md).

`bridge.user_access` lists the user access providers of the bridge Resource,
by `slug` ascending, and carries `enabled`, the control plane's switch, which
it sends as `true` on every block. A bridge serves the providers when `enabled`
is true and its local configuration does not opt out with
[`bridge.user_access_enabled: false`](configuration.md#bridge), and reports
each provider's state with the
[user access status report](#user-access-status). Each provider carries `id`,
`slug` and `kind` (`wireguard`, `tailscale` or `netbird`). A `wireguard`
provider also carries `listen_port`, `address_pool`, `max_devices` and
`devices`, each device with `id`, `slug`, `public_key` and `address`; the
bridge serves it on a WireGuard interface of its own with each device as a
peer. A `tailscale` or `netbird` provider carries `auth_secret_name`, the
Secret of the bridge's Project that holds its join key, which the bridge
fetches in the version the `secrets` block lists. For every kind the bridge
forwards into the mesh with the source rewritten to its mesh address. The
block is whole, so a provider missing from a later pull is torn down, and a
`null` block serves no provider. The control plane delivers the block in this
shape since
[plexsphere/plexsphere#1108](https://github.com/plexsphere/plexsphere/pull/1108).
A node outside bridge mode ignores the block. See
[User Access Integration](../bridge/user-access-integration.md).

`bridge.ingress` lists the public ingress rules of the bridge Resource, by
`slug` ascending, and carries `enabled`, the control plane's switch, which it
sends as `true` on every block. A bridge serves the rules when `enabled` is
true and its local configuration does not opt out with
[`bridge.ingress_enabled: false`](configuration.md#bridge). A block whose
`enabled` is false or absent opens no public listener, and a bridge that opts
out opens none whatever the block says and reports `opted_out` with the
[ingress status report](#ingress-status). Each rule carries
`id`, `slug`, `protocol` (`tcp` or `udp`; a rule without it is a `tcp` rule),
`listen_port`, `mode` (`passthrough`, `terminate` or `acme`), an optional
`sni_host`, `target_node_id`, `target_address` and `target_port`, and a
`terminate` rule also `certificate_secret_name`, the Secret of the bridge's
Project that holds its certificate chain and key. A `terminate` or `acme` rule
may carry `conditions`, an optional `path_prefix` and at most 8 `headers` of a
`name` and a `value`, and, with a path prefix other than `/`,
`strip_path_prefix`; both members are absent on a rule without them. The
block's `acme` member, present exactly when a rule has mode `acme`, carries the
`directory_url` and the
optional `contact_email` of the ACME account the `acme` rules share. The
bridge opens one TCP listener per distinct `listen_port` of the `tcp` rules,
forwards a port whose rule names no `sni_host` without reading the stream, and
routes a port whose rules name hosts by the server name of each connection's
TLS ClientHello to
`target_address:target_port`. A `passthrough` rule forwards the TLS session
unchanged. A `terminate` rule ends TLS with the certificate of its Secret, which
the bridge fetches in the version the `secrets` block lists, and an `acme` rule
with a certificate the bridge obtains at `directory_url`; both forward
plaintext to the target. Rules with `conditions` share one `listen_port` and
`sni_host`: the bridge reads each request of such a host and forwards it over
HTTP/1.1 to the target of the rule whose conditions it matches (see
[Routing a Request](../bridge/public-ingress.md#routing-a-request)). A `udp`
rule is a `passthrough` rule without `sni_host`: the bridge opens one UDP socket on its `listen_port`, which may be
the port number of a `tcp` rule, and forwards the datagrams of each client
address and port on a flow of their own to the target (see
[Forwarding Datagrams](../bridge/public-ingress.md#forwarding-datagrams)).
The block is whole,
so a rule missing from a later pull is removed, and a `null` block closes every
public listener. A failed bind fails the reconcile cycle, and the next pull
retries it. A node outside bridge mode ignores the block. See
[Public Ingress](../bridge/public-ingress.md).

`bridge.site_to_site` lists the site-to-site tunnels of the bridge Resource,
by `slug` ascending, and carries `enabled`, the control plane's switch, which
it sends as `true` on every block; a bridge without tunnels gets no block. A
bridge serves the tunnels when `enabled` is true and its local configuration
does not opt out with
[`bridge.site_to_site_enabled: false`](configuration.md#bridge), and reports
each tunnel's state with the
[site-to-site status report](#site-to-site-status). Each tunnel carries `id`,
`slug`, `kind` (`wireguard`, `ipsec` or `openvpn`), `remote_host`, the remote
site's host name or IP address, `remote_port` and `allowed_subnets`, the 1 to
64 networks behind the remote site. A `wireguard` tunnel also carries
`listen_port`, `remote_public_key` and an optional `auth_secret_name`, the
Secret that holds its preshared key; the bridge serves it on a WireGuard
interface of its own with the remote site as its one peer and a private key it
keeps across restarts. An `ipsec` tunnel carries `auth_secret_name`, the Secret
that holds its IKE pre-shared key, and an `openvpn` tunnel the one that holds
its static key; the bridge hands either to the host's strongSwan or to an
`openvpn` process it starts. The bridge fetches a Secret in the version the
`secrets` block lists. For every kind the bridge routes `allowed_subnets` into
the tunnel and forwards what arrives from the tunnel into the mesh with the
source rewritten to its mesh address. Only a Linux bridge serves tunnels; on
macOS and Windows every tunnel that passes its checks reads `kind_not_served`.
The block is whole, so a tunnel missing from a later pull is torn down, and a
`null` block serves no tunnel. The control plane delivers the block in this
shape since
[plexsphere/plexsphere#1109](https://github.com/plexsphere/plexsphere/pull/1109).
A node outside bridge mode ignores the block. See
[Site-to-Site VPN](../bridge/site-to-site-vpn.md) and
[Tunnel Providers](../bridge/tunnel-providers.md).

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

`policy` is the node's merged network policy. Every rule allows the traffic
from `source_cidr` to `destination_cidr` that its `protocol` (`tcp`, `udp`,
`icmp` or `any`) and its optional `ports` range match, and rule order carries
no meaning. Both prefixes are IPv4 or both IPv6, `0.0.0.0/0` is every IPv4
address and `::/0` every IPv6 address, and `icmp` in an IPv6 rule is ICMPv6.
`log: true` asks for the rule's traffic to be logged: plexd writes the line
`policy rule allowed connection` to its own log for each connection such a
rule allows, naming the block's `revision_id` and the rule's index in `rules`,
and log forwarding carries the line to the control plane (see
[Connection logging](../networking/network-policy.md#connection-logging)).
plexd ends the ruleset with a default deny for both families, also when the
block is `null`. A rule
that still carries the `action` key of the format before
plexsphere/plexsphere#1058 is read as an allow when the value is `allow`. Any
other value, or any rule plexd cannot translate, rejects the whole revision:
the node keeps the ruleset it enforces, reports the revision as `rejected` in
its [policy status report](#policy-status), and applies it again on every pull.
plexd compares `fingerprint` byte for byte with the installed ruleset's on every
pull and never re-derives it from the rules: a block with the installed
fingerprint is not applied again. See
[Network Policy Enforcement](../networking/network-policy.md#buildfirewallrules).

`revisions` names every compiled row the block merges, one
`{policy_id, revision_id}` pair per row, in ascending `policy_id`, the order the
`fingerprint` covers. The first pair's `revision_id` equals the block's
`revision_id`. A control plane before plexsphere/plexsphere#1059 sends none.
plexd echoes the pairs of the block it applied or rejected in its
[policy status report](#policy-status) and never parses the ids.

`executions` is the delivery channel for action dispatches, and the only block
that is a delivery queue rather than desired state. It is always an array — `[]` when empty, never `null` —
ordered by `requested_at`, then `execution_id`. An entry keeps reappearing on
every pull until its execution reaches a terminal status through the
[execution callback](#action-execution-callbacks), so a consumer
must tolerate re-observing the same `execution_id`. `expires_at` is an absolute
UTC deadline, not a relative timeout; the entry carries no callback URL and no
hook checksum. A `started` entry may carry `cancel_requested_at` once an operator
cancelled its Execution; a cancel moves a `pending` or `ack` target to
`cancelled` at once, and that entry leaves the block. plexd reads the field on
its next pull and stops a run it holds: a killed hook, or a built-in that reports
the stop, is reported `cancelled`, and a run that finished first or does not
watch its context reports its real outcome. A `started` entry this process does not run is
still reported lost with `failed`, and a `pending` or `ack` entry carrying the
field is never started. See [Remote Actions and Hooks](/reference/actions/remote-actions-hooks)
for how plexd consumes it, and [Cancel](/reference/actions/remote-actions-hooks#cancel)
for what a cancelled run reports.

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

`hooks` lists the published hook versions the node should run, as the
"Published hooks" section of plexsphere's agent contract
(`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere)
describes it: one entry per version a rollout assigns the node, with its `name`,
its `version` and the `checksum` of its script, never the script itself. A
`name` matches `^[a-z0-9][a-z0-9_-]{0,62}$`, a `version` is at least 1, and the
`checksum` is the SHA-256 of the script as 32 bytes of standard-padded base64.
Entries are ordered by `name` ascending. The block is the node's full desired
set, not a delta: plexd removes a hook it rolled out whose name the block no
longer lists, and `[]` removes every one. `null` means the control plane could
not compute the set; plexd then keeps every hook it installed, as it does when a
control plane older than the block leaves it out. plexd reads the block on every
successful pull, drift or not, hands it to the rollout installer, and fetches
each listed version it has not installed from
[`GET /v1/nodes/{node_id}/hooks/{name}/versions/{version}`](#get-v1-nodes-node-id-hooks-name-versions-version).
No event announces a change, so a new rollout reaches the node within one
reconcile interval, or sooner on a triggered pull. The block is not desired state
for the differ: the reconcile snapshot neither stores nor compares it. See
[Rolled-out Hooks](../actions/remote-actions-hooks.md#rolled-out-hooks).

`dns` carries the mesh DNS names and records of the node's Domain, and the
node's DNS forwarding setting, as the
"Mesh DNS names" section of plexsphere's agent contract
(`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere)
describes it. `search_domain` is the zone of the node's own Project. `zones`
lists the Domain's default domain and every Project zone, ascending. `hosts`
lists every node of the Domain, the pulling node included, each with its
`node_id`, its `fqdn` and its `mesh_ip`, ordered by `fqdn`. `records` lists
the DNS records of the Domain and of every Project, ordered by `fqdn`, then by
`type`. Each carries its `fqdn`, its `type`, one of `A`, `AAAA`, `CNAME`, `TXT`,
`SRV` and `MX`, and the members of that type: `address` for `A` and `AAAA`,
`target` for `CNAME`, `SRV` and `MX`, `priority` for `SRV` and `MX`, `weight`
and `port` for `SRV`, and `text` for `TXT`. A member the type does not take is
absent, and a `priority` or `weight` of 0 is sent as `0`. A `records` key that
is `null` or missing means the Domain has no records. `reverse_zones` lists the
`in-addr.arpa` or `ip6.arpa` zones that cover the Domain's mesh CIDR and
nothing wider. `forwarding` carries the DNS forwarding setting that applies to
the node: its Project's when the Project holds one, otherwise its Domain's,
otherwise two empty lists. `forward_zones` lists zones outside the mesh,
ascending, each with 1 to 3 `resolvers`, and `catch_all` lists 0 to 3
resolvers, which answer every name outside the mesh zones, the reverse zones
and the forward zones. A resolver is an IPv4 or IPv6 address, asked in list
order on port 53 over plain DNS. Every name is in lower case without a trailing
dot, and an empty list is `[]`. The block is the full set, not a delta: it
replaces the names and the records the node answers, and its `forwarding`
replaces the forwarding. `null`, or a key missing because the control plane
predates the block, means the control plane did not say, and plexd keeps the
names, the records and the forwarding it holds. A `forwarding` member that is
`null` or missing in a block keeps the forwarding alone, and two empty lists
end it. On Linux, macOS and Windows, a plexd whose mesh resolver
listens reads the block on every successful pull, drift or not. The resolver
answers `A`, `AAAA` and `PTR` queries for the names, and queries for the
records of all six types, on
the node's own mesh IP, port 5354 by default (on macOS on `127.0.0.1`, and on
Windows on `127.0.0.1`, port 53), and
plexd registers the zones and the search domain with systemd-resolved on the
mesh interface. The resolver
forwards a query for a name under a forward zone to the zone's resolvers, and
with a catch-all a query for any other name outside the mesh zones to the
catch-all resolvers, and relays the reply without caching it. plexd registers
the forward zones with systemd-resolved beside the mesh zones, and with a
catch-all it makes the mesh interface the host's default DNS route. On macOS
plexd writes the same zones, the search domain and the forward zones into
configd's dynamic store instead, and with a catch-all a default-resolver entry
(see [Registration on macOS](../networking/mesh-dns.md#registration-on-macos)).
On Windows plexd writes them as rules of the Name Resolution Policy Table,
from which the DNS Client (`Dnscache`) takes the server for those names, with
the search domain also on the mesh adapter's search list, and with a catch-all a
rule for every name
(see [Registration on Windows](../networking/mesh-dns.md#registration-on-windows)).
A forward zone that equals a zone or reverse zone of the block, or lies
under one, is skipped, so the mesh names always win. The resolver
follows a CNAME while its target lies under one of `zones` or `reverse_zones`,
and answers one whose target lies outside them with the CNAME alone, which
systemd-resolved follows. An answer too large for UDP is sent with TC set and
no records, so the client asks again over TCP. A pull that changes only hosts,
records or resolvers issues no call to
the system resolver, as long as the accepted forward zones stay the same
and an accepted catch-all resolver neither appears nor goes. plexd skips an
entry that breaks a rule of the contract, such as a zone under `arpa`, `local`
or `localhost`, a record of a type it does not answer, or a loopback resolver,
and logs `mesh dns skipped invalid entries` at Warn. The block is
not desired state for the differ: the reconcile snapshot neither stores nor
compares it. See [Mesh DNS](../networking/mesh-dns.md).

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

## Published Hooks

### GET /v1/nodes/{node_id}/hooks/{name}/versions/{version} {#get-v1-nodes-node-id-hooks-name-versions-version}

Returns one published hook version, signed, with its script. plexd calls it from
the rollout installer for each version the [`hooks` block](#get-v1-nodes-node-id-state)
of the state pull lists and it has not installed, one fetch at a time, each under
a 30-second deadline. The request has no body.

`api.ControlPlane.FetchHookVersion(ctx, nodeID, name, version)` checks the name
against the grammar `^[a-z0-9][a-z0-9_-]{0,62}$` **before any request is sent**
and returns an error wrapping `api.ErrHookNameInvalid` for a name outside it. A
version below 1 returns
`api: fetch hook version "<name>": version must be >= 1, got <n>`, also without
a request. The grammar forbids every character a path escape would touch, so the
name goes into the path as it is.

**Response** (`200 OK`), a `NodeHookVersion`:

```json
{
  "envelope": {
    "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f1",
    "type": "hook_version",
    "scope": "domain:0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1",
    "key_id": "signing-domain-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1-1767225600000000000",
    "issued_at": "2026-05-02T10:00:00Z",
    "payload": {
      "project_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1",
      "name": "backup-db",
      "version": 1,
      "checksum": "REA9yHQRkMbFu76wJTDLSMvpMnUd9WeDatQzSknU1Qg=",
      "description": "Dump the application database to /var/backups.",
      "parameters": [
        { "name": "database", "type": "string", "description": "Database to dump." }
      ],
      "timeout_seconds": 600,
      "sandbox_level": "none"
    },
    "signature": "…"
  },
  "script_base64": "IyEvYmluL3NoCnBnX2R1bXAgLUZjIGFwcCA+IC92YXIvYmFja3Vwcy9hcHAuZHVtcAo="
}
```

The envelope has the members of a [signed event envelope](event-verification.md#envelope),
with `type` `hook_version`, `id` the version id, `scope` the Domain of the hook's
Project, and `issued_at` the instant the version was signed. Its payload is a
`HookVersionPayload`: `project_id`, `name`, `version`, `checksum` in the encoding
of the pull entry's, and `sandbox_level`, always, and `description`,
`parameters` and `timeout_seconds` only when the version declares them. The
script sits outside the envelope, so the signature covers its checksum rather
than its bytes. See [API Types](api-types.md#published-hooks).

The body, decompressed first when the response is gzip-encoded, is capped at
4 MiB: a larger body returns
`api: hook version response exceeds the 4 MiB cap`, a gzip body that inflates
past the cap included. A body that does not
decode returns `api: decode hook version: <cause>`. `FetchHookVersion` verifies
nothing. The installer checks the envelope type, the pair in the payload, the
signature with `VerifySignature`, which has no freshness window because
`issued_at` can lie days back, and the script's SHA-256 against the payload's and
the pull entry's checksum, before it writes anything; see
[Verification](../actions/remote-actions-hooks.md#verification).

**Errors** are RFC 9457 `application/problem+json` bodies with a machine-readable
`code`. `FetchHookVersion` returns each as an `*api.APIError`, and the installer
reports every failure the same way:

| Status | Problem `code` | Meaning | plexd behavior |
|---|---|---|---|
| `200 OK` | — | The version, as above | Verified and installed, or reported `verification_failed` or `install_failed` |
| `401 Unauthorized` | `nsk_invalid`, `nsk_revoked` | The NSK does not resolve or is revoked | Reported `fetch_failed` with the error, less its `correlation_id`, as its detail, `actions: rollout: fetch failed` logged at Warn, and fetched again on the next pass |
| `403 Forbidden` | `node_id_mismatch` | The NSK belongs to another node than the path | As for `401` |
| `404 Not Found` | `hook_not_assigned` | The node's desired set does not list this version of this hook, as when the node's last pull predates a rollout change | As for `401`. The next pull lists the version the rollout now names |
| `500 Internal Server Error` | `hook_version_signature_invalid` | The stored version was changed after it was published, so its signature no longer verifies; a retry gets the same answer | As for `401` |
| `501 Not Implemented` | `published_hooks_not_provisioned` | The control plane has not wired published hooks | As for `401` |
| `503 Service Unavailable` | `signing_unavailable` | The version has to be signed again under the Domain's active key and the Signing Service cannot be reached | As for `401` |

A transport error and the 30-second deadline are reported as `fetch_failed` too.
There is no backoff of its own: a pass runs on each successful pull that carries
a non-null block, and each pass fetches each listed version that is not
installed once.

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

![The callback states of an action execution. An execution starts at pending, moves to ack and then to started. From started it moves to one of three terminal states: succeeded, failed or cancelled. Started also has a transition back to itself, used only to declare an over-ceiling output size.](../../diagrams/core-execution-callback-states.svg)

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
