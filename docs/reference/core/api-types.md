---
title: API Types
package: internal/api
feature: PXD-0001
---

# API Types

All request/response types for the 17 control plane API endpoints, organized by endpoint group. All types use JSON struct tags matching the API specification.

## Registration

### `POST /v1/register`

Unauthenticated (`security: []`): the bootstrap token travels in the request
body, not an `Authorization` header. Success is `201 Created`; errors use RFC
9457 `application/problem+json`. See [Control Plane API Endpoints](api-endpoints.md)
for the wire examples and error taxonomy.

**RegisterRequest**

| Field                 | Type     | JSON Tag                            | Constraints                     |
|-----------------------|----------|-------------------------------------|---------------------------------|
| `ProjectID`           | `string` | `"project_id"`                      | Required. Platform project UUID. |
| `ResourceHandle`      | `string` | `"resource_handle"`                 | Required. Platform Resource handle. |
| `BootstrapToken`      | `string` | `"bootstrap_token"`                 | Required. Format `psb_<env>_<project>_<kind>_<random>`, matching `^psb_[a-z]+_[a-z2-7]+_(node\|bridge)_[a-z2-7]{20,}$`. |
| `Nonce`               | `string` | `"nonce"`                           | Required. Fresh UUIDv4 generated per registration attempt (server-side replay protection). |
| `PublicKey`           | `string` | `"public_key"`                      | Required. Curve25519 public key as 44-char standard base64, matching `^[A-Za-z0-9+/]{43}=$`. |
| `RequestedResourceID` | `string` | `"requested_resource_id,omitempty"` | Optional. Resource ID override when substrate naming differs from the handle. |

`hostname`, `metadata`, and `capabilities` are no longer part of registration.
Capabilities are published after registration via `PUT /v1/nodes/{node_id}/capabilities`.

**RegisterResponse** (`201 Created`)

| Field              | Type            | JSON Tag               | Description                        |
|--------------------|-----------------|------------------------|------------------------------------|
| `NodeID`           | `string`        | `"node_id"`            | Assigned node identifier (UUID)    |
| `MeshIP`           | `string`        | `"mesh_ip"`            | Assigned mesh IP address           |
| `SigningPublicKey` | `string`        | `"signing_public_key"` | Control plane signing public key   |
| `SigningKeyID`     | `string`        | `"signing_key_id"`     | Signing key id for rotation-aware signature verification (e.g. `did:web:plexsphere.com#key-2026-04`) |
| `NSK`              | `string`        | `"nsk"`                | Node secret key, returned exactly once: 44-char standard-padded base64 that decodes to the 32-byte AES-256-GCM key. Sent verbatim as the bearer credential; decoded before use as a key |
| `PeerSnapshot`     | `[]RegisterPeer`| `"peer_snapshot"`      | Initial peer snapshot              |
| `DomainMeshCIDR`   | `string`        | `"domain_mesh_cidr"`   | Domain mesh address range (e.g. `100.64.0.0/10`) |

**RegisterPeer**

| Field              | Type     | JSON Tag                       | Description                     |
|--------------------|----------|--------------------------------|---------------------------------|
| `NodeID`           | `string` | `"node_id"`                    | Peer node ID                    |
| `MeshIP`           | `string` | `"mesh_ip"`                    | Peer mesh IP address            |
| `PublicKey`        | `string` | `"public_key"`                 | Peer Curve25519 public key      |
| `FallbackEndpoint` | `string` | `"fallback_endpoint,omitempty"`| Optional fallback WireGuard endpoint |

`RegisterPeer` is deliberately narrow: it carries **no** `psk`, `allowed_ips`, or
`endpoint`. The reconciliation peer shape is `SnapshotPeer` (see
[State](#state)), used by `GET /v1/nodes/{node_id}/state`.

**Peer**

`Peer` is the WireGuard peer shape used **only** for the SSE `peer_*` payloads;
it no longer appears on the state pull. It remains until issue #25 migrates that
contract.

| Field        | Type       | JSON Tag       | Description                |
|--------------|------------|----------------|----------------------------|
| `ID`         | `string`   | `"id"`         | Peer node ID               |
| `PublicKey`  | `string`   | `"public_key"` | WireGuard public key       |
| `MeshIP`     | `string`   | `"mesh_ip"`    | Mesh IP address            |
| `Endpoint`   | `string`   | `"endpoint"`   | WireGuard endpoint         |
| `AllowedIPs` | `[]string` | `"allowed_ips"`| Allowed IP ranges          |
| `PSK`        | `string`   | `"psk"`        | Pre-shared key             |

## Heartbeat

### `POST /v1/nodes/{node_id}/heartbeat`

**HeartbeatRequest**

| Field            | Type             | JSON Tag            | Description                    |
|------------------|------------------|---------------------|--------------------------------|
| `ClientNow`      | `time.Time`      | `"client_now"`      | RFC 3339 UTC send time, stamped fresh per request; the server rejects a skew above 60s |
| `BinaryChecksum` | `string`         | `"binary_checksum"` | SHA-256 of the running binary (64-char hex or 44-char base64 of 32 bytes) |
| `BinaryVersion`  | `string`         | `"binary_version"`  | Build version (`dev` when unset); never empty |
| `NATSummary`     | `map[string]any` | `"nat_summary"`     | Always a JSON object: `{}` before discovery, else `{"endpoint", "nat_type"}` |

`nat_summary` is a `map[string]any` rather than a nil-able pointer so it always
marshals to an object: a nil map would emit `null`, which the control plane
rejects with `malformed_heartbeat_request`.

The in-memory NAT discovery result that feeds `nat_summary` is
[`nat.DiscoveryResult`](../networking/nat-traversal.md#discoveryresult); it is
never serialized on its own.

**HeartbeatResponse**

| Field        | Type        | JSON Tag        | Description                       |
|--------------|-------------|-----------------|-----------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time (used for skew estimation) |
| `Reconcile`  | `bool`      | `"reconcile"`   | Whether to trigger reconciliation |
| `RotateKeys` | `bool`      | `"rotate_keys"` | Whether to rotate keys            |

## State

### `GET /v1/nodes/{node_id}/state`

**NodeStateSnapshot**

The desired-state envelope. Every block key is **always present on the wire**: a
`null` value means "block not populated", never "field absent", so the differ
distinguishes a nil pointer from a populated block. None of the eight fields carry
`omitempty`.

| Field          | Type                   | JSON Tag         | Description                                              |
|----------------|------------------------|------------------|---------------------------------------------------------|
| `Peers`        | `[]SnapshotPeer`       | `"peers"`        | Desired peers; `[]` when empty, node_id ascending, self excluded |
| `Reachability` | `json.RawMessage`      | `"reachability"` | The node's own health projection, carried opaquely (unconsumed) |
| `Policy`       | `*PolicySnapshot`      | `"policy"`       | Merged network policy block                             |
| `Bridge`       | `*BridgeSnapshot`      | `"bridge"`       | Bridge subtrees                                         |
| `State`        | `*NodeStateBlock`      | `"state"`        | Node state buckets                                     |
| `Reports`      | `*NodeStateBlock`      | `"reports"`      | Mirrors `state` today (forward-compat split)           |
| `Executions`   | `[]NodeStateExecution` | `"executions"`   | Pending action dispatches; `[]` when empty, never `null` |
| `Sessions`     | `*[]NodeStateSession`  | `"sessions"`     | Live mediated-access sessions; `[]` when empty, never `null` on the wire. A pointer, like the block fields above: a `nil` value is a block the control plane did **not** populate, which is not a teardown signal |

Two members are consumed on the dispatch seam rather than by the differ.
`executions` is not desired state at all — it is a delivery queue, documented
under [Executions](#executions) below. `sessions` *is* desired state, but state
the tunnel dispatcher converges on itself, documented under
[Sessions](#sessions) below.

**SnapshotPeer**

Carries **no** `psk`, `allowed_ips`, or `endpoint`. plexd derives `AllowedIPs`
locally as `mesh_ip/32`, programs `fallback_endpoint` as the WireGuard endpoint
(relay target), and configures peers without a preshared key.

| Field              | Type     | JSON Tag                        | Description                   |
|--------------------|----------|---------------------------------|-------------------------------|
| `NodeID`           | `string` | `"node_id"`                     | Peer node ID                  |
| `MeshIP`           | `string` | `"mesh_ip"`                     | Peer mesh IP address          |
| `PublicKey`        | `string` | `"public_key"`                  | Peer WireGuard public key     |
| `FallbackEndpoint` | `string` | `"fallback_endpoint,omitempty"` | Optional relay/fallback endpoint |

**PolicySnapshot**

The single merged policy block.

| Field         | Type           | JSON Tag          | Description                                                     |
|---------------|----------------|-------------------|-----------------------------------------------------------------|
| `RevisionID`  | `string`       | `"revision_id"`   | Policy revision identifier                                      |
| `Fingerprint` | `string`       | `"fingerprint"`   | 44-char base64 SHA-256 over the server's canonical rule stream; plexd compares it byte-for-byte and never re-derives it |
| `Rules`       | `[]PolicyRule` | `"rules"`         | Ordered firewall rules                                          |

**PolicyRule**

A five-tuple firewall rule. `Ports` is present iff `Protocol` is `tcp` or `udp`.

| Field             | Type         | JSON Tag             | Description                              |
|-------------------|--------------|----------------------|------------------------------------------|
| `Action`          | `string`     | `"action"`           | `allow`, `deny`, or `log`                |
| `Protocol`        | `string`     | `"protocol"`         | `tcp`, `udp`, `icmp`, or `any`           |
| `SourceCIDR`      | `string`     | `"source_cidr"`      | Source CIDR                              |
| `DestinationCIDR` | `string`     | `"destination_cidr"` | Destination CIDR                        |
| `Ports`           | `*PortRange` | `"ports,omitempty"`  | Inclusive destination port range        |

**PortRange**

A single inclusive destination port range (`from <= to`).

| Field  | Type  | JSON Tag  | Description       |
|--------|-------|-----------|-------------------|
| `From` | `int` | `"from"`  | Range start port  |
| `To`   | `int` | `"to"`    | Range end port    |

**BridgeSnapshot**

Carries the four bridge subtrees. Each child is present-but-nullable; there are
no base fields on the wire. Inner shapes (`RelayConfig`, `UserAccessConfig`,
`IngressConfig`, `SiteToSiteConfig`) are documented under
[Bridge Mode](/reference/bridge/bridge-mode).

| Field        | Type                | JSON Tag           | Description                     |
|--------------|---------------------|--------------------|---------------------------------|
| `Relay`      | `*RelayConfig`      | `"relay"`          | Relay session assignments       |
| `UserAccess` | `*UserAccessConfig` | `"user_access"`    | User access configuration       |
| `Ingress`    | `*IngressConfig`    | `"ingress"`        | Public ingress configuration    |
| `SiteToSite` | `*SiteToSiteConfig` | `"site_to_site"`   | Site-to-site VPN configuration  |

**NodeStateBlock**

A three-bucket state block. Each bucket is a required array (never `null` when the
block is populated), with entries ordered by key ascending.

| Field      | Type          | JSON Tag     | Description        |
|------------|---------------|--------------|--------------------|
| `Metadata` | `[]StateEntry`| `"metadata"` | Metadata entries   |
| `Data`     | `[]StateEntry`| `"data"`     | Data entries       |
| `Reports`  | `[]StateEntry`| `"reports"`  | Report entries     |

**StateEntry**

`Value` is an opaque string; `WorkloadTag` is absent/empty when the entry is
unattributed.

| Field         | Type     | JSON Tag                    | Description             |
|---------------|----------|-----------------------------|-------------------------|
| `Key`         | `string` | `"key"`                     | Entry key               |
| `Value`       | `string` | `"value"`                   | Opaque string value     |
| `WorkloadTag` | `string` | `"workload_tag,omitempty"`  | Owning workload, if any |

### Supporting types

These types are still part of the API but no longer ride the state snapshot.
`SigningKeyRotation` is the payload of the `signing_key_rotated` SSE event;
`SecretRef` is the shape of the local node API's secret index; `DataEntry` is the
shape the local node API serves for cached data entries.

**SigningKeyRotation**

| Field               | Type        | JSON Tag                | Description                                       |
|---------------------|-------------|-------------------------|--------------------------------------------------|
| `KeyID`             | `string`    | `"key_id"`              | Key id of the new current signing key            |
| `PublicKey`         | `string`    | `"public_key"`          | Base64 Ed25519 public key of the new current key |
| `PreviousKeyID`     | `string`    | `"previous_key_id"`     | Prior key id kept valid during the grace window  |
| `TransitionExpires` | `time.Time` | `"transition_expires"`  | When the previous key id stops being accepted    |

**DataEntry**

| Field        | Type              | JSON Tag       | Description              |
|--------------|-------------------|----------------|--------------------------|
| `Key`        | `string`          | `"key"`        | Entry key                |
| `ContentType`| `string`          | `"content_type"`| MIME content type       |
| `Payload`    | `json.RawMessage` | `"payload"`    | Arbitrary JSON payload   |
| `Version`    | `int`             | `"version"`    | Entry version            |
| `UpdatedAt`  | `time.Time`       | `"updated_at"` | Last update timestamp    |

**SecretRef**

| Field    | Type   | JSON Tag    | Description      |
|----------|--------|-------------|------------------|
| `Key`    | `string`| `"key"`    | Secret key name  |
| `Version`| `int`  | `"version"` | Secret version   |

## Secrets

### `GET /v1/nodes/{node_id}/secrets/{key}`

**SecretEnvelope**

The raw AES-256-GCM envelope served by the endpoint. Unlike every other type on
this page it carries **no JSON tags**: `Data` is read from the octet-stream body,
`Version` and `KID` from response headers — the type is never JSON-marshaled or
unmarshaled.

| Field     | Type     | Source                                      | Description                                          |
|-----------|----------|---------------------------------------------|------------------------------------------------------|
| `Data`    | `[]byte` | Response body (`application/octet-stream`)  | `<12-byte nonce> \|\| <ciphertext + 16-byte GCM tag>` |
| `Version` | `int`    | `X-Plexsphere-Secret-Version` header        | Version of the returned secret                       |
| `KID`     | `string` | `X-Plexsphere-Secret-KID` header            | Key id of the NSK the envelope was sealed under      |

## Reports

### `PUT` / `DELETE /v1/nodes/{node_id}/state/reports/{key}`

Per-key node state reports. `PUT` upserts the report at `{key}`; `DELETE` removes
it. `{key}` follows the report key grammar `^[a-z][a-z0-9._-]{0,127}$`, and
`Value` is capped at 4096 bytes. See
[Control Plane API Endpoints](api-endpoints.md#reports) for the wire examples and
error taxonomy.

**NodeStateReportRequest** (`PUT` body)

| Field         | Type     | JSON Tag                    | Description                                |
|---------------|----------|-----------------------------|--------------------------------------------|
| `Value`       | `string` | `"value"`                   | Opaque report payload (at most 4096 bytes) |
| `WorkloadTag` | `string` | `"workload_tag,omitempty"`  | Owning workload; absent when unattributed  |

**NodeStateReportResponse** (`200 OK` on `PUT`)

`DELETE` returns `204 No Content` with no body (or `404` `report_not_found` when
the key has no report).

| Field        | Type        | JSON Tag        | Description                     |
|--------------|-------------|-----------------|---------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time             |
| `Key`        | `string`    | `"key"`         | Echoes the addressed report key |

## Executions

The `executions` block of the state snapshot and the single execution callback the
node posts back to `POST /v1/nodes/{node_id}/executions/{execution_id}`.

### `executions` block of `GET /v1/nodes/{node_id}/state`

**NodeStateExecution**

One pending action dispatch. The block is the delivery channel for action
dispatches: it is always present (`[]` when empty, never `null`) and ordered by
`RequestedAt`, then `ExecutionID`. An entry keeps reappearing on every pull until
its execution reaches a terminal status through the execution callback, so a
consumer must tolerate re-observing the same `ExecutionID`. The entry carries **no**
callback URL and **no** hook checksum.

| Field         | Type             | JSON Tag         | Description                                            |
|---------------|------------------|------------------|--------------------------------------------------------|
| `ExecutionID` | `string`         | `"execution_id"` | Execution identifier                                   |
| `Action`      | `string`         | `"action"`       | Action name (builtin or hook)                          |
| `Type`        | `string`         | `"type"`         | One of the `ActionKind*` values                        |
| `Parameters`  | `map[string]json.RawMessage` | `"parameters"` | Action parameters, each held as raw JSON so a large integer keeps every digit; nullable, a JSON `null` decodes to a nil map |
| `Status`      | `string`         | `"status"`       | `pending`, `ack`, or `started`                         |
| `RequestedAt` | `time.Time`      | `"requested_at"` | When the control plane dispatched the execution        |
| `ExpiresAt`   | `time.Time`      | `"expires_at"`   | Absolute UTC deadline, **not** a relative timeout      |

**ActionKind constants**

| Constant            | Value     | Description                            |
|---------------------|-----------|----------------------------------------|
| `ActionKindBuiltin` | `builtin` | Dispatches an action built into plexd  |
| `ActionKindHook`    | `hook`    | Dispatches a hook registered by the node |

**Pull-only execution status**

| Constant                 | Value     | Description                                                        |
|--------------------------|-----------|--------------------------------------------------------------------|
| `ExecutionStatusPending` | `pending` | Dispatched and not yet acknowledged; observed only on the pull block and **never** reported by a node on the callback |

The other two statuses an entry can carry, `ack` and `started`, are the
node-reportable constants listed below.

### `POST /v1/nodes/{node_id}/executions/{execution_id}`

A single callback advances an execution through its lifecycle, posted once per
transition: `ack` → `started` → `succeeded` | `failed` | `cancelled`.

**ExecutionCallbackRequest**

| Field                | Type              | JSON Tag                          | Description                                             |
|----------------------|-------------------|-----------------------------------|---------------------------------------------------------|
| `Status`             | `string`          | `"status"`                        | One of the `ExecutionStatus*` values                    |
| `ExitCode`           | `*int`            | `"exit_code,omitempty"`           | Process exit code on a terminal callback (explicit zero)|
| `Error`              | `string`          | `"error,omitempty"`               | Failure reason on a `failed` terminal                   |
| `DeclaredOutputBytes`| `int64`           | `"declared_output_bytes,omitempty"`| Captured output length; over 16 KiB drives the presign  |
| `Output`             | `*ExecutionOutput`| `"output,omitempty"`              | Captured output on a terminal callback                  |

**ExecutionOutput**

| Field       | Type   | JSON Tag               | Description                                          |
|-------------|--------|------------------------|------------------------------------------------------|
| `Inline`    | `string`| `"inline,omitempty"`  | Base64 output body, used only when at most 16 KiB    |
| `ObjectKey` | `string`| `"object_key,omitempty"`| Object-store key of an uploaded over-ceiling output|
| `SHA256`    | `string`| `"sha256,omitempty"`  | Lowercase-hex SHA-256 of the uploaded bytes          |

**ExecutionCallbackResponse**

| Field            | Type   | JSON Tag                       | Description                                              |
|------------------|--------|--------------------------------|----------------------------------------------------------|
| `Status`         | `string`| `"status"`                    | The new invocation status                                |
| `OutputUploadURL`| `string`| `"output_upload_url,omitempty"`| Presigned PUT URL, set only on the declaring callback    |

**ExecutionStatus constants**

| Constant                  | Value        | Description                                    |
|---------------------------|--------------|------------------------------------------------|
| `ExecutionStatusAck`      | `ack`        | Acknowledges receipt of the action request     |
| `ExecutionStatusStarted`  | `started`    | Reports that the action has begun running       |
| `ExecutionStatusSucceeded`| `succeeded`  | Terminal callback for a successful run          |
| `ExecutionStatusFailed`   | `failed`     | Terminal callback for a failed run              |
| `ExecutionStatusCancelled`| `cancelled`  | Terminal callback for a cancelled run           |

## Observability

The control-plane leg of the three ingest endpoints sends the flattened wire
types below and receives an `IngestReceipt` on `202 Accepted`. The internal
pipeline and the optional local endpoint keep the richer `MetricPoint` /
`LogEntry` / `AuditEntry` shapes; see
[Metrics Collection](../observability/metrics-collection.md),
[Log Forwarding](../observability/log-forwarding.md), and
[Audit Forwarding](../observability/audit-forwarding.md).

### `POST /v1/nodes/{node_id}/metrics`

Body is a JSON array of `MetricSample`.

**MetricSample**

| Field       | Type                | JSON Tag             | Description                                                    |
|-------------|---------------------|----------------------|----------------------------------------------------------------|
| `Group`     | `string`            | `"group"`            | Wire group: `node_resources`, `tunnel_health`, `peer_latency`, or `agent_stats` |
| `Name`      | `string`            | `"name"`             | Sample name                                                    |
| `Value`     | `float64`           | `"value"`            | Sample value                                                   |
| `Labels`    | `map[string]string` | `"labels,omitempty"` | Dimensions (e.g. `peer_id`); absent when the sample has none   |
| `Timestamp` | `time.Time`         | `"timestamp"`        | Sample time                                                    |

**MetricPoint** — internal pipeline and local-endpoint format; `MetricBatch` is a
type alias for `[]MetricPoint`

| Field      | Type              | JSON Tag            | Description          |
|------------|-------------------|---------------------|----------------------|
| `Timestamp`| `time.Time`       | `"timestamp"`       | Measurement time     |
| `Group`    | `string`          | `"group"`           | Metric group name    |
| `PeerID`   | `string`          | `"peer_id,omitempty"`| Optional peer ID    |
| `Data`     | `json.RawMessage` | `"data"`            | Metric data payload  |

### `POST /v1/nodes/{node_id}/logs`

Body is NDJSON: one `LogLine` per line.

**LogLine**

| Field       | Type        | JSON Tag              | Description                                                    |
|-------------|-------------|-----------------------|----------------------------------------------------------------|
| `Severity`  | `string`    | `"severity"`          | Syslog severity: `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug` |
| `Unit`      | `string`    | `"unit,omitempty"`    | Systemd unit; absent when unknown                              |
| `Hostname`  | `string`    | `"hostname,omitempty"`| Origin hostname; absent when unknown                           |
| `Message`   | `string`    | `"message"`           | Log message (non-empty)                                        |
| `Timestamp` | `time.Time` | `"timestamp"`         | Log time                                                       |

**LogEntry** — internal pipeline and local-endpoint format; `LogBatch` is a type
alias for `[]LogEntry`

| Field      | Type        | JSON Tag      | Description        |
|------------|-------------|---------------|--------------------|
| `Timestamp`| `time.Time` | `"timestamp"` | Log timestamp      |
| `Source`   | `string`    | `"source"`    | Log source         |
| `Unit`     | `string`    | `"unit"`      | Systemd unit       |
| `Message`  | `string`    | `"message"`   | Log message        |
| `Severity` | `string`    | `"severity"`  | Log level          |
| `Hostname` | `string`    | `"hostname"`  | Origin hostname    |

### `POST /v1/nodes/{node_id}/audit`

Body is NDJSON: one `AuditEvent` per line.

**AuditEvent**

| Field       | Type        | JSON Tag      | Description                     |
|-------------|-------------|---------------|---------------------------------|
| `Source`    | `string`    | `"source"`    | Wire source: `auditd`, `k8s`, or `plexd`  |
| `Action`    | `string`    | `"action"`    | Action performed (non-empty)    |
| `Outcome`   | `string`    | `"outcome"`   | Outcome (non-empty)             |
| `Timestamp` | `time.Time` | `"timestamp"` | Event time                      |

**AuditEntry** — internal pipeline and local-endpoint format; `AuditBatch` is a
type alias for `[]AuditEntry`

| Field      | Type              | JSON Tag       | Description         |
|------------|-------------------|----------------|---------------------|
| `Timestamp`| `time.Time`       | `"timestamp"`  | Event timestamp     |
| `Source`   | `string`          | `"source"`     | Audit source        |
| `EventType`| `string`          | `"event_type"` | Audit event type    |
| `Subject`  | `json.RawMessage` | `"subject"`    | Who performed it    |
| `Object`   | `json.RawMessage` | `"object"`     | What was affected   |
| `Action`   | `string`          | `"action"`     | Action performed    |
| `Result`   | `string`          | `"result"`     | Action result       |
| `Hostname` | `string`          | `"hostname"`   | Origin hostname     |
| `Raw`      | `string`          | `"raw"`        | Raw audit record    |

### Ingest receipt

**IngestReceipt** (`202 Accepted` for all three ingest endpoints)

| Field        | Type        | JSON Tag        | Description                                |
|--------------|-------------|-----------------|--------------------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | When the control plane accepted the batch  |
| `Records`    | `int`       | `"records"`     | Number of records accepted from the batch  |

## Capabilities

### `PUT /v1/nodes/{node_id}/capabilities`

**CapabilityManifestRequest**

| Field                   | Type             | JSON Tag                                | Description                                             |
|-------------------------|------------------|-----------------------------------------|---------------------------------------------------------|
| `BinaryVersion`         | `string`         | `"binary_version"`                      | Agent version, non-empty after trimming                 |
| `BinaryChecksum`        | `string`         | `"binary_checksum"`                     | Running binary's SHA-256: 32 bytes, standard-padded base64 |
| `SSHHostKeyFingerprint` | `string`         | `"ssh_host_key_fingerprint,omitempty"`  | Optional `SHA256:<base64>` host-key fingerprint         |
| `DeclaredHooks`         | `[]DeclaredHook` | `"declared_hooks,omitempty"`            | Optional hook declarations, at most 128, unique names   |

**DeclaredHook**

| Field      | Type     | JSON Tag     | Description                                        |
|------------|----------|--------------|----------------------------------------------------|
| `Name`     | `string` | `"name"`     | Hook identifier, non-empty                         |
| `Checksum` | `string` | `"checksum"` | Hook payload SHA-256: 32 bytes, standard-padded base64 |

The handler decodes this body with `DisallowUnknownFields`, so the manifest
carries these fields and nothing else. Two consequences are worth stating
outright:

- **The digest is base64, never hex.** Both checksum fields are declared
  `format: byte`, so a hex digest decodes to 48 bytes and is refused with
  `binary_checksum_invalid`. `integrity.WireChecksum` converts the hex form the
  integrity package works in into the wire form.
- **There is no field for the agent's builtin action list.** An earlier payload
  sent one under `builtin_actions`, inside a `binary` object the contract also
  does not define; the whole manifest was rejected. The action inventory is
  served locally by the node API's `GET /v1/actions`.

**BinaryInfo** — the node API's local view of the running binary. The control
plane receives the same two values as the manifest's flat fields.

| Field    | Type   | JSON Tag    | Description        |
|----------|--------|-------------|--------------------|
| `Version`| `string`| `"version"`| Binary version     |
| `Checksum`| `string`| `"checksum"`| Binary checksum  |

**ActionInfo**

| Field        | Type            | JSON Tag        | Description            |
|--------------|-----------------|-----------------|------------------------|
| `Name`       | `string`        | `"name"`        | Action name            |
| `Description`| `string`        | `"description"` | Action description     |
| `Parameters` | `[]ActionParam` | `"parameters"`  | Action parameters      |

**ActionParam**

| Field        | Type   | JSON Tag        | Description              |
|--------------|--------|-----------------|--------------------------|
| `Name`       | `string`| `"name"`       | Parameter name           |
| `Type`       | `string`| `"type"`       | Parameter type           |
| `Required`   | `bool` | `"required"`    | Whether required         |
| `Default`    | `string`| `"default,omitempty"` | Default value for optional parameters |
| `Description`| `string`| `"description"`| Parameter description   |

**HookInfo**

| Field        | Type            | JSON Tag        | Description           |
|--------------|-----------------|-----------------|-----------------------|
| `Name`       | `string`        | `"name"`        | Hook name             |
| `Description`| `string`        | `"description"` | Hook description      |
| `Source`     | `string`        | `"source"`      | Hook source path      |
| `Checksum`   | `string`        | `"checksum"`    | Source checksum       |
| `Parameters` | `[]ActionParam` | `"parameters"`  | Hook parameters       |
| `Timeout`    | `string`        | `"timeout"`     | Execution timeout     |
| `Sandbox`    | `string`        | `"sandbox"`     | Sandbox type          |

## NAT Endpoint

### `PUT /v1/nodes/{node_id}/endpoint`

**EndpointRequest**

| Field        | Type        | JSON Tag        | Description                            |
|--------------|-------------|-----------------|----------------------------------------|
| `Endpoint`   | `string`    | `"endpoint"`    | Discovered public endpoint (`ip:port`) |
| `NATType`    | `string`    | `"nat_type"`    | Wire NAT type (`full_cone`, `restricted`, `port_restricted`, `symmetric`, `unknown`) |
| `ReportedAt` | `time.Time` | `"reported_at"` | RFC 3339 UTC, stamped fresh per attempt |

**EndpointResponse**

| Field        | Type        | JSON Tag        | Description                            |
|--------------|-------------|-----------------|----------------------------------------|
| `AcceptedAt` | `time.Time` | `"accepted_at"` | Server receive time                    |
| `StaleAfter` | `time.Time` | `"stale_after"` | Deadline after which the endpoint is stale; drives the re-report cadence |

The response no longer carries peer endpoints. Inbound peer endpoint updates
arrive via the `peer_endpoint_changed` SSE event.

## Key Rotation

### `POST /v1/keys/rotate`

The server identifies the rotating node from its NSK bearer credential, so the
request carries no node id. The response is a receipt, not a peer list — the
propagated peer and PSK changes arrive via the next state pull.

**KeyRotateRequest**

| Field          | Type     | JSON Tag           | Description                                          |
|----------------|----------|--------------------|-----------------------------------------------------|
| `NewPublicKey` | `string` | `"new_public_key"` | New Curve25519 public key (44-char standard base64) |

**KeyRotateResponse**

| Field            | Type     | JSON Tag             | Description                                |
|------------------|----------|----------------------|--------------------------------------------|
| `RotationID`     | `string` | `"rotation_id"`      | Identifier for this rotation               |
| `KID`            | `string` | `"kid"`              | Key identifier for the rotated material    |
| `WrapKeyVersion` | `int`    | `"wrap_key_version"` | Wrap-key version (monotonic, `>= 0`)       |

## Sessions

The `sessions` block of the state snapshot and the activity records the node posts
back to `POST /v1/nodes/{node_id}/sessions/{session_id}`.

### `sessions` block of `GET /v1/nodes/{node_id}/state`

**NodeStateSession**

One live mediated-access session. The block is **desired state, not a queue**: it
is always present on the wire (`[]` when empty, never `null`). A response that
violates that contract by omitting or nulling the key decodes to a `nil`
`Sessions` pointer, which the tunnel dispatcher leaves alone rather than reading
as an empty block — emptiness tears every live session down, so the two cases
must stay distinguishable. An entry appears when the control plane issues the
session and disappears on revocation or hard expiry — that disappearance *is* the
teardown signal, so there is no separate teardown event, no revocation callback to
answer, and no terminal status to report. A live entry is redelivered on every
pull, so a consumer must tolerate re-observing the same `SessionID`.

| Field                | Type            | JSON Tag                            | Description                                                          |
|----------------------|-----------------|-------------------------------------|----------------------------------------------------------------------|
| `SessionID`          | `string`        | `"session_id"`                      | Session identifier                                                   |
| `JTI`                | `string`        | `"jti"`                             | Equals the session id; carried opaquely and **never** evaluated      |
| `Kind`               | `string`        | `"kind"`                            | One of the `SessionKind*` values; selects the member of `Target`     |
| `Target`             | `SessionTarget` | `"target"`                          | Exactly one member set, matching `Kind`                              |
| `ExpiresAt`          | `time.Time`     | `"expires_at"`                      | Absolute UTC deadline, **not** a relative timeout                    |
| `IdleTimeoutSeconds` | `int`           | `"idle_timeout_seconds,omitempty"`  | Idle window in seconds; `0` or absent means no idle window           |

**SessionTarget**

| Field | Type                | JSON Tag          | Description                        |
|-------|---------------------|-------------------|------------------------------------|
| `SSH` | `*SessionTargetSSH` | `"ssh,omitempty"` | Target of an `ssh` session         |
| `K8s` | `*SessionTargetK8s` | `"k8s,omitempty"` | Target of a `k8s` session          |
| `TCP` | `*SessionTargetTCP` | `"tcp,omitempty"` | Target of a `tcp` session          |

**SessionTargetSSH**

| Field             | Type       | JSON Tag                       | Description                                            |
|-------------------|------------|--------------------------------|--------------------------------------------------------|
| `User`            | `string`   | `"user"`                       | Local account the session logs in as                   |
| `AllowedCommands` | `[]string` | `"allowed_commands,omitempty"` | Closed set of command lines the session may run        |

**SessionTargetK8s**

| Field               | Type       | JSON Tag                         | Description                            |
|---------------------|------------|----------------------------------|----------------------------------------|
| `User`              | `string`   | `"user"`                         | Impersonated Kubernetes user           |
| `ImpersonateGroups` | `[]string` | `"impersonate_groups,omitempty"` | Groups impersonated alongside the user |

**SessionTargetTCP**

| Field  | Type     | JSON Tag | Description                                       |
|--------|----------|----------|---------------------------------------------------|
| `Host` | `string` | `"host"` | Host the node forwards the session's connections to |
| `Port` | `int`    | `"port"` | Port on that host                                 |

**SessionKind constants**

| Constant          | Value | Description                                        |
|-------------------|-------|----------------------------------------------------|
| `SessionKindSSH`  | `ssh` | Mediates an SSH session; `Target.SSH` is set       |
| `SessionKindK8s`  | `k8s` | Mediates a Kubernetes API session; `Target.K8s` is set |
| `SessionKindTCP`  | `tcp` | Mediates a plain TCP forward; `Target.TCP` is set  |

Only `tcp` entries are provisionable by this agent; `ssh` and `k8s` entries are
decoded and settled as unsupported. See
[Secure Access Tunneling](../networking/secure-access-tunneling.md) for how plexd
consumes the block.

### `POST /v1/nodes/{node_id}/sessions/{session_id}`

A one-of session activity record: exactly one of `ssh`, `k8s`, or `tcp` is set,
selecting the session kind. plexd's tunnel subsystem is an opaque TCP forwarder,
so it emits only `tcp` rows; the `ssh` and `k8s` variants are carried by the type
and accepted by the server but not emitted by any current session type. Success
is `204 No Content`.

**SessionActivityRequest**

| Field | Type           | JSON Tag          | Description                     |
|-------|----------------|-------------------|---------------------------------|
| `SSH` | `*SSHActivity` | `"ssh,omitempty"` | Per-command SSH session row      |
| `K8s` | `*K8sActivity` | `"k8s,omitempty"` | Per-request Kubernetes API row   |
| `TCP` | `*TCPActivity` | `"tcp,omitempty"` | TCP session lifecycle row        |

**SSHActivity**

| Field         | Type         | JSON Tag                  | Description                            |
|---------------|--------------|---------------------------|----------------------------------------|
| `Command`     | `string`     | `"command"`               | Executed command line (capped at 1 KiB)|
| `ExitCode`    | `*int`       | `"exit_code,omitempty"`   | Command exit code                      |
| `StartedAt`   | `*time.Time` | `"started_at,omitempty"`  | RFC 3339 start time                    |
| `CompletedAt` | `*time.Time` | `"completed_at,omitempty"`| RFC 3339 completion time               |

**K8sActivity**

| Field          | Type    | JSON Tag                    | Description               |
|----------------|---------|-----------------------------|---------------------------|
| `Verb`         | `string`| `"verb"`                    | API verb                  |
| `ResourceKind` | `string`| `"resource_kind,omitempty"` | Target resource kind      |
| `Namespace`    | `string`| `"namespace,omitempty"`     | Target namespace          |
| `Name`         | `string`| `"name,omitempty"`          | Target object name        |
| `StatusCode`   | `int`   | `"status_code,omitempty"`   | Response status code      |
| `DurationMS`   | `int64` | `"duration_ms,omitempty"`   | Request duration in ms    |

**TCPActivity**

| Field          | Type    | JSON Tag                   | Description                                             |
|----------------|---------|----------------------------|---------------------------------------------------------|
| `Phase`        | `string`| `"phase"`                  | One of the `TCPPhase*` values                           |
| `TargetHost`   | `string`| `"target_host,omitempty"`  | Forward target host                                     |
| `TargetPort`   | `int`   | `"target_port,omitempty"`  | Forward target port                                     |
| `ListenerEndpoint` | `string`| `"listener_endpoint,omitempty"` | Address the node's listener bound; set on `session_started` rows only |
| `BytesIn`      | `*int64`| `"bytes_in,omitempty"`     | Operator→target bytes (explicit `0` on `session_ended`) |
| `BytesOut`     | `*int64`| `"bytes_out,omitempty"`    | Target→operator bytes (explicit `0` on `session_ended`) |
| `TerminatedBy` | `string`| `"terminated_by,omitempty"`| One of the `TerminatedBy*` values                       |

**TCPPhase constants**

| Constant                 | Value             | Description                  |
|--------------------------|-------------------|------------------------------|
| `TCPPhaseSessionStarted` | `session_started` | Opening of a TCP session     |
| `TCPPhaseSessionEnded`   | `session_ended`   | Close of a TCP session       |

**TerminatedBy constants**

| Constant                     | Value            | Description                                   |
|------------------------------|------------------|-----------------------------------------------|
| `TerminatedByTTLExpired`     | `ttl_expired`    | Session reached its time-to-live              |
| `TerminatedByIdleTimeout`    | `idle_timeout`   | Idle window elapsed with no byte flow          |
| `TerminatedByPlexdClose`     | `plexd_close`    | plexd closed the session locally              |
| `TerminatedByOperatorRevoke` | `operator_revoke`| Operator's access was revoked. Part of the wire enum; **never produced by plexd**, which cannot tell a revocation from a block the control plane failed to serve |

## Integrity

### `POST /v1/nodes/{node_id}/integrity-violations`

A batch of the tamper-evidence divergences the agent detected on the node: a
mismatched binary checksum, a tampered hook checksum, or a rotated SSH host key.
The endpoint takes a batch even for a single finding, so a lone violation travels
as a one-entry array rather than as a bare object. Success is `200 OK` with a
receipt, not `202`: the violation rows and the `integrity_alert` outbox event are
committed before the response is written.

The handler decodes with `DisallowUnknownFields` and caps the body at 32 KiB, so
an unknown or renamed field refuses the whole request.

**IntegrityViolationsRequest**

| Field        | Type                         | JSON Tag       | Description                                    |
|--------------|------------------------------|----------------|------------------------------------------------|
| `Violations` | `[]IntegrityViolationReport` | `"violations"` | 1 to `MaxIntegrityViolationsPerBatch` (128) entries |

An empty array is refused with `400 integrity_violations_empty` and an oversized
one with `integrity_violations_too_many`. `ReportIntegrityViolations` checks both
bounds locally and returns `ErrIntegrityViolationsEmpty` or
`ErrIntegrityViolationsTooMany` without sending, since a refused request would
take every violation in it down.

**IntegrityViolationReport**

| Field                 | Type                     | JSON Tag                          | Description                                     |
|-----------------------|--------------------------|-----------------------------------|-------------------------------------------------|
| `Kind`                | `IntegrityViolationKind` | `"kind"`                          | Artifact class the divergence applies to        |
| `DetectedBy`          | `IntegrityDetector`      | `"detected_by"`                   | On-node detector that surfaced it               |
| `ArtifactID`          | `string`                 | `"artifact_id"`                   | Affected artifact; non-empty after trimming, at most 4096 bytes |
| `ObservedChecksum`    | `string`                 | `"observed_checksum,omitempty"`   | Computed SHA-256, 32 raw bytes in standard-padded base64 |
| `ExpectedChecksum`    | `string`                 | `"expected_checksum,omitempty"`   | Baseline digest, same encoding                  |
| `ObservedFingerprint` | `string`                 | `"observed_fingerprint,omitempty"`| Observed host-key fingerprint, `SHA256:<base64>`|
| `ExpectedFingerprint` | `string`                 | `"expected_fingerprint,omitempty"`| Baseline fingerprint, same form                 |

`Kind` decides which digest pair is legal: a checksum kind carries the checksums
and no fingerprint, the host-key kind carries the fingerprints and no checksum.
Crossing them is refused with `400 integrity_violation_kind_mismatch`, which is
why the four digest fields are `omitempty` — an unset one must be absent from the
JSON rather than present and empty.

The checksum fields are declared `format: byte`, so the hex form the integrity
package works in decodes to 48 bytes and is refused with
`integrity_violation_checksum_invalid`. `integrity.WireChecksum` converts hex into
the wire form.

**IntegrityViolationKind constants**

| Constant                      | Value             | Description                       |
|-------------------------------|-------------------|-----------------------------------|
| `IntegrityKindBinaryChecksum` | `binary_checksum` | The agent's own binary            |
| `IntegrityKindHookChecksum`   | `hook_checksum`   | A hook script                     |
| `IntegrityKindSSHHostKey`     | `ssh_host_key`    | The mesh SSH host key             |

**IntegrityDetector constants**

| Constant                       | Value          | Description                                             |
|--------------------------------|----------------|---------------------------------------------------------|
| `IntegrityDetectorStartupScan` | `startup_scan` | The agent's sweep of the artifacts it holds baselines for. The enum has no value for a periodic re-scan, so the interval-driven sweeps report this one too |
| `IntegrityDetectorInotify`     | `inotify`      | The hooks-directory watcher reacting to a filesystem event |
| `IntegrityDetectorPreDispatch` | `pre_dispatch` | The check that runs immediately before a hook executes  |

A value outside either set is refused with `400
integrity_violation_kind_invalid` or `integrity_violation_detected_by_invalid`.

**IntegrityViolationsResponse**

| Field            | Type        | JSON Tag            | Description                            |
|------------------|-------------|---------------------|----------------------------------------|
| `AcceptedAt`     | `time.Time` | `"accepted_at"`     | Server-side commit timestamp           |
| `ViolationCount` | `int`       | `"violation_count"` | Rows persisted; matches the input length |

## SSE Events

### `GET /v1/nodes/{node_id}/events`

Returns `text/event-stream` with signed event envelopes.

**Envelope**

| Field       | Type              | JSON Tag       | Description                                   |
|-------------|-------------------|----------------|-----------------------------------------------|
| `ID`        | `string`          | `"id"`         | Unique event identifier (required)            |
| `Type`      | `string`          | `"type"`       | Event type discriminator (required)           |
| `Scope`     | `string`          | `"scope"`      | Scope the event applies to                    |
| `KeyID`     | `string`          | `"key_id"`     | Key id that selects the verifying signing key |
| `IssuedAt`  | `time.Time`       | `"issued_at"`  | Event timestamp                               |
| `Payload`   | `json.RawMessage` | `"payload"`    | Event-specific JSON payload                   |
| `Signature` | `string`          | `"signature"`  | Base64 Ed25519 signature over the canonical form |

`ParseEnvelope` requires `id` and `type`. See [Event Verification](event-verification.md)
for the canonical form and signature rules.

### Event Types

The event set is organized in two tiers. Contract types are emitted today;
documented-coming types are named for the platform's 14-type taxonomy.
Reconcile-driving payloads are opaque — the state pull is authoritative.

| Constant                   | Value                   | Tier              |
|----------------------------|-------------------------|-------------------|
| `EventNodeStateUpdated`    | `node_state_updated`    | contract          |
| `EventPolicyUpdated`       | `policy_updated`        | contract          |
| `EventBridgeConfigUpdated` | `bridge_config_updated` | contract          |
| `EventActionRequest`       | `action_request`        | contract          |
| `EventSessionSetup`        | `session_setup`         | contract          |
| `EventPeerRegistered`      | `peer_registered`       | documented-coming |
| `EventPeerPSKAssigned`     | `peer_psk_assigned`     | documented-coming |
| `EventPeerDeregistered`    | `peer_deregistered`     | documented-coming |
| `EventPeerEndpointChanged` | `peer_endpoint_changed` | documented-coming |
| `EventPeerKeyRotated`      | `peer_key_rotated`      | documented-coming |
| `EventRotateKeys`          | `rotate_keys`           | documented-coming |
| `EventSigningKeyRotated`   | `signing_key_rotated`   | documented-coming |
| `EventSessionRevoked`      | `session_revoked`       | documented-coming |

`action_request` is a contract type with an opaque payload: action dispatches are
delivered in the `executions` block of the state pull, so the event only triggers
a reconcile and the resulting pull carries the dispatch. `session_setup` is the
same shape for mediated access — the session is delivered in the `sessions` block
of that pull. `session_revoked` is the same shape from the other end: a session
leaving the `sessions` block is what tears it down, so the event only pulls the
observing reconcile forward.
