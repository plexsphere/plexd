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
`endpoint`. The richer `Peer` shape (below) is the state-path shape and remains
in use for `GET /v1/nodes/{node_id}/state` and `POST /v1/keys/rotate` until issue
#20 reshapes the reconciliation peer contract.

**Peer**

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

**StateResponse**

| Field        | Type                | JSON Tag                  | Description              |
|--------------|---------------------|---------------------------|--------------------------|
| `Peers`      | `[]Peer`            | `"peers"`                 | Desired peer list        |
| `Policies`   | `[]Policy`          | `"policies"`              | Network policies         |
| `SigningKeys` | `*SigningKeys`     | `"signing_keys,omitempty"`| Signing key material     |
| `Metadata`   | `map[string]string` | `"metadata,omitempty"`    | Node metadata            |
| `BridgeConfig`     | `*BridgeConfig`     | `"bridge_config,omitempty"`      | Bridge configuration           |
| `RelayConfig`      | `*RelayConfig`      | `"relay_config,omitempty"`       | Relay configuration            |
| `UserAccessConfig` | `*UserAccessConfig` | `"user_access_config,omitempty"` | User access configuration      |
| `IngressConfig`    | `*IngressConfig`    | `"ingress_config,omitempty"`     | Ingress configuration          |
| `SiteToSiteConfig` | `*SiteToSiteConfig` | `"site_to_site_config,omitempty"`| Site-to-site VPN configuration |
| `Data`       | `[]DataEntry`       | `"data"`                  | Arbitrary data entries   |
| `SecretRefs` | `[]SecretRef`       | `"secret_refs"`           | Secret references        |

**Policy**

| Field   | Type           | JSON Tag  | Description      |
|---------|----------------|-----------|------------------|
| `ID`    | `string`       | `"id"`    | Policy ID        |
| `Rules` | `[]PolicyRule` | `"rules"` | Policy rules     |

**PolicyRule**

| Field      | Type   | JSON Tag     | Description        |
|------------|--------|--------------|--------------------|
| `Src`      | `string`| `"src"`     | Source CIDR/ID     |
| `Dst`      | `string`| `"dst"`     | Destination CIDR/ID|
| `Port`     | `int`  | `"port"`     | Port number        |
| `Protocol` | `string`| `"protocol"`| Protocol (tcp/udp) |
| `Action`   | `string`| `"action"`  | allow/deny         |

**SigningKeys**

| Field               | Type         | JSON Tag                         | Description                   |
|---------------------|--------------|----------------------------------|-------------------------------|
| `Current`           | `string`     | `"current"`                      | Current signing public key    |
| `Previous`          | `string`     | `"previous,omitempty"`           | Previous key (during rotation)|
| `TransitionExpires` | `*time.Time` | `"transition_expires,omitempty"` | When previous key expires     |

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

**SecretResponse**

| Field       | Type   | JSON Tag      | Description            |
|-------------|--------|---------------|------------------------|
| `Key`       | `string`| `"key"`      | Secret key name        |
| `Ciphertext`| `string`| `"ciphertext"`| Encrypted secret value|
| `Nonce`     | `string`| `"nonce"`    | Encryption nonce       |
| `Version`   | `int`  | `"version"`   | Secret version         |

## Drift

### `POST /v1/nodes/{node_id}/drift`

**DriftReport**

| Field        | Type                | JSON Tag        | Description              |
|--------------|---------------------|-----------------|--------------------------|
| `Timestamp`  | `time.Time`         | `"timestamp"`   | Report timestamp         |
| `Corrections`| `[]DriftCorrection` | `"corrections"` | Applied corrections      |

**DriftCorrection**

| Field   | Type   | JSON Tag  | Description          |
|---------|--------|-----------|----------------------|
| `Type`  | `string`| `"type"` | Correction type      |
| `Detail`| `string`| `"detail"`| Correction details  |

## Reports

### `POST /v1/nodes/{node_id}/report`

**ReportSyncRequest**

| Field    | Type            | JSON Tag    | Description             |
|----------|-----------------|-------------|-------------------------|
| `Entries`| `[]ReportEntry` | `"entries"` | Report entries to sync  |
| `Deleted`| `[]string`      | `"deleted"` | Deleted entry keys      |

**ReportEntry**

| Field        | Type              | JSON Tag       | Description            |
|--------------|-------------------|----------------|------------------------|
| `Key`        | `string`          | `"key"`        | Entry key              |
| `ContentType`| `string`          | `"content_type"`| MIME content type     |
| `Payload`    | `json.RawMessage` | `"payload"`    | Arbitrary JSON payload |
| `Version`    | `int`             | `"version"`    | Entry version          |
| `UpdatedAt`  | `time.Time`       | `"updated_at"` | Last update timestamp  |

## Executions

### `POST /v1/nodes/{node_id}/executions/{execution_id}/ack`

**ExecutionAck**

| Field        | Type   | JSON Tag         | Description            |
|--------------|--------|------------------|------------------------|
| `ExecutionID`| `string`| `"execution_id"`| Execution identifier   |
| `Status`     | `string`| `"status"`      | Acknowledgement status |
| `Reason`     | `string`| `"reason"`      | Status reason          |

### `POST /v1/nodes/{node_id}/executions/{execution_id}/result`

**ExecutionResult**

| Field        | Type          | JSON Tag                   | Description            |
|--------------|---------------|----------------------------|------------------------|
| `ExecutionID`| `string`      | `"execution_id"`           | Execution identifier   |
| `Status`     | `string`      | `"status"`                 | Final status           |
| `ExitCode`   | `int`         | `"exit_code"`              | Process exit code      |
| `Stdout`     | `string`      | `"stdout"`                 | Standard output        |
| `Stderr`     | `string`      | `"stderr"`                 | Standard error         |
| `Duration`   | `string`      | `"duration"`               | Execution duration     |
| `FinishedAt` | `time.Time`   | `"finished_at"`            | Completion timestamp   |
| `TriggeredBy`| `*TriggeredBy`| `"triggered_by,omitempty"` | Who triggered it       |

**TriggeredBy**

| Field      | Type   | JSON Tag      | Description        |
|------------|--------|---------------|--------------------|
| `Type`     | `string`| `"type"`     | Trigger type       |
| `SessionID`| `string`| `"session_id"`| Session ID        |
| `UserID`   | `string`| `"user_id"`  | User ID            |
| `Email`    | `string`| `"email"`    | User email         |

## Observability

### `POST /v1/nodes/{node_id}/metrics`

**MetricBatch** — type alias for `[]MetricPoint`

**MetricPoint**

| Field      | Type              | JSON Tag            | Description          |
|------------|-------------------|---------------------|----------------------|
| `Timestamp`| `time.Time`       | `"timestamp"`       | Measurement time     |
| `Group`    | `string`          | `"group"`           | Metric group name    |
| `PeerID`   | `string`          | `"peer_id,omitempty"`| Optional peer ID    |
| `Data`     | `json.RawMessage` | `"data"`            | Metric data payload  |

### `POST /v1/nodes/{node_id}/logs`

**LogBatch** — type alias for `[]LogEntry`

**LogEntry**

| Field      | Type        | JSON Tag      | Description        |
|------------|-------------|---------------|--------------------|
| `Timestamp`| `time.Time` | `"timestamp"` | Log timestamp      |
| `Source`   | `string`    | `"source"`    | Log source         |
| `Unit`     | `string`    | `"unit"`      | Systemd unit       |
| `Message`  | `string`    | `"message"`   | Log message        |
| `Severity` | `string`    | `"severity"`  | Log level          |
| `Hostname` | `string`    | `"hostname"`  | Origin hostname    |

### `POST /v1/nodes/{node_id}/audit`

**AuditBatch** — type alias for `[]AuditEntry`

**AuditEntry**

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

## Capabilities

### `PUT /v1/nodes/{node_id}/capabilities`

**CapabilitiesPayload**

| Field           | Type           | JSON Tag                | Description              |
|-----------------|----------------|-------------------------|--------------------------|
| `Binary`        | `*BinaryInfo`  | `"binary,omitempty"`    | Binary version info      |
| `BuiltinActions`| `[]ActionInfo` | `"builtin_actions"`     | Built-in actions         |
| `Hooks`         | `[]HookInfo`   | `"hooks"`               | Registered hooks         |

**BinaryInfo**

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

**KeyRotateRequest**

| Field        | Type   | JSON Tag         | Description            |
|--------------|--------|------------------|------------------------|
| `NodeID`     | `string`| `"node_id"`     | Node identifier        |
| `NewPublicKey`| `string`| `"new_public_key"`| New WireGuard key   |

**KeyRotateResponse**

| Field         | Type     | JSON Tag         | Description              |
|---------------|----------|------------------|--------------------------|
| `UpdatedPeers`| `[]Peer` | `"updated_peers"`| Peers with updated keys  |

## Artifacts

### `GET /v1/artifacts/plexd/{version}/{os}/{arch}`

Returns `io.ReadCloser` with the binary stream. No request/response struct — path parameters only.

## SSE Events

### `GET /v1/nodes/{node_id}/events`

Returns `text/event-stream` with signed event envelopes.

**SignedEnvelope**

| Field      | Type              | JSON Tag      | Description                    |
|------------|-------------------|---------------|--------------------------------|
| `EventType`| `string`          | `"event_type"`| Event type constant            |
| `EventID`  | `string`          | `"event_id"`  | Unique event identifier        |
| `IssuedAt` | `time.Time`       | `"issued_at"` | Event timestamp                |
| `Nonce`    | `string`          | `"nonce"`     | Replay protection nonce        |
| `Payload`  | `json.RawMessage` | `"payload"`   | Event-specific JSON payload    |
| `Signature`| `string`          | `"signature"` | Ed25519 signature              |

### Event Types

| Constant                    | Value                     | Description                    |
|-----------------------------|---------------------------|--------------------------------|
| `EventPeerAdded`            | `peer_added`              | New peer joined mesh           |
| `EventPeerRemoved`          | `peer_removed`            | Peer left mesh                 |
| `EventPeerKeyRotated`       | `peer_key_rotated`        | Peer rotated WireGuard key     |
| `EventPeerEndpointChanged`  | `peer_endpoint_changed`   | Peer endpoint updated          |
| `EventPolicyUpdated`        | `policy_updated`          | Network policy changed         |
| `EventActionRequest`        | `action_request`          | Remote action requested        |
| `EventSessionRevoked`       | `session_revoked`         | Session revoked                |
| `EventSSHSessionSetup`      | `ssh_session_setup`       | SSH session initiated          |
| `EventRotateKeys`           | `rotate_keys`             | Key rotation requested         |
| `EventSigningKeyRotated`    | `signing_key_rotated`     | Signing key rotated            |
| `EventNodeStateUpdated`     | `node_state_updated`      | Node state changed             |
| `EventNodeSecretsUpdated`   | `node_secrets_updated`    | Node secrets changed           |
| `EventBridgeConfigUpdated`  | `bridge_config_updated`   | Bridge configuration changed   |
| `EventRelaySessionAssigned` | `relay_session_assigned`  | Relay session assigned         |
| `EventRelaySessionRevoked`  | `relay_session_revoked`   | Relay session revoked          |
| `EventUserAccessConfigUpdated` | `user_access_config_updated` | User access config changed |
| `EventUserAccessPeerAssigned`  | `user_access_peer_assigned`  | User access peer assigned  |
| `EventUserAccessPeerRevoked`   | `user_access_peer_revoked`   | User access peer revoked   |
| `EventIngressConfigUpdated`    | `ingress_config_updated`     | Ingress config changed     |
| `EventIngressRuleAssigned`     | `ingress_rule_assigned`      | Ingress rule assigned      |
| `EventIngressRuleRevoked`      | `ingress_rule_revoked`       | Ingress rule revoked       |
| `EventSiteToSiteConfigUpdated`   | `site_to_site_config_updated`   | Site-to-site config changed   |
| `EventSiteToSiteTunnelAssigned`  | `site_to_site_tunnel_assigned`  | Site-to-site tunnel assigned  |
| `EventSiteToSiteTunnelRevoked`   | `site_to_site_tunnel_revoked`   | Site-to-site tunnel revoked   |
