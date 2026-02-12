---
title: API Types
quadrant: backend
package: internal/api
feature: PXD-0001
---

# API Types

All request/response types for the 17 control plane API endpoints, organized by endpoint group. All types use JSON struct tags matching the API specification.

## Registration

### `POST /v1/register`

**RegisterRequest**

| Field          | Type                   | JSON Tag                   | Description                     |
|----------------|------------------------|----------------------------|---------------------------------|
| `Token`        | `string`               | `"token"`                  | Bootstrap authentication token  |
| `PublicKey`     | `string`               | `"public_key"`             | Node's WireGuard public key     |
| `Hostname`     | `string`               | `"hostname"`               | Node hostname                   |
| `Metadata`     | `map[string]string`    | `"metadata,omitempty"`     | Optional key-value metadata     |
| `Capabilities` | `*CapabilitiesPayload` | `"capabilities,omitempty"` | Optional initial capabilities   |

**RegisterResponse**

| Field             | Type     | JSON Tag             | Description                        |
|-------------------|----------|----------------------|------------------------------------|
| `NodeID`          | `string` | `"node_id"`          | Assigned node identifier           |
| `MeshIP`          | `string` | `"mesh_ip"`          | Assigned mesh IP address           |
| `SigningPublicKey` | `string` | `"signing_public_key"` | Control plane signing public key |
| `NodeSecretKey`   | `string` | `"node_secret_key"`  | Node identity secret key           |
| `Peers`           | `[]Peer` | `"peers"`            | Initial peer list                  |

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

| Field            | Type        | JSON Tag              | Description                    |
|------------------|-------------|-----------------------|--------------------------------|
| `NodeID`         | `string`    | `"node_id"`           | Node identifier                |
| `Timestamp`      | `time.Time` | `"timestamp"`         | Heartbeat timestamp            |
| `Status`         | `string`    | `"status"`            | Node status                    |
| `Uptime`         | `string`    | `"uptime"`            | Node uptime                    |
| `BinaryChecksum` | `string`    | `"binary_checksum"`   | Running binary checksum        |
| `Mesh`           | `*MeshInfo` | `"mesh,omitempty"`    | Optional mesh status           |
| `NAT`            | `*NATInfo`  | `"nat,omitempty"`     | Optional NAT information       |

**MeshInfo**

| Field        | Type   | JSON Tag        | Description            |
|--------------|--------|-----------------|------------------------|
| `Interface`  | `string`| `"interface"`  | WireGuard interface    |
| `PeerCount`  | `int`  | `"peer_count"`  | Connected peer count   |
| `ListenPort` | `int`  | `"listen_port"` | WireGuard listen port  |

**NATInfo**

| Field            | Type   | JSON Tag            | Description          |
|------------------|--------|---------------------|----------------------|
| `PublicEndpoint`  | `string`| `"public_endpoint"`| Public endpoint      |
| `Type`           | `string`| `"type"`           | NAT type             |

**HeartbeatResponse**

| Field        | Type   | JSON Tag       | Description                       |
|--------------|--------|----------------|-----------------------------------|
| `Reconcile`  | `bool` | `"reconcile"`  | Whether to trigger reconciliation |
| `RotateKeys` | `bool` | `"rotate_keys"`| Whether to rotate keys            |

## State

### `GET /v1/nodes/{node_id}/state`

**StateResponse**

| Field        | Type                | JSON Tag                  | Description              |
|--------------|---------------------|---------------------------|--------------------------|
| `Peers`      | `[]Peer`            | `"peers"`                 | Desired peer list        |
| `Policies`   | `[]Policy`          | `"policies"`              | Network policies         |
| `SigningKeys` | `*SigningKeys`     | `"signing_keys,omitempty"`| Signing key material     |
| `Metadata`   | `map[string]string` | `"metadata,omitempty"`    | Node metadata            |
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

**EndpointReport**

| Field            | Type   | JSON Tag            | Description          |
|------------------|--------|---------------------|----------------------|
| `PublicEndpoint`  | `string`| `"public_endpoint"`| Public endpoint      |
| `NATType`        | `string`| `"nat_type"`       | NAT type             |

**EndpointResponse**

| Field          | Type             | JSON Tag           | Description          |
|----------------|------------------|--------------------|----------------------|
| `PeerEndpoints`| `[]PeerEndpoint` | `"peer_endpoints"` | Updated peer endpoints|

**PeerEndpoint**

| Field    | Type   | JSON Tag    | Description      |
|----------|--------|-------------|------------------|
| `PeerID` | `string`| `"peer_id"`| Peer node ID     |
| `Endpoint`| `string`| `"endpoint"`| Peer endpoint   |

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
