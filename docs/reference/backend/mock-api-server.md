---
title: Mock Central API Server
quadrant: backend
package: test/e2e/mockapi
feature: PXD-0037
---

# Mock Central API Server

A fixture-based mock of the Central API for end-to-end testing. Returns static responses that are wire-compatible with `internal/api` types, enabling CI pipelines to validate plexd's registration, heartbeat, reconciliation, and SSE logic without a production control plane.

## Configuration

| Option | Flag | Environment Variable | Default | Description |
|--------|------|---------------------|---------|-------------|
| Listen address | `-addr` | — | `:0` | TCP address (`host:port`) to listen on |

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

Returns a fixture `RegisterResponse` with a node identity and two mesh peers. Accepts any valid JSON body without validation.

**Response:** `200 OK`

```json
{
  "node_id": "node-mock-001",
  "mesh_ip": "10.99.0.1",
  "signing_public_key": "ed25519-mock-signing-pub-key",
  "node_secret_key": "mock-node-secret-key-abc123",
  "peers": [
    {
      "id": "peer-001",
      "public_key": "wg-pub-key-peer-001",
      "mesh_ip": "10.99.0.2",
      "endpoint": "203.0.113.1:51820",
      "allowed_ips": ["10.99.0.2/32"],
      "psk": "mock-psk-001"
    },
    {
      "id": "peer-002",
      "public_key": "wg-pub-key-peer-002",
      "mesh_ip": "10.99.0.3",
      "endpoint": "203.0.113.2:51820",
      "allowed_ips": ["10.99.0.3/32"],
      "psk": "mock-psk-002"
    }
  ]
}
```

**Content-Type:** `application/json`

**Counter:** Increments `registration_count` on each call.

**Error:** Returns `400` if the request body is not valid JSON. Returns `405` if the HTTP method is not `POST`.

### `POST /v1/nodes/{id}/heartbeat`

Returns a fixture `HeartbeatResponse` signaling that reconciliation is needed. Accepts any node ID in the path.

**Response:** `200 OK`

```json
{
  "reconcile": true,
  "rotate_keys": false
}
```

**Content-Type:** `application/json`

**Counter:** Increments `heartbeat_count` on each call.

**Error:** Returns `405` if the HTTP method is not `POST`.

### `GET /v1/nodes/{id}/state`

Returns the active `StateResponse` fixture. By default this is an enriched fixture containing two peers, one policy with two rules, metadata, signing keys, all feature config sections, sample data entries, and secret references. The active fixture can be replaced at runtime via `POST /test/configure-state`.

**Default fixture fields:**

| Field | Default Value |
|-------|---------------|
| `peers` | 2 mesh peers (`peer-001`, `peer-002`) |
| `policies` | 1 policy (`policy-001`) with 2 rules |
| `metadata` | `{"environment":"e2e-test","region":"mock-region-1"}` |
| `signing_keys` | `current`: base64 Ed25519 mock key |
| `bridge_config` | `enabled: true`, `access_subnets: ["192.168.100.0/24"]`, NAT and forwarding enabled |
| `relay_config` | 1 relay session assignment (`relay-sess-001`) |
| `user_access_config` | `enabled: true`, interface `wg-access0`, 1 peer |
| `ingress_config` | `enabled: true`, 1 rule (`ingress-001`, port 443) |
| `site_to_site_config` | `enabled: true`, 1 tunnel (`s2s-001`) |
| `data` | 2 entries: `app/config` (JSON) and `certs/ca` (PEM) |
| `secret_refs` | 2 refs: `db-password` (v1) and `tls-private-key` (v3) |

**Response:** `200 OK`

```json
{
  "peers": [
    {
      "id": "peer-001",
      "public_key": "wg-pub-key-peer-001",
      "mesh_ip": "10.99.0.2",
      "endpoint": "203.0.113.1:51820",
      "allowed_ips": ["10.99.0.2/32"],
      "psk": "mock-psk-001"
    },
    {
      "id": "peer-002",
      "public_key": "wg-pub-key-peer-002",
      "mesh_ip": "10.99.0.3",
      "endpoint": "203.0.113.2:51820",
      "allowed_ips": ["10.99.0.3/32"],
      "psk": "mock-psk-002"
    }
  ],
  "policies": [
    {
      "id": "policy-001",
      "rules": [
        {
          "src": "10.99.0.0/24",
          "dst": "10.99.0.0/24",
          "port": 0,
          "protocol": "any",
          "action": "allow"
        },
        {
          "src": "10.99.0.0/24",
          "dst": "0.0.0.0/0",
          "port": 443,
          "protocol": "tcp",
          "action": "allow"
        }
      ]
    }
  ],
  "signing_keys": {
    "current": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  },
  "metadata": {
    "environment": "e2e-test",
    "region": "mock-region-1"
  },
  "bridge_config": {
    "access_subnets": ["192.168.100.0/24"],
    "enable_nat": true,
    "enable_forwarding": true
  },
  "relay_config": {
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
  "user_access_config": {
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
  "ingress_config": {
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
  "site_to_site_config": {
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
  },
  "data": [
    {
      "key": "app/config",
      "content_type": "application/json",
      "payload": {"log_level": "info", "max_conns": 100},
      "version": 1,
      "updated_at": "2025-01-01T00:00:00Z"
    },
    {
      "key": "certs/ca",
      "content_type": "application/x-pem-file",
      "payload": "-----BEGIN CERTIFICATE-----\nmock-ca-cert\n-----END CERTIFICATE-----",
      "version": 2,
      "updated_at": "2025-01-15T12:00:00Z"
    }
  ],
  "secret_refs": [
    {"key": "db-password", "version": 1},
    {"key": "tls-private-key", "version": 3}
  ]
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
  "drift_count": 0,
  "secrets_count": 0,
  "report_count": 0,
  "execution_ack_count": 0,
  "execution_result_count": 0,
  "metrics_count": 0,
  "logs_count": 0,
  "audit_count": 0,
  "artifact_count": 0,
  "tunnel_ready_count": 0,
  "tunnel_closed_count": 0,
  "integrity_violation_count": 0,
  "inject_event_count": 0
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

Replaces the active `StateResponse` fixture at runtime. Subsequent calls to `GET /v1/nodes/{id}/state` return the configured state instead of the default. The `state_count` counter continues to increment regardless of which fixture is active.

**Request body:** A full `api.StateResponse` JSON object (same schema as the `GET /v1/nodes/{id}/state` response).

```json
{
  "peers": [],
  "policies": [],
  "metadata": {"custom": "value"}
}
```

**Response:** `204 No Content`

**Behavior:**

- The replacement is atomic — concurrent readers never see a partial update
- The state fixture is protected by `sync.RWMutex`
- Any valid `StateResponse` JSON is accepted, including minimal objects with empty fields
- Request body is captured and retrievable via `GET /test/last-request/configure_state`

**Error:** Returns `400` if the request body is not valid JSON. Returns `405` if the HTTP method is not `POST`.

**Go API:** The `Server` also exposes `SetState(api.StateResponse)` and `GetState() api.StateResponse` methods for direct use in Go test code without HTTP.

### `PUT /test/state`

Alias for `POST /test/configure-state`. Same behavior.

**Response:** `204 No Content`

### `GET /test/last-request/{endpoint}`

Returns the raw request body captured from the last call to the specified endpoint. Useful for asserting that the client sent the correct payload.

**Path parameter:** `endpoint` — the capture key (e.g., `register`, `heartbeat`, `inject_event`).

**Response:** `200 OK` with `Content-Type: application/octet-stream` and the raw body bytes.

**Error:** Returns `404` if no request has been captured for the given endpoint.

## Call Counters

The server tracks API calls using `sync/atomic.Int64` counters. Each endpoint increments its counter atomically before writing the response, ensuring accurate counts under concurrent access.

| Counter | Incremented By |
|---------|---------------|
| `registration_count` | `POST /v1/register` |
| `heartbeat_count` | `POST /v1/nodes/{id}/heartbeat` |
| `state_count` | `GET /v1/nodes/{id}/state` |
| `metadata_count` | `GET /v1/nodes/{id}/metadata` |
| `deregister_count` | `POST /v1/nodes/{id}/deregister` |
| `key_rotate_count` | `POST /v1/keys/rotate` |
| `capabilities_count` | `PUT /v1/nodes/{id}/capabilities` |
| `endpoint_count` | `PUT /v1/nodes/{id}/endpoint` |
| `drift_count` | `POST /v1/nodes/{id}/drift` |
| `secrets_count` | `GET /v1/nodes/{id}/secrets/{key}` |
| `report_count` | `POST /v1/nodes/{id}/report` |
| `execution_ack_count` | `POST /v1/nodes/{id}/executions/{eid}/ack` |
| `execution_result_count` | `POST /v1/nodes/{id}/executions/{eid}/result` |
| `metrics_count` | `POST /v1/nodes/{id}/metrics` |
| `logs_count` | `POST /v1/nodes/{id}/logs` |
| `audit_count` | `POST /v1/nodes/{id}/audit` |
| `artifact_count` | `GET /v1/artifacts/plexd/{version}/{os}/{arch}` |
| `tunnel_ready_count` | `POST /v1/nodes/{id}/tunnels/{sid}/ready` |
| `tunnel_closed_count` | `POST /v1/nodes/{id}/tunnels/{sid}/closed` |
| `integrity_violation_count` | `POST /v1/nodes/{id}/integrity/violations` |
| `inject_event_count` | `POST /test/inject-event` |

Query current values via `GET /test/assertions`.

## Wire Compatibility

All responses use the same JSON field names as the types in `internal/api`:

- `RegisterResponse` — `internal/api.RegisterResponse`
- `HeartbeatResponse` — `internal/api.HeartbeatResponse`
- `StateResponse` — `internal/api.StateResponse`
- `SignedEnvelope` — `internal/api.SignedEnvelope`
- `Peer` — `internal/api.Peer`
- `Policy` / `PolicyRule` — `internal/api.Policy` / `internal/api.PolicyRule`
- `SigningKeys` — `internal/api.SigningKeys`
- `BridgeConfig` — `internal/api.BridgeConfig`
- `RelayConfig` / `RelaySessionAssignment` — `internal/api.RelayConfig` / `internal/api.RelaySessionAssignment`
- `UserAccessConfig` / `UserAccessPeer` — `internal/api.UserAccessConfig` / `internal/api.UserAccessPeer`
- `IngressConfig` / `IngressRule` — `internal/api.IngressConfig` / `internal/api.IngressRule`
- `SiteToSiteConfig` / `SiteToSiteTunnel` — `internal/api.SiteToSiteConfig` / `internal/api.SiteToSiteTunnel`
- `DataEntry` — `internal/api.DataEntry`
- `SecretRef` — `internal/api.SecretRef`

## Dockerfile

Multi-stage build at `test/e2e/mockapi/Dockerfile`.

| Stage | Image | Purpose |
|-------|-------|---------|
| Builder | `golang:1.24-alpine` | Compile the mock server binary |
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
| Exposed port | `8080` |
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

## Source

- Server: `test/e2e/mockapi/mockapi.go`
- CLI entry point: `test/e2e/mockapi/cmd/mockapi/main.go`
- Tests: `test/e2e/mockapi/mockapi_test.go`
- Dockerfile: `test/e2e/mockapi/Dockerfile`
