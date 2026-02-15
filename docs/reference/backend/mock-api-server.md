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

Returns a fixture `StateResponse` with two peers, one policy containing two rules, and metadata.

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
  "metadata": {
    "environment": "e2e-test",
    "region": "mock-region-1"
  }
}
```

**Content-Type:** `application/json`

**Counter:** Increments `state_count` on each call.

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

Server-Sent Events (SSE) endpoint. Sends an initial `SignedEnvelope` event, then holds the connection open with periodic keep-alive comments until the client disconnects.

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

**Disconnect:** The server detects client disconnect via context cancellation and cleans up the goroutine.

### `GET /test/assertions`

Test-only endpoint returning a snapshot of all call counters. Not part of the `/v1/` API namespace.

**Response:** `200 OK`

```json
{
  "registration_count": 0,
  "heartbeat_count": 0,
  "state_count": 0,
  "metadata_count": 0
}
```

**Content-Type:** `application/json`

## Call Counters

The server tracks API calls using `sync/atomic.Int64` counters. Each endpoint increments its counter atomically before writing the response, ensuring accurate counts under concurrent access.

| Counter | Incremented By |
|---------|---------------|
| `registration_count` | `POST /v1/register` |
| `heartbeat_count` | `POST /v1/nodes/{id}/heartbeat` |
| `state_count` | `GET /v1/nodes/{id}/state` |
| `metadata_count` | `GET /v1/nodes/{id}/metadata` |

Query current values via `GET /test/assertions`.

## Wire Compatibility

All responses use the same JSON field names as the types in `internal/api`:

- `RegisterResponse` — `internal/api.RegisterResponse`
- `HeartbeatResponse` — `internal/api.HeartbeatResponse`
- `StateResponse` — `internal/api.StateResponse`
- `SignedEnvelope` — `internal/api.SignedEnvelope`
- `Peer` — `internal/api.Peer`
- `Policy` / `PolicyRule` — `internal/api.Policy` / `internal/api.PolicyRule`

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
