---
title: Using the Local Node API
package: internal/nodeapi
feature: PXD-0004
---

# Using the Local Node API

The Local Node API lets programs running on a plexd-managed node read node
state (metadata, data entries, secrets) and write report entries back to the
control plane. The API is served over a Unix domain socket on Linux and macOS
and over the named pipe `\\.\pipe\plexd` on Windows, and, optionally, over TCP
with bearer-token authentication.

This guide walks through common tasks. For a full reference of types and
internals, see [Local Node API Reference](../reference/core/nodeapi.md).

## Prerequisites

1. **plexd is running** on the node. The daemon creates the socket, or the
   named pipe on Windows, on startup.

2. **Access to the endpoint** -- who may read what depends on the platform:

   On Linux, access to the socket is controlled by filesystem permissions:

   | Group            | Grants access to                      |
   |------------------|---------------------------------------|
   | `plexd`          | All endpoints except secret values    |
   | `plexd-secrets`  | Secret-value endpoints (`/v1/state/secrets/{key}`) |

   `deploy/install.sh` creates both groups. If you installed plexd another
   way, create them first, then add your user (or service account) to the
   appropriate one:

   ```bash
   sudo groupadd --system plexd
   sudo groupadd --system plexd-secrets
   sudo usermod -aG plexd myuser
   sudo usermod -aG plexd-secrets myuser   # only if secret access is needed
   ```

   On macOS the same two groups apply, nothing creates them, and macOS keeps
   them in Open Directory. Create a group and add a user to it with:

   ```bash
   sudo dscl . -create /Groups/plexd-secrets
   sudo dseditgroup -o edit -a <user> -t user plexd-secrets
   ```

   Run the same pair for `plexd`. On both platforms, without the `plexd` group
   the daemon narrows the socket to mode `0600` and only root reaches the API:
   opening the socket is the whole authorization for every route but the
   secret ones, so a missing group fails closed rather than opening the action
   and report routes to every local account. Restarting the daemon after
   creating the group is what applies the new mode.

   The daemon narrows to `0600` for the same reason when it may not hand
   the socket to the group. That is the case under the systemd unit
   `plexd install` writes, whose capability set excludes `CAP_CHOWN`: the
   `plexd` group grants access to a daemon started with full root
   capabilities, such as `sudo plexd up`, and not to one started with
   `systemctl start plexd`. When a member of `plexd` is refused, look for
   `cannot hand the socket to the plexd group` in the daemon log.

   On Windows the endpoint is the named pipe `\\.\pipe\plexd`, and no group
   governs it. Its security descriptor admits LocalSystem and Administrators
   only, so reaching the API needs an elevated shell or a caller running as
   LocalSystem, such as the plexd service. That is the same posture as the
   `plexd` group on Linux and macOS, for the same reason: the pipe carries the
   action, hook and report routes, which the service runs as LocalSystem.

3. **An HTTP client that reaches the endpoint.** On Linux and macOS that is
   curl, or any HTTP client that supports `--unix-socket`. curl cannot open a
   Windows named pipe, so use the plexd CLI (`plexd status`, `plexd state`)
   from an elevated shell there, or a pipe-capable client:

   ```powershell
   $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'plexd', [System.IO.Pipes.PipeDirection]::InOut)
   $pipe.Connect(2000)
   $writer = New-Object System.IO.StreamWriter($pipe)
   $writer.NewLine = "`r`n"; $writer.AutoFlush = $true
   $writer.WriteLine('GET /v1/state HTTP/1.0'); $writer.WriteLine('Host: localhost'); $writer.WriteLine('')
   $reader = New-Object System.IO.StreamReader($pipe)
   $reader.ReadToEnd()
   ```

   The request asks for HTTP/1.0, so the server closes the connection after
   the response and `ReadToEnd` returns.

## Connecting to the API

### Via the local endpoint (default)

The socket path defaults to `/var/run/plexd/api.sock` on Linux and macOS, and
the pipe is `\\.\pipe\plexd` on Windows. All examples in this guide use the
socket path.

```bash
curl -s --unix-socket /var/run/plexd/api.sock http://localhost/v1/state
```

No authentication header is required -- access is governed by the socket's file
mode, or by the pipe's security descriptor on Windows. On Windows, reach the
pipe with the plexd CLI or with the PowerShell client from the
[prerequisites](#prerequisites).

### Via TCP (when enabled)

When the optional TCP listener is enabled (see
[Using the TCP Listener](#using-the-tcp-listener) below), requests must
include a bearer token:

```bash
curl -s -H "Authorization: Bearer $(cat /etc/plexd/api-token)" \
  http://127.0.0.1:9100/v1/state
```

## Reading Node State

`GET /v1/state` returns a summary of everything the node currently holds:
metadata, data keys, secret keys, and report keys.

```bash
curl -s --unix-socket /var/run/plexd/api.sock http://localhost/v1/state | jq .
```

Example response:

```json
{
  "metadata": {
    "node_id": "edge-us-west-42",
    "region": "us-west-2",
    "role": "gateway"
  },
  "data_keys": [
    { "key": "nginx.conf", "version": 3, "content_type": "text/plain" }
  ],
  "secret_keys": [
    { "key": "tls/server.key", "version": 1 }
  ],
  "report_keys": [
    { "key": "health", "version": 5 }
  ]
}
```

## Reading Metadata

### List all metadata

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  http://localhost/v1/state/metadata | jq .
```

```json
{
  "node_id": "edge-us-west-42",
  "region": "us-west-2",
  "role": "gateway"
}
```

### Read a single metadata key

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  http://localhost/v1/state/metadata/region | jq .
```

```json
{
  "key": "region",
  "value": "us-west-2"
}
```

If the key does not exist the API returns `404`:

```json
{ "error": "not found" }
```

## Reading Data Entries

### List data keys

`GET /v1/state/data` returns a summary of each data entry (key, version,
content type) without the payload.

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  http://localhost/v1/state/data | jq .
```

```json
[
  { "key": "nginx.conf", "version": 3, "content_type": "text/plain" },
  { "key": "routes.json", "version": 1, "content_type": "application/json" }
]
```

### Read a single data entry

`GET /v1/state/data/{key}` returns the full entry including its payload.

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  http://localhost/v1/state/data/routes.json | jq .
```

```json
{
  "key": "routes.json",
  "content_type": "application/json",
  "payload": { "default_backend": "10.0.0.5:8080" },
  "version": 1,
  "updated_at": "2025-06-01T12:34:56Z"
}
```

## Reading Secrets

Secret access requires root or membership in the `plexd-secrets` group on
Linux and macOS, and an elevated Administrator or LocalSystem token on
Windows. Secrets are fetched from the control plane on demand and decrypted
locally using the node's secret key. They are never cached to disk.

Secret key names follow the grammar `^[a-z][a-z0-9_-]{0,62}$` — a
lowercase-leading name of at most 63 characters over `[a-z0-9_-]`. A forward
slash is outside the grammar, so secret keys never contain one and never need
URL-encoding.

### List available secret keys

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  http://localhost/v1/state/secrets | jq .
```

```json
[
  { "key": "tls_server_key", "version": 1 },
  { "key": "db_password", "version": 2 }
]
```

### Read a secret value

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  http://localhost/v1/state/secrets/db_password | jq .
```

```json
{
  "key": "db_password",
  "value": "s3cret-p@ssw0rd",
  "version": 2
}
```

By default the current version is returned. Pass `?version=N` (a positive
integer) to read a specific older version:

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  "http://localhost/v1/state/secrets/db_password?version=1" | jq .
```

The endpoint maps upstream failures to these statuses (the body is always
`{"error": "<message>"}`):

| Status | Error message               | Cause                                                         |
|--------|-----------------------------|--------------------------------------------------------------|
| `400`  | `invalid version`           | `?version` is not a positive integer                         |
| `400`  | `invalid secret key`        | Key is outside `^[a-z][a-z0-9_-]{0,62}$`                      |
| `403`  | `forbidden`                 | Node is not authorized to access this secret                 |
| `404`  | `not found`                 | The secret key — or the requested `?version` — does not exist |
| `429`  | `rate limited`              | Upstream fetch rate limit; a `Retry-After` header carries the wait in seconds |
| `503`  | `control plane unavailable` | Control plane unreachable                                    |

For example, an unreachable control plane returns `503`:

```json
{ "error": "control plane unavailable" }
```

## Managing Report Entries

Report entries are local key-value records that the node publishes back to
the control plane (e.g. health checks, inventory). They support optimistic
locking via the `If-Match` header.

Two limits mirror what the control plane accepts: the key must match
`^[a-z][a-z0-9._-]{0,127}$` (a lowercase-leading name of at most 128 characters
over `[a-z0-9._-]`), and the serialized `payload` must be at most 4096 bytes.
The `health` key used in the examples below conforms. Each key is synced upstream
independently — plexd flushes changed keys one at a time (`PUT`/`DELETE` per
key), so a rejected or oversized key never blocks the others.

### Create a report entry

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  -X PUT \
  -H "Content-Type: application/json" \
  http://localhost/v1/state/report/health \
  -d '{
    "content_type": "application/json",
    "payload": { "status": "healthy", "uptime_s": 86400 }
  }' | jq .
```

```json
{
  "key": "health",
  "content_type": "application/json",
  "payload": { "status": "healthy", "uptime_s": 86400 },
  "version": 1,
  "updated_at": "2025-06-01T13:00:00Z"
}
```

### Update with optimistic locking

Pass the current version in the `If-Match` header. The server rejects the
update with `409 Conflict` if the version does not match.

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  -X PUT \
  -H "Content-Type: application/json" \
  -H "If-Match: 1" \
  http://localhost/v1/state/report/health \
  -d '{
    "content_type": "application/json",
    "payload": { "status": "degraded", "uptime_s": 90000 }
  }' | jq .
```

On success the response contains the incremented version:

```json
{
  "key": "health",
  "content_type": "application/json",
  "payload": { "status": "degraded", "uptime_s": 90000 },
  "version": 2,
  "updated_at": "2025-06-01T13:05:00Z"
}
```

If the version does not match:

```json
{ "error": "version conflict" }
```

### Read a report entry

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  http://localhost/v1/state/report/health | jq .
```

### List all report keys

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  http://localhost/v1/state/report | jq .
```

```json
[
  { "key": "health", "version": 2 },
  { "key": "inventory", "version": 1 }
]
```

### Delete a report entry

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  -X DELETE \
  http://localhost/v1/state/report/health
```

A successful delete returns `204 No Content` with an empty body. If the key
does not exist the API returns `404`.

## Using the TCP Listener

By default the Local Node API is only accessible via the Unix socket. For
cases where a Unix socket is impractical (e.g. containers without shared
volumes), an optional TCP listener can be enabled.

### Enable TCP in the plexd configuration

Set `http_enabled` to `true` in the node API configuration. The default listen
address is `127.0.0.1:9100`.

| Field            | Default             | Description                         |
|------------------|---------------------|-------------------------------------|
| `http_enabled`   | `false`             | Enable the TCP listener             |
| `http_listen`    | `127.0.0.1:9100`   | TCP listen address                  |
| `http_token_file`| (none)              | Path to file containing the bearer token |

### Create a token file

Generate a token and store it in a file readable only by plexd:

```bash
openssl rand -base64 32 > /etc/plexd/api-token
chmod 600 /etc/plexd/api-token
```

### Making requests over TCP

Every TCP request must include the `Authorization: Bearer <token>` header.
The token value must match the contents of the configured token file exactly.

```bash
TOKEN=$(cat /etc/plexd/api-token)

# Read state
curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:9100/v1/state | jq .

# Write a report entry
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT \
  http://127.0.0.1:9100/v1/state/report/health \
  -d '{"content_type":"application/json","payload":{"status":"healthy"}}'
```

Requests without a token or with an invalid token receive `401 Unauthorized`:

```json
{ "error": "unauthorized" }
```

## Troubleshooting

| HTTP status | Error message                | Likely cause                                                  | Fix                                                                 |
|-------------|------------------------------|---------------------------------------------------------------|---------------------------------------------------------------------|
| 400         | `invalid JSON body`          | Request body is not valid JSON                                | Check your JSON syntax                                              |
| 400         | `content_type is required`   | PUT report missing `content_type` field                       | Include `"content_type"` in the request body                        |
| 400         | `payload must be valid JSON` | PUT report `payload` is empty or not valid JSON               | Ensure `"payload"` is a non-empty, valid JSON value                 |
| 400         | `invalid report key`         | Report key doesn't match `^[a-z][a-z0-9._-]{0,127}$`          | Use a lowercase-leading key of at most 128 chars over `[a-z0-9._-]` |
| 400         | `payload exceeds the 4096-byte limit` | Serialized report payload is larger than 4096 bytes | Shrink the payload below 4 KiB                                     |
| 400         | `If-Match must be an integer`| `If-Match` header is not a valid integer                      | Pass a numeric version (e.g. `If-Match: 3`)                         |
| 401         | `unauthorized`               | Missing or invalid bearer token on the TCP listener           | Pass `-H "Authorization: Bearer <token>"` with the correct token    |
| 403         | `forbidden: insufficient privileges for secret access` | Peer is not root or a `plexd-secrets` member (Linux, macOS), or not elevated / LocalSystem (Windows) | Add the user to `plexd-secrets` and re-login, or run from an elevated shell on Windows |
| 404         | `not found`                  | Key does not exist in metadata, data, secrets, or report      | Verify the key name; list available keys first                      |
| 409         | `version conflict`           | `If-Match` version does not match current version             | Re-read the entry, use the latest version in `If-Match`             |
| 503         | `control plane unavailable`  | Control plane unreachable when fetching a secret value         | Verify network connectivity; check plexd logs for details           |

If the socket file does not exist (`curl: (7) Couldn't connect to server`),
verify that plexd is running:

```bash
systemctl status plexd                              # Linux
launchctl print system/com.plexsphere.plexd         # macOS
sc query plexd                                      # Windows
```

## Reference

For the full API type definitions, configuration fields, and implementation
details, see the
[Local Node API Reference](../reference/core/nodeapi.md).
