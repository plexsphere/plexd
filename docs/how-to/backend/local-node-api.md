---
title: Using the Local Node API
quadrant: backend
package: internal/nodeapi
feature: PXD-0004
---

# Using the Local Node API

The Local Node API lets programs running on a plexd-managed node read node
state (metadata, data entries, secrets) and write report entries back to the
control plane. The API is served over a Unix domain socket by default and,
optionally, over TCP with bearer-token authentication.

This guide walks through common tasks. For a full reference of types and
internals, see [Local Node API Reference](../../reference/backend/nodeapi.md).

## Prerequisites

1. **plexd is running** on the node. The daemon creates the Unix socket on
   startup.

2. **Group membership** -- access to the socket is controlled by filesystem
   permissions:

   | Group            | Grants access to                      |
   |------------------|---------------------------------------|
   | `plexd`          | All endpoints except secret values    |
   | `plexd-secrets`  | Secret-value endpoints (`/v1/state/secrets/{key}`) |

   Add your user (or service account) to the appropriate group:

   ```bash
   sudo usermod -aG plexd myuser
   sudo usermod -aG plexd-secrets myuser   # only if secret access is needed
   ```

3. **curl** (or any HTTP client that supports `--unix-socket`).

## Connecting to the API

### Via Unix socket (default)

The socket path defaults to `/var/run/plexd/api.sock`. All examples in this
guide use this path.

```bash
curl -s --unix-socket /var/run/plexd/api.sock http://localhost/v1/state
```

No authentication header is required -- access is governed by socket file
permissions.

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

Secret access requires membership in the `plexd-secrets` group. Secrets are
fetched from the control plane on demand and decrypted locally using the
node's secret key. They are never cached to disk.

### List available secret keys

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  http://localhost/v1/state/secrets | jq .
```

```json
[
  { "key": "tls/server.key", "version": 1 },
  { "key": "db/password", "version": 2 }
]
```

### Read a secret value

```bash
curl -s --unix-socket /var/run/plexd/api.sock \
  http://localhost/v1/state/secrets/db%2Fpassword | jq .
```

> URL-encode forward slashes in key names (`/` becomes `%2F`).

```json
{
  "key": "db/password",
  "value": "s3cret-p@ssw0rd",
  "version": 2
}
```

If the control plane is unreachable the API returns `503`:

```json
{ "error": "control plane unavailable" }
```

## Managing Report Entries

Report entries are local key-value records that the node publishes back to
the control plane (e.g. health checks, inventory). They support optimistic
locking via the `If-Match` header.

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

Set `HTTPEnabled` to `true` in the node API configuration. The default listen
address is `127.0.0.1:9100`.

| Field           | Default             | Description                         |
|-----------------|---------------------|-------------------------------------|
| `HTTPEnabled`   | `false`             | Enable the TCP listener             |
| `HTTPListen`    | `127.0.0.1:9100`   | TCP listen address                  |
| `HTTPTokenFile` | (none)              | Path to file containing the bearer token |

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
| 400         | `If-Match must be an integer`| `If-Match` header is not a valid integer                      | Pass a numeric version (e.g. `If-Match: 3`)                         |
| 401         | `unauthorized`               | Missing or invalid bearer token on the TCP listener           | Pass `-H "Authorization: Bearer <token>"` with the correct token    |
| 403         | (connection refused)         | User not in the `plexd` (or `plexd-secrets`) group            | Add the user to the appropriate group and re-login                  |
| 404         | `not found`                  | Key does not exist in metadata, data, secrets, or report      | Verify the key name; list available keys first                      |
| 409         | `version conflict`           | `If-Match` version does not match current version             | Re-read the entry, use the latest version in `If-Match`             |
| 503         | `control plane unavailable`  | Control plane unreachable when fetching a secret value         | Verify network connectivity; check plexd logs for details           |

If the socket file does not exist (`curl: (7) Couldn't connect to server`),
verify that plexd is running:

```bash
systemctl status plexd
```

## Reference

For the full API type definitions, configuration fields, and implementation
details, see the
[Local Node API Reference](../../reference/backend/nodeapi.md).
