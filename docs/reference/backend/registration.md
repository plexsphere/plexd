---
title: Registration
quadrant: backend
package: internal/registration
feature: PXD-0002
---

# Registration

The `internal/registration` package handles node self-registration and bootstrap authentication with the Plexsphere control plane. It resolves a one-time bootstrap token, generates a Curve25519 keypair, registers with the control plane, persists the resulting identity, and manages auth token lifecycle.

## Config

`Config` holds registration parameters passed to the `Registrar` constructor. Config loading is the caller's responsibility.

| Field              | Type                | Default                        | Description                                |
|--------------------|---------------------|--------------------------------|--------------------------------------------|
| `DataDir`          | `string`            | —                              | Data directory for identity files (required)|
| `TokenFile`        | `string`            | `/etc/plexd/bootstrap-token`   | Path to bootstrap token file               |
| `TokenEnv`         | `string`            | `PLEXD_BOOTSTRAP_TOKEN`        | Environment variable for bootstrap token   |
| `TokenValue`       | `string`            | —                              | Direct token value override                |
| `UseMetadata`      | `bool`              | `false`                        | Enable cloud metadata token source         |
| `MetadataTokenPath`| `string`            | `/plexd/bootstrap-token`       | Metadata key path for bootstrap token      |
| `MetadataTimeout`  | `time.Duration`     | `5s`                           | Timeout for metadata service requests      |
| `Hostname`         | `string`            | —                              | Hostname override (default: `os.Hostname`)|
| `Metadata`         | `map[string]string` | —                              | Optional metadata for registration request |
| `MaxRetryDuration` | `time.Duration`     | `5m`                           | Maximum retry duration for transient errors|

```go
cfg := registration.Config{
    DataDir: "/var/lib/plexd",
}
cfg.ApplyDefaults() // sets TokenFile, TokenEnv, MetadataTokenPath, MetadataTimeout, MaxRetryDuration
if err := cfg.Validate(); err != nil {
    log.Fatal(err) // DataDir is required
}
```

## TokenResolver

Resolves the bootstrap token by checking sources in priority order. The first non-empty result wins.

### Source Priority

1. **Direct value** — `Config.TokenValue`
2. **File** — `Config.TokenFile` (content trimmed of whitespace)
3. **Environment variable** — `os.Getenv(Config.TokenEnv)` (trimmed)
4. **Metadata service** — via `MetadataProvider` interface (only if `Config.UseMetadata` is true)

### Token Validation

- Non-empty
- Maximum 512 bytes
- Printable ASCII only (bytes 0x20–0x7E)

### TokenResult

| Field      | Type     | Description                                    |
|------------|----------|------------------------------------------------|
| `Value`    | `string` | The resolved token value                       |
| `FilePath` | `string` | Non-empty if token was read from a file        |

`FilePath` is used by the `Registrar` to delete the token file after successful registration.

```go
resolver := registration.NewTokenResolver(&cfg, nil) // nil = no metadata provider
result, err := resolver.Resolve(ctx)
if err != nil {
    // error lists all attempted sources
}
```

### MetadataProvider

Pluggable interface for cloud-specific token resolution.

```go
type MetadataProvider interface {
    ReadToken(ctx context.Context) (string, error)
}
```

The concrete implementation `IMDSProvider` reads tokens from cloud instance metadata services. See [Cloud-Init VM Deployment Reference](cloud-init-vm-deployment.md) for details.

## GenerateKeypair

Generates a Curve25519 keypair for WireGuard mesh encryption.

- Private key: 32 random bytes from `crypto/rand`, clamped per Curve25519 spec
- Public key: derived via `curve25519.X25519(privateKey, Basepoint)`
- Private key never leaves the node and is never logged

```go
keypair, err := registration.GenerateKeypair()
if err != nil {
    log.Fatal(err)
}
pubKeyBase64 := keypair.EncodePublicKey() // standard base64, 44 characters
```

### Keypair

| Field        | Type     | Description                     |
|--------------|----------|---------------------------------|
| `PrivateKey` | `[]byte` | 32-byte clamped Curve25519 key  |
| `PublicKey`  | `[]byte` | 32-byte derived public key      |

## NodeIdentity

Holds the registration identity of a node after successful enrollment.

| Field              | Type     | JSON Tag             | Persisted To            |
|--------------------|----------|----------------------|-------------------------|
| `NodeID`           | `string` | `"node_id"`          | `identity.json`         |
| `MeshIP`           | `string` | `"mesh_ip"`          | `identity.json`         |
| `SigningPublicKey`  | `string` | `"signing_public_key"`| `identity.json` + `signing_public_key` |
| `PrivateKey`       | `[]byte` | `"-"` (excluded)     | `private_key` (base64)  |
| `NodeSecretKey`    | `string` | `"-"` (excluded)     | `node_secret_key`       |

### Data Directory Layout

```
{data_dir}/
├── identity.json        (0600) — NodeID, MeshIP, SigningPublicKey
├── private_key          (0600) — base64-encoded Curve25519 private key
├── node_secret_key      (0600) — bearer token for post-registration API calls
└── signing_public_key   (0600) — control plane signing public key
```

- Directory created with `0700` permissions if missing
- All files written atomically (temp file + fsync + rename)
- `PrivateKey` and `NodeSecretKey` use `json:"-"` tags to prevent accidental JSON serialization

### SaveIdentity / LoadIdentity

```go
// Persist after registration
err := registration.SaveIdentity("/var/lib/plexd", identity)

// Load on restart
identity, err := registration.LoadIdentity("/var/lib/plexd")
if errors.Is(err, registration.ErrNotRegistered) {
    // no identity files — need to register
}
```

## ErrNotRegistered

Sentinel error returned by `LoadIdentity` when identity files are absent from the data directory.

```go
var ErrNotRegistered = errors.New("registration: node is not registered")
```

Supports `errors.Is` matching:

```go
if errors.Is(err, registration.ErrNotRegistered) {
    // proceed with fresh registration
}
```

## Registrar

Orchestrates the complete registration lifecycle: check existing identity, resolve token, generate keypair, register with retries, persist identity, clean up token file, and set auth token.

### Constructor

```go
func NewRegistrar(client *api.ControlPlane, cfg Config, logger *slog.Logger) *Registrar
```

- Applies config defaults
- Logger tagged with `component=registration`
- Optional: call `SetMetadataProvider`, `SetCapabilities`, `SetClock` after construction

### Register

```go
func (r *Registrar) Register(ctx context.Context) (*NodeIdentity, error)
```

Orchestration flow:

1. **Load existing identity** — if valid, set auth token and return (idempotent)
2. **Corrupt identity** — log warning, proceed with fresh registration
3. **Resolve bootstrap token** — via `TokenResolver`
4. **Generate Curve25519 keypair**
5. **Resolve hostname** — `Config.Hostname` or `os.Hostname()`
6. **Set bootstrap token as auth** — `client.SetAuthToken(token)`
7. **POST /v1/register with retry** — exponential backoff on transient errors
8. **Build NodeIdentity** from response + private key
9. **Persist identity** atomically to data directory
10. **Delete token file** if token was file-based (failure logged, not fatal)
11. **Set node_secret_key as auth** — `client.SetAuthToken(nsk)`

### Retry Logic

Registration retries on transient failures using `api.ClassifyError` for error classification.

| Error Type              | Action                                    |
|-------------------------|-------------------------------------------|
| Network errors / 5xx    | Retry with exponential backoff            |
| 429 Rate Limited        | Respect `Retry-After` header              |
| 401 Unauthorized        | Fail immediately (invalid bootstrap token)|
| 403 Forbidden           | Fail immediately                          |
| 409 Conflict            | Fail immediately (hostname registered)    |
| 400 Bad Request         | Fail immediately                          |

Backoff parameters (consistent with `internal/api/ReconnectEngine`):

| Parameter         | Value  |
|-------------------|--------|
| Base interval     | 1s     |
| Multiplier        | 2x     |
| Max interval      | 60s    |
| Jitter            | ±25%   |
| Timeout           | `Config.MaxRetryDuration` (default 5m) |

### IsRegistered

```go
func (r *Registrar) IsRegistered() bool
```

Returns `true` if valid identity files exist in `Config.DataDir`.

### Usage Example

```go
// Create control plane client
cpClient, err := api.NewControlPlane(api.Config{
    BaseURL: "https://api.plexsphere.com",
}, "1.0.0", slog.Default())
if err != nil {
    log.Fatal(err)
}

// Create registrar
reg := registration.NewRegistrar(cpClient, registration.Config{
    DataDir:  "/var/lib/plexd",
    Hostname: "node-01",
    Metadata: map[string]string{"region": "us-east-1"},
}, slog.Default())

// Run registration (idempotent — skips if already registered)
identity, err := reg.Register(ctx)
if err != nil {
    log.Fatalf("registration failed: %v", err)
}

log.Printf("registered as %s with mesh IP %s", identity.NodeID, identity.MeshIP)
// Control plane client now has node_secret_key set as auth token
```

### Auth Token Lifecycle

| Phase                    | Auth Token Value        |
|--------------------------|-------------------------|
| Before registration      | Bootstrap token         |
| During POST /v1/register | Bootstrap token (Bearer)|
| After registration       | `NodeSecretKey`         |
| On restart (cached)      | `NodeSecretKey` from disk|
