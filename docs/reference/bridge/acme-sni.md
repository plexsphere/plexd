---
title: ACME and SNI Routing
package: internal/bridge
feature: PXD-0028
---

# ACME and SNI Routing

`ACMEManager` provides automatic TLS certificate management via the ACME protocol (Let's Encrypt). `SNIRouter` provides hostname-based TCP routing by peeking at TLS ClientHello SNI extensions. Both extend the bridge mode ingress capabilities in `internal/bridge`.

## Data Flow

```
Public Internet Clients
(HTTPS / TLS)
        |
        |  TLS ClientHello
        v
+---------------------------------------------------------------+
|                        Bridge Node                              |
|                                                                 |
|  +-------------------+         +-------------------+           |
|  |  SNIRouter        |  peek   |  Backend Services |           |
|  |  TCP Listener     |-------->|  (per SNI route)  |           |
|  |  :443             |  route  |  host:port        |           |
|  +-------------------+         +-------------------+           |
|         ^                                                       |
|         |                                                       |
|  TLS ClientHello                                                |
|  -> extractSNI (peek 1024 bytes)                                |
|  -> lookup route by hostname                                    |
|  -> dial backend                                                |
|  -> bidirectional io.Copy                                       |
|                                                                 |
|  +-------------------+         +-------------------+           |
|  |  IngressManager   |  ACME   |  ACMEManager      |           |
|  |  (mode="acme")    |-------->|  autocert.Manager  |           |
|  |  per-rule listener|  TLS    |  DirCache          |           |
|  +-------------------+         +-------------------+           |
|         ^                                                       |
|         |                                                       |
|  ACME mode:                                                     |
|  -> ACMEManager.TLSConfig()                                     |
|  -> GetCertificate delegates to autocert                        |
|  -> automatic issuance + renewal                                |
+-----------------------------------------------------------------+
```

SNIRouter accepts TCP connections, peeks at the TLS ClientHello to extract the SNI hostname, looks up the matching backend route, and proxies the full connection (including the replayed peeked bytes) to the backend via bidirectional `io.Copy`. ACMEManager integrates with IngressManager to provide automatic TLS termination for ingress rules using the `acme` mode.

## ACMEConfig

`ACMEConfig` holds configuration for automatic TLS certificate management via the ACME protocol.

```go
type ACMEConfig struct {
    Enabled          bool
    CacheDir         string
    AllowedHosts     []string
    Email            string
    ACMEDirectoryURL string
}
```

| Field              | Type       | Description                                                                 |
|--------------------|------------|-----------------------------------------------------------------------------|
| `Enabled`          | `bool`     | Whether ACME certificate management is active                               |
| `CacheDir`         | `string`   | Directory for caching certificates on disk (used by `autocert.DirCache`)    |
| `AllowedHosts`     | `[]string` | Whitelist of hostnames for which certificates may be obtained               |
| `Email`            | `string`   | Contact email for the ACME account (optional, used in registration)         |
| `ACMEDirectoryURL` | `string`   | Override for the ACME directory URL; empty means Let's Encrypt production   |

## ACMEManager

Manages automatic TLS certificate acquisition and renewal via the ACME protocol. Wraps `autocert.Manager` with `DirCache`, `HostWhitelist`, and certificate lifecycle management. Concurrent-safe via `sync.Mutex`.

### Constructor

```go
func NewACMEManager(cfg ACMEConfig, logger *slog.Logger) *ACMEManager
```

### Methods

| Method           | Signature                                                        | Description                                                                |
|------------------|------------------------------------------------------------------|----------------------------------------------------------------------------|
| `Setup`          | `() error`                                                       | Creates underlying `autocert.Manager`; no-op when disabled                 |
| `Teardown`       | `() error`                                                       | Idempotent cleanup, sets manager to nil                                    |
| `TLSConfig`      | `() *tls.Config`                                                 | Returns `tls.Config` with `GetCertificate`; nil when inactive              |
| `GetCertificate` | `(hello *tls.ClientHelloInfo) (*tls.Certificate, error)`         | Delegates to autocert; error if inactive                                   |
| `AllowedHosts`   | `() []string`                                                    | Returns copy of allowed hosts                                              |
| `Active`         | `() bool`                                                        | Reports active state                                                       |

### Lifecycle

```go
logger := slog.Default()

acmeMgr := bridge.NewACMEManager(bridge.ACMEConfig{
    Enabled:      true,
    CacheDir:     "/var/lib/plexd/acme",
    AllowedHosts: []string{"app.example.com", "api.example.com"},
    Email:        "admin@example.com",
}, logger)

// Setup — creates autocert.Manager with DirCache and HostWhitelist
if err := acmeMgr.Setup(); err != nil {
    log.Fatal(err)
}

// Check active state
acmeMgr.Active() // true

// Get TLS config for use with listeners
tlsCfg := acmeMgr.TLSConfig() // *tls.Config with GetCertificate, MinVersion TLS 1.2

// Retrieve allowed hosts (returns a copy)
hosts := acmeMgr.AllowedHosts() // ["app.example.com", "api.example.com"]

// Graceful shutdown
if err := acmeMgr.Teardown(); err != nil {
    logger.Warn("acme teardown failed", "error", err)
}
```

### Setup

When `Enabled` is `false`, `Setup` is a no-op. When enabled:

1. Validates `CacheDir` is non-empty
2. Validates `AllowedHosts` has at least one entry
3. Creates `autocert.Manager` with `Prompt: AcceptTOS`, `Cache: DirCache(CacheDir)`, `HostPolicy: HostWhitelist(AllowedHosts...)`
4. Sets `Email` on the autocert manager if non-empty
5. Sets a custom `acme.Client` with `DirectoryURL` if `ACMEDirectoryURL` is non-empty
6. Marks the manager as active

### Teardown

Idempotent cleanup: sets `active` to `false` and `manager` to `nil`. Calling `Teardown` when inactive returns `nil`.

### TLSConfig

Returns a `*tls.Config` with:

- `GetCertificate` set to the underlying `autocert.Manager.GetCertificate`
- `MinVersion` set to `tls.VersionTLS12`

Returns `nil` when the manager is not active.

### GetCertificate

Delegates to the underlying `autocert.Manager.GetCertificate`. Returns an error if the manager is not active.

## Config Fields for ACME

ACME fields extend the existing bridge `Config` struct. ACME requires ingress to be enabled (`IngressEnabled=true`).

| Field              | Type       | Default                     | Description                                        |
|--------------------|------------|-----------------------------|----------------------------------------------------|
| `ACMEEnabled`      | `bool`     | `false`                     | Requires `IngressEnabled=true`                     |
| `ACMECacheDir`     | `string`   | —                           | Required when ACME enabled                         |
| `ACMEAllowedHosts` | `[]string` | —                           | At least one required when ACME enabled            |
| `ACMEEmail`        | `string`   | —                           | Optional contact email                             |
| `ACMEDirectoryURL` | `string`   | Let's Encrypt production    | Optional, overrides the default ACME directory     |

```go
cfg := bridge.Config{
    Enabled:         true,
    AccessInterface: "eth1",
    AccessSubnets:   []string{"10.0.0.0/24"},
    IngressEnabled:  true,
    ACMEEnabled:     true,
    ACMECacheDir:    "/var/lib/plexd/acme",
    ACMEAllowedHosts: []string{"app.example.com"},
    ACMEEmail:       "admin@example.com",
}
cfg.ApplyDefaults()
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

### Validation Rules

ACME validation is skipped when `ACMEEnabled` is `false`. When enabled:

| Field              | Rule                              | Error Message                                                                  |
|--------------------|-----------------------------------|--------------------------------------------------------------------------------|
| `ACMEEnabled`      | Requires `IngressEnabled=true`    | `bridge: config: ACME requires ingress to be enabled`                          |
| `ACMECacheDir`     | Must not be empty when enabled    | `bridge: config: ACMECacheDir is required when ACME is enabled`                |
| `ACMEAllowedHosts` | At least one required when enabled| `bridge: config: at least one ACMEAllowedHosts is required when ACME is enabled`|

## ACME Ingress Mode

ACME integrates with `IngressManager` to provide automatic TLS certificate management for ingress rules.

### Constructor

The `IngressManager` constructor accepts an optional `*ACMEManager` parameter:

```go
func NewIngressManager(ctrl IngressController, cfg Config, logger *slog.Logger, acme *ACMEManager) *IngressManager
```

The `acme` parameter may be `nil` when ACME is not used.

### AddRule with ACME Mode

When `AddRule` receives a rule with `Mode: "acme"`:

1. Validates that `ACMEManager` is not nil (`ACME mode requires ACMEManager`)
2. Validates that `Hostname` is non-empty (`hostname is required for ACME mode`)
3. Calls `acme.TLSConfig()` to get the ACME-backed TLS configuration
4. Validates that the returned `tls.Config` is not nil (`ACME manager is not active`)
5. Creates the listener with the ACME TLS config

### IngressRule Hostname Field

The `api.IngressRule` type includes a `Hostname` field used by the ACME mode:

```go
type IngressRule struct {
    RuleID     string `json:"rule_id"`
    ListenPort int    `json:"listen_port"`
    TargetAddr string `json:"target_addr"`
    Mode       string `json:"mode"`
    CertPEM    string `json:"cert_pem,omitempty"`
    KeyPEM     string `json:"key_pem,omitempty"`
    Hostname   string `json:"hostname,omitempty"`
}
```

### TLS Modes

| Mode          | Behavior                                                                           |
|---------------|------------------------------------------------------------------------------------|
| `passthrough` | Raw TCP bytes forwarded without decryption; no certificates required               |
| `terminate`   | Bridge performs TLS handshake with static `CertPEM`/`KeyPEM`; plaintext forwarded  |
| `acme`        | Bridge performs TLS handshake with automatic ACME certificate; plaintext forwarded  |

All TLS modes enforce minimum TLS 1.2 via `tls.Config.MinVersion`.

### ACME Ingress Lifecycle

```go
// Create ACME manager
acmeMgr := bridge.NewACMEManager(bridge.ACMEConfig{
    Enabled:      true,
    CacheDir:     "/var/lib/plexd/acme",
    AllowedHosts: []string{"app.example.com"},
}, logger)
if err := acmeMgr.Setup(); err != nil {
    log.Fatal(err)
}

// Create ingress manager with ACME support
ingressMgr := bridge.NewIngressManager(ingressCtrl, cfg, logger, acmeMgr)
if err := ingressMgr.Setup(); err != nil {
    log.Fatal(err)
}

// Add an ACME-mode ingress rule
err := ingressMgr.AddRule(api.IngressRule{
    RuleID:     "web-acme",
    ListenPort: 443,
    TargetAddr: "10.42.0.5:8080",
    Mode:       "acme",
    Hostname:   "app.example.com",
})

// Graceful shutdown
ingressMgr.Teardown()
acmeMgr.Teardown()
```

## SNIRoute

`SNIRoute` maps an SNI hostname to a backend TCP address.

```go
type SNIRoute struct {
    Hostname    string // SNI hostname to match (exact match, lowercase)
    BackendAddr string // TCP address to forward to (host:port)
}
```

| Field         | Description                                                |
|---------------|------------------------------------------------------------|
| `Hostname`    | SNI hostname to match; stored and matched as lowercase     |
| `BackendAddr` | TCP address to forward the connection to (host:port)       |

## SNIRouter

Accepts TCP connections, peeks at the TLS ClientHello to extract the SNI hostname, and routes connections to the appropriate backend. Concurrent-safe via `sync.Mutex`. Active proxy connections are tracked via `atomic.Int64` for lock-free counting.

### Constructor

```go
func NewSNIRouter(dialTimeout time.Duration, logger *slog.Logger) *SNIRouter
```

### Methods

| Method        | Signature                     | Description                                                    |
|---------------|-------------------------------|----------------------------------------------------------------|
| `Start`       | `(ln net.Listener) error`     | Begins accepting connections on the given listener             |
| `Stop`        | `() error`                    | Idempotent; cancels accept loop, waits for goroutine exit      |
| `Active`      | `() bool`                     | Reports active state                                           |
| `ConnCount`   | `() int64`                    | Returns active proxy connection count; lock-free via atomic    |
| `AddRoute`    | `(route SNIRoute) error`      | Rejects empty hostname/backend; overwrites existing            |
| `RemoveRoute` | `(hostname string) error`     | Idempotent; removing non-existent route returns nil            |
| `Routes`      | `() []SNIRoute`               | Returns sorted copy of all routes                              |

### Lifecycle

```go
logger := slog.Default()

router := bridge.NewSNIRouter(10*time.Second, logger)

// Start accepting connections
ln, _ := net.Listen("tcp", ":443")
if err := router.Start(ln); err != nil {
    log.Fatal(err)
}

// Add SNI routes
router.AddRoute(bridge.SNIRoute{
    Hostname:    "app.example.com",
    BackendAddr: "10.42.0.5:443",
})
router.AddRoute(bridge.SNIRoute{
    Hostname:    "api.example.com",
    BackendAddr: "10.42.0.6:8443",
})

// Query state
router.Active()    // true
router.ConnCount() // 0 (no active connections yet)
router.Routes()    // [{api.example.com 10.42.0.6:8443} {app.example.com 10.42.0.5:443}]

// Remove a route
router.RemoveRoute("api.example.com")

// Graceful shutdown
if err := router.Stop(); err != nil {
    logger.Warn("sni router stop failed", "error", err)
}
```

### Start

Begins accepting connections on the given `net.Listener`. Spawns an `acceptLoop` goroutine with a cancellable context. Marks the router as active.

### Stop

Idempotent: if not active, returns `nil`. When active:

1. Cancels the accept loop context
2. Closes the listener
3. Clears all routes
4. Waits for the accept loop goroutine to exit (via `done` channel)

### AddRoute

1. Rejects if router is not active (`bridge: sni: router is not active`)
2. Rejects empty hostname (`bridge: sni: empty hostname`)
3. Rejects empty backend address (`bridge: sni: empty backend address`)
4. Normalizes hostname to lowercase
5. Stores the route; overwrites any existing route for the same hostname

### RemoveRoute

Idempotent: removing a non-existent hostname returns `nil`. Normalizes hostname to lowercase before lookup.

### Routes

Returns a copy of all routes, sorted alphabetically by hostname.

## SNI Extraction

The `extractSNI` function parses a TLS ClientHello record from the peeked bytes and returns the SNI hostname. Returns an empty string if the data is not a valid ClientHello or does not contain an SNI extension.

### Peek Size

```go
const sniPeekSize = 1024
```

Up to 1024 bytes are read from the connection to extract the SNI hostname.

### Parse Sequence

1. **TLS record header** (5 bytes): type(1) + version(2) + length(2). Requires `type == 0x16` (handshake).
2. **Handshake header** (4 bytes): type(1) + length(3). Requires `type == 0x01` (ClientHello).
3. **ClientHello body**: skips version(2) + random(32).
4. **Session ID**: reads length(1), skips `length` bytes.
5. **Cipher suites**: reads length(2), skips `length` bytes.
6. **Compression methods**: reads length(1), skips `length` bytes.
7. **Extensions**: reads total length(2), then iterates extension entries.
8. **SNI extension** (type `0x0000`): parses the SNI list for an entry with `host_name` type (`0x00`).
9. Returns the hostname as a lowercase string.

At any point, if the data is too short or the structure is invalid, an empty string is returned.

### peekConn

The `peekConn` wrapper uses `io.MultiReader` to prepend the already-read bytes before the underlying connection, so the peeked TLS ClientHello bytes are replayed to the backend:

```go
type peekConn struct {
    net.Conn
    reader io.Reader
}

func newPeekConn(conn net.Conn, peeked []byte) *peekConn {
    return &peekConn{
        Conn:   conn,
        reader: io.MultiReader(bytes.NewReader(peeked), conn),
    }
}
```

## TCP Proxy

### Connection Handling

The `handleConnection` method processes each accepted connection:

1. Peeks up to `sniPeekSize` (1024) bytes from the connection
2. Calls `extractSNI` to parse the TLS ClientHello and extract the hostname
3. Looks up the route by hostname in the routes map
4. Dials the backend address with the configured `dialTimeout`
5. Wraps the client connection with `peekConn` to replay the peeked bytes
6. Runs two `io.Copy` goroutines for bidirectional relay
7. On context cancellation or either copy finishing, closes both connections

### Connection Counting

The `connCount` is tracked via `atomic.Int64`:

- Incremented in `acceptLoop` when a connection is accepted
- Decremented in `handleConnection` on exit (via `defer`)
- Read lock-free via `ConnCount()` which calls `connCount.Load()`

## Error Prefixes

| Source                                | Prefix                                                       |
|---------------------------------------|--------------------------------------------------------------|
| `ACMEManager.Setup` (cache dir)       | `bridge: acme: cache directory must be set`                  |
| `ACMEManager.Setup` (hosts)           | `bridge: acme: at least one allowed host is required`        |
| `ACMEManager.GetCertificate`          | `bridge: acme: manager is not active`                        |
| `SNIRouter.AddRoute` (not active)     | `bridge: sni: router is not active`                          |
| `SNIRouter.AddRoute` (hostname)       | `bridge: sni: empty hostname`                                |
| `SNIRouter.AddRoute` (backend)        | `bridge: sni: empty backend address`                         |
| `IngressManager.AddRule` (acme nil)   | `bridge: ingress: rule <id>: ACME mode requires ACMEManager` |
| `IngressManager.AddRule` (hostname)   | `bridge: ingress: rule <id>: hostname is required for ACME mode` |
| `IngressManager.AddRule` (inactive)   | `bridge: ingress: rule <id>: ACME manager is not active`     |
| Config validation (ACME + ingress)    | `bridge: config: ACME requires ingress to be enabled`        |
| Config validation (cache dir)         | `bridge: config: ACMECacheDir is required when ACME is enabled` |
| Config validation (allowed hosts)     | `bridge: config: at least one ACMEAllowedHosts is required when ACME is enabled` |

## Logging

All log entries use `component=bridge`.

| Level   | Event                          | Keys                                          |
|---------|--------------------------------|-----------------------------------------------|
| `Info`  | ACME manager started           | `cache_dir`, `allowed_hosts`                  |
| `Info`  | ACME manager stopped           | (none)                                        |
| `Info`  | SNI router started             | `addr`                                        |
| `Info`  | SNI router stopped             | (none)                                        |
| `Info`  | SNI route added                | `hostname`, `backend`                         |
| `Info`  | SNI route removed              | `hostname`                                    |
| `Warn`  | No SNI hostname found          | `remote`                                      |
| `Warn`  | No route for hostname          | `hostname`, `remote`                          |
| `Error` | Dial backend failed            | `hostname`, `backend`, `error`                |
