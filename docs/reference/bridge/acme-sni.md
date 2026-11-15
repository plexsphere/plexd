---
title: ACME and SNI Routing
package: internal/bridge
feature: PXD-0028
---

# ACME and SNI Routing

`ACMEManager` provides TLS certificate management through the ACME protocol (Let's Encrypt) from the local `bridge.acme_*` settings. SNI routing lets several [public ingress](public-ingress.md) rules share one listen port: the bridge reads the server name of each connection's TLS ClientHello and routes the connection to the rule whose host matches. Both live in `internal/bridge`.

## Data Flow

```
Public Internet Clients
(HTTPS / TLS)
        |
        |  TLS ClientHello
        v
+------------------------------------------------------------------+
|                          Bridge Node                             |
|                                                                  |
|  IngressManager: one listener per SNI port (:443)                |
|    -> peekClientHello: crypto/tls parses the hello,              |
|       at most 16 KiB and 5 s, nothing is answered                |
|    -> ingressTable.match(server name):                           |
|       exact host first, then a wildcard of one label             |
|    -> served passthrough rule: dial the target, replay           |
|       the peeked bytes, copy both ways                           |
|    -> no rule, no server name, or a held terminate/acme          |
|       rule: close the connection                                 |
|                                                                  |
|  ACMEManager (bridge.acme_*): autocert.Manager with DirCache     |
|    serves no ingress rule yet                                    |
+------------------------------------------------------------------+
```

When a rule's target is on a mesh peer, the bridge's dial to it is traffic the bridge itself sends over the mesh, which its compiled policy governs (see [What the rules govern](../networking/pf-wfp-firewall.md#what-the-rules-govern)). The policy therefore needs a rule that allows TCP from the bridge's mesh IP to the target's address and port. A Project's allow-all policy covers every mesh address. Without such a rule the dial fails, and the bridge logs `bridge: ingress: dial target failed`.

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

An ingress rule with `mode: acme` is held and not served. The agent contract says a bridge serves neither `terminate` nor `acme` until the `bridge.ingress` block names where the certificate comes from, and the block does not name it yet. The rule keeps its `(listen_port, sni_host)` slot, so a wildcard `passthrough` rule never takes its host, and a connection for its host is closed with the reason `rule_not_served`. Its state reads `mode_not_served`, and a port whose rules are all `terminate` or `acme` opens no listener (see [The Listener Plan](public-ingress.md#the-listener-plan)).

`ACMEManager` and the `bridge.acme_*` settings stay as they are and serve no rule. `NewIngressManager` still takes the optional `*ACMEManager`:

```go
func NewIngressManager(ctrl IngressController, cfg Config, logger *slog.Logger, acme *ACMEManager) *IngressManager
```

It only sets `ACMEEnabled` in `IngressStatus()`.

## ClientHello Peeking

```go
const sniPeekLimit = 16 << 10
const sniPeekTimeout = 5 * time.Second

func peekClientHello(conn net.Conn, timeout time.Duration) (serverName string, peeked []byte, err error)
```

`peekClientHello` reads the client's TLS ClientHello without answering it and returns its server name and every byte it read:

1. It sets a read deadline of `timeout` on the connection; the manager passes `sniPeekTimeout`.
2. It runs `tls.Server(rec, cfg).Handshake()` over a wrapper that records every byte it reads and discards every write, so the client receives nothing.
3. `cfg.GetConfigForClient` stores `hello.ServerName` and returns the sentinel `errClientHelloPeeked`, which stops the handshake. A handshake error that wraps the sentinel is a successful peek.
4. The wrapper fails a read with `errSNIPeekLimit` once it has recorded more than `sniPeekLimit` bytes.
5. On success it clears the read deadline.

`crypto/tls` parses the hello, so a hello that spans several reads or TLS records, and a server name behind any other extension, are read in full. A ClientHello of Go 1.26 with its default key shares is 1,505 bytes.

| Client | Result |
|---|---|
| A ClientHello with SNI, whole or in pieces | The server name and the recorded bytes, nil error |
| A ClientHello without SNI | An empty server name, nil error |
| Bytes that are not TLS, such as `GET / HTTP/1.1` | An error for which `errors.As` finds `tls.RecordHeaderError` |
| Nothing within the timeout | A `net.Error` with `Timeout()` |
| A connection closed at once | An error for which `errors.Is(err, io.EOF)` holds |
| A handshake message larger than 16 KiB | An error for which `errors.Is(err, errSNIPeekLimit)` holds |

The bytes come back on an error too. The manager closes the connection on any error and replays the bytes to the target on success through `peekConn`, which uses `io.MultiReader` to prepend them to the connection:

```go
func newPeekConn(conn net.Conn, peeked []byte) *peekConn
```

## Host Matching

Each SNI port has an `ingressTable` with an exact map by lowercase host and a wildcard map by the suffix after `*.`. `match` lowercases the server name, returns the exact route when one exists, and otherwise cuts the name at its first dot and looks the rest up in the wildcard map:

| Rules on the port | Server name | Route |
|---|---|---|
| `api.example.com`, `*.example.com` | `api.example.com` | `api.example.com`: an exact host wins |
| `*.example.com` | `a.example.com`, `A.EXAMPLE.COM` | `*.example.com` |
| `*.example.com` | `example.com` | none |
| `*.example.com` | `a.b.example.com` | none: the `*` stands for one label |
| any | empty | none |

A connection without a route is closed (see [Routing a Connection](public-ingress.md#routing-a-connection)).

## Error Prefixes

| Source                                | Prefix                                                       |
|---------------------------------------|--------------------------------------------------------------|
| `ACMEManager.Setup` (cache dir)       | `bridge: acme: cache directory must be set`                  |
| `ACMEManager.Setup` (hosts)           | `bridge: acme: at least one allowed host is required`        |
| `ACMEManager.GetCertificate`          | `bridge: acme: manager is not active`                        |
| `peekClientHello` (limit)             | `bridge: ingress: client hello exceeds the peek limit`       |
| Config validation (ACME + ingress)    | `bridge: config: ACME requires ingress to be enabled`        |
| Config validation (cache dir)         | `bridge: config: ACMECacheDir is required when ACME is enabled` |
| Config validation (allowed hosts)     | `bridge: config: at least one ACMEAllowedHosts is required when ACME is enabled` |

## Logging

All log entries use `component=bridge`.

| Level   | Event                          | Keys                                          |
|---------|--------------------------------|-----------------------------------------------|
| `Info`  | ACME manager started           | `cache_dir`, `allowed_hosts`                  |
| `Info`  | ACME manager stopped           | (none)                                        |
| `Debug` | `ingress connection closed`    | `listen_port`, `remote`, `server_name`, `reason` (`no_client_hello`, `no_server_name`, `no_matching_rule`, `rule_not_served`) |

The ingress manager's other log lines are listed in [Public Ingress](public-ingress.md#logging).
