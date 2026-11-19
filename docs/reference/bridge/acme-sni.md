---
title: ACME and SNI Routing
package: internal/bridge
feature: PXD-0028
---

# ACME and SNI Routing

`ACMEManager` obtains and renews the certificates of the `acme` rules of the [public ingress](public-ingress.md) block through the ACME protocol (RFC 8555), at the directory and with the contact the block's `acme` member names. It proves control of a host with the TLS-ALPN-01 challenge (RFC 8737) on port 443. SNI routing lets several rules share one listen port: the bridge reads the server name of each connection's TLS ClientHello and routes the connection to the rule whose host matches. On a host whose `terminate` or `acme` rules have request conditions, the bridge then hands each request to one of them (see [Routing a Request](public-ingress.md#routing-a-request)). Both live in `internal/bridge`.

## Data Flow

![Public internet clients over HTTPS or TLS, and the ACME CA for TLS-ALPN-01, send a TLS ClientHello to IngressManager, which runs one listener per SNI port (:443). peekClientHello parses the hello with crypto/tls, reading at most 16 KiB for at most 5 s and answering nothing, and returns the server name and the offered ALPN. ingressTable.match then looks up the server name, the exact host first, then a wildcard of one label. Three paths leave the match. A TLS-ALPN-01 challenge, a hello on :443 whose ALPN is exactly acme-tls/1 for a host of the ACME account that no rule or an acme rule matched, is answered and then closed. A passthrough rule dials the target, replays the peeked bytes and copies both ways. A terminate or acme rule completes a TLS handshake at the bridge, then copies the plaintext to the target or, on a host whose rules have conditions, routes each request. Three stages close the connection: the peek for no ClientHello or no server name, the match for no rule or a rule with a reason, and the termination for no certificate or a failed TLS handshake. ACMEManager runs one autocert.Manager per account, keeps the DirCache in the acme directory of the data directory, and sends HTTPS to the block's directory_url at the ACME CA.](../../diagrams/bridge-acme-sni-routing.svg)

When a rule's target is on a mesh peer, the bridge's dial to it is traffic the bridge itself sends over the mesh, which its compiled policy governs (see [What the rules govern](../networking/pf-wfp-firewall.md#what-the-rules-govern)). The policy therefore needs a rule that allows TCP from the bridge's mesh IP to the target's address and port. A Project's allow-all policy covers every mesh address. Without such a rule the dial fails, and the bridge logs `bridge: ingress: dial target failed`.

## The ACME Account

The block's `acme` member names the account the `acme` rules share: `directory_url` and an optional `contact_email`. The control plane sends it exactly when the block holds an `acme` rule. An `acme` rule needs no local switch. The bridge host only bounds the directories it accepts, with `bridge.acme_directory_urls` (see [Local Configuration](#local-configuration)).

`Apply` checks the member once per block:

```go
type acmeAvailability struct{ Reason, Detail string }

func checkACMEDirectory(settings *api.IngressACME, allowed []string) acmeAvailability

func ValidACMEDirectoryURL(s string) bool
```

| Case | Reason | Detail |
|---|---|---|
| `settings` is nil, or `DirectoryURL` is not an absolute https URL: `url.Parse` fails, the scheme is not `https`, the host is empty, or the URL carries user information | `acme_directory_invalid` | the URL |
| `allowed` is not empty and holds no entry equal to the URL, after `strings.TrimSpace` on both | `acme_directory_not_allowed` | the URL |
| otherwise | none | |

An empty `Reason` means the bridge can use ACME. A reason goes to every `acme` rule of the block, which keeps its slot and is not served (see [The Listener Plan](public-ingress.md#the-listener-plan)). `ValidACMEDirectoryURL` carries the URL rule, and `Config.Validate` uses it for `bridge.acme_directory_urls`.

The control plane checks only that `directory_url` is an https URL, so a holder of `manage` on the bridge Resource decides where the bridge sends its ACME requests. `bridge.acme_directory_urls` is the bridge host's bound on that decision.

## ACMEConfig

```go
type ACMEConfig struct {
    CacheDir string
    // HTTPTransport carries the ACME requests; nil means http.DefaultTransport.
    HTTPTransport http.RoundTripper
}
```

| Field           | Type                | Description |
|-----------------|---------------------|-------------|
| `CacheDir`      | `string`            | The directory `autocert.DirCache` keeps the account key and the certificates in (see [The Cache Directory](#the-cache-directory)) |
| `HTTPTransport` | `http.RoundTripper` | Carries the ACME requests; nil means `http.DefaultTransport` |

`ACMEConfig.Enabled`, `AllowedHosts`, `Email` and `ACMEDirectoryURL` are removed: the block names the hosts, the contact and the directory.

## ACMEManager

```go
func NewACMEManager(cfg ACMEConfig, logger *slog.Logger) *ACMEManager

// Configure sets the account and the hosts certificates may be requested for.
// nil settings or no hosts retire the account.
func (m *ACMEManager) Configure(settings *api.IngressACME, hosts []string)
func (m *ACMEManager) HasHost(serverName string) bool
func (m *ACMEManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
func (m *ACMEManager) Active() bool
func (m *ACMEManager) Issued(host string) bool
func (m *ACMEManager) OnIssuedChange(fn func())
func (m *ACMEManager) Teardown() error
```

| Method           | Description |
|------------------|-------------|
| `Configure`      | Sets the account and the host set, and builds, keeps or replaces the `autocert.Manager` (see [Configure](#configure)). nil settings or no hosts retire the account |
| `HasHost`        | Whether the server name is a host of the active account; false when no account is active |
| `GetCertificate` | The certificate for a ClientHello, from the active `autocert.Manager`, which also answers the TLS-ALPN-01 challenge; `bridge: acme: no account is configured` when no manager is active |
| `Active`         | Whether an account is active: true exactly while the last `IngressManager.Apply` ended with an `acme` rule without a reason. An `acme` rule whose port failed to bind reads `listen_failed` and does not count |
| `Issued`         | Whether an account is active and the last certificate request for the host, in any case, succeeded; see below |
| `OnIssuedChange` | Registers the function called when a request changes whether a host of the active account is issued. `NewIngressManager` registers the signal of its `ReportChanged` |
| `Teardown`       | Retires the active manager and waits at most 10 s for the certificate requests in flight (see [Teardown](#teardown)); idempotent, returns nil |

After each call into `autocert`, or into the test hook that replaces it, for a ClientHello that is no TLS-ALPN-01 challenge (its `SupportedProtos` do not hold `acme-tls/1`), the manager records the outcome on the account: a certificate marks the lowercase server name issued, an error unmarks it. Both the obtain ahead of the first client and every client handshake count; a challenge hello does not. When the set changed and the account is still the active one, the manager calls the registered function outside its lock. A new account starts with no host issued, so a changed directory reads `acme_not_issued` until the certificate is obtained again, from the cache directory or the CA. The [ingress status report](public-ingress.md#rule-entries) reads `Issued` for an `acme` rule's certificate: `ready` while it is true, and `not_ready` with `acme_not_issued` otherwise. A host whose obtain failed stays `acme_not_issued` until a client's handshake makes `autocert` ask again and succeed: the bridge does not retry an issuance on its own.

`Setup`, `TLSConfig` and `AllowedHosts` are removed. In bridge mode `plexd up` builds the manager unless the bridge opts out of public ingress with `bridge.ingress_enabled: false`, as `bridge.NewACMEManager(bridge.ACMEConfig{CacheDir: dir}, logger)`, and hands it to `NewIngressManager`. A bridge that opts out builds neither manager (see [Activation](public-ingress.md#activation)). The manager holds no account until a state pull's block names an `acme` rule. `IngressManager.Apply` calls `Configure` after it binds the ports, with the block's `acme` member and the hosts of the `acme` rules that end the `Apply` without a reason. An `acme` rule whose port failed to bind (`listen_failed`) does not keep the account, and port 443 is bound before the account asks the CA for a certificate (see [Applying the Block](public-ingress.md#applying-the-block)). The ingress manager is torn down before the ACME manager.

### Configure

`Configure` stores the hosts in lowercase and builds a new `autocert.Manager` when none is active, when `DirectoryURL` or `ContactEmail` differ from the active one's, or when a host of the active one left the set. A host that only joins keeps the manager. The new manager has:

- `Prompt: autocert.AcceptTOS`: the bridge accepts the CA's terms of service when it registers the account;
- `Cache: autocert.DirCache(cfg.CacheDir)`;
- `Email: settings.ContactEmail`;
- `HostPolicy` bound to the stored host set (see [The Host Policy](#the-host-policy));
- `Client: &acme.Client{DirectoryURL: settings.DirectoryURL, HTTPClient: ...}`, over a gate transport in front of `HTTPTransport`.

It logs `acme account configured` with `directory_url`, `contact`, a bool that is never the address, and `hosts`, the count of hosts.

### Retired Managers

`autocert` cannot change its directory or stop a renewal: its `stopRenew` is unexported. So the manager is replaced when the settings change or a host leaves, and the replaced manager is retired. Its gate fails every request with `errACMERetired` (`bridge: acme: the account settings were replaced`), so no request of a retired manager reaches the network, and its client stops retrying: an issuance the retired manager still runs ends at its next request instead of waiting for a retry. Its renewal timers stay armed, one per certificate it had loaded, and fail at the gate. What a retired manager leaves behind is idle timers. `Configure` without hosts and `Teardown` retire the active manager the same way.

A changed `directory_url` applies to the certificates obtained from then on: a cached certificate keeps serving until its renewal. A changed `contact_email` applies to an account the bridge registers from then on, because `autocert` registers once per account key and the key stays in the cache.

### Request Retries

The account's `acme.Client` repeats a request whose response the `acme` package counts as retryable: a server error (5xx), `429 Too Many Requests`, `400 Bad Request` for a bad nonce, and a status below 400 the request did not expect. Any other client error (4xx) ends the request at once. The bridge sets how long the client waits before it repeats one:

| Retryable response | Next request |
|---|---|
| No `Retry-After` header | After 1 s, doubling with each further retry to at most 10 s |
| A `Retry-After` of at most 10 s | After the `Retry-After` |
| A `Retry-After` of more than 10 s (`acmeMaxRetryWait`) | None: the attempt ends with the CA's error instead of sleeping |
| Any, once the manager is retired | None: the client stops retrying |

An attempt that ends this way fails the issuance it belongs to. The next client handshake asks `autocert` again, and `autocert` waits a minute after a failed issuance before it orders again (see [Obtaining a Certificate](#obtaining-a-certificate)). A rate limit of the CA, whose `Retry-After` can run to hours, therefore leaves no request asleep.

### Teardown

`Teardown` retires the active manager the way a replacement does, and then waits for the certificate requests in flight for at most 10 s (`acmeTeardownWait`). When that bound ends the wait, it logs `bridge: acme: certificate requests still running after teardown` at Warn and returns; the requests still running are cut off at the retired gate. `Teardown` is idempotent and returns nil.

### The Host Policy

The host policy admits exactly the hosts `Configure` stored, compared in lowercase, and refuses any other name with `bridge: acme: "<name>" is not the sni_host of an acme rule`. The hosts are the `sni_host` of the `acme` rules that end the `Apply` without a reason. The plan has already refused an `acme` rule whose host starts with `*.` or has one label (`invalid_rule`, detail `sni_host`): TLS-ALPN-01 cannot prove a wildcard, and `autocert` refuses a name without a dot.

### Obtaining a Certificate

For each host new to the active manager, `Configure` starts a goroutine that obtains the certificate ahead of the first client. It calls `GetCertificate` with a ClientHello that names the host and offers ECDSA P-256 (`SignatureSchemes: ECDSAWithP256AndSHA256`, `SupportedCurves: CurveP256`, `CipherSuites: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`), the variant `autocert` gives a current client. It logs `ingress certificate obtained` with `sni_host` and `not_after`, or `bridge: acme: obtain certificate failed` at Error with `sni_host` and `error`. A result that arrives after the manager was retired is dropped.

A client handshake for a host whose certificate is still being issued waits for it, within the 10 s bound of the handshake (`ingressHandshakeTimeout`, see [TLS Termination](public-ingress.md#tls-termination)). When the certificate is not ready by then, the bridge closes that client with `tls_handshake_failed`, and `autocert` finishes the issuance in the background, so a later handshake gets the certificate.

There is no retry loop for a failed issuance. The next client handshake asks `autocert` again, and `autocert` waits a minute after a failed issuance before it orders again for that host (`createCertRetryAfter`); a handshake within that minute fails at once with `tls_handshake_failed`. How a single request of the account is retried is described in [Request Retries](#request-retries).

### GetCertificate

`GetCertificate` delegates to the active `autocert.Manager` and returns `bridge: acme: no account is configured` when no manager is active. An unexported field `getCertificate`, nil in production, replaces the `autocert` call in tests.

## The Challenge on Port 443

The CA validates a host by connecting to port 443 of the name and offering the ALPN protocol `acme-tls/1` (RFC 8737). HTTP-01 and DNS-01 are not served. The bridge answers the challenge inside its listener for port 443:

- A ClientHello on port 443 whose ALPN list is exactly `["acme-tls/1"]`, for a server name `HasHost` knows, is a challenge when the port's table has no route for the name or routes it to an `acme` rule. The bridge completes the handshake with `tls.Server` over `newPeekConn(conn, peeked)` and its own `&tls.Config{GetCertificate: m.acme.GetCertificate, NextProtos: []string{acme.ALPNProto}, MinVersion: tls.VersionTLS12}`, within the 10 s handshake bound (`ingressHandshakeTimeout`). `autocert` returns the challenge certificate for such a hello. The bridge logs `ingress acme challenge answered` at Debug and closes the connection. No target is dialed.
- The same hello for the host of a `passthrough` rule is forwarded to that rule's target like any other connection, so a target that runs its own ACME client keeps working.
- The same hello for a host the account does not hold is no challenge, and is routed or closed like any other connection.

The challenge gets its own `tls.Config` because a terminating host offers no ALPN protocol, or `h2` and `http/1.1` when its rules have request conditions (see [TLS Termination](public-ingress.md#tls-termination)), and a server whose only protocol is `acme-tls/1` fails the handshake of an ordinary client with `tls: no application protocol`. The bridge chooses the configuration from the peeked ClientHello, before it reads any request, so an `acme` host whose rules have conditions answers its challenges as one without.

When at least one `acme` rule has no reason and no rule listens on port 443, the plan adds an empty table for port 443, and `Apply` opens the port for challenges alone. Every other connection to it is closed (see [Routing a Connection](public-ingress.md#routing-a-connection)). `Apply` binds the ports before it calls `Configure`, so port 443 listens before the account asks the CA for a certificate and the CA's validation finds it open. A failed bind of the challenge-only port fails `Apply` like any other port's and is retried by the next one. The port holds no rule, so no rule reads `listen_failed` for it: the `acme` rules on other ports stay served from the cache, and the CA cannot validate a new certificate until the bind succeeds.

A held `acme` rule reads `acme_challenge_port_taken`, with the holder's slug as detail, when port 443 has a plain rule, or when the table of port 443 routes the rule's host to a rule of another mode, such as a `passthrough` rule for the host or a `passthrough` wildcard that covers it. Such a rule would take the CA's connection. A host whose port 443 a plain rule holds therefore gets no `acme` certificate.

## The Cache Directory

The cache directory is `bridge.acme_cache_dir`, or `<data_dir>/acme` when the key is empty, `/var/lib/plexd/acme` on Linux. `autocert.DirCache` writes flat files there, creating the directory with mode 0700 and each file with mode 0600:

| File | Content |
|---|---|
| `acme_account+key` | The ACME account key |
| `<host>` | The ECDSA private key and the certificate chain of an `acme` rule's host |
| `<host>+rsa` | The same with an RSA key, for a client that offers no ECDSA |
| `<host>+token` | The challenge certificate, while a validation runs |

One directory serves every account, so the certificates and the account key stay across directory changes. Cache files of a host that left stay on disk. A rule that comes back, or a block that was `null` for one pull, then reuses its certificate and spends no order against the CA's rate limits. plexd does not prune the cache.

## Local Configuration

| Field               | YAML key              | Default                   | Description |
|---------------------|-----------------------|---------------------------|-------------|
| `ACMECacheDir`      | `acme_cache_dir`      | empty: `<data_dir>/acme`  | The cache directory |
| `ACMEDirectoryURLs` | `acme_directory_urls` | empty                     | The ACME directories the bridge accepts from the block's `acme` member; empty accepts any https directory |

```go
// ACMEDirectoryURLs bounds the ACME directories the bridge accepts from the
// state pull's bridge.ingress.acme member. Empty accepts any https directory.
ACMEDirectoryURLs []string `yaml:"acme_directory_urls"`
```

```yaml
bridge:
  enabled: true
  access_interface: eth1
  access_subnets:
    - 10.0.0.0/24
  acme_directory_urls:
    - https://acme-v02.api.letsencrypt.org/directory
```

`Config.Validate` refuses an entry of `ACMEDirectoryURLs` that fails `ValidACMEDirectoryURL` with `bridge: config: acme_directory_urls: "<entry>" is not an absolute https URL`, whether or not ingress is enabled. An entry matches `directory_url` when the two are equal after trimming surrounding spaces.

`Config.ACMEEnabled`, `ACMEAllowedHosts`, `ACMEEmail` and `ACMEDirectoryURL` are removed with their YAML keys, which [Configuration](../core/configuration.md#bridge) lists. A config file that still sets them keeps loading, and they have no effect.

## ClientHello Peeking

```go
const sniPeekLimit = 16 << 10
const sniPeekTimeout = 5 * time.Second

type clientHello struct {
    ServerName string
    ALPN       []string
}

func peekClientHello(conn net.Conn, timeout time.Duration) (hello clientHello, peeked []byte, err error)
```

`peekClientHello` reads the client's TLS ClientHello without answering it and returns its server name, the ALPN protocols it offers, and every byte it read:

1. It sets a read deadline of `timeout` on the connection; the manager passes `sniPeekTimeout`.
2. It runs `tls.Server(rec, cfg).Handshake()` over a wrapper that records every byte it reads and discards every write, so the client receives nothing.
3. `cfg.GetConfigForClient` stores `hello.ServerName` and `hello.SupportedProtos` and returns the sentinel `errClientHelloPeeked`, which stops the handshake. A handshake error that wraps the sentinel is a successful peek.
4. The wrapper fails a read with `errSNIPeekLimit` once it has recorded more than `sniPeekLimit` bytes.
5. On success it clears the read deadline.

`crypto/tls` parses the hello, so a hello that spans several reads or TLS records, and a server name behind any other extension, are read in full. A ClientHello of Go 1.26 with its default key shares is 1,505 bytes.

| Client | Result |
|---|---|
| A ClientHello with SNI, whole or in pieces | The server name, the offered ALPN protocols, and the recorded bytes, nil error |
| A ClientHello without ALPN | A nil `ALPN` list |
| A ClientHello without SNI | An empty server name, nil error |
| Bytes that are not TLS, such as `GET / HTTP/1.1` | An error for which `errors.As` finds `tls.RecordHeaderError` |
| Nothing within the timeout | A `net.Error` with `Timeout()` |
| A connection closed at once | An error for which `errors.Is(err, io.EOF)` holds |
| A handshake message larger than 16 KiB | An error for which `errors.Is(err, errSNIPeekLimit)` holds |

The bytes come back on an error too. The manager closes the connection on any error. On success it hands the bytes on through `peekConn`, which uses `io.MultiReader` to prepend them to the connection: to the target of a `passthrough` rule, and to the bridge's own `tls.Server` for a terminating rule or a challenge, so the handshake reads the ClientHello first.

```go
func newPeekConn(conn net.Conn, peeked []byte) *peekConn
```

## Host Matching

Each SNI port has an `ingressTable` with an exact map by lowercase host and a wildcard map by the suffix after `*.`. Each entry is an `ingressHost`: the route of the host's one rule, or the routes of the rules that share the host by their request conditions. `match` lowercases the server name, returns the exact host when one exists, and otherwise cuts the name at its first dot and looks the rest up in the wildcard map:

| Rules on the port | Server name | Host |
|---|---|---|
| `api.example.com`, `*.example.com` | `api.example.com` | `api.example.com`: an exact host wins |
| `*.example.com` | `a.example.com`, `A.EXAMPLE.COM` | `*.example.com` |
| `*.example.com` | `example.com` | none |
| `*.example.com` | `a.b.example.com` | none: the `*` stands for one label |
| any | empty | none |

A connection without a host is closed (see [Routing a Connection](public-ingress.md#routing-a-connection)), unless it is a challenge on port 443 (see [The Challenge on Port 443](#the-challenge-on-port-443)). On a host whose rules have conditions, `serveHTTP` also looks up the authority of each request with `match`, and answers `421` when the port routes it to another host (see [Routing a Request](public-ingress.md#routing-a-request)).

## Error Prefixes

| Source                                     | Prefix                                                       |
|--------------------------------------------|--------------------------------------------------------------|
| `ACMEManager.GetCertificate` (no account)  | `bridge: acme: no account is configured`                     |
| Host policy                                | `bridge: acme: "<name>" is not the sni_host of an acme rule` |
| A retired manager's request (`errACMERetired`) | `bridge: acme: the account settings were replaced`       |
| `peekClientHello` (limit)                  | `bridge: ingress: client hello exceeds the peek limit`       |
| Config validation (ACME directories)       | `bridge: config: acme_directory_urls: "<entry>" is not an absolute https URL` |

## Logging

All log entries use `component=bridge`.

| Level   | Message                                   | Keys |
|---------|-------------------------------------------|------|
| `Info`  | `acme account configured`                 | `directory_url`, `contact` (a bool), `hosts` (a count) |
| `Info`  | `ingress certificate obtained`            | `sni_host`, `not_after` |
| `Error` | `bridge: acme: obtain certificate failed` | `sni_host`, `error` |
| `Warn`  | `bridge: acme: certificate requests still running after teardown` | (none); `Teardown` stopped waiting after 10 s (`acmeTeardownWait`) |
| `Debug` | `ingress acme challenge answered`         | `server_name`, `remote`, `error` |
| `Warn`  | `ingress rule not served`                 | `rule_id`, `slug`, `listen_port`, `reason`, `detail`; the ACME reasons are `acme_directory_invalid`, `acme_directory_not_allowed` and `acme_challenge_port_taken` |
| `Debug` | `ingress connection closed`               | `listen_port`, `remote`, `server_name`, `reason` (`no_client_hello`, `no_server_name`, `no_matching_rule`, `rule_not_served`, `no_certificate`, `tls_handshake_failed`) |

The ingress manager's other log lines are listed in [Public Ingress](public-ingress.md#logging).

## Limits

| Bound | Value | Name |
|---|---|---|
| The ClientHello peek | 16 KiB and 5 s per connection | `sniPeekLimit`, `sniPeekTimeout` |
| The TLS handshake of a terminating rule or a challenge, for an `acme` rule the wait for a certificate still being issued included | 10 s | `ingressHandshakeTimeout` |
| The wait before a retried request without `Retry-After` | 1 s, doubling to 10 s | |
| The longest `Retry-After` the account's client waits out; a longer one ends the attempt | 10 s | `acmeMaxRetryWait` |
| The wait of `Teardown` for the certificate requests in flight | 10 s | `acmeTeardownWait` |
| The pause after a failed issuance before `autocert` orders again for the host | 1 minute | `createCertRetryAfter`, in `autocert` |

See [Request Retries](#request-retries) and [Teardown](#teardown).
