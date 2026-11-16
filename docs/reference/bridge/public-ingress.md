---
title: Public Ingress
package: internal/bridge
feature: PXD-0014
---

# Public Ingress

Public ingress lets a bridge node publish services that run on nodes of its Domain. A client outside the mesh connects to a public TCP port of the bridge, and the bridge forwards the connection over the mesh to a port on the target node. Each published service is a rule of the `bridge.ingress` block of the bridge's state pull, which an operator authors on the bridge Resource in the control plane.

The bridge opens one TCP listener per distinct listen port. A port with a rule that names no `sni_host` forwards every connection without reading it. On a port whose rules name hosts, the bridge reads the server name of each connection's TLS ClientHello and routes by it, so several HTTPS services share port 443. A `passthrough` rule forwards the TLS session to the target unchanged. A `terminate` rule ends TLS at the bridge with the certificate of the Secret it names, and an `acme` rule with a certificate the bridge obtains from an ACME CA; both forward plaintext to the target.

## Data Flow

```
Public Internet Clients
        |
        |  TCP to <bridge>:<listen_port>
        v
+------------------------------------------------------------------+
|                          Bridge Node                             |
|                                                                  |
|  one listener per listen port                                    |
|  +-------------------+     plain port: forward without reading   |
|  | :2222  (plain)    |-------------------------------+           |
|  +-------------------+                               |           |
|  +-------------------+     SNI port: peek the        |           |
|  | :443   (SNI)      |---> ClientHello, match the    |           |
|  +-------------------+     server name               |           |
|           ^                  |                       |           |
|           |                  | passthrough: replay   |           |
|           |                  |   the peeked bytes    |           |
|           |                  | terminate, acme: end  |           |
|           |                  |   TLS at the bridge   v           |
|           |                  +------------------> dial target    |
|           |                                       over plexd0    |
|           | ingressTable per port, swapped in place  |           |
|  IngressReconcileHandler --> IngressManager.Apply    |           |
|  IngressSecretInventoryHandler --> terminate certs   |           |
|  ACMEManager --> acme certs, challenges on :443      |           |
+------------------------------------------------------|-----------+
                                                       v
                                         Target node <target_address>:<target_port>
```

The control plane delivers the block in the state pull and announces a change with a `bridge_config_updated` event, which only triggers a pull (see [SSE event handling](#sse-event-handling)). `IngressReconcileHandler` hands the block to `IngressManager.Apply`, which plans the rules, opens and closes listeners, swaps each port's routing table, and then configures the ACME account. `IngressSecretInventoryHandler` hands the pull's secret inventory to `IngressManager.SyncSecretInventory` on every successful pull, which loads, replaces and drops the certificates of the `terminate` rules (see [Certificates from the Secret Store](#certificates-from-the-secret-store)). The certificates of the `acme` rules come from `ACMEManager` (see [ACME and SNI Routing](acme-sni.md)).

The bridge's dial to a target is traffic the bridge itself sends over the mesh, which its compiled policy governs (see [What the rules govern](../networking/pf-wfp-firewall.md#what-the-rules-govern)). A rule grants no allow of its own: the policy needs a rule that allows TCP from the bridge's mesh IP to the target's address and port. A Project's allow-all policy covers every mesh address. Without such a rule the dial fails, and the bridge logs `bridge: ingress: dial target failed`.

## The bridge.ingress Block

The block is the control plane's `NodeStateBridgeIngress`, each rule a `NodeStateBridgeIngressRule`, and its `acme` member a `NodeStateBridgeIngressACME`. The agent contract's `## Public ingress` section in plexsphere's `docs/reference/api/plexd-agent-contract.md` defines it, and its sections `### Terminate rules` and `### ACME rules` define where the certificates come from. The pull lists the rules by `slug` ascending. A bridge with one rule per mode and one plain TCP rule pulls:

```json
"bridge": {
  "ingress": {
    "rules": [
      {
        "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f1",
        "slug": "api",
        "listen_port": 443,
        "mode": "acme",
        "sni_host": "api.example.com",
        "target_node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1",
        "target_address": "10.42.0.7",
        "target_port": 8443
      },
      {
        "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f2",
        "slug": "apps",
        "listen_port": 443,
        "mode": "passthrough",
        "sni_host": "*.apps.example.com",
        "target_node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2",
        "target_address": "10.42.0.8",
        "target_port": 443
      },
      {
        "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f3",
        "slug": "mqtt",
        "listen_port": 8883,
        "mode": "terminate",
        "sni_host": "mqtt.example.com",
        "target_node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1",
        "target_address": "10.42.0.7",
        "target_port": 1883,
        "certificate_secret_name": "mqtt-cert"
      },
      {
        "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f4",
        "slug": "ssh",
        "listen_port": 2222,
        "mode": "passthrough",
        "target_node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2",
        "target_address": "10.42.0.8",
        "target_port": 22
      }
    ],
    "acme": {
      "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
      "contact_email": "ops@example.com"
    }
  }
}
```

| Field | Type | Description |
|---|---|---|
| `id` | string | The rule's id. The bridge tells rules apart by it |
| `slug` | string | The rule's name within the bridge Resource; logs and listener conflicts name it |
| `listen_port` | int | The public TCP port, 1 to 65535, on all of the node's addresses |
| `mode` | string | `passthrough`, `terminate` or `acme` (see [Modes](#modes)) |
| `sni_host` | string, optional | The server name the rule matches, in lowercase: an exact name, or `*.` and a suffix for one label in place of the `*`. A rule without it is the only rule on its port |
| `target_node_id` | string | The target node. It is not dialed |
| `target_address` | string | The target node's mesh address, IPv4 or IPv6, without brackets |
| `target_port` | int | The port the bridge dials on the target, 1 to 65535 |
| `certificate_secret_name` | string, `terminate` only | The Secret of the bridge's Project that holds the rule's certificate chain and key, one PEM document (see [Certificates from the Secret Store](#certificates-from-the-secret-store)). The bridge ignores it on the other modes |

The `acme` member is the ACME account the block's `acme` rules share. The control plane sends it exactly when the block holds an `acme` rule:

| Field | Type | Description |
|---|---|---|
| `directory_url` | string | The ACME directory (RFC 8555) the bridge registers its account at and orders certificates from. The bridge accepts only an absolute https URL, and only one that `bridge.acme_directory_urls` lists when that list is not empty (see [The ACME Account](acme-sni.md#the-acme-account)) |
| `contact_email` | string, optional | The contact the account registers with. Without it the account has no contact |

The block is whole: a rule missing from a later pull is removed, and a port no rule names any more is closed. An `ingress` child that is absent or `null` closes every public listener. An `ingress` child with an empty or `null` rule list does the same. A changed `acme` member or `certificate_secret_name` is bridge drift like any other change to the block.

## Activation

The bridge serves the block only in bridge mode with the local `bridge.ingress_enabled: true` (default `false`); `cmd/plexd/cmd/up.go` builds the ingress manager only then. Without it, the block is ignored. The block carries no `enabled` member, and an `acme` rule needs no local switch of its own.

| Field                | Type            | Default | Description                                      |
|----------------------|-----------------|---------|--------------------------------------------------|
| `IngressEnabled`     | `bool`          | `false` | `bridge.ingress_enabled`: the local switch for public ingress |
| `MaxIngressRules`    | `int`           | `20`    | `bridge.max_ingress_rules`: the most rules the bridge holds |
| `IngressDialTimeout` | `time.Duration` | `10s`   | `bridge.ingress_dial_timeout`: the timeout for dialing a target |
| `ACMECacheDir`       | `string`        | `""`    | `bridge.acme_cache_dir`: the directory of the ACME account key and the certificates of `acme` rules; empty means `<data_dir>/acme` (see [The Cache Directory](acme-sni.md#the-cache-directory)) |
| `ACMEDirectoryURLs`  | `[]string`      | empty   | `bridge.acme_directory_urls`: the ACME directories the bridge accepts from the block's `acme` member; empty accepts any https directory |

Ingress validation is skipped when `IngressEnabled` is `false`. When enabled:

| Field                | Rule                    | Error Message                                                               |
|----------------------|-------------------------|-----------------------------------------------------------------------------|
| `IngressEnabled`     | Requires `Enabled=true` | `bridge: config: ingress requires bridge mode to be enabled`                |
| `MaxIngressRules`    | Must be > 0             | `bridge: config: MaxIngressRules must be positive when ingress is enabled`  |
| `IngressDialTimeout` | Must be >= 1s           | `bridge: config: IngressDialTimeout must be at least 1s`                    |

`ACMEDirectoryURLs` is checked whether or not ingress is enabled: an entry that is not an absolute https URL fails with `bridge: config: acme_directory_urls: "<entry>" is not an absolute https URL`.

## Modes

| Mode | Behavior |
|---|---|
| `passthrough` | The bridge forwards the bytes unchanged, the TLS handshake included, so the target ends TLS |
| `terminate` | The bridge ends TLS with the certificate of the Secret `certificate_secret_name` names, in the version the secret inventory lists, and forwards plaintext to the target (see [Certificates from the Secret Store](#certificates-from-the-secret-store)) |
| `acme` | The bridge ends TLS with a certificate it obtains for `sni_host` at the block's `acme` directory, and forwards plaintext to the target (see [ACME and SNI Routing](acme-sni.md)) |

A `terminate` or `acme` rule needs `sni_host`, because the bridge picks the certificate by the server name. An `acme` rule names an exact host of at least two labels: TLS-ALPN-01 cannot prove a wildcard, and `autocert` refuses a name without a dot. A terminating rule offers no ALPN protocol (see [TLS Termination](#tls-termination)), and the bridge opens no TLS connection to the target.

A held `terminate` or `acme` rule that cannot serve yet keeps its `(listen_port, sni_host)` slot, so no other rule takes its host, not even a wildcard `passthrough` rule that covers it, and its port keeps its listener. A `terminate` rule waits for its certificate, and an `acme` rule with a reason is not served while the reason holds.

## The Listener Plan

```go
type acmeAvailability struct{ Reason, Detail string }

func planIngress(rules []api.IngressRule, maxRules int, acme acmeAvailability) ingressPlan
```

`planIngress` walks the rules in the order the pull lists them and gives each the first reason that applies:

| Order | Check | Reason | Detail |
| --- | --- | --- | --- |
| 1 | `id` is empty | `invalid_rule` | `id` |
| 2 | an earlier rule has the same `id` | `duplicate_id` | |
| 3 | `mode` is none of the three modes | `invalid_rule` | `mode` |
| 4 | `listen_port` outside 1 to 65535 | `invalid_rule` | `listen_port` |
| 5 | `sni_host`, lowercased: longer than 253 bytes, an empty label, or a `*` anywhere but as the whole first label of at least two; empty on `terminate` or `acme`; or on `acme`, a host that starts with `*.` or has one label | `invalid_rule` | `sni_host` |
| 6 | `target_address` is not an IP address, or carries a port, brackets or a zone | `invalid_rule` | `target_address` |
| 7 | `target_port` outside 1 to 65535 | `invalid_rule` | `target_port` |
| 8 | on `terminate`, `certificate_secret_name` is outside the Secret name grammar `^[a-z][a-z0-9_-]{0,62}$` (`api.ValidSecretName`) | `invalid_rule` | `certificate_secret_name` |
| 9 | a held rule has the same port and the same host, or one of the two has no host | `listener_conflict` | slug of the holder |
| 10 | `max_ingress_rules` rules are held already | `max_rules` | |

A rule that passes check 10 is held. After the walk, each held `acme` rule gets the first reason that applies:

| Order | Check | Reason | Detail |
| --- | --- | --- | --- |
| 1 | the block has no `acme` member, or its `directory_url` is not an absolute https URL | `acme_directory_invalid` | the URL |
| 2 | `bridge.acme_directory_urls` is not empty and lists no entry equal to `directory_url` | `acme_directory_not_allowed` | the URL |
| 3 | the table of port 443 has a plain rule, or routes the rule's host to a rule of another mode | `acme_challenge_port_taken` | slug of that rule |

The first two are the `acmeAvailability` that `Apply` computes once per block with `checkACMEDirectory` (see [The ACME Account](acme-sni.md#the-acme-account)), so they apply to every `acme` rule of the block alike. The third keeps a rule whose challenge connection from the CA would reach another rule (see [The Challenge on Port 443](acme-sni.md#the-challenge-on-port-443)). An `acme` rule with a reason keeps its slot and is not served.

Every port with a held rule gets a routing table and a listener, also a port whose rules are all `terminate` or `acme` rules without a certificate yet: the set of listeners follows the rules alone, not the state of a fetch. A route is served when its rule is `passthrough` or `terminate`, and when it is `acme` without a reason. When at least one `acme` rule has no reason and port 443 has no table, the plan adds an empty table for port 443, so that `Apply` opens the port for ACME challenges alone. When a bind fails, the port's rules read `listen_failed`, and an `acme` rule among them is left out of the ACME account (see [Applying the Block](#applying-the-block)). A failed bind of the challenge-only port 443 fails `Apply` like any other port's and is retried by the next one. That port holds no rule, so no rule reads `listen_failed` for it: the `acme` rules on other ports stay served, from the certificates the cache holds, and the CA cannot validate a new certificate until the bind succeeds.

A held `terminate` rule's state also follows its certificate: `RuleStates()` reports it served exactly while the manager holds a certificate for its Secret, and otherwise with `certificate_secret_not_listed`, `certificate_fetch_failed` or `certificate_invalid` and the Secret name as detail (see [Certificates from the Secret Store](#certificates-from-the-secret-store)).

The control plane refuses a rule set a bridge could not serve: a second rule on a listener another rule holds answers `409 bridge_port_conflict`, a `terminate` or `acme` rule without `sni_host` answers `400 ingress_rule_invalid`, and a `terminate` rule whose Secret the bridge Resource may not read answers `422 certificate_secret_not_readable`. A rule the bridge skips is therefore a defect report, not a routine path. The bridge serves the rest of the block and logs `ingress rule not served` for the rule.

`target_address` is checked for syntax only. The pull is the node's authenticated configuration, and the control plane resolves the address from the target node.

The reasons are exported constants:

| Constant | Reason | Rule |
|---|---|---|
| `IngressReasonInvalid` | `invalid_rule` | Not held |
| `IngressReasonDuplicateID` | `duplicate_id` | Not held |
| `IngressReasonListenerConflict` | `listener_conflict` | Not held |
| `IngressReasonMaxRules` | `max_rules` | Not held |
| `IngressReasonListenFailed` | `listen_failed` | Held; its port did not bind |
| `IngressReasonACMEDirectoryInvalid` | `acme_directory_invalid` | A held `acme` rule |
| `IngressReasonACMEDirectoryNotAllowed` | `acme_directory_not_allowed` | A held `acme` rule |
| `IngressReasonACMEChallengePortTaken` | `acme_challenge_port_taken` | A held `acme` rule |
| `IngressReasonCertificateSecretNotListed` | `certificate_secret_not_listed` | A held `terminate` rule |
| `IngressReasonCertificateFetchFailed` | `certificate_fetch_failed` | A held `terminate` rule |
| `IngressReasonCertificateInvalid` | `certificate_invalid` | A held `terminate` rule |

The challenge port is the unexported `const acmeChallengePort = 443`.

## Certificates from the Secret Store

A `terminate` rule's certificate is the value of the Secret its `certificate_secret_name` names, in the version the pull's `secrets` block lists. The block is the node's secret inventory: the name and version of every Secret the node may read (see [GET /v1/nodes/{node_id}/state](../core/api-endpoints.md#get-v1-nodes-node-id-state)). The bridge fetches the value with the node's own credential and opens it under the node secret key, the way the [edge PSK store](../networking/wireguard.md#edge-psks) fetches.

```go
// CertificateSecretFetcher reads the value of one version of a Secret the
// node may read: the PEM document of a terminate rule's certificate.
type CertificateSecretFetcher interface {
    FetchCertificateSecret(ctx context.Context, name string, version int) ([]byte, error)
}

// SyncSecretInventory takes the secret inventory of a pull and loads, replaces
// or drops the certificates of the held terminate rules.
func (m *IngressManager) SyncSecretInventory(ctx context.Context, inventory []api.NodeStateSecret)
```

The manager keeps the inventory as a map from name to version, filtered as the node API's [secret index](../core/nodeapi.md#secretindexdispatchhandler) filters it: the first entry of a name counts, and a name outside the grammar or a version below 1 counts as not listed. It holds no inventory until the first `SyncSecretInventory`. It keeps one entry per Secret name a held `terminate` rule names: the loaded certificate with its version, and for the last failure the version, the reason, the attempt count and the time of the next attempt.

The unexported `loadCertificates` runs at the end of every `SyncSecretInventory` and every `Apply`, and applies these rules per name:

| Inventory | Entry | Outcome |
| --- | --- | --- |
| does not list the name (or no inventory yet) | no certificate | reason `certificate_secret_not_listed`; no fetch |
| does not list the name | a certificate | the certificate is dropped, the connections of every rule naming it are closed, `ingress certificate dropped` is logged |
| lists version v | a certificate of version v | nothing |
| lists version v | none, or another version | fetch v, unless v failed as invalid, or failed to fetch and the next attempt is not due |

Both callers run on the reconcile goroutine, one cycle at a time, so two loads never overlap. The fetch itself runs outside the manager's lock, which guards the entries against the connections that read a rule's certificate and against status readers. `SyncSecretInventory` does nothing while the manager is not active.

The value is one PEM document (RFC 7468): the certificate chain, leaf first, as `CERTIFICATE` blocks, and one private key block. The bridge parses it with `tls.X509KeyPair(pem, pem)`, which reads the `CERTIFICATE` blocks as the chain and the first private key block as the key, and refuses a key that does not match the leaf. On success the entry holds the new certificate and `ingress certificate loaded` is logged. A failure keeps the rule's slot:

| Failure | Reason | Next attempt |
|---|---|---|
| The fetch fails | `certificate_fetch_failed` | After 5 s, doubling with each further failure to at most 60 s (5 s, 10 s, 20 s, 40 s, 60 s), or after the `Retry-After` of the response (`APIError.RetryAfter`) when that is longer. The first pull or `Apply` that finds the attempt due tries again |
| The value does not parse | `certificate_invalid` | None for this version: the bridge fetches again once the inventory lists another version, or after a restart |

In both cases a certificate the entry already holds keeps serving, and the rule stays served with it: a rotation that fails never takes a working certificate away. `ingress certificate not loaded` names the version that failed and the `serving_version`, and is logged once per Secret, version and reason. A `403` for a listed name is a fetch failure like any other, so the bridge retries it on the schedule above; only an inventory that leaves the name out drops the certificate.

A new version replaces the certificate and closes nothing: an established connection keeps its session, and the next handshake gets the new certificate. An inventory that stops listing a name drops its certificate and closes the established connections of every rule that names the Secret, while the other rules of the port keep theirs and the listener stays open. A rule's connections are closed by cancelling its route and storing a copy of the port's table with a fresh route for the rule. An entry that no held rule names any more is deleted, so a rule that names the Secret again fetches it again.

When the leaf of a loaded certificate does not cover a rule's host (`x509.Certificate.VerifyHostname`, with `x` in place of the `*` of a wildcard host), the bridge logs `ingress certificate does not cover the rule's host` and serves the certificate anyway: the control plane checks no coverage, and the client reports the mismatch itself. plexd checks neither expiry, chain nor key strength.

Certificates and their keys live in memory only. Nothing writes a Secret's value to disk, a restart fetches every certificate again, and `Teardown` forgets the inventory and every certificate. No log line and no error carries a Secret's value.

`cmd/plexd/cmd/ingress_certs.go` implements `CertificateSecretFetcher` with `ingressCertFetcher`, over `ControlPlane.FetchSecret` and `nodeapi.DecryptSecret`:

```go
type ingressCertFetcher struct {
    client nodeapi.SecretFetcher
    nodeID string
    nsk    []byte
}
```

| Case | Error |
|---|---|
| `FetchSecret` fails | `fetch secret "<name>" version <v>: <error>`, wrapping the error, such as `api.ErrForbidden` or an `*api.APIError` |
| The envelope holds another version | `fetch secret "<name>": asked for version <v>, got <w>` |
| The envelope does not open under the NSK | `decrypt secret "<name>" version <v>: <error>` |

## Routing a Connection

The accept loop of a port loads the port's routing table for each connection:

- **A plain port.** The rule without `sni_host` takes every connection. The bridge reads nothing and dials the target, so a protocol whose server speaks first, such as SSH or SMTP, works as well as TLS.
- **An SNI port.** `peekClientHello` reads the TLS ClientHello without answering it: `crypto/tls` parses it, so a hello that spans several reads or records, or that orders the server name behind a large key share, is read in full. The peek reads at most 16 KiB and waits at most 5 s, and returns the server name and the ALPN protocols the client offers. On port 443 a hello that offers only `acme-tls/1` can be an ACME challenge (see [ACME Challenges](#acme-challenges)). Otherwise the server name is compared with the rules' hosts case-insensitively. An exact host wins over a wildcard, and `*.example.com` matches exactly one label in place of the `*`: it matches `a.example.com` and neither `example.com` nor `a.b.example.com`. A `passthrough` rule dials the target and replays the bytes it peeked to it first. A `terminate` or `acme` rule ends TLS at the bridge (see [TLS Termination](#tls-termination)).

A connection that matches no served rule is closed without a byte from any target and logged at Debug, with one of these reasons:

| Reason | Cause |
|---|---|
| `no_client_hello` | The client sent no ClientHello within 5 s or 16 KiB, closed the connection, or sent bytes that are not TLS |
| `no_server_name` | The ClientHello carries no server name |
| `no_matching_rule` | No rule's host matches the server name |
| `rule_not_served` | The matching rule is an `acme` rule with a reason |
| `no_certificate` | The matching rule is a `terminate` rule whose certificate is not loaded |
| `tls_handshake_failed` | The TLS handshake of a `terminate` or `acme` rule failed, or did not complete within 10 s. For an `acme` rule the 10 s include the wait for a certificate that is still being issued |

The level is Debug because a public port draws scanners: a line per connection at Warn would let any client fill the log and the log forwarder.

The bridge dials `target_address:target_port` with `ingress_dial_timeout` and copies both ways, the plaintext of a terminated session included, until one side ends or the rule is removed or changed. A failed dial closes the client connection and logs `bridge: ingress: dial target failed`.

### TLS Termination

For a `terminate` or `acme` rule the bridge completes the TLS handshake itself, with `tls.Server` over `newPeekConn(conn, peeked)`, so the handshake reads the ClientHello it peeked first. Its `tls.Config` has `MinVersion: tls.VersionTLS12`, no `NextProtos`, and either `Certificates` holding the rule's loaded certificate (`terminate`) or `GetCertificate: m.acme.GetCertificate` (`acme`). A `terminate` rule without a loaded certificate closes the connection with `no_certificate` before any handshake. After the handshake the bridge dials the target and copies the plaintext both ways.

A terminating rule offers no ALPN protocol. The bridge forwards plaintext to the target, and a negotiated `h2` would hand the target HTTP/2 frames it did not ask for. A client that offers `h2` and `http/1.1` completes the handshake, and no protocol is negotiated.

The handshake is bounded by 10 s: the package constant `ingressHandshakeTimeout`, which the manager holds in its unexported field `handshakeTimeout` so that a test can shorten it. The bound covers the whole handshake, and for an `acme` rule also the wait for a certificate that is still being issued. A client that sends a ClientHello and then stays silent is closed with `tls_handshake_failed` when the bound ends. So is a client of an `acme` host whose certificate is not ready within the bound; `autocert` finishes the issuance in the background, and a later handshake gets the certificate (see [Obtaining a Certificate](acme-sni.md#obtaining-a-certificate)). The bound ends with the handshake: the plaintext copy that follows has no deadline.

### ACME Challenges

On port 443, a ClientHello whose ALPN list is exactly `["acme-tls/1"]` and whose server name `ACMEManager.HasHost` knows is a TLS-ALPN-01 challenge when the port's table has no route for the name or routes it to an `acme` rule. The bridge answers it with a `tls.Config` of its own, `GetCertificate: m.acme.GetCertificate`, `NextProtos: []string{acme.ALPNProto}` and `MinVersion: tls.VersionTLS12`, within the same 10 s bound, logs `ingress acme challenge answered` at Debug and closes the connection. No target is dialed. The same hello for the host of a `passthrough` rule is forwarded like any other connection, so a target that runs its own ACME client keeps working. See [The Challenge on Port 443](acme-sni.md#the-challenge-on-port-443).

## Applying the Block

`Apply(ctx, block)` makes the manager serve exactly the block it is given:

1. It returns `bridge: ingress: manager is not active` before `Setup` or after `Teardown`.
2. It checks the block's `acme` member with `checkACMEDirectory(block.ACME, cfg.ACMEDirectoryURLs)` and plans the rules with the outcome.
3. It deletes the certificate entries of the Secret names no held rule names any more.
4. A route whose rule is unchanged, compared with `==` and so with `certificate_secret_name` included, keeps its context and its established connections. Every other planned route gets a new context. Every route of the last `Apply` that is not carried over is cancelled, which closes its connections. Other rules on the port keep theirs.
5. For a port in the plan without a listener, it calls `IngressController.Listen(":<port>", nil)`, also for the challenge-only port 443. On an error it marks the port's rules `listen_failed`, goes on with the other ports, and adds `bridge: ingress: listen on :<port>: <error>` to the result.
6. For a port with a listener, it stores the new routing table. The listener is not rebound, also when the port changes between a plain rule and SNI rules.
7. It closes the listener of a port that left the plan and waits for its accept loop.
8. It calls `ACMEManager.Configure(block.ACME, hosts)` with the hosts of the `acme` rules that end the `Apply` without a reason, so an `acme` rule whose port failed to bind (`listen_failed`) does not keep the account. Without such a rule the call retires the ACME account. Because the call follows the binds, port 443 is bound before the account asks the CA for a certificate (see [The Challenge on Port 443](acme-sni.md#the-challenge-on-port-443)).
9. It loads, replaces or drops the certificates of the held `terminate` rules with `loadCertificates` (see [Certificates from the Secret Store](#certificates-from-the-secret-store)).
10. It returns the listen errors joined, or nil.

A second `Apply` with the same block, after one whose binds all succeeded, binds nothing, cancels nothing, keeps the ACME account as it is and logs no rule or listener line again. It is not free of side effects: its `loadCertificates` still fetches a version whose last fetch failed once that version's next attempt is due, and logs `ingress certificate loaded` when the retry succeeds (see [Certificates from the Secret Store](#certificates-from-the-secret-store)). A failed bind fails the reconcile cycle, so the reconciler keeps its snapshot, and the next pull tries the bind again.

## Ports Below 1024

A listen port below 1024, such as 443 or 80, needs `CAP_NET_BIND_SERVICE`. So does the challenge-only port 443 a bridge opens for an `acme` rule on another port. The systemd unit `plexd install` writes and `deploy/systemd/plexd.service` grant it (see [Bare-Metal Packaging](../deployment/bare-metal-packaging.md)). When the bind fails with a permission error on such a port, `bridge: ingress: listen failed` carries `hint="ports below 1024 need CAP_NET_BIND_SERVICE"`.

A unit an earlier release wrote keeps `CAP_NET_ADMIN CAP_NET_RAW` until `plexd install` writes it again. Until then, this drop-in adds the capability, because systemd merges repeated capability lines:

```ini
# /etc/systemd/system/plexd.service.d/bind-service.conf
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

Run `systemctl daemon-reload` and `systemctl restart plexd` after adding it. A host firewall plexd does not manage must open the listen ports too, and port 443 for a bridge that serves `acme` rules.

## IngressController

Interface abstracting TCP listener operations for ingress testability.

```go
type IngressController interface {
    Listen(addr string, tlsCfg *tls.Config) (net.Listener, error)
    Close(listener net.Listener) error
}
```

| Method   | Description |
|----------|-------------|
| `Listen` | Creates a TCP listener on `addr`. The manager always passes a nil `tlsCfg`: it runs the TLS handshake of a terminating rule itself, after the peek |
| `Close`  | Closes the given listener; idempotent |

`StdIngressController` implements it with `net.Listen`.

## IngressManager

```go
func NewIngressManager(ctrl IngressController, cfg Config, logger *slog.Logger, acme *ACMEManager, certs CertificateSecretFetcher) *IngressManager
```

Neither `acme` nor `certs` may be nil. With `bridge.ingress_enabled`, `plexd up` builds the `ACMEManager` over the cache directory (`bridge.acme_cache_dir`, or `<data_dir>/acme`), reads the node secret key with `identity.SecretKey()` (an error fails `plexd up`), builds `ingressCertFetcher` with it, and passes the two to `NewIngressManager`.

Concurrent-safe via `sync.Mutex`. The connection counter is an `atomic.Int64`.

| Method                | Signature                                                   | Description |
|-----------------------|-------------------------------------------------------------|-------------|
| `Setup`               | `() error`                                                  | Marks the manager active; a no-op when `IngressEnabled` is `false` |
| `Apply`               | `(ctx context.Context, block api.IngressConfig) error`      | Serves exactly this block (see [Applying the Block](#applying-the-block)) |
| `SyncSecretInventory` | `(ctx context.Context, inventory []api.NodeStateSecret)`    | Takes the pull's secret inventory and loads, replaces or drops the certificates of the held `terminate` rules (see [Certificates from the Secret Store](#certificates-from-the-secret-store)); a no-op when inactive |
| `RuleStates`          | `() []IngressRuleState`                                     | The outcome of the last `Apply`, one entry per rule, in block order, with each `terminate` rule's certificate state |
| `Teardown`            | `() error`                                                  | Cancels every route, which closes every connection, closes every listener, and forgets the inventory and every certificate; joins close errors; a no-op when inactive |
| `IngressStatus`       | `() *api.IngressInfo`                                       | The `status.ingress` report entry; nil when inactive |
| `IngressCapabilities` | `() map[string]string`                                      | `{"ingress": "true", "max_ingress_rules": "<n>"}`; nil when disabled |

```go
type IngressRuleState struct {
    Rule   api.IngressRule
    Served bool
    Reason string // empty when served
    Detail string // the field of an invalid rule, the slug of the rule that holds the listener or the challenge port, the ACME directory URL, or the Secret name
    held   bool   // the rule keeps its slot
}
```

`logRuleChanges` reads the unexported `held`, so a held rule with a reason, such as an `acme` rule whose directory is refused, still logs `ingress rule added` and `ingress rule removed`.

`IngressStatus().RuleCount` counts the served rules with the certificate state applied, so a `terminate` rule counts only while it has a certificate. `ConnectionCount` counts the connections from accept to close. `ACMEEnabled` reads `ACMEManager.Active()`: it is true exactly while the last `Apply` ended with an `acme` rule without a reason. An `acme` rule whose port failed to bind reads `listen_failed` and does not count.

## IngressReconcileHandler

```go
func IngressReconcileHandler(mgr *IngressManager, logger *slog.Logger) reconcile.ReconcileHandler
```

The handler returns nil for a nil snapshot. Otherwise it passes its context and the whole `desired.Bridge.Ingress` block, the zero `api.IngressConfig` when `Bridge` or `Ingress` is nil, to `mgr.Apply(ctx, block)`, and on an error logs `ingress reconcile: apply failed` and returns it.

## IngressSecretInventoryHandler

```go
func IngressSecretInventoryHandler(mgr *IngressManager) reconcile.DispatchHandler
```

The handler runs on the dispatch seam, on every successful pull, drift or not (see [DispatchHandler](../core/reconciliation.md#dispatchhandler)). It returns for a nil `desired.Secrets`, which keeps the inventory the manager holds, and otherwise calls `mgr.SyncSecretInventory(ctx, *desired.Secrets)`. A pull whose only change is the `secrets` block reports an empty diff and runs no reconcile handler, so without this handler no reconcile handler would see a Secret rotation. Dispatch handlers run before the reconcile handlers of a cycle, so a cycle that brings a new rule and its Secret hands the inventory over first, and the `Apply` of that cycle fetches the certificate.

`cmd/plexd/cmd/up.go` registers both handlers when the ingress manager exists:

```go
reconciler.RegisterDispatchHandler(bridge.IngressSecretInventoryHandler(ingressMgr))
reconciler.RegisterHandler(bridge.IngressReconcileHandler(ingressMgr, logger))
```

## SSE Event Handling

There are no ingress-specific SSE handlers. The control plane emits a single `bridge_config_updated` event with an opaque payload; `bridge.HandleBridgeConfigUpdated` dispatches it to `TriggerReconcile()`, and `IngressReconcileHandler` applies the block from the authoritative state snapshot. `node_secrets_updated` also only triggers a pull, whose `secrets` block reaches `IngressSecretInventoryHandler`.

## API Types

### IngressConfig

`api.BridgeSnapshot.Ingress`, present-but-nullable.

```go
type IngressConfig struct {
    Rules []IngressRule `json:"rules"`
    // ACME is the account the block's acme rules share, the control plane's
    // NodeStateBridgeIngressACME. It is present exactly when a rule has mode acme.
    ACME *IngressACME `json:"acme,omitempty"`
}
```

### IngressACME

```go
type IngressACME struct {
    DirectoryURL string `json:"directory_url"`
    ContactEmail string `json:"contact_email,omitempty"`
}
```

### IngressRule

```go
type IngressRule struct {
    ID                    string `json:"id"`
    Slug                  string `json:"slug"`
    ListenPort            int    `json:"listen_port"`
    Mode                  string `json:"mode"`
    SNIHost               string `json:"sni_host,omitempty"`
    TargetNodeID          string `json:"target_node_id"`
    TargetAddress         string `json:"target_address"`
    TargetPort            int    `json:"target_port"`
    CertificateSecretName string `json:"certificate_secret_name,omitempty"`
}

const (
    IngressModePassthrough = "passthrough"
    IngressModeTerminate   = "terminate"
    IngressModeACME        = "acme"
)
```

`IngressRule` is comparable with `==`, which is how `Apply` tells an unchanged rule from a changed one. A changed `certificate_secret_name` is a changed rule.

### IngressInfo

Published as the `status.ingress` report entry, each field under its snake_case JSON name:

| Field | Type | Description |
|---|---|---|
| `Enabled` | `bool` | Whether the ingress manager is active |
| `RuleCount` | `int` | The served rules, a `terminate` rule only while it has a certificate |
| `ConnectionCount` | `int` | The connections from accept to close |
| `ACMEEnabled` | `bool` | `ACMEManager.Active()`: whether the last `Apply` ended with an `acme` rule without a reason; a rule that reads `listen_failed` does not count |

## Error Prefixes

| Source                                  | Prefix                                         |
|-----------------------------------------|------------------------------------------------|
| `IngressManager.Apply` (inactive)       | `bridge: ingress: manager is not active`       |
| `IngressManager.Apply` (listen)         | `bridge: ingress: listen on :<port>: `         |
| `IngressManager.Teardown` (close)       | `bridge: ingress: close listener <port>: `     |
| `ingressCertFetcher` (fetch)            | `fetch secret "<name>" version <v>: `          |
| `ingressCertFetcher` (version)          | `fetch secret "<name>": asked for version <v>, got <w>` |
| `ingressCertFetcher` (decrypt)          | `decrypt secret "<name>" version <v>: `        |
| `Config.Validate` (ACME directories)    | `bridge: config: acme_directory_urls: "<entry>" is not an absolute https URL` |

## Logging

All ingress log entries use `component=bridge`.

| Level   | Message                                  | Keys |
|---------|------------------------------------------|------|
| `Info`  | `ingress manager started`                | `max_rules`, `dial_timeout` |
| `Info`  | `ingress manager stopped`                | (none) |
| `Info`  | `ingress listener opened`                | `listen_port` |
| `Info`  | `ingress listener closed`                | `listen_port` |
| `Info`  | `ingress rule added`                     | `rule_id`, `slug`, `listen_port`, `mode`, `sni_host`, `target` |
| `Info`  | `ingress rule updated`                   | the same; an id held before with another value |
| `Info`  | `ingress rule removed`                   | the same |
| `Warn`  | `ingress rule not served`                | `rule_id`, `slug`, `listen_port`, `reason`, `detail`; once per rule value and reason |
| `Info`  | `ingress certificate loaded`             | `secret`, `version`, `not_after` |
| `Warn`  | `ingress certificate not loaded`         | `secret`, `version`, `reason`, `error`, `serving_version` (0 when none); once per secret, version and reason |
| `Info`  | `ingress certificate dropped`            | `secret`, `version`, `reason` (`certificate_secret_not_listed` or `rule_removed`) |
| `Warn`  | `ingress certificate does not cover the rule's host` | `rule_id`, `slug`, `sni_host`, `secret`, `version` |
| `Debug` | `ingress connection closed`              | `listen_port`, `remote`, `server_name`, `reason` |
| `Debug` | `ingress acme challenge answered`        | `server_name`, `remote`, `error` |
| `Error` | `bridge: ingress: listen failed`         | `listen_port`, `error`, and `hint` for a permission error below port 1024 |
| `Error` | `bridge: ingress: close listener failed` | `listen_port`, `error` |
| `Error` | `bridge: ingress: dial target failed`    | `rule_id`, `slug`, `target`, `error` |
| `Error` | `ingress reconcile: apply failed`        | `error` |

A rule logs `ingress rule not served` once: an `Apply` that leaves its value and reason unchanged logs nothing for it. The line carries the reasons of the plan. A `terminate` rule's certificate state is logged by the `ingress certificate` lines instead. The ACME account's lines are listed in [ACME and SNI Routing](acme-sni.md#logging).

## Limits

The bridge sets no connection limit and no idle timeout on a public listener. It bounds the ClientHello peek, to 16 KiB and 5 s per connection, and the TLS handshake of a terminating rule or an ACME challenge, to 10 s (`ingressHandshakeTimeout`). For an `acme` rule the 10 s include the wait for a certificate that is still being issued; a client whose certificate is not ready by then is closed with `tls_handshake_failed`, and the issuance goes on in the background. The bounds of the ACME account's own requests are listed in [ACME and SNI Routing](acme-sni.md#limits).
