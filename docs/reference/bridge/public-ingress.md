---
title: Public Ingress
package: internal/bridge
feature: PXD-0014
---

# Public Ingress

Public ingress lets a bridge node publish services that run on nodes of its Domain. A client outside the mesh connects to a public TCP port of the bridge, and the bridge forwards the connection over the mesh to a port on the target node. Each published service is a rule of the `bridge.ingress` block of the bridge's state pull, which an operator authors on the bridge Resource in the control plane.

The bridge opens one TCP listener per distinct listen port. A port with a rule that names no `sni_host` forwards every connection without reading it. On a port whose rules name hosts, the bridge reads the server name of each connection's TLS ClientHello and routes by it, so several HTTPS services share port 443. A `passthrough` rule forwards the TLS session to the target unchanged. A `terminate` rule ends TLS at the bridge with the certificate of the Secret it names, and an `acme` rule with a certificate the bridge obtains from an ACME CA; both forward plaintext to the target.

## Data Flow

![Public internet clients open TCP connections to a listen port of the bridge node, which runs one listener per listen port. On the plain port :2222 a connection goes to the target dial without being read. On the SNI port :443 the bridge peeks the ClientHello and matches the server name; a passthrough rule replays the peeked bytes, and a terminate or acme rule ends TLS at the bridge. Both go on to dial the target over plexd0, which reaches the target address and port on the target node. IngressReconcileHandler calls IngressManager.Apply, which swaps the ingressTable of each port in place. IngressSecretInventoryHandler supplies the terminate certificates, and ACMEManager the acme certificates and the challenges on :443.](../../diagrams/bridge-public-ingress.svg)

The control plane delivers the block in the state pull and announces a change with a `bridge_config_updated` event, which only triggers a pull (see [SSE event handling](#sse-event-handling)). `IngressReconcileHandler` hands the block to `IngressManager.Apply`, which plans the rules, opens and closes listeners, swaps each port's routing table, and then configures the ACME account. `IngressSecretInventoryHandler` hands the pull's secret inventory to `IngressManager.SyncSecretInventory` on every successful pull, which loads, replaces and drops the certificates of the `terminate` rules (see [Certificates from the Secret Store](#certificates-from-the-secret-store)). The certificates of the `acme` rules come from `ACMEManager` (see [ACME and SNI Routing](acme-sni.md)).

The bridge's dial to a target is traffic the bridge itself sends over the mesh, which its compiled policy governs (see [What the rules govern](../networking/pf-wfp-firewall.md#what-the-rules-govern)). A rule grants no allow of its own: the policy needs a rule that allows TCP from the bridge's mesh IP to the target's address and port. A Project's allow-all policy covers every mesh address. Without such a rule the dial fails, the bridge logs `bridge: ingress: dial target failed` with `reason=policy_denied`, and the rule's entry in the [ingress status report](#rule-entries) reads `dial` `failed` with `dial_reason` `policy_denied`.

## The bridge.ingress Block

The block is the control plane's `NodeStateBridgeIngress`, each rule a `NodeStateBridgeIngressRule`, and its `acme` member a `NodeStateBridgeIngressACME`. The agent contract's `## Public ingress` section in plexsphere's `docs/reference/api/plexd-agent-contract.md` defines it, and its sections `### Terminate rules` and `### ACME rules` define where the certificates come from. The pull lists the rules by `slug` ascending. A bridge with one rule per mode and one plain TCP rule pulls:

```json
"bridge": {
  "ingress": {
    "enabled": true,
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

The `enabled` member is the control plane's switch for the block: a bridge serves the rules only when it is `true` and the bridge's local configuration does not opt out (see [Activation](#activation)). The control plane sends `true` on every block it delivers, and a bridge without rules gets no block at all.

The `acme` member is the ACME account the block's `acme` rules share. The control plane sends it exactly when the block holds an `acme` rule:

| Field | Type | Description |
|---|---|---|
| `directory_url` | string | The ACME directory (RFC 8555) the bridge registers its account at and orders certificates from. The bridge accepts only an absolute https URL, and only one that `bridge.acme_directory_urls` lists when that list is not empty (see [The ACME Account](acme-sni.md#the-acme-account)) |
| `contact_email` | string, optional | The contact the account registers with. Without it the account has no contact |

The block is whole: a rule missing from a later pull is removed, and a port no rule names any more is closed. An `ingress` child that is absent or `null` closes every public listener. An `ingress` child with an empty or `null` rule list does the same, and so does a block whose `enabled` is `false` or absent, whatever rules it lists. A changed `enabled`, `acme` member or `certificate_secret_name` is bridge drift like any other change to the block.

## Activation

A bridge serves the pulled block when three conditions hold:

1. It runs in bridge mode: `mode: bridge` and `bridge.enabled: true`.
2. Its local configuration does not opt out: `bridge.ingress_enabled` is absent or `true`.
3. The block carries `enabled: true`.

The control plane sends `enabled: true` on every block, so the bridge host's configuration decides. A bridge with `bridge.ingress_enabled: false` opts out: step 5e of `plexd up` builds neither the ingress manager nor the ACME manager, so no code path can bind a public port, and the bridge opens no public listener whatever the pull says. It logs `public ingress: opted out by bridge.ingress_enabled, no public listener is opened` at start, and `bridge subsystem initialized` reads `ingress=false`. On every other bridge in bridge mode, `plexd up` builds both managers, and a block whose `enabled` is `false` or absent opens no public listener (see [IngressReconcileHandler](#ingressreconcilehandler)). An `acme` rule needs no local switch of its own.

Every bridge reports which of the two its configuration says with the [ingress status report](#ingress-status-report), `enabled` or `opted_out`, and the control plane answers a rule create or update on a bridge that reported `opted_out` with `409 bridge_ingress_opted_out`. The report never gates serving. plexd reads its configuration once per start, so a changed `bridge.ingress_enabled` takes effect, and is reported, with the next restart.

The control plane enables ingress by default, a bridge host opts out in its local configuration, and plexd keeps no compatibility path. Two consequences of an upgrade follow and are intended:

- A bridge that upgrades without `bridge.ingress_enabled` in its configuration starts serving the rules the control plane delivers. A host that must stay closed sets `bridge.ingress_enabled: false` before it upgrades.
- A control plane older than [plexsphere/plexsphere#1090](https://github.com/plexsphere/plexsphere/pull/1090) sends blocks without `enabled`. plexd then opens no public listener, as the contract states for a block without the member.

| Field                | Type            | Default | Description                                      |
|----------------------|-----------------|---------|--------------------------------------------------|
| `IngressEnabled`     | `*bool`         | `true`  | `bridge.ingress_enabled`: the local switch for public ingress (nil = true). nil and `true` serve, `false` opts out and is reported as `opted_out`. `ApplyDefaults` leaves it nil, and `IngressOptedOut()` is true exactly when it is non-nil and `false` |
| `MaxIngressRules`    | `int`           | `20`    | `bridge.max_ingress_rules`: the most rules the bridge holds |
| `IngressDialTimeout` | `time.Duration` | `10s`   | `bridge.ingress_dial_timeout`: the timeout for dialing a target |
| `ACMECacheDir`       | `string`        | `""`    | `bridge.acme_cache_dir`: the directory of the ACME account key and the certificates of `acme` rules; empty means `<data_dir>/acme` (see [The Cache Directory](acme-sni.md#the-cache-directory)) |
| `ACMEDirectoryURLs`  | `[]string`      | empty   | `bridge.acme_directory_urls`: the ACME directories the bridge accepts from the block's `acme` member; empty accepts any https directory |

Every reader of `IngressEnabled` outside `config.go` goes through `IngressOptedOut()`. `Validate` checks the ingress fields as follows:

| Field                | Rule                    | Error Message                                                               |
|----------------------|-------------------------|-----------------------------------------------------------------------------|
| `IngressEnabled`     | An explicit `true` requires `Enabled=true` | `bridge: config: ingress requires bridge mode to be enabled`                |
| `MaxIngressRules`    | Must be > 0 when `Enabled` is true and `IngressOptedOut()` is false | `bridge: config: MaxIngressRules must be positive when ingress is enabled`  |
| `IngressDialTimeout` | Must be >= 1s when `Enabled` is true and `IngressOptedOut()` is false | `bridge: config: IngressDialTimeout must be at least 1s`                    |

An absent key and an explicit `false` are valid without `Enabled`, so a node outside bridge mode loads without the key. `ParseConfig` applies the defaults before anything validates, so only an explicit bad value fails: a bridge whose configuration never enabled ingress and carries `max_ingress_rules: -1` or `ingress_dial_timeout: 500ms` fails `plexd up` with these messages until it corrects the value or sets `bridge.ingress_enabled: false`.

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

Certificates and their keys live in memory only. Nothing writes a certificate Secret's value to disk, a restart fetches every certificate again, and `Teardown` forgets the inventory and every certificate. No log line and no error carries a Secret's value.

`cmd/plexd/cmd/node_secrets.go` implements `CertificateSecretFetcher` with `nodeSecretFetcher`, over `ControlPlane.FetchSecret` and `nodeapi.DecryptSecret`. The same fetcher reads the join key of a `tailscale` or `netbird` user access provider and the key of a site-to-site tunnel through `FetchSecretValue`, which delegates to `FetchCertificateSecret` (see [VPN Providers](vpn-providers.md#the-join-key) and [Tunnel Providers](tunnel-providers.md#the-key)):

```go
type nodeSecretFetcher struct {
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

The bridge dials `target_address:target_port` with `ingress_dial_timeout` and copies both ways, the plaintext of a terminated session included, until one side ends or the rule is removed or changed. A failed dial closes the client connection and logs `bridge: ingress: dial target failed` with the dial's `reason`.

Right after each dial, the manager records its outcome per rule id, with the target it dialled and the time on its clock, and the ingress status report reads it as the rule's `dial` (see [Rule Entries](#rule-entries)). A dial whose route was cancelled meanwhile, because the rule changed or was removed or the manager stopped, records nothing, and its error, `context.Canceled` or a failure of a target the rule no longer names, is not classified. `Apply` drops the records of rules it no longer holds and `Teardown` drops them all, so the manager holds at most `bridge.max_ingress_rules` records. A connection costs one lock and one map write more for the record.

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

`Apply` does not read the block's `enabled` member: [IngressReconcileHandler](#ingressreconcilehandler) hands it the zero block when the pull does not enable ingress.

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

Neither `acme` nor `certs` may be nil. In bridge mode, `plexd up` reads the node secret key with `identity.SecretKey()` (an error fails `plexd up` as `plexd up: <error>`) and builds `nodeSecretFetcher` with it once, when the bridge serves public ingress, user access or site-to-site tunnels. Unless `bridge.ingress_enabled` is `false`, it builds the `ACMEManager` over the cache directory (`bridge.acme_cache_dir`, or `<data_dir>/acme`) and passes the two to `NewIngressManager`. A bridge that opts out builds neither manager and reads no node secret key for ingress; it reads the key for user access or site-to-site tunnels unless `bridge.user_access_enabled` and `bridge.site_to_site_enabled` are `false` too.

Concurrent-safe via `sync.Mutex`. The connection counter is an `atomic.Int64`.

| Method                | Signature                                                   | Description |
|-----------------------|-------------------------------------------------------------|-------------|
| `Setup`               | `() error`                                                  | Marks the manager active; a no-op when `IngressOptedOut()` is true |
| `Apply`               | `(ctx context.Context, block api.IngressConfig) error`      | Serves exactly this block (see [Applying the Block](#applying-the-block)) |
| `SyncSecretInventory` | `(ctx context.Context, inventory []api.NodeStateSecret)`    | Takes the pull's secret inventory and loads, replaces or drops the certificates of the held `terminate` rules (see [Certificates from the Secret Store](#certificates-from-the-secret-store)); a no-op when inactive |
| `RuleStates`          | `() []IngressRuleState`                                     | The outcome of the last `Apply`, one entry per rule, in block order, with each `terminate` rule's certificate state |
| `RuleReports`         | `() []IngressRuleReport`                                    | What the ingress status report says per rule: listener, certificate and last dial (see [Rule Entries](#rule-entries)); nil when inactive |
| `ReportChanged`       | `() <-chan struct{}`                                        | Signalled, without blocking, when what `RuleReports` returns may have changed; capacity 1 |
| `SetDialPolicy`       | `(p IngressDialPolicy)`                                     | Sets the policy that names a failed dial `policy_denied`; called before `Setup`. Without one, no dial reads `policy_denied` |
| `Teardown`            | `() error`                                                  | Cancels every route, which closes every connection, closes every listener, and forgets the inventory and every certificate; joins close errors; a no-op when inactive |
| `IngressStatus`       | `() *api.IngressInfo`                                       | The `status.ingress` report entry; nil when inactive |
| `IngressCapabilities` | `() map[string]string`                                      | `{"ingress": "true", "max_ingress_rules": "<n>"}`; nil when `IngressOptedOut()` is true |

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

```go
type IngressRuleReport struct {
    RuleID            string
    Listener          string    // api.IngressListener*
    ListenerReason    string
    Certificate       string    // api.IngressCertificate*; empty when the rule does not listen
    CertificateReason string
    Dial              string    // api.IngressDial*; empty when the rule does not listen
    DialReason        string
    DialAt            time.Time // zero unless Dial is succeeded or failed
}

// IngressDialPolicy tells whether the node's compiled policy blocks a TCP dial to target.
type IngressDialPolicy interface {
    DialDenied(target netip.AddrPort) bool
}
```

`NewIngressManager` registers with `ACMEManager.OnIssuedChange`, so an `acme` rule's certificate state signals `ReportChanged`. `plexd up` sets the dial policy before `Setup` from `cmd/plexd/cmd/ingress_policy.go`: `ingressDialPolicy` asks `Enforcer.AdmitsTCPDial` with the node's mesh address when a UDP connect to the target picks that address as its source. A mesh address that does not parse leaves the policy unset and logs the Warn `ingress: mesh ip is not an address, a policy-blocked dial is reported by its network error`.

`IngressStatus().RuleCount` counts the served rules with the certificate state applied, so a `terminate` rule counts only while it has a certificate. `ConnectionCount` counts the connections from accept to close. `ACMEEnabled` reads `ACMEManager.Active()`: it is true exactly while the last `Apply` ended with an `acme` rule without a reason. An `acme` rule whose port failed to bind reads `listen_failed` and does not count.

## IngressReconcileHandler

```go
func IngressReconcileHandler(mgr *IngressManager, logger *slog.Logger) reconcile.ReconcileHandler
```

Returns a `reconcile.ReconcileHandler` that serves the pull's `bridge.ingress` block when the block enables ingress. `mgr` is nil on a bridge that opts out with `bridge.ingress_enabled: false`, as the relay is nil on a bridge without relay consent in [`RelayReconcileHandler`](nat-relay.md#relayreconcilehandler). The handler honors the block's `enabled` member, and `Apply` serves exactly the block the handler hands it:

| `mgr` | Pulled block | What the handler does |
|---|---|---|
| any | nil snapshot | Returns nil |
| set | `Bridge` or `Ingress` nil | Applies the zero block |
| set | `enabled` true | Applies the block |
| set | `enabled` false, no rules | Applies the zero block |
| set | `enabled` false, at least one rule | Logs the Warn `ingress: the state pull carries rules but does not enable public ingress, closing every listener` with `rules=<n>`, then applies the zero block |
| nil | `enabled` true, at least one rule | Logs the Warn `ingress: the control plane enables public ingress, but bridge.ingress_enabled is false` with `rules=<n>`, and returns nil |
| nil | anything else | Returns nil without a log line |

`enabled` false covers a block without the member, which decodes to `false`. To apply, the handler passes its context and the block to `mgr.Apply(ctx, block)`, and on an error logs `ingress reconcile: apply failed` and returns it. A failed bind therefore fails the reconcile cycle, so the reconciler keeps its snapshot, and the next pull tries the bind again.

Reconcile handlers run only on a cycle with drift, but on every such cycle: a changed peer or policy runs the handler too. The handler therefore logs its two Warn lines only when the cycle's diff has `BridgeChanged` set. `enabled` is part of the bridge block the differ compares, so a flip of `enabled` is bridge drift, and each Warn is logged once per change of the pulled `bridge` block, the first pull after every start included, because the reconciler's snapshot starts empty. A cycle in which a handler fails keeps the old snapshot, so the next cycle sees the same bridge drift and logs the Warn again. Applying the zero block is not gated: it runs on every cycle with drift, and a zero block after a zero block changes nothing.

## IngressSecretInventoryHandler

```go
func IngressSecretInventoryHandler(mgr *IngressManager) reconcile.DispatchHandler
```

The handler runs on the dispatch seam, on every successful pull, drift or not (see [DispatchHandler](../core/reconciliation.md#dispatchhandler)). It returns for a nil `desired.Secrets`, which keeps the inventory the manager holds, and otherwise calls `mgr.SyncSecretInventory(ctx, *desired.Secrets)`. A pull whose only change is the `secrets` block reports an empty diff and runs no reconcile handler, so without this handler no reconcile handler would see a Secret rotation. Dispatch handlers run before the reconcile handlers of a cycle, so a cycle that brings a new rule and its Secret hands the inventory over first, and the `Apply` of that cycle fetches the certificate.

`cmd/plexd/cmd/up.go` registers `IngressReconcileHandler` whenever bridge mode runs, with a nil `ingressMgr` on a bridge that opts out, and `IngressSecretInventoryHandler` only when the ingress manager exists:

```go
if ingressMgr != nil {
    reconciler.RegisterDispatchHandler(bridge.IngressSecretInventoryHandler(ingressMgr))
}
reconciler.RegisterHandler(bridge.IngressReconcileHandler(ingressMgr, logger)) // ingressMgr is nil on an opted-out bridge
```

## Ingress Status Report

A bridge reports with [`PUT /v1/nodes/{node_id}/ingress-status`](../core/api-endpoints.md#ingress-status) whether its local configuration serves public ingress, so the control plane refuses an ingress rule that no listener would serve, and how each ingress rule fares: whether its listener is up, whether its certificate is in place, and how the last dial to its target ended. Without the report, a Project operator who writes a rule for a bridge whose host opted out gets `201` and a bridge that never listens, and an operator whose published service is unreachable has to read the bridge's journal to learn why. Every node in bridge mode reports, whether or not it opts out, and a node outside bridge mode sends nothing. No configuration key turns the report on or off.

### Reported States

| State | `bridge.ingress_enabled` | Meaning |
|-------|--------------------------|---------|
| `enabled` | absent or `true` | The bridge serves the rules the pull enables |
| `opted_out` | `false` | The bridge built no ingress manager and opens no public listener whatever the pull says |

The state follows from the local configuration alone, which plexd reads once per start, so one process always reports the same state. A report of `opted_out` carries the state alone.

### Rule Entries

An `enabled` report carries `rules`: one entry per rule of the last applied block, in the order of the pull, built from `IngressManager.RuleReports`. Each member after `listener` is sent exactly when the facet before it calls for it:

| Member | Values | Present |
|---|---|---|
| `id` | the rule's `id` from the pull | always |
| `listener` | `listening` or `not_listening` | always |
| `listener_reason` | a reason token | exactly when `listener` is `not_listening` |
| `certificate` | `not_required`, `ready` or `not_ready` | exactly when `listener` is `listening` |
| `certificate_reason` | a reason token | exactly when `certificate` is `not_ready` |
| `dial` | `none`, `succeeded` or `failed` | exactly when `listener` is `listening` |
| `dial_reason` | a reason token | exactly when `dial` is `failed` |
| `dial_age_seconds` | whole seconds from the dial to the report, floored, from 0 to 2147483647 | exactly when `dial` is `succeeded` or `failed` |

A rule whose `id` is no UUID in canonical form, or is the zero UUID, has no entry, and neither has a rule whose `id` an earlier rule of the block carried, compared without case. The control plane refuses a whole report for one such entry, and the refused report would take the bridge's `state` with it. Both rules read `invalid_rule` or `duplicate_id` in the Warn `ingress rule not served`. A report carries no `detail`: a Secret name, a directory URL, a slug and an error text stay in the bridge's log.

The listener is read from the ports the last `Apply` bound, not from the rule's reason:

| Rule after the last `Apply` | `listener` | `listener_reason` |
| --- | --- | --- |
| not held | `not_listening` | its reason: `invalid_rule`, `listener_conflict` or `max_rules` |
| held, and its listen port is not bound | `not_listening` | `listen_failed` |
| held, and its listen port is bound | `listening` | none |

A held `acme` rule with a reason of the plan, such as `acme_directory_invalid`, on a port that failed to bind reads `listen_failed`. For a rule that listens:

| Rule | `certificate` | `certificate_reason` |
| --- | --- | --- |
| `passthrough` | `not_required` | none |
| `terminate`, certificate loaded | `ready` | none |
| `terminate`, no certificate loaded | `not_ready` | `certificate_secret_not_listed`, `certificate_fetch_failed` or `certificate_invalid`, as `RuleStates` reads it |
| `acme` with a reason of the plan | `not_ready` | `acme_directory_invalid`, `acme_directory_not_allowed` or `acme_challenge_port_taken` |
| `acme`, `ACMEManager.Issued` true for its host | `ready` | none |
| `acme` otherwise | `not_ready` | `acme_not_issued` |

`acme_not_issued` reads until the last certificate request for the host succeeds: the obtain ahead of the first client or a client handshake (see [Obtaining a Certificate](acme-sni.md#obtaining-a-certificate)). A host whose obtain failed keeps it until a client's handshake makes `autocert` ask again and succeed; plexd does not retry an issuance on its own.

The dial is the last one a client connection caused to the rule's target (see [Routing a Connection](#routing-a-connection)). The bridge never dials a target on its own to test it, so `dial` reads `none` until the first connection to a rule, and a failed dial stays the rule's state until a later client's dial succeeds. A rule whose target changed reads `none`, and so does a rule removed and applied again. The reason of a failed dial is the first of these that applies:

1. `policy_denied`: the dial policy says the node's compiled policy blocks a TCP dial to the target (see below).
2. `timeout`: the dial did not complete within `bridge.ingress_dial_timeout`, or failed with a timeout error (`WSAETIMEDOUT` on Windows).
3. `refused`: the target's host refused the connection (`ECONNREFUSED`, `WSAECONNREFUSED`).
4. `unreachable`: no route reaches the target's host or network (`EHOSTUNREACH`, `ENETUNREACH`, and their Winsock names).
5. `other`.

A rule grants no allow of its own, so the likeliest failure of a correct rule is a missing Policy for the bridge's dial, and its fix is in the control plane. On the bridge that failure looks like any other failed dial: the nftables backend ends a denied packet in a drop verdict, so the socket gets no error that names the policy, and what a blocked dial fails with differs by backend. `plexd up` therefore gives the manager a dial policy, which checks a failed dial against the ruleset the Enforcer installed, in user space, after the failure: `Enforcer.AdmitsTCPDial` (see [network policy](../networking/network-policy.md#methods)). The check applies only when the kernel would send the dial from the node's mesh address, which a UDP connect to the target tells without sending a packet. A target outside the mesh, the mesh address itself and a target no route reaches never read `policy_denied`. The kernel stays the only place that enforces: the bridge dials as before, and the check only names the reason. A failed dial costs one UDP socket and one pass over the installed rules; a dial that succeeds costs neither.

### Reporter

`IngressStatusReporter` (`ingress_status.go`) sends the report from a goroutine of its own.

```go
type IngressStatusClient interface {
    ReportIngressStatus(ctx context.Context, nodeID string, req api.IngressStatusRequest) (*api.IngressStatusResponse, error)
}

// IngressRuleReportSource is the part of *IngressManager the reporter reads.
type IngressRuleReportSource interface {
    RuleReports() []IngressRuleReport
    ReportChanged() <-chan struct{}
}

func NewIngressStatusReporter(interval time.Duration, nodeID string, client IngressStatusClient,
    optedOut bool, rules IngressRuleReportSource, logger *slog.Logger) *IngressStatusReporter
func (r *IngressStatusReporter) Run(ctx context.Context) error // returns nil when ctx is done
```

`*api.ControlPlane` satisfies `IngressStatusClient`. The state is fixed at construction: `api.IngressStateOptedOut` when `optedOut` is true, `api.IngressStateEnabled` otherwise. `rules` is nil on an opted-out bridge. A non-positive `interval` becomes 30 s, the default `heartbeat.interval`. The reporter's logger carries `component=bridge`.

`Run` logs `ingress status: reporter started` with `interval` and `state`, sends one report at once, and then:

- **On a change.** When `ReportChanged` signals, it builds the report and does nothing when its entries equal those of the last accepted report, `dial_age_seconds` ignored. Otherwise it sends when at least 5 s (`ingressStatusChangeGap`) have passed since the last on-change send, and arms one timer for the rest of the 5 s when they have not; the timer builds, compares and sends the same way, with the entries as they are then. An on-change send restarts the interval. Only on-change sends count for the 5 s; the send at start and the tick sends do not.
- **On a tick.** It drops a pending change signal and the timer, and sends.
- **When `ctx` is done.** It returns nil and sends nothing.

The manager signals `ReportChanged` liberally, without blocking, and the reporter compares before it sends: at the end of every `Apply`, every certificate load and `Teardown`, when the ACME manager's issued hosts change, and when a dial record changes its outcome or reason. A moving dial age alone triggers no report.

A manager that reports more than 1,024 rules has the first 1,024 sent, in order, and the reporter logs the Warn `ingress status: more rules than a report carries, reporting the first 1024` with `rules` once on entering that state.

The type carries five decisions:

- **The send at start.** The reporter sends at once, without waiting for a state pull, unlike the [relay status reporter](nat-relay.md#reporter), which waits for its reconcile handler: the relay's state comes from the pull, the ingress state from the configuration, which plexd has read by then. Because plexd reads the configuration once per start (it handles SIGTERM and SIGINT only), the send after each start is the report "on every change of its setting" that the contract asks for. That report carries no entries, because no pull is applied yet; the first `Apply` signals a change, and the entries follow at once.
- **The 5 s bound.** Dial outcomes follow public connections. Without the bound, a target that alternates between failing and answering would cost one request per flip.
- **No retry within a tick.** A failed send is not retried before the next tick. The last accepted report stays what it was, so the tick, or the next change, sends the state and the entries as they are then. An opt-out whose first send fails reaches the control plane at most one interval later, and the bridge is closed the whole time.
- **No shutdown report.** The state is sticky, and a stopped bridge keeps the state its configuration gives it, so the reporter sends nothing when `ctx` ends. Its rule entries read `stale` once its reports stop.
- **The report never gates serving.** A bridge serves as the pull says while a send fails or the control plane does not serve the operation, as the contract requires. The reporter only reads the ingress manager.

A bridge sends at most one report per 5 s on change and one per interval, each under 250 bytes per entry.

Step 17d of `plexd up` starts `bridge.NewIngressStatusReporter(statusInterval, identity.NodeID, client, cfg.Bridge.IngressOptedOut(), ingressRules, logger)` in a goroutine under the shutdown `WaitGroup`, beside the relay status reporter, whenever bridge mode runs. `statusInterval` is `heartbeat.interval`. `ingressRules` is the ingress manager, or an untyped nil on a bridge that opts out: a nil `*IngressManager` in the interface would not compare equal to nil. The shutdown sequence needs no step of its own: the reporter ends with `ctx`.

### Answers

No answer stops the loop, and none touches the listeners:

| Answer | Reporter behavior |
|--------|-------------------|
| `200 OK` | Debug `ingress status: accepted` with `state`, `rules` (the number of entries sent) and `accepted_at` on every accepted send. Info `ingress status: reported` with `state` and `rules` for the first accepted send. After a not-served phase, one Info `ingress status: control plane accepts ingress status reports` |
| `404` with any code but `ingress_status_node_gone`, or `501 ingress_status_not_provisioned` | The control plane does not serve the report, as `api.IsIngressStatusNotServed` classifies it. Info `ingress status: control plane does not accept ingress status reports, retrying every interval` with `status` and `code`, once on entering that state. plexd keeps reporting every interval and keeps serving as the pull says |
| `404 ingress_status_node_gone` | The node was removed while the request ran. Warn `ingress status: rejected, this node was removed` with `code` on every send. It does not enter the not-served state |
| `api.ErrCredentialRefused` | Debug `ingress status: send failed` with `error`. The heartbeat parked the agent on a refused credential and names the cause once |
| Any error after `ctx` ended | Nothing, because that is the shutdown |
| Anything else, `400 malformed_ingress_status`, `400 invalid_ingress_status`, `413 ingress_status_body_too_large` and `context.DeadlineExceeded` included | Warn `ingress status: send failed` with `error`, on every send |

A control plane that predates `rules` answers `400 malformed_ingress_status` to every `enabled` report with entries, as an unknown member. plexd has no fallback: the control plane is upgraded before the agent, and the Warn names the code.

### What the Control Plane Does

The control plane keeps the latest state per node and never ages it, so a bridge that reported `opted_out` and went offline stays opted out until it reports `enabled`. A report that repeats the stored state changes nothing. While a bridge's report reads `opted_out`, the control plane answers a create or an update of an ingress rule on its bridge Resource with `409 bridge_ingress_opted_out`. It keeps the rules stored before the opt-out and keeps delivering them in the `bridge.ingress` block with `enabled: true`. The opted-out bridge ignores them and logs the Warn `ingress: the control plane enables public ingress, but bridge.ingress_enabled is false`, and it serves them again once a restart without the opt-out makes it report `enabled`. A delete of a rule stays allowed. A bridge that never reported reads `not_reported` and accepts rules. A node reports only for itself, so a leaked NSK can block rule writes on its own bridge Resource and on no other. A control plane that predates the report answers `404`, and plexd keeps serving as the pull says.

Each report replaces the rule entries of the one before, and the control plane dates each dial on its own clock, as the receive time minus `dial_age_seconds`. It derives each rule's status from the latest report; a bridge that has not reported for three heartbeat intervals has its rules read `stale`, and a rule the report does not name reads `not_reported`. See [Ingress status](https://github.com/plexsphere/plexsphere/blob/16f468bfc58128dd46f06e64196bf9b71e146986/docs/reference/api/plexd-agent-contract.md#ingress-status) in plexsphere's agent contract.

## SSE Event Handling

There are no ingress-specific SSE handlers. The control plane emits a single `bridge_config_updated` event with an opaque payload; `bridge.HandleBridgeConfigUpdated` dispatches it to `TriggerReconcile()`, and `IngressReconcileHandler` applies the block from the authoritative state snapshot. `node_secrets_updated` also only triggers a pull, whose `secrets` block reaches `IngressSecretInventoryHandler`.

## API Types

### IngressConfig

`api.BridgeSnapshot.Ingress`, present-but-nullable.

```go
type IngressConfig struct {
    // Enabled is the control plane's switch: a bridge serves Rules only when
    // it is true and its local configuration does not opt out. A block
    // without the member decodes to false and opens no public listener. The
    // control plane sends true on every block it delivers.
    Enabled bool          `json:"enabled"`
    Rules   []IngressRule `json:"rules"`
    // ACME is the account the block's acme rules share, the control plane's
    // NodeStateBridgeIngressACME. It is present exactly when a rule has mode acme.
    ACME *IngressACME `json:"acme,omitempty"`
}
```

`Enabled` carries no `omitempty`, so a zero `IngressConfig` marshals with `"enabled":false`.

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
| `nodeSecretFetcher` (fetch)             | `fetch secret "<name>" version <v>: `          |
| `nodeSecretFetcher` (version)           | `fetch secret "<name>": asked for version <v>, got <w>` |
| `nodeSecretFetcher` (decrypt)           | `decrypt secret "<name>" version <v>: `        |
| `Config.Validate` (ACME directories)    | `bridge: config: acme_directory_urls: "<entry>" is not an absolute https URL` |

## Logging

All ingress log entries use `component=bridge`, the reporter's included. `bridge subsystem initialized`, which step 5e of `plexd up` logs, carries `ingress=false` on a bridge that opts out.

| Level   | Message                                  | Keys |
|---------|------------------------------------------|------|
| `Info`  | `public ingress: opted out by bridge.ingress_enabled, no public listener is opened` | (none); logged by step 5e of `plexd up` on a bridge with `bridge.ingress_enabled: false` |
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
| `Warn`  | `ingress: the state pull carries rules but does not enable public ingress, closing every listener` | `rules`; once per change of the pulled `bridge` block |
| `Warn`  | `ingress: the control plane enables public ingress, but bridge.ingress_enabled is false` | `rules`; once per change of the pulled `bridge` block, on a bridge that opts out |
| `Info`  | `ingress status: reporter started`       | `interval`, `state` |
| `Info`  | `ingress status: reported`               | `state`, `rules`; logged for the first accepted send |
| `Info`  | `ingress status: control plane does not accept ingress status reports, retrying every interval` | `status`, `code`; logged on entering the not-served state only |
| `Info`  | `ingress status: control plane accepts ingress status reports` | (none); logged once after a not-served phase |
| `Warn`  | `ingress status: rejected, this node was removed` | `code`; logged on every send |
| `Warn`  | `ingress status: send failed`            | `error` |
| `Warn`  | `ingress status: more rules than a report carries, reporting the first 1024` | `rules`; once on entering that state |
| `Warn`  | `ingress: mesh ip is not an address, a policy-blocked dial is reported by its network error` | `mesh_ip`, `error`; logged by step 5e of `plexd up` |
| `Debug` | `ingress status: accepted`               | `state`, `rules`, `accepted_at` |
| `Debug` | `ingress status: send failed`            | `error`; logged instead of the Warn while the client holds a refused credential (`api.ErrCredentialRefused`) |
| `Debug` | `ingress connection closed`              | `listen_port`, `remote`, `server_name`, `reason` |
| `Debug` | `ingress acme challenge answered`        | `server_name`, `remote`, `error` |
| `Error` | `bridge: ingress: listen failed`         | `listen_port`, `error`, and `hint` for a permission error below port 1024 |
| `Error` | `bridge: ingress: close listener failed` | `listen_port`, `error` |
| `Error` | `bridge: ingress: dial target failed`    | `rule_id`, `slug`, `target`, `reason`, `error`; `reason` is absent for a dial whose route was cancelled meanwhile |
| `Error` | `ingress reconcile: apply failed`        | `error` |

A rule logs `ingress rule not served` once: an `Apply` that leaves its value and reason unchanged logs nothing for it. The line carries the reasons of the plan. A `terminate` rule's certificate state is logged by the `ingress certificate` lines instead. The ACME account's lines are listed in [ACME and SNI Routing](acme-sni.md#logging).

## Limits

The bridge sets no connection limit and no idle timeout on a public listener. It bounds the ClientHello peek, to 16 KiB and 5 s per connection, and the TLS handshake of a terminating rule or an ACME challenge, to 10 s (`ingressHandshakeTimeout`). For an `acme` rule the 10 s include the wait for a certificate that is still being issued; a client whose certificate is not ready by then is closed with `tls_handshake_failed`, and the issuance goes on in the background. The bounds of the ACME account's own requests are listed in [ACME and SNI Routing](acme-sni.md#limits).
