---
title: Event Verification
package: internal/api
feature: PXD-0025
---

# Event Verification

The `internal/api` package provides Ed25519 signature verification for SSE events received from the control plane. Every event envelope is verified before being dispatched to handlers, ensuring the event was issued by the control plane and has not been tampered with in transit.

## Architecture

```
Control Plane → SSE Stream → SSEManager → Ed25519Verifier → EventDispatcher → Handlers
```

The `EventVerifier` interface decouples verification from the SSE transport:

```go
type EventVerifier interface {
    Verify(ctx context.Context, envelope Envelope) error
}
```

`NoOpVerifier` is the default implementation and accepts every envelope without checking a signature. Production wiring constructs an `Ed25519Verifier` from the signing key persisted in the identity files instead.

## Envelope

`Envelope` is the wire format for signed events. It matches the control plane's OpenAPI v1 events contract:

| Field       | Type              | JSON Tag       | Description                                              |
|-------------|-------------------|----------------|---------------------------------------------------------|
| `ID`        | `string`          | `"id"`         | Unique event identifier (required)                      |
| `Type`      | `string`          | `"type"`       | Event type discriminator (required)                     |
| `Scope`     | `string`          | `"scope"`      | Scope the envelope was signed under: `domain:<uuid>` for the node's Domain, or `platform` |
| `KeyID`     | `string`          | `"key_id"`     | Key id that selects the verifying signing key           |
| `IssuedAt`  | `time.Time`       | `"issued_at"`  | Event timestamp                                         |
| `Payload`   | `json.RawMessage` | `"payload"`    | Event-specific JSON payload (verification re-encodes it but never interprets it) |
| `Signature` | `string`          | `"signature"`  | Base64-encoded Ed25519 signature over the SHA-512 digest of the canonical form |

A realistic envelope on the wire, indented here for reading (it is the [worked example](#worked-example) of the canonical form):

```json
{
  "id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0",
  "type": "policy_updated",
  "scope": "domain:0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1",
  "key_id": "signing-domain-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1-1767225600000000000",
  "issued_at": "2026-05-27T10:00:00Z",
  "payload": {
    "node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a2",
    "policy_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3",
    "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a4",
    "fingerprint": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
    "rules": []
  },
  "signature": "6KztbqXrBOMO6zRemUQKvyjno1s2nSA4l0p1ZVJxfnhwB183pnw1DmRmv71cL6C7uXw3KZOfIAuAKZBAj9FTCA=="
}
```

### Parsing

`ParseEnvelope(data []byte) (Envelope, error)` unmarshals the frame's `data:` bytes and validates the two required fields:

- A JSON decode failure returns `api: envelope: <cause>`.
- A missing `id` returns `api: envelope: missing required field "id"`.
- A missing `type` returns `api: envelope: missing required field "type"`.

The SSE stream logs a parse failure and skips the frame; it never disconnects the stream for a single malformed envelope. Dispatch keys on the verified envelope's `type`, never on the SSE frame's `event:` field.

## Canonical Form

Signature verification is computed over the SHA-512 digest of a deterministic JSON representation of the envelope (see [Signed message](#signed-message)). plexd rebuilds that representation from the decoded values. The frame's `data:` line is not the signed message: its member order, its time format and the spelling of its payload are whatever the control plane's encoder wrote.

`CanonicalBytes(env Envelope) ([]byte, error)` builds the bytes as the "Signed event envelope" section of plexsphere's agent contract (`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere) defines them: one JSON object with exactly these six members, in this order, with no whitespace, no trailing newline and **never** the signature:

1. `id`: the envelope id string.
2. `issued_at`: the instant in UTC with exactly nine fractional digits, so `2026-05-27T10:00:00Z` on the wire becomes `2026-05-27T10:00:00.000000000Z` (Go layout `2006-01-02T15:04:05.000000000Z`).
3. `key_id`: the key id string.
4. `payload`: the payload, decoded and written again by the rules below. An absent or empty payload is `null`.
5. `scope`: an object, not the wire string. `domain:<uuid>` becomes `{"id":"<uuid>","kind":"domain"}`, and `platform` becomes `{"id":"00000000-0000-0000-0000-000000000000","kind":"platform"}`.
6. `type`: the event type string.

The payload is decoded with `UseNumber` and written again:

- Object members are sorted by key at every depth, in byte order (which is UTF-8 order). Array elements keep their order.
- A number that parses as a 64-bit signed or unsigned integer is written in plain decimal. Any other number is parsed as a `float64` and written in its shortest round-trip form, `strconv.FormatFloat(f, 'g', -1, 64)`, so `1.50` becomes `1.5` and `1e3` becomes `1000`.
- Strings, keys included, are written the way `encoding/json` writes them with HTML escaping turned off: `<`, `>` and `&` stay raw, while control characters, U+2028 and U+2029 are escaped. The `id`, `key_id` and `type` strings follow the same rule.
- `true`, `false` and `null` are written as they are.

`CanonicalBytes` returns an error instead of bytes when the envelope has no canonical form:

- A `scope` that is neither `platform` nor `domain:` followed by a lowercase hyphenated UUID returns `api: envelope: canonical scope "<scope>": want "platform" or "domain:<uuid>"`.
- A payload that does not decode returns `api: envelope: canonical payload: <cause>`.
- A payload that holds a second JSON value after the first returns `api: envelope: canonical payload: more than one JSON value`.
- A payload number that does not fit a `float64`, such as `1e400`, returns `api: envelope: canonical payload: number "<n>": <cause>`.

`CanonicalBytes` is the single canonical-form seam shared by the agent's verifier and the e2e mock control plane: the mock signs every envelope it injects over `SignedMessage`, so it signs what plexd verifies. It mirrors the control plane's own `CanonicalBytes` (`internal/signing/envelope/canonical.go` in plexsphere/plexsphere).

### Signed message

The Ed25519 signature does not cover the canonical bytes themselves. `SignedMessage(env Envelope) ([]byte, error)` returns the 64-byte SHA-512 digest of `CanonicalBytes(env)`, and that digest is the message the control plane signs:

```text
signature = Ed25519-Sign(private key, SHA-512(canonical bytes))
```

The envelope carries the signature as standard base64 in its `signature` field. `SignedMessage` returns a `CanonicalBytes` error unchanged. Checking the signature over the canonical bytes directly fails for every envelope.

### Worked example

plexsphere's agent contract closes its "Signed event envelope" section with a worked example. It signs with the Ed25519 secret key of RFC 8032 section 7.1, TEST 1, a published test vector and never a real key. Its public key is `11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=`. The envelope is a `policy_updated` event for the Domain `0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1`, signed with the key `signing-domain-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1-1767225600000000000`. A node receives this `data:` line:

```text
data: {"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","type":"policy_updated","scope":"domain:0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1","key_id":"signing-domain-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1-1767225600000000000","issued_at":"2026-05-27T10:00:00Z","payload":{"node_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a2","policy_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3","revision_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a4","fingerprint":"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=","rules":[]},"signature":"6KztbqXrBOMO6zRemUQKvyjno1s2nSA4l0p1ZVJxfnhwB183pnw1DmRmv71cL6C7uXw3KZOfIAuAKZBAj9FTCA=="}
```

Its canonical bytes, 504 of them, differ from that line in five ways: the members stand in canonical order, `issued_at` carries nine fractional digits, the payload members are sorted, `scope` is an object, and `signature` is gone:

```text
{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","issued_at":"2026-05-27T10:00:00.000000000Z","key_id":"signing-domain-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1-1767225600000000000","payload":{"fingerprint":"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=","node_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a2","policy_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3","revision_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a4","rules":[]},"scope":{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1","kind":"domain"},"type":"policy_updated"}
```

Their SHA-512 digest, in hex, is the message the signature covers:

```text
836b0de19c82abbf8a12c019964789f06918894af27e168caa62bb21f736ac5ec7582962e8f9eca2ef1a38f5169f253a6f9bad5b06f5ce659fe1a1dc8ecc940d
```

`TestCanonicalBytes_AgentContractWorkedExample` in `internal/api/envelope_test.go` pins the example. It parses the `data:` line, compares `CanonicalBytes` with the contract's canonical bytes and checks that they are 504 bytes long, compares `SignedMessage` with the digest, and checks that the signature verifies over the digest under the public key and does not verify over the canonical bytes.

## Verification Steps

`Ed25519Verifier.Verify()` performs these checks in order, returning a descriptive error on the first failure:

1. **Signature present** — a non-empty `signature`, else `api: verifier: missing signature`.
2. **Timestamp present** — a non-zero `issued_at`, else `api: verifier: missing issued_at`.
3. **Staleness** — `time.Since(issued_at)` must be within `DefaultStalenessWindow` (5 minutes), else `api: verifier: event is stale`.
4. **Future timestamp** — `issued_at` must not be more than `DefaultStalenessWindow` in the future, else `api: verifier: event timestamp is in the future`.
5. **Key selection** — a signing key is selected by the envelope's `key_id` (see below); if none matches, `api: verifier: unknown signing key id`.
6. **Ed25519 signature** — the base64 signature is decoded and checked with the selected key against `SignedMessage(env)`, the SHA-512 digest of the canonical bytes. A signature that is not valid base64, or that does not verify, returns `api: verifier: signature verification failed`. An envelope with no canonical form returns `api: verifier: canonical form: <cause>` instead, where `<cause>` is the `CanonicalBytes` error, so the `event verification failed` log line names why plexd could not check the envelope rather than reading like a signature made with the wrong key.

There is no nonce and no replay-tracking step: the events contract carries no nonce, so replay protection is delegated to the transport and to the idempotence of what each event triggers. TLS keeps captured envelopes off the wire; every production event drives an authoritative state pull (a reconcile), which is idempotent under duplicated or reordered delivery; a replayed `rotate_keys` only re-requests a rotation the control plane rejects with `409 keys_rotate_no_pending_rotation` when none is pending; and a replayed `session_revoked` can only close a session the control plane already revoked, which never becomes live again, so it finds nothing to close and only triggers a pull. This is a deliberate trade-off of the contract's no-nonce design, not an oversight.

When verification fails, the SSE stream logs `event verification failed` (with the envelope `type` and `id`) and skips the envelope. A failed envelope is never dispatched to a handler.

## Key Selection and Rotation

`Ed25519Verifier` is keyed by signing key id. `plexd up` constructs it from the `signing_key_id` and `signing_public_key` of the persisted identity: the pair the registration response handed out, or the pair a later state pull installed and persisted (see [Key from the state pull](#key-from-the-state-pull)):

```go
verifier := api.NewEd25519Verifier(identity.SigningKeyID, ed25519.PublicKey(sigKey))
```

At verification time the verifier selects the key that matches the envelope's `key_id`:

- The **current** key id is always accepted.
- The **previous** key id is accepted **only** while `time.Now()` is before `transitionExpires` (the rotation grace window).

Any other `key_id` — including an empty one — is rejected as an unknown signing key id.

### Rotation

The `signing_key_rotated` SSE event carries an `api.SigningKeyRotation` payload, which the event handler applies via `Rotate`:

```go
type SigningKeyRotation struct {
    KeyID             string    `json:"key_id"`
    PublicKey         string    `json:"public_key"`
    PreviousKeyID     string    `json:"previous_key_id"`
    TransitionExpires time.Time `json:"transition_expires"`
}
```

`Rotate(rot SigningKeyRotation) error` installs `key_id`/`public_key` as the new current key. It retains a previous key as a grace entry **only** when all of these hold:

- `previous_key_id` is non-empty, and
- `transition_expires` is non-zero, and
- `previous_key_id` matches a key id the verifier currently holds (its current or its previous key id).

When any of those conditions is unmet — an empty `previous_key_id`, a zero `transition_expires`, or an unknown previous key id — no grace entry is kept and only the new current key is accepted after the rotation.

`Rotate` returns an error and leaves the installed keys **unchanged** when:

- `key_id` is empty — `api: verifier: rotation missing key_id`.
- `public_key` is not valid base64 — `api: verifier: rotation public key: <cause>`.
- the decoded key is not 32 bytes — `api: verifier: rotation public key: invalid length: got N, want 32`.

The rotation event is itself signed with the current (pre-rotation) key, so each key vouches for its successor.

### Key from the state pull

Every successful state pull (`GET /v1/nodes/{node_id}/state`) carries a `signing_key` block: the node's Domain signing key as `{"key_id": "…", "public_key": "…"}`, or `null`, as the "Domain signing key" section of plexsphere's agent contract describes it. The block decodes into `NodeStateSnapshot.SigningKey`, a `*NodeStateSigningKey`:

```go
type NodeStateSigningKey struct {
    KeyID     string `json:"key_id"`
    PublicKey string `json:"public_key"`
}
```

`public_key` is the standard base64 of the 32-byte Ed25519 public key, the same encoding `POST /v1/register` uses. A `null` block, or a missing one from a control plane that predates the block, decodes to nil. A nil block means "keep the key you hold", never "drop it". The reconcile snapshot store neither stores nor diffs the block.

`signingKeyDispatchHandler` (`cmd/plexd/cmd/up.go`) consumes the block. It is the first dispatch handler `plexd up` registers, so the rest of the reconcile cycle already runs under the pulled key. On every successful pull it:

1. ignores a nil block, logging `state pull carried no signing key; keeping the installed one` at Debug;
2. hands the key to `Install(key NodeStateSigningKey) (bool, error)`, which makes it the current key, and stops there when `Install` refuses it;
3. logs `installed signing key from state pull` at Info when `Install` changed the key, with `key_id` and `public_key` (the base64 value an operator copies into `tunnel.session_signing_public_key`);
4. persists a pulled pair that differs from the persisted one with `registration.CommitSigningKey(dataDir, keyID, publicKey)`, whether or not `Install` changed the verifier.

`Install` compares the pulled pair with the current one:

- A key whose id and bytes both equal the current pair changes nothing. `Install` returns `false` and keeps any rotation grace entry, so a pull that carries the key a `signing_key_rotated` event already installed leaves that rotation's grace window open.
- Any other key replaces the current key and drops the grace entry, because a node trusts exactly one key of its Domain. Envelopes signed with the replaced key are refused from then on, and the pull converges whatever they carried.

`Install` returns an error and leaves the installed keys unchanged when:

- `key_id` is empty: `api: verifier: install: missing key_id`.
- `public_key` is not valid base64: `api: verifier: install: public key: <cause>`.
- the decoded key is not 32 bytes: `api: verifier: install: public key: invalid length: got N, want 32`.

The handler logs a refused key at Warn as `signing key from state pull rejected`, with `key_id` and `error`, once, and not again until a pull carries a different key (a control plane that serves a broken block serves it on every pull), and changes nothing.

`CommitSigningKey` rewrites the identity file group under `identityMu`: the `signing_public_key` file first, then `signing_key_id` and `signing_public_key` in `identity.json`. Every other identity field is written back as it was loaded. On an empty data dir it returns an error wrapping `ErrNotRegistered` and writes nothing. When the commit fails, the handler logs `signing key not persisted; retrying on the next pull` at Warn, with `key_id` and `error`. The installed key stays in force and every later pull retries the commit. A crash between the two writes leaves a mismatched pair; the next start seeds the verifier from it, and its first pull differs from that pair in at least one field, so `Install` installs the key again and the handler commits it again.

The verifier that `Install` updates also answers `TrustedKeys`, which ssh session token checks use, so a pulled key reaches mediated ssh logins as well. The mesh SSH server (`tunnel.ssh_listen_addr`) keeps the key its JWT verifier loaded at start; after a restart that is the persisted key. On Linux, a socket-activated session helper that already pinned a key keeps its pin: see [Trust anchor](../networking/secure-access-tunneling.md#trust-anchor).

## Thread Safety

All verifier operations are safe for concurrent use:

- `Verify()` acquires a read lock while selecting the key.
- `Rotate()` and `Install()` acquire a write lock to install the new key material.
