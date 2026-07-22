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

`NoOpVerifier` is the default implementation and accepts every envelope without checking a signature. Production wiring constructs an `Ed25519Verifier` from the registration-persisted signing key instead.

## Envelope

`Envelope` is the wire format for signed events. It matches the control plane's OpenAPI v1 events contract:

| Field       | Type              | JSON Tag       | Description                                              |
|-------------|-------------------|----------------|---------------------------------------------------------|
| `ID`        | `string`          | `"id"`         | Unique event identifier (required)                      |
| `Type`      | `string`          | `"type"`       | Event type discriminator (required)                     |
| `Scope`     | `string`          | `"scope"`      | Scope the event applies to                              |
| `KeyID`     | `string`          | `"key_id"`     | Key id that selects the verifying signing key           |
| `IssuedAt`  | `time.Time`       | `"issued_at"`  | Event timestamp                                         |
| `Payload`   | `json.RawMessage` | `"payload"`    | Event-specific JSON payload (opaque to verification)    |
| `Signature` | `string`          | `"signature"`  | Base64-encoded Ed25519 signature over the canonical form |

A realistic envelope on the wire:

```json
{
  "id": "evt-9f2a1c",
  "type": "node_state_updated",
  "scope": "node:n_abc123",
  "key_id": "did:web:plexsphere.com#key-2026-01",
  "issued_at": "2026-01-15T10:30:00Z",
  "payload": { "revision": 42 },
  "signature": "base64-encoded-ed25519-signature"
}
```

### Parsing

`ParseEnvelope(data []byte) (Envelope, error)` unmarshals the frame's `data:` bytes and validates the two required fields:

- A JSON decode failure returns `api: envelope: <cause>`.
- A missing `id` returns `api: envelope: missing required field "id"`.
- A missing `type` returns `api: envelope: missing required field "type"`.

The SSE stream logs a parse failure and skips the frame; it never disconnects the stream for a single malformed envelope. Dispatch keys on the verified envelope's `type`, never on the SSE frame's `event:` field.

## Canonical Form

Signature verification is computed over a deterministic JSON representation of the envelope. `CanonicalBytes(env Envelope) ([]byte, error)` serializes exactly these fields, in this order, and **never** the signature:

```json
{"id":"evt-9f2a1c","type":"node_state_updated","scope":"node:n_abc123","key_id":"did:web:plexsphere.com#key-2026-01","issued_at":"2026-01-15T10:30:00Z","payload":{"revision":42}}
```

The Go struct tag ordering fixes the serialization:

```go
type canonicalEnvelope struct {
    ID       string          `json:"id"`
    Type     string          `json:"type"`
    Scope    string          `json:"scope"`
    KeyID    string          `json:"key_id"`
    IssuedAt time.Time       `json:"issued_at"`
    Payload  json.RawMessage `json:"payload"`
}
```

A nil `Payload` serializes as `"payload":null`. The signature is `ed25519.Sign(privateKey, canonicalBytes)` transmitted as base64 in the envelope's `signature` field.

::: info Author-approved assumption
`CanonicalBytes` is the single canonical-form seam shared between the agent and the e2e mock control plane. The real control plane's own canonical-bytes helper is not published, so this field set and ordering is an author-approved assumption. A future mismatch with the real control plane is corrected in this one function, and both the agent verifier and the mock signer follow it.
:::

## Verification Steps

`Ed25519Verifier.Verify()` performs these checks in order, returning a descriptive error on the first failure:

1. **Signature present** — a non-empty `signature`, else `api: verifier: missing signature`.
2. **Timestamp present** — a non-zero `issued_at`, else `api: verifier: missing issued_at`.
3. **Staleness** — `time.Since(issued_at)` must be within `DefaultStalenessWindow` (5 minutes), else `api: verifier: event is stale`.
4. **Future timestamp** — `issued_at` must not be more than `DefaultStalenessWindow` in the future, else `api: verifier: event timestamp is in the future`.
5. **Key selection** — a signing key is selected by the envelope's `key_id` (see below); if none matches, `api: verifier: unknown signing key id`.
6. **Ed25519 signature** — the base64 signature is decoded and checked against `CanonicalBytes(env)` with the selected key. A decode failure, a canonicalization failure, or a signature that does not verify all return `api: verifier: signature verification failed`.

There is no nonce and no replay-tracking step: the events contract carries no nonce, so replay protection is delegated to the transport and to the idempotence of what each event triggers. TLS keeps captured envelopes off the wire; every production event drives an authoritative state pull (a reconcile), which is idempotent under duplicated or reordered delivery; and a replayed `rotate_keys` only re-requests a rotation the control plane rejects with `409 keys_rotate_no_pending_rotation` when none is pending. This is a deliberate trade-off of the contract's no-nonce design, not an oversight.

When verification fails, the SSE stream logs `event verification failed` (with the envelope `type` and `id`) and skips the envelope. A failed envelope is never dispatched to a handler.

## Key Selection and Rotation

`Ed25519Verifier` is keyed by signing key id. It is constructed from the registration response's `signing_key_id` and `signing_public_key`:

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

The rotation event is itself signed with the current (pre-rotation) key, so each key vouches for its successor. Signing keys never ride the state snapshot; the reconcile loop has no signing-key handler.

## Thread Safety

All verifier operations are safe for concurrent use:

- `Verify()` acquires a read lock while selecting the key.
- `Rotate()` acquires a write lock to install the new key material.
