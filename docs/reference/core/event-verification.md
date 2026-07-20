---
title: Event Verification
package: internal/api
feature: PXD-0025
---

# Event Verification

The `internal/api` package provides Ed25519 signature verification for SSE events received from the control plane. Every event envelope is verified before being dispatched to handlers, ensuring authenticity and preventing replay attacks.

## Architecture

```
Control Plane → SSE Stream → SSEManager → Ed25519Verifier → EventDispatcher → Handlers
```

The `EventVerifier` interface decouples verification from the SSE transport:

```go
type EventVerifier interface {
    Verify(ctx context.Context, envelope SignedEnvelope) error
}
```

## Canonical JSON Format

Signature verification uses a deterministic JSON representation of the envelope fields. The canonical form includes exactly these fields in struct-defined order:

```json
{
  "event_type": "node_state_updated",
  "event_id": "evt-abc-123",
  "issued_at": "2025-01-15T10:30:00Z",
  "nonce": "random-nonce-value",
  "payload": { ... }
}
```

The Go struct tag ordering ensures deterministic serialization via `encoding/json`:

```go
type canonicalEnvelope struct {
    EventType string          `json:"event_type"`
    EventID   string          `json:"event_id"`
    IssuedAt  time.Time       `json:"issued_at"`
    Nonce     string          `json:"nonce"`
    Payload   json.RawMessage `json:"payload"`
}
```

The signature is computed as `ed25519.Sign(privateKey, canonicalJSON)` and transmitted as base64-encoded bytes in the `signature` field of the envelope.

## Verification Steps

The `Ed25519Verifier.Verify()` method performs these checks in order:

1. **Signature present** — envelope must have a non-empty `signature` field
2. **Nonce present** — envelope must have a non-empty `nonce` field
3. **Timestamp present** — `issued_at` must be non-zero
4. **Staleness check** — `time.Since(issued_at)` must be within 5 minutes (`DefaultStalenessWindow`)
5. **Future timestamp check** — `issued_at` must not be more than `DefaultStalenessWindow` in the future
6. **Ed25519 signature** — `ed25519.Verify(publicKey, canonicalJSON, signatureBytes)` must return true
7. **Nonce uniqueness** — nonce must not have been seen before (replay protection; recorded only after signature verification to prevent nonce exhaustion via forged envelopes)

If any check fails, the event is rejected with a descriptive error.

## Nonce Replay Protection

The `NonceStore` prevents replay attacks by tracking recently seen nonces:

| Parameter        | Value   | Description                                |
|------------------|---------|--------------------------------------------|
| Nonce TTL        | 5 min   | Duration nonces are remembered             |
| Cleanup interval | 60 sec  | How often expired nonces are garbage-collected |

The store uses a `sync.Mutex`-protected `map[string]time.Time`. Cleanup runs lazily on the next `Add()` call after the cleanup interval elapses.

## Signing Key Rotation

The verifier supports zero-downtime key rotation by holding two keys simultaneously:

| Field               | Type                | Description                              |
|---------------------|---------------------|------------------------------------------|
| `currentKey`        | `ed25519.PublicKey` | Primary verification key                 |
| `previousKey`       | `ed25519.PublicKey` | Previous key accepted during transition  |
| `transitionExpires` | `time.Time`         | Deadline after which previous key is rejected |

### Rotation Flow

1. Control plane generates a new signing key pair
2. Control plane sends `signing_key_rotated` SSE event with both keys and a transition deadline
3. Agent updates verifier via `SetKeys(current, previous, transitionExpires)`
4. During the transition period, signatures from either key are accepted
5. After `transitionExpires`, only the current key is accepted

### Update Sources

Keys are updated from two sources:

- **Registration** — the initial verifier key comes from the registration response's `signing_public_key`
- **SSE event** — the `signing_key_rotated` event handler decodes the rotated keys and calls `verifier.SetKeys()` immediately

Signing keys no longer ride the state snapshot: the reconcile loop has no signing-keys handler. The `signing_key_rotated` SSE payload decodes base64-encoded keys from `api.SigningKeys`:

```go
type SigningKeys struct {
    Current           string     `json:"current"`
    Previous          string     `json:"previous,omitempty"`
    TransitionExpires *time.Time `json:"transition_expires,omitempty"`
}
```

## Thread Safety

All verifier operations are safe for concurrent use:

- `Verify()` acquires a read lock on the key pair
- `SetKeys()` acquires a write lock to replace keys
- `NonceStore.Add()` is mutex-protected
