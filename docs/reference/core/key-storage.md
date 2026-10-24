---
title: Key Storage
package: internal/registration
feature: PXD-0003
---

# Key Storage

plexd stores cryptographic keys and identity material in a single directory on the node filesystem. All key files are written atomically via `fsutil.WriteFileAtomic` and restricted to owner-only access. This page documents every key type, its purpose, storage format, lifecycle, and the security properties that protect it.

## Overview

During registration, the control plane provisions the node with several cryptographic artifacts. These are persisted to `data_dir` so that the node can rejoin the mesh, decrypt secrets, and verify SSE events across restarts. The stored keys are:

- **Curve25519 private key** -- mesh encryption (WireGuard)
- **Pre-Shared Keys (PSK)** -- per-peer-pair post-quantum defense layer
- **Node Secret Key (NSK)** -- AES-256-GCM secret decryption
- **Ed25519 signing public key** -- SSE event and JWT verification
- **Bootstrap token** -- one-time registration credential (its file is removed after use, or emptied where it cannot be removed)

## Storage Location

All key material is stored under `data_dir`, which defaults to `/var/lib/plexd/` on Linux and to a platform location on macOS and Windows (see [Platform defaults](configuration.md#platform-defaults)). The directory is created with mode `0700` if it does not already exist.

| Setting | Default | Description |
|---------|---------|-------------|
| `data_dir` | `/var/lib/plexd` (Linux) | Root directory for identity and key files ([per platform](configuration.md#platform-defaults)) |

The directory is also referenced by `registration.data_dir` and `node_api.data_dir`, which are propagated from the top-level `data_dir` at runtime. See the [Configuration Reference](configuration.md) for details.

## Key Types

| File | Key Type | Algorithm | Purpose | Received From |
|------|----------|-----------|---------|---------------|
| `private_key` | Curve25519 private key | X25519 (WireGuard) | Mesh traffic encryption and authentication | Generated locally during registration |
| `rotation_pending_key` | Curve25519 private key (staged) | X25519 (WireGuard) | Staged private key for an in-flight rotation; same base64 encoding as `private_key`; removed on completion or discard | Generated locally when a rotation is signaled |
| (in-memory, per peer) | Pre-Shared Key (PSK) | 256-bit symmetric | Post-quantum defense layer for each peer pair | Control plane, delivered with peer configuration |
| `node_secret_key` | Node Secret Key (NSK) | AES-256-GCM | Decrypts secret values fetched from the control plane | Control plane, issued during registration |
| `signing_public_key` | Ed25519 public key | Ed25519 | Verifies SSE event signatures and session JWT tokens | Control plane, issued during registration and carried by the state pull's `signing_key` block |
| `identity.json` | Node identity metadata | N/A | Stores `node_id`, `mesh_ip`, `signing_key_id`, and `signing_public_key` | Control plane registration response; the two signing fields are rewritten from the state pull |
| (bootstrap token file) | Bootstrap token | N/A | One-time authentication for initial registration | Provisioned externally (file, env var, or metadata service) |

### Curve25519 Private Key

The Curve25519 keypair is generated locally by the node during registration (`internal/registration`). The private key is base64-encoded and written to `data_dir/private_key`. The corresponding public key is sent to the control plane as part of the registration request; it is not stored separately on disk.

WireGuard uses this keypair for all mesh traffic encryption. When keys are rotated, a new keypair is generated and its public key is uploaded via `POST /v1/keys/rotate`; the control plane returns a rotation receipt (`rotation_id`, `kid`, `wrap_key_version`). The updated peer view arrives afterwards via the state pull, not as a response peer list.

### Pre-Shared Keys (PSK)

PSKs are 256-bit symmetric keys assigned per peer pair by the control plane. They are delivered as part of the `Peer` structure (field `psk`, base64-encoded) and applied to the WireGuard interface at configuration time. PSKs provide a post-quantum defense layer: even if Curve25519 is broken in the future, an attacker who did not also compromise the PSK cannot decrypt captured traffic.

PSKs are not written to individual files on disk. They are part of the peer configuration that the WireGuard subsystem applies to the kernel interface. They are refreshed whenever the control plane distributes updated peer lists (e.g., after key rotation or reconciliation).

### Node Secret Key (NSK)

The NSK is an AES-256 symmetric key used with GCM mode to decrypt secret values fetched from the control plane (`GET /v1/nodes/{node_id}/secrets/{key}`). It is received during registration and stored as a raw string in `data_dir/node_secret_key`.

The NSK is rotated independently of the mesh keypair:

- **Mesh keypair only** -- when the control plane signals `rotate_keys` via heartbeat response or SSE event, only the Curve25519 mesh keypair is rotated. The `POST /v1/keys/rotate` response carries no NSK.
- **NSK rotation** -- the control plane rotates the NSK as an independent concern, without rotating the Curve25519 mesh keypair.

After rotation, the control plane re-encrypts all secrets with the new NSK. The old NSK is overwritten atomically on disk.

### Ed25519 Signing Public Key

The control plane's Ed25519 signing public key is used by the node for two purposes:

1. **SSE event signature verification** -- every `Envelope` received on the SSE stream is verified against this key before dispatch (see [Event Verification](event-verification.md)).
2. **Session JWT validation** -- session tokens presented during secure access tunneling are validated using the same key.

The node learns the key, and the id it signs under, from two sources:

- Registration: `POST /v1/register` returns `signing_key_id` and `signing_public_key`, which `SaveIdentity` writes with the rest of the identity.
- The state pull: every `GET /v1/nodes/{node_id}/state` response carries the key as the `signing_key` block (`key_id`, and `public_key` as the 32-byte key in standard base64), as the "Domain signing key" section of plexsphere's agent contract (`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere) describes it. plexd installs it into the verifier on every successful pull and persists a key that differs from the stored pair (see [Signing Key from the State Pull](#signing-key-from-the-state-pull)). A `null` or absent block means the node keeps the key it holds, never that it drops it. A node enrolled before its Domain had a key of its own learns that key here.

The key is stored as a raw string in `data_dir/signing_public_key` and also recorded in `identity.json`. On load, the file value takes precedence if it differs from the JSON field (a warning is logged).

The key id is recorded in `identity.json` as `signing_key_id`. At startup plexd seeds the verifier from this persisted pair, so a node that installed a key from a pull restarts with that key. A key installed from a pull reaches ssh session logins too, because the ssh session listener checks tokens against the verifier's keys. The mesh SSH server (`tunnel.ssh_listen_addr`) keeps the key it loaded at start, which after a restart is the persisted key.

`CommitSigningKey(dataDir, keyID, publicKey)` (`internal/registration/signing_key.go`) persists a pulled key. It holds the lock that `SaveIdentity` and `CommitRotatedKey` hold, re-reads the identity, writes the `signing_public_key` file first and then `identity.json` with the new `signing_key_id` and `signing_public_key`, and writes every other field (`last_rotation` included) back as it was loaded. On a data dir that holds no identity it returns an error wrapping `ErrNotRegistered` and writes nothing. A crash between the two writes leaves a mismatched pair. The next pull's key differs from that pair in at least one field, so plexd installs and commits the key again.

The Linux socket-activated session helper trusts `tunnel.session_signing_public_key` when it is set. Otherwise it pins the signing key from `identity.json` at `/etc/plexd/session-signing-key` on its first run. Because a pull can rewrite `identity.json`, a helper that has not pinned yet pins the key plexd last persisted, and deleting the pin makes it pin that key again. A helper that already pinned a key keeps it. See [Trust anchor](../networking/secure-access-tunneling.md#trust-anchor) for nodes whose pin holds an older key.

plexd also handles a `signing_key_rotated` SSE event, which plexsphere's agent contract does not define. Its payload is `api.SigningKeyRotation`:

```go
type SigningKeyRotation struct {
    KeyID             string    `json:"key_id"`
    PublicKey         string    `json:"public_key"`
    PreviousKeyID     string    `json:"previous_key_id"`
    TransitionExpires time.Time `json:"transition_expires"`
}
```

`Rotate` makes the event's key current. It keeps the previous key in memory as a grace entry only when `previous_key_id` names a key the verifier holds and `transition_expires` is set. Until that deadline, events signed with either key pass verification; after it, only the current key is used. The event changes only the verifier in memory and writes nothing to disk. A different key installed from the state pull drops the grace entry (see [Signing Key from the State Pull](#signing-key-from-the-state-pull)).

### Bootstrap Token

The bootstrap token is a one-time credential used to authenticate the initial registration request. It can be sourced from a file (`/etc/plexd/bootstrap-token` on Linux; see [Platform defaults](configuration.md#platform-defaults)), an environment variable (`PLEXD_BOOTSTRAP_TOKEN`), a direct value, or a cloud metadata service.

The token is **removed from disk immediately after successful registration** to prevent reuse. Under plexd's systemd unit `/etc` is read-only and only the token file itself is writable, so the unlink fails and the file is emptied instead; the resolver skips an empty file:

```go
// 9. Delete token file if applicable.
if tokenResult.FilePath != "" {
    if err := os.Remove(tokenResult.FilePath); err != nil && !errors.Is(err, os.ErrNotExist) {
        if terr := os.Truncate(tokenResult.FilePath, 0); terr != nil {
            r.logger.Warn("failed to delete token file", ..., "truncate_error", terr)
        } else {
            r.logger.Info("token file emptied, it could not be removed", ...)
        }
    }
}
```

## File Permissions

All key files are written with mode `0600` (owner read/write only). The `data_dir` directory itself is created with mode `0700`. Files are written atomically using `fsutil.WriteFileAtomic`, which writes to a temporary file first and then renames it into place, ensuring readers never observe a partially-written file.

| Path | Mode | Contents |
|------|------|----------|
| `data_dir/` | `0700` | Key storage directory |
| `data_dir/identity.json` | `0600` | `node_id`, `mesh_ip`, `signing_key_id`, `signing_public_key`, `last_rotation` (rotation receipt) (JSON) |
| `data_dir/private_key` | `0600` | Base64-encoded Curve25519 private key |
| `data_dir/rotation_pending_key` | `0600` | Base64-encoded staged rotation private key |
| `data_dir/node_secret_key` | `0600` | Raw AES-256 Node Secret Key |
| `data_dir/signing_public_key` | `0600` | Raw Ed25519 public key string |

The plexd process should run as a dedicated `plexd` user. No other user or group needs read access to these files.

## Key Lifecycle

### Generation and Initial Storage

1. **Bootstrap token** is provisioned out-of-band (file, env var, metadata).
2. Node generates a **Curve25519 keypair** locally.
3. Node calls `POST /v1/nodes/register` with the bootstrap token and public key.
4. Control plane responds with `node_id`, `mesh_ip`, `node_secret_key`, `signing_public_key`, and peer list (including PSKs).
5. `SaveIdentity` writes `identity.json`, `private_key`, `node_secret_key`, and `signing_public_key` atomically with `0600` permissions.
6. Bootstrap token file is removed from disk, or emptied when it cannot be removed (as under plexd's systemd unit).

### Rotation

Key rotation can be triggered in two ways:

- **Heartbeat response** -- the control plane sets `rotate_keys: true` in the `HeartbeatResponse`, causing the node to trigger reconciliation which performs the rotation.
- **SSE events** -- specific events signal individual key rotations.

The Domain signing key also changes through the state pull's `signing_key` block (see [Signing Key from the State Pull](#signing-key-from-the-state-pull)).

#### Mesh Key Rotation (`rotate_keys`)

1. Control plane signals rotation via the heartbeat `rotate_keys` flag or the `rotate_keys` SSE event.
2. Node loads the staged `rotation_pending_key`, or generates a fresh Curve25519 keypair and stages it crash-safe (base64, mode `0600`, atomic write) **before** any HTTP call.
3. Node calls `POST /v1/keys/rotate` with `{new_public_key}`.
4. On a `200` receipt carrying `rotation_id` and `kid` -- or a `422 keys_rotate_public_key_unchanged`, which means an earlier submission already landed -- the node commits: it swaps `private_key`, persists the receipt as `last_rotation` in `identity.json`, and removes the staging file. The commit re-reads `identity.json` first, so it only ever advances `private_key` and `last_rotation` and never writes back an identity that a re-registration has replaced.
5. Node updates the WireGuard device private key, retrying a failed install with a backoff that spans about two minutes: the committed key is already published to every peer, so a device left on the old key would reject every handshake.
6. Node triggers a reconcile -- the propagated peer and PSK changes arrive via the state pull, not as a rotate response.

On `409 keys_rotate_no_pending_rotation` the signal is stale or cancelled, so the staged key is discarded. A permanent rejection -- `400`, `403`, `413`, `404 keys_rotate_peer_not_found`, or `422 keys_rotate_public_key_invalid` -- discards it too, because no resubmit changes the answer. A staged key that never received a terminal answer -- after a crash between a landed submit and the local commit, a `5xx`, or a `200` whose body carries no receipt because the control plane predates this contract -- is resubmitted by `RecoverPending` with a capped exponential backoff (5s doubling to 2min). That sweep runs for the lifetime of the process, not only at startup: a rotation the control plane completed is never signalled again, so a submit whose response was lost would otherwise leave the node on the old key until a restart.

#### NSK Rotation

The NSK is rotated together with mesh keys or independently via the control plane. After rotation:

- The new NSK is written atomically to `data_dir/node_secret_key`, overwriting the old value.
- The control plane re-encrypts all secrets with the new NSK.
- Secrets are fetched in real-time (not cached as plaintext), so no historical ciphertext accumulates on-node.

#### Signing Key from the State Pull

When an operator rotates the Domain signing key, the control plane serves the incoming key in the `signing_key` block, so the node's next pull carries it. The dispatch handler that applies the block is registered first among the reconcile dispatch handlers, so the rest of the cycle already runs under the pulled key. On every successful pull:

1. A `null` or absent block changes nothing. plexd logs `state pull carried no signing key; keeping the installed one` at Debug.
2. The verifier's `Install` refuses a block with no `key_id`, or a `public_key` that is not standard base64 or does not decode to 32 bytes. The keys stay as they were, and plexd logs `signing key from state pull rejected` (`key_id`, `error`) at Warn once, not again on every pull that repeats the same block.
3. A key whose id and bytes both equal the current pair changes nothing and leaves a rotation's grace entry in place. Any other key replaces the current key and drops the grace entry, because a node trusts exactly one Domain key. plexd logs `installed signing key from state pull` with `key_id` and `public_key` at Info; that `public_key` is the value an operator sets as `tunnel.session_signing_public_key` for a session helper that pinned an older key.
4. A pulled key that differs from the persisted pair is written with `CommitSigningKey`. A failed write logs `signing key not persisted; retrying on the next pull` (`key_id`, `error`) at Warn and is retried on every pull.

A pull install has no transition period: from that pull on, the verifier accepts envelopes signed with the new key only.

#### Signing Key Rotation (`signing_key_rotated`)

1. A `signing_key_rotated` SSE event arrives, signed with a key the verifier already accepts.
2. The event payload carries the new key's `key_id` and `public_key`, a `previous_key_id`, and a `transition_expires` timestamp.
3. The node's `Ed25519Verifier` makes the new key current. It accepts signatures from the previous key until `transition_expires` only when `previous_key_id` names a key the verifier holds and the deadline is set.
4. After the transition expires, only the new key is used for verification.

The event updates the verifier in memory only. A later pull that carries a different key replaces the current key and drops the grace entry.

### Deletion

- **Bootstrap token**: deleted immediately after successful registration.
- **Local identity**: `plexd deregister` is a local-only cleanup (no control-plane call) that removes just `identity.json` from `data_dir`. `plexd deregister --purge` additionally removes the rest of `data_dir` — the remaining identity and key files and cached state — and the registration token file.

## Security Considerations

- **File permissions**: all key files use `0600`; the data directory uses `0700`. Only the plexd process owner can read key material.
- **Atomic writes**: `fsutil.WriteFileAtomic` ensures that a crash during a write never leaves a corrupted or partial key file on disk.
- **No plaintext secret caching**: secrets are decrypted in memory on demand via the NSK. No plaintext secret values are persisted to disk.
- **One-time bootstrap token**: the token is deleted after registration, limiting the window for token theft and replay.
- **Transition period for signing keys**: during a rotation announced by a `signing_key_rotated` event that names the previous key and a deadline, both old and new signing keys are accepted, preventing event verification failures during rollover. After the transition expires, only the new key is trusted. A key installed from the state pull has no transition period: it replaces the current key, because a node trusts exactly one Domain key.
- **PSK as post-quantum layer**: even if the Curve25519 key exchange is compromised (e.g., by a future quantum computer), the per-peer PSK provides an additional symmetric encryption layer that protects captured traffic.
- **NSK rotation invalidates old ciphertext**: after NSK rotation, secrets encrypted with the old key cannot be decrypted by the node. The control plane re-encrypts with the new NSK.
- **TLS on all control plane communication**: key material is exchanged over TLS-protected channels, mitigating interception during registration and key rotation.

## Source Reference

| Component | Source |
|-----------|--------|
| Identity persistence | `internal/registration/identity.go` |
| Registration flow | `internal/registration/registrar.go` |
| Atomic file writes | `internal/fsutil/atomic.go` |
| Signing key rotation and state pull handlers | `cmd/plexd/cmd/up.go` |
| Signing key install and rotation | `internal/api/verifier.go` |
| Signing key persistence | `internal/registration/signing_key.go` |
| WireGuard peer key rotation | `internal/wireguard/handler.go` |
| Key rotate API endpoint | `internal/api/endpoints.go` |
| Key rotation service | `internal/agent/keyrotation.go` |
| Rotation staging and receipt | `internal/registration/rotation.go` |
| Event types | `internal/api/envelope.go` |
| Signing key types | `internal/api/types.go` |
