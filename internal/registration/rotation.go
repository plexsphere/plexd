package registration

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"

	"github.com/plexsphere/plexd/internal/fsutil"
)

// pendingKeyFile holds a freshly staged rotation private key. It sits next to
// private_key in the data dir and uses the same standard base64 encoding.
const pendingKeyFile = "rotation_pending_key"

// SavePendingKey stages the fresh rotation private key on disk before its public
// half is submitted to the control plane. Persisting it first makes rotation
// crash-safe: if the process dies after the server learns the new public key, a
// startup resubmit can recover the matching private key from this file.
func SavePendingKey(dataDir string, kp *Keypair) error {
	data := []byte(base64.StdEncoding.EncodeToString(kp.PrivateKey))
	if err := fsutil.WriteFileAtomic(dataDir, pendingKeyFile, data, 0600); err != nil {
		return fmt.Errorf("registration: save pending key: %w", err)
	}
	return nil
}

// LoadPendingKey reads a staged rotation keypair from dataDir. It returns
// (nil, nil) when no key is staged so callers can distinguish "nothing pending"
// from a read error. The public key is re-derived from the stored private key.
func LoadPendingKey(dataDir string) (*Keypair, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, pendingKeyFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("registration: load pending key: %w", err)
	}

	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("registration: load pending key: %w", err)
	}
	if n := len(priv); n != 32 {
		return nil, fmt.Errorf("registration: load pending key: key must be 32 bytes, got %d", n)
	}

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("registration: load pending key: %w", err)
	}

	return &Keypair{PrivateKey: priv, PublicKey: pub}, nil
}

// ClearPendingKey removes the staged rotation key. A missing file is not an
// error: clearing is the terminal step of a rotation and must be idempotent.
func ClearPendingKey(dataDir string) error {
	if err := os.Remove(filepath.Join(dataDir, pendingKeyFile)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("registration: clear pending key: %w", err)
	}
	return nil
}

// CommitRotatedKey performs the post-confirmation swap after the control plane
// accepts a rotation. It durably installs kp as the node's private_key, records
// the receipt in identity.json, and only then drops the staging file. A nil
// receipt keeps the previous LastRotation, which happens when the server answers
// 422 unchanged on a crash-retry of an already-committed rotation. Rotation only
// ever owns private_key and last_rotation; every other identity field is taken
// from disk, so a re-registration that happened after id was loaded is not
// overwritten with the caller's stale copy.
func CommitRotatedKey(dataDir string, id *NodeIdentity, kp *Keypair, receipt *RotationReceipt) error {
	// identityMu makes the read-modify-write below atomic against a concurrent
	// SaveIdentity; see its declaration for what interleaving would otherwise
	// cost.
	identityMu.Lock()
	defer identityMu.Unlock()

	// Re-read identity.json first: id may predate a re-registration that wrote a
	// new node_id, mesh_ip, and node_secret_key. Serialising the caller's copy
	// would rebind the on-disk credential to the deleted node's identity.
	current, err := LoadIdentity(dataDir)
	if err != nil {
		return fmt.Errorf("registration: commit rotated key: %w", err)
	}
	if receipt != nil {
		current.LastRotation = receipt
	}

	// private_key: base64-encoded, same as SaveIdentity.
	privKeyData := []byte(base64.StdEncoding.EncodeToString(kp.PrivateKey))
	if err := fsutil.WriteFileAtomic(dataDir, "private_key", privKeyData, 0600); err != nil {
		return fmt.Errorf("registration: commit rotated key: %w", err)
	}

	// Rewrite identity.json without SaveIdentity's remove-first dance:
	// identity.json holds no key material, so a torn combination of the new
	// private_key with an old identity.json is safe. Removing it first would
	// instead open an identity-less window that, on a crash, forces an
	// impossible re-registration (the bootstrap token is long gone).
	jsonData, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return fmt.Errorf("registration: commit rotated key: %w", err)
	}
	if err := fsutil.WriteFileAtomic(dataDir, "identity.json", jsonData, 0600); err != nil {
		return fmt.Errorf("registration: commit rotated key: %w", err)
	}

	// Keep the caller's in-memory identity in step with what was just written.
	id.PrivateKey = kp.PrivateKey
	id.LastRotation = current.LastRotation

	// Drop the staging file last. A crash after the private_key write but before
	// this removal is recovered by the idempotent resubmit at startup.
	if err := ClearPendingKey(dataDir); err != nil {
		return fmt.Errorf("registration: commit rotated key: %w", err)
	}
	return nil
}
