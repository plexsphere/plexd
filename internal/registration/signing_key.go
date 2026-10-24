package registration

import (
	"encoding/json"
	"fmt"

	"github.com/plexsphere/plexd/internal/fsutil"
)

// CommitSigningKey persists a Domain signing key learned after registration,
// the one a state pull carried, into the identity file group: the
// signing_public_key file and identity.json's signing_key_id and
// signing_public_key. A restart then seeds the verifier with it rather than with
// the key registration handed out, and a session helper that has not pinned a
// key yet pins this one.
//
// It re-reads the group under identityMu and changes only the two signing
// fields, so every other field, last_rotation included, is written back as it
// was loaded. The file is written before identity.json, as SaveIdentity does. A
// crash between the two writes leaves a mismatched pair, which the next start's
// first pull repairs: its key differs from that pair in at least one field, so
// the verifier installs it and the caller commits it again.
//
// An empty data dir returns an error wrapping ErrNotRegistered and writes
// nothing.
func CommitSigningKey(dataDir, keyID, publicKey string) error {
	// identityMu makes the read-modify-write below atomic against SaveIdentity
	// and CommitRotatedKey; see its declaration.
	identityMu.Lock()
	defer identityMu.Unlock()

	current, err := LoadIdentity(dataDir)
	if err != nil {
		return fmt.Errorf("registration: commit signing key: %w", err)
	}

	if err := fsutil.WriteFileAtomic(dataDir, "signing_public_key", []byte(publicKey), 0600); err != nil {
		return fmt.Errorf("registration: commit signing key: %w", err)
	}

	// Rewrite identity.json without SaveIdentity's remove-first step, for the
	// reason CommitRotatedKey gives: identity.json holds no key material, and an
	// identity-less window would force an impossible re-registration on a crash.
	current.SigningKeyID = keyID
	current.SigningPublicKey = publicKey
	jsonData, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return fmt.Errorf("registration: commit signing key: %w", err)
	}
	if err := fsutil.WriteFileAtomic(dataDir, "identity.json", jsonData, 0600); err != nil {
		return fmt.Errorf("registration: commit signing key: %w", err)
	}
	return nil
}
