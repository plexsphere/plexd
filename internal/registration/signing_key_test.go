package registration

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// Two distinct, well-formed Ed25519 public keys in the encoding the identity
// files and the state pull use.
var (
	oldSigningKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize))
	newSigningKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, ed25519.PublicKeySize))
)

// saveSigningKeyIdentity writes a full identity holding the old signing key.
func saveSigningKeyIdentity(t *testing.T, dir string) *NodeIdentity {
	t.Helper()
	id := &NodeIdentity{
		NodeID:           "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3",
		MeshIP:           "100.64.0.7",
		SigningPublicKey: oldSigningKey,
		SigningKeyID:     "kid-old",
		DomainMeshCIDR:   "100.64.0.0/10",
		LastRotation:     &RotationReceipt{RotationID: "rot-1", KID: "mesh-kid", WrapKeyVersion: 3},
		PrivateKey:       bytes.Repeat([]byte{0x33}, 32),
		NodeSecretKey:    testNSK,
	}
	if err := SaveIdentity(dir, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	return id
}

func readFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func TestCommitSigningKey_RewritesTheSigningFields(t *testing.T) {
	dir := t.TempDir()
	saved := saveSigningKeyIdentity(t, dir)
	privateKey := readFile(t, dir, "private_key")
	nsk := readFile(t, dir, "node_secret_key")

	if err := CommitSigningKey(dir, "kid-new", newSigningKey); err != nil {
		t.Fatalf("CommitSigningKey: %v", err)
	}

	got, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if got.SigningKeyID != "kid-new" || got.SigningPublicKey != newSigningKey {
		t.Errorf("signing pair = (%q, %q), want (kid-new, the new key)", got.SigningKeyID, got.SigningPublicKey)
	}
	if string(readFile(t, dir, "signing_public_key")) != newSigningKey {
		t.Errorf("signing_public_key file = %q, want the new key", readFile(t, dir, "signing_public_key"))
	}
	// LoadIdentity prefers the signing_public_key file over identity.json, so
	// identity.json itself is read raw: both of its signing fields must move.
	var raw struct {
		SigningKeyID     string `json:"signing_key_id"`
		SigningPublicKey string `json:"signing_public_key"`
	}
	if err := json.Unmarshal(readFile(t, dir, "identity.json"), &raw); err != nil {
		t.Fatalf("decode identity.json: %v", err)
	}
	if raw.SigningKeyID != "kid-new" || raw.SigningPublicKey != newSigningKey {
		t.Errorf("identity.json signing pair = (%q, %q), want (kid-new, the new key)", raw.SigningKeyID, raw.SigningPublicKey)
	}

	// Every other field survives as it was saved.
	want := *saved
	want.SigningKeyID, want.SigningPublicKey = "kid-new", newSigningKey
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("identity after commit = %+v, want %+v", *got, want)
	}
	if !bytes.Equal(readFile(t, dir, "private_key"), privateKey) {
		t.Error("private_key changed")
	}
	if !bytes.Equal(readFile(t, dir, "node_secret_key"), nsk) {
		t.Error("node_secret_key changed")
	}

	if runtime.GOOS != "windows" {
		for _, name := range []string{"identity.json", "signing_public_key"} {
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("stat %s: %v", name, err)
			}
			if perm := info.Mode().Perm(); perm != 0600 {
				t.Errorf("%s permissions = %o, want 0600", name, perm)
			}
		}
	}
}

func TestCommitSigningKey_NotRegistered(t *testing.T) {
	dir := t.TempDir()

	err := CommitSigningKey(dir, "kid-new", newSigningKey)
	if !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("error = %v, want one wrapping ErrNotRegistered", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("data dir holds %d entries, want none written", len(entries))
	}
}

func TestCommitSigningKey_UnwritableDirChangesNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions, so the write cannot fail")
	}
	dir := t.TempDir()
	saveSigningKeyIdentity(t, dir)
	identityJSON := readFile(t, dir, "identity.json")
	signingKeyFile := readFile(t, dir, "signing_public_key")

	// Restore the mode so t.TempDir cleanup can remove the tree.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("chmod 0500: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	err := CommitSigningKey(dir, "kid-new", newSigningKey)
	if err == nil || !strings.HasPrefix(err.Error(), "registration: commit signing key:") {
		t.Fatalf("error = %v, want prefix %q", err, "registration: commit signing key:")
	}
	if !bytes.Equal(readFile(t, dir, "identity.json"), identityJSON) {
		t.Error("identity.json changed after a failed commit")
	}
	if !bytes.Equal(readFile(t, dir, "signing_public_key"), signingKeyFile) {
		t.Error("signing_public_key changed after a failed commit")
	}
}

// TestCommitSigningKey_TornPairIsRepairedByTheNextPull simulates a crash
// between the two writes, in both orders. LoadIdentity then yields a pair that
// matches neither key, and installing the pulled key reports a change, which is
// what makes the dispatch handler commit it again.
func TestCommitSigningKey_TornPairIsRepairedByTheNextPull(t *testing.T) {
	pulled := api.NodeStateSigningKey{KeyID: "kid-new", PublicKey: newSigningKey}

	t.Run("key file written, identity.json not", func(t *testing.T) {
		dir := t.TempDir()
		saveSigningKeyIdentity(t, dir)
		if err := os.WriteFile(filepath.Join(dir, "signing_public_key"), []byte(newSigningKey), 0600); err != nil {
			t.Fatal(err)
		}
		assertPullRepairs(t, dir, pulled)
	})

	t.Run("identity.json written, key file not", func(t *testing.T) {
		dir := t.TempDir()
		saveSigningKeyIdentity(t, dir)
		if err := CommitSigningKey(dir, "kid-new", newSigningKey); err != nil {
			t.Fatalf("CommitSigningKey: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "signing_public_key"), []byte(oldSigningKey), 0600); err != nil {
			t.Fatal(err)
		}
		assertPullRepairs(t, dir, pulled)
	})
}

// assertPullRepairs seeds a verifier from the identity in dir, the way plexd up
// does, and checks that installing pulled changes it.
func assertPullRepairs(t *testing.T, dir string, pulled api.NodeStateSigningKey) {
	t.Helper()
	id, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if id.SigningKeyID == pulled.KeyID && id.SigningPublicKey == pulled.PublicKey {
		t.Fatalf("loaded pair (%q, %q) is not torn", id.SigningKeyID, id.SigningPublicKey)
	}
	key, err := base64.StdEncoding.DecodeString(id.SigningPublicKey)
	if err != nil {
		t.Fatalf("decode loaded key: %v", err)
	}
	changed, err := api.NewEd25519Verifier(id.SigningKeyID, ed25519.PublicKey(key)).Install(pulled)
	if err != nil || !changed {
		t.Errorf("Install(pulled) = %v, %v; want true, nil", changed, err)
	}
}
