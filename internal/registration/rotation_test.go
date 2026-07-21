package registration

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSavePendingKey_LoadPendingKey_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	if err := SavePendingKey(dir, kp); err != nil {
		t.Fatalf("SavePendingKey: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "rotation_pending_key"))
	if err != nil {
		t.Fatalf("Stat(rotation_pending_key): %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("rotation_pending_key permissions = %o, want 0600", perm)
	}

	loaded, err := LoadPendingKey(dir)
	if err != nil {
		t.Fatalf("LoadPendingKey: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadPendingKey returned nil keypair")
	}
	if !bytes.Equal(loaded.PrivateKey, kp.PrivateKey) {
		t.Errorf("loaded PrivateKey mismatch")
	}
	if !bytes.Equal(loaded.PublicKey, kp.PublicKey) {
		t.Errorf("re-derived PublicKey mismatch: got %x, want %x", loaded.PublicKey, kp.PublicKey)
	}
}

func TestLoadPendingKey_Missing(t *testing.T) {
	dir := t.TempDir()

	kp, err := LoadPendingKey(dir)
	if err != nil {
		t.Fatalf("LoadPendingKey on empty dir: %v", err)
	}
	if kp != nil {
		t.Errorf("LoadPendingKey on empty dir = %v, want nil", kp)
	}
}

func TestLoadPendingKey_ShortKey(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{name: "five bytes", raw: []byte("hello"), wantErr: "registration: load pending key: key must be 32 bytes, got 5"},
		{name: "empty", raw: nil, wantErr: "registration: load pending key: key must be 32 bytes, got 0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			data := []byte(base64.StdEncoding.EncodeToString(tt.raw))
			if err := os.WriteFile(filepath.Join(dir, "rotation_pending_key"), data, 0600); err != nil {
				t.Fatalf("write rotation_pending_key: %v", err)
			}

			_, err := LoadPendingKey(dir)
			if err == nil {
				t.Fatal("LoadPendingKey: expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Errorf("error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoadPendingKey_NotBase64(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "rotation_pending_key"), []byte("not!!base64@@"), 0600); err != nil {
		t.Fatalf("write rotation_pending_key: %v", err)
	}

	_, err := LoadPendingKey(dir)
	if err == nil {
		t.Fatal("LoadPendingKey: expected error, got nil")
	}
	var corrupt base64.CorruptInputError
	if !errors.As(err, &corrupt) {
		t.Errorf("error = %v, want a base64.CorruptInputError", err)
	}
}

func TestCommitRotatedKey_SwapsKeyAndWritesReceipt(t *testing.T) {
	dir := t.TempDir()

	id := &NodeIdentity{
		NodeID:           "node-rotate",
		MeshIP:           "100.64.0.1",
		SigningPublicKey: "spk",
		NodeSecretKey:    testNSK,
	}
	id.PrivateKey = make([]byte, 32)
	for i := range id.PrivateKey {
		id.PrivateKey[i] = byte(i)
	}
	if err := SaveIdentity(dir, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := SavePendingKey(dir, kp); err != nil {
		t.Fatalf("SavePendingKey: %v", err)
	}

	receipt := &RotationReceipt{RotationID: "rot-1", KID: "kid-1", WrapKeyVersion: 2}
	if err := CommitRotatedKey(dir, id, kp, receipt); err != nil {
		t.Fatalf("CommitRotatedKey: %v", err)
	}

	// private_key file now decodes to the new key.
	pkData, err := os.ReadFile(filepath.Join(dir, "private_key"))
	if err != nil {
		t.Fatalf("read private_key: %v", err)
	}
	pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pkData)))
	if err != nil {
		t.Fatalf("decode private_key: %v", err)
	}
	if !bytes.Equal(pk, kp.PrivateKey) {
		t.Errorf("private_key file does not hold the new key")
	}

	// In-memory identity carries the new key and the receipt.
	if !bytes.Equal(id.PrivateKey, kp.PrivateKey) {
		t.Errorf("in-memory PrivateKey not swapped")
	}
	if id.LastRotation == nil || *id.LastRotation != *receipt {
		t.Errorf("in-memory LastRotation = %+v, want %+v", id.LastRotation, receipt)
	}

	// The staging file is gone.
	if _, err := os.Stat(filepath.Join(dir, "rotation_pending_key")); !os.IsNotExist(err) {
		t.Errorf("Stat(rotation_pending_key) = %v, want os.IsNotExist", err)
	}

	// LoadIdentity re-reads the persisted receipt and the new private key.
	loaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if loaded.LastRotation == nil {
		t.Fatal("loaded LastRotation is nil")
	}
	if *loaded.LastRotation != *receipt {
		t.Errorf("loaded LastRotation = %+v, want %+v", loaded.LastRotation, receipt)
	}
	if !bytes.Equal(loaded.PrivateKey, kp.PrivateKey) {
		t.Errorf("loaded PrivateKey is not the new key")
	}
}

func TestCommitRotatedKey_NilReceiptKeepsLastRotation(t *testing.T) {
	dir := t.TempDir()

	prior := &RotationReceipt{RotationID: "rot-prior", KID: "kid-prior", WrapKeyVersion: 1}
	id := &NodeIdentity{
		NodeID:           "node-rotate",
		MeshIP:           "100.64.0.1",
		SigningPublicKey: "spk",
		NodeSecretKey:    testNSK,
		LastRotation:     prior,
	}
	id.PrivateKey = make([]byte, 32)
	if err := SaveIdentity(dir, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := SavePendingKey(dir, kp); err != nil {
		t.Fatalf("SavePendingKey: %v", err)
	}

	if err := CommitRotatedKey(dir, id, kp, nil); err != nil {
		t.Fatalf("CommitRotatedKey: %v", err)
	}

	// A nil receipt keeps the previous LastRotation in memory.
	if id.LastRotation == nil || *id.LastRotation != *prior {
		t.Errorf("in-memory LastRotation = %+v, want %+v", id.LastRotation, prior)
	}

	// And on disk after reload.
	loaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if loaded.LastRotation == nil || *loaded.LastRotation != *prior {
		t.Errorf("loaded LastRotation = %+v, want %+v", loaded.LastRotation, prior)
	}
}

func TestCommitRotatedKey_UnwritableDirKeepsPending(t *testing.T) {
	dir := t.TempDir()

	id := &NodeIdentity{
		NodeID:           "node-rotate",
		MeshIP:           "100.64.0.1",
		SigningPublicKey: "spk",
		NodeSecretKey:    testNSK,
	}
	id.PrivateKey = make([]byte, 32)
	if err := SaveIdentity(dir, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := SavePendingKey(dir, kp); err != nil {
		t.Fatalf("SavePendingKey: %v", err)
	}

	// Make the data dir unwritable so the private_key write fails. Restore the
	// mode so t.TempDir cleanup can remove the tree.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("chmod 0500: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	err = CommitRotatedKey(dir, id, kp, &RotationReceipt{RotationID: "rot-1"})
	if err == nil {
		t.Fatal("CommitRotatedKey on unwritable dir: expected error, got nil")
	}
	if !strings.HasPrefix(err.Error(), "registration: commit rotated key:") {
		t.Errorf("error = %q, want prefix %q", err.Error(), "registration: commit rotated key:")
	}

	// The staging key must survive so a resubmit can recover.
	if _, err := os.Stat(filepath.Join(dir, "rotation_pending_key")); err != nil {
		t.Errorf("Stat(rotation_pending_key) = %v, want the staged key to survive", err)
	}
}

func TestCommitRotatedKey_ReReadsIdentityAfterReRegistration(t *testing.T) {
	dir := t.TempDir()

	// The identity the rotator captured at startup.
	stale := &NodeIdentity{
		NodeID:           "node-old",
		MeshIP:           "100.64.0.1",
		SigningPublicKey: "spk-old",
		SigningKeyID:     "skid-old",
		NodeSecretKey:    testNSK,
	}
	stale.PrivateKey = make([]byte, 32)
	if err := SaveIdentity(dir, stale); err != nil {
		t.Fatalf("SaveIdentity(stale): %v", err)
	}

	// A re-registration replaces the identity on disk while the rotator still
	// holds the pre-registration struct.
	fresh := &NodeIdentity{
		NodeID:           "node-new",
		MeshIP:           "100.64.0.9",
		SigningPublicKey: "spk-new",
		SigningKeyID:     "skid-new",
		NodeSecretKey:    testNSK,
	}
	fresh.PrivateKey = bytes.Repeat([]byte{0x07}, 32)
	if err := SaveIdentity(dir, fresh); err != nil {
		t.Fatalf("SaveIdentity(fresh): %v", err)
	}

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := SavePendingKey(dir, kp); err != nil {
		t.Fatalf("SavePendingKey: %v", err)
	}

	receipt := &RotationReceipt{RotationID: "rot-1", KID: "kid-1", WrapKeyVersion: 2}
	if err := CommitRotatedKey(dir, stale, kp, receipt); err != nil {
		t.Fatalf("CommitRotatedKey: %v", err)
	}

	// identity.json must still describe the node the on-disk credential belongs
	// to, with only the rotation-owned fields advanced.
	loaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if loaded.NodeID != fresh.NodeID {
		t.Errorf("node_id = %q, want the re-registered %q", loaded.NodeID, fresh.NodeID)
	}
	if loaded.MeshIP != fresh.MeshIP {
		t.Errorf("mesh_ip = %q, want the re-registered %q", loaded.MeshIP, fresh.MeshIP)
	}
	if loaded.SigningKeyID != fresh.SigningKeyID {
		t.Errorf("signing_key_id = %q, want the re-registered %q", loaded.SigningKeyID, fresh.SigningKeyID)
	}
	if loaded.LastRotation == nil || *loaded.LastRotation != *receipt {
		t.Errorf("LastRotation = %+v, want %+v", loaded.LastRotation, receipt)
	}
	if !bytes.Equal(loaded.PrivateKey, kp.PrivateKey) {
		t.Error("private_key file does not hold the rotated key")
	}
}

func TestCommitRotatedKey_ConcurrentWithSaveIdentity(t *testing.T) {
	// Re-registration runs on the heartbeat goroutine while a rotation runs on
	// its own; both read-modify-write the identity file group. Interleaved, the
	// commit either fails inside SaveIdentity's identity.json removal window or
	// rewrites identity.json from a snapshot taken before the re-registration,
	// leaving an identity.json that disagrees with node_secret_key.
	dir := t.TempDir()

	nskFor := func(i int) string {
		return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(i)}, 32))
	}
	identityFor := func(i int) *NodeIdentity {
		id := &NodeIdentity{
			NodeID:           fmt.Sprintf("node-%d", i),
			MeshIP:           "100.64.0.1",
			SigningPublicKey: "spk",
			NodeSecretKey:    nskFor(i),
		}
		id.PrivateKey = bytes.Repeat([]byte{byte(i)}, 32)
		return id
	}

	if err := SaveIdentity(dir, identityFor(0)); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	const iterations = 40
	errs := make(chan error, 2*iterations)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 1; i <= iterations; i++ {
			if err := SaveIdentity(dir, identityFor(i)); err != nil {
				errs <- fmt.Errorf("SaveIdentity: %w", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := range iterations {
			kp, err := GenerateKeypair()
			if err != nil {
				errs <- fmt.Errorf("GenerateKeypair: %w", err)
				return
			}
			receipt := &RotationReceipt{RotationID: fmt.Sprintf("rot-%d", i), KID: "kid"}
			if err := CommitRotatedKey(dir, &NodeIdentity{}, kp, receipt); err != nil {
				errs <- fmt.Errorf("CommitRotatedKey: %w", err)
			}
		}
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("%v", err)
	}

	// identity.json and node_secret_key must still describe the same node.
	loaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	var i int
	if _, err := fmt.Sscanf(loaded.NodeID, "node-%d", &i); err != nil {
		t.Fatalf("unexpected node_id %q: %v", loaded.NodeID, err)
	}
	if loaded.NodeSecretKey != nskFor(i) {
		t.Errorf("node_secret_key does not belong to %s", loaded.NodeID)
	}
}
