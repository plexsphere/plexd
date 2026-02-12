package registration

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveIdentity_CreatesDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")

	id := &NodeIdentity{
		NodeID:          "node-1",
		MeshIP:          "100.64.0.1",
		SigningPublicKey: "spk",
		PrivateKey:      []byte("01234567890123456789012345678901"),
		NodeSecretKey:   "nsk",
	}

	if err := SaveIdentity(dir, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat(%q): %v", dir, err)
	}
	if !info.IsDir() {
		t.Fatalf("%q is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("data dir permissions = %o, want 0700", perm)
	}
}

func TestSaveIdentity_AtomicWrite(t *testing.T) {
	dir := t.TempDir()

	id := &NodeIdentity{
		NodeID:          "node-abc",
		MeshIP:          "100.64.0.2",
		SigningPublicKey: "sign-key-123",
		PrivateKey:      []byte("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"),
		NodeSecretKey:   "secret-val",
	}

	if err := SaveIdentity(dir, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	// Check identity.json.
	jsonData, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatalf("read identity.json: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("unmarshal identity.json: %v", err)
	}
	if parsed["node_id"] != "node-abc" {
		t.Errorf("node_id = %v, want %q", parsed["node_id"], "node-abc")
	}
	if parsed["mesh_ip"] != "100.64.0.2" {
		t.Errorf("mesh_ip = %v, want %q", parsed["mesh_ip"], "100.64.0.2")
	}
	if parsed["signing_public_key"] != "sign-key-123" {
		t.Errorf("signing_public_key = %v, want %q", parsed["signing_public_key"], "sign-key-123")
	}
	// PrivateKey and NodeSecretKey must NOT appear in JSON.
	if _, ok := parsed["private_key"]; ok {
		t.Error("private_key should not appear in identity.json")
	}
	if _, ok := parsed["node_secret_key"]; ok {
		t.Error("node_secret_key should not appear in identity.json")
	}

	// Check private_key file.
	pkData, err := os.ReadFile(filepath.Join(dir, "private_key"))
	if err != nil {
		t.Fatalf("read private_key: %v", err)
	}
	wantPK := base64.StdEncoding.EncodeToString(id.PrivateKey)
	if string(pkData) != wantPK {
		t.Errorf("private_key content = %q, want %q", string(pkData), wantPK)
	}

	// Check node_secret_key file.
	nskData, err := os.ReadFile(filepath.Join(dir, "node_secret_key"))
	if err != nil {
		t.Fatalf("read node_secret_key: %v", err)
	}
	if string(nskData) != "secret-val" {
		t.Errorf("node_secret_key content = %q, want %q", string(nskData), "secret-val")
	}

	// Check signing_public_key file.
	spkData, err := os.ReadFile(filepath.Join(dir, "signing_public_key"))
	if err != nil {
		t.Fatalf("read signing_public_key: %v", err)
	}
	if string(spkData) != "sign-key-123" {
		t.Errorf("signing_public_key content = %q, want %q", string(spkData), "sign-key-123")
	}

	// Check file permissions (0600).
	for _, name := range []string{"identity.json", "private_key", "node_secret_key", "signing_public_key"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("Stat(%q): %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("%s permissions = %o, want 0600", name, perm)
		}
	}
}

func TestLoadIdentity_Success(t *testing.T) {
	dir := t.TempDir()

	original := &NodeIdentity{
		NodeID:          "node-roundtrip",
		MeshIP:          "100.64.1.1",
		SigningPublicKey: "spk-roundtrip",
		PrivateKey:      []byte("abcdefghijklmnopqrstuvwxyz012345"),
		NodeSecretKey:   "nsk-roundtrip",
	}

	if err := SaveIdentity(dir, original); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	loaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}

	if loaded.NodeID != original.NodeID {
		t.Errorf("NodeID = %q, want %q", loaded.NodeID, original.NodeID)
	}
	if loaded.MeshIP != original.MeshIP {
		t.Errorf("MeshIP = %q, want %q", loaded.MeshIP, original.MeshIP)
	}
	if loaded.SigningPublicKey != original.SigningPublicKey {
		t.Errorf("SigningPublicKey = %q, want %q", loaded.SigningPublicKey, original.SigningPublicKey)
	}
	if string(loaded.PrivateKey) != string(original.PrivateKey) {
		t.Errorf("PrivateKey mismatch")
	}
	if loaded.NodeSecretKey != original.NodeSecretKey {
		t.Errorf("NodeSecretKey = %q, want %q", loaded.NodeSecretKey, original.NodeSecretKey)
	}
}

func TestLoadIdentity_MissingFiles(t *testing.T) {
	dir := t.TempDir()

	_, err := LoadIdentity(dir)
	if err == nil {
		t.Fatal("LoadIdentity on empty dir: expected error, got nil")
	}
	if !errors.Is(err, ErrNotRegistered) {
		t.Errorf("error = %v, want errors.Is(err, ErrNotRegistered)", err)
	}
}

func TestLoadIdentity_CorruptJSON(t *testing.T) {
	dir := t.TempDir()

	// Write invalid JSON to identity.json.
	if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte("{bad json"), 0600); err != nil {
		t.Fatalf("write identity.json: %v", err)
	}

	_, err := LoadIdentity(dir)
	if err == nil {
		t.Fatal("LoadIdentity with corrupt JSON: expected error, got nil")
	}
	if errors.Is(err, ErrNotRegistered) {
		t.Error("corrupt JSON should not return ErrNotRegistered")
	}
}

func TestSaveAndLoad_Roundtrip(t *testing.T) {
	dir := t.TempDir()

	original := &NodeIdentity{
		NodeID:          "node-abc123",
		MeshIP:          "100.64.0.1",
		PrivateKey:      make([]byte, 32),
		SigningPublicKey: "base64-key",
		NodeSecretKey:   "secret-key-value",
	}
	// Fill PrivateKey with deterministic but non-trivial bytes.
	for i := range original.PrivateKey {
		original.PrivateKey[i] = byte(i * 7)
	}

	if err := SaveIdentity(dir, original); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	loaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}

	if loaded.NodeID != original.NodeID {
		t.Errorf("NodeID = %q, want %q", loaded.NodeID, original.NodeID)
	}
	if loaded.MeshIP != original.MeshIP {
		t.Errorf("MeshIP = %q, want %q", loaded.MeshIP, original.MeshIP)
	}
	if loaded.SigningPublicKey != original.SigningPublicKey {
		t.Errorf("SigningPublicKey = %q, want %q", loaded.SigningPublicKey, original.SigningPublicKey)
	}
	if string(loaded.PrivateKey) != string(original.PrivateKey) {
		t.Errorf("PrivateKey mismatch: got %v, want %v", loaded.PrivateKey, original.PrivateKey)
	}
	if loaded.NodeSecretKey != original.NodeSecretKey {
		t.Errorf("NodeSecretKey = %q, want %q", loaded.NodeSecretKey, original.NodeSecretKey)
	}
}

func TestSaveIdentity_Permissions(t *testing.T) {
	dir := t.TempDir()

	id := &NodeIdentity{
		NodeID:          "node-perm",
		MeshIP:          "100.64.0.3",
		SigningPublicKey: "spk-perm",
		PrivateKey:      []byte("01234567890123456789012345678901"),
		NodeSecretKey:   "nsk-perm",
	}

	if err := SaveIdentity(dir, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	for _, name := range []string{"private_key", "node_secret_key"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("Stat(%q): %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("%s permissions = %o, want 0600", name, perm)
		}
	}
}
