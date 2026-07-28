package registration

import (
	"bytes"
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
		NodeID:           "node-1",
		MeshIP:           "100.64.0.1",
		SigningPublicKey: "spk",
		PrivateKey:       []byte("01234567890123456789012345678901"),
		NodeSecretKey:    "nsk",
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
		NodeID:           "node-abc",
		MeshIP:           "100.64.0.2",
		SigningPublicKey: "sign-key-123",
		PrivateKey:       []byte("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"),
		NodeSecretKey:    "secret-val",
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
		NodeID:           "node-roundtrip",
		MeshIP:           "100.64.1.1",
		SigningPublicKey: "spk-roundtrip",
		PrivateKey:       []byte("abcdefghijklmnopqrstuvwxyz012345"),
		NodeSecretKey:    testNSK,
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
		NodeID:           "node-abc123",
		MeshIP:           "100.64.0.1",
		PrivateKey:       make([]byte, 32),
		SigningPublicKey: "base64-key",
		NodeSecretKey:    testNSK,
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

func TestSaveAndLoad_RoundtripNewFields(t *testing.T) {
	dir := t.TempDir()

	original := &NodeIdentity{
		NodeID:           "node-newfields",
		MeshIP:           "100.64.0.1",
		SigningPublicKey: "spk",
		SigningKeyID:     "did:web:plexsphere.com#key-2026-04",
		DomainMeshCIDR:   "100.64.0.0/10",
		PrivateKey:       make([]byte, 32),
		NodeSecretKey:    testNSK,
	}

	if err := SaveIdentity(dir, original); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	// identity.json must persist the new keys.
	jsonData, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatalf("read identity.json: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("unmarshal identity.json: %v", err)
	}
	if parsed["signing_key_id"] != "did:web:plexsphere.com#key-2026-04" {
		t.Errorf("signing_key_id = %v, want %q", parsed["signing_key_id"], "did:web:plexsphere.com#key-2026-04")
	}
	if parsed["domain_mesh_cidr"] != "100.64.0.0/10" {
		t.Errorf("domain_mesh_cidr = %v, want %q", parsed["domain_mesh_cidr"], "100.64.0.0/10")
	}

	// The loaded struct must round-trip the new fields.
	loaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if loaded.SigningKeyID != original.SigningKeyID {
		t.Errorf("SigningKeyID = %q, want %q", loaded.SigningKeyID, original.SigningKeyID)
	}
	if loaded.DomainMeshCIDR != original.DomainMeshCIDR {
		t.Errorf("DomainMeshCIDR = %q, want %q", loaded.DomainMeshCIDR, original.DomainMeshCIDR)
	}
}

func TestSaveAndLoad_RoundtripLastRotation(t *testing.T) {
	dir := t.TempDir()

	original := &NodeIdentity{
		NodeID:           "node-rotation",
		MeshIP:           "100.64.0.1",
		SigningPublicKey: "spk",
		PrivateKey:       make([]byte, 32),
		NodeSecretKey:    testNSK,
		LastRotation: &RotationReceipt{
			RotationID:     "rot-2026-07",
			KID:            "kid-abc",
			WrapKeyVersion: 3,
		},
	}

	if err := SaveIdentity(dir, original); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	// identity.json must persist the receipt.
	jsonData, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatalf("read identity.json: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("unmarshal identity.json: %v", err)
	}
	lr, ok := parsed["last_rotation"].(map[string]any)
	if !ok {
		t.Fatalf("last_rotation missing or wrong type in identity.json: %v", parsed["last_rotation"])
	}
	if lr["rotation_id"] != "rot-2026-07" {
		t.Errorf("rotation_id = %v, want %q", lr["rotation_id"], "rot-2026-07")
	}
	if lr["kid"] != "kid-abc" {
		t.Errorf("kid = %v, want %q", lr["kid"], "kid-abc")
	}
	if lr["wrap_key_version"] != float64(3) {
		t.Errorf("wrap_key_version = %v, want 3", lr["wrap_key_version"])
	}

	// The loaded struct must round-trip the receipt.
	loaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if loaded.LastRotation == nil {
		t.Fatal("loaded LastRotation is nil")
	}
	if *loaded.LastRotation != *original.LastRotation {
		t.Errorf("loaded LastRotation = %+v, want %+v", loaded.LastRotation, original.LastRotation)
	}
}

func TestLoadIdentity_LegacyWithoutNewKeys(t *testing.T) {
	dir := t.TempDir()

	// A legacy identity.json predating signing_key_id / domain_mesh_cidr.
	legacyJSON := `{"node_id":"legacy-node","mesh_ip":"100.64.0.7","signing_public_key":"legacy-spk"}`
	if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte(legacyJSON), 0600); err != nil {
		t.Fatalf("write identity.json: %v", err)
	}
	// Provide the sidecar files LoadIdentity requires.
	if err := os.WriteFile(filepath.Join(dir, "private_key"), []byte(base64.StdEncoding.EncodeToString(make([]byte, 32))), 0600); err != nil {
		t.Fatalf("write private_key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node_secret_key"), []byte(testNSK), 0600); err != nil {
		t.Fatalf("write node_secret_key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signing_public_key"), []byte("legacy-spk"), 0600); err != nil {
		t.Fatalf("write signing_public_key: %v", err)
	}

	loaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity legacy: %v", err)
	}
	if loaded.NodeID != "legacy-node" {
		t.Errorf("NodeID = %q, want %q", loaded.NodeID, "legacy-node")
	}
	if loaded.SigningKeyID != "" {
		t.Errorf("SigningKeyID = %q, want empty for legacy identity", loaded.SigningKeyID)
	}
	if loaded.DomainMeshCIDR != "" {
		t.Errorf("DomainMeshCIDR = %q, want empty for legacy identity", loaded.DomainMeshCIDR)
	}
	if loaded.LastRotation != nil {
		t.Errorf("LastRotation = %+v, want nil for legacy identity", loaded.LastRotation)
	}
}

func TestLoadIdentity_AcceptsLegacyRawNSK(t *testing.T) {
	dir := t.TempDir()

	// Identities written before nsk became base64 hold the raw 32-byte secret.
	// This is the exact value the pre-contract mock issued and earlier plexd
	// used verbatim as the AES-256-GCM key. LoadIdentity must accept it so an
	// upgraded node keeps its identity: forcing fresh registration would brick
	// the node because the bootstrap token file is already gone.
	const legacyNSK = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
	writeIdentityFiles(t, dir, legacyNSK)

	loaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity with legacy raw nsk: %v", err)
	}
	if loaded.NodeSecretKey != legacyNSK {
		t.Errorf("NodeSecretKey = %q, want %q", loaded.NodeSecretKey, legacyNSK)
	}
	// The raw secret doubles as the AES-256-GCM key, so SecretKey returns it
	// unchanged rather than base64-decoding it.
	key, err := loaded.SecretKey()
	if err != nil {
		t.Fatalf("SecretKey: %v", err)
	}
	if string(key) != legacyNSK {
		t.Errorf("SecretKey = %q, want %q", key, legacyNSK)
	}
}

// TestNodeIdentity_BearerToken_WireForm pins the exact bearer envelope the
// control plane admits: `nsk_<env>_<base64url(node_id_bytes || nsk_bytes)>`
// with unpadded base64url and a 48-byte payload. The literals are fixed so a
// drift in the prefix, the env segment, the byte order, or the encoding
// (padded, or non-URL alphabet) fails against a known-good string instead of
// against a re-derivation sharing the same bug.
func TestNodeIdentity_BearerToken_WireForm(t *testing.T) {
	id := &NodeIdentity{
		// 0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3 || 32 x 0x2a
		NodeID:        "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3",
		NodeSecretKey: "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=",
	}
	got, err := id.BearerToken()
	if err != nil {
		t.Fatalf("BearerToken: %v", err)
	}
	const want = "nsk_plexd_AZCouKDAegqKCqCgoKCgoyoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioq"
	if got != want {
		t.Errorf("BearerToken = %q, want %q", got, want)
	}
}

// A legacy identity holds the raw 32-byte secret instead of its base64 form;
// the envelope embeds those bytes directly, so an upgraded node authenticates
// without rewriting its identity files.
func TestNodeIdentity_BearerToken_LegacyRawNSK(t *testing.T) {
	id := &NodeIdentity{
		NodeID:        "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3",
		NodeSecretKey: "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
	}
	got, err := id.BearerToken()
	if err != nil {
		t.Fatalf("BearerToken: %v", err)
	}
	const want = "nsk_plexd_AZCouKDAegqKCqCgoKCgo0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMDEyMzQ1"
	if got != want {
		t.Errorf("BearerToken = %q, want %q", got, want)
	}
}

func TestNodeIdentity_BearerToken_Rejects(t *testing.T) {
	validNSK := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, 32))
	tests := []struct {
		name   string
		nodeID string
		nsk    string
	}{
		{"mock-era node id", "node-123", validNSK},
		{"empty node id", "", validNSK},
		{"node id with non-hex groups", "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0zz", validNSK},
		{"node id without dashes", "0190a8b8a0c07a0a8a0aa0a0a0a0a0a3", validNSK},
		{"nsk not base64", "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3", "nsk-secret-value"},
		{"nsk wrong length", "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, 31))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := &NodeIdentity{NodeID: tc.nodeID, NodeSecretKey: tc.nsk}
			if got, err := id.BearerToken(); err == nil {
				t.Errorf("BearerToken = %q, want error", got)
			}
		})
	}
}

func TestSaveIdentity_PartialWriteLeavesNoIdentityJSON(t *testing.T) {
	dir := t.TempDir()

	// Block the node_secret_key write: WriteFileAtomic renames its temp file
	// over the target, and renaming a file over a directory always fails.
	if err := os.Mkdir(filepath.Join(dir, "node_secret_key"), 0700); err != nil {
		t.Fatalf("mkdir node_secret_key: %v", err)
	}

	id := &NodeIdentity{
		NodeID:           "node-partial",
		MeshIP:           "100.64.0.5",
		SigningPublicKey: "spk-partial",
		PrivateKey:       make([]byte, 32),
		NodeSecretKey:    testNSK,
	}
	if err := SaveIdentity(dir, id); err == nil {
		t.Fatal("SaveIdentity: expected error, got nil")
	}

	// identity.json is what marks a node registered, so a torn write must not
	// leave one behind: the next start registers cleanly instead of loading a
	// partial identity.
	if _, err := os.Stat(filepath.Join(dir, "identity.json")); !os.IsNotExist(err) {
		t.Errorf("Stat(identity.json) = %v, want os.IsNotExist", err)
	}
	if _, err := LoadIdentity(dir); !errors.Is(err, ErrNotRegistered) {
		t.Errorf("LoadIdentity = %v, want ErrNotRegistered", err)
	}
}

func TestSaveIdentity_PartialReRegistrationLeavesNoStaleIdentity(t *testing.T) {
	dir := t.TempDir()

	// A node registered once, so identity.json is already on disk.
	first := &NodeIdentity{
		NodeID:           "old-node",
		MeshIP:           "100.64.0.9",
		SigningPublicKey: "spk-old",
		PrivateKey:       make([]byte, 32),
		NodeSecretKey:    testNSK,
	}
	if err := SaveIdentity(dir, first); err != nil {
		t.Fatalf("SaveIdentity (first): %v", err)
	}

	// Re-registration writes a new key group but fails part-way: block the
	// node_secret_key write by turning it into a directory.
	if err := os.RemoveAll(filepath.Join(dir, "node_secret_key")); err != nil {
		t.Fatalf("remove node_secret_key: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "node_secret_key"), 0700); err != nil {
		t.Fatalf("mkdir node_secret_key: %v", err)
	}

	second := &NodeIdentity{
		NodeID:           "new-node",
		MeshIP:           "100.64.0.10",
		SigningPublicKey: "spk-new",
		PrivateKey:       make([]byte, 32),
		NodeSecretKey:    testNSKAlt,
	}
	if err := SaveIdentity(dir, second); err == nil {
		t.Fatal("SaveIdentity (second): expected error, got nil")
	}

	// The stale identity.json (old node_id/mesh_ip) must not survive alongside
	// the partially written new key group — otherwise the node would announce
	// old-node while holding new-node's secret. No identity.json means the next
	// start re-registers cleanly.
	if _, err := os.Stat(filepath.Join(dir, "identity.json")); !os.IsNotExist(err) {
		t.Errorf("Stat(identity.json) = %v, want os.IsNotExist", err)
	}
	if _, err := LoadIdentity(dir); !errors.Is(err, ErrNotRegistered) {
		t.Errorf("LoadIdentity = %v, want ErrNotRegistered", err)
	}
}

// writeIdentityFiles writes the four files LoadIdentity reads, using nsk
// verbatim as the node_secret_key contents.
func writeIdentityFiles(t *testing.T, dir, nsk string) {
	t.Helper()
	files := map[string]string{
		"identity.json":      `{"node_id":"` + testNodeID + `","mesh_ip":"100.64.0.7","signing_public_key":"spk"}`,
		"private_key":        base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"node_secret_key":    nsk,
		"signing_public_key": "spk",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func TestSaveIdentity_Permissions(t *testing.T) {
	dir := t.TempDir()

	id := &NodeIdentity{
		NodeID:           "node-perm",
		MeshIP:           "100.64.0.3",
		SigningPublicKey: "spk-perm",
		PrivateKey:       []byte("01234567890123456789012345678901"),
		NodeSecretKey:    "nsk-perm",
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
