package tunnel

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateHostKey(t *testing.T) {
	signer, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}
	if signer == nil {
		t.Fatal("GenerateHostKey() returned nil signer")
	}
	if signer.PublicKey().Type() != "ssh-ed25519" {
		t.Errorf("key type = %q, want %q", signer.PublicKey().Type(), "ssh-ed25519")
	}
}

func TestLoadOrGenerateHostKey_GeneratesNew(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()

	signer, err := LoadOrGenerateHostKey(dir, logger)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey() error: %v", err)
	}
	if signer == nil {
		t.Fatal("LoadOrGenerateHostKey() returned nil signer")
	}

	keyPath := filepath.Join(dir, hostKeyFileName)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("key file permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestLoadOrGenerateHostKey_LoadsExisting(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()

	signer1, err := LoadOrGenerateHostKey(dir, logger)
	if err != nil {
		t.Fatalf("first LoadOrGenerateHostKey() error: %v", err)
	}

	signer2, err := LoadOrGenerateHostKey(dir, logger)
	if err != nil {
		t.Fatalf("second LoadOrGenerateHostKey() error: %v", err)
	}

	pub1 := signer1.PublicKey().Marshal()
	pub2 := signer2.PublicKey().Marshal()
	if len(pub1) != len(pub2) {
		t.Fatal("public key lengths differ after reload")
	}
	for i := range pub1 {
		if pub1[i] != pub2[i] {
			t.Fatal("public keys differ after reload")
		}
	}
}

func TestLoadOrGenerateHostKey_DirNotExist(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "nested", "subdir")

	logger := slog.Default()

	signer, err := LoadOrGenerateHostKey(dir, logger)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey() error: %v", err)
	}
	if signer == nil {
		t.Fatal("LoadOrGenerateHostKey() returned nil signer")
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("expected directory, got file")
	}
}
