//go:build windows

package wintundll

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readDLL returns the contents of the wintun.dll Ensure wrote into dir.
func readDLL(t *testing.T, dir string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, dllName))
	if err != nil {
		t.Fatalf("read written dll: %v", err)
	}
	return data
}

func TestEnsure_WritesIntoEmptyDir(t *testing.T) {
	dir := t.TempDir()

	path, wrote, err := Ensure(dir)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !wrote {
		t.Error("wrote = false, want true for an empty directory")
	}
	if want := filepath.Join(dir, "wintun.dll"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if got := sha256.Sum256(readDLL(t, dir)); got != sha256.Sum256(dll) {
		t.Error("written file does not match the embedded driver")
	}
}

func TestEnsure_KeepsIdenticalFile(t *testing.T) {
	dir := t.TempDir()

	if _, _, err := Ensure(dir); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	before, err := os.Stat(filepath.Join(dir, dllName))
	if err != nil {
		t.Fatalf("stat after first Ensure: %v", err)
	}

	_, wrote, err := Ensure(dir)
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if wrote {
		t.Error("wrote = true, want false for a file that already matches")
	}

	after, err := os.Stat(filepath.Join(dir, dllName))
	if err != nil {
		t.Fatalf("stat after second Ensure: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("the matching file was rewritten, want it left alone")
	}
}

func TestEnsure_ReplacesDifferentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, dllName)

	if err := os.WriteFile(path, []byte("not a dll"), 0o644); err != nil {
		t.Fatalf("seed stale dll: %v", err)
	}

	_, wrote, err := Ensure(dir)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !wrote {
		t.Error("wrote = false, want true for a file that differs")
	}
	if got := readDLL(t, dir); !bytes.Equal(got, dll) {
		t.Error("the stale file survived, want it replaced by the embedded driver")
	}
}

func TestEnsure_MissingDir(t *testing.T) {
	_, wrote, err := Ensure(filepath.Join(t.TempDir(), "absent"))
	if err == nil {
		t.Fatal("Ensure into a missing directory succeeded, want an error")
	}
	if !strings.HasPrefix(err.Error(), "wintundll: write dll:") {
		t.Errorf("error = %q, want the wintundll: write dll: prefix", err)
	}
	if wrote {
		t.Error("wrote = true after a failure, want false")
	}
}
