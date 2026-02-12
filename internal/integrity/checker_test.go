package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

// writeTemp creates a temporary file with the given content and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "testfile")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writeTemp: %v", err)
	}
	return p
}

// sha256Hex computes the SHA-256 of data and returns the hex-encoded digest.
func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func TestHashFile_ComputesSHA256(t *testing.T) {
	const content = "hello world\n"
	want := sha256Hex(content)

	p := writeTemp(t, content)

	got, err := HashFile(p)
	if err != nil {
		t.Fatalf("HashFile(%q) unexpected error: %v", p, err)
	}
	if len(got) != 64 {
		t.Fatalf("HashFile(%q) returned %d hex chars, want 64", p, len(got))
	}
	if got != want {
		t.Errorf("HashFile(%q) = %s, want %s", p, got, want)
	}
}

func TestHashFile_EmptyFile(t *testing.T) {
	const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	p := writeTemp(t, "")

	got, err := HashFile(p)
	if err != nil {
		t.Fatalf("HashFile(%q) unexpected error: %v", p, err)
	}
	if got != emptyHash {
		t.Errorf("HashFile(empty) = %s, want %s", got, emptyHash)
	}
}

func TestHashFile_FileNotFound(t *testing.T) {
	_, err := HashFile("/nonexistent/path/to/file")
	if err == nil {
		t.Fatal("HashFile on nonexistent path: want error, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("HashFile error = %v, want wrapping os.ErrNotExist", err)
	}
}

func TestVerifyFile_MatchingChecksum(t *testing.T) {
	p := writeTemp(t, "verify me")

	hash, err := HashFile(p)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}

	result, err := VerifyFile(p, hash, true)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if !result.OK {
		t.Error("VerifyFile: want OK=true, got false")
	}
	if result.Path != p {
		t.Errorf("VerifyFile Path = %q, want %q", result.Path, p)
	}
	if result.Expected != hash {
		t.Errorf("VerifyFile Expected = %q, want %q", result.Expected, hash)
	}
	if result.Actual != hash {
		t.Errorf("VerifyFile Actual = %q, want %q", result.Actual, hash)
	}
}

func TestVerifyFile_MismatchedChecksum(t *testing.T) {
	p := writeTemp(t, "some content")

	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"

	result, err := VerifyFile(p, wrongHash, true)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if result.OK {
		t.Error("VerifyFile: want OK=false, got true")
	}
	if result.Expected != wrongHash {
		t.Errorf("VerifyFile Expected = %q, want %q", result.Expected, wrongHash)
	}
	if result.Actual == "" {
		t.Error("VerifyFile Actual is empty, want computed hash")
	}
	if result.Actual == wrongHash {
		t.Error("VerifyFile Actual equals wrong hash, should differ")
	}
}

func TestVerifyFile_EmptyExpectedRequireChecksum(t *testing.T) {
	p := writeTemp(t, "data")

	_, err := VerifyFile(p, "", true)
	if err == nil {
		t.Fatal("VerifyFile with empty expected and requireChecksum=true: want error, got nil")
	}
	const wantMsg = "integrity: expected checksum is required"
	if err.Error() != wantMsg {
		t.Errorf("error = %q, want %q", err.Error(), wantMsg)
	}
	_ = p // p exists but should not be opened when requireChecksum short-circuits
}

func TestVerifyFile_EmptyExpectedNoRequire(t *testing.T) {
	p := writeTemp(t, "baseline data")

	result, err := VerifyFile(p, "", false)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if !result.OK {
		t.Error("VerifyFile: want OK=true for baseline, got false")
	}
	if result.Actual == "" {
		t.Error("VerifyFile Actual is empty, want computed hash")
	}
	if result.Expected != "" {
		t.Errorf("VerifyFile Expected = %q, want empty for baseline", result.Expected)
	}
	if result.Path != p {
		t.Errorf("VerifyFile Path = %q, want %q", result.Path, p)
	}
}

func TestVerifyFile_FileNotFound(t *testing.T) {
	_, err := VerifyFile("/nonexistent/path/to/file", "abc123", true)
	if err == nil {
		t.Fatal("VerifyFile on nonexistent path: want error, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("VerifyFile error = %v, want wrapping os.ErrNotExist", err)
	}
}

func TestHashFile_LargeFile(t *testing.T) {
	const size = 1 << 20 // 1 MiB

	data := make([]byte, size)
	// Deterministic pseudo-random content so the expected hash is stable.
	r := rand.New(rand.NewPCG(42, 99))
	for i := range data {
		data[i] = byte(r.UintN(256))
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "largefile")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write large file: %v", err)
	}

	wantSum := sha256.Sum256(data)
	want := hex.EncodeToString(wantSum[:])

	got, err := HashFile(p)
	if err != nil {
		t.Fatalf("HashFile(%q) unexpected error: %v", p, err)
	}
	if got != want {
		t.Errorf("HashFile(1MiB) = %s, want %s", got, want)
	}
}
