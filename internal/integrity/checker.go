// Package integrity provides SHA-256 checksum verification for plexd binaries and hook scripts.
package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// CheckResult holds the outcome of a file integrity check.
type CheckResult struct {
	// Path is the filesystem path that was verified.
	Path string
	// Expected is the hex-encoded SHA-256 checksum that was expected.
	Expected string
	// Actual is the hex-encoded SHA-256 checksum that was computed.
	Actual string
	// OK is true when Expected matches Actual (or when establishing a new baseline).
	OK bool
}

// HashFile computes the SHA-256 checksum of the file at path using streaming I/O.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("integrity: open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("integrity: hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyFile computes the SHA-256 checksum of the file at path and compares it
// against expectedChecksum. When requireChecksum is true and expectedChecksum is
// empty, an error is returned (hooks must have a control-plane-provided checksum).
// When requireChecksum is false and expectedChecksum is empty, the computed
// checksum is returned as a new baseline with OK=true.
func VerifyFile(path, expectedChecksum string, requireChecksum bool) (CheckResult, error) {
	if expectedChecksum == "" && requireChecksum {
		return CheckResult{}, errors.New("integrity: expected checksum is required")
	}

	actual, err := HashFile(path)
	if err != nil {
		return CheckResult{}, err
	}

	if expectedChecksum == "" {
		return CheckResult{
			Path:   path,
			Actual: actual,
			OK:     true,
		}, nil
	}

	return CheckResult{
		Path:     path,
		Expected: expectedChecksum,
		Actual:   actual,
		OK:       actual == expectedChecksum,
	}, nil
}
