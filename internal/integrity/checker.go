// Package integrity verifies the plexd binary and hook scripts by SHA-256
// checksum, and the SSH host key by its OpenSSH fingerprint.
package integrity

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh"
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

// SelfChecksum computes the SHA-256 checksum of the currently running binary.
func SelfChecksum() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("integrity: self checksum: %w", err)
	}
	return HashFile(exe)
}

// WireChecksum re-encodes a hex digest from HashFile into the form the control
// plane's checksum fields carry: the 32 raw bytes in standard-padded base64.
//
// Hex is this package's own currency — it is what the baseline store holds and
// what hook comparisons run on — but on the wire those fields are declared
// `format: byte`, so a hex string is decoded as base64 and yields 48 bytes
// instead of 32. The capability manifest refuses that outright, and while the
// heartbeat contract also documents a hex form, the deployed control plane
// answers it with 400 `binary_checksum_empty`. Base64 is the one encoding both
// operations accept, so it is the one this agent sends.
func WireChecksum(hexDigest string) (string, error) {
	raw, err := hex.DecodeString(hexDigest)
	if err != nil {
		return "", fmt.Errorf("integrity: wire checksum: %w", err)
	}
	if len(raw) != sha256.Size {
		return "", fmt.Errorf("integrity: wire checksum: digest is %d bytes, want %d", len(raw), sha256.Size)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// HostKeyFingerprint parses the OpenSSH private key at path and renders its
// public half as the canonical `SHA256:<base64>` fingerprint — the form
// `ssh-keygen -l` prints, the one the capability manifest already carries, and
// the one the integrity contract's fingerprint fields accept.
//
// The fingerprint, not a file digest, is what identifies a host key: the same
// key re-serialised is a different PEM but the same identity, and it is the
// identity a peer pins.
func HostKeyFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("integrity: read host key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return "", fmt.Errorf("integrity: parse host key %s: %w", path, err)
	}
	return ssh.FingerprintSHA256(signer.PublicKey()), nil
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
