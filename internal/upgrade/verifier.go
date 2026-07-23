package upgrade

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// embeddedTrustedRoot is the Sigstore public-good trusted root, vendored so that
// verification works fully offline with no TUF fetch at verify time.
//
//go:embed trusted_root.json
var embeddedTrustedRoot []byte

// Verifier checks a plexd release Sigstore bundle against a trusted root and a
// required signing identity. It performs no network I/O.
type Verifier struct {
	verifier *verify.Verifier
	identity verify.CertificateIdentity
}

// NewVerifier builds a Verifier from the given configuration. The trusted root
// is read from cfg.TrustedRootPath when set, otherwise the embedded public-good
// root is used. The signing-identity regexp is compiled here so a malformed
// pattern is rejected at construction.
func NewVerifier(cfg Config) (*Verifier, error) {
	rootJSON := embeddedTrustedRoot
	if cfg.TrustedRootPath != "" {
		data, err := os.ReadFile(cfg.TrustedRootPath)
		if err != nil {
			return nil, fmt.Errorf("upgrade: load trusted root: %w", err)
		}
		rootJSON = data
	}

	trustedRoot, err := root.NewTrustedRootFromJSON(rootJSON)
	if err != nil {
		return nil, fmt.Errorf("upgrade: parse trusted root: %w", err)
	}

	sev, err := verify.NewVerifier(trustedRoot,
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("upgrade: build verifier: %w", err)
	}

	identity, err := verify.NewShortCertificateIdentity(cfg.SigningIssuer, "", "", cfg.SigningIdentityRegexp)
	if err != nil {
		return nil, fmt.Errorf("upgrade: build signing identity: %w", err)
	}

	return &Verifier{verifier: sev, identity: identity}, nil
}

// Verify checks that bundleJSON is a valid Sigstore bundle for an artifact with
// the given hex-encoded SHA-256 digest, signed by the configured identity and
// chaining to the trusted root. Any failure (unparsable bundle, digest or
// identity mismatch, untrusted chain) is returned as a wrapped error rather than
// a panic.
func (v *Verifier) Verify(bundleJSON []byte, sha256Hex string) error {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return fmt.Errorf("upgrade: parse bundle: %w", err)
	}

	digest, err := hex.DecodeString(sha256Hex)
	if err != nil {
		return fmt.Errorf("upgrade: decode digest: %w", err)
	}

	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest),
		verify.WithCertificateIdentity(v.identity),
	)
	if _, err := v.verifier.Verify(&b, policy); err != nil {
		return fmt.Errorf("upgrade: verify bundle: %w", err)
	}
	return nil
}
