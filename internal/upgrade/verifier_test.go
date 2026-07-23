package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

// loadFixture returns the fixture bundle JSON and the hex SHA-256 of the blob
// it was signed over.
func loadFixture(t *testing.T) (bundleJSON []byte, sha256Hex string) {
	t.Helper()
	blob, err := os.ReadFile("testdata/fixture.bin")
	if err != nil {
		t.Fatalf("read fixture.bin: %v", err)
	}
	sum := sha256.Sum256(blob)
	bundleJSON, err = os.ReadFile("testdata/fixture.sigstore.json")
	if err != nil {
		t.Fatalf("read fixture.sigstore.json: %v", err)
	}
	return bundleJSON, hex.EncodeToString(sum[:])
}

// fixtureIdentity parses the fixture bundle's leaf certificate and returns its
// signing issuer and SAN. Deriving these from the fixture keeps the tests valid
// across fixture regeneration.
func fixtureIdentity(t *testing.T, bundleJSON []byte) (issuer, san string) {
	t.Helper()
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		t.Fatalf("parse fixture bundle: %v", err)
	}
	vc, err := b.VerificationContent()
	if err != nil {
		t.Fatalf("fixture verification content: %v", err)
	}
	cert := vc.Certificate()
	if cert == nil {
		t.Fatal("fixture bundle has no leaf certificate")
	}
	summary, err := certificate.SummarizeCertificate(cert)
	if err != nil {
		t.Fatalf("summarize fixture certificate: %v", err)
	}
	return summary.Extensions.Issuer, summary.SubjectAlternativeName
}

// acceptConfig builds a Config whose identity policy matches the fixture leaf.
func acceptConfig(t *testing.T, bundleJSON []byte) Config {
	t.Helper()
	issuer, san := fixtureIdentity(t, bundleJSON)
	return Config{
		SigningIssuer:         issuer,
		SigningIdentityRegexp: "^" + regexp.QuoteMeta(san) + "$",
	}
}

func TestVerify_AcceptsFixtureOffline(t *testing.T) {
	bundleJSON, digest := loadFixture(t)
	cfg := acceptConfig(t, bundleJSON)

	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(bundleJSON, digest); err != nil {
		t.Fatalf("Verify() = %v, want nil", err)
	}
}

func TestVerify_Refusals(t *testing.T) {
	bundleJSON, digest := loadFixture(t)
	accept := acceptConfig(t, bundleJSON)

	otherDigest := sha256.Sum256([]byte("different"))

	tests := []struct {
		name    string
		cfg     Config
		bundle  []byte
		digest  string
		wantSub string
	}{
		{
			name:    "unparsable bundle",
			cfg:     accept,
			bundle:  []byte("this is not json"),
			digest:  digest,
			wantSub: "upgrade: parse bundle:",
		},
		{
			name:    "digest mismatch",
			cfg:     accept,
			bundle:  bundleJSON,
			digest:  hex.EncodeToString(otherDigest[:]),
			wantSub: "upgrade: verify bundle:",
		},
		{
			name: "identity mismatch",
			cfg: Config{
				SigningIssuer:         accept.SigningIssuer,
				SigningIdentityRegexp: `^https://example\.invalid/$`,
			},
			bundle:  bundleJSON,
			digest:  digest,
			wantSub: "upgrade: verify bundle:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(tt.cfg)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			err = v.Verify(tt.bundle, tt.digest)
			if err == nil {
				t.Fatal("Verify() = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("Verify() error = %q, want substring %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestNewVerifier_UnreadableTrustedRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file mode 0000 is still readable")
	}

	path := filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(path, []byte("{}"), 0o000); err != nil {
		t.Fatalf("write temp trusted root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, err := NewVerifier(Config{TrustedRootPath: path})
	if err == nil {
		t.Fatal("NewVerifier() = nil error, want open failure")
	}
	if !strings.Contains(err.Error(), "upgrade: load trusted root:") {
		t.Errorf("NewVerifier() error = %q, want load-trusted-root wrap", err.Error())
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Errorf("NewVerifier() error = %v, want wrapped *os.PathError", err)
	}
}
