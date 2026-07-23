package upgrade

import (
	"strings"
	"testing"
)

func TestConfig_ApplyDefaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if cfg.ReleaseBaseURL != DefaultReleaseBaseURL {
		t.Errorf("ReleaseBaseURL = %q, want %q", cfg.ReleaseBaseURL, DefaultReleaseBaseURL)
	}
	if cfg.SigningIdentityRegexp != DefaultSigningIdentityRegexp {
		t.Errorf("SigningIdentityRegexp = %q, want %q", cfg.SigningIdentityRegexp, DefaultSigningIdentityRegexp)
	}
	if cfg.SigningIssuer != DefaultSigningIssuer {
		t.Errorf("SigningIssuer = %q, want %q", cfg.SigningIssuer, DefaultSigningIssuer)
	}
	if cfg.TrustedRootPath != "" {
		t.Errorf("TrustedRootPath = %q, want empty (use embedded root)", cfg.TrustedRootPath)
	}
}

func TestConfig_ApplyDefaultsPreservesExisting(t *testing.T) {
	cfg := Config{
		ReleaseBaseURL:        "https://mirror.example.com/dl",
		SigningIdentityRegexp: "^custom$",
		SigningIssuer:         "https://issuer.example.com",
		TrustedRootPath:       "/etc/plexd/trusted_root.json",
	}
	cfg.ApplyDefaults()

	if cfg.ReleaseBaseURL != "https://mirror.example.com/dl" {
		t.Errorf("ReleaseBaseURL = %q, want preserved", cfg.ReleaseBaseURL)
	}
	if cfg.SigningIdentityRegexp != "^custom$" {
		t.Errorf("SigningIdentityRegexp = %q, want preserved", cfg.SigningIdentityRegexp)
	}
	if cfg.SigningIssuer != "https://issuer.example.com" {
		t.Errorf("SigningIssuer = %q, want preserved", cfg.SigningIssuer)
	}
	if cfg.TrustedRootPath != "/etc/plexd/trusted_root.json" {
		t.Errorf("TrustedRootPath = %q, want preserved", cfg.TrustedRootPath)
	}
}

func TestConfig_ValidateRejectsBadRegexp(t *testing.T) {
	cfg := Config{SigningIdentityRegexp: "("}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for non-compiling regexp")
	}
	const wantPrefix = "upgrade: config: compile signing_identity_regexp:"
	if !strings.HasPrefix(err.Error(), wantPrefix) {
		t.Errorf("Validate() error = %q, want prefix %q", err.Error(), wantPrefix)
	}
}

func TestConfig_ValidateAcceptsDefaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for default config", err)
	}
}
