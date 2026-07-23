// Package upgrade downloads plexd release binaries from the GitHub release
// channel and verifies their Sigstore bundles before they are trusted.
package upgrade

import (
	"fmt"
	"regexp"
)

// DefaultReleaseBaseURL is the base URL of the GitHub release download channel.
const DefaultReleaseBaseURL = "https://github.com/plexsphere/plexd/releases/download"

// DefaultSigningIdentityRegexp is the certificate SAN regexp that a release
// bundle's signing identity must match: the plexd release workflow signed for a
// tagged version.
const DefaultSigningIdentityRegexp = `^https://github\.com/plexsphere/plexd/\.github/workflows/release\.yml@refs/tags/v.+$`

// DefaultSigningIssuer is the expected OIDC issuer of the signing certificate.
const DefaultSigningIssuer = "https://token.actions.githubusercontent.com"

// Config holds the configuration for release download and Sigstore verification.
type Config struct {
	// ReleaseBaseURL is the base URL of the GitHub release download channel.
	// Release assets are fetched from {ReleaseBaseURL}/{tag}/{asset}.
	// Default: https://github.com/plexsphere/plexd/releases/download
	ReleaseBaseURL string `yaml:"release_base_url"`

	// SigningIdentityRegexp is the regexp the signing certificate's SAN must
	// match. It is compiled by Validate.
	// Default: ^https://github\.com/plexsphere/plexd/\.github/workflows/release\.yml@refs/tags/v.+$
	SigningIdentityRegexp string `yaml:"signing_identity_regexp"`

	// SigningIssuer is the exact OIDC issuer the signing certificate must carry.
	// Default: https://token.actions.githubusercontent.com
	SigningIssuer string `yaml:"signing_issuer"`

	// TrustedRootPath is the path to a Sigstore trusted root JSON file. When
	// empty the embedded public-good trusted root is used.
	// Default: "" (use the embedded trusted root)
	TrustedRootPath string `yaml:"trusted_root_path"`
}

// ApplyDefaults sets default values for empty fields. TrustedRootPath is left
// empty by design so the embedded trusted root remains the default.
func (c *Config) ApplyDefaults() {
	if c.ReleaseBaseURL == "" {
		c.ReleaseBaseURL = DefaultReleaseBaseURL
	}
	if c.SigningIdentityRegexp == "" {
		c.SigningIdentityRegexp = DefaultSigningIdentityRegexp
	}
	if c.SigningIssuer == "" {
		c.SigningIssuer = DefaultSigningIssuer
	}
}

// Validate checks that the configuration is usable. It compiles
// SigningIdentityRegexp so a malformed pattern is rejected before verification.
func (c *Config) Validate() error {
	if _, err := regexp.Compile(c.SigningIdentityRegexp); err != nil {
		return fmt.Errorf("upgrade: config: compile signing_identity_regexp: %w", err)
	}
	return nil
}
