// Package integrity provides SHA-256 checksum verification for plexd binaries and hook scripts.
package integrity

import (
	"errors"
	"time"
)

// DefaultVerifyInterval is the default interval between integrity verification runs.
const DefaultVerifyInterval = 5 * time.Minute

// Config holds the configuration for integrity verification.
type Config struct {
	// Enabled controls whether integrity verification is active.
	// Default: true (set by ApplyDefaults).
	Enabled bool

	// BinaryPath is the path to the plexd binary to verify.
	BinaryPath string

	// HooksDir is the directory containing hook scripts to verify.
	HooksDir string

	// VerifyInterval is the interval between integrity verification runs.
	// Must be at least 30s when enabled.
	// Default: 5m
	VerifyInterval time.Duration
}

// ApplyDefaults sets default values for zero-valued fields.
// On a zero-valued Config, Enabled defaults to true.
// To disable integrity verification, set Enabled=false before or after calling ApplyDefaults.
func (c *Config) ApplyDefaults() {
	// On a zero-valued Config (VerifyInterval == 0), the caller wants defaults
	// including Enabled=true. If VerifyInterval was set explicitly, the caller
	// constructed the config intentionally and we respect Enabled as-is.
	if c.VerifyInterval == 0 {
		c.Enabled = true
		c.VerifyInterval = DefaultVerifyInterval
	}
}

// Validate checks that configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.VerifyInterval < 30*time.Second {
		return errors.New("integrity: config: VerifyInterval must be at least 30s when enabled")
	}
	return nil
}
