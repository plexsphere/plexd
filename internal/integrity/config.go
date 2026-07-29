// Package integrity verifies the plexd binary and hook scripts by SHA-256
// checksum, and the SSH host key by its OpenSSH fingerprint.
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
	Enabled bool `yaml:"enabled"`

	// BinaryPath is the path to the plexd binary to verify.
	BinaryPath string `yaml:"binary_path"`

	// HooksDir is the directory containing hook scripts to verify.
	HooksDir string `yaml:"hooks_dir"`

	// HostKeyPath is the SSH host key whose fingerprint is verified. It is
	// derived from the agent's data dir rather than configured, so it is kept
	// off the YAML surface.
	HostKeyPath string `yaml:"-"`

	// VerifyInterval is the interval between integrity verification runs.
	// Must be at least 30s when enabled.
	// Default: 5m
	VerifyInterval time.Duration `yaml:"verify_interval"`

	// WatchEnabled controls whether inotify file watching is active.
	// When enabled, file changes in HooksDir trigger immediate checksum
	// recomputation instead of waiting for the next periodic verification.
	// Default: true (set by ApplyDefaults).
	WatchEnabled bool `yaml:"watch_enabled"`
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
		c.WatchEnabled = true
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
