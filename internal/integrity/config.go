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
	// Enabled controls whether Run makes the baseline checks of the binary,
	// the hooks directory and the SSH host key. nil means use default (true);
	// explicit false disables them. VerifyHook, which the executor calls
	// before a hook runs, does not read it.
	//
	// It is a tri-state for the reason actions.Config.Enabled is: with a plain
	// bool an operator's `enabled: false` is indistinguishable from an omitted
	// key, and defaulting would turn it back on.
	Enabled *bool `yaml:"enabled"`

	// BinaryPath is the path to the plexd binary to verify. Empty means plexd
	// up verifies the running executable, resolved through symlinks. The
	// path is the baseline's store key and the report's artifact_id.
	BinaryPath string `yaml:"binary_path"`

	// HooksDir is the directory containing hook scripts to verify. Empty
	// means no sweep and no watcher: the hooks directory is checked only
	// where this field or PLEXD_HOOKS_DIR names one. It does not mirror
	// actions.hooks_dir.
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
	// It has no effect while HooksDir is empty.
	// nil means use default (true); explicit false disables the watcher.
	WatchEnabled *bool `yaml:"watch_enabled"`
}

// IsEnabled returns the effective Enabled setting: true unless explicitly set
// to false.
func (c *Config) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// IsWatchEnabled returns the effective WatchEnabled setting: true unless
// explicitly set to false.
func (c *Config) IsWatchEnabled() bool {
	if c.WatchEnabled == nil {
		return true
	}
	return *c.WatchEnabled
}

// MarshalYAML renders the effective Enabled and WatchEnabled values so a dump
// of the live config never reports either switch as null. config.dump marshals
// the whole agent config, and a null there reads as "unset", which for these
// fields reads as off while it means on.
func (c Config) MarshalYAML() (any, error) {
	// plain drops the method set, so encoding it does not recurse.
	type plain Config
	out := plain(c)
	if out.Enabled == nil {
		effective := true
		out.Enabled = &effective
	}
	if out.WatchEnabled == nil {
		effective := true
		out.WatchEnabled = &effective
	}
	return out, nil
}

// ApplyDefaults sets default values for zero-valued fields.
func (c *Config) ApplyDefaults() {
	// Enabled and WatchEnabled are handled via IsEnabled() and
	// IsWatchEnabled(); nil means default true, and an explicit false
	// survives. BinaryPath is resolved by plexd up, which knows the running
	// executable, and HostKeyPath by AgentConfig.ApplyDefaults.
	if c.VerifyInterval == 0 {
		c.VerifyInterval = DefaultVerifyInterval
	}
}

// Validate checks that configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	if !c.IsEnabled() {
		return nil
	}
	if c.VerifyInterval < 30*time.Second {
		return errors.New("integrity: config: VerifyInterval must be at least 30s when enabled")
	}
	return nil
}
