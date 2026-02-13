// Package actions provides remote action execution and hook management for plexd mesh nodes.
package actions

import (
	"errors"
	"time"
)

// DefaultMaxConcurrent is the default maximum number of concurrent actions.
const DefaultMaxConcurrent = 5

// DefaultMaxActionTimeout is the default maximum duration for a single action.
const DefaultMaxActionTimeout = 10 * time.Minute

// DefaultMaxOutputBytes is the default maximum output size per action (1 MiB).
const DefaultMaxOutputBytes = 1 << 20

// Config holds the configuration for remote action execution.
type Config struct {
	// Enabled controls whether action execution is active.
	// Default: true (set by ApplyDefaults).
	Enabled bool

	// HooksDir is the directory containing hook scripts.
	HooksDir string

	// MaxConcurrent is the maximum number of actions that can run concurrently.
	// Must be at least 1 when enabled. Default: 5.
	MaxConcurrent int

	// MaxActionTimeout is the maximum duration for a single action.
	// Must be at least 10s when enabled. Default: 10m.
	MaxActionTimeout time.Duration

	// MaxOutputBytes is the maximum output size per action in bytes.
	// Must be at least 1024 when enabled. Default: 1 MiB.
	MaxOutputBytes int64
}

// ApplyDefaults sets default values for zero-valued fields.
// On a zero-valued Config, Enabled defaults to true.
// To disable action execution, set Enabled=false before or after calling ApplyDefaults.
func (c *Config) ApplyDefaults() {
	// Enabled defaults to true for zero-valued Config. Since bool zero is false,
	// we use a heuristic: if all fields are zero, the caller wants defaults (including Enabled=true).
	// If any field is non-zero, the caller constructed the config explicitly and we respect Enabled as-is.
	if c.MaxConcurrent == 0 && c.MaxActionTimeout == 0 && c.MaxOutputBytes == 0 {
		c.Enabled = true
	}
	if c.MaxConcurrent == 0 {
		c.MaxConcurrent = DefaultMaxConcurrent
	}
	if c.MaxActionTimeout == 0 {
		c.MaxActionTimeout = DefaultMaxActionTimeout
	}
	if c.MaxOutputBytes == 0 {
		c.MaxOutputBytes = DefaultMaxOutputBytes
	}
}

// Validate checks that configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.MaxConcurrent < 1 {
		return errors.New("actions: config: MaxConcurrent must be at least 1")
	}
	if c.MaxActionTimeout < 10*time.Second {
		return errors.New("actions: config: MaxActionTimeout must be at least 10s")
	}
	if c.MaxOutputBytes < 1024 {
		return errors.New("actions: config: MaxOutputBytes must be at least 1024")
	}
	return nil
}
