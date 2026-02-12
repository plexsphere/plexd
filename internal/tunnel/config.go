// Package tunnel implements secure access tunneling for plexd mesh nodes.
package tunnel

import (
	"errors"
	"time"
)

// DefaultMaxSessions is the default maximum number of concurrent tunnel sessions.
const DefaultMaxSessions = 10

// DefaultTimeout is the default session timeout.
const DefaultTimeout = 30 * time.Minute

// Config holds the configuration for secure access tunneling.
type Config struct {
	// Enabled controls whether tunneling is active.
	// Default: true (set by ApplyDefaults).
	Enabled bool

	// MaxSessions is the maximum number of concurrent tunnel sessions.
	// Default: 10
	MaxSessions int

	// DefaultTimeout is the default/maximum session timeout.
	// Default: 30m
	DefaultTimeout time.Duration
}

// ApplyDefaults sets default values for zero-valued fields.
// On a zero-valued Config, Enabled defaults to true.
// To disable tunneling, set Enabled=false before or after calling ApplyDefaults.
func (c *Config) ApplyDefaults() {
	// On a zero-valued Config (MaxSessions == 0), the caller wants defaults
	// including Enabled=true. If MaxSessions was set explicitly, the caller
	// constructed the config intentionally and we respect Enabled as-is.
	if c.MaxSessions == 0 {
		c.Enabled = true
		c.MaxSessions = DefaultMaxSessions
		c.DefaultTimeout = DefaultTimeout
	}
	if c.DefaultTimeout == 0 {
		c.DefaultTimeout = DefaultTimeout
	}
}

// Validate checks that configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.MaxSessions <= 0 {
		return errors.New("tunnel: config: MaxSessions must be positive when enabled")
	}
	if c.DefaultTimeout < time.Minute {
		return errors.New("tunnel: config: DefaultTimeout must be at least 1m when enabled")
	}
	return nil
}
