package reconcile

import (
	"errors"
	"time"
)

// Config holds the configuration for the reconciliation loop.
// Config is passed as a constructor argument — no file I/O in this package.
type Config struct {
	// Interval is the time between reconciliation cycles.
	// Default: 60s
	Interval time.Duration
}

// DefaultInterval is the default reconciliation interval.
const DefaultInterval = 60 * time.Second

// ApplyDefaults sets default values for zero-valued fields.
func (c *Config) ApplyDefaults() {
	if c.Interval == 0 {
		c.Interval = DefaultInterval
	}
}

// Validate checks that configuration values are acceptable.
func (c *Config) Validate() error {
	if c.Interval < 0 {
		return errors.New("reconcile: config: Interval must not be negative")
	}
	if c.Interval < time.Second {
		return errors.New("reconcile: config: Interval must be at least 1s")
	}
	return nil
}
