// Package nat provides NAT traversal via STUN for plexd mesh nodes.
package nat

import (
	"errors"
	"time"
)

// DefaultRefreshInterval is the default interval between STUN binding refreshes.
const DefaultRefreshInterval = 60 * time.Second

// DefaultTimeout is the default per-server STUN request timeout.
const DefaultTimeout = 5 * time.Second

// DefaultSTUNServers is the default list of STUN servers used for NAT traversal.
var DefaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun.cloudflare.com:3478",
}

// Config holds the configuration for NAT traversal.
type Config struct {
	// Enabled controls whether NAT traversal is active.
	// Default: true (set by ApplyDefaults).
	Enabled bool

	// STUNServers is the list of STUN server addresses (host:port).
	STUNServers []string

	// RefreshInterval is the interval between STUN binding refreshes.
	// Must be at least 10s.
	RefreshInterval time.Duration

	// Timeout is the per-server STUN request timeout.
	// Must be positive.
	Timeout time.Duration
}

// ApplyDefaults sets default values for zero-valued fields.
// On a zero-valued Config, Enabled defaults to true.
// To disable NAT traversal, set Enabled=false before or after calling ApplyDefaults.
func (c *Config) ApplyDefaults() {
	// Enabled defaults to true for zero-valued Config. Since bool zero is false,
	// we use a heuristic: if all fields are zero, the caller wants defaults (including Enabled=true).
	// If any field is non-zero, the caller constructed the config explicitly and we respect Enabled as-is.
	if c.STUNServers == nil && c.RefreshInterval == 0 && c.Timeout == 0 {
		c.Enabled = true
	}
	if c.STUNServers == nil {
		c.STUNServers = append([]string{}, DefaultSTUNServers...)
	}
	if c.RefreshInterval == 0 {
		c.RefreshInterval = DefaultRefreshInterval
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
}

// Validate checks that configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if len(c.STUNServers) == 0 {
		return errors.New("nat: config: STUNServers must not be empty when enabled")
	}
	if c.RefreshInterval < 10*time.Second {
		return errors.New("nat: config: RefreshInterval must be at least 10s")
	}
	if c.Timeout <= 0 {
		return errors.New("nat: config: Timeout must be positive")
	}
	return nil
}
