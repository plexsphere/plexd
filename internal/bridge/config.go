package bridge

import (
	"fmt"
	"net"
)

// Config holds the configuration for bridge mode.
// Config is passed as a constructor argument — no file I/O in this package.
type Config struct {
	// Enabled controls whether bridge mode is active.
	// Default: false
	Enabled bool

	// AccessInterface is the name of the access-side network interface.
	AccessInterface string

	// AccessSubnets are the CIDR subnets reachable via the access-side interface.
	AccessSubnets []string

	// EnableNAT controls whether NAT masquerading is applied on the access-side interface.
	// nil means use default (true); explicit false disables NAT.
	EnableNAT *bool
}

// BoolPtr returns a pointer to the given bool value.
func BoolPtr(v bool) *bool { return &v }

// natEnabled returns the effective NAT setting: true unless explicitly set to false.
func (c *Config) natEnabled() bool {
	if c.EnableNAT == nil {
		return true
	}
	return *c.EnableNAT
}

// ApplyDefaults sets default values for zero-valued fields.
func (c *Config) ApplyDefaults() {
	// EnableNAT is handled via natEnabled(); nil means default true.
}

// Validate checks that configuration values are acceptable.
// When bridge mode is disabled, validation is skipped.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.AccessInterface == "" {
		return fmt.Errorf("bridge: config: AccessInterface is required when enabled")
	}
	if len(c.AccessSubnets) == 0 {
		return fmt.Errorf("bridge: config: at least one AccessSubnet is required when enabled")
	}
	for _, subnet := range c.AccessSubnets {
		if _, _, err := net.ParseCIDR(subnet); err != nil {
			return fmt.Errorf("bridge: config: invalid CIDR %q: %w", subnet, err)
		}
	}
	return nil
}
