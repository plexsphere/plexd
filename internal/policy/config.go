// Package policy implements network policy enforcement for plexd mesh nodes.
package policy

import "errors"

// DefaultChainName is the default iptables chain name for policy enforcement.
const DefaultChainName = "plexd-mesh"

// Config holds the configuration for network policy enforcement.
type Config struct {
	// Enabled controls whether policy enforcement is active.
	// Default: true (set by ApplyDefaults).
	Enabled bool

	// ChainName is the iptables chain name for firewall rules.
	ChainName string
}

// ApplyDefaults sets default values for zero-valued fields.
// On a zero-valued Config, Enabled defaults to true.
// To disable policy enforcement, set Enabled=false before or after calling ApplyDefaults.
func (c *Config) ApplyDefaults() {
	// On a zero-valued Config (ChainName == ""), the caller wants defaults
	// including Enabled=true. If ChainName was set explicitly, the caller
	// constructed the config intentionally and we respect Enabled as-is.
	if c.ChainName == "" {
		c.Enabled = true
		c.ChainName = DefaultChainName
	}
}

// Validate checks that configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.ChainName == "" {
		return errors.New("policy: config: ChainName must not be empty when enabled")
	}
	return nil
}
