// Package policy implements network policy enforcement for plexd mesh nodes.
package policy

import "errors"

// DefaultChainName is the default iptables chain name for policy enforcement.
const DefaultChainName = "plexd-mesh"

// Config holds the configuration for network policy enforcement.
type Config struct {
	// Enabled controls whether policy enforcement is active. A pointer, so an
	// unset key stays distinguishable from an explicit false: enforcement is the
	// deny-by-default posture and its absence is fatal at startup, so
	// `enabled: false` is the operator's only way to run a node without it and
	// must survive ApplyDefaults exactly as written.
	// Default: true (nil reads as enabled).
	Enabled *bool `yaml:"enabled"`

	// ChainName is the iptables chain name for firewall rules.
	// Default: plexd-mesh.
	ChainName string `yaml:"chain_name"`
}

// IsEnabled returns the effective Enabled setting: true unless explicitly set
// to false.
func (c *Config) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// ApplyDefaults sets default values for zero-valued fields. Enabled is left
// untouched — nil already means enabled, and writing a value into it would
// erase the difference between an omitted key and an operator's `false`.
func (c *Config) ApplyDefaults() {
	if c.ChainName == "" {
		c.ChainName = DefaultChainName
	}
}

// Validate checks that configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	if !c.IsEnabled() {
		return nil
	}
	if c.ChainName == "" {
		return errors.New("policy: config: ChainName must not be empty when enabled")
	}
	return nil
}
