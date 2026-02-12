// Package peerexchange orchestrates peer endpoint exchange for plexd mesh nodes.
package peerexchange

import "github.com/plexsphere/plexd/internal/nat"

// Config holds the configuration for peer endpoint exchange.
// It embeds nat.Config to reuse NAT traversal settings.
type Config struct {
	nat.Config
}

// ApplyDefaults sets default values for zero-valued fields.
func (c *Config) ApplyDefaults() {
	c.Config.ApplyDefaults()
}

// Validate checks that configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	return c.Config.Validate()
}
