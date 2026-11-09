package meshdns

import "errors"

// DefaultListenPort is the port the resolver listens on when listen_port is
// not set. It is unprivileged, so plexd.service needs no
// CAP_NET_BIND_SERVICE, and systemd-resolved 246 and newer accept a port
// beside the server address of a link.
const DefaultListenPort = 5354

// Config holds the configuration of the mesh DNS resolver.
type Config struct {
	// Enabled controls whether the resolver runs. A pointer, so an unset key
	// stays distinguishable from an explicit false: an existing deployment
	// sets nothing and gets the resolver, and `enabled: false` is the Node
	// operator's only way out, so it must survive ApplyDefaults exactly as
	// written.
	// Default: true (nil reads as enabled).
	Enabled *bool `yaml:"enabled"`

	// ListenPort is the UDP and TCP port the resolver listens on, on the
	// node's own mesh IP.
	// Default: 5354.
	ListenPort int `yaml:"listen_port"`
}

// IsEnabled returns the effective Enabled setting: true unless explicitly set
// to false.
func (c *Config) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// ApplyDefaults sets default values for zero-valued fields. Enabled is left
// untouched, because nil already means enabled, and writing a value into it
// would erase the difference between an omitted key and an operator's
// `false`.
func (c *Config) ApplyDefaults() {
	if c.ListenPort == 0 {
		c.ListenPort = DefaultListenPort
	}
}

// Validate checks that configuration values are within acceptable ranges. A
// disabled resolver binds nothing, so its port is not checked.
func (c *Config) Validate() error {
	if !c.IsEnabled() {
		return nil
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return errors.New("meshdns: config: ListenPort must be between 1 and 65535")
	}
	return nil
}
