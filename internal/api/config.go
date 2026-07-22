package api

import (
	"errors"
	"time"
)

// Config holds the configuration for the ControlPlane client.
// Config is passed as a constructor argument — no file I/O in this package.
type Config struct {
	// BaseURL is the control plane API base URL (required).
	// Example: "https://api.plexsphere.com"
	BaseURL string `yaml:"base_url"`

	// TLSInsecureSkipVerify disables TLS certificate verification.
	// WARNING: Only use for development/testing.
	TLSInsecureSkipVerify bool `yaml:"tls_insecure_skip_verify"`

	// ConnectTimeout is the maximum time to wait for a TCP connection.
	// Default: 10s
	ConnectTimeout time.Duration `yaml:"connect_timeout"`

	// RequestTimeout is the maximum time for a complete HTTP request/response cycle.
	// Default: 30s
	RequestTimeout time.Duration `yaml:"request_timeout"`

	// SSEIdleTimeout is the maximum time to wait for any data on the SSE stream
	// before considering the connection stale and reconnecting.
	// Default: 90s
	SSEIdleTimeout time.Duration `yaml:"sse_idle_timeout"`
}

// DefaultConnectTimeout is the default TCP connect timeout.
const DefaultConnectTimeout = 10 * time.Second

// DefaultRequestTimeout is the default HTTP request timeout.
const DefaultRequestTimeout = 30 * time.Second

// DefaultSSEIdleTimeout is the default SSE idle timeout.
const DefaultSSEIdleTimeout = 90 * time.Second

// DefaultSSEReprobeInterval is how often pull-only delivery mode re-probes the
// descoped SSE endpoint to detect that it has come back.
const DefaultSSEReprobeInterval = 10 * time.Minute

// ApplyDefaults sets default values for zero-valued fields.
func (c *Config) ApplyDefaults() {
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = DefaultConnectTimeout
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = DefaultRequestTimeout
	}
	if c.SSEIdleTimeout == 0 {
		c.SSEIdleTimeout = DefaultSSEIdleTimeout
	}
}

// Validate checks that required fields are set.
func (c *Config) Validate() error {
	if c.BaseURL == "" {
		return errors.New("api: config: BaseURL is required")
	}
	return nil
}
