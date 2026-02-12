package nodeapi

import (
	"errors"
	"time"
)

// Config holds the configuration for the local node API server.
// Config is passed as a constructor argument — no file I/O in this package.
type Config struct {
	// SocketPath is the path to the Unix domain socket.
	// Default: /var/run/plexd/api.sock
	SocketPath string

	// HTTPEnabled enables the optional HTTP listener.
	// Default: false
	HTTPEnabled bool

	// HTTPListen is the HTTP listen address.
	// Default: 127.0.0.1:9100
	HTTPListen string

	// HTTPTokenFile is the path to the HTTP bearer token file.
	HTTPTokenFile string

	// DebouncePeriod is the debounce period for coalescing events.
	// Default: 5s
	DebouncePeriod time.Duration

	// ShutdownTimeout is the maximum time to wait for a graceful shutdown.
	// Default: 5s
	ShutdownTimeout time.Duration

	// DataDir is the path to the data directory (required).
	DataDir string
}

// DefaultSocketPath is the default Unix domain socket path.
const DefaultSocketPath = "/var/run/plexd/api.sock"

// DefaultHTTPListen is the default HTTP listen address.
const DefaultHTTPListen = "127.0.0.1:9100"

// DefaultDebouncePeriod is the default debounce period.
const DefaultDebouncePeriod = 5 * time.Second

// DefaultShutdownTimeout is the default graceful shutdown timeout.
const DefaultShutdownTimeout = 5 * time.Second

// ApplyDefaults sets default values for zero-valued fields.
func (c *Config) ApplyDefaults() {
	if c.SocketPath == "" {
		c.SocketPath = DefaultSocketPath
	}
	if c.HTTPListen == "" {
		c.HTTPListen = DefaultHTTPListen
	}
	if c.DebouncePeriod == 0 {
		c.DebouncePeriod = DefaultDebouncePeriod
	}
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = DefaultShutdownTimeout
	}
}

// Validate checks that required fields are set and values are acceptable.
func (c *Config) Validate() error {
	if c.DataDir == "" {
		return errors.New("nodeapi: config: DataDir is required")
	}
	if c.DebouncePeriod <= 0 {
		return errors.New("nodeapi: config: DebouncePeriod must be positive")
	}
	if c.ShutdownTimeout <= 0 {
		return errors.New("nodeapi: config: ShutdownTimeout must be positive")
	}
	return nil
}
