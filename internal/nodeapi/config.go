package nodeapi

import (
	"errors"
	"time"

	"github.com/plexsphere/plexd/internal/paths"
)

// Config holds the configuration for the local node API server.
// Config is passed as a constructor argument — no file I/O in this package.
type Config struct {
	// SocketPath is the address of the local API listener: a Unix socket
	// path, or on Windows a named pipe name (`\\.\pipe\plexd` by default).
	// Default: paths.SocketPath()
	SocketPath string `yaml:"socket_path"`

	// HTTPEnabled enables the optional HTTP listener.
	// Default: false
	HTTPEnabled bool `yaml:"http_enabled"`

	// HTTPListen is the HTTP listen address.
	// Default: 127.0.0.1:9100
	HTTPListen string `yaml:"http_listen"`

	// HTTPTokenFile is the path to the HTTP bearer token file.
	HTTPTokenFile string `yaml:"http_token_file"`

	// DebouncePeriod is the debounce period for coalescing events.
	// Default: 5s
	DebouncePeriod time.Duration `yaml:"debounce_period"`

	// ShutdownTimeout is the maximum time to wait for a graceful shutdown.
	// Default: 5s
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`

	// DataDir is the path to the data directory (required). It is propagated
	// from the top-level data_dir by AgentConfig.ApplyDefaults, not from YAML.
	DataDir string `yaml:"-"`

	// SecretAuthEnabled enables peer-credential authentication for
	// /v1/state/secrets/* on the local listener: SO_PEERCRED on Linux,
	// LOCAL_PEERCRED on macOS, the pipe client's process token on Windows.
	// When enabled, only a privileged local peer (root or a plexd-secrets
	// member on Linux and macOS; an elevated Administrator or LocalSystem on
	// Windows) may read secrets.
	// Default: false (enabled by cmd/plexd/cmd/up.go in production).
	SecretAuthEnabled bool `yaml:"secret_auth_enabled"`
}

// DefaultSocketPath is the default address of the local API listener. It is
// resolved per platform (a Unix socket path, or the named pipe
// `\\.\pipe\plexd` on Windows), which is why it is a var rather than a const.
var DefaultSocketPath = paths.SocketPath()

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
	if err := validateSocketPath(c.SocketPath); err != nil {
		return err
	}
	if c.DebouncePeriod <= 0 {
		return errors.New("nodeapi: config: DebouncePeriod must be positive")
	}
	if c.ShutdownTimeout <= 0 {
		return errors.New("nodeapi: config: ShutdownTimeout must be positive")
	}
	return nil
}
