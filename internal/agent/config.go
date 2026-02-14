package agent

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/plexsphere/plexd/internal/actions"
	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/auditfwd"
	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/integrity"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/nat"
	"github.com/plexsphere/plexd/internal/nodeapi"
	"github.com/plexsphere/plexd/internal/peerexchange"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/registration"
	"github.com/plexsphere/plexd/internal/tunnel"
	"github.com/plexsphere/plexd/internal/wireguard"
)

const (
	// DefaultMode is the default operating mode.
	DefaultMode = "node"

	// DefaultLogLevel is the default log level.
	DefaultLogLevel = "info"

	// DefaultDataDir is the default data directory.
	DefaultDataDir = "/var/lib/plexd"
)

// AgentConfig is the top-level configuration for the plexd agent.
// It aggregates all subsystem configurations and is populated from
// a YAML configuration file via ParseConfig.
type AgentConfig struct {
	// Mode is the operating mode: "node" or "bridge".
	// Default: "node"
	Mode string `yaml:"mode"`

	// LogLevel is the log level: "debug", "info", "warn", "error".
	// Default: "info"
	LogLevel string `yaml:"log_level"`

	// DataDir is the directory for persistent agent data.
	// Default: /var/lib/plexd
	DataDir string `yaml:"data_dir"`

	API          api.Config          `yaml:"api"`
	Registration registration.Config `yaml:"registration"`
	Reconcile    reconcile.Config    `yaml:"reconcile"`
	NodeAPI      nodeapi.Config      `yaml:"node_api"`
	Actions      actions.Config      `yaml:"actions"`
	Policy       policy.Config       `yaml:"policy"`
	WireGuard    wireguard.Config    `yaml:"wireguard"`
	Metrics      metrics.Config      `yaml:"metrics"`
	LogFwd       logfwd.Config       `yaml:"log_fwd"`
	AuditFwd     auditfwd.Config     `yaml:"audit_fwd"`
	Integrity    integrity.Config    `yaml:"integrity"`
	Tunnel       tunnel.Config       `yaml:"tunnel"`
	NAT          nat.Config          `yaml:"nat"`
	PeerExchange peerexchange.Config `yaml:"peer_exchange"`
	Bridge       bridge.Config       `yaml:"bridge"`
	Heartbeat    HeartbeatConfig     `yaml:"heartbeat"`
}

// ApplyDefaults sets default values for zero-valued fields.
func (c *AgentConfig) ApplyDefaults() {
	if c.Mode == "" {
		c.Mode = DefaultMode
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir
	}
	c.API.ApplyDefaults()
	c.Registration.ApplyDefaults()
	c.Reconcile.ApplyDefaults()
	c.NodeAPI.ApplyDefaults()
	c.Actions.ApplyDefaults()
	c.Policy.ApplyDefaults()
	c.WireGuard.ApplyDefaults()
	c.Metrics.ApplyDefaults()
	c.LogFwd.ApplyDefaults()
	c.AuditFwd.ApplyDefaults()
	c.Integrity.ApplyDefaults()
	c.Tunnel.ApplyDefaults()
	c.NAT.ApplyDefaults()
	c.PeerExchange.ApplyDefaults()
	c.Bridge.ApplyDefaults()
	c.Heartbeat.ApplyDefaults()
}

// Validate checks that required fields are set and values are acceptable.
func (c *AgentConfig) Validate() error {
	if c.Mode != "node" && c.Mode != "bridge" {
		return fmt.Errorf("agent: config: invalid mode %q (must be \"node\" or \"bridge\")", c.Mode)
	}
	if err := c.API.Validate(); err != nil {
		return err
	}
	if err := c.Registration.Validate(); err != nil {
		return err
	}
	if err := c.Reconcile.Validate(); err != nil {
		return err
	}
	if err := c.NodeAPI.Validate(); err != nil {
		return err
	}
	if err := c.Actions.Validate(); err != nil {
		return err
	}
	if err := c.Policy.Validate(); err != nil {
		return err
	}
	if err := c.WireGuard.Validate(); err != nil {
		return err
	}
	if err := c.Metrics.Validate(); err != nil {
		return err
	}
	if err := c.LogFwd.Validate(); err != nil {
		return err
	}
	if err := c.AuditFwd.Validate(); err != nil {
		return err
	}
	if err := c.Integrity.Validate(); err != nil {
		return err
	}
	if err := c.Tunnel.Validate(); err != nil {
		return err
	}
	if err := c.NAT.Validate(); err != nil {
		return err
	}
	if err := c.PeerExchange.Validate(); err != nil {
		return err
	}
	if err := c.Bridge.Validate(); err != nil {
		return err
	}
	if err := c.Heartbeat.Validate(); err != nil {
		return err
	}
	return nil
}

// ParseConfig reads a YAML configuration file and returns an AgentConfig.
// It applies defaults and validates the configuration.
func ParseConfig(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("agent: config: read %s: %w", path, err)
	}
	var cfg AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("agent: config: parse %s: %w", path, err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
