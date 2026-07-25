package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/plexsphere/plexd/internal/actions"
	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/auditfwd"
	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/health"
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
	"github.com/plexsphere/plexd/internal/upgrade"
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
	Health       health.Config       `yaml:"health"`
	Actions      actions.Config      `yaml:"actions"`
	Policy       policy.Config       `yaml:"policy"`
	WireGuard    wireguard.Config    `yaml:"wireguard"`
	Metrics      metrics.Config      `yaml:"metrics"`
	LogFwd       logfwd.Config       `yaml:"log_fwd"`
	AuditFwd     auditfwd.Config     `yaml:"audit_fwd"`
	Integrity    integrity.Config    `yaml:"integrity"`
	Upgrade      upgrade.Config      `yaml:"upgrade"`
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
	c.Health.ApplyDefaults()
	c.Actions.ApplyDefaults()
	c.Policy.ApplyDefaults()
	c.WireGuard.ApplyDefaults()
	c.Metrics.ApplyDefaults()
	c.LogFwd.ApplyDefaults()
	c.AuditFwd.ApplyDefaults()
	c.Integrity.ApplyDefaults()
	c.Upgrade.ApplyDefaults()
	c.Tunnel.ApplyDefaults()
	c.NAT.ApplyDefaults()
	c.PeerExchange.ApplyDefaults()
	c.Bridge.ApplyDefaults()
	c.Heartbeat.ApplyDefaults()
	// Propagate the top-level data dir into the subsystem configs. Both fields
	// are excluded from the YAML surface (yaml:"-"), so this is their only
	// source.
	c.Registration.DataDir = c.DataDir
	c.NodeAPI.DataDir = c.DataDir
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
	if err := c.Health.Validate(); err != nil {
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
	if err := c.Upgrade.Validate(); err != nil {
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
	// Heartbeat is deliberately not validated here: its NodeID only exists
	// after registration, so plexd up validates the constructed config instead.
	return nil
}

// ParseConfig reads a YAML configuration file and returns an AgentConfig with
// defaults applied. An absent file is not an error: it is treated as an empty
// config, and the returned bool reports whether the file was found. A file
// that exists but cannot be read, that is empty, or that does not parse, is an
// error.
// Validating the result is the caller's responsibility, once the CLI flag and
// environment overrides have been merged in.
func ParseConfig(path string) (*AgentConfig, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			var cfg AgentConfig
			cfg.ApplyDefaults()
			// An unset Actions.Enabled means on, and it is the only kill
			// switch on control-plane-driven execution. An absent file carries
			// no operator-expressed policy, so it must not enable it: a
			// deleted or unmounted config would otherwise silently undo
			// actions.enabled: false. PLEXD_ACTIONS_ENABLED turns it back on
			// for a deliberately file-less deployment.
			disabled := false
			cfg.Actions.Enabled = &disabled
			return &cfg, false, nil
		}
		return nil, false, fmt.Errorf("agent: config: read %s: %w", path, err)
	}
	// A file with no content is not a configuration. yaml.Unmarshal accepts it
	// silently, so it would come back as "found" with every field defaulted —
	// including the actions kill switch, which the absent-file path above
	// deliberately turns off. A truncated write, a Helm template that rendered
	// an empty ConfigMap key, and a bootstrap that created the file before
	// writing it all land here, and none of them carry operator intent.
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, false, fmt.Errorf("agent: config: %s is empty: remove the file to run without one, or supply a configuration", path)
	}
	var cfg AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, false, fmt.Errorf("agent: config: parse %s: %w", path, err)
	}
	cfg.ApplyDefaults()
	return &cfg, true, nil
}
