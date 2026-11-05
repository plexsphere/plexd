// Package actions provides remote action execution and hook management for plexd mesh nodes.
package actions

import (
	"errors"
	"time"

	"github.com/plexsphere/plexd/internal/paths"
)

// DefaultMaxConcurrent is the default maximum number of concurrent actions.
const DefaultMaxConcurrent = 5

// DefaultMaxActionTimeout is the default maximum duration for a single action.
const DefaultMaxActionTimeout = 10 * time.Minute

// DefaultMaxOutputBytes is the default maximum output size per action (1 MiB).
const DefaultMaxOutputBytes = 1 << 20

// DefaultHooksDir is the default directory for hook scripts. It is resolved
// per platform, which is why it is a var rather than a const.
var DefaultHooksDir = paths.HooksDir()

// Config holds the configuration for remote action execution.
type Config struct {
	// Enabled controls whether action execution is active.
	// nil means use default (true); explicit false disables execution.
	//
	// The tri-state is what makes the switch usable: with a plain bool an
	// operator's `enabled: false` is indistinguishable from an omitted key,
	// and defaulting turns it back on. Enabled is the only switch that stops
	// the control plane from running actions and hooks on the node, so it has
	// to survive ApplyDefaults exactly as written.
	Enabled *bool `yaml:"enabled"`

	// RolloutsEnabled is the node owner's veto on hooks the control plane
	// rolls out. nil means use default (true); explicit false makes plexd
	// remove every rolled-out hook, fetch none, and report each version the
	// pull lists as install_failed. Builtins and hand-placed hooks keep
	// working either way.
	//
	// It is a tri-state for the reason Enabled is: an operator who writes
	// `rollouts_enabled: false` refuses scripts delivered by the control
	// plane, and defaulting must not turn that refusal back into consent.
	RolloutsEnabled *bool `yaml:"rollouts_enabled"`

	// HooksDir is the directory containing hook scripts.
	// Default: paths.HooksDir()
	HooksDir string `yaml:"hooks_dir"`

	// RolloutHooksDir is the directory plexd installs rolled-out hooks into.
	// AgentConfig.ApplyDefaults sets it to <data_dir>/hooks, which makes it
	// the only source of the value. It is not a YAML key because plexd owns
	// the directory and everything in it: the path derives from data_dir like
	// every other file plexd persists, and pointing it at a directory an
	// operator fills would hand plexd's cleanup the operator's files.
	RolloutHooksDir string `yaml:"-"`

	// MaxConcurrent is the maximum number of actions that can run concurrently.
	// Must be at least 1 when enabled. Default: 5.
	MaxConcurrent int `yaml:"max_concurrent"`

	// MaxActionTimeout is the maximum duration for a single action.
	// Must be at least 10s when enabled. Default: 10m.
	MaxActionTimeout time.Duration `yaml:"max_action_timeout"`

	// MaxOutputBytes is the maximum output size per action in bytes.
	// Must be at least 1024 when enabled. Default: 1 MiB.
	MaxOutputBytes int64 `yaml:"max_output_bytes"`
}

// IsEnabled returns the effective Enabled setting: true unless explicitly set
// to false.
func (c *Config) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// IsRolloutsEnabled returns the effective RolloutsEnabled setting: true unless
// explicitly set to false.
func (c *Config) IsRolloutsEnabled() bool {
	if c.RolloutsEnabled == nil {
		return true
	}
	return *c.RolloutsEnabled
}

// MarshalYAML renders the effective Enabled and RolloutsEnabled values so a
// dump of the live config never reports a switch that gates remote execution
// as null. config.dump is what an operator reads to audit which nodes accept
// control-plane-driven execution and delivered scripts, and a null there reads
// as "unset" — which for these fields reads as off, while it means on.
func (c Config) MarshalYAML() (any, error) {
	// plain drops the method set, so encoding it does not recurse.
	type plain Config
	out := plain(c)
	if out.Enabled == nil {
		effective := true
		out.Enabled = &effective
	}
	if out.RolloutsEnabled == nil {
		effective := true
		out.RolloutsEnabled = &effective
	}
	return out, nil
}

// ApplyDefaults sets default values for zero-valued fields.
func (c *Config) ApplyDefaults() {
	// Enabled and RolloutsEnabled are handled via IsEnabled() and
	// IsRolloutsEnabled(); nil means default true. RolloutHooksDir derives
	// from data_dir, so AgentConfig.ApplyDefaults sets it.
	if c.HooksDir == "" {
		c.HooksDir = DefaultHooksDir
	}
	if c.MaxConcurrent == 0 {
		c.MaxConcurrent = DefaultMaxConcurrent
	}
	if c.MaxActionTimeout == 0 {
		c.MaxActionTimeout = DefaultMaxActionTimeout
	}
	if c.MaxOutputBytes == 0 {
		c.MaxOutputBytes = DefaultMaxOutputBytes
	}
}

// Validate checks that configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	if !c.IsEnabled() {
		return nil
	}
	if c.MaxConcurrent < 1 {
		return errors.New("actions: config: MaxConcurrent must be at least 1")
	}
	if c.MaxActionTimeout < 10*time.Second {
		return errors.New("actions: config: MaxActionTimeout must be at least 10s")
	}
	if c.MaxOutputBytes < 1024 {
		return errors.New("actions: config: MaxOutputBytes must be at least 1024")
	}
	return nil
}
