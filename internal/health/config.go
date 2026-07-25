package health

import (
	"errors"
)

// Config holds the configuration for the health listener.
// Config is passed as a constructor argument — no file I/O in this package.
type Config struct {
	// Enabled controls whether the health listener runs.
	// nil means use default (true); explicit false disables the listener.
	//
	// The default is on because the shipped DaemonSet probes /healthz and
	// /readyz unconditionally. An operator has to supply a ConfigMap for the
	// control-plane URL, the node identity and the WireGuard settings anyway,
	// and the health block is the one they have no reason to know about: with a
	// default of off, an omitted block leaves the probe target unbound, the
	// kubelet fails liveness and restarts the container — and that restart runs
	// the drain path, which deletes the WireGuard interface and the
	// deny-by-default chain on every node in the fleet, on a loop.
	Enabled *bool `yaml:"enabled"`

	// Listen is the address the health listener binds to.
	// Default: DefaultListen
	Listen string `yaml:"listen"`
}

// DefaultListen is the default health listen address. It binds loopback on
// purpose: the endpoints are unauthenticated, so the default must not expose
// them on the node's NICs — and, once the mesh is up, to every WireGuard peer.
// Under hostNetwork: true the kubelet probes from the host network namespace,
// which is the same namespace the process listens in, so a probe that sets
// host: 127.0.0.1 reaches a loopback-bound listener; that is the arrangement
// host-networked agents such as kube-proxy use. A wider bind stays available
// as an explicit opt-in through health.listen.
const DefaultListen = "127.0.0.1:9101"

// IsEnabled returns the effective Enabled setting: true unless explicitly set
// to false.
func (c *Config) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// ApplyDefaults sets default values for zero-valued fields.
func (c *Config) ApplyDefaults() {
	// Enabled is handled via IsEnabled(); nil means default true.
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
}

// Validate checks that required fields are set and values are acceptable.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("health: config: Listen is required")
	}
	return nil
}
