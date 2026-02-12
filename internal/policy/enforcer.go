package policy

import (
	"fmt"
	"log/slog"

	"github.com/plexsphere/plexd/internal/api"
)

// Enforcer combines a PolicyEngine with a FirewallController to enforce
// network policies on the local node.
type Enforcer struct {
	engine   *PolicyEngine
	firewall FirewallController
	cfg      Config
	logger   *slog.Logger
}

// NewEnforcer creates an Enforcer. The firewall parameter may be nil if no
// firewall backend is available; in that case only peer filtering is functional.
func NewEnforcer(engine *PolicyEngine, firewall FirewallController, cfg Config, logger *slog.Logger) *Enforcer {
	cfg.ApplyDefaults()
	return &Enforcer{
		engine:   engine,
		firewall: firewall,
		cfg:      cfg,
		logger:   logger.With("component", "policy"),
	}
}

// FilterPeers returns the peers allowed by the configured policies.
// If policy enforcement is disabled, all peers are returned unchanged.
func (e *Enforcer) FilterPeers(peers []api.Peer, policies []api.Policy, localNodeID string) []api.Peer {
	if !e.cfg.Enabled {
		return peers
	}
	return e.engine.FilterPeers(peers, policies, localNodeID)
}

// ApplyFirewallRules builds firewall rules from the given policies and applies
// them via the FirewallController. It is a no-op when enforcement is disabled
// or no firewall backend is available.
func (e *Enforcer) ApplyFirewallRules(policies []api.Policy, localNodeID string, iface string, peersByID map[string]string) error {
	if !e.cfg.Enabled {
		return nil
	}
	if e.firewall == nil {
		e.logger.Warn("no firewall backend available, skipping rule enforcement")
		return nil
	}

	rules := e.engine.BuildFirewallRules(policies, localNodeID, iface, peersByID)

	if err := e.firewall.EnsureChain(e.cfg.ChainName); err != nil {
		return fmt.Errorf("policy: enforce: %w", err)
	}
	if err := e.firewall.ApplyRules(e.cfg.ChainName, rules); err != nil {
		return fmt.Errorf("policy: enforce: %w", err)
	}

	e.logger.Info("applied firewall rules", "count", len(rules), "chain", e.cfg.ChainName)
	return nil
}

// Teardown removes the firewall chain and its rules. It is safe to call when
// the firewall backend is nil.
func (e *Enforcer) Teardown() error {
	if e.firewall == nil {
		return nil
	}
	if err := e.firewall.FlushChain(e.cfg.ChainName); err != nil {
		return fmt.Errorf("policy: teardown: %w", err)
	}
	if err := e.firewall.DeleteChain(e.cfg.ChainName); err != nil {
		return fmt.Errorf("policy: teardown: %w", err)
	}
	return nil
}
