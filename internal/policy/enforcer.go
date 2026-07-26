package policy

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/plexsphere/plexd/internal/api"
)

// ErrInvalidRuleset marks a policy revision the engine cannot translate into
// firewall rules. It is a permanent property of the revision's rules, not a
// transient backend failure: retrying the identical revision can never succeed,
// so callers must not hold state back waiting for it to clear.
var ErrInvalidRuleset = errors.New("policy: invalid ruleset")

// Enforcer combines a PolicyEngine with a FirewallController to enforce
// network policies on the local node.
type Enforcer struct {
	engine   *PolicyEngine
	firewall FirewallController
	cfg      Config
	logger   *slog.Logger
}

// NewEnforcer creates an Enforcer. The firewall parameter may be nil if no
// firewall backend is available; in that case ApplyFirewallRules is a no-op.
func NewEnforcer(engine *PolicyEngine, firewall FirewallController, cfg Config, logger *slog.Logger) *Enforcer {
	cfg.ApplyDefaults()
	return &Enforcer{
		engine:   engine,
		firewall: firewall,
		cfg:      cfg,
		logger:   logger.With("component", "policy"),
	}
}

// ApplyFirewallRules builds firewall rules from the merged policy and applies
// them via the FirewallController. A nil policy yields a default-deny-only
// ruleset — deny-by-default is plexd's documented posture.
//
// The bool reports whether the ruleset actually reached the kernel. Enforcement
// being disabled and the absence of a firewall backend are no-ops that return
// (false, nil), so callers cannot mistake either for a successful apply and
// claim an enforcement that never happened.
//
// A ruleset the engine refuses to translate is reported as ErrInvalidRuleset so
// callers can tell a permanently broken revision from a transient netlink
// failure.
func (e *Enforcer) ApplyFirewallRules(policy *api.PolicySnapshot, iface string) (bool, error) {
	if !e.cfg.IsEnabled() {
		return false, nil
	}
	if e.firewall == nil {
		e.logger.Warn("no firewall backend available, skipping rule enforcement")
		return false, nil
	}

	var rules []api.PolicyRule
	if policy != nil {
		rules = policy.Rules
	}
	fwRules, err := e.engine.BuildFirewallRules(rules, iface)
	if err != nil {
		return false, fmt.Errorf("policy: enforce: %w: %w", ErrInvalidRuleset, err)
	}

	if err := e.firewall.EnsureChain(e.cfg.ChainName); err != nil {
		return false, fmt.Errorf("policy: enforce: %w", err)
	}
	if err := e.firewall.ApplyRules(e.cfg.ChainName, fwRules); err != nil {
		return false, fmt.Errorf("policy: enforce: %w", err)
	}

	e.logger.Info("applied firewall rules", "count", len(fwRules), "chain", e.cfg.ChainName)
	return true, nil
}

// Preflight reports whether this node can enforce policy at all, without
// changing any kernel state. It answers the question the first
// ApplyFirewallRules would otherwise answer — but that call happens after
// registration has spent a one-shot bootstrap token, so a node that can never
// install a chain has to learn it here instead.
//
// The two no-op paths of ApplyFirewallRules are no-ops here as well: with
// enforcement disabled or no firewall backend compiled in, there is no
// enforcement to be unable to perform. A backend that fails the probe is an
// error — that node was told to enforce and cannot.
func (e *Enforcer) Preflight() error {
	if !e.cfg.IsEnabled() {
		return nil
	}
	if e.firewall == nil {
		return nil
	}
	if err := e.firewall.Probe(); err != nil {
		return fmt.Errorf("policy: preflight: %w", err)
	}
	e.logger.Debug("firewall backend available", "chain", e.cfg.ChainName)
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
