package policy

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

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
	connLog  *ConnLogger

	// mu guards every field below. Sync, ApplyFirewallRules, Teardown and
	// DropCounts hold it across their backend calls, so the record always
	// describes what the backend holds.
	mu sync.Mutex

	// generation counts the applies that got past the engine. It names an
	// apply in the log tags, so a tag from one ruleset never names a rule of
	// another.
	generation uint64

	// installed is the policy the backend holds, nil standing for the
	// default deny alone; hasInstalled tells whether the backend holds a
	// ruleset of plexd's at all. installs counts the applies the backend
	// accepted, so it names the install whose counters the backend keeps: a
	// failed apply leaves the chain, and its counters, as they were.
	installed    *api.PolicySnapshot
	hasInstalled bool
	installs     uint64

	// closed is set by Teardown. A closed Enforcer touches the backend no
	// more, so a pull that the reconciler dispatches while plexd shuts down
	// cannot install the chain Teardown removed.
	closed bool

	// status is what Status returns; changed carries Sync's signal.
	status  Status
	changed chan struct{}

	// failKey names the last failed apply, its fingerprint and reason, so a
	// repeat logs at Debug; it is empty after a successful apply.
	failKey string

	// lastDrops are the drop counts read last, and dropsFailing tells
	// whether the latest reads failed, so the failure is logged once.
	lastDrops    dropCounts
	dropsFailing bool
}

// NewEnforcer creates an Enforcer. The firewall parameter may be nil if no
// firewall backend is available; in that case ApplyFirewallRules is a no-op.
// When the firewall can report the connections its logged rules admit, its
// reports go to the Enforcer's ConnLogger.
func NewEnforcer(engine *PolicyEngine, firewall FirewallController, cfg Config, logger *slog.Logger) *Enforcer {
	cfg.ApplyDefaults()
	e := &Enforcer{
		engine:   engine,
		firewall: firewall,
		cfg:      cfg,
		logger:   logger.With("component", "policy"),
		connLog:  NewConnLogger(logger),
		changed:  make(chan struct{}, 1),
	}
	if reporter, ok := firewall.(ConnReporter); ok {
		reporter.SetConnSink(e.connLog)
	}
	return e
}

// ConnLogger returns the logger that writes a line for each connection a
// logged rule admits. plexd up runs its summary loop and, where no platform
// log source reads plexd's output, forwards its lines.
func (e *Enforcer) ConnLogger() *ConnLogger {
	return e.connLog
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
//
// Every rule with log: true gets the tag "<generation>/<index>", the index
// being the rule's position in the policy's rules. The ConnLogger learns the
// tags before the firewall does, so an event the kernel produces right after
// the apply finds its rule, and forgets them again when the apply fails, so
// repeated failures never push the installed ruleset's tags out of it.
//
// DECISION: the logged rules go ahead of the unlogged ones, each group in the
// order given, and the default deny stays last. Every rule is an allow and
// order carries no verdict, so the move changes nothing that passes or drops.
// It makes every backend's first match a logged rule whenever one allows the
// connection, so a narrow logged rule still logs behind a Project's allow-all
// policy. A connection is named after the first logged rule in revision order
// that allows it. The backends see the reordered list, so a WFP filter's #<i>
// and a pf line's position follow it, while a line's rule stays the revision
// index.
//
// A successful apply records the policy as the one the backend holds, which
// Sync compares the next pull against. It does not count as applying a
// pull's block: the startup baseline, ApplyFirewallRules(nil, iface), leaves
// Status's HasApplied false until Sync adopts a pull.
func (e *Enforcer) ApplyFirewallRules(policy *api.PolicySnapshot, iface string) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false, nil
	}
	return e.applyLocked(policy, iface)
}

// applyLocked is ApplyFirewallRules with e.mu held.
func (e *Enforcer) applyLocked(policy *api.PolicySnapshot, iface string) (bool, error) {
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

	e.generation++
	for i, r := range rules {
		if r.Log {
			fwRules[i].LogTag = fmt.Sprintf("%d/%d", e.generation, i)
		}
	}
	slices.SortStableFunc(fwRules, func(a, b FirewallRule) int {
		return untagged(a) - untagged(b)
	})

	revisionID := ""
	if policy != nil {
		revisionID = policy.RevisionID
	}
	e.connLog.SetRuleset(revisionID, fwRules)

	if err := e.firewall.EnsureChain(e.cfg.ChainName); err != nil {
		e.connLog.Revert()
		return false, fmt.Errorf("policy: enforce: %w", err)
	}
	if err := e.firewall.ApplyRules(e.cfg.ChainName, fwRules); err != nil {
		e.connLog.Revert()
		return false, fmt.Errorf("policy: enforce: %w", err)
	}

	e.installed = policy.Clone()
	e.hasInstalled = true
	e.installs++
	e.logger.Info("applied firewall rules", "count", len(fwRules), "chain", e.cfg.ChainName)
	return true, nil
}

// untagged sorts a rule without a log tag after one with a tag.
func untagged(r FirewallRule) int {
	if r.LogTag == "" {
		return 1
	}
	return 0
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
// the firewall backend is nil. It clears the record of what is installed and
// applied, so Status no longer claims a ruleset the backend dropped, and
// closes the Enforcer: Sync and ApplyFirewallRules touch the backend no more.
//
// DECISION: plexd up tears the chain down before it waits for the
// reconciler, which can still be inside a cycle whose pull it fetched before
// the shutdown. The dispatch handler syncs every pull, so without the close
// that cycle would install the chain again after Teardown removed it.
func (e *Enforcer) Teardown() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	e.installed, e.hasInstalled = nil, false
	e.status.HasApplied, e.status.Applied = false, nil
	e.clearRejectedLocked()
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
