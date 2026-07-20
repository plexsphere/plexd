package policy

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Integration test infrastructure
// ---------------------------------------------------------------------------

// countingFirewall is a thread-safe FirewallController recording apply counts
// for integration assertions.
type countingFirewall struct {
	mu          sync.Mutex
	ensureCalls int
	applyCalls  int
	lastRules   []FirewallRule
}

func (c *countingFirewall) EnsureChain(string) error {
	c.mu.Lock()
	c.ensureCalls++
	c.mu.Unlock()
	return nil
}

func (c *countingFirewall) ApplyRules(_ string, rules []FirewallRule) error {
	c.mu.Lock()
	c.applyCalls++
	c.lastRules = rules
	c.mu.Unlock()
	return nil
}

func (c *countingFirewall) FlushChain(string) error  { return nil }
func (c *countingFirewall) DeleteChain(string) error { return nil }

func (c *countingFirewall) applyCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applyCalls
}

// integrationStateFetcher implements reconcile.StateFetcher for integration tests.
type integrationStateFetcher struct {
	mu         sync.Mutex
	state      *api.NodeStateSnapshot
	fetchCount int
}

func (f *integrationStateFetcher) FetchState(_ context.Context, _ string) (*api.NodeStateSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetchCount++
	return f.state, nil
}

func (f *integrationStateFetcher) setState(state *api.NodeStateSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = state
}

func (f *integrationStateFetcher) getFetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetchCount
}

func snapshotWithPolicy(fingerprint string, rules ...api.PolicyRule) *api.NodeStateSnapshot {
	return &api.NodeStateSnapshot{
		Policy: &api.PolicySnapshot{RevisionID: "rev-1", Fingerprint: fingerprint, Rules: rules},
	}
}

func enabledEnforcer(fw FirewallController) *Enforcer {
	return NewEnforcer(NewPolicyEngine(testLogger()), fw, Config{Enabled: true, ChainName: "TEST"}, testLogger())
}

// waitForCondition polls until cond returns true or timeout expires.
func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out after %v waiting for condition", timeout)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestIntegration_PolicyEnforcementFlow wires a real PolicyEngine, a counting
// FirewallController, and a real Reconciler. A populated policy arriving on the
// first cycle results in a firewall apply.
func TestIntegration_PolicyEnforcementFlow(t *testing.T) {
	fw := &countingFirewall{}
	enforcer := enabledEnforcer(fw)

	state := snapshotWithPolicy("fp-1",
		api.PolicyRule{Action: "allow", Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
	)
	fetcher := &integrationStateFetcher{state: state}

	reconciler := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, testLogger())
	reconciler.RegisterHandler(ReconcileHandler(enforcer, "wg0"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx, "node-a") }()

	waitForCondition(t, 2*time.Second, func() bool { return fw.applyCount() >= 1 })

	cancel()
	<-done

	if got := fw.applyCount(); got != 1 {
		t.Errorf("apply count = %d, want 1", got)
	}
	// 1 policy rule + trailing default-deny.
	if got := len(fw.lastRules); got != 2 {
		t.Errorf("applied rules = %d, want 2", got)
	}
}

// TestIntegration_FingerprintShortCircuit verifies that an equal fingerprint —
// even with a different rule set — does not re-apply the ruleset, while a
// changed fingerprint does.
func TestIntegration_FingerprintShortCircuit(t *testing.T) {
	fw := &countingFirewall{}
	enforcer := enabledEnforcer(fw)

	fetcher := &integrationStateFetcher{state: snapshotWithPolicy("fp-1",
		api.PolicyRule{Action: "allow", Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
	)}

	reconciler := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, testLogger())
	reconciler.RegisterHandler(ReconcileHandler(enforcer, "wg0"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx, "node-a") }()

	waitForCondition(t, 2*time.Second, func() bool { return fw.applyCount() >= 1 })

	// Same fingerprint, different rules — must NOT re-apply.
	fetcher.setState(snapshotWithPolicy("fp-1",
		api.PolicyRule{Action: "deny", Protocol: "any", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "0.0.0.0/0"},
	))
	before := fetcher.getFetchCount()
	reconciler.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool { return fetcher.getFetchCount() > before })

	if got := fw.applyCount(); got != 1 {
		t.Errorf("apply count = %d after equal-fingerprint cycle, want 1 (short-circuit)", got)
	}

	// New fingerprint — must re-apply.
	fetcher.setState(snapshotWithPolicy("fp-2",
		api.PolicyRule{Action: "deny", Protocol: "any", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "0.0.0.0/0"},
	))
	reconciler.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool { return fw.applyCount() >= 2 })

	cancel()
	<-done

	if got := fw.applyCount(); got != 2 {
		t.Errorf("apply count = %d after fingerprint change, want 2", got)
	}
}

// TestIntegration_SSEPolicyUpdatedTriggersReconcile verifies that dispatching a
// policy_updated SSE event through a real EventDispatcher triggers a new cycle.
func TestIntegration_SSEPolicyUpdatedTriggersReconcile(t *testing.T) {
	fw := &countingFirewall{}
	enforcer := enabledEnforcer(fw)

	fetcher := &integrationStateFetcher{state: snapshotWithPolicy("fp-1",
		api.PolicyRule{Action: "allow", Protocol: "any", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.0/24"},
	)}

	reconciler := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, testLogger())
	reconciler.RegisterHandler(ReconcileHandler(enforcer, "wg0"))

	dispatcher := api.NewEventDispatcher(testLogger())
	dispatcher.Register(api.EventPolicyUpdated, HandlePolicyUpdated(reconciler))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx, "node-a") }()

	waitForCondition(t, 2*time.Second, func() bool { return fetcher.getFetchCount() >= 1 })
	initialFetch := fetcher.getFetchCount()

	payload, _ := json.Marshal(map[string]string{"policy_id": "pol-1"})
	envelope := api.SignedEnvelope{
		EventType: api.EventPolicyUpdated,
		EventID:   "evt-sse-1",
		Payload:   payload,
	}
	dispatcher.Dispatch(ctx, envelope)

	waitForCondition(t, 2*time.Second, func() bool { return fetcher.getFetchCount() > initialFetch })

	cancel()
	<-done

	if n := fetcher.getFetchCount(); n <= initialFetch {
		t.Errorf("FetchState calls = %d, want > %d (SSE should trigger reconcile)", n, initialFetch)
	}
}

// TestIntegration_ConcurrentPolicyChangesNoRace exercises concurrent SSE
// dispatch while the reconcile loop alternates policy fingerprints. Run with -race.
func TestIntegration_ConcurrentPolicyChangesNoRace(t *testing.T) {
	fw := &countingFirewall{}
	enforcer := enabledEnforcer(fw)

	var cycle atomic.Int32
	fetcher := &alternatingStateFetcher{
		states: []*api.NodeStateSnapshot{
			snapshotWithPolicy("fp-a", api.PolicyRule{Action: "allow", Protocol: "any", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.0/24"}),
			snapshotWithPolicy("fp-b", api.PolicyRule{Action: "deny", Protocol: "any", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "0.0.0.0/0"}),
		},
		cycle: &cycle,
	}

	reconciler := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: 30 * time.Millisecond}, testLogger())
	reconciler.RegisterHandler(ReconcileHandler(enforcer, "wg0"))

	dispatcher := api.NewEventDispatcher(testLogger())
	dispatcher.Register(api.EventPolicyUpdated, HandlePolicyUpdated(reconciler))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx, "node-a") }()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload, _ := json.Marshal(map[string]string{"policy_id": "pol-x"})
			envelope := api.SignedEnvelope{
				EventType: api.EventPolicyUpdated,
				EventID:   "concurrent-evt",
				Payload:   payload,
			}
			dispatcher.Dispatch(ctx, envelope)
		}()
	}

	time.Sleep(300 * time.Millisecond)

	wg.Wait()
	cancel()
	<-done

	if n := fetcher.getFetchCount(); n < 2 {
		t.Errorf("FetchState calls = %d, want >= 2", n)
	}
}

// alternatingStateFetcher returns different snapshots on each fetch.
type alternatingStateFetcher struct {
	mu         sync.Mutex
	states     []*api.NodeStateSnapshot
	cycle      *atomic.Int32
	fetchCount int
}

func (f *alternatingStateFetcher) FetchState(_ context.Context, _ string) (*api.NodeStateSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetchCount++
	idx := int(f.cycle.Add(1)-1) % len(f.states)
	return f.states[idx], nil
}

func (f *alternatingStateFetcher) getFetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetchCount
}
