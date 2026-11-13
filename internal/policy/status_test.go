package policy

import (
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unicode/utf8"

	"github.com/plexsphere/plexd/internal/api"
)

// dropCountingFirewall is a mockFirewallController that also counts drops.
type dropCountingFirewall struct {
	mockFirewallController

	dropCalls      []string
	packets, bytes uint64
	dropErr        error
}

var _ DropCounter = (*dropCountingFirewall)(nil)

func (f *dropCountingFirewall) DropCounts(chain string) (uint64, uint64, error) {
	f.dropCalls = append(f.dropCalls, chain)
	if f.dropErr != nil {
		return 0, 0, f.dropErr
	}
	return f.packets, f.bytes, nil
}

// statusBlock is a policy block with one allowed rule, its fingerprint and
// one revision pair.
func statusBlock(fingerprint, revisionID string) *api.PolicySnapshot {
	return &api.PolicySnapshot{
		RevisionID:  revisionID,
		Fingerprint: fingerprint,
		Rules:       []api.PolicyRule{{Protocol: "any", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.0/24"}},
		Revisions:   []api.PolicyRevisionRef{{PolicyID: "pol-1", RevisionID: revisionID}},
	}
}

// deniedBlock is a policy block the engine refuses: its rule carries a deny.
func deniedBlock(fingerprint string) *api.PolicySnapshot {
	return &api.PolicySnapshot{
		RevisionID:  "rev-deny",
		Fingerprint: fingerprint,
		Rules:       []api.PolicyRule{{LegacyAction: legacyAction("deny"), Protocol: "any", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.5/32"}},
		Revisions:   []api.PolicyRevisionRef{{PolicyID: "pol-1", RevisionID: "rev-deny"}},
	}
}

// recordingLogger returns a Debug logger writing into a buffer the test reads.
func recordingLogger() (*slog.Logger, *syncBuffer) {
	logs := &syncBuffer{}
	return slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})), logs
}

func TestEnforcer_Sync(t *testing.T) {
	t.Run("disabled enforcement touches nothing", func(t *testing.T) {
		fw := &mockFirewallController{}
		e := NewEnforcer(NewPolicyEngine(testLogger()), fw, Config{Enabled: boolPtr(false), ChainName: "TEST"}, testLogger())

		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")

		st := e.Status()
		if st.Enforcement != api.PolicyEnforcementDisabled || st.HasApplied || st.Applied != nil {
			t.Errorf("Status() = %+v, want disabled with nothing applied", st)
		}
		if st.Received == nil || st.Received.Fingerprint != "fp-a" {
			t.Errorf("Received = %+v, want fp-a", st.Received)
		}
		if len(fw.ensureChainCalls)+len(fw.applyRulesCalls) != 0 {
			t.Errorf("backend calls: ensure=%d apply=%d, want none", len(fw.ensureChainCalls), len(fw.applyRulesCalls))
		}
	})

	t.Run("no backend is unavailable", func(t *testing.T) {
		e := newEnabledEnforcer(nil)

		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")

		if st := e.Status(); st.Enforcement != api.PolicyEnforcementUnavailable || st.HasApplied {
			t.Errorf("Status() = %+v, want unavailable with nothing applied", st)
		}
	})

	t.Run("a block applies once per fingerprint", func(t *testing.T) {
		fw := &mockFirewallController{}
		e := newEnabledEnforcer(fw)

		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		st := e.Status()
		if st.Enforcement != api.PolicyEnforcementEnforcing || !st.HasApplied || st.Applied == nil || st.Applied.Fingerprint != "fp-a" {
			t.Fatalf("Status() = %+v, want fp-a applied while enforcing", st)
		}
		if len(fw.applyRulesCalls) != 1 {
			t.Fatalf("ApplyRules calls = %d, want 1", len(fw.applyRulesCalls))
		}

		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		if len(fw.applyRulesCalls) != 1 {
			t.Errorf("ApplyRules calls = %d after a pull of the same fingerprint, want 1", len(fw.applyRulesCalls))
		}
	})

	t.Run("other revisions under the same fingerprint are adopted", func(t *testing.T) {
		fw := &mockFirewallController{}
		e := newEnabledEnforcer(fw)
		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")

		e.Sync(statusBlock("fp-a", "rev-b"), "wg0")

		if len(fw.applyRulesCalls) != 1 {
			t.Errorf("ApplyRules calls = %d, want 1", len(fw.applyRulesCalls))
		}
		want := []api.PolicyRevisionRef{{PolicyID: "pol-1", RevisionID: "rev-b"}}
		if st := e.Status(); st.Applied == nil || !slices.Equal(st.Applied.Revisions, want) {
			t.Errorf("Applied = %+v, want revisions %+v", st.Applied, want)
		}
	})

	t.Run("a null pull over the baseline is applied without a kernel call", func(t *testing.T) {
		fw := &mockFirewallController{}
		e := newEnabledEnforcer(fw)
		if _, err := e.ApplyFirewallRules(nil, "wg0"); err != nil {
			t.Fatalf("baseline: %v", err)
		}
		if e.Status().HasApplied {
			t.Fatalf("the baseline alone counts as an applied pull")
		}

		e.Sync(nil, "wg0")

		if len(fw.applyRulesCalls) != 1 {
			t.Errorf("ApplyRules calls = %d, want only the baseline's", len(fw.applyRulesCalls))
		}
		if st := e.Status(); !st.HasApplied || st.Applied != nil {
			t.Errorf("Status() = %+v, want HasApplied with a nil Applied", st)
		}
	})

	t.Run("a null pull with nothing installed changes nothing", func(t *testing.T) {
		fw := &mockFirewallController{}
		e := newEnabledEnforcer(fw)

		e.Sync(nil, "wg0")

		if len(fw.applyRulesCalls) != 0 {
			t.Errorf("ApplyRules calls = %d, want 0", len(fw.applyRulesCalls))
		}
		if st := e.Status(); st.HasApplied {
			t.Errorf("Status() = %+v, want nothing applied", st)
		}
	})

	t.Run("a null pull after a block applies the default deny alone", func(t *testing.T) {
		fw := &mockFirewallController{}
		e := newEnabledEnforcer(fw)
		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")

		e.Sync(nil, "wg0")

		if len(fw.applyRulesCalls) != 2 {
			t.Fatalf("ApplyRules calls = %d, want 2", len(fw.applyRulesCalls))
		}
		if rules := fw.applyRulesCalls[1].Rules; len(rules) != 1 || rules[0].Action != "deny" {
			t.Errorf("rules = %+v, want the default deny alone", rules)
		}
	})

	t.Run("a refused block keeps the previous one and counts attempts", func(t *testing.T) {
		fw := &mockFirewallController{}
		e := newEnabledEnforcer(fw)
		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")

		for attempt := 1; attempt <= 3; attempt++ {
			e.Sync(deniedBlock("fp-deny"), "wg0")
			st := e.Status()
			if st.Attempts != attempt {
				t.Errorf("Attempts = %d after %d pulls, want %d", st.Attempts, attempt, attempt)
			}
			if st.Applied == nil || st.Applied.Fingerprint != "fp-a" {
				t.Errorf("Applied = %+v, want fp-a kept", st.Applied)
			}
			if st.Rejected == nil || st.Rejected.Fingerprint != "fp-deny" {
				t.Errorf("Rejected = %+v, want fp-deny", st.Rejected)
			}
			if !strings.Contains(st.Reason, `unsupported action "deny"`) {
				t.Errorf("Reason = %q, want it to name the unsupported action", st.Reason)
			}
		}
		if len(fw.applyRulesCalls) != 1 {
			t.Errorf("ApplyRules calls = %d, want 1", len(fw.applyRulesCalls))
		}
	})

	t.Run("a backend failure is rejected until an apply succeeds", func(t *testing.T) {
		fw := &mockFirewallController{}
		e := newEnabledEnforcer(fw)
		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")

		fw.applyRulesErr = syscall.ENOBUFS
		e.Sync(statusBlock("fp-b", "rev-b"), "wg0")
		st := e.Status()
		if st.Rejected == nil || st.Rejected.Fingerprint != "fp-b" {
			t.Fatalf("Rejected = %+v, want fp-b", st.Rejected)
		}
		if !strings.Contains(st.Reason, syscall.ENOBUFS.Error()) {
			t.Errorf("Reason = %q, want it to contain %q", st.Reason, syscall.ENOBUFS.Error())
		}
		if st.Applied == nil || st.Applied.Fingerprint != "fp-a" {
			t.Errorf("Applied = %+v, want fp-a kept", st.Applied)
		}

		fw.applyRulesErr = nil
		e.Sync(statusBlock("fp-b", "rev-b"), "wg0")
		st = e.Status()
		if st.Rejected != nil || st.Reason != "" || st.Attempts != 0 {
			t.Errorf("Status() = %+v, want the rejection cleared", st)
		}
		if st.Applied == nil || st.Applied.Fingerprint != "fp-b" {
			t.Errorf("Applied = %+v, want fp-b", st.Applied)
		}
	})

	t.Run("a failure without a fingerprint rejects nothing", func(t *testing.T) {
		fw := &mockFirewallController{}
		e := newEnabledEnforcer(fw)
		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		fw.applyRulesErr = errors.New("netlink: boom")

		e.Sync(nil, "wg0")
		if st := e.Status(); st.Rejected != nil {
			t.Errorf("Rejected = %+v after a failed null pull, want nil", st.Rejected)
		}

		e.Sync(statusBlock("", "rev-c"), "wg0")
		if st := e.Status(); st.Rejected != nil {
			t.Errorf("Rejected = %+v after a failed block without a fingerprint, want nil", st.Rejected)
		}
	})

	t.Run("a block without a fingerprint applies on every pull", func(t *testing.T) {
		fw := &mockFirewallController{}
		e := newEnabledEnforcer(fw)

		for i := 0; i < 3; i++ {
			e.Sync(statusBlock("", "rev-a"), "wg0")
		}
		if len(fw.applyRulesCalls) != 3 {
			t.Errorf("ApplyRules calls = %d, want 3", len(fw.applyRulesCalls))
		}
	})
}

// The first failure of a fingerprint and reason logs at Error under the
// message plexd always logged; the retries of the same failure log at Debug.
func TestEnforcer_SyncLogsAFailureOnce(t *testing.T) {
	logger, logs := recordingLogger()
	fw := &mockFirewallController{}
	e := NewEnforcer(NewPolicyEngine(logger), fw, Config{Enabled: boolPtr(true), ChainName: "TEST"}, logger)

	for i := 0; i < 3; i++ {
		e.Sync(deniedBlock("fp-deny"), "wg0")
	}
	if got := logs.count(`level=ERROR msg="policy revision rejected, keeping previous ruleset"`); got != 1 {
		t.Errorf("Error lines = %d, want 1", got)
	}
	if got := logs.count(`level=DEBUG msg="policy revision still rejected"`); got != 2 {
		t.Errorf("Debug lines = %d, want 2", got)
	}

	fw.applyRulesErr = errors.New("netlink: boom")
	e.Sync(statusBlock("fp-b", "rev-b"), "wg0")
	if got := logs.count(`level=ERROR msg="reconcile: apply firewall rules failed"`); got != 1 {
		t.Errorf("backend failure Error lines = %d, want 1", got)
	}
}

func TestEnforcer_Changed(t *testing.T) {
	fw := &mockFirewallController{}
	e := newEnabledEnforcer(fw)

	signalled := func() bool {
		select {
		case <-e.Changed():
			return true
		default:
			return false
		}
	}

	if signalled() {
		t.Fatal("Changed() signalled before the first Sync")
	}
	e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
	if !signalled() {
		t.Error("no signal after the first Sync")
	}
	e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
	if signalled() {
		t.Error("signal after a Sync that changed nothing")
	}
	e.Sync(statusBlock("fp-b", "rev-b"), "wg0")
	if !signalled() {
		t.Error("no signal after the applied fingerprint changed")
	}
	e.Sync(statusBlock("fp-b", "rev-c"), "wg0")
	if !signalled() {
		t.Error("no signal after the applied revisions changed")
	}
	e.Sync(deniedBlock("fp-deny"), "wg0")
	if !signalled() {
		t.Error("no signal after a block was rejected")
	}
	e.Sync(deniedBlock("fp-deny"), "wg0")
	if signalled() {
		t.Error("signal after a Sync that changed only Attempts")
	}
	fw.applyRulesErr = errors.New("netlink: boom")
	e.Sync(statusBlock("fp-c", "rev-c"), "wg0")
	if !signalled() {
		t.Error("no signal after the rejected block changed")
	}
	fw.applyRulesErr = errors.New("netlink: bang")
	e.Sync(statusBlock("fp-c", "rev-c"), "wg0")
	if !signalled() {
		t.Error("no signal after the rejection's reason changed")
	}
}

func TestRejectionReason(t *testing.T) {
	// One byte ahead of 1000 two-byte runes puts byte 1024 inside a rune, so
	// a cut at 1024 bytes splits it.
	long := "x" + strings.Repeat("ä", 1000)

	tests := []struct {
		name string
		err  error
		want string
	}{
		{"plain", errors.New("policy: rule 0: unsupported action"), "policy: rule 0: unsupported action"},
		{"newline and DEL become spaces", errors.New("a\nb\x7fc"), "a b c"},
		{"invalid UTF-8 becomes U+FFFD", errors.New("bad \xff byte"), "bad � byte"},
		{"empty", errors.New(""), "apply failed"},
		{"only control characters", errors.New("\x00\x01\n\t"), "apply failed"},
		{"nil", nil, "apply failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rejectionReason(tt.err); got != tt.want {
				t.Errorf("rejectionReason() = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("cut on a rune boundary", func(t *testing.T) {
		got := rejectionReason(errors.New(long))
		if len(got) > maxRejectionReasonBytes {
			t.Errorf("len = %d, want at most %d", len(got), maxRejectionReasonBytes)
		}
		if !utf8.ValidString(got) {
			t.Errorf("result is not valid UTF-8")
		}
		if got != long[:1023] {
			t.Errorf("result = %d bytes, want the 1023 bytes before the split rune", len(got))
		}
	})
}

func TestEnforcer_DropCounts(t *testing.T) {
	t.Run("a backend without DropCounter counts nothing", func(t *testing.T) {
		e := newEnabledEnforcer(&mockFirewallController{})
		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		if _, _, ok := e.DropCounts(); ok {
			t.Error("DropCounts() ok = true, want false")
		}
	})

	t.Run("disabled enforcement counts nothing", func(t *testing.T) {
		fw := &dropCountingFirewall{packets: 1, bytes: 40}
		e := NewEnforcer(NewPolicyEngine(testLogger()), fw, Config{Enabled: boolPtr(false), ChainName: "TEST"}, testLogger())
		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		if _, _, ok := e.DropCounts(); ok {
			t.Error("DropCounts() ok = true, want false")
		}
	})

	t.Run("nothing installed counts nothing", func(t *testing.T) {
		fw := &dropCountingFirewall{packets: 1, bytes: 40}
		e := newEnabledEnforcer(fw)
		if _, _, ok := e.DropCounts(); ok {
			t.Error("DropCounts() ok = true, want false")
		}
		if len(fw.dropCalls) != 0 {
			t.Errorf("backend reads = %d, want 0", len(fw.dropCalls))
		}
	})

	t.Run("reads the configured chain", func(t *testing.T) {
		fw := &dropCountingFirewall{packets: 3, bytes: 120}
		e := newEnabledEnforcer(fw)
		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")

		packets, bytes, ok := e.DropCounts()
		if !ok || packets != 3 || bytes != 120 {
			t.Errorf("DropCounts() = %d, %d, %v, want 3, 120, true", packets, bytes, ok)
		}
		if !slices.Equal(fw.dropCalls, []string{"TEST"}) {
			t.Errorf("backend reads = %v, want [TEST]", fw.dropCalls)
		}
	})

	t.Run("a failed read returns the counts of the same install", func(t *testing.T) {
		logger, logs := recordingLogger()
		fw := &dropCountingFirewall{packets: 3, bytes: 120}
		e := NewEnforcer(NewPolicyEngine(logger), fw, Config{Enabled: boolPtr(true), ChainName: "TEST"}, logger)
		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		e.DropCounts()

		fw.dropErr = errors.New("netlink: dump interrupted")
		for i := 0; i < 3; i++ {
			packets, bytes, ok := e.DropCounts()
			if !ok || packets != 3 || bytes != 120 {
				t.Errorf("DropCounts() = %d, %d, %v, want the remembered 3, 120, true", packets, bytes, ok)
			}
		}
		if got := logs.count(`level=WARN msg="policy drop counters unavailable"`); got != 1 {
			t.Errorf("Warn lines = %d for three failures in a row, want 1", got)
		}

		fw.dropErr = nil
		e.DropCounts()
		fw.dropErr = errors.New("netlink: dump interrupted")
		e.DropCounts()
		if got := logs.count(`level=WARN msg="policy drop counters unavailable"`); got != 2 {
			t.Errorf("Warn lines = %d after a new run of failures, want 2", got)
		}
	})

	t.Run("a failed read without earlier counts counts nothing", func(t *testing.T) {
		fw := &dropCountingFirewall{dropErr: errors.New("netlink: boom")}
		e := newEnabledEnforcer(fw)
		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		if _, _, ok := e.DropCounts(); ok {
			t.Error("DropCounts() ok = true, want false")
		}
	})

	t.Run("a failed apply keeps the counts of the install still in place", func(t *testing.T) {
		fw := &dropCountingFirewall{packets: 3, bytes: 120}
		e := newEnabledEnforcer(fw)
		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		e.DropCounts()

		// The backend refuses fp-b and keeps fp-a's chain and counters.
		fw.applyRulesErr = errors.New("netlink: no buffer space available")
		e.Sync(statusBlock("fp-b", "rev-b"), "wg0")
		fw.dropErr = errors.New("netlink: boom")

		packets, bytes, ok := e.DropCounts()
		if !ok || packets != 3 || bytes != 120 {
			t.Errorf("DropCounts() = %d, %d, %v after a failed apply, want fp-a's remembered 3, 120, true", packets, bytes, ok)
		}
	})

	t.Run("a new install forgets the remembered counts", func(t *testing.T) {
		fw := &dropCountingFirewall{packets: 3, bytes: 120}
		e := newEnabledEnforcer(fw)
		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		e.DropCounts()

		e.Sync(statusBlock("fp-b", "rev-b"), "wg0")
		fw.dropErr = errors.New("netlink: boom")
		if _, _, ok := e.DropCounts(); ok {
			t.Error("DropCounts() ok = true with counts of the previous install, want false")
		}
	})
}

// plexd up tears the chain down before the reconciler has finished, so a
// pull it dispatched before the shutdown can reach Sync after Teardown. A
// closed Enforcer must not install the chain again.
func TestEnforcer_TeardownCloses(t *testing.T) {
	fw := &mockFirewallController{}
	e := newEnabledEnforcer(fw)
	e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
	<-e.Changed()

	if err := e.Teardown(); err != nil {
		t.Fatalf("Teardown() error = %v", err)
	}
	e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
	e.Sync(statusBlock("fp-b", "rev-b"), "wg0")
	if applied, err := e.ApplyFirewallRules(nil, "wg0"); applied || err != nil {
		t.Errorf("ApplyFirewallRules() after Teardown = %v, %v, want false, nil", applied, err)
	}

	if len(fw.ensureChainCalls) != 1 || len(fw.applyRulesCalls) != 1 {
		t.Errorf("backend calls after Teardown: ensure=%d apply=%d, want only the one before it",
			len(fw.ensureChainCalls), len(fw.applyRulesCalls))
	}
	if len(fw.deleteChainCalls) != 1 {
		t.Errorf("DeleteChain calls = %d, want 1", len(fw.deleteChainCalls))
	}
	if st := e.Status(); st.HasApplied || st.Applied != nil {
		t.Errorf("Status() = %+v after Teardown, want nothing applied", st)
	}
	select {
	case <-e.Changed():
		t.Error("Changed() signalled for a Sync after Teardown")
	default:
	}
}

// Sync, Status and DropCounts run on the reconcile goroutine, the node API's
// and the reporter's. Run with -race.
func TestEnforcer_StatusConcurrent(t *testing.T) {
	fw := &dropCountingFirewall{packets: 1, bytes: 40}
	e := newEnabledEnforcer(fw)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			fp := "fp-a"
			if i%2 == 1 {
				fp = "fp-b"
			}
			e.Sync(statusBlock(fp, "rev"), "wg0")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			st := e.Status()
			if st.Applied != nil {
				st.Applied.Revisions = nil // a copy: must not reach the Enforcer
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			e.DropCounts()
		}
	}()
	wg.Wait()

	if st := e.Status(); st.Applied == nil || len(st.Applied.Revisions) != 1 {
		t.Errorf("Applied = %+v, want the last block with its revision", st.Applied)
	}
}
