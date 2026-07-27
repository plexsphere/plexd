package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// countingHandler counts emitted log records by message so a test can pin log
// cadence — that a settled entry warns exactly once across repeated pulls, for
// instance, rather than once per pull.
type countingHandler struct {
	mu     sync.Mutex
	counts map[string]int
}

func newCountingHandler() *countingHandler {
	return &countingHandler{counts: make(map[string]int)}
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(_ context.Context, rec slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.counts[rec.Message]++
	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *countingHandler) WithGroup(string) slog.Handler { return h }

func (h *countingHandler) count(msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counts[msg]
}

// newTestDispatcher wires a Dispatcher onto a real SessionManager. The manager
// keeps the default logger; only the dispatcher logs into the counting handler,
// so the counts belong to the dispatch decisions alone.
func newTestDispatcher(t *testing.T, cfg Config) (*Dispatcher, *SessionManager, *mockReporter, *countingHandler) {
	t.Helper()
	mgr := newTestManager(t, cfg)
	reporter := &mockReporter{}
	logs := newCountingHandler()
	return NewDispatcher(mgr, reporter, slog.New(logs)), mgr, reporter, logs
}

// sessionsSnapshot builds the pull snapshot the dispatcher consumes. The block
// is populated even with no entries: that is the contract form of "this node has
// no live sessions", distinct from a snapshot whose block is absent.
func sessionsSnapshot(entries ...api.NodeStateSession) *api.NodeStateSnapshot {
	if entries == nil {
		entries = []api.NodeStateSession{}
	}
	return &api.NodeStateSnapshot{Sessions: &entries}
}

// echoSession builds a valid tcp entry pointing at a local echo server.
func echoSession(t *testing.T, sessionID, echoAddr string) api.NodeStateSession {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q) error: %v", portStr, err)
	}
	return tcpSession(sessionID, host, port, time.Now().Add(5*time.Minute))
}

// recordCloses registers an on-closed callback collecting every close.
func recordCloses(mgr *SessionManager) (*sync.Mutex, *[]closedRecord) {
	var (
		mu      sync.Mutex
		records []closedRecord
	)
	mgr.SetOnClosed(func(sessionID, reason string, info *ClosedSessionInfo) {
		mu.Lock()
		defer mu.Unlock()
		records = append(records, closedRecord{sessionID: sessionID, reason: reason, info: info})
	})
	return &mu, &records
}

func TestDispatcher_ProvisionsTCPEntry(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, reporter, _ := newTestDispatcher(t, Config{})

	d.Handle(context.Background(), sessionsSnapshot(echoSession(t, "sess-tcp", echoAddr)))

	if mgr.ActiveCount() != 1 {
		t.Fatalf("expected ActiveCount()=1, got %d", mgr.ActiveCount())
	}

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 1 {
		t.Fatalf("expected 1 started row, got %d", len(reporter.startedCalls))
	}
	got := reporter.startedCalls[0]
	if got.SessionID != "sess-tcp" {
		t.Errorf("started row session_id = %q, want %q", got.SessionID, "sess-tcp")
	}
	// The row's listener_endpoint is the address the listener actually bound.
	if want := sessionListenAddr(t, mgr, "sess-tcp"); got.ListenerEndpoint != want {
		t.Errorf("started row listener_endpoint = %q, want %q", got.ListenerEndpoint, want)
	}
}

func TestDispatcher_ReObservedEntryIsNotReprovisioned(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, reporter, _ := newTestDispatcher(t, Config{})

	entry := echoSession(t, "sess-repeat", echoAddr)
	snapshot := sessionsSnapshot(entry)
	d.Handle(context.Background(), snapshot)
	addr := sessionListenAddr(t, mgr, "sess-repeat")

	// The block keeps serving the entry for the life of the session; that is a
	// re-observation, not a second setup.
	d.Handle(context.Background(), snapshot)
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 1 {
		t.Errorf("expected ActiveCount()=1, got %d", mgr.ActiveCount())
	}
	if got := sessionListenAddr(t, mgr, "sess-repeat"); got != addr {
		t.Errorf("listener address changed from %q to %q", addr, got)
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 1 {
		t.Errorf("expected 1 started row across three pulls, got %d", len(reporter.startedCalls))
	}
}

func TestDispatcher_DrainBeforeExpiryClosesAsDrained(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, _ := newTestDispatcher(t, Config{})
	mu, records := recordCloses(mgr)

	d.Handle(context.Background(), sessionsSnapshot(echoSession(t, "sess-drain", echoAddr)))

	// The entry disappears while the session still has time on it. That may be a
	// revocation or a control plane that failed to serve the entry, so the node
	// records a local close instead of asserting an operator action.
	d.Handle(context.Background(), sessionsSnapshot())

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0 after the drain, got %d", mgr.ActiveCount())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*records) != 1 {
		t.Fatalf("expected 1 close, got %d", len(*records))
	}
	if (*records)[0].reason != reasonDrained {
		t.Errorf("close reason = %q, want %q", (*records)[0].reason, reasonDrained)
	}
	if got := TerminatedByFromReason((*records)[0].reason); got != api.TerminatedByPlexdClose {
		t.Errorf("terminated_by = %q, want %q", got, api.TerminatedByPlexdClose)
	}
}

func TestDispatcher_DrainAtExpiryClosesAsExpired(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, _ := newTestDispatcher(t, Config{})
	mu, records := recordCloses(mgr)

	d.Handle(context.Background(), sessionsSnapshot(echoSession(t, "sess-expire", echoAddr)))

	// Backdate the capped local expiry rather than waiting one out: a real wait
	// races the manager's own expiry timer, which would close the session first
	// and leave the teardown pass nothing to discriminate. The write is under the
	// manager's lock, the same lock ActiveSessions reads the value under.
	mgr.mu.Lock()
	mgr.sessions["sess-expire"].expiresAt = time.Now().Add(-time.Second)
	mgr.mu.Unlock()

	d.Handle(context.Background(), sessionsSnapshot())

	mu.Lock()
	defer mu.Unlock()
	if len(*records) != 1 {
		t.Fatalf("expected 1 close, got %d", len(*records))
	}
	if (*records)[0].reason != reasonExpired {
		t.Errorf("close reason = %q, want %q", (*records)[0].reason, reasonExpired)
	}
	if got := TerminatedByFromReason((*records)[0].reason); got != api.TerminatedByTTLExpired {
		t.Errorf("terminated_by = %q, want %q", got, api.TerminatedByTTLExpired)
	}
}

func TestDispatcher_EmptyBlockTearsDownEverything(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, _ := newTestDispatcher(t, Config{})

	d.Handle(context.Background(), sessionsSnapshot(
		echoSession(t, "sess-a", echoAddr),
		echoSession(t, "sess-b", echoAddr),
	))
	if mgr.ActiveCount() != 2 {
		t.Fatalf("expected ActiveCount()=2, got %d", mgr.ActiveCount())
	}

	d.Handle(context.Background(), sessionsSnapshot())

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0 after the drain, got %d", mgr.ActiveCount())
	}
}

// TestDispatcher_UnpopulatedBlockLeavesSessionsAlone pins the difference between
// "no live sessions" and "no sessions block". A control plane rolled back to a
// build predating the block, or one degraded response that omits or nulls the
// key, decodes to a nil block — reading that as an empty one would kill every
// live operator forward on every node that pulls from it.
func TestDispatcher_UnpopulatedBlockLeavesSessionsAlone(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, logs := newTestDispatcher(t, Config{})
	mu, records := recordCloses(mgr)

	d.Handle(context.Background(), sessionsSnapshot(echoSession(t, "sess-keep", echoAddr)))
	if mgr.ActiveCount() != 1 {
		t.Fatalf("expected ActiveCount()=1, got %d", mgr.ActiveCount())
	}

	d.Handle(context.Background(), &api.NodeStateSnapshot{})

	if mgr.ActiveCount() != 1 {
		t.Errorf("expected the session to survive a snapshot without a sessions block, ActiveCount()=%d", mgr.ActiveCount())
	}
	mu.Lock()
	if len(*records) != 0 {
		t.Errorf("expected no close, got %d", len(*records))
	}
	mu.Unlock()
	if n := logs.count("state snapshot carries no sessions block; leaving live sessions alone"); n != 1 {
		t.Errorf("missing block logged %d times, want 1", n)
	}

	// The entry is still known, so the block coming back is a re-observation
	// rather than a second setup.
	d.Handle(context.Background(), sessionsSnapshot(echoSession(t, "sess-keep", echoAddr)))
	if mgr.ActiveCount() != 1 {
		t.Errorf("expected ActiveCount()=1 once the block is served again, got %d", mgr.ActiveCount())
	}
}

func TestDispatcher_EmptySessionIDDropped(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, reporter, logs := newTestDispatcher(t, Config{})

	entry := echoSession(t, "", echoAddr)
	snapshot := sessionsSnapshot(entry)
	d.Handle(context.Background(), snapshot)
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
	}
	// Unlike every other refusal, a malformed entry has no id to settle under, so
	// it is re-logged for as long as the control plane serves it.
	if n := logs.count("session entry carries no session_id; dropping"); n != 2 {
		t.Errorf("drop logged %d times across two pulls, want 2", n)
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 0 {
		t.Errorf("expected no started row, got %d", len(reporter.startedCalls))
	}
}

func TestDispatcher_ZeroExpiresAtSettled(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, logs := newTestDispatcher(t, Config{})

	entry := echoSession(t, "sess-no-expiry", echoAddr)
	entry.ExpiresAt = time.Time{}
	snapshot := sessionsSnapshot(entry)

	d.Handle(context.Background(), snapshot)
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
	}
	if n := logs.count("session carries no expires_at; refusing to provision"); n != 1 {
		t.Errorf("refusal warned %d times across two pulls, want 1", n)
	}
}

func TestDispatcher_LapsedExpiresAtSettled(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, logs := newTestDispatcher(t, Config{})

	entry := echoSession(t, "sess-lapsed", echoAddr)
	entry.ExpiresAt = time.Now().Add(-time.Minute)
	snapshot := sessionsSnapshot(entry)

	d.Handle(context.Background(), snapshot)
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
	}
	// A lapsed entry is the control plane's to drain, so it is noted once at
	// info and never warned about.
	if n := logs.count("session expired; waiting for the control plane to drain the entry"); n != 1 {
		t.Errorf("lapse logged %d times across two pulls, want 1", n)
	}
	if n := logs.count("session carries no expires_at; refusing to provision"); n != 0 {
		t.Errorf("a lapsed entry must not be reported as missing expires_at, got %d warnings", n)
	}
}

func TestDispatcher_UnsupportedKindsSettled(t *testing.T) {
	d, mgr, reporter, logs := newTestDispatcher(t, Config{})

	expires := time.Now().Add(5 * time.Minute)
	snapshot := sessionsSnapshot(
		api.NodeStateSession{
			SessionID: "sess-ssh",
			Kind:      api.SessionKindSSH,
			Target:    api.SessionTarget{SSH: &api.SessionTargetSSH{User: "ops"}},
			ExpiresAt: expires,
		},
		api.NodeStateSession{
			SessionID: "sess-k8s",
			Kind:      api.SessionKindK8s,
			Target:    api.SessionTarget{K8s: &api.SessionTargetK8s{User: "ops"}},
			ExpiresAt: expires,
		},
	)

	d.Handle(context.Background(), snapshot)
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
	}
	// One warning per entry, not one per entry per pull.
	if n := logs.count("unsupported session kind; no listener provisioned"); n != 2 {
		t.Errorf("unsupported-kind warned %d times, want 2 (once per entry)", n)
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 0 {
		t.Errorf("expected no started row, got %d", len(reporter.startedCalls))
	}
}

func TestDispatcher_TargetMismatchSettled(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.Atoi(portStr)
	expires := time.Now().Add(5 * time.Minute)

	noTarget := tcpSession("sess-no-target", host, port, expires)
	noTarget.Target = api.SessionTarget{}

	twoTargets := tcpSession("sess-two-targets", host, port, expires)
	twoTargets.Target.SSH = &api.SessionTargetSSH{User: "ops"}

	for _, tt := range []struct {
		name  string
		entry api.NodeStateSession
	}{
		{"tcp kind without tcp target", noTarget},
		{"tcp kind with a second target member", twoTargets},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d, mgr, reporter, logs := newTestDispatcher(t, Config{})
			snapshot := sessionsSnapshot(tt.entry)

			d.Handle(context.Background(), snapshot)
			d.Handle(context.Background(), snapshot)

			if mgr.ActiveCount() != 0 {
				t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
			}
			if n := logs.count("session target does not match kind"); n != 1 {
				t.Errorf("mismatch warned %d times across two pulls, want 1", n)
			}
			reporter.mu.Lock()
			defer reporter.mu.Unlock()
			if len(reporter.startedCalls) != 0 {
				t.Errorf("expected no started row, got %d", len(reporter.startedCalls))
			}
		})
	}
}

// TestDispatcher_UnknownKindSettled covers a kind outside the three the contract
// names — a later control plane emitting a fourth one. The target is well formed,
// so the operator is told the kind is unrecognised rather than sent to inspect a
// target that is fine.
func TestDispatcher_UnknownKindSettled(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, reporter, logs := newTestDispatcher(t, Config{})

	entry := echoSession(t, "sess-unknown-kind", echoAddr)
	entry.Kind = "vpn"
	snapshot := sessionsSnapshot(entry)

	d.Handle(context.Background(), snapshot)
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
	}
	if n := logs.count("unrecognised session kind; no listener provisioned"); n != 1 {
		t.Errorf("unrecognised kind warned %d times across two pulls, want 1", n)
	}
	if n := logs.count("session target does not match kind"); n != 0 {
		t.Errorf("an unrecognised kind must not be reported as a target mismatch, got %d warnings", n)
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 0 {
		t.Errorf("expected no started row, got %d", len(reporter.startedCalls))
	}
}

func TestDispatcher_TunnelingDisabledSettledPermanently(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, logs := newTestDispatcher(t, Config{
		Enabled:        false,
		MaxSessions:    10,
		DefaultTimeout: 5 * time.Minute,
	})

	snapshot := sessionsSnapshot(echoSession(t, "sess-disabled", echoAddr))
	d.Handle(context.Background(), snapshot)
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
	}
	// Disabled tunneling is a configuration decision, so it is settled once
	// rather than retried on every pull.
	if n := logs.count("tunneling is disabled; no listener provisioned"); n != 1 {
		t.Errorf("disabled warned %d times across two pulls, want 1", n)
	}
	if n := logs.count("session listener setup failed"); n != 0 {
		t.Errorf("disabled must not be reported as a setup failure, got %d warnings", n)
	}
}

func TestDispatcher_CapacityFailureIsRetried(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, reporter, logs := newTestDispatcher(t, Config{
		Enabled:        true,
		MaxSessions:    1,
		DefaultTimeout: 5 * time.Minute,
	})

	snapshot := sessionsSnapshot(
		echoSession(t, "sess-cap-1", echoAddr),
		echoSession(t, "sess-cap-2", echoAddr),
	)
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 1 {
		t.Fatalf("expected ActiveCount()=1 at capacity, got %d", mgr.ActiveCount())
	}
	if n := logs.count("session listener setup failed"); n != 1 {
		t.Fatalf("capacity failure warned %d times, want 1", n)
	}

	// The rejected entry was left unsettled, so a freed slot lets the next pull
	// provision it.
	mgr.CloseSession("sess-cap-1", reasonDrained)
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 1 {
		t.Errorf("expected ActiveCount()=1 after the retry, got %d", mgr.ActiveCount())
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 2 {
		t.Fatalf("expected 2 started rows, got %d", len(reporter.startedCalls))
	}
	if got := reporter.startedCalls[1].SessionID; got != "sess-cap-2" {
		t.Errorf("second started row session_id = %q, want %q", got, "sess-cap-2")
	}
}

func TestDispatcher_ReissuedIDIsReprovisioned(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, reporter, _ := newTestDispatcher(t, Config{})

	snapshot := sessionsSnapshot(echoSession(t, "sess-reissued", echoAddr))
	d.Handle(context.Background(), snapshot)

	// The drain prunes the id, so the control plane may reuse it for a freshly
	// issued session.
	d.Handle(context.Background(), sessionsSnapshot())
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 1 {
		t.Errorf("expected ActiveCount()=1 after reissue, got %d", mgr.ActiveCount())
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 2 {
		t.Errorf("expected 2 started rows, got %d", len(reporter.startedCalls))
	}
}

func TestDispatcher_LocallyClosedSessionIsNotReprovisioned(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, reporter, _ := newTestDispatcher(t, Config{})

	snapshot := sessionsSnapshot(echoSession(t, "sess-local-close", echoAddr))
	d.Handle(context.Background(), snapshot)

	// An idle or local-expiry close ends the session while its entry lingers in
	// the block. The entry is settled, so it must not come back up.
	mgr.CloseSession("sess-local-close", reasonIdle)
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 1 {
		t.Errorf("expected 1 started row, got %d", len(reporter.startedCalls))
	}
}

func TestDispatcher_IdleTimeoutClosesProvisionedSession(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, _ := newTestDispatcher(t, Config{})
	mu, records := recordCloses(mgr)

	entry := echoSession(t, "sess-idle", echoAddr)
	entry.IdleTimeoutSeconds = 1
	d.Handle(context.Background(), sessionsSnapshot(entry))

	// Nothing ever connects, so the window runs out from the listener bind.
	waitForCondition(t, 4*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(*records) == 1
	})

	mu.Lock()
	defer mu.Unlock()
	if (*records)[0].reason != reasonIdle {
		t.Errorf("close reason = %q, want %q", (*records)[0].reason, reasonIdle)
	}
	if got := TerminatedByFromReason((*records)[0].reason); got != api.TerminatedByIdleTimeout {
		t.Errorf("terminated_by = %q, want %q", got, api.TerminatedByIdleTimeout)
	}
}

// TestDispatcher_TeardownClosesConcurrently verifies the teardown pass closes
// drained sessions concurrently. Each close blocks on a bounded activity report,
// and the pass runs inline on the reconciler's single goroutine ahead of every
// reconcile handler, so closing serially would stall the whole cycle for
// MaxSessions times the per-report bound.
func TestDispatcher_TeardownClosesConcurrently(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, _ := newTestDispatcher(t, Config{})

	const (
		sessionCount = 8
		reportDelay  = 100 * time.Millisecond
	)

	entries := make([]api.NodeStateSession, 0, sessionCount)
	for i := 0; i < sessionCount; i++ {
		entries = append(entries, echoSession(t, "sess-teardown-"+strconv.Itoa(i), echoAddr))
	}
	d.Handle(context.Background(), sessionsSnapshot(entries...))
	if mgr.ActiveCount() != sessionCount {
		t.Fatalf("expected ActiveCount()=%d, got %d", sessionCount, mgr.ActiveCount())
	}

	var closed atomic.Int32
	mgr.SetOnClosed(func(sessionID, reason string, info *ClosedSessionInfo) {
		time.Sleep(reportDelay)
		closed.Add(1)
	})

	start := time.Now()
	d.Handle(context.Background(), sessionsSnapshot())
	elapsed := time.Since(start)

	if n := closed.Load(); int(n) != sessionCount {
		t.Fatalf("on-closed fired %d times, want %d", n, sessionCount)
	}
	// Serial closing takes sessionCount*reportDelay (800ms); concurrent closing
	// takes ~reportDelay. The midpoint (400ms) cleanly separates the two.
	if maxWant := sessionCount * reportDelay / 2; elapsed >= maxWant {
		t.Errorf("teardown took %v for %d sessions; want < %v (closes must run concurrently)", elapsed, sessionCount, maxWant)
	}
}

// TestDispatcher_DrainAndProvisionInOnePullAtCapacity pins the pass ordering:
// teardown runs before provisioning, which is the only thing that lets a node
// sitting at MaxSessions swap one session for another within a single pull.
func TestDispatcher_DrainAndProvisionInOnePullAtCapacity(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, reporter, _ := newTestDispatcher(t, Config{
		Enabled:        true,
		MaxSessions:    1,
		DefaultTimeout: 5 * time.Minute,
	})

	d.Handle(context.Background(), sessionsSnapshot(echoSession(t, "sess-out", echoAddr)))
	if mgr.ActiveCount() != 1 {
		t.Fatalf("expected ActiveCount()=1, got %d", mgr.ActiveCount())
	}

	// One pull drains the old entry and carries a new one: the teardown has to
	// free the only slot before the provision pass needs it.
	d.Handle(context.Background(), sessionsSnapshot(echoSession(t, "sess-in", echoAddr)))

	if mgr.ActiveCount() != 1 {
		t.Fatalf("expected ActiveCount()=1 after the swap, got %d", mgr.ActiveCount())
	}
	if _, ok := mgr.ActiveSessions()["sess-in"]; !ok {
		t.Errorf("ActiveSessions() = %v, want the newly served entry", mgr.ActiveSessions())
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 2 {
		t.Errorf("started rows = %d, want 2", len(reporter.startedCalls))
	}
}

// TestDispatcher_SessionLifetimeFollowsDispatchContext pins that a provisioned
// session is parented on the context Handle was called with, so the reconciler
// must hand it a long-lived one — its Run context, not a per-cycle one.
func TestDispatcher_SessionLifetimeFollowsDispatchContext(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, _ := newTestDispatcher(t, Config{})
	mu, records := recordCloses(mgr)

	ctx, cancel := context.WithCancel(context.Background())
	d.Handle(ctx, sessionsSnapshot(echoSession(t, "sess-ctx", echoAddr)))
	if mgr.ActiveCount() != 1 {
		t.Fatalf("expected ActiveCount()=1, got %d", mgr.ActiveCount())
	}
	listenAddr := sessionListenAddr(t, mgr, "sess-ctx")

	// Cancelling the dispatch context closes the listener, so nothing reaches the
	// target through it any more.
	cancel()
	waitForCondition(t, 2*time.Second, func() bool {
		conn, err := net.DialTimeout("tcp", listenAddr, 200*time.Millisecond)
		if err != nil {
			return true
		}
		conn.Close()
		return false
	})

	// The manager still holds the session — nothing reported it closed — so the
	// listener died without a session_ended row.
	mu.Lock()
	defer mu.Unlock()
	if len(*records) != 0 {
		t.Errorf("expected no on-closed callback from a context cancellation, got %d", len(*records))
	}
}

// TestDispatcher_UndeliveredStartedRowKeepsListener covers the row that carries
// the ephemeral port the operator connects to: if it does not reach the control
// plane, the listener stays bound and the entry stays unsettled, so the next
// pull re-posts the row from the address that is actually bound. Tearing the
// listener down instead would forfeit the port, so a control plane too slow to
// answer within the bound would collect a session_ended row and a fresh, already
// stale listener_endpoint on every pull for the whole TTL of the entry.
func TestDispatcher_UndeliveredStartedRowKeepsListener(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, reporter, logs := newTestDispatcher(t, Config{})
	mu, records := recordCloses(mgr)

	reporter.mu.Lock()
	reporter.startedErr = errors.New("control plane unreachable")
	reporter.mu.Unlock()

	snapshot := sessionsSnapshot(echoSession(t, "sess-unreported", echoAddr))
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 1 {
		t.Fatalf("expected the listener to survive the dropped row, ActiveCount()=%d", mgr.ActiveCount())
	}
	listenAddr := sessionListenAddr(t, mgr, "sess-unreported")
	if n := logs.count("session started report failed; keeping the listener for the next pull to re-post it"); n != 1 {
		t.Errorf("report failure logged %d times, want 1", n)
	}
	mu.Lock()
	if len(*records) != 0 {
		t.Errorf("expected no session_ended row from a dropped started row, got %d", len(*records))
	}
	mu.Unlock()

	// A pull the report fails on again re-posts the row rather than settling the
	// entry, so the outstanding row is retried for as long as the entry stands.
	d.Handle(context.Background(), snapshot)

	// The entry was left unsettled, so the next pull re-posts it — this time with
	// a reporter that delivers.
	reporter.mu.Lock()
	reporter.startedErr = nil
	reporter.mu.Unlock()

	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 1 {
		t.Errorf("expected ActiveCount()=1 after the retry, got %d", mgr.ActiveCount())
	}
	// Once the row lands the entry is settled, so a further pull posts nothing.
	d.Handle(context.Background(), snapshot)

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 3 {
		t.Fatalf("started rows = %d, want 3 (two dropped and the delivered retry)", len(reporter.startedCalls))
	}
	// Every attempt carries the endpoint the one listener holds: the operator is
	// never sent to a port that was rebound between pulls.
	for i, call := range reporter.startedCalls {
		if call.ListenerEndpoint != listenAddr {
			t.Errorf("started row %d listener_endpoint = %q, want %q", i, call.ListenerEndpoint, listenAddr)
		}
	}
}

// barrierReporter holds every started report until the test releases them, and
// counts how many were in flight at once.
type barrierReporter struct {
	release  chan struct{}
	inFlight atomic.Int32
}

func (r *barrierReporter) ReportSessionStarted(context.Context, string, string, int, string) error {
	r.inFlight.Add(1)
	defer r.inFlight.Add(-1)
	<-r.release
	return nil
}

// TestDispatcher_StartedRowsAreReportedConcurrently pins that the provisioning
// pass posts its started rows concurrently. Posting them one after another would
// let a stalled control plane stretch a single pull to MaxSessions times the
// per-report bound, on the reconciler's single goroutine — a control-plane
// slowdown would freeze every other reconcile handler behind it.
func TestDispatcher_StartedRowsAreReportedConcurrently(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})
	reporter := &barrierReporter{release: make(chan struct{})}
	d := NewDispatcher(mgr, reporter, slog.Default())

	const sessionCount = 4
	entries := make([]api.NodeStateSession, 0, sessionCount)
	for i := 0; i < sessionCount; i++ {
		entries = append(entries, echoSession(t, "sess-report-"+strconv.Itoa(i), echoAddr))
	}

	handled := make(chan struct{})
	go func() {
		defer close(handled)
		d.Handle(context.Background(), sessionsSnapshot(entries...))
	}()

	// Nothing releases the reports until all of them have arrived, so a serial
	// pass never gets past the first one.
	waitForCondition(t, 2*time.Second, func() bool { return reporter.inFlight.Load() == sessionCount })
	close(reporter.release)

	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Handle to return")
	}
	if mgr.ActiveCount() != sessionCount {
		t.Errorf("expected ActiveCount()=%d, got %d", sessionCount, mgr.ActiveCount())
	}
}

// deadlineReporter records the time each started report had left on its context,
// or -1 for a context that carried no deadline at all.
type deadlineReporter struct {
	mu        sync.Mutex
	remaining []time.Duration
}

func (r *deadlineReporter) ReportSessionStarted(ctx context.Context, _, _ string, _ int, _ string) error {
	remaining := time.Duration(-1)
	if deadline, ok := ctx.Deadline(); ok {
		remaining = time.Until(deadline)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remaining = append(r.remaining, remaining)
	return nil
}

// TestDispatcher_StartedReportIsBounded pins the explicit bound on a started
// report. The dispatch context is the reconciler's own and carries no deadline,
// so without it a control plane that accepts the connection and then stalls
// holds the reconcile goroutine for the API client's whole request timeout.
//
// The bound also has to clear the API client's own connect timeout, since it
// covers the connect, the handshake, the request and the response. Below that,
// the started row would be the one call a high-latency link fails on while every
// other call to the same control plane succeeds.
func TestDispatcher_StartedReportIsBounded(t *testing.T) {
	if sessionStartedReportTimeout <= api.DefaultConnectTimeout {
		t.Errorf("sessionStartedReportTimeout = %v, want more than the client's connect timeout %v",
			sessionStartedReportTimeout, api.DefaultConnectTimeout)
	}

	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})
	reporter := &deadlineReporter{}
	d := NewDispatcher(mgr, reporter, slog.Default())

	d.Handle(context.Background(), sessionsSnapshot(echoSession(t, "sess-bounded", echoAddr)))

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.remaining) != 1 {
		t.Fatalf("started rows = %d, want 1", len(reporter.remaining))
	}
	if got := reporter.remaining[0]; got <= 0 || got > sessionStartedReportTimeout {
		t.Errorf("started report deadline left %v, want a bound in (0, %v]", got, sessionStartedReportTimeout)
	}
}
