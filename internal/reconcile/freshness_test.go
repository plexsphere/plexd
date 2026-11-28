package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

const (
	limitSet       = "state freshness limit set"
	limitRemoved   = "state freshness limit removed"
	limitMalformed = "state freshness block malformed"
	limitRange     = "state freshness limit out of range"
	limitFloor     = "state freshness limit below three reconcile intervals"
)

// newFreshnessReconciler returns a reconciler on a recording handler with a
// one-second interval, so the floor of three intervals stays below every
// limit the takeFreshness tests set.
func newFreshnessReconciler() (*Reconciler, *recordingHandler) {
	logs := newRecordingHandler()
	return NewReconciler(&mockFetcher{}, Config{Interval: time.Second}, slog.New(logs)), logs
}

// An absent block and a null say nothing about the limit: the held one stays,
// and nothing is logged.
func TestTakeFreshness_EmptyAndNullKeepTheLimit(t *testing.T) {
	for _, raw := range []string{"", "null", " null "} {
		r, logs := newFreshnessReconciler()
		r.SetMaxAgeSeconds(3600)
		before := len(logs.all())

		r.takeFreshness(json.RawMessage(raw))

		if got := r.MaxAgeSeconds(); got != 3600 {
			t.Errorf("raw %q: MaxAgeSeconds() = %d, want the held 3600", raw, got)
		}
		if got := logs.all()[before:]; len(got) != 0 {
			t.Errorf("raw %q: logged %v, want nothing", raw, got)
		}
	}
}

// A block without max_age_seconds, or with null, removes the limit and says
// so once.
func TestTakeFreshness_BlockWithoutAValueClearsTheLimit(t *testing.T) {
	for _, raw := range []string{`{}`, `{"max_age_seconds":null}`} {
		r, logs := newFreshnessReconciler()
		r.SetMaxAgeSeconds(3600)

		r.takeFreshness(json.RawMessage(raw))
		r.takeFreshness(json.RawMessage(raw))

		if got := r.MaxAgeSeconds(); got != 0 {
			t.Errorf("raw %s: MaxAgeSeconds() = %d, want 0", raw, got)
		}
		if got := r.MaxAge(); got != 0 {
			t.Errorf("raw %s: MaxAge() = %v, want 0", raw, got)
		}
		if n := logs.count(limitRemoved); n != 1 {
			t.Errorf("raw %s: %q logged %d times, want once", raw, limitRemoved, n)
		}
		wantString(t, logs.last(t, limitRemoved), "component", "reconcile")
	}
}

// A value json.Unmarshal refuses and a number below 1 keep the held limit,
// and the same malformed block on three pulls logs its Warn once.
func TestTakeFreshness_RefusedValuesKeepTheLimit(t *testing.T) {
	tests := []struct {
		raw  string
		warn string
	}{
		{`{"max_age_seconds":"x"}`, limitMalformed},
		{`{"max_age_seconds":1.5}`, limitMalformed},
		{`"soon"`, limitMalformed},
		{`{"max_age_seconds":0}`, limitRange},
		{`{"max_age_seconds":-5}`, limitRange},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			r, logs := newFreshnessReconciler()
			r.SetMaxAgeSeconds(3600)

			for range 3 {
				r.takeFreshness(json.RawMessage(tt.raw))
			}

			if got := r.MaxAgeSeconds(); got != 3600 {
				t.Errorf("MaxAgeSeconds() = %d, want the held 3600", got)
			}
			if n := logs.count(tt.warn); n != 1 {
				t.Errorf("%q logged %d times over three pulls, want once", tt.warn, n)
			}
			rec := logs.last(t, tt.warn)
			if rec.level != slog.LevelWarn {
				t.Errorf("%q at %v, want Warn", tt.warn, rec.level)
			}
			wantString(t, rec, "component", "reconcile")
			if tt.warn == limitRange {
				var block struct {
					MaxAgeSeconds int64 `json:"max_age_seconds"`
				}
				if err := json.Unmarshal([]byte(tt.raw), &block); err != nil {
					t.Fatal(err)
				}
				if got := rec.attrs["max_age_seconds"].Int64(); got != block.MaxAgeSeconds {
					t.Errorf("max_age_seconds = %d, want %d", got, block.MaxAgeSeconds)
				}
			}
		})
	}
}

// A malformed block logs again once a block decoded between, and an
// out-of-range value logs again once another value ended its run.
func TestTakeFreshness_RunsEndOnADecodedBlock(t *testing.T) {
	r, logs := newFreshnessReconciler()

	r.takeFreshness(json.RawMessage(`{"max_age_seconds":"x"}`))
	r.takeFreshness(json.RawMessage(`{"max_age_seconds":3600}`))
	r.takeFreshness(json.RawMessage(`{"max_age_seconds":"x"}`))
	if n := logs.count(limitMalformed); n != 2 {
		t.Errorf("%q logged %d times, want twice", limitMalformed, n)
	}

	r.takeFreshness(json.RawMessage(`{"max_age_seconds":0}`))
	r.takeFreshness(json.RawMessage(`{"max_age_seconds":-5}`))
	r.takeFreshness(json.RawMessage(`{"max_age_seconds":-5}`))
	r.takeFreshness(json.RawMessage(`{"max_age_seconds":3600}`))
	r.takeFreshness(json.RawMessage(`{"max_age_seconds":-5}`))
	if n := logs.count(limitRange); n != 3 {
		t.Errorf("%q logged %d times, want three times (0, -5, and -5 after 3600)", limitRange, n)
	}
}

// A whole number becomes the limit and logs the applied value once.
func TestTakeFreshness_ValueSetsTheLimit(t *testing.T) {
	r, logs := newFreshnessReconciler()

	r.takeFreshness(json.RawMessage(`{"max_age_seconds":3600}`))
	r.takeFreshness(json.RawMessage(`{"max_age_seconds":3600}`))

	if got := r.MaxAgeSeconds(); got != 3600 {
		t.Errorf("MaxAgeSeconds() = %d, want 3600", got)
	}
	if got := r.MaxAge(); got != time.Hour {
		t.Errorf("MaxAge() = %v, want 1h", got)
	}
	if n := logs.count(limitSet); n != 1 {
		t.Fatalf("%q logged %d times, want once", limitSet, n)
	}
	rec := logs.last(t, limitSet)
	wantString(t, rec, "component", "reconcile")
	if got := rec.attrs["max_age"].Duration(); got != time.Hour {
		t.Errorf("max_age = %v, want 1h", got)
	}
	if n := logs.count(limitFloor); n != 0 {
		t.Errorf("%q logged %d times for a limit above the floor, want never", limitFloor, n)
	}
}

// The floor of three intervals raises a short limit, and the raw value stays
// what the control plane set; a value beyond ten years is read as ten years
// without overflowing a time.Duration.
func TestMaxAge_FloorAndCap(t *testing.T) {
	logs := newRecordingHandler()
	r := NewReconciler(&mockFetcher{}, Config{Interval: 60 * time.Second}, slog.New(logs))

	r.SetMaxAgeSeconds(30)
	if got := r.MaxAge(); got != 180*time.Second {
		t.Errorf("MaxAge() for 30 at a 60s interval = %v, want 3m0s", got)
	}
	if got := r.MaxAgeSeconds(); got != 30 {
		t.Errorf("MaxAgeSeconds() = %d, want 30", got)
	}
	if n := logs.count(limitFloor); n != 1 {
		t.Fatalf("%q logged %d times, want once", limitFloor, n)
	}
	rec := logs.last(t, limitFloor)
	if rec.level != slog.LevelWarn {
		t.Errorf("%q at %v, want Warn", limitFloor, rec.level)
	}
	if got := rec.attrs["max_age_seconds"].Int64(); got != 30 {
		t.Errorf("max_age_seconds = %d, want 30", got)
	}
	if got := rec.attrs["applied"].Duration(); got != 180*time.Second {
		t.Errorf("applied = %v, want 3m0s", got)
	}

	r.SetMaxAgeSeconds(math.MaxInt64)
	if got, want := r.MaxAge(), 315_360_000*time.Second; got != want {
		t.Errorf("MaxAge() for MaxInt64 = %v, want ten years (%v)", got, want)
	}
	if got := r.MaxAgeSeconds(); got != math.MaxInt64 {
		t.Errorf("MaxAgeSeconds() = %d, want MaxInt64", got)
	}

	r.SetMaxAgeSeconds(-1)
	if got := r.MaxAge(); got != 0 {
		t.Errorf("MaxAge() after SetMaxAgeSeconds(-1) = %v, want 0", got)
	}
}

// A successful pull records its time and takes its state_freshness block; a
// failed one does neither.
func TestReconciler_PullRecordsTimeAndFreshness(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	fail := false
	fetcher := &mockFetcher{}
	fetcher.fetchFunc = func(_ context.Context, _ string) (*api.NodeStateSnapshot, error) {
		if fail {
			return nil, context.DeadlineExceeded
		}
		return &api.NodeStateSnapshot{StateFreshness: json.RawMessage(`{"max_age_seconds":3600}`)}, nil
	}
	r := NewReconciler(fetcher, Config{Interval: time.Second}, discardLogger())
	r.now = func() time.Time { return now }

	r.runCycle(context.Background(), "node-1")
	if !r.lastPull.Equal(now) {
		t.Errorf("lastPull = %v, want %v", r.lastPull, now)
	}
	if got := r.MaxAgeSeconds(); got != 3600 {
		t.Errorf("MaxAgeSeconds() = %d, want 3600", got)
	}

	fail = true
	pulled := now
	now = now.Add(time.Minute)
	r.runCycle(context.Background(), "node-1")
	if !r.lastPull.Equal(pulled) {
		t.Errorf("lastPull after a failed fetch = %v, want %v", r.lastPull, pulled)
	}
}

// handlerCall is one invocation a recordingReconcileHandler saw.
type handlerCall struct {
	desired *api.NodeStateSnapshot
	diff    StateDiff
}

// recordingReconcileHandler records every call and returns the error fail
// gives for the call's index, nil when fail is nil.
type recordingReconcileHandler struct {
	mu    sync.Mutex
	calls []handlerCall
	fail  func(call int) error
}

func (h *recordingReconcileHandler) handle(_ context.Context, desired *api.NodeStateSnapshot, diff StateDiff) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, handlerCall{desired: desired, diff: diff})
	if h.fail != nil {
		return h.fail(len(h.calls) - 1)
	}
	return nil
}

func (h *recordingReconcileHandler) recorded() []handlerCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]handlerCall(nil), h.calls...)
}

// peerIDs returns the node IDs of peers, in order.
func peerIDs(peers []api.SnapshotPeer) []string {
	ids := make([]string, 0, len(peers))
	for _, p := range peers {
		ids = append(ids, p.NodeID)
	}
	return ids
}

var (
	restorePeerA = api.SnapshotPeer{NodeID: "peer-a", MeshIP: "10.0.0.2", PublicKey: "pk-a"}
	restorePeerB = api.SnapshotPeer{NodeID: "peer-b", MeshIP: "10.0.0.3", PublicKey: "pk-b"}
)

// restoredState returns a stored state with peers A and B and a policy.
func restoredState() *api.NodeStateSnapshot {
	return &api.NodeStateSnapshot{
		Peers:  []api.SnapshotPeer{restorePeerA, restorePeerB},
		Policy: &api.PolicySnapshot{RevisionID: "rev-1", Fingerprint: "fp-1"},
	}
}

// A restore of two peers and a policy invokes each reconcile handler once
// with both peers to add, runs no dispatch handler, and a pull equal to the
// stored state then reports no drift.
func TestRestore_AppliesTheStoredState(t *testing.T) {
	fetcher := &mockFetcher{fetchFunc: func(context.Context, string) (*api.NodeStateSnapshot, error) {
		return restoredState(), nil
	}}
	logs := newRecordingHandler()
	r := NewReconciler(fetcher, Config{Interval: time.Hour}, slog.New(logs))
	h1, h2 := &recordingReconcileHandler{}, &recordingReconcileHandler{}
	r.RegisterHandler(h1.handle)
	r.RegisterHandler(h2.handle)
	dispatched := 0
	r.RegisterDispatchHandler(func(context.Context, *api.NodeStateSnapshot) { dispatched++ })

	if failed := r.Restore(context.Background(), restoredState(), 5*time.Minute); failed {
		t.Fatal("Restore() = true, want false with handlers that succeed")
	}
	for i, h := range []*recordingReconcileHandler{h1, h2} {
		calls := h.recorded()
		if len(calls) != 1 {
			t.Fatalf("handler %d called %d times by Restore, want once", i, len(calls))
		}
		if got := peerIDs(calls[0].diff.PeersToAdd); !slices.Equal(got, []string{"peer-a", "peer-b"}) {
			t.Errorf("handler %d PeersToAdd = %v, want [peer-a peer-b]", i, got)
		}
		if !calls[0].diff.PolicyChanged {
			t.Errorf("handler %d diff carries no policy change", i)
		}
	}
	if dispatched != 0 {
		t.Errorf("Restore ran %d dispatch handlers, want none", dispatched)
	}
	rec := logs.last(t, "stored state applied")
	wantString(t, rec, "component", "reconcile")
	wantString(t, rec, "drift", "peers+2-0~0 policy")
	if got := rec.attrs["age"].Duration(); got != 5*time.Minute {
		t.Errorf("age = %v, want 5m0s", got)
	}
	if got := rec.attrs["handler_failed"].Bool(); got {
		t.Error("handler_failed = true, want false")
	}

	r.runCycle(context.Background(), "node-1")
	if n := len(h1.recorded()); n != 1 {
		t.Errorf("handler called %d times after a pull equal to the stored state, want no further call", n)
	}
	if n := logs.count("no drift detected"); n != 1 {
		t.Errorf("%q logged %d times, want once", "no drift detected", n)
	}
	if dispatched != 1 {
		t.Errorf("the pull ran %d dispatch handlers, want 1", dispatched)
	}
}

// A restore counts as a pull age old, and a negative age as 0.
func TestRestore_SetsTheLastPull(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	r := NewReconciler(&mockFetcher{}, Config{Interval: time.Hour}, discardLogger())
	r.now = func() time.Time { return now }

	r.Restore(context.Background(), restoredState(), 10*time.Minute)
	if want := now.Add(-10 * time.Minute); !r.lastPull.Equal(want) {
		t.Errorf("lastPull = %v, want %v", r.lastPull, want)
	}
	r.Restore(context.Background(), restoredState(), -time.Hour)
	if !r.lastPull.Equal(now) {
		t.Errorf("lastPull after a negative age = %v, want %v", r.lastPull, now)
	}
}

// A restore of an empty snapshot finds no drift and invokes nothing.
func TestRestore_EmptySnapshotInvokesNothing(t *testing.T) {
	r := NewReconciler(&mockFetcher{}, Config{Interval: time.Hour}, discardLogger())
	h := &recordingReconcileHandler{}
	r.RegisterHandler(h.handle)

	if failed := r.Restore(context.Background(), &api.NodeStateSnapshot{}, 0); failed {
		t.Error("Restore() = true, want false")
	}
	if n := len(h.recorded()); n != 0 {
		t.Errorf("handler called %d times, want never", n)
	}
}

// A nil stored state does nothing at all.
func TestRestore_NilDoesNothing(t *testing.T) {
	logs := newRecordingHandler()
	r := NewReconciler(&mockFetcher{}, Config{Interval: time.Hour}, slog.New(logs))
	h := &recordingReconcileHandler{}
	r.RegisterHandler(h.handle)

	if failed := r.Restore(context.Background(), nil, time.Minute); failed {
		t.Error("Restore(nil) = true, want false")
	}
	if n := len(h.recorded()); n != 0 {
		t.Errorf("handler called %d times, want never", n)
	}
	if !r.lastPull.IsZero() {
		t.Errorf("lastPull = %v, want zero", r.lastPull)
	}
	if got := logs.all(); len(got) != 0 {
		t.Errorf("logged %v, want nothing", got)
	}
}

// A restore whose handler failed still records the stored state, so the next
// pull removes the restored peer the control plane dropped, and writes the
// peer it kept again; a third, equal pull finds no drift.
func TestRestore_FailedHandlerReappliesOnTheNextPull(t *testing.T) {
	fetcher := &mockFetcher{fetchFunc: func(context.Context, string) (*api.NodeStateSnapshot, error) {
		return &api.NodeStateSnapshot{
			Peers:  []api.SnapshotPeer{restorePeerB},
			Policy: &api.PolicySnapshot{RevisionID: "rev-1", Fingerprint: "fp-1"},
		}, nil
	}}
	r := NewReconciler(fetcher, Config{Interval: time.Hour}, discardLogger())
	h := &recordingReconcileHandler{fail: func(call int) error {
		if call == 0 {
			return errors.New("device busy")
		}
		return nil
	}}
	r.RegisterHandler(h.handle)

	if failed := r.Restore(context.Background(), restoredState(), 0); !failed {
		t.Fatal("Restore() = false, want true when a handler failed")
	}

	r.runCycle(context.Background(), "node-1")
	calls := h.recorded()
	if len(calls) != 2 {
		t.Fatalf("handler called %d times after the restore and one pull, want 2", len(calls))
	}
	if got := calls[1].diff.PeersToRemove; !slices.Equal(got, []string{"peer-a"}) {
		t.Errorf("PeersToRemove = %v, want [peer-a]", got)
	}
	if got := peerIDs(calls[1].diff.PeersToAdd); !slices.Equal(got, []string{"peer-b"}) {
		t.Errorf("PeersToAdd = %v, want [peer-b]", got)
	}

	r.runCycle(context.Background(), "node-1")
	if n := len(h.recorded()); n != 2 {
		t.Errorf("handler called %d times after a third, equal pull, want no further call", n)
	}
}

// While reapply is set, a pull without drift still invokes the handlers, and
// a failure keeps the flag for the next pull.
func TestReconciler_ReapplyInvokesHandlersOnAnEmptyDiff(t *testing.T) {
	fetcher := &mockFetcher{fetchFunc: func(context.Context, string) (*api.NodeStateSnapshot, error) {
		return restoredState(), nil
	}}
	r := NewReconciler(fetcher, Config{Interval: time.Hour}, discardLogger())
	h := &recordingReconcileHandler{fail: func(call int) error {
		if call < 2 {
			return errors.New("device busy")
		}
		return nil
	}}
	r.RegisterHandler(h.handle)

	r.Restore(context.Background(), restoredState(), 0)
	for range 3 {
		r.runCycle(context.Background(), "node-1")
	}
	calls := h.recorded()
	if len(calls) != 3 {
		t.Fatalf("handler called %d times, want 3: the restore, the failed reapply, the reapply that succeeded", len(calls))
	}
	for i, c := range calls[1:] {
		if got := peerIDs(c.diff.PeersToAdd); !slices.Equal(got, []string{"peer-a", "peer-b"}) {
			t.Errorf("reapply %d PeersToAdd = %v, want [peer-a peer-b]", i, got)
		}
	}
}

// withdrawalRig runs a Reconciler at a 10ms interval against a scripted
// fetcher and a clock the test moves. The pull of phase 0 carries a maximum
// age of 60 s; phase 1 fails every fetch with context.DeadlineExceeded.
type withdrawalRig struct {
	r        *Reconciler
	logs     *recordingHandler
	fetcher  *mockFetcher
	handler  *recordingReconcileHandler
	phase    atomic.Int32
	offset   atomic.Int64 // nanoseconds the clock is ahead
	withdraw atomic.Int32 // withdraw handler calls
	pulls    map[int32]func() *api.NodeStateSnapshot
	cancel   context.CancelFunc
	done     chan error
}

var withdrawalBase = time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

func newWithdrawalRig(t *testing.T, pulls map[int32]func() *api.NodeStateSnapshot, withdrawErr func(call int32) error) *withdrawalRig {
	t.Helper()
	rig := &withdrawalRig{logs: newRecordingHandler(), handler: &recordingReconcileHandler{}, pulls: pulls}
	rig.fetcher = &mockFetcher{fetchFunc: func(context.Context, string) (*api.NodeStateSnapshot, error) {
		if pull, ok := rig.pulls[rig.phase.Load()]; ok {
			return pull(), nil
		}
		return nil, context.DeadlineExceeded
	}}
	rig.r = NewReconciler(rig.fetcher, Config{Interval: 10 * time.Millisecond}, slog.New(rig.logs))
	rig.r.now = func() time.Time { return withdrawalBase.Add(time.Duration(rig.offset.Load())) }
	rig.r.RegisterHandler(rig.handler.handle)
	rig.r.RegisterWithdrawHandler(func(context.Context) error {
		n := rig.withdraw.Add(1)
		if withdrawErr != nil {
			return withdrawErr(n)
		}
		return nil
	})
	return rig
}

func (rig *withdrawalRig) start() {
	ctx, cancel := context.WithCancel(context.Background())
	rig.cancel = cancel
	rig.done = make(chan error, 1)
	go func() { rig.done <- rig.r.Run(ctx, "node-1") }()
}

func (rig *withdrawalRig) stop(t *testing.T) {
	t.Helper()
	rig.cancel()
	if err := <-rig.done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run() = %v, want context.Canceled", err)
	}
}

// waitFor polls cond every millisecond for up to 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after 5s waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// fetchesAfter waits until n more fetches than now happened.
func (rig *withdrawalRig) fetchesAfter(t *testing.T, n int) {
	t.Helper()
	target := rig.fetcher.getFetchCount() + n
	waitFor(t, fmt.Sprintf("%d more fetches", n), func() bool { return rig.fetcher.getFetchCount() >= target })
}

// expire moves the clock two minutes on, past the 60 s limit.
func (rig *withdrawalRig) expire() {
	rig.offset.Add(int64(2 * time.Minute))
}

// limitedPull returns a pull with peers A and B, a policy, a state block, a
// bridge block with every child, and a maximum age of 60 s.
func limitedPull() *api.NodeStateSnapshot {
	return &api.NodeStateSnapshot{
		Peers:  []api.SnapshotPeer{restorePeerA, restorePeerB},
		Policy: &api.PolicySnapshot{RevisionID: "rev-1", Fingerprint: "fp-1"},
		State:  &api.NodeStateBlock{Metadata: []api.StateEntry{{Key: "region", Value: "eu"}}, Data: []api.StateEntry{}, Reports: []api.StateEntry{}},
		Bridge: &api.BridgeSnapshot{
			Relay:      &api.RelayConfig{Enabled: true, ListenPort: 51821},
			Ingress:    &api.IngressConfig{Enabled: true},
			UserAccess: &api.UserAccessConfig{Enabled: true, Providers: []api.UserAccessProvider{{ID: "ua-1"}}},
			SiteToSite: &api.SiteToSiteConfig{Enabled: true, Tunnels: []api.SiteToSiteTunnel{{ID: "s2s-1"}}},
		},
		SharedSubnets:  []api.NodeStateSharedSubnet{{Subnet: "10.20.0.0/16", Bridges: []string{"peer-a"}}},
		StateFreshness: json.RawMessage(`{"max_age_seconds":60}`),
	}
}

// A node whose last successful pull is older than the limit runs the
// withdraw handlers once and hands the reconcile handlers the withdrawn
// snapshot: no peers and no policy, the state block as it was, and a bridge
// block that keeps the user access providers and site-to-site tunnels
// disabled, without relay and ingress.
func TestWithdraw_PassedLimitWithdrawsTheState(t *testing.T) {
	rig := newWithdrawalRig(t, map[int32]func() *api.NodeStateSnapshot{0: limitedPull}, nil)
	rig.start()
	defer rig.stop(t)

	waitFor(t, "the first pull's handler call", func() bool { return len(rig.handler.recorded()) == 1 })
	rig.phase.Store(1)
	rig.expire()
	waitFor(t, "the withdraw handler", func() bool { return rig.withdraw.Load() >= 1 })
	rig.fetchesAfter(t, 10)

	if n := rig.withdraw.Load(); n != 1 {
		t.Errorf("withdraw handler ran %d times, want once", n)
	}
	calls := rig.handler.recorded()
	if len(calls) != 2 {
		t.Fatalf("reconcile handler ran %d times, want 2: the pull and the withdrawal", len(calls))
	}
	got := calls[1]
	if got.desired.Peers != nil {
		t.Errorf("withdrawn Peers = %v, want nil", got.desired.Peers)
	}
	if got.desired.Policy != nil {
		t.Errorf("withdrawn Policy = %+v, want nil", got.desired.Policy)
	}
	if got.desired.SharedSubnets != nil {
		t.Errorf("withdrawn SharedSubnets = %v, want nil", got.desired.SharedSubnets)
	}
	if !reflect.DeepEqual(got.desired.State, limitedPull().State) {
		t.Errorf("withdrawn State = %+v, want the pulled block unchanged", got.desired.State)
	}
	b := got.desired.Bridge
	if b == nil {
		t.Fatal("withdrawn Bridge = nil, want the block with its children disabled")
	}
	if b.Relay != nil || b.Ingress != nil {
		t.Errorf("withdrawn Relay = %+v, Ingress = %+v, want both nil", b.Relay, b.Ingress)
	}
	if b.UserAccess == nil || b.UserAccess.Enabled || len(b.UserAccess.Providers) != 1 || b.UserAccess.Providers[0].ID != "ua-1" {
		t.Errorf("withdrawn UserAccess = %+v, want provider ua-1 kept with Enabled false", b.UserAccess)
	}
	if b.SiteToSite == nil || b.SiteToSite.Enabled || len(b.SiteToSite.Tunnels) != 1 || b.SiteToSite.Tunnels[0].ID != "s2s-1" {
		t.Errorf("withdrawn SiteToSite = %+v, want tunnel s2s-1 kept with Enabled false", b.SiteToSite)
	}
	if ids := got.diff.PeersToRemove; !slices.Equal(ids, []string{"peer-a", "peer-b"}) {
		t.Errorf("PeersToRemove = %v, want [peer-a peer-b]", ids)
	}
	if !got.diff.PolicyChanged || !got.diff.BridgeChanged || !got.diff.SharedSubnetsChanged || got.diff.StateChanged {
		t.Errorf("withdrawal diff = %+v, want policy, bridge and shared subnets changed and state unchanged", got.diff)
	}

	warn := rig.logs.last(t, "desired state passed its maximum age, withdrawing")
	if warn.level != slog.LevelWarn {
		t.Errorf("level = %v, want Warn", warn.level)
	}
	if got := warn.attrs["max_age"].Duration(); got != time.Minute {
		t.Errorf("max_age = %v, want 1m0s", got)
	}
	if got := warn.attrs["age"].Duration(); got < time.Minute {
		t.Errorf("age = %v, want more than 1m0s", got)
	}
	done := rig.logs.last(t, "desired state withdrawn")
	if done.attrs["handler_failed"].Bool() {
		t.Error("handler_failed = true, want false")
	}
}

// No withdrawal happens without a limit, before the first successful pull,
// or while pulls keep succeeding within the limit.
func TestWithdraw_NothingWithdrawnWithinTheRules(t *testing.T) {
	t.Run("no limit", func(t *testing.T) {
		unlimited := func() *api.NodeStateSnapshot {
			p := limitedPull()
			p.StateFreshness = nil
			return p
		}
		rig := newWithdrawalRig(t, map[int32]func() *api.NodeStateSnapshot{0: unlimited}, nil)
		rig.start()
		defer rig.stop(t)
		rig.fetchesAfter(t, 1)
		rig.phase.Store(1)
		rig.expire()
		rig.fetchesAfter(t, 20)
		if n := rig.withdraw.Load(); n != 0 {
			t.Errorf("withdraw handler ran %d times without a limit, want never", n)
		}
	})
	t.Run("no pull yet", func(t *testing.T) {
		rig := newWithdrawalRig(t, nil, nil)
		rig.r.SetMaxAgeSeconds(60)
		rig.start()
		defer rig.stop(t)
		rig.expire()
		rig.fetchesAfter(t, 20)
		if n := rig.withdraw.Load(); n != 0 {
			t.Errorf("withdraw handler ran %d times before any pull, want never", n)
		}
	})
	t.Run("pulls within the limit", func(t *testing.T) {
		rig := newWithdrawalRig(t, map[int32]func() *api.NodeStateSnapshot{0: limitedPull}, nil)
		// Every fetch moves the clock 10 s on: far past the limit in total,
		// but each pull is within it of the one before.
		pull := rig.pulls[0]
		rig.pulls[0] = func() *api.NodeStateSnapshot {
			rig.offset.Add(int64(10 * time.Second))
			return pull()
		}
		rig.start()
		defer rig.stop(t)
		rig.fetchesAfter(t, 30)
		if n := rig.withdraw.Load(); n != 0 {
			t.Errorf("withdraw handler ran %d times while pulls succeeded, want never", n)
		}
	})
}

// A pull that succeeds after a withdrawal hands every peer to the handlers as
// an add and arms the limit again.
func TestWithdraw_PullAfterAWithdrawalAddsEveryPeer(t *testing.T) {
	rig := newWithdrawalRig(t, map[int32]func() *api.NodeStateSnapshot{0: limitedPull, 2: limitedPull}, nil)
	rig.start()
	defer rig.stop(t)

	waitFor(t, "the first pull's handler call", func() bool { return len(rig.handler.recorded()) == 1 })
	rig.phase.Store(1)
	rig.expire()
	waitFor(t, "the withdrawal", func() bool { return len(rig.handler.recorded()) == 2 })

	rig.phase.Store(2)
	waitFor(t, "the pull after the withdrawal", func() bool { return len(rig.handler.recorded()) == 3 })
	if ids := peerIDs(rig.handler.recorded()[2].diff.PeersToAdd); !slices.Equal(ids, []string{"peer-a", "peer-b"}) {
		t.Errorf("PeersToAdd after the withdrawal = %v, want [peer-a peer-b]", ids)
	}

	rig.phase.Store(3)
	rig.fetchesAfter(t, 3)
	rig.expire()
	waitFor(t, "the second withdrawal", func() bool { return rig.withdraw.Load() == 2 })
}

// A withdraw handler that fails is called again, with the reconcile handlers
// and the same diff, on every later cycle whose fetch fails. A fetch that then
// succeeds drops the withdrawal: it removes the peer the pull dropped, writes
// the one it kept again, and no withdraw handler runs after it.
func TestWithdraw_FailedWithdrawalRetriesUntilAPull(t *testing.T) {
	onlyB := func() *api.NodeStateSnapshot {
		p := limitedPull()
		p.Peers = []api.SnapshotPeer{restorePeerB}
		return p
	}
	rig := newWithdrawalRig(t, map[int32]func() *api.NodeStateSnapshot{0: limitedPull, 2: onlyB},
		func(int32) error { return errors.New("firewall busy") })
	rig.start()
	defer rig.stop(t)

	waitFor(t, "the first pull's handler call", func() bool { return len(rig.handler.recorded()) == 1 })
	rig.phase.Store(1)
	rig.expire()
	// A retry logs its Debug line after its handlers ran, so the line is
	// what marks a retry as done.
	waitFor(t, "two retries of the withdrawal", func() bool { return rig.logs.count("withdrawal retried") >= 2 })
	if n := rig.withdraw.Load(); n < 3 {
		t.Errorf("withdraw handler ran %d times after two retries, want at least 3", n)
	}
	for i, c := range rig.handler.recorded()[1:] {
		if ids := c.diff.PeersToRemove; !slices.Equal(ids, []string{"peer-a", "peer-b"}) {
			t.Errorf("withdrawal call %d PeersToRemove = %v, want [peer-a peer-b]", i, ids)
		}
	}

	before := len(rig.handler.recorded())
	rig.phase.Store(2)
	var pulled handlerCall
	waitFor(t, "the pull that drops peer A", func() bool {
		for _, c := range rig.handler.recorded()[before:] {
			if c.desired.StateFreshness != nil {
				pulled = c
				return true
			}
		}
		return false
	})
	if ids := pulled.diff.PeersToRemove; !slices.Equal(ids, []string{"peer-a"}) {
		t.Errorf("PeersToRemove = %v, want [peer-a]", ids)
	}
	if ids := peerIDs(pulled.diff.PeersToAdd); !slices.Equal(ids, []string{"peer-b"}) {
		t.Errorf("PeersToAdd = %v, want [peer-b]", ids)
	}
	withdrawals := rig.withdraw.Load()
	rig.fetchesAfter(t, 10)
	if n := rig.withdraw.Load(); n != withdrawals {
		t.Errorf("withdraw handler ran %d more times after the pull, want none", n-withdrawals)
	}
}

// A withdrawal over an empty snapshot runs the withdraw handlers and no
// reconcile handler, and the timer fires no second withdrawal while fetches
// keep failing.
func TestWithdraw_EmptySnapshotRunsOnlyTheWithdrawHandlers(t *testing.T) {
	empty := func() *api.NodeStateSnapshot {
		return &api.NodeStateSnapshot{StateFreshness: json.RawMessage(`{"max_age_seconds":60}`)}
	}
	rig := newWithdrawalRig(t, map[int32]func() *api.NodeStateSnapshot{0: empty}, nil)
	rig.start()
	defer rig.stop(t)

	rig.fetchesAfter(t, 1)
	rig.phase.Store(1)
	rig.expire()
	waitFor(t, "the withdraw handler", func() bool { return rig.withdraw.Load() >= 1 })
	rig.fetchesAfter(t, 20)
	rig.expire()
	rig.fetchesAfter(t, 20)

	if n := rig.withdraw.Load(); n != 1 {
		t.Errorf("withdraw handler ran %d times, want once", n)
	}
	if n := len(rig.handler.recorded()); n != 0 {
		t.Errorf("reconcile handler ran %d times, want never", n)
	}
}

// withdrawnBridge keeps a nil block nil and never shares memory with the
// block it read.
func TestWithdrawnBridge(t *testing.T) {
	if got := withdrawnBridge(nil); got != nil {
		t.Errorf("withdrawnBridge(nil) = %+v, want nil", got)
	}
	src := limitedPull().Bridge
	got := withdrawnBridge(src)
	got.UserAccess.Providers[0].ID = "changed"
	if src.UserAccess.Providers[0].ID != "ua-1" || !src.UserAccess.Enabled || !src.SiteToSite.Enabled {
		t.Errorf("withdrawnBridge changed its input: %+v", src)
	}
	if got := withdrawnBridge(&api.BridgeSnapshot{Relay: &api.RelayConfig{Enabled: true}}); got.UserAccess != nil || got.SiteToSite != nil || got.Relay != nil {
		t.Errorf("withdrawnBridge of a relay-only block = %+v, want an empty block", got)
	}
}
