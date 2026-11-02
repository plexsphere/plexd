package actions

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// newTestDispatcher wires a dispatcher onto an executor carrying a single
// instantly-succeeding builtin, and returns both plus the reporter that records
// the callbacks the dispatch drives.
func newTestDispatcher(t *testing.T, cfg Config) (*Dispatcher, *Executor, *mockReporter) {
	t.Helper()
	reporter := &mockReporter{}
	exec := newTestExecutor(cfg, reporter, &mockVerifier{ok: true})
	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return "hello", "", 0, nil
	})
	return NewDispatcher(exec, "node-1", testLogger()), exec, reporter
}

// snapshot wraps entries in the pull's desired-state envelope.
func snapshot(entries ...api.NodeStateExecution) *api.NodeStateSnapshot {
	return &api.NodeStateSnapshot{Executions: entries}
}

// activeExecutions reports how many executions the executor still holds in
// flight. An id is released after its terminal callback has been delivered, so
// this is the only way to tell that a re-dispatch under the same id will be
// taken rather than refused as already_active.
func activeExecutions(e *Executor) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.active)
}

func TestDispatcher_EmptyBlock(t *testing.T) {
	d, _, reporter := newTestDispatcher(t, Config{})

	d.Handle(context.Background(), snapshot())

	if cbs := reporter.getCallbacks(); len(cbs) != 0 {
		t.Errorf("callbacks = %v, want none", cbs)
	}
	if len(d.handled) != 0 {
		t.Errorf("handled = %v, want empty", d.handled)
	}
}

func TestDispatcher_PendingEntryDispatchedOnce(t *testing.T) {
	d, _, reporter := newTestDispatcher(t, Config{})
	entry := pendingExec("exec-pending", "test.echo")

	d.Handle(context.Background(), snapshot(entry))

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 3
	})
	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})

	// The entry stays in the block until the control plane settles it. Every
	// re-observation must be a no-op.
	d.Handle(context.Background(), snapshot(entry))
	d.Handle(context.Background(), snapshot(entry))

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})
}

// TestDispatcher_DrainPrunesHandled checks that the settled-id set is garbage
// collected when an entry leaves the block, keeping it bounded by the block.
func TestDispatcher_DrainPrunesHandled(t *testing.T) {
	d, exec, reporter := newTestDispatcher(t, Config{})
	entry := pendingExec("exec-drained", "test.echo")

	d.Handle(context.Background(), snapshot(entry))
	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 3
	})
	// The terminal callback is delivered before the executor releases the id,
	// so the re-dispatch below can race that release and be refused as
	// already_active. Wait for the release itself, not just for its callback.
	waitFor(t, 5*time.Second, func() bool { return activeExecutions(exec) == 0 })

	// The entry drains: the control plane has settled it.
	d.Handle(context.Background(), snapshot())
	if len(d.handled) != 0 {
		t.Fatalf("handled = %v, want empty after the drain", d.handled)
	}

	// A re-appearance under the same id is therefore dispatched again.
	d.Handle(context.Background(), snapshot(entry))
	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 6
	})
	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})
}

// TestDispatcher_ExpiredEntry checks that a lapsed deadline produces no callback
// at all: timeout is a server-side status the node never reports.
func TestDispatcher_ExpiredEntry(t *testing.T) {
	d, _, reporter := newTestDispatcher(t, Config{})
	entry := pendingExec("exec-expired", "test.echo")
	entry.ExpiresAt = time.Now().Add(-time.Second)

	d.Handle(context.Background(), snapshot(entry))

	if cbs := reporter.getCallbacks(); len(cbs) != 0 {
		t.Errorf("callbacks = %v, want none for an expired entry", cbs)
	}
	if _, settled := d.handled[entry.ExecutionID]; !settled {
		t.Error("expired entry was not marked handled")
	}
}

// TestDispatcher_ActionsDisabled checks that a node with actions switched off
// still settles the execution instead of leaving it pending until it expires.
func TestDispatcher_ActionsDisabled(t *testing.T) {
	d, _, reporter := newTestDispatcher(t, Config{Enabled: boolPtr(false)})

	d.Handle(context.Background(), snapshot(pendingExec("exec-disabled", "test.echo")))

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusFailed,
	})
	if got := cbs[len(cbs)-1].Error; got != "actions_disabled" {
		t.Errorf("failed error = %q, want %q", got, "actions_disabled")
	}
}

// TestDispatcher_SaturationDefersEntry checks that an entry the executor cannot
// take right now stays unsettled, so a later cycle delivers it.
func TestDispatcher_SaturationDefersEntry(t *testing.T) {
	reporter := &mockReporter{}
	exec := newTestExecutor(Config{
		MaxConcurrent:    1,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   DefaultMaxOutputBytes,
	}, reporter, &mockVerifier{ok: true})

	started := make(chan struct{})
	block := make(chan struct{})
	exec.RegisterBuiltin("slow", "Slow action", nil, func(ctx context.Context, _ map[string]string) (string, string, int, error) {
		close(started)
		select {
		case <-block:
		case <-ctx.Done():
		}
		return "done", "", 0, nil
	})
	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return "hello", "", 0, nil
	})

	d := NewDispatcher(exec, "node-1", testLogger())
	occupier := pendingExec("exec-occupier", "slow")
	deferred := pendingExec("exec-deferred", "test.echo")

	d.Handle(context.Background(), snapshot(occupier))
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("occupying action did not start")
	}

	// The block redelivers both entries; only the occupier has a slot.
	d.Handle(context.Background(), snapshot(occupier, deferred))
	if _, settled := d.handled[deferred.ExecutionID]; settled {
		t.Error("deferred entry was marked handled")
	}
	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
	})

	// Free the slot; the next cycle delivers the deferred entry.
	close(block)
	waitFor(t, 5*time.Second, func() bool {
		return exec.ActiveCount() == 0
	})

	d.Handle(context.Background(), snapshot(occupier, deferred))
	waitFor(t, 5*time.Second, func() bool {
		return countStatus(reporter.getCallbacks(), api.ExecutionStatusSucceeded) >= 2
	})
}

// TestDispatcher_StartedEntryReportedLost checks that an execution the control
// plane holds at started is failed rather than re-run: actions are not
// idempotent and the node keeps no run state across a restart.
func TestDispatcher_StartedEntryReportedLost(t *testing.T) {
	reporter := &mockReporter{}
	exec := newTestExecutor(Config{}, reporter, &mockVerifier{ok: true})

	ran := make(chan struct{}, 1)
	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		ran <- struct{}{}
		return "hello", "", 0, nil
	})

	d := NewDispatcher(exec, "node-1", testLogger())
	entry := pendingExec("exec-orphaned", "test.echo")
	entry.Status = api.ExecutionStatusStarted

	d.Handle(context.Background(), snapshot(entry))

	select {
	case <-ran:
		t.Fatal("orphaned execution was re-run")
	case <-time.After(100 * time.Millisecond):
	}

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{api.ExecutionStatusFailed})
	if cbs[0].Error != orphanedRunError {
		t.Errorf("terminal error = %q, want %q", cbs[0].Error, orphanedRunError)
	}
}

// TestDispatcher_OrphanUnsettledOnUndeliveredReport checks that an orphan report
// the control plane never accepted leaves the entry unsettled. Settling it
// anyway would drop the report for the life of the process: the dispatcher skips
// the id on every later pull, so the execution sits at started until server-side
// expiry and the operator reads timeout instead of the run this agent lost.
func TestDispatcher_OrphanUnsettledOnUndeliveredReport(t *testing.T) {
	reporter := &mockReporter{
		statusErrs:      map[string]error{api.ExecutionStatusFailed: errors.New("connection reset")},
		statusErrBudget: map[string]int{api.ExecutionStatusFailed: terminalCallbackAttempts},
	}
	exec := newTestExecutor(Config{}, reporter, &mockVerifier{ok: true})
	d := NewDispatcher(exec, "node-1", testLogger())
	entry := pendingExec("exec-orphan-transient", "test.echo")
	entry.Status = api.ExecutionStatusStarted

	d.Handle(context.Background(), snapshot(entry))

	if got := countStatus(reporter.getCallbacks(), api.ExecutionStatusFailed); got != terminalCallbackAttempts {
		t.Errorf("failed callbacks = %d, want the %d exhausted attempts", got, terminalCallbackAttempts)
	}
	if _, settled := d.handled[entry.ExecutionID]; settled {
		t.Fatal("an execution whose orphan report was never delivered was marked settled")
	}

	// The next pull redelivers the entry, and the report lands.
	d.Handle(context.Background(), snapshot(entry))

	cbs := reporter.getCallbacks()
	if got := countStatus(cbs, api.ExecutionStatusFailed); got != terminalCallbackAttempts+1 {
		t.Errorf("failed callbacks = %d, want %d after the redelivery", got, terminalCallbackAttempts+1)
	}
	if got := cbs[len(cbs)-1].Error; got != orphanedRunError {
		t.Errorf("terminal error = %q, want %q", got, orphanedRunError)
	}
	if _, settled := d.handled[entry.ExecutionID]; !settled {
		t.Error("the delivered orphan report did not settle the entry")
	}
}

// TestDispatcher_OrphanReportAbandonedAfterRepeatedPasses checks that a report
// the control plane never takes stops being retried. An unsettled entry is
// retried at the head of the block on every pull, and each attempt spends part
// of the dispatch budget, so retrying it for the execution's whole expiry window
// starves every entry queued behind it. After maxDeferrals passes the entry is
// settled locally and left to the server-side expiry it was heading for anyway.
func TestDispatcher_OrphanReportAbandonedAfterRepeatedPasses(t *testing.T) {
	// No error budget: this control plane never accepts the terminal callback.
	reporter := &mockReporter{
		statusErrs: map[string]error{api.ExecutionStatusFailed: errors.New("connection reset")},
	}
	exec := newTestExecutor(Config{}, reporter, &mockVerifier{ok: true})
	d := NewDispatcher(exec, "node-1", testLogger())
	entry := pendingExec("exec-orphan-stuck", "test.echo")
	entry.Status = api.ExecutionStatusStarted

	for pass := 1; pass < maxDeferrals; pass++ {
		d.Handle(context.Background(), snapshot(entry))
		if _, settled := d.handled[entry.ExecutionID]; settled {
			t.Fatalf("entry settled after %d passes, want it retried through %d", pass, maxDeferrals)
		}
	}

	d.Handle(context.Background(), snapshot(entry))
	if _, settled := d.handled[entry.ExecutionID]; !settled {
		t.Fatalf("entry still unsettled after the %d permitted passes", maxDeferrals)
	}

	// Every later pull skips it, so the undeliverable report stops costing the
	// pass and the entries behind it get the budget.
	spent := len(reporter.getCallbacks())
	d.Handle(context.Background(), snapshot(entry))
	if got := len(reporter.getCallbacks()); got != spent {
		t.Errorf("callbacks = %d, want %d: the abandoned report was retried again", got, spent)
	}

	// The entry draining from the block forgets the deferrals alongside the
	// settled id, so a later execution under the same id starts from scratch.
	d.Handle(context.Background(), snapshot())
	if len(d.deferrals) != 0 {
		t.Errorf("deferrals = %v, want empty after the drain", d.deferrals)
	}
}

// TestDispatcher_AckedEntrySkipsAck checks that an entry the pull already
// reports at ack starts with the started callback: repeating the ack would be a
// non-terminal self-edge the control plane answers 409.
func TestDispatcher_AckedEntrySkipsAck(t *testing.T) {
	d, _, reporter := newTestDispatcher(t, Config{})
	entry := pendingExec("exec-acked", "test.echo")
	entry.Status = api.ExecutionStatusAck

	d.Handle(context.Background(), snapshot(entry))

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 2
	})
	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})
}

// TestDispatcher_UnexpectedStatus checks the defensive branch: an entry whose
// status is outside the pull roster is settled without a callback rather than
// retried forever. The disabled node takes the same branch: driving a status the
// node cannot place through a rejection walk would guess a transition path from
// an unknown state, which the control plane answers 409.
func TestDispatcher_UnexpectedStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{name: "actions enabled", cfg: Config{}},
		{name: "actions disabled", cfg: Config{Enabled: boolPtr(false)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, reporter := newTestDispatcher(t, tc.cfg)
			entry := pendingExec("exec-weird", "test.echo")
			entry.Status = "queued"

			d.Handle(context.Background(), snapshot(entry))

			if cbs := reporter.getCallbacks(); len(cbs) != 0 {
				t.Errorf("callbacks = %v, want none", cbs)
			}
			if _, settled := d.handled[entry.ExecutionID]; !settled {
				t.Error("entry with an unexpected status was not marked handled")
			}
		})
	}
}

// TestDispatcher_MissingExecutionID checks that an entry without an id is
// dropped. It has no callback route, and every such entry would collapse onto
// the same active and handled slot.
func TestDispatcher_MissingExecutionID(t *testing.T) {
	d, exec, reporter := newTestDispatcher(t, Config{})
	entry := pendingExec("", "test.echo")

	d.Handle(context.Background(), snapshot(entry))

	if cbs := reporter.getCallbacks(); len(cbs) != 0 {
		t.Errorf("callbacks = %v, want none", cbs)
	}
	if len(d.handled) != 0 {
		t.Errorf("handled = %v, want empty", d.handled)
	}
	if got := exec.ActiveCount(); got != 0 {
		t.Errorf("active count = %d, want 0", got)
	}
}

// TestDispatcher_MissingExpiresAt checks that a missing deadline is called out
// rather than folded into the lapsed branch: the zero time is never after now,
// so a control plane that stops sending expires_at would otherwise silently
// discard every dispatch on the fleet.
func TestDispatcher_MissingExpiresAt(t *testing.T) {
	d, exec, reporter := newTestDispatcher(t, Config{})
	entry := pendingExec("exec-no-deadline", "test.echo")
	entry.ExpiresAt = time.Time{}

	d.Handle(context.Background(), snapshot(entry))

	if cbs := reporter.getCallbacks(); len(cbs) != 0 {
		t.Errorf("callbacks = %v, want none", cbs)
	}
	if _, settled := d.handled[entry.ExecutionID]; !settled {
		t.Error("entry without an expires_at was not marked handled")
	}
	if got := exec.ActiveCount(); got != 0 {
		t.Errorf("active count = %d, want 0", got)
	}
}

// TestDispatcher_ActiveRunSurvivesHandledPrune checks that a run in flight is
// never reported lost. A block that transiently omits an entry prunes its id
// from the settled set, and the executor — not that set — is what knows the run
// is still going.
func TestDispatcher_ActiveRunSurvivesHandledPrune(t *testing.T) {
	reporter := &mockReporter{}
	exec := newTestExecutor(Config{
		MaxConcurrent:    1,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   DefaultMaxOutputBytes,
	}, reporter, &mockVerifier{ok: true})

	// A buffered signal rather than a close: a second run must fail the
	// assertion below, not panic the test process.
	started := make(chan struct{}, 2)
	block := make(chan struct{})
	exec.RegisterBuiltin("slow", "Slow action", nil, func(ctx context.Context, _ map[string]string) (string, string, int, error) {
		started <- struct{}{}
		select {
		case <-block:
		case <-ctx.Done():
		}
		return "done", "", 0, nil
	})

	d := NewDispatcher(exec, "node-1", testLogger())
	entry := pendingExec("exec-inflight", "slow")

	d.Handle(context.Background(), snapshot(entry))
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("action did not start")
	}

	// The control plane serves a pull without the block populated, which prunes
	// the settled id, and then serves the entry again at started.
	d.Handle(context.Background(), snapshot())
	entry.Status = api.ExecutionStatusStarted
	d.Handle(context.Background(), snapshot(entry))

	if got := countStatus(reporter.getCallbacks(), api.ExecutionStatusFailed); got != 0 {
		t.Errorf("failed callbacks = %d, want 0 for a run still in flight", got)
	}

	close(block)
	waitFor(t, 5*time.Second, func() bool {
		return exec.ActiveCount() == 0
	})
	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})
	if got := len(started); got != 0 {
		t.Errorf("the action started %d extra times, want 0", got)
	}
}

// TestDispatcher_BudgetStopsThePass checks that the pass stops once its budget
// is spent instead of walking the rest of a control-plane-sized block on the
// reconcile goroutine. The entries it never reached must stay unsettled so the
// next pull redelivers them.
func TestDispatcher_BudgetStopsThePass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reporter := &cancelingReporter{cancel: cancel}
	cfg := Config{Enabled: boolPtr(false)}
	cfg.ApplyDefaults()
	exec := NewExecutor(cfg, reporter, &mockVerifier{ok: true}, testLogger())
	d := NewDispatcher(exec, "node-1", testLogger())

	first := pendingExec("exec-first", "test.echo")
	second := pendingExec("exec-second", "test.echo")

	d.Handle(ctx, snapshot(first, second))

	if _, settled := d.handled[first.ExecutionID]; !settled {
		t.Error("the first entry was not settled")
	}
	if _, settled := d.handled[second.ExecutionID]; settled {
		t.Error("an entry the pass never reached was marked settled")
	}
	if got := countStatus(reporter.getCallbacks(), api.ExecutionStatusFailed); got != 1 {
		t.Errorf("failed callbacks = %d, want exactly the first entry's", got)
	}
}

// cancelingReporter cancels the pass context as soon as the first callback
// lands, standing in for a control plane that eats the whole dispatch budget.
type cancelingReporter struct {
	mockReporter
	cancel context.CancelFunc
}

func (r *cancelingReporter) ExecutionCallback(ctx context.Context, nodeID, executionID string, req api.ExecutionCallbackRequest) (*api.ExecutionCallbackResponse, error) {
	resp, err := r.mockReporter.ExecutionCallback(ctx, nodeID, executionID, req)
	r.cancel()
	return resp, err
}

// TestDispatcher_BudgetReservesTheCostliestSettlement checks that the pass stops
// starting entries once less than one whole settlement of the budget is left.
// The budget is a wall-clock gate taken before an entry starts and nothing
// clamps an entry that already passed it, so without the reservation a single
// rejection walk — three legs of dispatchCallbackTimeout — carries the pass a
// full settlement past the budget. Handle runs inline on the reconcile
// goroutine, so that overshoot is time peer, policy, and bridge convergence
// spend waiting.
func TestDispatcher_BudgetReservesTheCostliestSettlement(t *testing.T) {
	// The first entry's three-leg rejection walk is stretched just past the
	// window in which entries may still start — what the budget holds beyond the
	// reservation — so the second entry is the one the reservation refuses.
	startWindow := dispatchBudget - maxSettlementCost
	reporter := &mockReporter{callbackDelay: (startWindow + 300*time.Millisecond) / 3}
	exec := newTestExecutor(Config{Enabled: boolPtr(false)}, reporter, &mockVerifier{ok: true})
	d := NewDispatcher(exec, "node-1", testLogger())

	first := pendingExec("exec-first", "test.echo")
	second := pendingExec("exec-second", "test.echo")

	d.Handle(context.Background(), snapshot(first, second))

	if _, settled := d.handled[first.ExecutionID]; !settled {
		t.Error("the first entry was not settled")
	}
	if _, settled := d.handled[second.ExecutionID]; settled {
		t.Error("an entry the remaining budget could not cover was started")
	}
	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusFailed,
	})
}

// TestDispatcher_RejectionUnsettledOnTransientFailure checks that a rejection
// walk cut short by a transient failure leaves the entry unsettled. Marking it
// settled would strand the execution — the walk delivered no terminal, and the
// dispatcher would skip the entry for the life of the process.
func TestDispatcher_RejectionUnsettledOnTransientFailure(t *testing.T) {
	reporter := &mockReporter{
		statusErrs:      map[string]error{api.ExecutionStatusStarted: errors.New("connection reset")},
		statusErrBudget: map[string]int{api.ExecutionStatusStarted: 1},
	}
	exec := newTestExecutor(Config{Enabled: boolPtr(false)}, reporter, &mockVerifier{ok: true})
	d := NewDispatcher(exec, "node-1", testLogger())
	entry := pendingExec("exec-reject-transient", "test.echo")

	d.Handle(context.Background(), snapshot(entry))

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
	})
	if _, settled := d.handled[entry.ExecutionID]; settled {
		t.Fatal("an unresolved execution was marked settled")
	}

	// The next pull redelivers the entry, which now walks from the status the
	// control plane recorded.
	entry.Status = api.ExecutionStatusAck
	d.Handle(context.Background(), snapshot(entry))

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusStarted,
		api.ExecutionStatusFailed,
	})
	if got := cbs[len(cbs)-1].Error; got != "actions_disabled" {
		t.Errorf("failed error = %q, want %q", got, "actions_disabled")
	}
	if _, settled := d.handled[entry.ExecutionID]; !settled {
		t.Error("the completed rejection did not settle the entry")
	}
}

// cancelHarness is a dispatcher over an executor carrying test.block, a
// builtin that runs until its context ends or the test opens release.
type cancelHarness struct {
	d        *Dispatcher
	exec     *Executor
	reporter *mockReporter
	started  chan struct{}
	release  *latch
}

// newCancelHarness builds a cancelHarness whose dispatcher logs to logger.
func newCancelHarness(t *testing.T, logger *slog.Logger) *cancelHarness {
	t.Helper()
	h := &cancelHarness{
		reporter: &mockReporter{},
		started:  make(chan struct{}, 4),
		release:  newLatch(t),
	}
	h.exec = newTestExecutor(Config{}, h.reporter, &mockVerifier{ok: true})
	h.exec.RegisterBuiltin("test.block", "Blocking action", nil, blockingBuiltin(h.started, h.release.ch))
	h.exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return "hello", "", 0, nil
	})
	h.d = NewDispatcher(h.exec, "node-1", logger)
	return h
}

// startRun dispatches a pending test.block entry under id and returns it as
// the control plane serves it once the run has started.
func (h *cancelHarness) startRun(t *testing.T, id string) api.NodeStateExecution {
	t.Helper()
	entry := pendingExec(id, "test.block")
	h.d.Handle(context.Background(), snapshot(entry))
	waitStarted(t, h.started)
	entry.Status = api.ExecutionStatusStarted
	return entry
}

// withCancelRequest returns entry carrying the mark the control plane sets
// once an operator cancelled the Execution. plexd never compares its value
// with its own clock, so a fixed instant will do.
func withCancelRequest(entry api.NodeStateExecution) api.NodeStateExecution {
	at := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	entry.CancelRequestedAt = &at
	return entry
}

func TestDispatcher_CancelForwardedToRunningEntry(t *testing.T) {
	h := newCancelHarness(t, testLogger())
	entry := h.startRun(t, "exec-cancel")

	h.d.Handle(context.Background(), snapshot(withCancelRequest(entry)))
	waitFor(t, 5*time.Second, func() bool {
		return h.exec.ActiveCount() == 0
	})

	// The run reports the stop itself. The dispatcher sends nothing, and above
	// all no failed report for a run it stopped.
	assertStatuses(t, h.reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusCancelled,
	})
}

// orderingReporter is a mockReporter whose callbacks for one execution wait
// until another has left the executor. It lets a test make a pass reach a
// later entry only once a run the same pass stopped is gone.
type orderingReporter struct {
	mockReporter
	exec      *Executor
	held      string
	untilGone string
}

func (r *orderingReporter) ExecutionCallback(ctx context.Context, nodeID, executionID string, req api.ExecutionCallbackRequest) (*api.ExecutionCallbackResponse, error) {
	if executionID == r.held {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for r.exec.IsActive(r.untilGone) {
			select {
			case <-tick.C:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return r.mockReporter.ExecutionCallback(ctx, nodeID, executionID, req)
}

// A pull that briefly omits an entry prunes its settled id. When the entry
// comes back carrying a cancel request, the stopped run can leave the executor
// before the pass reaches the entry, and the pass must not then report it lost
// to a restart on top of the cancelled report the run sent.
func TestDispatcher_CancelledRunNotReportedLostAfterPrune(t *testing.T) {
	reporter := &orderingReporter{held: "exec-next", untilGone: "exec-cancel"}
	cfg := Config{}
	cfg.ApplyDefaults()
	exec := NewExecutor(cfg, reporter, &mockVerifier{ok: true}, testLogger())
	reporter.exec = exec
	started := make(chan struct{}, 1)
	exec.RegisterBuiltin("test.block", "Blocking action", nil, blockingBuiltin(started, newLatch(t).ch))
	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return "hello", "", 0, nil
	})
	d := NewDispatcher(exec, "node-1", testLogger())

	running := pendingExec("exec-cancel", "test.block")
	d.Handle(context.Background(), snapshot(running))
	waitStarted(t, started)
	d.Handle(context.Background(), snapshot())

	// exec-next comes first in the block, and its claim waits until the stopped
	// run has left the executor, so the pass reaches exec-cancel with no run
	// behind it.
	running.Status = api.ExecutionStatusStarted
	next := pendingExec("exec-next", "test.echo")
	d.Handle(context.Background(), snapshot(next, withCancelRequest(running)))
	waitFor(t, 5*time.Second, func() bool {
		return exec.ActiveCount() == 0
	})

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusCancelled,
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})
}

// The control plane never serves a waiting entry with a cancel request, since
// it ends such a target itself. One that arrives anyway is never started, and
// with actions disabled it is not walked to failed either: both would be
// answered execution_already_terminal.
func TestDispatcher_CancelRequestOnWaitingEntryNeverStarts(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{name: "actions enabled", cfg: Config{}},
		{name: "actions disabled", cfg: Config{Enabled: boolPtr(false)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, exec, reporter := newTestDispatcher(t, tc.cfg)
			pending := withCancelRequest(pendingExec("exec-pending", "test.echo"))
			acked := withCancelRequest(pendingExec("exec-acked", "test.echo"))
			acked.Status = api.ExecutionStatusAck

			d.Handle(context.Background(), snapshot(pending, acked))

			if cbs := reporter.getCallbacks(); len(cbs) != 0 {
				t.Errorf("callbacks = %v, want none", cbs)
			}
			if got := exec.ActiveCount(); got != 0 {
				t.Errorf("active count = %d, want 0", got)
			}
			for _, id := range []string{pending.ExecutionID, acked.ExecutionID} {
				if _, settled := d.handled[id]; !settled {
					t.Errorf("%s was not marked handled", id)
				}
			}
		})
	}
}

// A started entry whose run this process does not hold is the agent restart
// case, cancel request or not: this process stopped nothing, so the contract's
// cancelled does not fit, and the run is reported lost.
func TestDispatcher_CancelRequestForRunNotHeldReportedLost(t *testing.T) {
	d, _, reporter := newTestDispatcher(t, Config{})
	entry := withCancelRequest(pendingExec("exec-lost", "test.echo"))
	entry.Status = api.ExecutionStatusStarted

	d.Handle(context.Background(), snapshot(entry))

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{api.ExecutionStatusFailed})
	if cbs[0].Error != orphanedRunError {
		t.Errorf("terminal error = %q, want %q", cbs[0].Error, orphanedRunError)
	}
	if _, forwarded := d.cancelled[entry.ExecutionID]; forwarded {
		t.Error("a cancel the executor had no run for was recorded as forwarded")
	}
}

// The cancel is forwarded while the block's ids are collected, so a pass that
// stops on its budget, here at the first entry, still stops the run.
func TestDispatcher_CancelForwardedUnderSpentBudget(t *testing.T) {
	h := newCancelHarness(t, testLogger())
	running := h.startRun(t, "exec-cancel")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fresh := pendingExec("exec-fresh", "test.echo")
	h.d.Handle(ctx, snapshot(fresh, withCancelRequest(running)))
	waitFor(t, 5*time.Second, func() bool {
		return h.exec.ActiveCount() == 0
	})

	assertStatuses(t, h.reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusCancelled,
	})
	if _, settled := h.d.handled[fresh.ExecutionID]; settled {
		t.Error("the entry the spent pass never reached was marked handled")
	}
}

func TestDispatcher_RunWithoutCancelRequestKeepsRunning(t *testing.T) {
	h := newCancelHarness(t, testLogger())
	running := h.startRun(t, "exec-running")

	h.d.Handle(context.Background(), snapshot(running))

	if !h.exec.IsActive(running.ExecutionID) {
		t.Fatal("the run left the executor without a cancel request")
	}
	h.release.open()
	waitFor(t, 5*time.Second, func() bool {
		return h.exec.ActiveCount() == 0
	})
	assertStatuses(t, h.reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})
}

func TestDispatcher_DrainPrunesCancelled(t *testing.T) {
	h := newCancelHarness(t, testLogger())
	entry := withCancelRequest(h.startRun(t, "exec-cancel"))

	h.d.Handle(context.Background(), snapshot(entry))
	waitFor(t, 5*time.Second, func() bool {
		return h.exec.ActiveCount() == 0
	})
	if _, forwarded := h.d.cancelled[entry.ExecutionID]; !forwarded {
		t.Fatal("the forwarded cancel was not recorded")
	}

	h.d.Handle(context.Background(), snapshot())

	if _, ok := h.d.cancelled[entry.ExecutionID]; ok {
		t.Error("cancelled still holds the drained id")
	}
	if _, ok := h.d.handled[entry.ExecutionID]; ok {
		t.Error("handled still holds the drained id")
	}
	if _, ok := h.d.deferrals[entry.ExecutionID]; ok {
		t.Error("deferrals still holds the drained id")
	}
}
