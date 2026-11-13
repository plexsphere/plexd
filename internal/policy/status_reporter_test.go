package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

var _ StatusClient = (*api.ControlPlane)(nil)

const testStatusNodeID = "node-1"

// errBlockUntilDone makes fakeStatusClient block a call until its context
// ends, like a control plane that does not answer.
var errBlockUntilDone = errors.New("block until the context is done")

// fakeStatusClient records every report and answers the n-th with errs[n]
// when that is set, and with a receipt otherwise. It also tracks how many
// calls run at once.
type fakeStatusClient struct {
	mu          sync.Mutex
	nodeIDs     []string
	requests    []api.PolicyStatusRequest
	errs        map[int]error
	inFlight    int
	maxInFlight int

	// gate, when set, holds the first call open until the test closes it.
	gate chan struct{}
}

func (c *fakeStatusClient) ReportPolicyStatus(ctx context.Context, nodeID string, req api.PolicyStatusRequest) (*api.PolicyStatusResponse, error) {
	c.mu.Lock()
	idx := len(c.requests)
	c.nodeIDs = append(c.nodeIDs, nodeID)
	c.requests = append(c.requests, req)
	err := c.errs[idx]
	c.inFlight++
	c.maxInFlight = max(c.maxInFlight, c.inFlight)
	gate := c.gate
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.inFlight--
		c.mu.Unlock()
	}()
	if idx == 0 && gate != nil {
		<-gate
	}
	switch {
	case errors.Is(err, errBlockUntilDone):
		<-ctx.Done()
		return nil, ctx.Err()
	case err != nil:
		return nil, err
	}
	return &api.PolicyStatusResponse{AcceptedAt: time.Now(), Status: "applied"}, nil
}

func (c *fakeStatusClient) recorded() []api.PolicyStatusRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]api.PolicyStatusRequest(nil), c.requests...)
}

func (c *fakeStatusClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

// countingBackend is a mockFirewallController whose drop counts the test
// moves while the reporter reads them.
type countingBackend struct {
	mockFirewallController

	mu             sync.Mutex
	packets, bytes uint64
}

func (b *countingBackend) DropCounts(string) (uint64, uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.packets, b.bytes, nil
}

func (b *countingBackend) set(packets, bytes uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.packets, b.bytes = packets, bytes
}

// startStatusReporter runs r until the returned stop is called, or the test
// ends. stop cancels Run and fails the test unless Run returns nil.
func startStatusReporter(t *testing.T, r *StatusReporter) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("Run() = %v, want nil", err)
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func mustJSONString(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal(%+v): %v", v, err)
	}
	return string(data)
}

func TestBuildPolicyStatusRequest(t *testing.T) {
	applied := statusBlock("fp-a", "rev-a")
	rejected := deniedBlock("fp-deny")

	tests := []struct {
		name           string
		status         Status
		packets, bytes uint64
		counted        bool
		want           string
	}{
		{
			name:   "disabled",
			status: Status{Enforcement: api.PolicyEnforcementDisabled, Synced: true},
			want:   `{"enforcement":"disabled"}`,
		},
		{
			name:   "applied null pull",
			status: Status{Enforcement: api.PolicyEnforcementEnforcing, Synced: true, HasApplied: true},
			want:   `{"enforcement":"enforcing","applied":{"revisions":[]}}`,
		},
		{
			name:   "applied block",
			status: Status{Enforcement: api.PolicyEnforcementEnforcing, Synced: true, HasApplied: true, Applied: applied},
			want:   `{"enforcement":"enforcing","applied":{"fingerprint":"fp-a","revisions":[{"policy_id":"pol-1","revision_id":"rev-a"}]}}`,
		},
		{
			name:   "applied block without a fingerprint",
			status: Status{Enforcement: api.PolicyEnforcementEnforcing, Synced: true, HasApplied: true, Applied: statusBlock("", "rev-a")},
			want:   `{"enforcement":"enforcing"}`,
		},
		{
			name:   "applied block without revisions",
			status: Status{Enforcement: api.PolicyEnforcementEnforcing, Synced: true, HasApplied: true, Applied: &api.PolicySnapshot{Fingerprint: "fp-old"}},
			want:   `{"enforcement":"enforcing","applied":{"fingerprint":"fp-old","revisions":[]}}`,
		},
		{
			name: "rejected",
			status: Status{
				Enforcement: api.PolicyEnforcementEnforcing, Synced: true, HasApplied: true, Applied: applied,
				Rejected: rejected, Reason: "policy: rule 0: unsupported action", Attempts: 2,
			},
			want: `{"enforcement":"enforcing","applied":{"fingerprint":"fp-a","revisions":[{"policy_id":"pol-1","revision_id":"rev-a"}]},` +
				`"rejected":{"fingerprint":"fp-deny","revisions":[{"policy_id":"pol-1","revision_id":"rev-deny"}],"reason":"policy: rule 0: unsupported action"}}`,
		},
		{
			name:    "counts not counted",
			status:  Status{Enforcement: api.PolicyEnforcementEnforcing, Synced: true},
			packets: 5, bytes: 500,
			want: `{"enforcement":"enforcing"}`,
		},
		{
			name:    "counted drops",
			status:  Status{Enforcement: api.PolicyEnforcementEnforcing, Synced: true},
			packets: 5, bytes: 500, counted: true,
			want: `{"enforcement":"enforcing","drops":{"packets":5,"bytes":500}}`,
		},
		{
			name:    "counters above MaxInt64 are capped",
			status:  Status{Enforcement: api.PolicyEnforcementEnforcing, Synced: true},
			packets: math.MaxUint64, bytes: math.MaxInt64 + 1, counted: true,
			want: fmt.Sprintf(`{"enforcement":"enforcing","drops":{"packets":%d,"bytes":%d}}`, int64(math.MaxInt64), int64(math.MaxInt64)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustJSONString(t, buildPolicyStatusRequest(tt.status, tt.packets, tt.bytes, tt.counted))
			if got != tt.want {
				t.Errorf("request =\n  %s\nwant\n  %s", got, tt.want)
			}
		})
	}
}

func TestNewStatusReporter_NonPositiveIntervalRunsAtDefault(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		r := NewStatusReporter(interval, testStatusNodeID, &fakeStatusClient{}, newEnabledEnforcer(nil), testLogger())
		if r.interval != 30*time.Second {
			t.Errorf("interval for %v = %v, want 30s", interval, r.interval)
		}
	}
}

func TestStatusReporter_NothingBeforeTheFirstSync(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnabledEnforcer(&mockFirewallController{})
		client := &fakeStatusClient{}
		startStatusReporter(t, NewStatusReporter(time.Minute, testStatusNodeID, client, e, testLogger()))

		time.Sleep(3 * time.Minute)
		synctest.Wait()
		if n := client.calls(); n != 0 {
			t.Fatalf("reports before the first Sync = %d, want 0", n)
		}

		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		synctest.Wait()
		reqs := client.recorded()
		if len(reqs) != 1 {
			t.Fatalf("reports after the first Sync = %d, want 1", len(reqs))
		}
		if got := client.nodeIDs[0]; got != testStatusNodeID {
			t.Errorf("node ID = %q, want %q", got, testStatusNodeID)
		}
		if reqs[0].Applied == nil || reqs[0].Applied.Fingerprint != "fp-a" {
			t.Errorf("report = %s, want fp-a applied", mustJSONString(t, reqs[0]))
		}
	})
}

func TestStatusReporter_ReportsEachChangeAndNothingWhileQuiet(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnabledEnforcer(&mockFirewallController{})
		client := &fakeStatusClient{}
		startStatusReporter(t, NewStatusReporter(time.Minute, testStatusNodeID, client, e, testLogger()))

		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		synctest.Wait()
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		if n := client.calls(); n != 1 {
			t.Fatalf("reports after five quiet intervals = %d, want 1", n)
		}

		e.Sync(statusBlock("fp-b", "rev-b"), "wg0")
		synctest.Wait()
		e.Sync(statusBlock("fp-b", "rev-b"), "wg0")
		synctest.Wait()
		e.Sync(deniedBlock("fp-deny"), "wg0")
		synctest.Wait()

		reqs := client.recorded()
		if len(reqs) != 3 {
			t.Fatalf("reports = %d, want 3 (one per change)", len(reqs))
		}
		if reqs[1].Applied == nil || reqs[1].Applied.Fingerprint != "fp-b" || reqs[1].Rejected != nil {
			t.Errorf("second report = %s, want fp-b applied", mustJSONString(t, reqs[1]))
		}
		if reqs[2].Rejected == nil || reqs[2].Rejected.Fingerprint != "fp-deny" || reqs[2].Applied.Fingerprint != "fp-b" {
			t.Errorf("third report = %s, want fp-deny rejected over fp-b", mustJSONString(t, reqs[2]))
		}
	})
}

func TestStatusReporter_TickSendsMovedCountersAndRetriesFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		backend := &countingBackend{packets: 1, bytes: 40}
		e := newEnabledEnforcer(backend)
		client := &fakeStatusClient{errs: map[int]error{
			2: &api.APIError{StatusCode: 503, Code: "datastore_unavailable"},
			4: fmt.Errorf("api: request: %w", context.DeadlineExceeded),
		}}
		logger, logs := recordingLogger()
		startStatusReporter(t, NewStatusReporter(time.Minute, testStatusNodeID, client, e, logger))

		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		synctest.Wait()
		time.Sleep(time.Minute + time.Second)
		synctest.Wait()
		if n := client.calls(); n != 1 {
			t.Fatalf("reports after a tick with unmoved counters = %d, want 1", n)
		}

		backend.set(2, 80)
		time.Sleep(time.Minute)
		synctest.Wait()
		reqs := client.recorded()
		if len(reqs) != 2 || reqs[1].Drops == nil || reqs[1].Drops.Packets != 2 || reqs[1].Drops.Bytes != 80 {
			t.Fatalf("reports = %d, last %s; want 2 with drops 2/80", len(reqs), mustJSONString(t, reqs[len(reqs)-1]))
		}
		if got := logs.count(`level=DEBUG msg="policy status: reported"`); got != 1 {
			t.Errorf("Debug report lines = %d, want 1 for the counters-only report", got)
		}

		// Call 2 answers 503; call 3, on the next tick, sends the same
		// report again, though nothing moved since, and is accepted.
		backend.set(3, 120)
		time.Sleep(time.Minute)
		synctest.Wait()
		time.Sleep(time.Minute)
		synctest.Wait()
		if n := client.calls(); n != 4 {
			t.Fatalf("reports = %d, want 4 (a 503 is repeated on the next tick)", n)
		}

		// Call 4 fails with a deadline; call 5 repeats it on the next tick.
		backend.set(4, 160)
		time.Sleep(time.Minute)
		synctest.Wait()
		time.Sleep(time.Minute)
		synctest.Wait()
		reqs = client.recorded()
		if len(reqs) != 6 {
			t.Fatalf("reports = %d, want 6 (a deadline is repeated on the next tick)", len(reqs))
		}
		if got, want := mustJSONString(t, reqs[5]), mustJSONString(t, reqs[4]); got != want {
			t.Errorf("repeated report = %s, want the failed one %s", got, want)
		}

		time.Sleep(3 * time.Minute)
		synctest.Wait()
		if n := client.calls(); n != 6 {
			t.Errorf("reports after an accepted retry and quiet ticks = %d, want 6", n)
		}
		if got := logs.count(`level=WARN msg="policy status: send failed"`); got != 2 {
			t.Errorf("send failure lines = %d, want 2", got)
		}
	})
}

func TestStatusReporter_NotServedStopsReporting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnabledEnforcer(&mockFirewallController{})
		client := &fakeStatusClient{errs: map[int]error{0: &api.APIError{StatusCode: 404, Code: "not_found"}}}
		logger, logs := recordingLogger()
		startStatusReporter(t, NewStatusReporter(time.Minute, testStatusNodeID, client, e, logger))

		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		synctest.Wait()
		e.Sync(statusBlock("fp-b", "rev-b"), "wg0")
		synctest.Wait()
		time.Sleep(3 * time.Minute)
		synctest.Wait()

		if n := client.calls(); n != 1 {
			t.Errorf("reports = %d, want 1 (no report after the control plane said it has no route)", n)
		}
		if got := logs.count(`level=INFO msg="policy status: control plane does not accept policy status reports, not reporting until restart"`); got != 1 {
			t.Errorf("not-served lines = %d, want 1", got)
		}
	})
}

func TestStatusReporter_NotProvisionedRetriesEveryInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		notProvisioned := &api.APIError{StatusCode: 501, Code: "policy_status_not_provisioned"}
		e := newEnabledEnforcer(&mockFirewallController{})
		client := &fakeStatusClient{errs: map[int]error{0: notProvisioned, 1: notProvisioned, 2: notProvisioned}}
		logger, logs := recordingLogger()
		startStatusReporter(t, NewStatusReporter(time.Minute, testStatusNodeID, client, e, logger))

		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		synctest.Wait()
		for range 3 {
			time.Sleep(time.Minute)
			synctest.Wait()
		}

		if n := client.calls(); n != 4 {
			t.Errorf("reports = %d, want 4 (one per tick until accepted)", n)
		}
		if got := logs.count(`msg="policy status: control plane has not provisioned policy status reports, retrying every interval"`); got != 1 {
			t.Errorf("not-provisioned lines = %d, want 1", got)
		}
		if got := logs.count(`level=INFO msg="policy status: control plane accepts policy status reports"`); got != 1 {
			t.Errorf("accepts lines = %d, want 1", got)
		}
	})
}

func TestStatusReporter_LogLevels(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodeGone := &api.APIError{StatusCode: 404, Code: "policy_status_node_gone"}
		e := newEnabledEnforcer(&mockFirewallController{})
		client := &fakeStatusClient{errs: map[int]error{
			0: fmt.Errorf("api: heartbeat: %w", api.ErrCredentialRefused),
			1: nodeGone,
			2: nodeGone,
		}}
		logger, logs := recordingLogger()
		startStatusReporter(t, NewStatusReporter(time.Minute, testStatusNodeID, client, e, logger))

		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		synctest.Wait()
		for range 2 {
			time.Sleep(time.Minute)
			synctest.Wait()
		}

		if got := logs.count(`level=DEBUG msg="policy status: send failed"`); got != 1 {
			t.Errorf("Debug lines for a refused credential = %d, want 1", got)
		}
		if got := logs.count(`level=WARN msg="policy status: rejected, this node was removed"`); got != 2 {
			t.Errorf("node-gone Warn lines = %d, want 2 (one per send)", got)
		}
	})
}

func TestStatusReporter_CancelledSendIsNotLogged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnabledEnforcer(&mockFirewallController{})
		client := &fakeStatusClient{errs: map[int]error{0: errBlockUntilDone}}
		logger, logs := recordingLogger()
		stop := startStatusReporter(t, NewStatusReporter(time.Minute, testStatusNodeID, client, e, logger))

		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		synctest.Wait()
		stop()

		if got := logs.count(`msg="policy status: send failed"`); got != 0 {
			t.Errorf("send failure lines = %d after a cancelled send, want 0", got)
		}
	})
}

// A change the Enforcer signals while a report is in flight waits for it:
// the reporter sends one report at a time, so two never race at the control
// plane, which keeps the last one to arrive.
func TestStatusReporter_OneReportInFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnabledEnforcer(&mockFirewallController{})
		client := &fakeStatusClient{gate: make(chan struct{})}
		startStatusReporter(t, NewStatusReporter(time.Minute, testStatusNodeID, client, e, testLogger()))

		e.Sync(statusBlock("fp-a", "rev-a"), "wg0")
		synctest.Wait()
		e.Sync(statusBlock("fp-b", "rev-b"), "wg0")
		synctest.Wait()
		if n := client.calls(); n != 1 {
			t.Fatalf("reports started while the first is held = %d, want 1", n)
		}

		close(client.gate)
		synctest.Wait()
		reqs := client.recorded()
		if len(reqs) != 2 || reqs[1].Applied == nil || reqs[1].Applied.Fingerprint != "fp-b" {
			t.Fatalf("reports = %d, want 2 with fp-b last once the first returned", len(reqs))
		}
		client.mu.Lock()
		defer client.mu.Unlock()
		if client.maxInFlight != 1 {
			t.Errorf("reports in flight at once = %d, want 1", client.maxInFlight)
		}
	})
}

func TestStatusReporter_StopsWithoutALastReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnabledEnforcer(&mockFirewallController{})
		client := &fakeStatusClient{}
		stop := startStatusReporter(t, NewStatusReporter(time.Minute, testStatusNodeID, client, e, testLogger()))

		for _, fp := range []string{"fp-a", "fp-b", "fp-c", "fp-d"} {
			e.Sync(statusBlock(fp, "rev"), "wg0")
		}
		synctest.Wait()
		before := client.calls()
		stop()

		if n := client.calls(); n != before {
			t.Errorf("reports = %d after stop, want %d (no shutdown report)", n, before)
		}
	})
}
