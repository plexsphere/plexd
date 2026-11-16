package bridge

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The composition root hands the reporter the control-plane client; this
// assertion keeps the seam satisfiable by it.
var _ IngressStatusClient = (*api.ControlPlane)(nil)

const testIngressNodeID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c2"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fakeIngressStatusClient records every report it is handed and answers the
// n-th with errs[n] when that is set, and with a receipt at testAcceptedAt
// otherwise.
type fakeIngressStatusClient struct {
	mu       sync.Mutex
	nodeIDs  []string
	requests []api.IngressStatusRequest
	errs     []error
}

func (c *fakeIngressStatusClient) ReportIngressStatus(_ context.Context, nodeID string, req api.IngressStatusRequest) (*api.IngressStatusResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := len(c.requests)
	c.nodeIDs = append(c.nodeIDs, nodeID)
	c.requests = append(c.requests, req)
	if idx < len(c.errs) && c.errs[idx] != nil {
		return nil, c.errs[idx]
	}
	return &api.IngressStatusResponse{AcceptedAt: testAcceptedAt}, nil
}

func (c *fakeIngressStatusClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *fakeIngressStatusClient) recorded() (nodeIDs []string, reqs []api.IngressStatusRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.nodeIDs), slices.Clone(c.requests)
}

// startIngressStatusReporter runs r.Run in a goroutine and returns a stop
// function that cancels it and waits for Run to return nil. The stop is also
// registered as a cleanup, so a failed assertion does not leave the goroutine
// behind, which a synctest bubble would report as a deadlock.
func startIngressStatusReporter(t *testing.T, r *IngressStatusReporter) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run() = %v, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("Run did not return within 5s of the context being cancelled")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// ---------------------------------------------------------------------------
// Construction and Run
// ---------------------------------------------------------------------------

// The reporter's timing runs on synctest's fake clock: synctest.Wait returns
// once Run blocks on its ticker again, so every count below is exact and no
// assertion waits on the wall clock.

func TestIngressStatusReporter_SendsItsStateAtStart(t *testing.T) {
	for _, tc := range []struct {
		optedOut bool
		want     string
	}{
		{optedOut: false, want: api.IngressStateEnabled},
		{optedOut: true, want: api.IngressStateOptedOut},
	} {
		t.Run(tc.want, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := &fakeIngressStatusClient{}
				logger, logs := newRelayLogger()
				r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, tc.optedOut, nil, logger)

				startIngressStatusReporter(t, r)
				synctest.Wait()

				nodeIDs, reqs := client.recorded()
				if len(reqs) != 1 {
					t.Fatalf("reports before the first tick = %d, want exactly 1", len(reqs))
				}
				if reqs[0].State != tc.want {
					t.Errorf("State = %q, want %q", reqs[0].State, tc.want)
				}
				if got, want := mustJSON(t, reqs[0]), `{"state":"`+tc.want+`"}`; got != want {
					t.Errorf("body = %s, want %s", got, want)
				}
				if !slices.Equal(nodeIDs, []string{testIngressNodeID}) {
					t.Errorf("node IDs = %v, want [%s]", nodeIDs, testIngressNodeID)
				}
				line := relayLogLine(t, logs, "ingress status: reporter started")
				for _, want := range []string{"level=INFO", "component=bridge", "interval=1h0m0s", "state=" + tc.want} {
					if !strings.Contains(line, want) {
						t.Errorf("started log = %q, want it to contain %q", line, want)
					}
				}
			})
		})
	}
}

func TestIngressStatusReporter_ResendsEveryTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = 10 * time.Millisecond
		client := &fakeIngressStatusClient{}
		r := NewIngressStatusReporter(interval, testIngressNodeID, client, true, nil, discardLogger())

		startIngressStatusReporter(t, r)
		time.Sleep(2*interval + interval/2)
		synctest.Wait()

		_, reqs := client.recorded()
		if len(reqs) < 3 {
			t.Fatalf("reports after two ticks = %d, want at least 3: the one at start and one per tick", len(reqs))
		}
		for k, req := range reqs {
			if req.State != api.IngressStateOptedOut {
				t.Errorf("report %d State = %q, want %q", k, req.State, api.IngressStateOptedOut)
			}
		}
	})
}

func TestNewIngressStatusReporter_NonPositiveIntervalRunsAtDefault(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := &fakeIngressStatusClient{}
				logger, logs := newRelayLogger()

				r := NewIngressStatusReporter(interval, testIngressNodeID, client, false, nil, logger)
				if r.interval != 30*time.Second {
					t.Errorf("interval = %v, want 30s", r.interval)
				}

				startIngressStatusReporter(t, r)
				synctest.Wait()
				line := relayLogLine(t, logs, "ingress status: reporter started")
				if !strings.Contains(line, "interval=30s") {
					t.Errorf("started log = %q, want it to contain %q", line, "interval=30s")
				}

				time.Sleep(30*time.Second - time.Millisecond)
				synctest.Wait()
				if got := client.calls(); got != 1 {
					t.Errorf("reports just before 30s = %d, want 1", got)
				}
				time.Sleep(2 * time.Millisecond)
				synctest.Wait()
				if got := client.calls(); got != 2 {
					t.Errorf("reports just after 30s = %d, want 2", got)
				}
			})
		})
	}
}

func TestIngressStatusReporter_FailedSendIsNotRetriedWithinItsTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		client := &fakeIngressStatusClient{errs: []error{context.DeadlineExceeded}}
		logger, logs := newRelayLogger()
		r := NewIngressStatusReporter(interval, testIngressNodeID, client, false, nil, logger)

		startIngressStatusReporter(t, r)
		synctest.Wait()
		line := relayLogLine(t, logs, "ingress status: send failed")
		for _, want := range []string{"level=WARN", "component=bridge", `error="context deadline exceeded"`} {
			if !strings.Contains(line, want) {
				t.Errorf("send failed log = %q, want it to contain %q", line, want)
			}
		}
		if n := relayLogLines(logs, "ingress status: reported"); n != 0 {
			t.Errorf("reported logged %d times after a failed send, want 0", n)
		}

		time.Sleep(interval - time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != 1 {
			t.Errorf("reports before the tick = %d, want only the failed one", got)
		}

		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Errorf("reports after the tick = %d, want 2", got)
		}
		line = relayLogLine(t, logs, "ingress status: reported")
		for _, want := range []string{"level=INFO", "state=enabled"} {
			if !strings.Contains(line, want) {
				t.Errorf("reported log = %q, want it to contain %q", line, want)
			}
		}
		if n := relayLogLines(logs, "ingress status: send failed"); n != 1 {
			t.Errorf("send failed logged %d times, want 1", n)
		}
	})
}

func TestIngressStatusReporter_NoSendAtShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &fakeIngressStatusClient{}
		r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, true, nil, discardLogger())

		stop := startIngressStatusReporter(t, r)
		synctest.Wait()
		if got := client.calls(); got != 1 {
			t.Fatalf("reports after the start = %d, want 1", got)
		}
		stop()

		if got := client.calls(); got != 1 {
			t.Errorf("reports after the cancel = %d, want still 1: no report at shutdown", got)
		}
	})
}

// ---------------------------------------------------------------------------
// reportOnce
// ---------------------------------------------------------------------------

func TestIngressStatusReporter_NotServedLoggedOnTransitions(t *testing.T) {
	const (
		notServedMsg = "ingress status: control plane does not accept ingress status reports, retrying every interval"
		recoveredMsg = "ingress status: control plane accepts ingress status reports"
		reportedMsg  = "ingress status: reported"
	)
	tests := []struct {
		name     string
		err      *api.APIError
		wantAttr string
	}{
		{name: "404 without code", err: &api.APIError{StatusCode: 404}, wantAttr: `status=404 code=""`},
		{
			name:     "501 ingress_status_not_provisioned",
			err:      &api.APIError{StatusCode: 501, Code: "ingress_status_not_provisioned"},
			wantAttr: "status=501 code=ingress_status_not_provisioned",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeIngressStatusClient{errs: []error{tt.err, tt.err, tt.err}}
			logger, logs := newRelayLogger()
			r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, false, nil, logger)
			ctx := context.Background()

			for range 3 {
				r.reportOnce(ctx)
			}
			if n := client.calls(); n != 3 {
				t.Errorf("reports = %d after three refused sends, want 3", n)
			}
			line := relayLogLine(t, logs, notServedMsg)
			for _, want := range []string{"level=INFO", "component=bridge", tt.wantAttr} {
				if !strings.Contains(line, want) {
					t.Errorf("not-served log = %q, want it to contain %q", line, want)
				}
			}
			for _, msg := range []string{recoveredMsg, reportedMsg} {
				if n := relayLogLines(logs, msg); n != 0 {
					t.Errorf("%q logged %d times before any report was accepted, want 0", msg, n)
				}
			}
			if strings.Contains(logs.String(), "send failed") {
				t.Errorf("a not-served answer was logged as a send failure:\n%s", logs.String())
			}

			r.reportOnce(ctx)
			r.reportOnce(ctx)
			if n := relayLogLines(logs, notServedMsg); n != 1 {
				t.Errorf("not-served logged %d times, want 1", n)
			}
			for _, msg := range []string{recoveredMsg, reportedMsg} {
				line := relayLogLine(t, logs, msg)
				if !strings.Contains(line, "level=INFO") {
					t.Errorf("%q log = %q, want level=INFO", msg, line)
				}
			}
		})
	}
}

func TestIngressStatusReporter_NodeGoneWarnsOnEverySend(t *testing.T) {
	const msg = "ingress status: rejected, this node was removed"
	gone := &api.APIError{StatusCode: 404, Code: "ingress_status_node_gone"}
	client := &fakeIngressStatusClient{errs: []error{gone, gone}}
	logger, logs := newRelayLogger()
	r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, false, nil, logger)

	for range 2 {
		r.reportOnce(context.Background())
	}

	if n := logs.count(`level=WARN msg="` + msg + `" component=bridge code=ingress_status_node_gone`); n != 2 {
		t.Errorf("node gone lines at Warn with the code = %d over two sends, want 2:\n%s", n, logs.String())
	}
	if strings.Contains(logs.String(), "does not accept ingress status reports") {
		t.Errorf("ingress_status_node_gone was logged as not served:\n%s", logs.String())
	}
}

func TestIngressStatusReporter_SendFailuresWarn(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "400 malformed_ingress_status", err: &api.APIError{StatusCode: 400, Code: "malformed_ingress_status"}},
		{name: "413 ingress_status_body_too_large", err: &api.APIError{StatusCode: 413, Code: "ingress_status_body_too_large"}},
		{name: "500", err: &api.APIError{StatusCode: 500, Code: "internal"}},
		{name: "501 for another surface", err: &api.APIError{StatusCode: 501, Code: "relay_status_not_provisioned"}},
		{name: "transport error", err: errors.New("dial tcp: connection refused")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeIngressStatusClient{errs: []error{tt.err}}
			logger, logs := newRelayLogger()
			r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, false, nil, logger)

			r.reportOnce(context.Background())

			if n := client.calls(); n != 1 {
				t.Errorf("reports = %d within one send, want 1 (no retry)", n)
			}
			line := relayLogLine(t, logs, "ingress status: send failed")
			for _, want := range []string{"level=WARN", "error="} {
				if !strings.Contains(line, want) {
					t.Errorf("send failed log = %q, want it to contain %q", line, want)
				}
			}
			if r.notServed {
				t.Error("notServed set by a failure that is not a not-served answer")
			}
		})
	}
}

// While the heartbeat has parked the agent, every send fails locally with
// api.ErrCredentialRefused. The heartbeat names the cause once, so the
// reporter logs the failure at Debug instead of a Warn per send.
func TestIngressStatusReporter_RefusedCredentialLoggedAtDebug(t *testing.T) {
	client := &fakeIngressStatusClient{errs: []error{fmt.Errorf("x: %w", api.ErrCredentialRefused)}}
	logger, logs := newRelayLogger()
	r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, false, nil, logger)

	r.reportOnce(context.Background())

	line := relayLogLine(t, logs, "ingress status: send failed")
	for _, want := range []string{"level=DEBUG", "error="} {
		if !strings.Contains(line, want) {
			t.Errorf("send failed log = %q, want it to contain %q", line, want)
		}
	}
	if got := logs.String(); strings.Contains(got, "level=INFO") || strings.Contains(got, "level=WARN") || strings.Contains(got, "level=ERROR") {
		t.Errorf("logs = %s, want nothing above Debug for a refused credential", got)
	}
}

func TestIngressStatusReporter_CancelledSendIsNotLogged(t *testing.T) {
	client := &fakeIngressStatusClient{errs: []error{context.Canceled}}
	logger, logs := newRelayLogger()
	r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, false, nil, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.reportOnce(ctx)

	if n := client.calls(); n != 1 {
		t.Errorf("reports = %d, want 1", n)
	}
	if got := logs.String(); got != "" {
		t.Errorf("logs = %q, want nothing for a send cut short by shutdown", got)
	}
}

func TestIngressStatusReporter_ReportedOnceAcceptedOnEverySend(t *testing.T) {
	const (
		reportedMsg = "ingress status: reported"
		acceptedMsg = "ingress status: accepted"
	)
	client := &fakeIngressStatusClient{}
	logger, logs := newRelayLogger()
	r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, true, nil, logger)
	ctx := context.Background()

	for range 3 {
		r.reportOnce(ctx)
	}

	line := relayLogLine(t, logs, reportedMsg)
	for _, want := range []string{"level=INFO", "component=bridge", "state=opted_out"} {
		if !strings.Contains(line, want) {
			t.Errorf("reported log = %q, want it to contain %q", line, want)
		}
	}
	if n := logs.count(`level=DEBUG msg="` + acceptedMsg + `" component=bridge state=opted_out rules=0 accepted_at=2026-10-30T10:15:30.123Z`); n != 3 {
		t.Errorf("accepted lines at Debug with the state, the rule count and the receipt's accepted_at = %d over three accepted sends, want 3:\n%s", n, logs.String())
	}
}

// ---------------------------------------------------------------------------
// Rule entries
// ---------------------------------------------------------------------------

// fakeRuleSource is an IngressRuleReportSource whose reports a test sets. It
// is built inside the synctest bubble that uses it, since its channel belongs
// to the bubble that made it.
type fakeRuleSource struct {
	mu      sync.Mutex
	reports []IngressRuleReport
	changed chan struct{}
}

func newFakeRuleSource(reports ...IngressRuleReport) *fakeRuleSource {
	return &fakeRuleSource{reports: reports, changed: make(chan struct{}, 1)}
}

func (s *fakeRuleSource) RuleReports() []IngressRuleReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reports)
}

func (s *fakeRuleSource) ReportChanged() <-chan struct{} { return s.changed }

// store replaces the reports without a signal.
func (s *fakeRuleSource) store(reports ...IngressRuleReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = reports
}

// set replaces the reports and signals the change.
func (s *fakeRuleSource) set(reports ...IngressRuleReport) {
	s.store(reports...)
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// listeningReport returns the report of a passthrough rule that listens and
// whose target nobody dialled.
func listeningReport(id string) IngressRuleReport {
	return IngressRuleReport{RuleID: id, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateNotRequired, Dial: api.IngressDialNone}
}

// dialledReport returns the report of a passthrough rule whose last dial had
// the outcome dial, with reason, at at.
func dialledReport(id, dial, reason string, at time.Time) IngressRuleReport {
	r := listeningReport(id)
	r.Dial, r.DialReason, r.DialAt = dial, reason, at
	return r
}

// entryIDs returns the ids of a report's entries, in order.
func entryIDs(req api.IngressStatusRequest) []string {
	var ids []string
	for _, e := range req.Rules {
		ids = append(ids, e.ID)
	}
	return ids
}

func TestIngressStatusReporter_SourceWithoutReportsSendsTheStateAlone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &fakeIngressStatusClient{}
		r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, false, newFakeRuleSource(), discardLogger())
		startIngressStatusReporter(t, r)
		synctest.Wait()

		_, reqs := client.recorded()
		if len(reqs) != 1 {
			t.Fatalf("reports after the start = %d, want 1", len(reqs))
		}
		if got := mustJSON(t, reqs[0]); got != `{"state":"enabled"}` {
			t.Errorf("body = %s, want {\"state\":\"enabled\"}", got)
		}
	})
}

func TestBuildIngressStatusRequest_DialAge(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	id := reportID("a1")
	const absent = -1
	tests := []struct {
		name   string
		report IngressRuleReport
		want   int64 // absent for no member
	}{
		{"12.9 s ago", dialledReport(id, api.IngressDialFailed, IngressDialReasonRefused, now.Add(-12900*time.Millisecond)), 12},
		{"after now", dialledReport(id, api.IngressDialSucceeded, "", now.Add(time.Second)), 0},
		{"100 years ago", dialledReport(id, api.IngressDialSucceeded, "", now.AddDate(-100, 0, 0)), api.MaxIngressStatusDialAgeSeconds},
		{"no dial", listeningReport(id), absent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := buildIngressStatusRequest(api.IngressStateEnabled, []IngressRuleReport{tt.report}, now)
			if len(req.Rules) != 1 {
				t.Fatalf("rules = %+v, want one entry", req.Rules)
			}
			got := req.Rules[0].DialAgeSeconds
			switch {
			case tt.want == absent && got != nil:
				t.Errorf("DialAgeSeconds = %d, want none", *got)
			case tt.want != absent && (got == nil || *got != tt.want):
				t.Errorf("DialAgeSeconds = %v, want %d", got, tt.want)
			}
			if body := mustJSON(t, req); tt.want == absent && strings.Contains(body, "dial_age_seconds") {
				t.Errorf("body = %s, want no dial_age_seconds", body)
			}
		})
	}
}

func TestBuildIngressStatusRequest_OptedOutCarriesNoRules(t *testing.T) {
	req := buildIngressStatusRequest(api.IngressStateOptedOut, []IngressRuleReport{listeningReport(reportID("a1"))}, time.Now())
	if req.Rules != nil {
		t.Errorf("rules = %+v, want none for opted_out", req.Rules)
	}
}

func TestIngressStatusReporter_ReportsTheFirst1024Rules(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		reports := make([]IngressRuleReport, 1030)
		for i := range reports {
			reports[i] = listeningReport(fmt.Sprintf("0190a8b8-a0c0-7a0a-8a0a-%012x", i+1))
		}
		client := &fakeIngressStatusClient{}
		logger, logs := newRelayLogger()
		r := NewIngressStatusReporter(interval, testIngressNodeID, client, false, newFakeRuleSource(reports...), logger)

		startIngressStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(interval)
		synctest.Wait()

		_, reqs := client.recorded()
		if len(reqs) != 2 {
			t.Fatalf("reports = %d, want 2: the one at start and one tick", len(reqs))
		}
		var want []string
		for _, rep := range reports[:1024] {
			want = append(want, rep.RuleID)
		}
		for k, req := range reqs {
			if got := entryIDs(req); !slices.Equal(got, want) {
				t.Errorf("report %d holds %d entries, want the first 1024 in order", k, len(got))
			}
		}
		const msg = "ingress status: more rules than a report carries, reporting the first 1024"
		if n := logs.count(`level=WARN msg="` + msg + `" component=bridge rules=1030`); n != 1 {
			t.Errorf("%d Warns %q with rules=1030 over two sends, want 1:\n%s", n, msg, logs.String())
		}
	})
}

func TestIngressStatusReporter_SendsOnChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeRuleSource(listeningReport(reportID("a1")))
		client := &fakeIngressStatusClient{}
		r := NewIngressStatusReporter(interval, testIngressNodeID, client, false, source, discardLogger())

		startIngressStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.set(dialledReport(reportID("a1"), api.IngressDialFailed, IngressDialReasonRefused, time.Now()))
		synctest.Wait()
		_, reqs := client.recorded()
		if len(reqs) != 2 {
			t.Fatalf("reports after a change = %d, want 2: the one at start and one on change, before any tick", len(reqs))
		}
		if got := reqs[1].Rules; len(got) != 1 || got[0].Dial != api.IngressDialFailed {
			t.Errorf("on-change report rules = %+v, want the failed dial", got)
		}

		// The on-change send restarted the interval.
		time.Sleep(interval - time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Errorf("reports just before one interval after the change = %d, want 2", got)
		}
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != 3 {
			t.Errorf("reports just after one interval after the change = %d, want 3", got)
		}
	})
}

func TestIngressStatusReporter_DialAgeAloneSendsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		at := time.Now()
		source := newFakeRuleSource(dialledReport(reportID("a1"), api.IngressDialSucceeded, "", at))
		client := &fakeIngressStatusClient{}
		r := NewIngressStatusReporter(interval, testIngressNodeID, client, false, source, discardLogger())

		startIngressStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.set(dialledReport(reportID("a1"), api.IngressDialSucceeded, "", at.Add(10*time.Second)))
		synctest.Wait()
		time.Sleep(interval - 10*time.Second - time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != 1 {
			t.Errorf("reports before the tick after a change of DialAt alone = %d, want only the one at start", got)
		}
	})
}

func TestIngressStatusReporter_ChangesAreBoundedByTheGap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeRuleSource(listeningReport(reportID("a1")))
		client := &fakeIngressStatusClient{}
		r := NewIngressStatusReporter(interval, testIngressNodeID, client, false, source, discardLogger())

		startIngressStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.set(dialledReport(reportID("a1"), api.IngressDialFailed, IngressDialReasonRefused, time.Now()))
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Fatalf("reports after the first change = %d, want 2", got)
		}

		time.Sleep(time.Second)
		source.set(dialledReport(reportID("a1"), api.IngressDialSucceeded, "", time.Now()))
		synctest.Wait()
		time.Sleep(4*time.Second - time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Errorf("reports just before 5s after the first on-change send = %d, want still 2", got)
		}
		// The latest reports are the ones the timer sends.
		source.store(dialledReport(reportID("a1"), api.IngressDialFailed, IngressDialReasonTimeout, time.Now()))
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		_, reqs := client.recorded()
		if len(reqs) != 3 {
			t.Fatalf("reports just after 5s after the first on-change send = %d, want 3", len(reqs))
		}
		if got := reqs[2].Rules; len(got) != 1 || got[0].DialReason != IngressDialReasonTimeout {
			t.Errorf("second on-change report rules = %+v, want the latest reports (dial failed with timeout)", got)
		}
	})
}

func TestIngressStatusReporter_FailedOnChangeSendIsNotRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeRuleSource(listeningReport(reportID("a1")))
		client := &fakeIngressStatusClient{errs: []error{nil, &api.APIError{StatusCode: 400, Code: "invalid_ingress_status"}}}
		logger, logs := newRelayLogger()
		r := NewIngressStatusReporter(interval, testIngressNodeID, client, false, source, logger)

		startIngressStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.set(dialledReport(reportID("a1"), api.IngressDialFailed, IngressDialReasonRefused, time.Now()))
		synctest.Wait()
		if n := logs.count(`level=WARN msg="ingress status: send failed"`); n != 1 {
			t.Errorf("%d Warns 'ingress status: send failed' after the refused on-change send, want 1:\n%s", n, logs.String())
		}

		time.Sleep(interval - time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Errorf("reports before the tick = %d, want 2: no retry of the refused one", got)
		}
		source.store(dialledReport(reportID("a1"), api.IngressDialSucceeded, "", time.Now()))
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		_, reqs := client.recorded()
		if len(reqs) != 3 {
			t.Fatalf("reports after the tick = %d, want 3", len(reqs))
		}
		if got := reqs[2].Rules; len(got) != 1 || got[0].Dial != api.IngressDialSucceeded {
			t.Errorf("tick report rules = %+v, want the reports as they then are (dial succeeded)", got)
		}
	})
}

func TestIngressStatusReporter_ControlPlaneWithoutRules(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		// A manager whose port fails to bind opens no socket, so it runs
		// inside the bubble.
		fx := buildIngressFixture(t, &mockIngressController{listenErr: syscall.EADDRINUSE}, ingressTestConfig(true))
		if err := fx.mgr.Setup(); err != nil {
			t.Fatalf("Setup: %v", err)
		}
		_ = fx.mgr.Apply(t.Context(), rulesBlock(withID(ingressRule("web", 7022, "", 9000), reportID("a1"))))
		drain(fx.mgr.ReportChanged())
		before := fx.mgr.RuleReports()

		malformed := &api.APIError{StatusCode: 400, Code: "malformed_ingress_status"}
		client := &fakeIngressStatusClient{errs: slices.Repeat([]error{malformed}, 8)}
		logger, logs := newRelayLogger()
		r := NewIngressStatusReporter(interval, testIngressNodeID, client, false, fx.mgr, logger)

		startIngressStatusReporter(t, r)
		synctest.Wait()
		for k := 2; k <= 3; k++ {
			time.Sleep(interval)
			synctest.Wait()
			if got := client.calls(); got != k {
				t.Errorf("reports after %d intervals = %d, want %d: one per interval", k-1, got, k)
			}
		}
		if n, sends := logs.count(`level=WARN msg="ingress status: send failed"`), client.calls(); n != sends {
			t.Errorf("%d Warns 'ingress status: send failed' over %d refused sends, want one per send", n, sends)
		}
		if after := fx.mgr.RuleReports(); !slices.Equal(after, before) {
			t.Errorf("RuleReports after the refused sends = %+v, want it unchanged from %+v", after, before)
		}
	})
}

func TestIngressStatusReporter_LogsTheRuleCount(t *testing.T) {
	source := newFakeRuleSource(listeningReport(reportID("a1")), listeningReport(reportID("b2")), listeningReport(reportID("c3")))
	client := &fakeIngressStatusClient{}
	logger, logs := newRelayLogger()
	r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, false, source, logger)

	r.reportOnce(context.Background())

	if n := logs.count(`level=INFO msg="ingress status: reported" component=bridge state=enabled rules=3`); n != 1 {
		t.Errorf("Info 'ingress status: reported' with state=enabled rules=3 logged %d times, want 1:\n%s", n, logs.String())
	}
	if n := logs.count(`level=DEBUG msg="ingress status: accepted" component=bridge state=enabled rules=3`); n != 1 {
		t.Errorf("Debug 'ingress status: accepted' with rules=3 logged %d times, want 1:\n%s", n, logs.String())
	}
}

func TestIngressStatusReporter_CancelWhileTheGapTimerIsArmed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := newFakeRuleSource(listeningReport(reportID("a1")))
		client := &fakeIngressStatusClient{}
		r := NewIngressStatusReporter(time.Minute, testIngressNodeID, client, false, source, discardLogger())

		stop := startIngressStatusReporter(t, r)
		synctest.Wait()
		source.set(dialledReport(reportID("a1"), api.IngressDialFailed, IngressDialReasonRefused, time.Now()))
		synctest.Wait()
		time.Sleep(time.Second)
		source.set(dialledReport(reportID("a1"), api.IngressDialSucceeded, "", time.Now()))
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Fatalf("reports with the gap timer armed = %d, want 2", got)
		}

		stop()
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Errorf("reports after the cancel = %d, want still 2", got)
		}
	})
}
