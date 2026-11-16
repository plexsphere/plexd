package bridge

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
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
				r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, tc.optedOut, logger)

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
		r := NewIngressStatusReporter(interval, testIngressNodeID, client, true, discardLogger())

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

				r := NewIngressStatusReporter(interval, testIngressNodeID, client, false, logger)
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
		r := NewIngressStatusReporter(interval, testIngressNodeID, client, false, logger)

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
		r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, true, discardLogger())

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
			r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, false, logger)
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
	r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, false, logger)

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
			r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, false, logger)

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
	r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, false, logger)

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
	r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, false, logger)

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
	r := NewIngressStatusReporter(time.Hour, testIngressNodeID, client, true, logger)
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
	if n := logs.count(`level=DEBUG msg="` + acceptedMsg + `" component=bridge state=opted_out accepted_at=2026-10-30T10:15:30.123Z`); n != 3 {
		t.Errorf("accepted lines at Debug with the state and the receipt's accepted_at = %d over three accepted sends, want 3:\n%s", n, logs.String())
	}
}
