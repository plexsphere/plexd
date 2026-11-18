package bridge

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The composition root hands the reporter the control-plane client and the
// site-to-site manager; these assertions keep both seams satisfiable by them.
var (
	_ SiteToSiteStatusClient       = (*api.ControlPlane)(nil)
	_ SiteToSiteTunnelReportSource = (*SiteToSiteManager)(nil)
)

const testSiteToSiteNodeID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c3"

// The ids of the tunnels in reports: a wireguard, an ipsec and an openvpn
// tunnel of the contract's example.
const (
	s2sReportID1 = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1"
	s2sReportID2 = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2"
	s2sReportID3 = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e3"
)

// Public keys of wireguard tunnels in reports.
var (
	s2sReportKey1 = deviceKey(0xb1)
	s2sReportKey2 = deviceKey(0xb2)
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fakeSiteToSiteStatusClient records every report it is handed and answers
// the n-th with errs[n] when that is set, and with a receipt at
// testAcceptedAt otherwise.
type fakeSiteToSiteStatusClient struct {
	mu       sync.Mutex
	nodeIDs  []string
	requests []api.SiteToSiteStatusRequest
	errs     []error
}

func (c *fakeSiteToSiteStatusClient) ReportSiteToSiteStatus(_ context.Context, nodeID string, req api.SiteToSiteStatusRequest) (*api.SiteToSiteStatusResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := len(c.requests)
	c.nodeIDs = append(c.nodeIDs, nodeID)
	c.requests = append(c.requests, req)
	if idx < len(c.errs) && c.errs[idx] != nil {
		return nil, c.errs[idx]
	}
	return &api.SiteToSiteStatusResponse{AcceptedAt: testAcceptedAt}, nil
}

func (c *fakeSiteToSiteStatusClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *fakeSiteToSiteStatusClient) recorded() (nodeIDs []string, reqs []api.SiteToSiteStatusRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.nodeIDs), slices.Clone(c.requests)
}

// last returns the last report the client was handed.
func (c *fakeSiteToSiteStatusClient) last(t *testing.T) api.SiteToSiteStatusRequest {
	t.Helper()
	_, reqs := c.recorded()
	if len(reqs) == 0 {
		t.Fatal("no report was sent")
	}
	return reqs[len(reqs)-1]
}

// startSiteToSiteStatusReporter runs r.Run in a goroutine and returns a stop
// function that cancels it and waits for Run to return nil. The stop is also
// registered as a cleanup, so a failed assertion does not leave the goroutine
// behind, which a synctest bubble would report as a deadlock.
func startSiteToSiteStatusReporter(t *testing.T, r *SiteToSiteStatusReporter) (stop func()) {
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

// fakeTunnelReportSource is a SiteToSiteTunnelReportSource whose reports a
// test sets. It hands out the slice it holds, not a copy, so a reporter that
// wrote into the reports it reads would change what a later TunnelReports
// returns. It is built inside the synctest bubble that uses it, since its
// channel belongs to the bubble that made it.
type fakeTunnelReportSource struct {
	mu      sync.Mutex
	reports []SiteToSiteTunnelReport
	reads   int
	changed chan struct{}
}

func newFakeTunnelReportSource(reports ...SiteToSiteTunnelReport) *fakeTunnelReportSource {
	return &fakeTunnelReportSource{reports: reports, changed: make(chan struct{}, 1)}
}

func (s *fakeTunnelReportSource) TunnelReports() []SiteToSiteTunnelReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	return s.reports
}

func (s *fakeTunnelReportSource) ReportChanged() <-chan struct{} { return s.changed }

// readCount returns how often TunnelReports was called.
func (s *fakeTunnelReportSource) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// store replaces the reports without a signal.
func (s *fakeTunnelReportSource) store(reports ...SiteToSiteTunnelReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = reports
}

// set replaces the reports and signals the change.
func (s *fakeTunnelReportSource) set(reports ...SiteToSiteTunnelReport) {
	s.store(reports...)
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// s2sUpWireGuard returns the report of a wireguard tunnel that is up.
func s2sUpWireGuard(id, publicKey string, established bool) SiteToSiteTunnelReport {
	return SiteToSiteTunnelReport{TunnelID: id, Kind: api.SiteToSiteKindWireGuard, Health: api.SiteToSiteHealthUp, PublicKey: publicKey, Established: established}
}

// s2sUpTunnel returns the report of an ipsec or openvpn tunnel that is up.
func s2sUpTunnel(id, kind string, established bool) SiteToSiteTunnelReport {
	return SiteToSiteTunnelReport{TunnelID: id, Kind: kind, Health: api.SiteToSiteHealthUp, Established: established}
}

// s2sDownTunnel returns the report of a tunnel that is down for reason.
func s2sDownTunnel(id, kind, reason string) SiteToSiteTunnelReport {
	return SiteToSiteTunnelReport{TunnelID: id, Kind: kind, Health: api.SiteToSiteHealthDown, Reason: reason}
}

// siteToSiteEntryIDs returns the ids of a report's entries, in order.
func siteToSiteEntryIDs(req api.SiteToSiteStatusRequest) []string {
	var ids []string
	for _, e := range req.Tunnels {
		ids = append(ids, e.ID)
	}
	return ids
}

// ---------------------------------------------------------------------------
// Construction and Run
// ---------------------------------------------------------------------------

// The reporter's timing runs on synctest's fake clock: synctest.Wait returns
// once Run blocks on its ticker again, so every count below is exact and no
// assertion waits on the wall clock.

// TestSiteToSiteStatusReporter_SendsItsStateAtStart checks the send at start
// with an untyped nil source, which plexd up hands an opted-out reporter.
func TestSiteToSiteStatusReporter_SendsItsStateAtStart(t *testing.T) {
	for _, tc := range []struct {
		optedOut bool
		want     string
	}{
		{optedOut: false, want: api.SiteToSiteStateEnabled},
		{optedOut: true, want: api.SiteToSiteStateOptedOut},
	} {
		t.Run(tc.want, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := &fakeSiteToSiteStatusClient{}
				logger, logs := newRelayLogger()
				r := NewSiteToSiteStatusReporter(time.Hour, testSiteToSiteNodeID, client, tc.optedOut, nil, logger)

				startSiteToSiteStatusReporter(t, r)
				synctest.Wait()

				nodeIDs, reqs := client.recorded()
				if len(reqs) != 1 {
					t.Fatalf("reports before the first tick = %d, want exactly 1", len(reqs))
				}
				if got, want := mustJSON(t, reqs[0]), `{"state":"`+tc.want+`"}`; got != want {
					t.Errorf("body = %s, want %s", got, want)
				}
				if !slices.Equal(nodeIDs, []string{testSiteToSiteNodeID}) {
					t.Errorf("node IDs = %v, want [%s]", nodeIDs, testSiteToSiteNodeID)
				}
				line := relayLogLine(t, logs, "site-to-site status: reporter started")
				for _, want := range []string{"level=INFO", "component=bridge", "interval=1h0m0s", "state=" + tc.want} {
					if !strings.Contains(line, want) {
						t.Errorf("started log = %q, want it to contain %q", line, want)
					}
				}
			})
		})
	}
}

// TestSiteToSiteStatusReporter_OptedOutSendsNoTunnels checks that an
// opted-out report carries no tunnels and does not read the source, which
// plexd up never hands an opted-out reporter.
func TestSiteToSiteStatusReporter_OptedOutSendsNoTunnels(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeTunnelReportSource(s2sUpWireGuard(s2sReportID1, s2sReportKey1, true), s2sDownTunnel(s2sReportID2, api.SiteToSiteKindIPsec, SiteToSiteReasonAuthSecretNotListed))
		client := &fakeSiteToSiteStatusClient{}
		r := NewSiteToSiteStatusReporter(interval, testSiteToSiteNodeID, client, true, source, discardLogger())

		startSiteToSiteStatusReporter(t, r)
		synctest.Wait()
		source.set(s2sUpWireGuard(s2sReportID1, s2sReportKey2, false))
		synctest.Wait()
		time.Sleep(interval)
		synctest.Wait()

		_, reqs := client.recorded()
		if len(reqs) != 2 {
			t.Fatalf("reports = %d, want 2: the one at start and one tick, none on change", len(reqs))
		}
		for k, req := range reqs {
			if got := mustJSON(t, req); got != `{"state":"opted_out"}` {
				t.Errorf("report %d body = %s, want {\"state\":\"opted_out\"}", k, got)
			}
		}
		if n := source.readCount(); n != 0 {
			t.Errorf("TunnelReports read %d times on an opted-out bridge, want 0", n)
		}
	})
}

// TestSiteToSiteStatusReporter_SendsTheStateAloneWithoutTunnels checks that
// an enabled bridge whose manager reports no tunnel, as an empty or as a nil
// list, sends {"state":"enabled"} at start and on every tick, and that a
// signal that leaves the list empty sends nothing.
func TestSiteToSiteStatusReporter_SendsTheStateAloneWithoutTunnels(t *testing.T) {
	for _, tc := range []struct {
		name    string
		reports []SiteToSiteTunnelReport
	}{
		{name: "nil list", reports: nil},
		{name: "empty list", reports: []SiteToSiteTunnelReport{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const interval = time.Minute
				source := newFakeTunnelReportSource(tc.reports...)
				client := &fakeSiteToSiteStatusClient{}
				r := NewSiteToSiteStatusReporter(interval, testSiteToSiteNodeID, client, false, source, discardLogger())

				startSiteToSiteStatusReporter(t, r)
				synctest.Wait()
				time.Sleep(10 * time.Second)
				source.set(tc.reports...)
				synctest.Wait()
				time.Sleep(interval - 10*time.Second)
				synctest.Wait()

				_, reqs := client.recorded()
				if len(reqs) != 2 {
					t.Fatalf("reports = %d, want 2: the one at start and one tick, none on a signal that changed nothing", len(reqs))
				}
				for k, req := range reqs {
					if got := mustJSON(t, req); got != `{"state":"enabled"}` {
						t.Errorf("report %d body = %s, want {\"state\":\"enabled\"}", k, got)
					}
				}
				if n := source.readCount(); n != 3 {
					t.Errorf("TunnelReports read %d times, want 3: at start, on the signal and on the tick", n)
				}
			})
		})
	}
}

func TestSiteToSiteStatusReporter_ResendsEveryTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeTunnelReportSource(s2sUpWireGuard(s2sReportID1, s2sReportKey1, false))
		client := &fakeSiteToSiteStatusClient{}
		r := NewSiteToSiteStatusReporter(interval, testSiteToSiteNodeID, client, false, source, discardLogger())

		startSiteToSiteStatusReporter(t, r)
		synctest.Wait()
		for k := 2; k <= 4; k++ {
			time.Sleep(interval - time.Millisecond)
			synctest.Wait()
			if got := client.calls(); got != k-1 {
				t.Fatalf("reports just before tick %d = %d, want %d", k-1, got, k-1)
			}
			time.Sleep(time.Millisecond)
			synctest.Wait()
			if got := client.calls(); got != k {
				t.Fatalf("reports at tick %d = %d, want %d: one per interval", k-1, got, k)
			}
		}
		// An unchanged report is sent again on every tick: each renews the
		// window in which the control plane counts the bridge as reporting.
		_, reqs := client.recorded()
		for k, req := range reqs {
			if got := siteToSiteEntryIDs(req); !slices.Equal(got, []string{s2sReportID1}) {
				t.Errorf("report %d entries = %q, want the tunnel", k, got)
			}
		}
	})
}

func TestNewSiteToSiteStatusReporter_NonPositiveIntervalRunsAtDefault(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := &fakeSiteToSiteStatusClient{}
				logger, logs := newRelayLogger()

				r := NewSiteToSiteStatusReporter(interval, testSiteToSiteNodeID, client, false, nil, logger)
				if r.interval != 30*time.Second {
					t.Errorf("interval = %v, want 30s", r.interval)
				}

				startSiteToSiteStatusReporter(t, r)
				synctest.Wait()
				line := relayLogLine(t, logs, "site-to-site status: reporter started")
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

func TestSiteToSiteStatusReporter_FailedSendIsNotRetriedWithinItsTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		client := &fakeSiteToSiteStatusClient{errs: []error{context.DeadlineExceeded}}
		logger, logs := newRelayLogger()
		r := NewSiteToSiteStatusReporter(interval, testSiteToSiteNodeID, client, false, nil, logger)

		startSiteToSiteStatusReporter(t, r)
		synctest.Wait()
		line := relayLogLine(t, logs, "site-to-site status: send failed")
		for _, want := range []string{"level=WARN", "component=bridge", `error="context deadline exceeded"`} {
			if !strings.Contains(line, want) {
				t.Errorf("send failed log = %q, want it to contain %q", line, want)
			}
		}
		if n := relayLogLines(logs, "site-to-site status: reported"); n != 0 {
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
		line = relayLogLine(t, logs, "site-to-site status: reported")
		for _, want := range []string{"level=INFO", "state=enabled", "tunnels=0"} {
			if !strings.Contains(line, want) {
				t.Errorf("reported log = %q, want it to contain %q", line, want)
			}
		}
		if n := relayLogLines(logs, "site-to-site status: send failed"); n != 1 {
			t.Errorf("send failed logged %d times, want 1", n)
		}
	})
}

func TestSiteToSiteStatusReporter_NoSendAtShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := newFakeTunnelReportSource(s2sUpWireGuard(s2sReportID1, s2sReportKey1, true))
		client := &fakeSiteToSiteStatusClient{}
		r := NewSiteToSiteStatusReporter(time.Hour, testSiteToSiteNodeID, client, false, source, discardLogger())

		stop := startSiteToSiteStatusReporter(t, r)
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

func TestSiteToSiteStatusReporter_NotServedLoggedOnTransitions(t *testing.T) {
	const (
		notServedMsg = "site-to-site status: control plane does not accept site-to-site status reports, retrying every interval"
		recoveredMsg = "site-to-site status: control plane accepts site-to-site status reports"
		reportedMsg  = "site-to-site status: reported"
	)
	tests := []struct {
		name     string
		err      *api.APIError
		wantAttr string
	}{
		{name: "404 without code", err: &api.APIError{StatusCode: 404}, wantAttr: `status=404 code=""`},
		{name: "404 with another code", err: &api.APIError{StatusCode: 404, Code: "not_found"}, wantAttr: "status=404 code=not_found"},
		{
			name:     "501 site_to_site_status_not_provisioned",
			err:      &api.APIError{StatusCode: 501, Code: "site_to_site_status_not_provisioned"},
			wantAttr: "status=501 code=site_to_site_status_not_provisioned",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeSiteToSiteStatusClient{errs: []error{tt.err, tt.err, tt.err}}
			logger, logs := newRelayLogger()
			r := NewSiteToSiteStatusReporter(time.Hour, testSiteToSiteNodeID, client, false, nil, logger)
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

func TestSiteToSiteStatusReporter_NodeGoneWarnsOnEverySend(t *testing.T) {
	const msg = "site-to-site status: rejected, this node was removed"
	gone := &api.APIError{StatusCode: 404, Code: "site_to_site_status_node_gone"}
	client := &fakeSiteToSiteStatusClient{errs: []error{gone, gone}}
	logger, logs := newRelayLogger()
	r := NewSiteToSiteStatusReporter(time.Hour, testSiteToSiteNodeID, client, false, nil, logger)

	for range 2 {
		r.reportOnce(context.Background())
	}

	if n := logs.count(`level=WARN msg="` + msg + `" component=bridge code=site_to_site_status_node_gone`); n != 2 {
		t.Errorf("node gone lines at Warn with the code = %d over two sends, want 2:\n%s", n, logs.String())
	}
	if strings.Contains(logs.String(), "does not accept site-to-site status reports") {
		t.Errorf("site_to_site_status_node_gone was logged as not served:\n%s", logs.String())
	}
}

func TestSiteToSiteStatusReporter_SendFailuresWarn(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "400 malformed_site_to_site_status", err: &api.APIError{StatusCode: 400, Code: "malformed_site_to_site_status"}},
		{name: "400 invalid_site_to_site_status", err: &api.APIError{StatusCode: 400, Code: "invalid_site_to_site_status"}},
		{name: "413 site_to_site_status_body_too_large", err: &api.APIError{StatusCode: 413, Code: "site_to_site_status_body_too_large"}},
		{name: "500", err: &api.APIError{StatusCode: 500, Code: "internal"}},
		{name: "501 for another surface", err: &api.APIError{StatusCode: 501, Code: "user_access_status_not_provisioned"}},
		{name: "deadline exceeded", err: fmt.Errorf("put site-to-site-status: %w", context.DeadlineExceeded)},
		{name: "transport error", err: errors.New("dial tcp: connection refused")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeSiteToSiteStatusClient{errs: []error{tt.err}}
			logger, logs := newRelayLogger()
			r := NewSiteToSiteStatusReporter(time.Hour, testSiteToSiteNodeID, client, false, nil, logger)

			r.reportOnce(context.Background())

			if n := client.calls(); n != 1 {
				t.Errorf("reports = %d within one send, want 1 (no retry)", n)
			}
			line := relayLogLine(t, logs, "site-to-site status: send failed")
			for _, want := range []string{"level=WARN", "component=bridge", "error="} {
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
func TestSiteToSiteStatusReporter_RefusedCredentialLoggedAtDebug(t *testing.T) {
	client := &fakeSiteToSiteStatusClient{errs: []error{fmt.Errorf("x: %w", api.ErrCredentialRefused)}}
	logger, logs := newRelayLogger()
	r := NewSiteToSiteStatusReporter(time.Hour, testSiteToSiteNodeID, client, false, nil, logger)

	r.reportOnce(context.Background())

	line := relayLogLine(t, logs, "site-to-site status: send failed")
	for _, want := range []string{"level=DEBUG", "component=bridge", "error="} {
		if !strings.Contains(line, want) {
			t.Errorf("send failed log = %q, want it to contain %q", line, want)
		}
	}
	if got := logs.String(); strings.Contains(got, "level=INFO") || strings.Contains(got, "level=WARN") || strings.Contains(got, "level=ERROR") {
		t.Errorf("logs = %s, want nothing above Debug for a refused credential", got)
	}
}

func TestSiteToSiteStatusReporter_CancelledSendIsNotLogged(t *testing.T) {
	client := &fakeSiteToSiteStatusClient{errs: []error{context.Canceled}}
	logger, logs := newRelayLogger()
	r := NewSiteToSiteStatusReporter(time.Hour, testSiteToSiteNodeID, client, false, nil, logger)

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

func TestSiteToSiteStatusReporter_ReportedOnceAcceptedOnEverySend(t *testing.T) {
	const (
		reportedMsg = "site-to-site status: reported"
		acceptedMsg = "site-to-site status: accepted"
	)
	client := &fakeSiteToSiteStatusClient{}
	logger, logs := newRelayLogger()
	r := NewSiteToSiteStatusReporter(time.Hour, testSiteToSiteNodeID, client, true, nil, logger)
	ctx := context.Background()

	for range 3 {
		r.reportOnce(ctx)
	}

	line := relayLogLine(t, logs, reportedMsg)
	for _, want := range []string{"level=INFO", "component=bridge", "state=opted_out", "tunnels=0"} {
		if !strings.Contains(line, want) {
			t.Errorf("reported log = %q, want it to contain %q", line, want)
		}
	}
	if n := logs.count(`level=DEBUG msg="` + acceptedMsg + `" component=bridge state=opted_out tunnels=0 accepted_at=2026-10-30T10:15:30.123Z`); n != 3 {
		t.Errorf("accepted lines at Debug with the state, the tunnel count and the receipt's accepted_at = %d over three accepted sends, want 3:\n%s", n, logs.String())
	}
}

func TestSiteToSiteStatusReporter_LogsTheTunnelCount(t *testing.T) {
	source := newFakeTunnelReportSource(
		s2sUpWireGuard(s2sReportID1, s2sReportKey1, false),
		s2sDownTunnel(s2sReportID2, api.SiteToSiteKindIPsec, SiteToSiteReasonSetupFailed),
		s2sUpTunnel(s2sReportID3, api.SiteToSiteKindOpenVPN, true),
	)
	client := &fakeSiteToSiteStatusClient{}
	logger, logs := newRelayLogger()
	r := NewSiteToSiteStatusReporter(time.Hour, testSiteToSiteNodeID, client, false, source, logger)

	r.reportOnce(context.Background())

	if n := logs.count(`level=INFO msg="site-to-site status: reported" component=bridge state=enabled tunnels=3`); n != 1 {
		t.Errorf("Info 'site-to-site status: reported' with state=enabled tunnels=3 logged %d times, want 1:\n%s", n, logs.String())
	}
	if n := logs.count(`level=DEBUG msg="site-to-site status: accepted" component=bridge state=enabled tunnels=3`); n != 1 {
		t.Errorf("Debug 'site-to-site status: accepted' with tunnels=3 logged %d times, want 1:\n%s", n, logs.String())
	}
}

// ---------------------------------------------------------------------------
// Tunnel entries
// ---------------------------------------------------------------------------

// TestBuildSiteToSiteStatusRequest_Members checks which members each entry
// carries: established exactly for a tunnel that is up, false included,
// reason exactly for a tunnel that is down, and public_key exactly for a
// wireguard tunnel that is up. A member the report sets where the contract
// forbids it is dropped.
func TestBuildSiteToSiteStatusRequest_Members(t *testing.T) {
	tests := []struct {
		name   string
		report SiteToSiteTunnelReport
		want   string
	}{
		{
			name:   "wireguard up, not established",
			report: s2sUpWireGuard(s2sReportID1, s2sReportKey1, false),
			want:   `{"id":"` + s2sReportID1 + `","health":"up","established":false,"public_key":"` + s2sReportKey1 + `"}`,
		},
		{
			name:   "wireguard up, established",
			report: s2sUpWireGuard(s2sReportID1, s2sReportKey1, true),
			want:   `{"id":"` + s2sReportID1 + `","health":"up","established":true,"public_key":"` + s2sReportKey1 + `"}`,
		},
		{
			name: "wireguard up with a reason",
			report: SiteToSiteTunnelReport{
				TunnelID: s2sReportID1, Kind: api.SiteToSiteKindWireGuard, Health: api.SiteToSiteHealthUp,
				Reason: SiteToSiteReasonSetupFailed, PublicKey: s2sReportKey1,
			},
			want: `{"id":"` + s2sReportID1 + `","health":"up","established":false,"public_key":"` + s2sReportKey1 + `"}`,
		},
		{
			name: "wireguard down",
			report: SiteToSiteTunnelReport{
				TunnelID: s2sReportID1, Kind: api.SiteToSiteKindWireGuard, Health: api.SiteToSiteHealthDown,
				Reason: SiteToSiteReasonBindFailed, PublicKey: s2sReportKey1, Established: true,
			},
			want: `{"id":"` + s2sReportID1 + `","health":"down","reason":"bind_failed"}`,
		},
		{
			name: "ipsec up, established",
			report: SiteToSiteTunnelReport{
				TunnelID: s2sReportID2, Kind: api.SiteToSiteKindIPsec, Health: api.SiteToSiteHealthUp,
				PublicKey: s2sReportKey2, Established: true,
			},
			want: `{"id":"` + s2sReportID2 + `","health":"up","established":true}`,
		},
		{
			name:   "ipsec up, not established",
			report: s2sUpTunnel(s2sReportID2, api.SiteToSiteKindIPsec, false),
			want:   `{"id":"` + s2sReportID2 + `","health":"up","established":false}`,
		},
		{
			name:   "openvpn up, not established",
			report: s2sUpTunnel(s2sReportID3, api.SiteToSiteKindOpenVPN, false),
			want:   `{"id":"` + s2sReportID3 + `","health":"up","established":false}`,
		},
		{
			name:   "ipsec down",
			report: s2sDownTunnel(s2sReportID2, api.SiteToSiteKindIPsec, SiteToSiteReasonRemoteHostUnresolved),
			want:   `{"id":"` + s2sReportID2 + `","health":"down","reason":"remote_host_unresolved"}`,
		},
		{
			name:   "openvpn down",
			report: s2sDownTunnel(s2sReportID3, api.SiteToSiteKindOpenVPN, SiteToSiteReasonClientMissing),
			want:   `{"id":"` + s2sReportID3 + `","health":"down","reason":"client_missing"}`,
		},
		{
			name:   "unknown kind down",
			report: s2sDownTunnel(s2sReportID3, "gre", SiteToSiteReasonKindNotServed),
			want:   `{"id":"` + s2sReportID3 + `","health":"down","reason":"kind_not_served"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := buildSiteToSiteStatusRequest(api.SiteToSiteStateEnabled, []SiteToSiteTunnelReport{tt.report})
			if len(req.Tunnels) != 1 {
				t.Fatalf("tunnels = %+v, want one entry", req.Tunnels)
			}
			if got := mustJSON(t, req.Tunnels[0]); got != tt.want {
				t.Errorf("entry = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestBuildSiteToSiteStatusRequest_EachEntryHasItsOwnEstablished checks that
// the established members of two entries that are up do not share a value.
func TestBuildSiteToSiteStatusRequest_EachEntryHasItsOwnEstablished(t *testing.T) {
	req := buildSiteToSiteStatusRequest(api.SiteToSiteStateEnabled, []SiteToSiteTunnelReport{
		s2sUpWireGuard(s2sReportID1, s2sReportKey1, true),
		s2sUpTunnel(s2sReportID2, api.SiteToSiteKindIPsec, false),
	})
	const want = `{"state":"enabled","tunnels":[` +
		`{"id":"` + s2sReportID1 + `","health":"up","established":true,"public_key":"%s"},` +
		`{"id":"` + s2sReportID2 + `","health":"up","established":false}]}`
	if got := mustJSON(t, req); got != fmt.Sprintf(want, s2sReportKey1) {
		t.Errorf("body = %s, want %s", got, fmt.Sprintf(want, s2sReportKey1))
	}
}

func TestBuildSiteToSiteStatusRequest_StateAlone(t *testing.T) {
	reports := []SiteToSiteTunnelReport{s2sUpWireGuard(s2sReportID1, s2sReportKey1, true)}
	for _, tc := range []struct {
		name    string
		state   string
		reports []SiteToSiteTunnelReport
		want    string
	}{
		{"opted_out with reports", api.SiteToSiteStateOptedOut, reports, `{"state":"opted_out"}`},
		{"enabled without reports", api.SiteToSiteStateEnabled, nil, `{"state":"enabled"}`},
		{"enabled with an empty list", api.SiteToSiteStateEnabled, []SiteToSiteTunnelReport{}, `{"state":"enabled"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := buildSiteToSiteStatusRequest(tc.state, tc.reports)
			if req.Tunnels != nil {
				t.Errorf("tunnels = %+v, want none", req.Tunnels)
			}
			if got := mustJSON(t, req); got != tc.want {
				t.Errorf("body = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestSiteToSiteStatusReporter_ReportsTheFirst256Tunnels(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		reports := make([]SiteToSiteTunnelReport, 300)
		for i := range reports {
			reports[i] = s2sUpWireGuard(fmt.Sprintf("0190a8b8-a0c0-7a0a-8a0a-%012x", i+1), s2sReportKey1, false)
		}
		source := newFakeTunnelReportSource(reports...)
		client := &fakeSiteToSiteStatusClient{}
		logger, logs := newRelayLogger()
		r := NewSiteToSiteStatusReporter(interval, testSiteToSiteNodeID, client, false, source, logger)

		startSiteToSiteStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(interval)
		synctest.Wait()

		_, reqs := client.recorded()
		if len(reqs) != 2 {
			t.Fatalf("reports = %d, want 2: the one at start and one tick", len(reqs))
		}
		var want []string
		for _, rep := range reports[:256] {
			want = append(want, rep.TunnelID)
		}
		for k, req := range reqs {
			if got := siteToSiteEntryIDs(req); !slices.Equal(got, want) {
				t.Errorf("report %d holds %d entries, want the first 256 in order", k, len(got))
			}
		}
		const msg = "site-to-site status: more tunnels than a report carries, reporting the first 256"
		warn := `level=WARN msg="` + msg + `" component=bridge tunnels=300`
		if n := logs.count(warn); n != 1 {
			t.Errorf("%d Warns %q with tunnels=300 over two sends, want 1:\n%s", n, msg, logs.String())
		}

		// Leaving the state and entering it again warns again.
		source.set(reports[:10]...)
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.set(reports...)
		synctest.Wait()
		if got := client.calls(); got != 4 {
			t.Fatalf("reports = %d, want 4: two more on change", got)
		}
		if n := logs.count(warn); n != 2 {
			t.Errorf("%d Warns with tunnels=300 after entering the state again, want 2:\n%s", n, logs.String())
		}
	})
}

// TestSiteToSiteStatusReporter_SendsOnChange checks that a change of an
// entry's established, public key, health or reason, and a tunnel added,
// each send at once, that a change of a member the entry does not carry
// sends nothing, nor does a signal that changes nothing, and that an
// on-change send restarts the interval.
func TestSiteToSiteStatusReporter_SendsOnChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeTunnelReportSource(s2sUpWireGuard(s2sReportID1, s2sReportKey1, false))
		client := &fakeSiteToSiteStatusClient{}
		r := NewSiteToSiteStatusReporter(interval, testSiteToSiteNodeID, client, false, source, discardLogger())

		startSiteToSiteStatusReporter(t, r)
		synctest.Wait()

		ipsecWithKey := s2sUpTunnel(s2sReportID2, api.SiteToSiteKindIPsec, true)
		ipsecWithKey.PublicKey = s2sReportKey2
		downWithMembers := s2sDownTunnel(s2sReportID1, api.SiteToSiteKindWireGuard, SiteToSiteReasonSetupFailed)
		downWithMembers.PublicKey, downWithMembers.Established = s2sReportKey1, true
		steps := []struct {
			what    string
			reports []SiteToSiteTunnelReport
			sends   bool
		}{
			{"established", []SiteToSiteTunnelReport{s2sUpWireGuard(s2sReportID1, s2sReportKey1, true)}, true},
			{"public_key", []SiteToSiteTunnelReport{s2sUpWireGuard(s2sReportID1, s2sReportKey2, true)}, true},
			{"health", []SiteToSiteTunnelReport{s2sDownTunnel(s2sReportID1, api.SiteToSiteKindWireGuard, SiteToSiteReasonBindFailed)}, true},
			{"reason", []SiteToSiteTunnelReport{s2sDownTunnel(s2sReportID1, api.SiteToSiteKindWireGuard, SiteToSiteReasonSetupFailed)}, true},
			{"a tunnel added", []SiteToSiteTunnelReport{
				s2sDownTunnel(s2sReportID1, api.SiteToSiteKindWireGuard, SiteToSiteReasonSetupFailed),
				s2sUpTunnel(s2sReportID2, api.SiteToSiteKindIPsec, false),
			}, true},
			{"established of an ipsec tunnel", []SiteToSiteTunnelReport{
				s2sDownTunnel(s2sReportID1, api.SiteToSiteKindWireGuard, SiteToSiteReasonSetupFailed),
				s2sUpTunnel(s2sReportID2, api.SiteToSiteKindIPsec, true),
			}, true},
			{"members the entries do not carry", []SiteToSiteTunnelReport{downWithMembers, ipsecWithKey}, false},
			{"nothing", []SiteToSiteTunnelReport{downWithMembers, ipsecWithKey}, false},
		}
		want := 1
		for _, step := range steps {
			// Each change comes 10 s after the one before, past the gap.
			time.Sleep(10 * time.Second)
			source.set(step.reports...)
			synctest.Wait()
			if step.sends {
				want++
			}
			if got := client.calls(); got != want {
				t.Fatalf("reports after a change of %s = %d, want %d", step.what, got, want)
			}
			if step.sends {
				if got, wantBody := mustJSON(t, client.last(t)), mustJSON(t, buildSiteToSiteStatusRequest(api.SiteToSiteStateEnabled, step.reports)); got != wantBody {
					t.Errorf("report after a change of %s = %s, want %s", step.what, got, wantBody)
				}
			}
		}

		// The last on-change send, 60 s after the start, restarted the
		// interval; the two changes after it sent nothing.
		time.Sleep(interval - 20*time.Second - time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != want {
			t.Errorf("reports just before one interval after the last on-change send = %d, want %d", got, want)
		}
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != want+1 {
			t.Errorf("reports just after one interval after the last on-change send = %d, want %d", got, want+1)
		}
	})
}

// TestSiteToSiteStatusReporter_UnsignalledChangeWaitsForASignalOrTheTick
// checks that a change of established the manager does not signal is sent by
// the tick, and by the next signal when that comes first.
func TestSiteToSiteStatusReporter_UnsignalledChangeWaitsForASignalOrTheTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeTunnelReportSource(s2sUpWireGuard(s2sReportID1, s2sReportKey1, false))
		client := &fakeSiteToSiteStatusClient{}
		r := NewSiteToSiteStatusReporter(interval, testSiteToSiteNodeID, client, false, source, discardLogger())

		startSiteToSiteStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.store(s2sUpWireGuard(s2sReportID1, s2sReportKey1, true))
		synctest.Wait()
		if got := client.calls(); got != 1 {
			t.Fatalf("reports after a change without a signal = %d, want only the one at start", got)
		}

		time.Sleep(interval - 10*time.Second)
		synctest.Wait()
		_, reqs := client.recorded()
		if len(reqs) != 2 {
			t.Fatalf("reports after the tick = %d, want 2", len(reqs))
		}
		if got := reqs[1].Tunnels; len(got) != 1 || got[0].Established == nil || !*got[0].Established {
			t.Errorf("tick report tunnels = %s, want established true", mustJSON(t, got))
		}

		// A signal for another reason, a pull that changed nothing else, finds
		// established moved and sends it before the next tick.
		time.Sleep(10 * time.Second)
		source.store(s2sUpWireGuard(s2sReportID1, s2sReportKey1, false))
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.set(s2sUpWireGuard(s2sReportID1, s2sReportKey1, false))
		synctest.Wait()
		_, reqs = client.recorded()
		if len(reqs) != 3 {
			t.Fatalf("reports after the signal = %d, want 3", len(reqs))
		}
		if got := reqs[2].Tunnels; len(got) != 1 || got[0].Established == nil || *got[0].Established {
			t.Errorf("on-change report tunnels = %s, want established false", mustJSON(t, got))
		}
	})
}

func TestSiteToSiteStatusReporter_ChangesAreBoundedByTheGap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeTunnelReportSource(s2sUpWireGuard(s2sReportID1, s2sReportKey1, false))
		client := &fakeSiteToSiteStatusClient{}
		r := NewSiteToSiteStatusReporter(interval, testSiteToSiteNodeID, client, false, source, discardLogger())

		startSiteToSiteStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.set(s2sDownTunnel(s2sReportID1, api.SiteToSiteKindWireGuard, SiteToSiteReasonBindFailed))
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Fatalf("reports after the first change = %d, want 2", got)
		}

		time.Sleep(time.Second)
		source.set(s2sUpWireGuard(s2sReportID1, s2sReportKey1, false))
		synctest.Wait()
		time.Sleep(4*time.Second - time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Errorf("reports just before 5s after the first on-change send = %d, want still 2", got)
		}
		// The latest reports are the ones the timer sends.
		source.store(s2sDownTunnel(s2sReportID1, api.SiteToSiteKindWireGuard, SiteToSiteReasonSetupFailed))
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		_, reqs := client.recorded()
		if len(reqs) != 3 {
			t.Fatalf("reports just after 5s after the first on-change send = %d, want 3", len(reqs))
		}
		if got := reqs[2].Tunnels; len(got) != 1 || got[0].Reason != SiteToSiteReasonSetupFailed {
			t.Errorf("second on-change report tunnels = %s, want the latest reports (down with setup_failed)", mustJSON(t, got))
		}
	})
}

// TestSiteToSiteStatusReporter_GapEndsWithoutAChange checks that a change
// inside the gap that is undone before the gap ends sends nothing.
func TestSiteToSiteStatusReporter_GapEndsWithoutAChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := newFakeTunnelReportSource(s2sUpWireGuard(s2sReportID1, s2sReportKey1, false))
		client := &fakeSiteToSiteStatusClient{}
		r := NewSiteToSiteStatusReporter(time.Minute, testSiteToSiteNodeID, client, false, source, discardLogger())

		startSiteToSiteStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.set(s2sUpWireGuard(s2sReportID1, s2sReportKey1, true))
		synctest.Wait()
		time.Sleep(time.Second)
		source.set(s2sUpWireGuard(s2sReportID1, s2sReportKey1, false))
		synctest.Wait()
		source.store(s2sUpWireGuard(s2sReportID1, s2sReportKey1, true))
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Errorf("reports after a gap whose change was undone = %d, want 2", got)
		}
	})
}

func TestSiteToSiteStatusReporter_FailedOnChangeSendIsNotRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeTunnelReportSource(s2sUpWireGuard(s2sReportID1, s2sReportKey1, false))
		client := &fakeSiteToSiteStatusClient{errs: []error{nil, &api.APIError{StatusCode: 400, Code: "invalid_site_to_site_status"}}}
		logger, logs := newRelayLogger()
		r := NewSiteToSiteStatusReporter(interval, testSiteToSiteNodeID, client, false, source, logger)

		startSiteToSiteStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.set(s2sDownTunnel(s2sReportID1, api.SiteToSiteKindWireGuard, SiteToSiteReasonBindFailed))
		synctest.Wait()
		if n := logs.count(`level=WARN msg="site-to-site status: send failed"`); n != 1 {
			t.Errorf("%d Warns 'site-to-site status: send failed' after the refused on-change send, want 1:\n%s", n, logs.String())
		}

		time.Sleep(interval - time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Errorf("reports before the tick = %d, want 2: no retry of the refused one", got)
		}
		source.store(s2sUpWireGuard(s2sReportID1, s2sReportKey2, true))
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		_, reqs := client.recorded()
		if len(reqs) != 3 {
			t.Fatalf("reports after the tick = %d, want 3", len(reqs))
		}
		if got := reqs[2].Tunnels; len(got) != 1 || got[0].PublicKey != s2sReportKey2 {
			t.Errorf("tick report tunnels = %s, want the reports as they then are", mustJSON(t, got))
		}
	})
}

func TestSiteToSiteStatusReporter_CancelWhileTheGapTimerIsArmed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := newFakeTunnelReportSource(s2sUpWireGuard(s2sReportID1, s2sReportKey1, false))
		client := &fakeSiteToSiteStatusClient{}
		r := NewSiteToSiteStatusReporter(time.Minute, testSiteToSiteNodeID, client, false, source, discardLogger())

		stop := startSiteToSiteStatusReporter(t, r)
		synctest.Wait()
		source.set(s2sDownTunnel(s2sReportID1, api.SiteToSiteKindWireGuard, SiteToSiteReasonBindFailed))
		synctest.Wait()
		time.Sleep(time.Second)
		source.set(s2sUpWireGuard(s2sReportID1, s2sReportKey1, false))
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

// TestSiteToSiteStatusReporter_SendFailuresLeaveTheSourceAlone runs the
// reporter against a control plane that refuses the credential, times out,
// and does not serve the operation before it accepts a report: each failure
// is logged at its level, the loop sends once per interval throughout, and
// the source's reports are what they were, read once per send and never
// written.
func TestSiteToSiteStatusReporter_SendFailuresLeaveTheSourceAlone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeTunnelReportSource(
			s2sUpWireGuard(s2sReportID1, s2sReportKey1, true),
			s2sDownTunnel(s2sReportID2, api.SiteToSiteKindIPsec, SiteToSiteReasonAuthSecretNotListed),
		)
		before := slices.Clone(source.TunnelReports())

		client := &fakeSiteToSiteStatusClient{errs: []error{
			fmt.Errorf("put site-to-site-status: %w", api.ErrCredentialRefused),
			fmt.Errorf("put site-to-site-status: %w", context.DeadlineExceeded),
			&api.APIError{StatusCode: 404},
			&api.APIError{StatusCode: 404},
		}}
		logger, logs := newRelayLogger()
		r := NewSiteToSiteStatusReporter(interval, testSiteToSiteNodeID, client, false, source, logger)

		startSiteToSiteStatusReporter(t, r)
		synctest.Wait()
		for k := 2; k <= 5; k++ {
			time.Sleep(interval)
			synctest.Wait()
			if got := client.calls(); got != k {
				t.Fatalf("reports after %d intervals = %d, want %d: one per interval", k-1, got, k)
			}
		}

		for _, tc := range []struct {
			line string
			want int
		}{
			{`level=DEBUG msg="site-to-site status: send failed" component=bridge error=`, 1},
			{`level=WARN msg="site-to-site status: send failed" component=bridge error=`, 1},
			{`level=INFO msg="site-to-site status: control plane does not accept site-to-site status reports, retrying every interval" component=bridge status=404 code=""`, 1},
			{`level=INFO msg="site-to-site status: control plane accepts site-to-site status reports" component=bridge`, 1},
			{`level=INFO msg="site-to-site status: reported" component=bridge state=enabled tunnels=2`, 1},
		} {
			if n := logs.count(tc.line); n != tc.want {
				t.Errorf("%d lines %q, want %d:\n%s", n, tc.line, tc.want, logs.String())
			}
		}
		if n := relayLogLines(logs, "site-to-site status: send failed"); n != 2 {
			t.Errorf("%d 'send failed' lines over one refused credential and one timeout, want 2:\n%s", n, logs.String())
		}

		// The reporter only read the source: once per send and once above.
		if n := source.readCount(); n != 6 {
			t.Errorf("TunnelReports read %d times, want 6: one per send and one more", n)
		}
		if after := source.TunnelReports(); !slices.Equal(after, before) {
			t.Errorf("TunnelReports after the failed sends = %+v, want it unchanged from %+v", after, before)
		}
		const wantBody = `{"state":"enabled","tunnels":[` +
			`{"id":"` + s2sReportID1 + `","health":"up","established":true,"public_key":"%s"},` +
			`{"id":"` + s2sReportID2 + `","health":"down","reason":"auth_secret_not_listed"}]}`
		if got, want := mustJSON(t, client.last(t)), fmt.Sprintf(wantBody, s2sReportKey1); got != want {
			t.Errorf("accepted report = %s, want %s", got, want)
		}
	})
}

// TestSiteToSiteStatusReporter_SendFailuresLeaveTheManagerAlone runs the
// reporter over a real manager against a control plane that refuses the
// credential, times out, and does not serve the operation before it accepts
// a report: each failure is logged at its level, the loop sends once per
// interval throughout, and the manager serves and reports as before.
func TestSiteToSiteStatusReporter_SendFailuresLeaveTheManagerAlone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		fx := newS2SFixture(t, nil)
		fx.vpn.set(func(m *mockVPNController) {
			m.handshakes = map[string]time.Time{s2sWGIface: relayStart.Add(-time.Minute)}
		})
		fx.ipsec.set(func(p *mockTunnelProvider) { p.established = true })
		fx.openvpn.set(func(p *mockTunnelProvider) { p.createErr = fmt.Errorf("start openvpn: %w", exec.ErrNotFound) })
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast, office))
		drain(fx.mgr.ReportChanged())
		before := fx.mgr.TunnelReports()
		fx.reset()

		client := &fakeSiteToSiteStatusClient{errs: []error{
			fmt.Errorf("put site-to-site-status: %w", api.ErrCredentialRefused),
			fmt.Errorf("put site-to-site-status: %w", context.DeadlineExceeded),
			&api.APIError{StatusCode: 404},
			&api.APIError{StatusCode: 404},
		}}
		logger, logs := newRelayLogger()
		r := NewSiteToSiteStatusReporter(interval, testSiteToSiteNodeID, client, false, fx.mgr, logger)

		startSiteToSiteStatusReporter(t, r)
		synctest.Wait()
		for k := 2; k <= 5; k++ {
			time.Sleep(interval)
			synctest.Wait()
			if got := client.calls(); got != k {
				t.Fatalf("reports after %d intervals = %d, want %d: one per interval", k-1, got, k)
			}
		}

		for _, tc := range []struct {
			line string
			want int
		}{
			{`level=DEBUG msg="site-to-site status: send failed" component=bridge error=`, 1},
			{`level=WARN msg="site-to-site status: send failed" component=bridge error=`, 1},
			{`level=INFO msg="site-to-site status: control plane does not accept site-to-site status reports, retrying every interval" component=bridge status=404 code=""`, 1},
			{`level=INFO msg="site-to-site status: control plane accepts site-to-site status reports" component=bridge`, 1},
			{`level=INFO msg="site-to-site status: reported" component=bridge state=enabled tunnels=3`, 1},
		} {
			if n := logs.count(tc.line); n != tc.want {
				t.Errorf("%d lines %q, want %d:\n%s", n, tc.line, tc.want, logs.String())
			}
		}
		if n := relayLogLines(logs, "site-to-site status: send failed"); n != 2 {
			t.Errorf("%d 'send failed' lines over one refused credential and one timeout, want 2:\n%s", n, logs.String())
		}

		if after := fx.mgr.TunnelReports(); !slices.Equal(after, before) {
			t.Errorf("TunnelReports after the failed sends = %+v, want it unchanged from %+v", after, before)
		}
		// The reporter only read the manager: one handshake read and one
		// provider read per send, and one of each above.
		if got := len(fx.vpn.vpnCallsFor("TunnelPeerHandshake")); got != 6 {
			t.Errorf("handshake reads = %d, want 6: one per send and one more", got)
		}
		if got := len(fx.ipsec.establishedCalls()); got != 6 {
			t.Errorf("ipsec Established calls = %d, want 6: one per send and one more", got)
		}
		for _, m := range fx.calls() {
			if m != "vpn.TunnelPeerHandshake" && m != "ipsec.Established" {
				t.Errorf("the reporter made the manager call %s, want reads alone", m)
			}
		}
		const wantBody = `{"state":"enabled","tunnels":[` +
			`{"id":"` + s2sID1 + `","health":"up","established":true,"public_key":"%s"},` +
			`{"id":"` + s2sID2 + `","health":"up","established":true},` +
			`{"id":"` + s2sID3 + `","health":"down","reason":"client_missing"}]}`
		if got, want := mustJSON(t, client.last(t)), fmt.Sprintf(wantBody, publicKeyOf(t, fx.storedKey(t, s2sID1))); got != want {
			t.Errorf("accepted report = %s, want %s", got, want)
		}
	})
}

// ---------------------------------------------------------------------------
// The manager's reports
// ---------------------------------------------------------------------------

// TestSiteToSiteManager_TunnelReports checks the report of each tunnel the
// manager holds, in block order: a wireguard tunnel that is up with its
// interface's public key, an ipsec tunnel that is up without one, a tunnel
// that is down with its reason, and no report for an entry with an invalid or
// repeated id. Only a tunnel that is up has its remote site read, once per
// call. The reports are nil before Setup and after Teardown, and empty for a
// block without tunnels, for the zero block and for a block that is not
// enabled.
func TestSiteToSiteManager_TunnelReports(t *testing.T) {
	fx := buildS2SFixture(t, nil)
	if got := fx.mgr.TunnelReports(); got != nil {
		t.Errorf("TunnelReports() before Setup = %+v, want nil", got)
	}
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if got := fx.mgr.TunnelReports(); got == nil || len(got) != 0 {
		t.Errorf("TunnelReports() before the first Apply = %+v, want none", got)
	}
	fx.mgr.SyncSecretInventory(t.Context(), s2sInventory())
	fx.reset()

	// A manager that holds nothing calls nothing for a block without
	// tunnels, nor for the zero block, and reports no tunnel.
	for _, tc := range []struct {
		name  string
		block api.SiteToSiteConfig
	}{
		{"an empty tunnel list", api.SiteToSiteConfig{Enabled: true, Tunnels: []api.SiteToSiteTunnel{}}},
		{"the zero block", api.SiteToSiteConfig{}},
	} {
		fx.mgr.Apply(t.Context(), tc.block)
		fx.requireNoCalls(t, "Apply of "+tc.name)
		if got := fx.mgr.TunnelReports(); got == nil || len(got) != 0 {
			t.Errorf("TunnelReports() after %s = %+v, want none", tc.name, got)
		}
	}

	nouuid := office
	nouuid.ID, nouuid.Slug = "not-a-uuid", "nouuid"
	repeated := dcEast
	repeated.ID, repeated.Slug, repeated.AllowedSubnets = strings.ToUpper(s2sID1), "again", []string{"10.60.0.0/16"}
	gre := api.SiteToSiteTunnel{
		ID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e4", Slug: "gre", Kind: "gre",
		RemoteHost: "198.51.100.40", RemotePort: 4754, AllowedSubnets: []string{"10.50.0.0/16"},
	}
	fx.vpn.set(func(m *mockVPNController) {
		m.handshakes = map[string]time.Time{s2sWGIface: relayStart.Add(-time.Minute)}
	})
	fx.openvpn.set(func(p *mockTunnelProvider) { p.createErr = fmt.Errorf("start openvpn: %w", exec.ErrNotFound) })
	fx.mgr.Apply(t.Context(), s2sBlock(nouuid, branchBerlin, dcEast, repeated, office, gre))
	fx.reset()

	pub := publicKeyOf(t, fx.storedKey(t, s2sID1))
	want := []SiteToSiteTunnelReport{
		s2sUpWireGuard(s2sID1, pub, true),
		s2sUpTunnel(s2sID2, api.SiteToSiteKindIPsec, false),
		s2sDownTunnel(s2sID3, api.SiteToSiteKindOpenVPN, SiteToSiteReasonClientMissing),
		s2sDownTunnel(gre.ID, "gre", SiteToSiteReasonKindNotServed),
	}
	got := fx.mgr.TunnelReports()
	if !slices.Equal(got, want) {
		t.Errorf("TunnelReports() =\n  %+v\nwant\n  %+v", got, want)
	}
	if c := fx.vpn.vpnCallsFor("TunnelPeerHandshake"); len(c) != 1 || c[0].Args[0] != s2sWGIface || c[0].Args[1] != s2sRemoteKey {
		t.Errorf("TunnelPeerHandshake calls = %+v, want one (%s, the remote public key)", c, s2sWGIface)
	}
	if c := fx.ipsec.establishedCalls(); len(c) != 1 || c[0].tunnelID != s2sID2 {
		t.Errorf("ipsec Established calls = %+v, want one for %s", c, s2sID2)
	}
	if got := fx.calls(); !slices.Equal(got, []string{"vpn.TunnelPeerHandshake", "ipsec.Established"}) {
		t.Errorf("calls = %q, want one read per tunnel that is up", got)
	}
	const wantBody = `{"state":"enabled","tunnels":[` +
		`{"id":"` + s2sID1 + `","health":"up","established":true,"public_key":"%s"},` +
		`{"id":"` + s2sID2 + `","health":"up","established":false},` +
		`{"id":"` + s2sID3 + `","health":"down","reason":"client_missing"},` +
		`{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e4","health":"down","reason":"kind_not_served"}]}`
	if body, wantJSON := mustJSON(t, buildSiteToSiteStatusRequest(api.SiteToSiteStateEnabled, got)), fmt.Sprintf(wantBody, pub); body != wantJSON {
		t.Errorf("report body =\n  %s\nwant\n  %s", body, wantJSON)
	}

	// The local status lists the same tunnels with the same health, reason
	// and established.
	info := fx.mgr.SiteToSiteStatus()
	if info == nil || len(info.Tunnels) != len(want) {
		t.Fatalf("SiteToSiteStatus() = %+v, want an entry per report", info)
	}
	for i, r := range want {
		ti := info.Tunnels[i]
		if ti.ID != r.TunnelID || ti.Health != r.Health || ti.Reason != r.Reason || ti.Established != r.Established {
			t.Errorf("status entry %d = %+v, want the report %+v", i, ti, r)
		}
	}

	// A block that is not enabled leaves no report.
	disabled := s2sBlock(branchBerlin, dcEast)
	disabled.Enabled = false
	fx.mgr.Apply(t.Context(), disabled)
	if got := fx.mgr.TunnelReports(); got == nil || len(got) != 0 {
		t.Errorf("TunnelReports() after a block with Enabled false = %+v, want none", got)
	}

	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := fx.mgr.TunnelReports(); got != nil {
		t.Errorf("TunnelReports() after Teardown = %+v, want nil", got)
	}
}

// TestSiteToSiteManager_TunnelReportsEstablished checks whether a tunnel
// that is up reports its remote site as answering: a wireguard tunnel when
// the latest handshake with the remote peer is at most 180 s old on the
// manager's clock, an ipsec tunnel when the provider's Established says so,
// asked under a timeout of 5 s. A failed read counts false and is logged at
// Debug. SiteToSiteStatus reports the same.
func TestSiteToSiteManager_TunnelReportsEstablished(t *testing.T) {
	errRead := errors.New("no such device")
	handshake := func(at time.Time) func(*s2sFixture) {
		return func(fx *s2sFixture) {
			fx.vpn.set(func(m *mockVPNController) { m.handshakes = map[string]time.Time{s2sWGIface: at} })
		}
	}
	tests := []struct {
		name string
		// handshake sets the wireguard tunnel's handshake, provider the ipsec
		// provider's answer.
		handshake func(*s2sFixture)
		provider  func(*mockTunnelProvider)
		wireguard bool
		ipsec     bool
		// failed names the tunnel whose read fails, "" for none.
		failed string
	}{
		{
			name:      "handshake 60 s old, provider established",
			handshake: handshake(relayStart.Add(-60 * time.Second)),
			provider:  func(p *mockTunnelProvider) { p.established = true },
			wireguard: true, ipsec: true,
		},
		{
			name:      "handshake 180 s old, provider not established",
			handshake: handshake(relayStart.Add(-180 * time.Second)),
			provider:  func(p *mockTunnelProvider) { p.established = false },
			wireguard: true, ipsec: false,
		},
		{
			name:      "handshake 181 s old",
			handshake: handshake(relayStart.Add(-181 * time.Second)),
			provider:  func(p *mockTunnelProvider) { p.established = true },
			wireguard: false, ipsec: true,
		},
		{
			name:      "handshake 300 s old",
			handshake: handshake(relayStart.Add(-300 * time.Second)),
			provider:  func(p *mockTunnelProvider) { p.established = true },
			wireguard: false, ipsec: true,
		},
		{
			name:      "no handshake",
			handshake: handshake(time.Time{}),
			provider:  func(p *mockTunnelProvider) { p.established = true },
			wireguard: false, ipsec: true,
		},
		{
			name: "handshake read fails",
			handshake: func(fx *s2sFixture) {
				fx.vpn.set(func(m *mockVPNController) {
					m.handshakes = map[string]time.Time{s2sWGIface: relayStart}
					m.handshakeErr = errRead
				})
			},
			provider:  func(p *mockTunnelProvider) { p.established = true },
			wireguard: false, ipsec: true, failed: s2sID1,
		},
		{
			name:      "provider read fails",
			handshake: handshake(relayStart),
			provider: func(p *mockTunnelProvider) {
				p.established, p.establishedErr = true, errRead
			},
			wireguard: true, ipsec: false, failed: s2sID2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newS2SFixture(t, nil)
			fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast))
			tt.handshake(fx)
			fx.ipsec.set(tt.provider)
			fx.reset()

			got := fx.mgr.TunnelReports()
			if len(got) != 2 || got[0].TunnelID != s2sID1 || got[1].TunnelID != s2sID2 {
				t.Fatalf("TunnelReports() = %+v, want branch-berlin and dc-east", got)
			}
			if got[0].Established != tt.wireguard || got[1].Established != tt.ipsec {
				t.Errorf("established = %v, %v, want %v, %v", got[0].Established, got[1].Established, tt.wireguard, tt.ipsec)
			}
			for _, r := range got {
				if r.Health != api.SiteToSiteHealthUp {
					t.Errorf("tunnel %s = %+v, want up whatever its remote site answers", r.TunnelID, r)
				}
			}
			info := fx.mgr.SiteToSiteStatus()
			if info == nil || len(info.Tunnels) != 2 || info.Tunnels[0].Established != tt.wireguard || info.Tunnels[1].Established != tt.ipsec {
				t.Errorf("SiteToSiteStatus() = %+v, want established %v, %v", info, tt.wireguard, tt.ipsec)
			}

			// One read per tunnel and call: the report and the status.
			handshakes := fx.vpn.vpnCallsFor("TunnelPeerHandshake")
			if len(handshakes) != 2 {
				t.Errorf("TunnelPeerHandshake calls = %d, want 2", len(handshakes))
			}
			for _, c := range handshakes {
				if c.Args[0] != s2sWGIface || c.Args[1] != s2sRemoteKey {
					t.Errorf("TunnelPeerHandshake(%v), want (%s, the remote public key)", c.Args, s2sWGIface)
				}
			}
			established := fx.ipsec.establishedCalls()
			if len(established) != 2 {
				t.Errorf("ipsec Established calls = %d, want 2", len(established))
			}
			for _, c := range established {
				d, ok := c.ctx.Deadline()
				if c.tunnelID != s2sID2 || !ok || time.Until(d) <= 4*time.Second || time.Until(d) > 5*time.Second {
					t.Errorf("Established(%s) under a deadline %v away (set: %v), want dc-east's under one of 5 s", c.tunnelID, time.Until(d), ok)
				}
			}

			const failedMsg = `msg="bridge: site-to-site: read established failed"`
			if tt.failed == "" {
				if n := logLines(fx.logs, failedMsg); n != 0 {
					t.Errorf("%d read-failed lines, want none:\n%s", n, fx.logs.String())
				}
				return
			}
			needles := []string{"level=DEBUG", failedMsg, "component=bridge", "tunnel_id=" + tt.failed, `error="`}
			if tt.failed == s2sID1 {
				needles = append(needles, "kind=wireguard", "interface="+s2sWGIface)
			} else {
				needles = append(needles, "kind=ipsec", "interface="+s2sXfrmIface)
			}
			if n := logLines(fx.logs, needles...); n != 2 {
				t.Errorf("%d Debug lines for the failed reads, want 2 (the report and the status):\n%s", n, fx.logs.String())
			}
			if n := logLines(fx.logs, "level=WARN", failedMsg); n != 0 {
				t.Errorf("%d Warn lines for a failed read, want none:\n%s", n, fx.logs.String())
			}
		})
	}
}

// TestSiteToSiteManager_TunnelReportsReadOutsideTheMutex holds a provider's
// Established and checks that Teardown completes meanwhile, since the reports
// read whether a remote site answers outside the manager's mutex, and that
// the report holds what the read returned.
func TestSiteToSiteManager_TunnelReportsReadOutsideTheMutex(t *testing.T) {
	fx := newS2SFixture(t, nil)
	fx.mgr.Apply(t.Context(), s2sBlock(dcEast))
	started, release := make(chan struct{}), make(chan struct{})
	fx.ipsec.set(func(p *mockTunnelProvider) {
		p.established = true
		p.establishedHook = func() {
			close(started)
			<-release
		}
	})

	reports := make(chan []SiteToSiteTunnelReport, 1)
	go func() { reports <- fx.mgr.TunnelReports() }()
	<-started
	done := make(chan error, 1)
	go func() { done <- fx.mgr.Teardown() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Teardown: %v", err)
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("Teardown waited for a provider's Established")
	}
	close(release)

	got := <-reports
	if len(got) != 1 || got[0].TunnelID != s2sID2 || got[0].Health != api.SiteToSiteHealthUp || !got[0].Established {
		t.Errorf("TunnelReports() = %+v, want dc-east up and established, as it was when the read began", got)
	}
	if got := fx.mgr.TunnelReports(); got != nil {
		t.Errorf("TunnelReports() after Teardown = %+v, want nil", got)
	}
}

// TestSiteToSiteManager_TunnelReportsLeaveOutAFirstAttempt checks that a
// tunnel whose first attempt resolves its remote host outside the manager's
// mutex has no report until the attempt has an outcome, and that the Apply
// that started it signals ReportChanged once the attempt is done.
func TestSiteToSiteManager_TunnelReportsLeaveOutAFirstAttempt(t *testing.T) {
	fx := newS2SFixture(t, nil)
	// dc-east's remote host is an IP address, which is not resolved.
	fx.mgr.Apply(t.Context(), s2sBlock(dcEast))
	changed := fx.mgr.ReportChanged()
	drain(changed)

	started, release := make(chan struct{}), make(chan struct{})
	fx.resolver.set(func(r *fakeResolver) {
		r.hook = func() {
			close(started)
			<-release
		}
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		fx.mgr.Apply(context.Background(), s2sBlock(dcEast, branchBerlin))
	}()
	<-started
	if got := fx.mgr.TunnelReports(); len(got) != 1 || got[0].TunnelID != s2sID2 {
		t.Errorf("TunnelReports() during the first attempt = %+v, want dc-east alone", got)
	}
	requireNoSignal(t, changed, "an Apply whose attempt has no outcome yet")
	close(release)
	<-done

	requireSignal(t, changed, "the Apply whose attempt finished")
	got := fx.mgr.TunnelReports()
	if len(got) != 2 || got[1].TunnelID != s2sID1 || got[1].Health != api.SiteToSiteHealthUp {
		t.Errorf("TunnelReports() after the attempt = %+v, want dc-east and branch-berlin up", got)
	}
}

// TestSiteToSiteManager_ReportChangedSignals checks that Apply, Retry,
// SyncSecretInventory and Teardown each signal ReportChanged once without
// blocking, that two signals collapse into one, and that reading the reports
// signals nothing, nor does a remote site that starts to answer.
func TestSiteToSiteManager_ReportChangedSignals(t *testing.T) {
	fx := newS2SFixture(t, nil)
	changed := fx.mgr.ReportChanged()
	drain(changed)
	requireOne := func(what string) {
		t.Helper()
		requireSignal(t, changed, what)
		requireNoSignal(t, changed, what+", a second time")
	}

	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast))
	requireOne("an Apply")
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast))
	requireOne("an Apply of the same block")
	fx.mgr.Retry(t.Context())
	requireOne("a Retry")
	fx.mgr.SyncSecretInventory(t.Context(), s2sInventory())
	requireOne("a SyncSecretInventory")
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast))
	fx.mgr.Retry(t.Context())
	requireOne("an Apply and a Retry")

	// Reading the reports, and a remote site that starts to answer, signal
	// nothing.
	fx.vpn.set(func(m *mockVPNController) { m.handshakes = map[string]time.Time{s2sWGIface: relayStart} })
	fx.ipsec.set(func(p *mockTunnelProvider) { p.established = true })
	if got := fx.mgr.TunnelReports(); len(got) != 2 || !got[0].Established || !got[1].Established {
		t.Errorf("TunnelReports() = %+v, want both remote sites answering", got)
	}
	_ = fx.mgr.SiteToSiteStatus()
	requireNoSignal(t, changed, "reading the reports")

	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	requireOne("Teardown")
}
