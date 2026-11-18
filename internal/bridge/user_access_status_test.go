package bridge

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The composition root hands the reporter the control-plane client and the
// user access manager; these assertions keep both seams satisfiable by them.
var (
	_ UserAccessStatusClient         = (*api.ControlPlane)(nil)
	_ UserAccessProviderReportSource = (*UserAccessManager)(nil)
)

const testUserAccessNodeID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c3"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fakeUserAccessStatusClient records every report it is handed and answers
// the n-th with errs[n] when that is set, and with a receipt at
// testAcceptedAt otherwise.
type fakeUserAccessStatusClient struct {
	mu       sync.Mutex
	nodeIDs  []string
	requests []api.UserAccessStatusRequest
	errs     []error
}

func (c *fakeUserAccessStatusClient) ReportUserAccessStatus(_ context.Context, nodeID string, req api.UserAccessStatusRequest) (*api.UserAccessStatusResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := len(c.requests)
	c.nodeIDs = append(c.nodeIDs, nodeID)
	c.requests = append(c.requests, req)
	if idx < len(c.errs) && c.errs[idx] != nil {
		return nil, c.errs[idx]
	}
	return &api.UserAccessStatusResponse{AcceptedAt: testAcceptedAt}, nil
}

func (c *fakeUserAccessStatusClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *fakeUserAccessStatusClient) recorded() (nodeIDs []string, reqs []api.UserAccessStatusRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.nodeIDs), slices.Clone(c.requests)
}

// last returns the last report the client was handed.
func (c *fakeUserAccessStatusClient) last(t *testing.T) api.UserAccessStatusRequest {
	t.Helper()
	_, reqs := c.recorded()
	if len(reqs) == 0 {
		t.Fatal("no report was sent")
	}
	return reqs[len(reqs)-1]
}

// startUserAccessStatusReporter runs r.Run in a goroutine and returns a stop
// function that cancels it and waits for Run to return nil. The stop is also
// registered as a cleanup, so a failed assertion does not leave the goroutine
// behind, which a synctest bubble would report as a deadlock.
func startUserAccessStatusReporter(t *testing.T, r *UserAccessStatusReporter) (stop func()) {
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

// fakeProviderSource is a UserAccessProviderReportSource whose reports a test
// sets. It is built inside the synctest bubble that uses it, since its channel
// belongs to the bubble that made it.
type fakeProviderSource struct {
	mu      sync.Mutex
	reports []UserAccessProviderReport
	reads   int
	changed chan struct{}
}

func newFakeProviderSource(reports ...UserAccessProviderReport) *fakeProviderSource {
	return &fakeProviderSource{reports: reports, changed: make(chan struct{}, 1)}
}

func (s *fakeProviderSource) ProviderReports() []UserAccessProviderReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	return slices.Clone(s.reports)
}

func (s *fakeProviderSource) ReportChanged() <-chan struct{} { return s.changed }

// readCount returns how often ProviderReports was called.
func (s *fakeProviderSource) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// store replaces the reports without a signal.
func (s *fakeProviderSource) store(reports ...UserAccessProviderReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = reports
}

// set replaces the reports and signals the change.
func (s *fakeProviderSource) set(reports ...UserAccessProviderReport) {
	s.store(reports...)
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// Public keys of wireguard providers in reports.
var (
	uaPublicKey1 = deviceKey(0xa1)
	uaPublicKey2 = deviceKey(0xa2)
)

// upWireGuard returns the report of a wireguard provider that is up.
func upWireGuard(id, publicKey string, connected int) UserAccessProviderReport {
	return UserAccessProviderReport{ProviderID: id, Kind: api.UserAccessKindWireGuard, Health: api.UserAccessHealthUp, PublicKey: publicKey, ConnectedDevices: connected}
}

// upVendor returns the report of a vendor provider that is up.
func upVendor(id, kind string) UserAccessProviderReport {
	return UserAccessProviderReport{ProviderID: id, Kind: kind, Health: api.UserAccessHealthUp}
}

// downProvider returns the report of a provider that is down for reason.
func downProvider(id, kind, reason string) UserAccessProviderReport {
	return UserAccessProviderReport{ProviderID: id, Kind: kind, Health: api.UserAccessHealthDown, Reason: reason}
}

// userAccessEntryIDs returns the ids of a report's entries, in order.
func userAccessEntryIDs(req api.UserAccessStatusRequest) []string {
	var ids []string
	for _, e := range req.Providers {
		ids = append(ids, e.ID)
	}
	return ids
}

// storedPublicKey returns the public half of the key the fixture's store
// keeps for id.
func (fx *uaFixture) storedPublicKey(t *testing.T, id string) string {
	t.Helper()
	key, err := NewInterfaceKeyStore(fx.keyDir).LoadOrCreate(id)
	if err != nil {
		t.Fatalf("LoadOrCreate(%s): %v", id, err)
	}
	return key.PublicKey().String()
}

// handshakeReads returns the interfaces the access double was asked for
// handshakes, in order.
func handshakeReads(access *mockAccessController) []string {
	var out []string
	for _, c := range access.accessCallsFor("PeerHandshakes") {
		out = append(out, c.Args[0].(string))
	}
	return out
}

// ---------------------------------------------------------------------------
// Construction and Run
// ---------------------------------------------------------------------------

// The reporter's timing runs on synctest's fake clock: synctest.Wait returns
// once Run blocks on its ticker again, so every count below is exact and no
// assertion waits on the wall clock.

func TestUserAccessStatusReporter_SendsItsStateAtStart(t *testing.T) {
	for _, tc := range []struct {
		optedOut bool
		want     string
	}{
		{optedOut: false, want: api.UserAccessStateEnabled},
		{optedOut: true, want: api.UserAccessStateOptedOut},
	} {
		t.Run(tc.want, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := &fakeUserAccessStatusClient{}
				logger, logs := newRelayLogger()
				r := NewUserAccessStatusReporter(time.Hour, testUserAccessNodeID, client, tc.optedOut, nil, logger)

				startUserAccessStatusReporter(t, r)
				synctest.Wait()

				nodeIDs, reqs := client.recorded()
				if len(reqs) != 1 {
					t.Fatalf("reports before the first tick = %d, want exactly 1", len(reqs))
				}
				if got, want := mustJSON(t, reqs[0]), `{"state":"`+tc.want+`"}`; got != want {
					t.Errorf("body = %s, want %s", got, want)
				}
				if !slices.Equal(nodeIDs, []string{testUserAccessNodeID}) {
					t.Errorf("node IDs = %v, want [%s]", nodeIDs, testUserAccessNodeID)
				}
				line := relayLogLine(t, logs, "user access status: reporter started")
				for _, want := range []string{"level=INFO", "component=bridge", "interval=1h0m0s", "state=" + tc.want} {
					if !strings.Contains(line, want) {
						t.Errorf("started log = %q, want it to contain %q", line, want)
					}
				}
			})
		})
	}
}

// TestUserAccessStatusReporter_OptedOutSendsNoProviders checks that an
// opted-out report carries no providers and does not read the source, which
// plexd up never hands an opted-out reporter.
func TestUserAccessStatusReporter_OptedOutSendsNoProviders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeProviderSource(upWireGuard(uaID1, uaPublicKey1, 1), downProvider(uaID2, api.UserAccessKindTailscale, UserAccessReasonAuthSecretNotListed))
		client := &fakeUserAccessStatusClient{}
		r := NewUserAccessStatusReporter(interval, testUserAccessNodeID, client, true, source, discardLogger())

		startUserAccessStatusReporter(t, r)
		synctest.Wait()
		source.set(upWireGuard(uaID1, uaPublicKey2, 1))
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
			t.Errorf("ProviderReports read %d times on an opted-out bridge, want 0", n)
		}
	})
}

func TestUserAccessStatusReporter_ResendsEveryTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeProviderSource(upWireGuard(uaID1, uaPublicKey1, 0))
		client := &fakeUserAccessStatusClient{}
		r := NewUserAccessStatusReporter(interval, testUserAccessNodeID, client, false, source, discardLogger())

		startUserAccessStatusReporter(t, r)
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
			if got := userAccessEntryIDs(req); !slices.Equal(got, []string{uaID1}) {
				t.Errorf("report %d entries = %q, want the provider", k, got)
			}
		}
	})
}

func TestNewUserAccessStatusReporter_NonPositiveIntervalRunsAtDefault(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := &fakeUserAccessStatusClient{}
				logger, logs := newRelayLogger()

				r := NewUserAccessStatusReporter(interval, testUserAccessNodeID, client, false, nil, logger)
				if r.interval != 30*time.Second {
					t.Errorf("interval = %v, want 30s", r.interval)
				}

				startUserAccessStatusReporter(t, r)
				synctest.Wait()
				line := relayLogLine(t, logs, "user access status: reporter started")
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

func TestUserAccessStatusReporter_FailedSendIsNotRetriedWithinItsTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		client := &fakeUserAccessStatusClient{errs: []error{context.DeadlineExceeded}}
		logger, logs := newRelayLogger()
		r := NewUserAccessStatusReporter(interval, testUserAccessNodeID, client, false, nil, logger)

		startUserAccessStatusReporter(t, r)
		synctest.Wait()
		line := relayLogLine(t, logs, "user access status: send failed")
		for _, want := range []string{"level=WARN", "component=bridge", `error="context deadline exceeded"`} {
			if !strings.Contains(line, want) {
				t.Errorf("send failed log = %q, want it to contain %q", line, want)
			}
		}
		if n := relayLogLines(logs, "user access status: reported"); n != 0 {
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
		line = relayLogLine(t, logs, "user access status: reported")
		for _, want := range []string{"level=INFO", "state=enabled", "providers=0"} {
			if !strings.Contains(line, want) {
				t.Errorf("reported log = %q, want it to contain %q", line, want)
			}
		}
		if n := relayLogLines(logs, "user access status: send failed"); n != 1 {
			t.Errorf("send failed logged %d times, want 1", n)
		}
	})
}

func TestUserAccessStatusReporter_NoSendAtShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := newFakeProviderSource(upWireGuard(uaID1, uaPublicKey1, 0))
		client := &fakeUserAccessStatusClient{}
		r := NewUserAccessStatusReporter(time.Hour, testUserAccessNodeID, client, false, source, discardLogger())

		stop := startUserAccessStatusReporter(t, r)
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

func TestUserAccessStatusReporter_NotServedLoggedOnTransitions(t *testing.T) {
	const (
		notServedMsg = "user access status: control plane does not accept user access status reports, retrying every interval"
		recoveredMsg = "user access status: control plane accepts user access status reports"
		reportedMsg  = "user access status: reported"
	)
	tests := []struct {
		name     string
		err      *api.APIError
		wantAttr string
	}{
		{name: "404 without code", err: &api.APIError{StatusCode: 404}, wantAttr: `status=404 code=""`},
		{
			name:     "501 user_access_status_not_provisioned",
			err:      &api.APIError{StatusCode: 501, Code: "user_access_status_not_provisioned"},
			wantAttr: "status=501 code=user_access_status_not_provisioned",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeUserAccessStatusClient{errs: []error{tt.err, tt.err, tt.err}}
			logger, logs := newRelayLogger()
			r := NewUserAccessStatusReporter(time.Hour, testUserAccessNodeID, client, false, nil, logger)
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

func TestUserAccessStatusReporter_NodeGoneWarnsOnEverySend(t *testing.T) {
	const msg = "user access status: rejected, this node was removed"
	gone := &api.APIError{StatusCode: 404, Code: "user_access_status_node_gone"}
	client := &fakeUserAccessStatusClient{errs: []error{gone, gone}}
	logger, logs := newRelayLogger()
	r := NewUserAccessStatusReporter(time.Hour, testUserAccessNodeID, client, false, nil, logger)

	for range 2 {
		r.reportOnce(context.Background())
	}

	if n := logs.count(`level=WARN msg="` + msg + `" component=bridge code=user_access_status_node_gone`); n != 2 {
		t.Errorf("node gone lines at Warn with the code = %d over two sends, want 2:\n%s", n, logs.String())
	}
	if strings.Contains(logs.String(), "does not accept user access status reports") {
		t.Errorf("user_access_status_node_gone was logged as not served:\n%s", logs.String())
	}
}

func TestUserAccessStatusReporter_SendFailuresWarn(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "400 malformed_user_access_status", err: &api.APIError{StatusCode: 400, Code: "malformed_user_access_status"}},
		{name: "400 invalid_user_access_status", err: &api.APIError{StatusCode: 400, Code: "invalid_user_access_status"}},
		{name: "413 user_access_status_body_too_large", err: &api.APIError{StatusCode: 413, Code: "user_access_status_body_too_large"}},
		{name: "500", err: &api.APIError{StatusCode: 500, Code: "internal"}},
		{name: "501 for another surface", err: &api.APIError{StatusCode: 501, Code: "ingress_status_not_provisioned"}},
		{name: "deadline exceeded", err: fmt.Errorf("put user-access-status: %w", context.DeadlineExceeded)},
		{name: "transport error", err: errors.New("dial tcp: connection refused")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeUserAccessStatusClient{errs: []error{tt.err}}
			logger, logs := newRelayLogger()
			r := NewUserAccessStatusReporter(time.Hour, testUserAccessNodeID, client, false, nil, logger)

			r.reportOnce(context.Background())

			if n := client.calls(); n != 1 {
				t.Errorf("reports = %d within one send, want 1 (no retry)", n)
			}
			line := relayLogLine(t, logs, "user access status: send failed")
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
func TestUserAccessStatusReporter_RefusedCredentialLoggedAtDebug(t *testing.T) {
	client := &fakeUserAccessStatusClient{errs: []error{fmt.Errorf("x: %w", api.ErrCredentialRefused)}}
	logger, logs := newRelayLogger()
	r := NewUserAccessStatusReporter(time.Hour, testUserAccessNodeID, client, false, nil, logger)

	r.reportOnce(context.Background())

	line := relayLogLine(t, logs, "user access status: send failed")
	for _, want := range []string{"level=DEBUG", "component=bridge", "error="} {
		if !strings.Contains(line, want) {
			t.Errorf("send failed log = %q, want it to contain %q", line, want)
		}
	}
	if got := logs.String(); strings.Contains(got, "level=INFO") || strings.Contains(got, "level=WARN") || strings.Contains(got, "level=ERROR") {
		t.Errorf("logs = %s, want nothing above Debug for a refused credential", got)
	}
}

func TestUserAccessStatusReporter_CancelledSendIsNotLogged(t *testing.T) {
	client := &fakeUserAccessStatusClient{errs: []error{context.Canceled}}
	logger, logs := newRelayLogger()
	r := NewUserAccessStatusReporter(time.Hour, testUserAccessNodeID, client, false, nil, logger)

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

func TestUserAccessStatusReporter_ReportedOnceAcceptedOnEverySend(t *testing.T) {
	const (
		reportedMsg = "user access status: reported"
		acceptedMsg = "user access status: accepted"
	)
	client := &fakeUserAccessStatusClient{}
	logger, logs := newRelayLogger()
	r := NewUserAccessStatusReporter(time.Hour, testUserAccessNodeID, client, true, nil, logger)
	ctx := context.Background()

	for range 3 {
		r.reportOnce(ctx)
	}

	line := relayLogLine(t, logs, reportedMsg)
	for _, want := range []string{"level=INFO", "component=bridge", "state=opted_out", "providers=0"} {
		if !strings.Contains(line, want) {
			t.Errorf("reported log = %q, want it to contain %q", line, want)
		}
	}
	if n := logs.count(`level=DEBUG msg="` + acceptedMsg + `" component=bridge state=opted_out providers=0 accepted_at=2026-10-30T10:15:30.123Z`); n != 3 {
		t.Errorf("accepted lines at Debug with the state, the provider count and the receipt's accepted_at = %d over three accepted sends, want 3:\n%s", n, logs.String())
	}
}

func TestUserAccessStatusReporter_LogsTheProviderCount(t *testing.T) {
	source := newFakeProviderSource(
		upWireGuard(uaID1, uaPublicKey1, 0),
		downProvider(uaID2, api.UserAccessKindWireGuard, UserAccessReasonBindFailed),
		upVendor(uaID3, api.UserAccessKindNetbird),
	)
	client := &fakeUserAccessStatusClient{}
	logger, logs := newRelayLogger()
	r := NewUserAccessStatusReporter(time.Hour, testUserAccessNodeID, client, false, source, logger)

	r.reportOnce(context.Background())

	if n := logs.count(`level=INFO msg="user access status: reported" component=bridge state=enabled providers=3`); n != 1 {
		t.Errorf("Info 'user access status: reported' with state=enabled providers=3 logged %d times, want 1:\n%s", n, logs.String())
	}
	if n := logs.count(`level=DEBUG msg="user access status: accepted" component=bridge state=enabled providers=3`); n != 1 {
		t.Errorf("Debug 'user access status: accepted' with providers=3 logged %d times, want 1:\n%s", n, logs.String())
	}
}

// ---------------------------------------------------------------------------
// Provider entries
// ---------------------------------------------------------------------------

// TestBuildUserAccessStatusRequest_Members checks which members each entry
// carries: public_key and connected_devices exactly for a wireguard provider
// that is up, connected_devices 0 included, and reason exactly for a
// provider that is down. A member the report sets where the contract forbids
// it is dropped.
func TestBuildUserAccessStatusRequest_Members(t *testing.T) {
	tests := []struct {
		name   string
		report UserAccessProviderReport
		want   string
	}{
		{
			name:   "wireguard up without connected devices",
			report: upWireGuard(uaID1, uaPublicKey1, 0),
			want:   `{"id":"` + uaID1 + `","health":"up","public_key":"` + uaPublicKey1 + `","connected_devices":0}`,
		},
		{
			name:   "wireguard up with connected devices",
			report: upWireGuard(uaID1, uaPublicKey1, 3),
			want:   `{"id":"` + uaID1 + `","health":"up","public_key":"` + uaPublicKey1 + `","connected_devices":3}`,
		},
		{
			name:   "wireguard up past the contract's ceiling",
			report: upWireGuard(uaID1, uaPublicKey1, 5000),
			want:   `{"id":"` + uaID1 + `","health":"up","public_key":"` + uaPublicKey1 + `","connected_devices":1024}`,
		},
		{
			name: "wireguard down",
			report: UserAccessProviderReport{
				ProviderID: uaID1, Kind: api.UserAccessKindWireGuard, Health: api.UserAccessHealthDown,
				Reason: UserAccessReasonBindFailed, PublicKey: uaPublicKey1, ConnectedDevices: 2,
			},
			want: `{"id":"` + uaID1 + `","health":"down","reason":"bind_failed"}`,
		},
		{
			name: "tailscale up",
			report: UserAccessProviderReport{
				ProviderID: uaID2, Kind: api.UserAccessKindTailscale, Health: api.UserAccessHealthUp,
				PublicKey: uaPublicKey2, ConnectedDevices: 2,
			},
			want: `{"id":"` + uaID2 + `","health":"up"}`,
		},
		{
			name:   "netbird up",
			report: upVendor(uaID3, api.UserAccessKindNetbird),
			want:   `{"id":"` + uaID3 + `","health":"up"}`,
		},
		{
			name:   "tailscale down",
			report: downProvider(uaID2, api.UserAccessKindTailscale, UserAccessReasonAuthSecretNotListed),
			want:   `{"id":"` + uaID2 + `","health":"down","reason":"auth_secret_not_listed"}`,
		},
		{
			name:   "unknown kind down",
			report: downProvider(uaID3, "openvpn", UserAccessReasonKindNotServed),
			want:   `{"id":"` + uaID3 + `","health":"down","reason":"kind_not_served"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := buildUserAccessStatusRequest(api.UserAccessStateEnabled, []UserAccessProviderReport{tt.report})
			if len(req.Providers) != 1 {
				t.Fatalf("providers = %+v, want one entry", req.Providers)
			}
			if got := mustJSON(t, req.Providers[0]); got != tt.want {
				t.Errorf("entry = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestBuildUserAccessStatusRequest_StateAlone(t *testing.T) {
	reports := []UserAccessProviderReport{upWireGuard(uaID1, uaPublicKey1, 1)}
	for _, tc := range []struct {
		name    string
		state   string
		reports []UserAccessProviderReport
		want    string
	}{
		{"opted_out with reports", api.UserAccessStateOptedOut, reports, `{"state":"opted_out"}`},
		{"enabled without reports", api.UserAccessStateEnabled, nil, `{"state":"enabled"}`},
		{"enabled with an empty list", api.UserAccessStateEnabled, []UserAccessProviderReport{}, `{"state":"enabled"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := buildUserAccessStatusRequest(tc.state, tc.reports)
			if req.Providers != nil {
				t.Errorf("providers = %+v, want none", req.Providers)
			}
			if got := mustJSON(t, req); got != tc.want {
				t.Errorf("body = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestUserAccessStatusReporter_ReportsTheFirst256Providers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		reports := make([]UserAccessProviderReport, 300)
		for i := range reports {
			reports[i] = upWireGuard(fmt.Sprintf("0190a8b8-a0c0-7a0a-8a0a-%012x", i+1), uaPublicKey1, 0)
		}
		source := newFakeProviderSource(reports...)
		client := &fakeUserAccessStatusClient{}
		logger, logs := newRelayLogger()
		r := NewUserAccessStatusReporter(interval, testUserAccessNodeID, client, false, source, logger)

		startUserAccessStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(interval)
		synctest.Wait()

		_, reqs := client.recorded()
		if len(reqs) != 2 {
			t.Fatalf("reports = %d, want 2: the one at start and one tick", len(reqs))
		}
		var want []string
		for _, rep := range reports[:256] {
			want = append(want, rep.ProviderID)
		}
		for k, req := range reqs {
			if got := userAccessEntryIDs(req); !slices.Equal(got, want) {
				t.Errorf("report %d holds %d entries, want the first 256 in order", k, len(got))
			}
		}
		const msg = "user access status: more providers than a report carries, reporting the first 256"
		warn := `level=WARN msg="` + msg + `" component=bridge providers=300`
		if n := logs.count(warn); n != 1 {
			t.Errorf("%d Warns %q with providers=300 over two sends, want 1:\n%s", n, msg, logs.String())
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
			t.Errorf("%d Warns with providers=300 after entering the state again, want 2:\n%s", n, logs.String())
		}
	})
}

// TestUserAccessStatusReporter_SendsOnChange checks that a change of an
// entry's health, reason or public key, and a provider added, each send at
// once, that a change of connected_devices alone does not, and that an
// on-change send restarts the interval.
func TestUserAccessStatusReporter_SendsOnChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeProviderSource(upWireGuard(uaID1, uaPublicKey1, 0))
		client := &fakeUserAccessStatusClient{}
		r := NewUserAccessStatusReporter(interval, testUserAccessNodeID, client, false, source, discardLogger())

		startUserAccessStatusReporter(t, r)
		synctest.Wait()

		steps := []struct {
			what    string
			reports []UserAccessProviderReport
			sends   bool
		}{
			{"connected_devices alone", []UserAccessProviderReport{upWireGuard(uaID1, uaPublicKey1, 3)}, false},
			{"public_key", []UserAccessProviderReport{upWireGuard(uaID1, uaPublicKey2, 3)}, true},
			{"health", []UserAccessProviderReport{downProvider(uaID1, api.UserAccessKindWireGuard, UserAccessReasonBindFailed)}, true},
			{"reason", []UserAccessProviderReport{downProvider(uaID1, api.UserAccessKindWireGuard, UserAccessReasonSetupFailed)}, true},
			{"a provider added", []UserAccessProviderReport{
				downProvider(uaID1, api.UserAccessKindWireGuard, UserAccessReasonSetupFailed),
				upVendor(uaID2, api.UserAccessKindTailscale),
			}, true},
			{"nothing", []UserAccessProviderReport{
				downProvider(uaID1, api.UserAccessKindWireGuard, UserAccessReasonSetupFailed),
				upVendor(uaID2, api.UserAccessKindTailscale),
			}, false},
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
				if got, wantBody := mustJSON(t, client.last(t)), mustJSON(t, buildUserAccessStatusRequest(api.UserAccessStateEnabled, step.reports)); got != wantBody {
					t.Errorf("report after a change of %s = %s, want %s", step.what, got, wantBody)
				}
			}
		}

		// The last on-change send, 50 s after the start, restarted the
		// interval; the change after it sent nothing.
		time.Sleep(interval - 10*time.Second - time.Millisecond)
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

// TestUserAccessStatusReporter_TickCarriesConnectedDevices checks that a
// moving count of connected devices waits for the tick, which carries the
// count as it is then.
func TestUserAccessStatusReporter_TickCarriesConnectedDevices(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeProviderSource(upWireGuard(uaID1, uaPublicKey1, 0))
		client := &fakeUserAccessStatusClient{}
		r := NewUserAccessStatusReporter(interval, testUserAccessNodeID, client, false, source, discardLogger())

		startUserAccessStatusReporter(t, r)
		synctest.Wait()
		for _, n := range []int{1, 2, 5} {
			time.Sleep(10 * time.Second)
			source.set(upWireGuard(uaID1, uaPublicKey1, n))
			synctest.Wait()
		}
		if got := client.calls(); got != 1 {
			t.Fatalf("reports after three changes of connected_devices alone = %d, want only the one at start", got)
		}

		time.Sleep(interval - 30*time.Second)
		synctest.Wait()
		_, reqs := client.recorded()
		if len(reqs) != 2 {
			t.Fatalf("reports after the tick = %d, want 2", len(reqs))
		}
		if got := reqs[1].Providers; len(got) != 1 || got[0].ConnectedDevices == nil || *got[0].ConnectedDevices != 5 {
			t.Errorf("tick report providers = %s, want connected_devices 5", mustJSON(t, got))
		}
	})
}

func TestUserAccessStatusReporter_ChangesAreBoundedByTheGap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeProviderSource(upWireGuard(uaID1, uaPublicKey1, 0))
		client := &fakeUserAccessStatusClient{}
		r := NewUserAccessStatusReporter(interval, testUserAccessNodeID, client, false, source, discardLogger())

		startUserAccessStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.set(downProvider(uaID1, api.UserAccessKindWireGuard, UserAccessReasonBindFailed))
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Fatalf("reports after the first change = %d, want 2", got)
		}

		time.Sleep(time.Second)
		source.set(upWireGuard(uaID1, uaPublicKey1, 0))
		synctest.Wait()
		time.Sleep(4*time.Second - time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Errorf("reports just before 5s after the first on-change send = %d, want still 2", got)
		}
		// The latest reports are the ones the timer sends.
		source.store(downProvider(uaID1, api.UserAccessKindWireGuard, UserAccessReasonSetupFailed))
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		_, reqs := client.recorded()
		if len(reqs) != 3 {
			t.Fatalf("reports just after 5s after the first on-change send = %d, want 3", len(reqs))
		}
		if got := reqs[2].Providers; len(got) != 1 || got[0].Reason != UserAccessReasonSetupFailed {
			t.Errorf("second on-change report providers = %s, want the latest reports (down with setup_failed)", mustJSON(t, got))
		}
	})
}

// TestUserAccessStatusReporter_GapEndsWithoutAChange checks that a change
// inside the gap that is undone before the gap ends sends nothing.
func TestUserAccessStatusReporter_GapEndsWithoutAChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := newFakeProviderSource(upWireGuard(uaID1, uaPublicKey1, 0))
		client := &fakeUserAccessStatusClient{}
		r := NewUserAccessStatusReporter(time.Minute, testUserAccessNodeID, client, false, source, discardLogger())

		startUserAccessStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.set(downProvider(uaID1, api.UserAccessKindWireGuard, UserAccessReasonBindFailed))
		synctest.Wait()
		time.Sleep(time.Second)
		source.set(upWireGuard(uaID1, uaPublicKey1, 0))
		synctest.Wait()
		source.store(downProvider(uaID1, api.UserAccessKindWireGuard, UserAccessReasonBindFailed))
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Errorf("reports after a gap whose change was undone = %d, want 2", got)
		}
	})
}

func TestUserAccessStatusReporter_FailedOnChangeSendIsNotRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		source := newFakeProviderSource(upWireGuard(uaID1, uaPublicKey1, 0))
		client := &fakeUserAccessStatusClient{errs: []error{nil, &api.APIError{StatusCode: 400, Code: "invalid_user_access_status"}}}
		logger, logs := newRelayLogger()
		r := NewUserAccessStatusReporter(interval, testUserAccessNodeID, client, false, source, logger)

		startUserAccessStatusReporter(t, r)
		synctest.Wait()
		time.Sleep(10 * time.Second)
		source.set(downProvider(uaID1, api.UserAccessKindWireGuard, UserAccessReasonBindFailed))
		synctest.Wait()
		if n := logs.count(`level=WARN msg="user access status: send failed"`); n != 1 {
			t.Errorf("%d Warns 'user access status: send failed' after the refused on-change send, want 1:\n%s", n, logs.String())
		}

		time.Sleep(interval - time.Millisecond)
		synctest.Wait()
		if got := client.calls(); got != 2 {
			t.Errorf("reports before the tick = %d, want 2: no retry of the refused one", got)
		}
		source.store(upWireGuard(uaID1, uaPublicKey2, 0))
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		_, reqs := client.recorded()
		if len(reqs) != 3 {
			t.Fatalf("reports after the tick = %d, want 3", len(reqs))
		}
		if got := reqs[2].Providers; len(got) != 1 || got[0].PublicKey != uaPublicKey2 {
			t.Errorf("tick report providers = %s, want the reports as they then are", mustJSON(t, got))
		}
	})
}

func TestUserAccessStatusReporter_CancelWhileTheGapTimerIsArmed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := newFakeProviderSource(upWireGuard(uaID1, uaPublicKey1, 0))
		client := &fakeUserAccessStatusClient{}
		r := NewUserAccessStatusReporter(time.Minute, testUserAccessNodeID, client, false, source, discardLogger())

		stop := startUserAccessStatusReporter(t, r)
		synctest.Wait()
		source.set(downProvider(uaID1, api.UserAccessKindWireGuard, UserAccessReasonBindFailed))
		synctest.Wait()
		time.Sleep(time.Second)
		source.set(upWireGuard(uaID1, uaPublicKey1, 0))
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

// TestUserAccessStatusReporter_SendFailuresLeaveTheManagerAlone runs the
// reporter over a real manager against a control plane that refuses the
// credential, times out, and does not serve the operation before it accepts
// a report: each failure is logged at its level, the loop sends once per
// interval throughout, and the manager serves and reports as before.
func TestUserAccessStatusReporter_SendFailuresLeaveTheManagerAlone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Minute
		fx := newUAFixture(t, nil)
		fx.access.peerHandshakes = map[string]map[string]time.Time{
			uaIface1: {alice.PublicKey: relayStart.Add(-time.Minute)},
		}
		fx.mgr.Apply(t.Context(), uaBlock(fieldTeam, vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join")))
		drain(fx.mgr.ReportChanged())
		before := fx.mgr.ProviderReports()
		fx.reset()

		client := &fakeUserAccessStatusClient{errs: []error{
			fmt.Errorf("put user-access-status: %w", api.ErrCredentialRefused),
			fmt.Errorf("put user-access-status: %w", context.DeadlineExceeded),
			&api.APIError{StatusCode: 404},
			&api.APIError{StatusCode: 404},
		}}
		logger, logs := newRelayLogger()
		r := NewUserAccessStatusReporter(interval, testUserAccessNodeID, client, false, fx.mgr, logger)

		startUserAccessStatusReporter(t, r)
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
			{`level=DEBUG msg="user access status: send failed" component=bridge error=`, 1},
			{`level=WARN msg="user access status: send failed" component=bridge error=`, 1},
			{`level=INFO msg="user access status: control plane does not accept user access status reports, retrying every interval" component=bridge status=404 code=""`, 1},
			{`level=INFO msg="user access status: control plane accepts user access status reports" component=bridge`, 1},
			{`level=INFO msg="user access status: reported" component=bridge state=enabled providers=2`, 1},
		} {
			if n := logs.count(tc.line); n != tc.want {
				t.Errorf("%d lines %q, want %d:\n%s", n, tc.line, tc.want, logs.String())
			}
		}
		if n := relayLogLines(logs, "user access status: send failed"); n != 2 {
			t.Errorf("%d 'send failed' lines over one refused credential and one timeout, want 2:\n%s", n, logs.String())
		}

		if after := fx.mgr.ProviderReports(); !slices.Equal(after, before) {
			t.Errorf("ProviderReports after the failed sends = %+v, want it unchanged from %+v", after, before)
		}
		// The reporter only read the manager: one handshake read per send and
		// the one above.
		if got := handshakeReads(fx.access); len(got) != 6 {
			t.Errorf("handshake reads = %q, want 6: one per send and one more", got)
		}
		for _, m := range fx.calls() {
			if m != "access.PeerHandshakes" {
				t.Errorf("the reporter made the manager call %s, want reads alone", m)
			}
		}
		const wantBody = `{"state":"enabled","providers":[` +
			`{"id":"` + uaID1 + `","health":"up","public_key":"%s","connected_devices":1},` +
			`{"id":"` + uaID2 + `","health":"down","reason":"auth_secret_not_listed"}]}`
		if got, want := mustJSON(t, client.last(t)), fmt.Sprintf(wantBody, fx.storedPublicKey(t, uaID1)); got != want {
			t.Errorf("accepted report = %s, want %s", got, want)
		}
	})
}

// ---------------------------------------------------------------------------
// The manager's reports
// ---------------------------------------------------------------------------

// TestUserAccessManager_ProviderReports checks the report of each provider
// the manager holds, in block order: a wireguard provider that is up with its
// interface's public key, a provider that is down with its reason, a vendor
// provider that is up with neither, and no report for an entry with an
// invalid or repeated id. Only a wireguard provider that is up has its
// handshakes read, once per call.
func TestUserAccessManager_ProviderReports(t *testing.T) {
	const id4 = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e4"
	fx := buildUAFixture(t, nil)
	if got := fx.mgr.ProviderReports(); got != nil {
		t.Errorf("ProviderReports() before Setup = %+v, want nil", got)
	}
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if got := fx.mgr.ProviderReports(); len(got) != 0 {
		t.Errorf("ProviderReports() before the first Apply = %+v, want none", got)
	}

	fx.access.createInterfaceErrFor = map[string]error{uaIface2: fmt.Errorf("bind: %w", ErrListenPortInUse)}
	fx.secrets.set("ts-join", 1, "tskey")
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("ts-join", 1))
	fx.mgr.Apply(t.Context(), uaBlock(
		wgProvider("not-a-uuid", "nouuid", 51829, "10.96.0.0/24"),
		fieldTeam,
		wgProvider(uaID2, "office", 51822, "10.98.0.0/24"),
		vendorProvider(uaID3, "tailnet", api.UserAccessKindTailscale, "ts-join"),
		wgProvider(strings.ToUpper(uaID1), "again", 51830, "10.97.0.0/24"),
		api.UserAccessProvider{ID: id4, Slug: "vpn", Kind: "openvpn"},
	))
	fx.reset()

	pub := fx.storedPublicKey(t, uaID1)
	want := []UserAccessProviderReport{
		upWireGuard(uaID1, pub, 0),
		downProvider(uaID2, api.UserAccessKindWireGuard, UserAccessReasonBindFailed),
		upVendor(uaID3, api.UserAccessKindTailscale),
		downProvider(id4, "openvpn", UserAccessReasonKindNotServed),
	}
	got := fx.mgr.ProviderReports()
	if !slices.Equal(got, want) {
		t.Errorf("ProviderReports() =\n  %+v\nwant\n  %+v", got, want)
	}
	if reads := handshakeReads(fx.access); !slices.Equal(reads, []string{uaIface1}) {
		t.Errorf("handshake reads = %q, want one of %s", reads, uaIface1)
	}
	const wantBody = `{"state":"enabled","providers":[` +
		`{"id":"` + uaID1 + `","health":"up","public_key":"%s","connected_devices":0},` +
		`{"id":"` + uaID2 + `","health":"down","reason":"bind_failed"},` +
		`{"id":"` + uaID3 + `","health":"up"},` +
		`{"id":"` + id4 + `","health":"down","reason":"kind_not_served"}]}`
	if body, wantJSON := mustJSON(t, buildUserAccessStatusRequest(api.UserAccessStateEnabled, got)), fmt.Sprintf(wantBody, pub); body != wantJSON {
		t.Errorf("report body =\n  %s\nwant\n  %s", body, wantJSON)
	}

	// A block that is not enabled leaves no report.
	disabled := uaBlock(fieldTeam)
	disabled.Enabled = false
	fx.mgr.Apply(t.Context(), disabled)
	if got := fx.mgr.ProviderReports(); len(got) != 0 {
		t.Errorf("ProviderReports() after a block with Enabled false = %+v, want none", got)
	}

	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := fx.mgr.ProviderReports(); got != nil {
		t.Errorf("ProviderReports() after Teardown = %+v, want nil", got)
	}
}

// TestUserAccessManager_ProviderReportsCountConnectedDevices checks that a
// wireguard provider counts the devices configured on its interface whose
// handshake is at most 180 s old on the manager's clock, and none when the
// handshakes cannot be read. UserAccessStatus reports the same count.
func TestUserAccessManager_ProviderReportsCountConnectedDevices(t *testing.T) {
	fx := newUAFixture(t, nil)
	fx.access.peerHandshakes = map[string]map[string]time.Time{
		uaIface1: {
			alice.PublicKey: relayStart.Add(-60 * time.Second),
			bob.PublicKey:   relayStart.Add(-300 * time.Second),
			// A peer the block does not list, and a device that never
			// completed a handshake, count none.
			deviceKey(0xee): relayStart,
			carol.PublicKey: time.Time{},
		},
	}
	fx.mgr.Apply(t.Context(), uaBlock(wgProvider(uaID1, "field-team", 51821, "10.99.0.0/24", alice, bob, carol)))
	pub := fx.storedPublicKey(t, uaID1)
	fx.reset()

	if got, want := fx.mgr.ProviderReports(), []UserAccessProviderReport{upWireGuard(uaID1, pub, 1)}; !slices.Equal(got, want) {
		t.Errorf("ProviderReports() = %+v, want %+v: alice at 60 s counts, bob at 300 s does not", got, want)
	}
	if p := requireUp(t, fx.mgr, uaID1); p.ConnectedDevices != 1 || p.Devices != 3 {
		t.Errorf("status = %+v, want 3 devices and 1 connected", p)
	}
	if reads := handshakeReads(fx.access); !slices.Equal(reads, []string{uaIface1, uaIface1}) {
		t.Errorf("handshake reads = %q, want one per report and one per status", reads)
	}

	// The age is measured on the manager's clock: alice at 180 s counts, at
	// 181 s she does not.
	fx.clock.Add(120 * time.Second)
	if got := fx.mgr.ProviderReports(); len(got) != 1 || got[0].ConnectedDevices != 1 {
		t.Errorf("ProviderReports() with alice's handshake 180 s old = %+v, want 1 connected", got)
	}
	fx.clock.Add(time.Second)
	if got := fx.mgr.ProviderReports(); len(got) != 1 || got[0].ConnectedDevices != 0 {
		t.Errorf("ProviderReports() with alice's handshake 181 s old = %+v, want 0 connected", got)
	}

	// A failed read counts none and is logged at Debug; the provider stays
	// up with its key.
	fx.clock.Add(-121 * time.Second)
	fx.access.peerHandshakesErr = errors.New("netlink: no such device")
	if got, want := fx.mgr.ProviderReports(), []UserAccessProviderReport{upWireGuard(uaID1, pub, 0)}; !slices.Equal(got, want) {
		t.Errorf("ProviderReports() with a failed read = %+v, want %+v", got, want)
	}
	if p := requireUp(t, fx.mgr, uaID1); p.ConnectedDevices != 0 {
		t.Errorf("status with a failed read = %+v, want 0 connected", p)
	}
	if got := logLines(fx.logs, "level=DEBUG", `msg="bridge: user access: read handshakes failed"`, "component=bridge",
		"provider_id="+uaID1, "interface="+uaIface1, `error="netlink: no such device"`); got != 2 {
		t.Errorf("%d Debug lines for the failed reads, want 2 (the report and the status):\n%s", got, fx.logs.String())
	}
	if got := logLines(fx.logs, "level=WARN"); got != 0 {
		t.Errorf("%d Warn lines, want none for a failed handshake read:\n%s", got, fx.logs.String())
	}
}

// TestUserAccessManager_ProviderReportsLeaveOutAFirstJoin checks that a
// vendor provider whose first join runs outside the manager's mutex has no
// report until the join has an outcome, and that the Apply that started it
// signals ReportChanged once the join is done.
func TestUserAccessManager_ProviderReportsLeaveOutAFirstJoin(t *testing.T) {
	fx := newUAFixture(t, nil)
	fx.secrets.set("ts-join", 1, "tskey")
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("ts-join", 1))
	changed := fx.mgr.ReportChanged()
	drain(changed)

	started, release := make(chan struct{}), make(chan struct{})
	fx.tailscale.startHook = func() {
		close(started)
		<-release
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fx.mgr.Apply(context.Background(), uaBlock(fieldTeam, vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join")))
	}()
	<-started
	if got := fx.mgr.ProviderReports(); len(got) != 1 || got[0].ProviderID != uaID1 {
		t.Errorf("ProviderReports() during the join = %+v, want field-team alone", got)
	}
	requireNoSignal(t, changed, "an Apply whose join has no outcome yet")
	close(release)
	<-done

	requireSignal(t, changed, "the Apply whose join finished")
	got := fx.mgr.ProviderReports()
	if len(got) != 2 || got[1] != upVendor(uaID2, api.UserAccessKindTailscale) {
		t.Errorf("ProviderReports() after the join = %+v, want field-team and tailnet up", got)
	}
}

func TestUserAccessManager_ReportChangedSignals(t *testing.T) {
	fx := newUAFixture(t, nil)
	changed := fx.mgr.ReportChanged()
	drain(changed)
	requireOne := func(what string) {
		t.Helper()
		requireSignal(t, changed, what)
		requireNoSignal(t, changed, what+", a second time")
	}

	fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))
	requireOne("an Apply")
	fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))
	requireOne("an Apply of the same block")
	fx.mgr.Retry(t.Context())
	requireOne("a Retry")
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("ts-join", 1))
	requireOne("a SyncSecretInventory")

	// Reading the reports and a moving handshake signal nothing.
	fx.access.peerHandshakes = map[string]map[string]time.Time{uaIface1: {alice.PublicKey: relayStart}}
	_ = fx.mgr.ProviderReports()
	_ = fx.mgr.UserAccessStatus()
	requireNoSignal(t, changed, "reading the reports")

	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	requireOne("Teardown")
}

// TestUserAccessReasons_AreReasonTokens checks that every reason the manager
// reports matches the contract's reason grammar, which the control plane
// enforces on a user access status report.
func TestUserAccessReasons_AreReasonTokens(t *testing.T) {
	grammar := regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	for _, reason := range []string{
		UserAccessReasonInvalidProvider,
		UserAccessReasonKindNotServed,
		UserAccessReasonKeyUnavailable,
		UserAccessReasonBindFailed,
		UserAccessReasonSetupFailed,
		UserAccessReasonAuthSecretNotListed,
		UserAccessReasonAuthSecretUnreadable,
		UserAccessReasonJoinFailed,
		UserAccessReasonClientMissing,
	} {
		if !grammar.MatchString(reason) {
			t.Errorf("reason %q does not match %s", reason, grammar)
		}
	}
}
