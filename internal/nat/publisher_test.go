package nat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

var _ CandidateReporter = (*api.ControlPlane)(nil)

// candidateClock is the publisher's fake clock in the publisher tests. It is
// set in a non-UTC zone so a test can tell that reported_at was converted.
var candidateClock = time.Date(2026, 10, 21, 12, 15, 30, 0, time.FixedZone("CEST", 2*60*60))

// testCandidateConfig keeps the publisher's cadence short enough for the tests
// to watch several cycles.
func testCandidateConfig() Config {
	return Config{RefreshInterval: 50 * time.Millisecond, MinReportInterval: 10 * time.Millisecond}
}

// syncBuffer is a bytes.Buffer safe for a logger that writes from the
// publisher's goroutine while the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// logLines returns the logged lines whose message is msg.
func logLines(logs *syncBuffer, msg string) []string {
	var out []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, fmt.Sprintf("msg=%q", msg)) {
			out = append(out, line)
		}
	}
	return out
}

// candidateAnswer is one scripted reply of fakeCandidateReporter.
type candidateAnswer struct {
	resp *api.EndpointCandidatesResponse
	err  error
}

// accepted answers 200 with a stale_after deadline staleIn past candidateClock.
func accepted(staleIn time.Duration) candidateAnswer {
	return candidateAnswer{resp: &api.EndpointCandidatesResponse{
		AcceptedAt: candidateClock,
		StaleAfter: candidateClock.Add(staleIn),
	}}
}

// refused answers with the problem the control plane would send.
func refused(status int, code string) candidateAnswer {
	return candidateAnswer{err: &api.APIError{StatusCode: status, Code: code, Message: "refused"}}
}

// candidateCall is one recorded report, with the time it arrived.
type candidateCall struct {
	nodeID string
	req    api.EndpointCandidatesRequest
	at     time.Time
}

// fakeCandidateReporter is a CandidateReporter that answers from a script,
// falling back to one answer once the script runs out. Every call is handed to
// the test through calls; the buffer is deep enough that the publisher never
// waits on the test.
type fakeCandidateReporter struct {
	mu       sync.Mutex
	answers  []candidateAnswer
	fallback candidateAnswer
	n        int

	calls chan candidateCall
}

func newFakeCandidateReporter(fallback candidateAnswer, answers ...candidateAnswer) *fakeCandidateReporter {
	return &fakeCandidateReporter{answers: answers, fallback: fallback, calls: make(chan candidateCall, 64)}
}

func (f *fakeCandidateReporter) ReportEndpointCandidates(ctx context.Context, nodeID string, req api.EndpointCandidatesRequest) (*api.EndpointCandidatesResponse, error) {
	at := time.Now()
	f.mu.Lock()
	answer := f.fallback
	if f.n < len(f.answers) {
		answer = f.answers[f.n]
	}
	f.n++
	f.mu.Unlock()

	select {
	case f.calls <- candidateCall{nodeID: nodeID, req: req, at: at}:
	case <-ctx.Done():
	}
	return answer.resp, answer.err
}

// count returns how many reports arrived so far.
func (f *fakeCandidateReporter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

// waitCall returns the next report, failing the test when none arrives.
func (f *fakeCandidateReporter) waitCall(t *testing.T) candidateCall {
	t.Helper()
	select {
	case c := <-f.calls:
		return c
	case <-time.After(2 * time.Second):
		t.Fatal("no endpoint candidates report within 2s")
		return candidateCall{}
	}
}

// staticGather returns the same candidates on every cycle.
func staticGather(candidates ...string) func() ([]string, int, error) {
	return func() ([]string, int, error) {
		return slices.Clone(candidates), 0, nil
	}
}

func newTestPublisher(gather func() ([]string, int, error), logs *syncBuffer) *CandidatePublisher {
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := NewCandidatePublisher(gather, testCandidateConfig(), logger)
	p.now = func() time.Time { return candidateClock }
	return p
}

// startPublisher runs p.Run in a goroutine. The returned stop cancels it and
// fails the test unless Run returns nil promptly; once stop returns, Run's
// writes to p are visible to the test. stop also runs at cleanup.
func startPublisher(t *testing.T, p *CandidatePublisher, reporter CandidateReporter) (start time.Time, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	start = time.Now()
	go func() { done <- p.Run(ctx, reporter, "node-1") }()

	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run() = %v, want nil after cancel", err)
				}
			case <-time.After(2 * time.Second):
				t.Error("Run did not return within 2s of cancel")
			}
		})
	}
	t.Cleanup(stop)
	return start, stop
}

func TestReportDelay(t *testing.T) {
	cfg := Config{RefreshInterval: 60 * time.Second, MinReportInterval: 10 * time.Second}
	now := time.Date(2026, 10, 21, 10, 15, 30, 0, time.UTC)
	tests := []struct {
		name       string
		staleAfter time.Time
		want       time.Duration
	}{
		{name: "zero stale_after", staleAfter: time.Time{}, want: 60 * time.Second},
		{name: "deadline 5 min out", staleAfter: now.Add(5 * time.Minute), want: 60 * time.Second},
		{name: "deadline 20 s out", staleAfter: now.Add(20 * time.Second), want: 10 * time.Second},
		{name: "deadline 70 s out reports the margin early", staleAfter: now.Add(70 * time.Second), want: 40 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reportDelay(cfg, tt.staleAfter, now); got != tt.want {
				t.Errorf("reportDelay = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCandidatePublisher_ReportsAtOnceThenWaitsRefreshInterval(t *testing.T) {
	logs := &syncBuffer{}
	want := []string{"10.0.0.5:51820", "[fd00:10::5]:51820"}
	p := newTestPublisher(staticGather(want...), logs)
	reporter := newFakeCandidateReporter(accepted(5 * time.Minute))

	start, stop := startPublisher(t, p, reporter)
	first := reporter.waitCall(t)
	if d := first.at.Sub(start); d > 100*time.Millisecond {
		t.Errorf("first report %v after start, want within 100ms", d)
	}
	if first.nodeID != "node-1" {
		t.Errorf("nodeID = %q, want node-1", first.nodeID)
	}
	if !slices.Equal(first.req.Candidates, want) {
		t.Errorf("Candidates = %v, want %v", first.req.Candidates, want)
	}
	if !first.req.ReportedAt.Equal(candidateClock) || first.req.ReportedAt.Location() != time.UTC {
		t.Errorf("ReportedAt = %v, want the fake clock %v in UTC", first.req.ReportedAt, candidateClock.UTC())
	}

	// stale_after lies 5 min out, so reportDelay caps the wait at
	// RefreshInterval (50ms) rather than following the deadline.
	second := reporter.waitCall(t)
	stop()
	if gap := second.at.Sub(first.at); gap < 50*time.Millisecond || gap > time.Second {
		t.Errorf("second report %v after the first, want RefreshInterval (50ms)", gap)
	}

	if lines := logLines(logs, "nat: endpoint candidates: started"); len(lines) != 1 || !strings.Contains(lines[0], "level=INFO") || !strings.Contains(lines[0], "component=nat") {
		t.Errorf("started lines = %q, want one INFO line with component=nat", lines)
	}
	if lines := logLines(logs, "nat: endpoint candidates: control plane deadline shortens the report cadence"); len(lines) != 0 {
		t.Errorf("a deadline 5 min out logged %q, want no shortened-cadence warning", lines)
	}
}

func TestCandidatePublisher_EmptyGatherSendsEmptyArray(t *testing.T) {
	tests := []struct {
		name     string
		gathered []string
	}{
		{name: "nil", gathered: nil},
		{name: "empty", gathered: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := &syncBuffer{}
			p := newTestPublisher(func() ([]string, int, error) { return tt.gathered, 0, nil }, logs)
			reporter := newFakeCandidateReporter(accepted(5 * time.Minute))

			_, stop := startPublisher(t, p, reporter)
			call := reporter.waitCall(t)
			stop()

			if call.req.Candidates == nil || len(call.req.Candidates) != 0 {
				t.Errorf("Candidates = %#v, want an empty non-nil slice", call.req.Candidates)
			}
			body, err := json.Marshal(call.req)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if !strings.Contains(string(body), `"candidates":[]`) {
				t.Errorf("request body = %s, want \"candidates\":[]", body)
			}
			// The empty set is the first accepted one, so it is published.
			if lines := logLines(logs, "nat: endpoint candidates: published"); len(lines) != 1 || !strings.Contains(lines[0], "candidates=[]") {
				t.Errorf("published lines = %q, want one carrying candidates=[]", lines)
			}
		})
	}
}

func TestCandidatePublisher_GatherErrorSkipsCycle(t *testing.T) {
	logs := &syncBuffer{}
	reporter := newFakeCandidateReporter(accepted(5 * time.Minute))

	var mu sync.Mutex
	var reportsAtGather []int
	gather := func() ([]string, int, error) {
		mu.Lock()
		defer mu.Unlock()
		reportsAtGather = append(reportsAtGather, reporter.count())
		if len(reportsAtGather) == 1 {
			return nil, 0, errors.New("netlink: permission denied")
		}
		return []string{"10.0.0.5:51820"}, 0, nil
	}
	p := newTestPublisher(gather, logs)

	start, stop := startPublisher(t, p, reporter)
	call := reporter.waitCall(t)
	stop()

	mu.Lock()
	defer mu.Unlock()
	if len(reportsAtGather) < 2 || reportsAtGather[1] != 0 {
		t.Errorf("reports seen at each gather = %v, want none sent by the failed first cycle", reportsAtGather)
	}
	if !slices.Equal(call.req.Candidates, []string{"10.0.0.5:51820"}) {
		t.Errorf("Candidates = %v, want the second cycle's [10.0.0.5:51820]", call.req.Candidates)
	}
	if gap := call.at.Sub(start); gap < 50*time.Millisecond {
		t.Errorf("first report %v after start, want RefreshInterval (50ms) after the failed read", gap)
	}
	lines := logLines(logs, "nat: endpoint candidates: read interfaces failed")
	if len(lines) != 1 || !strings.Contains(lines[0], "level=WARN") || !strings.Contains(lines[0], "netlink: permission denied") {
		t.Errorf("read interfaces failed lines = %q, want one WARN carrying the error", lines)
	}
}

func TestCandidatePublisher_NotServedLoggedOnce(t *testing.T) {
	const notServedMsg = "nat: endpoint candidates: control plane does not accept endpoint candidates, retrying every interval"
	const recoveredMsg = "nat: endpoint candidates: control plane accepts endpoint candidates"
	tests := []struct {
		name     string
		status   int
		code     string
		wantAttr string
	}{
		{name: "404 without a code", status: 404, code: "", wantAttr: `status=404 code=""`},
		{name: "501 endpoint_candidates_not_provisioned", status: 501, code: "endpoint_candidates_not_provisioned", wantAttr: "status=501 code=endpoint_candidates_not_provisioned"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := &syncBuffer{}
			p := newTestPublisher(staticGather("10.0.0.5:51820"), logs)
			reporter := newFakeCandidateReporter(accepted(5*time.Minute),
				refused(tt.status, tt.code), refused(tt.status, tt.code), refused(tt.status, tt.code),
				accepted(5*time.Minute))

			_, stop := startPublisher(t, p, reporter)
			var calls []candidateCall
			for range 5 {
				calls = append(calls, reporter.waitCall(t))
			}
			stop()

			// Each refusal retries after RefreshInterval.
			for i := 1; i <= 3; i++ {
				if gap := calls[i].at.Sub(calls[i-1].at); gap < 50*time.Millisecond {
					t.Errorf("report %d came %v after a refusal, want RefreshInterval (50ms)", i+1, gap)
				}
			}
			lines := logLines(logs, notServedMsg)
			if len(lines) != 1 || !strings.Contains(lines[0], "level=INFO") || !strings.Contains(lines[0], tt.wantAttr) {
				t.Errorf("not-served lines = %q, want one INFO carrying %s", lines, tt.wantAttr)
			}
			if lines := logLines(logs, recoveredMsg); len(lines) != 1 || !strings.Contains(lines[0], "level=INFO") {
				t.Errorf("recovery lines = %q, want one INFO", lines)
			}
			if strings.Contains(logs.String(), "level=WARN") {
				t.Errorf("logs = %s, want no Warn for a control plane that does not serve the operation", logs.String())
			}
		})
	}
}

func TestCandidatePublisher_FailuresWarnAndWaitRefreshInterval(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		code      string
		wantMsg   string
		wantField string
	}{
		{name: "404 endpoint_peer_not_found", status: 404, code: "endpoint_peer_not_found", wantMsg: "nat: endpoint candidates: rejected, this node is not registered as a peer", wantField: "code=endpoint_peer_not_found"},
		{name: "410 endpoint_peer_gone", status: 410, code: "endpoint_peer_gone", wantMsg: "nat: endpoint candidates: rejected, this node is not registered as a peer", wantField: "code=endpoint_peer_gone"},
		{name: "400 endpoint_clock_skew", status: 400, code: "endpoint_clock_skew", wantMsg: "nat: endpoint candidates: rejected for clock skew", wantField: "error="},
		{name: "500", status: 500, code: "", wantMsg: "nat: endpoint candidates: send failed", wantField: "error="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := &syncBuffer{}
			p := newTestPublisher(staticGather("10.0.0.5:51820"), logs)
			// The first answer's deadline shortens the cadence to
			// MinReportInterval, so a failure that reused it instead of
			// falling back to RefreshInterval would show in the gap.
			reporter := newFakeCandidateReporter(accepted(5*time.Minute),
				accepted(20*time.Second), refused(tt.status, tt.code), accepted(5*time.Minute))

			_, stop := startPublisher(t, p, reporter)
			var calls []candidateCall
			for range 3 {
				calls = append(calls, reporter.waitCall(t))
			}
			stop()

			if gap := calls[2].at.Sub(calls[1].at); gap < 50*time.Millisecond {
				t.Errorf("report after the failure came %v later, want RefreshInterval (50ms)", gap)
			}
			lines := logLines(logs, tt.wantMsg)
			if len(lines) != 1 || !strings.Contains(lines[0], "level=WARN") || !strings.Contains(lines[0], tt.wantField) {
				t.Errorf("%q lines = %q, want one WARN carrying %s", tt.wantMsg, lines, tt.wantField)
			}
			// Run has returned, so reading its state is race-free.
			if p.notServed {
				t.Error("notServed = true, want a failure that is not a missing operation to leave it unset")
			}
			for _, msg := range []string{
				"nat: endpoint candidates: control plane does not accept endpoint candidates, retrying every interval",
				"nat: endpoint candidates: control plane accepts endpoint candidates",
			} {
				if lines := logLines(logs, msg); len(lines) != 0 {
					t.Errorf("logged %q, want no not-served transition", lines)
				}
			}
		})
	}
}

// While the heartbeat has parked the agent, every report fails locally with
// api.ErrCredentialRefused. The heartbeat names the cause once, so the
// publisher logs the failure at Debug and keeps its cadence.
func TestCandidatePublisher_RefusedCredentialLoggedAtDebug(t *testing.T) {
	const sendFailedMsg = "nat: endpoint candidates: send failed"
	tests := []struct {
		name      string
		err       error
		wantLevel string
	}{
		{name: "refused credential", err: fmt.Errorf("x: %w", api.ErrCredentialRefused), wantLevel: "level=DEBUG"},
		{name: "other error", err: errors.New("boom"), wantLevel: "level=WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := &syncBuffer{}
			p := newTestPublisher(staticGather("10.0.0.5:51820"), logs)
			reporter := newFakeCandidateReporter(candidateAnswer{err: tt.err})

			if got := p.cycle(context.Background(), reporter, "node-1"); got != 50*time.Millisecond {
				t.Errorf("cycle delay = %v, want RefreshInterval (50ms) after a failure", got)
			}
			lines := logLines(logs, sendFailedMsg)
			if len(lines) != 1 || !strings.Contains(lines[0], tt.wantLevel) || !strings.Contains(lines[0], "error=") {
				t.Errorf("%q lines = %q, want one %s carrying the error", sendFailedMsg, lines, tt.wantLevel)
			}
			if tt.wantLevel == "level=DEBUG" && (strings.Contains(logs.String(), "level=WARN") || strings.Contains(logs.String(), "level=ERROR")) {
				t.Errorf("logs = %s, want nothing at Warn or above for a refused credential", logs.String())
			}
		})
	}
}

func TestCandidatePublisher_PublishedOnFirstAndChangedSets(t *testing.T) {
	logs := &syncBuffer{}
	sets := []struct {
		candidates []string
		truncated  int
	}{
		{candidates: []string{"10.0.0.5:51820"}},
		{candidates: []string{"10.0.0.5:51820"}},
		{candidates: []string{"10.0.0.5:51820", "10.0.0.6:51820"}, truncated: 2},
	}
	var gathers atomic.Int32
	gather := func() ([]string, int, error) {
		i := min(int(gathers.Add(1))-1, len(sets)-1)
		return slices.Clone(sets[i].candidates), sets[i].truncated, nil
	}
	p := newTestPublisher(gather, logs)
	reporter := newFakeCandidateReporter(accepted(5 * time.Minute))

	_, stop := startPublisher(t, p, reporter)
	for range 3 {
		reporter.waitCall(t)
	}
	// The third answer was a success, which logs even after cancel, so every
	// line of the three cycles is in place once Run returns.
	stop()

	lines := logLines(logs, "nat: endpoint candidates: published")
	if len(lines) != 2 {
		t.Fatalf("published lines = %q, want two: the first set and the changed third", lines)
	}
	if !strings.Contains(lines[0], "level=INFO") || !strings.Contains(lines[0], "10.0.0.5:51820") || strings.Contains(lines[0], "10.0.0.6") || !strings.Contains(lines[0], "truncated=0") {
		t.Errorf("first published line = %q, want INFO with [10.0.0.5:51820] and truncated=0", lines[0])
	}
	if !strings.Contains(lines[1], "10.0.0.6:51820") || !strings.Contains(lines[1], "truncated=2") {
		t.Errorf("second published line = %q, want the changed set and truncated=2", lines[1])
	}
	acceptedLines := logLines(logs, "nat: endpoint candidates: accepted")
	if len(acceptedLines) != 3 || !strings.Contains(acceptedLines[0], "level=DEBUG") || !strings.Contains(acceptedLines[0], "count=1") || !strings.Contains(acceptedLines[0], "stale_after=") {
		t.Errorf("accepted lines = %q, want a DEBUG line with count and stale_after for each of the three successes", acceptedLines)
	}
}

func TestCandidatePublisher_ShortDeadlineWarns(t *testing.T) {
	const msg = "nat: endpoint candidates: control plane deadline shortens the report cadence"
	tests := []struct {
		name     string
		staleIn  time.Duration
		want     time.Duration
		wantWarn bool
	}{
		{name: "deadline 5 min out", staleIn: 5 * time.Minute, want: 50 * time.Millisecond},
		{name: "deadline 20 s out", staleIn: 20 * time.Second, want: 10 * time.Millisecond, wantWarn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := &syncBuffer{}
			p := newTestPublisher(staticGather("10.0.0.5:51820"), logs)
			reporter := newFakeCandidateReporter(accepted(tt.staleIn))

			if got := p.cycle(context.Background(), reporter, "node-1"); got != tt.want {
				t.Errorf("cycle delay = %v, want %v", got, tt.want)
			}
			lines := logLines(logs, msg)
			if !tt.wantWarn {
				if len(lines) != 0 {
					t.Errorf("logged %q, want no shortened-cadence warning", lines)
				}
				return
			}
			if len(lines) != 1 {
				t.Fatalf("shortened-cadence lines = %q, want one", lines)
			}
			for _, field := range []string{"level=WARN", "delay=10ms", "refresh_interval=50ms", "min_report_interval=10ms", "stale_after=2026-10-21T12:15:50"} {
				if !strings.Contains(lines[0], field) {
					t.Errorf("shortened-cadence line = %q, want it to carry %s", lines[0], field)
				}
			}
		})
	}
}

func TestCandidatePublisher_NilResponseIsSuccess(t *testing.T) {
	logs := &syncBuffer{}
	p := newTestPublisher(staticGather("10.0.0.5:51820"), logs)
	reporter := newFakeCandidateReporter(candidateAnswer{})

	if got := p.cycle(context.Background(), reporter, "node-1"); got != 50*time.Millisecond {
		t.Errorf("cycle delay = %v, want RefreshInterval (50ms) for a response without a deadline", got)
	}
	if lines := logLines(logs, "nat: endpoint candidates: published"); len(lines) != 1 {
		t.Errorf("published lines = %q, want one for an accepted report", lines)
	}
	if strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("logs = %s, want no Warn", logs.String())
	}
}

func TestCandidatePublisher_RunReturnsNilAfterCancel(t *testing.T) {
	logs := &syncBuffer{}
	p := newTestPublisher(staticGather("10.0.0.5:51820"), logs)
	reporter := newFakeCandidateReporter(accepted(5 * time.Minute))

	_, stop := startPublisher(t, p, reporter)
	reporter.waitCall(t)
	stop()
}

// blockingCandidateReporter holds every report until ctx is done and then
// fails it, as the HTTP client does when a shutdown interrupts a request.
type blockingCandidateReporter struct {
	entered chan struct{}
}

func (b *blockingCandidateReporter) ReportEndpointCandidates(ctx context.Context, _ string, _ api.EndpointCandidatesRequest) (*api.EndpointCandidatesResponse, error) {
	b.entered <- struct{}{}
	<-ctx.Done()
	return nil, fmt.Errorf("api: PUT /v1/nodes/node-1/endpoint-candidates: %w", ctx.Err())
}

func TestCandidatePublisher_ErrorAfterCancelIsSilent(t *testing.T) {
	logs := &syncBuffer{}
	p := newTestPublisher(staticGather("10.0.0.5:51820"), logs)
	reporter := &blockingCandidateReporter{entered: make(chan struct{}, 1)}

	_, stop := startPublisher(t, p, reporter)
	select {
	case <-reporter.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no endpoint candidates report within 2s")
	}
	stop()

	if strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("logs = %s, want no Warn for a report the shutdown interrupted", logs.String())
	}
}
