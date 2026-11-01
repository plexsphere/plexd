package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The composition root hands the reporter the control-plane client; this
// assertion keeps the seam satisfiable by it.
var _ CapabilityClient = (*api.ControlPlane)(nil)

const (
	testCapabilityNodeID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1"

	// capabilityTestWait bounds every wait on a condition. Only a failing test
	// reaches it.
	capabilityTestWait = 10 * time.Second

	// capabilityNeverFires is a delay no test outlives, for a timer that must
	// stay out of the way of what the test asserts.
	capabilityNeverFires = time.Hour

	capabilitySendFailed  = "agent: capability report: send failed"
	capabilityAccepted    = "agent: capability report: accepted"
	capabilityWideRefused = "agent: capability report: hook metadata refused; sending names and digests"
)

var (
	manifestA = capabilityManifest("digest-a")
	manifestB = capabilityManifest("digest-b")
	manifestC = capabilityManifest("digest-c")

	errCapabilityUnavailable = &api.APIError{StatusCode: 503, Message: "service unavailable"}
	errCapabilityNetwork     = errors.New("dial tcp 198.51.100.1:443: connect: connection refused")
	errCapabilityTimeout     = fmt.Errorf("put capabilities: %w", context.DeadlineExceeded)
	errCapabilityTooMany     = &api.APIError{StatusCode: 400, Code: "declared_hooks_too_many", Message: "too many hooks"}
	errCapabilityMalformed   = &api.APIError{StatusCode: 400, Code: "malformed_capabilities_request", Message: "unknown key"}
)

func capabilityManifest(digest string) api.CapabilityManifestRequest {
	return api.CapabilityManifestRequest{
		BinaryVersion:  "v1.2.3",
		BinaryChecksum: "Y2hlY2tzdW0=",
		DeclaredHooks:  []api.DeclaredHook{{Name: "hook", Checksum: digest}},
	}
}

// wideManifest is capabilityManifest with all four metadata fields on its
// entry, so its short form equals capabilityManifest(digest). Each call builds
// a new slice, which keeps an expected value apart from what the reporter was
// handed.
func wideManifest(digest, description string) api.CapabilityManifestRequest {
	m := capabilityManifest(digest)
	m.DeclaredHooks[0].Description = description
	m.DeclaredHooks[0].Parameters = []api.ActionParam{{Name: "target", Type: "string", Required: true, Description: "what to act on"}}
	m.DeclaredHooks[0].TimeoutSeconds = 30
	m.DeclaredHooks[0].SandboxLevel = "none"
	return m
}

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeCapabilityClient records every manifest it is handed and answers the n-th
// with errs[n] when that is set, and with success otherwise.
//
// onCall, when set, runs inside the n-th send. A test uses it to change the
// manifest or queue a Notify at a fixed point of the reporter's sequence, where
// doing so from the test goroutine would race the retry timer. With block set,
// every send instead waits for its ctx and returns the ctx's error, the way a
// request in flight at shutdown does.
type fakeCapabilityClient struct {
	mu        sync.Mutex
	nodeIDs   []string
	manifests []api.CapabilityManifestRequest
	sentAt    []time.Time
	errs      []error
	onCall    func(n int)
	block     bool
}

func (c *fakeCapabilityClient) UpdateCapabilities(ctx context.Context, nodeID string, caps api.CapabilityManifestRequest) error {
	c.mu.Lock()
	n := len(c.manifests)
	c.nodeIDs = append(c.nodeIDs, nodeID)
	c.manifests = append(c.manifests, caps)
	c.sentAt = append(c.sentAt, time.Now())
	var err error
	if n < len(c.errs) {
		err = c.errs[n]
	}
	onCall, block := c.onCall, c.block
	c.mu.Unlock()

	if onCall != nil {
		onCall(n)
	}
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func (c *fakeCapabilityClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.manifests)
}

func (c *fakeCapabilityClient) recorded() ([]api.CapabilityManifestRequest, []time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.manifests), slices.Clone(c.sentAt)
}

// fakeManifestSource is the build function. Its counter is what lets a test
// that expects no PUT know the attempt really ran.
type fakeManifestSource struct {
	mu       sync.Mutex
	manifest api.CapabilityManifestRequest
	builds   int
}

func (s *fakeManifestSource) build() api.CapabilityManifestRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.builds++
	return s.manifest
}

func (s *fakeManifestSource) set(m api.CapabilityManifestRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.manifest = m
}

func (s *fakeManifestSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.builds
}

// delayRecorder stands in for Jitter. It records every nominal delay it is
// handed and answers with actual when that is set, and with the nominal delay
// otherwise, so a test can read the backoff sequence without waiting it out.
type delayRecorder struct {
	mu      sync.Mutex
	nominal []time.Duration
	actual  time.Duration
}

func (d *delayRecorder) jitter(nominal time.Duration) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nominal = append(d.nominal, nominal)
	if d.actual > 0 {
		return d.actual
	}
	return nominal
}

func (d *delayRecorder) recorded() []time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.nominal)
}

// capabilityRig is a reporter wired to fakes. The quiet period is one
// millisecond and every other delay outlives the test, so a test shortens only
// the delay it is about.
type capabilityRig struct {
	reporter *CapabilityReporter
	client   *fakeCapabilityClient
	source   *fakeManifestSource
	delays   *delayRecorder
	logs     *lockedBuffer
}

func newCapabilityRig(errs ...error) *capabilityRig {
	client := &fakeCapabilityClient{errs: errs}
	source := &fakeManifestSource{manifest: manifestA}
	delays := &delayRecorder{}
	logger, logs := newDebugLogger()

	r := NewCapabilityReporter(testCapabilityNodeID, client, source.build, logger)
	r.quietPeriod = time.Millisecond
	r.maxDelay = capabilityNeverFires
	r.retryMin = capabilityNeverFires
	r.retryMax = capabilityNeverFires
	r.wideRetry = capabilityNeverFires
	r.jitter = delays.jitter

	return &capabilityRig{reporter: r, client: client, source: source, delays: delays, logs: logs}
}

// useRealBackoff restores the constructor's retry bounds and makes every wait
// take actual, so a test can read the real sequence without sitting through it.
func (rig *capabilityRig) useRealBackoff(actual time.Duration) {
	rig.reporter.retryMin = capabilityRetryMin
	rig.reporter.retryMax = capabilityRetryMax
	rig.delays.actual = actual
}

// run starts Run and returns a function that cancels it and waits for it to
// return nil. A test that reads the reporter's fields calls it first: its
// return orders the read after everything the Run goroutine wrote.
func (rig *capabilityRig) run(t *testing.T) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rig.reporter.Run(ctx) }()

	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run() = %v, want nil", err)
				}
			case <-time.After(capabilityTestWait):
				t.Errorf("Run did not return after ctx was cancelled")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func (rig *capabilityRig) waitPuts(t *testing.T, n int) {
	t.Helper()
	waitFor(t, capabilityTestWait, func() bool { return rig.client.calls() >= n })
}

func (rig *capabilityRig) waitBuilds(t *testing.T, n int) {
	t.Helper()
	waitFor(t, capabilityTestWait, func() bool { return rig.source.count() >= n })
}

// flush returns once every attempt whose build has already run is finished. Run
// is one goroutine, so the build this Notify causes cannot start before them.
// The count is read first because that build can run the moment Notify returns.
func (rig *capabilityRig) flush(t *testing.T) {
	t.Helper()
	builds := rig.source.count()
	rig.reporter.Notify()
	rig.waitBuilds(t, builds+1)
}

// notifyAndSettle sends a Notify and returns once the attempt it caused is
// finished, so a count of PUTs read afterwards includes that attempt.
func (rig *capabilityRig) notifyAndSettle(t *testing.T) {
	t.Helper()
	rig.flush(t)
	rig.flush(t)
}

// notifyUntilStopped calls Notify every millisecond until the returned function
// is called.
func (rig *capabilityRig) notifyUntilStopped(t *testing.T) (halt func()) {
	t.Helper()
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-quit:
				return
			case <-time.After(time.Millisecond):
				rig.reporter.Notify()
			}
		}
	}()

	var once sync.Once
	halt = func() {
		once.Do(func() {
			close(quit)
			<-done
		})
	}
	t.Cleanup(halt)
	return halt
}

func (rig *capabilityRig) assertPuts(t *testing.T, want ...api.CapabilityManifestRequest) {
	t.Helper()
	got, _ := rig.client.recorded()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PUTs = %+v, want %+v", got, want)
	}
}

// assertNoAttemptFor fails the test if an attempt runs within d. A wide timer
// that fires after acceptance finds an equal manifest and sends nothing, so
// only the build count can show that it stayed silent.
func (rig *capabilityRig) assertNoAttemptFor(t *testing.T, d time.Duration) {
	t.Helper()
	builds := rig.source.count()
	time.Sleep(d)
	if got := rig.source.count(); got != builds {
		t.Errorf("builds = %d after %v, want %d: an attempt ran", got, d, builds)
	}
}

// newFrozenClock returns a clock that reads testObservedAt until advanced, so a
// hold is judged by the test and not by how long the test took.
func newFrozenClock() *steppingClock {
	return &steppingClock{next: testObservedAt}
}

func advanceClock(c *steppingClock, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next = c.next.Add(d)
}

// ---------------------------------------------------------------------------
// Constants and delay arithmetic
// ---------------------------------------------------------------------------

func TestCapabilityReporter_ConstructorValues(t *testing.T) {
	logger, _ := newDebugLogger()
	r := NewCapabilityReporter(testCapabilityNodeID, &fakeCapabilityClient{}, (&fakeManifestSource{}).build, logger)

	durations := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"quietPeriod", r.quietPeriod, 1 * time.Second},
		{"maxDelay", r.maxDelay, 10 * time.Second},
		{"retryMin", r.retryMin, 5 * time.Second},
		{"retryMax", r.retryMax, 5 * time.Minute},
		{"wideRetry", r.wideRetry, 1 * time.Hour},
	}
	for _, d := range durations {
		if d.got != d.want {
			t.Errorf("%s = %v, want %v", d.name, d.got, d.want)
		}
	}

	if cap(r.notify) != 1 {
		t.Errorf("cap(notify) = %d, want 1", cap(r.notify))
	}
	if reflect.ValueOf(r.jitter).Pointer() != reflect.ValueOf(Jitter).Pointer() {
		t.Error("jitter is not Jitter")
	}
	if reflect.ValueOf(r.now).Pointer() != reflect.ValueOf(time.Now).Pointer() {
		t.Error("now is not time.Now")
	}
}

func TestCapabilityReporter_JitterStaysWithinAQuarter(t *testing.T) {
	const d = 100 * time.Second

	// A thousand draws land in the outer part of both sides with overwhelming
	// probability, so a narrower spread cannot pass.
	var low, high bool
	for range 1000 {
		got := Jitter(d)
		if got < d*75/100 || got > d*125/100 {
			t.Fatalf("Jitter(%v) = %v, outside 25%%", d, got)
		}
		low = low || got < d*85/100
		high = high || got > d*115/100
	}
	if !low || !high {
		t.Errorf("draws reached low = %v, high = %v, want both", low, high)
	}
}

func TestNextDelay(t *testing.T) {
	extremes := []struct {
		name   string
		jitter func(time.Duration) time.Duration
	}{
		{"jitter low", func(d time.Duration) time.Duration { return d * 75 / 100 }},
		{"jitter high", func(d time.Duration) time.Duration { return d * 125 / 100 }},
	}
	nominals := []time.Duration{
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		40 * time.Second,
		80 * time.Second,
		160 * time.Second,
		300 * time.Second,
	}

	for _, extreme := range extremes {
		for _, nominal := range nominals {
			jittered := extreme.jitter(nominal)
			tests := []struct {
				name       string
				retryAfter time.Duration
				want       time.Duration
			}{
				{"no RetryAfter", 0, jittered},
				{"negative RetryAfter", -time.Second, jittered},
				{"shorter RetryAfter", jittered - time.Second, jittered},
				{"equal RetryAfter", jittered, jittered},
				{"longer RetryAfter", jittered + time.Second, jittered + time.Second},
				{"RetryAfter past the cap", 1 * time.Hour, 1 * time.Hour},
			}
			for _, tt := range tests {
				t.Run(fmt.Sprintf("%s/%v/%s", extreme.name, nominal, tt.name), func(t *testing.T) {
					if got := nextDelay(nominal, tt.retryAfter, extreme.jitter); got != tt.want {
						t.Errorf("nextDelay(%v, %v) = %v, want %v", nominal, tt.retryAfter, got, tt.want)
					}
				})
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

func TestCapabilityReporter_SendsOncePerRunWithNoQuietPeriod(t *testing.T) {
	rig := newCapabilityRig()
	rig.reporter.quietPeriod = capabilityNeverFires
	stop := rig.run(t)

	rig.waitPuts(t, 1)
	stop()

	rig.assertPuts(t, manifestA)
	if got := rig.source.count(); got != 1 {
		t.Errorf("builds = %d, want 1", got)
	}
	if !slices.Equal(rig.client.nodeIDs, []string{testCapabilityNodeID}) {
		t.Errorf("nodeIDs = %v, want the reporter's node", rig.client.nodeIDs)
	}
}

func TestCapabilityReporter_NotifyWithNewContentSendsOnceAfterQuietPeriod(t *testing.T) {
	const quiet = 20 * time.Millisecond
	rig := newCapabilityRig()
	rig.reporter.quietPeriod = quiet
	rig.run(t)
	rig.waitPuts(t, 1)

	rig.source.set(manifestB)
	notifiedAt := time.Now()
	rig.reporter.Notify()
	rig.waitPuts(t, 2)
	rig.flush(t)

	rig.assertPuts(t, manifestA, manifestB)
	_, sentAt := rig.client.recorded()
	if gap := sentAt[1].Sub(notifiedAt); gap < quiet {
		t.Errorf("PUT came %v after the Notify, want at least the quiet period %v", gap, quiet)
	}
}

// The PlexdHook inventory's notifications change plexd_hooks and nothing else, in
// either direction, and the whole manifest is what decides.
func TestCapabilityReporter_ChangeInPlexdHooksAloneSends(t *testing.T) {
	rig := newCapabilityRig()
	rig.run(t)
	rig.waitPuts(t, 1)

	changed := manifestA
	changed.PlexdHooks = []api.DiscoveredPlexdHook{{Name: "created", ImageDigest: "sha256:0"}}
	rig.source.set(changed)
	rig.reporter.Notify()
	rig.waitPuts(t, 2)

	rig.source.set(manifestA)
	rig.reporter.Notify()
	rig.waitPuts(t, 3)

	rig.assertPuts(t, manifestA, changed, manifestA)
}

func TestCapabilityReporter_FiveNotifiesSendOnePut(t *testing.T) {
	const quiet = 100 * time.Millisecond
	rig := newCapabilityRig()
	rig.reporter.quietPeriod = quiet
	rig.run(t)
	rig.waitPuts(t, 1)

	// The manifest changes only with the fifth Notify, so a test goroutine
	// stalled past the quiet period gets an attempt that finds nothing to send,
	// not a second PUT. The four spaced notifications add up to less than one
	// quiet period, so the PUT lands a whole quiet period after the fifth only
	// if each of them restarted it.
	//
	// A process frozen between two of them lets the quiet period end, and the
	// next Notify then sends almost at once on correct code. So the gap is only
	// judged when no spacing came near the quiet period. Each spacing is measured
	// from before the earlier Notify to after the later one, which overstates it.
	var longest time.Duration
	var previous time.Time
	notify := func() {
		stamp := time.Now()
		rig.reporter.Notify()
		if !previous.IsZero() {
			longest = max(longest, time.Since(previous))
		}
		previous = stamp
	}
	for range 4 {
		notify()
		time.Sleep(quiet / 5)
	}
	rig.source.set(manifestB)
	lastNotify := time.Now()
	notify()

	rig.waitPuts(t, 2)
	rig.flush(t)

	rig.assertPuts(t, manifestA, manifestB)
	if longest >= quiet/2 {
		t.Logf("not judging the gap: notifications were %v apart at worst", longest)
		return
	}
	_, sentAt := rig.client.recorded()
	if gap := sentAt[1].Sub(lastNotify); gap < quiet {
		t.Errorf("PUT came %v after the last Notify, want at least the quiet period %v", gap, quiet)
	}
}

func TestCapabilityReporter_NotifyInFlightIsNotLost(t *testing.T) {
	rig := newCapabilityRig()
	rig.client.onCall = func(n int) {
		if n == 0 {
			rig.source.set(manifestB)
			rig.reporter.Notify()
		}
	}
	rig.run(t)

	rig.waitPuts(t, 2)
	rig.assertPuts(t, manifestA, manifestB)
}

func TestCapabilityReporter_EqualManifestSendsNothing(t *testing.T) {
	rig := newCapabilityRig()
	rig.run(t)
	rig.waitPuts(t, 1)

	builds := rig.source.count()
	rig.notifyAndSettle(t)

	if got := rig.source.count(); got <= builds {
		t.Fatalf("builds = %d, want more than %d: the attempt never ran", got, builds)
	}
	rig.assertPuts(t, manifestA)
}

func TestCapabilityReporter_MaxDelayBoundsAStreamOfNotifications(t *testing.T) {
	const maxDelay = 30 * time.Millisecond
	rig := newCapabilityRig()
	rig.reporter.quietPeriod = capabilityNeverFires
	rig.reporter.maxDelay = maxDelay
	rig.run(t)
	rig.waitPuts(t, 1)

	rig.source.set(manifestB)
	firstNotify := time.Now()
	rig.reporter.Notify()
	halt := rig.notifyUntilStopped(t)

	// The quiet period never ends here, so the PUT can only come from maxDelay,
	// and only if the stream does not restart it.
	rig.waitPuts(t, 2)
	halt()

	rig.assertPuts(t, manifestA, manifestB)
	_, sentAt := rig.client.recorded()
	if gap := sentAt[1].Sub(firstNotify); gap < maxDelay {
		t.Errorf("PUT came %v after the first Notify, want at least maxDelay %v", gap, maxDelay)
	}
}

func TestCapabilityReporter_LastHookRemovedSendsNoDeclaredHooksKey(t *testing.T) {
	rig := newCapabilityRig()
	rig.run(t)
	rig.waitPuts(t, 1)

	empty := api.CapabilityManifestRequest{BinaryVersion: manifestA.BinaryVersion, BinaryChecksum: manifestA.BinaryChecksum}
	rig.source.set(empty)
	rig.reporter.Notify()
	rig.waitPuts(t, 2)

	manifests, _ := rig.client.recorded()
	keys := func(m api.CapabilityManifestRequest) map[string]json.RawMessage {
		t.Helper()
		body, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("unmarshal manifest: %v", err)
		}
		return decoded
	}
	if _, ok := keys(manifests[0])["declared_hooks"]; !ok {
		t.Fatalf("first PUT has no declared_hooks key, so the check below proves nothing: %+v", manifests[0])
	}
	if raw, ok := keys(manifests[1])["declared_hooks"]; ok {
		t.Errorf("PUT after the last hook left carries declared_hooks = %s, want no key", raw)
	}
}

func TestCapabilityReporter_LogsAcceptedWithBothCounts(t *testing.T) {
	rig := newCapabilityRig()
	rig.source.set(api.CapabilityManifestRequest{
		BinaryVersion:  "v1.2.3",
		BinaryChecksum: "Y2hlY2tzdW0=",
		DeclaredHooks:  []api.DeclaredHook{{Name: "a", Checksum: "x"}, {Name: "b", Checksum: "y"}},
		PlexdHooks:     []api.DiscoveredPlexdHook{{Name: "p", ImageDigest: "sha256:0"}},
	})
	stop := rig.run(t)
	rig.waitPuts(t, 1)
	stop()

	line := logLine(t, rig.logs.String(), capabilityAccepted)
	for _, want := range []string{"level=INFO", "component=capability-report", "declared_hooks=2", "plexd_hooks=1", "hook_metadata=false"} {
		if !strings.Contains(line, want) {
			t.Errorf("accepted line %q lacks %q", line, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Retrying
// ---------------------------------------------------------------------------

func TestCapabilityReporter_BackoffDoublesToTheCapAndResetsOnAcceptance(t *testing.T) {
	errs := slices.Repeat([]error{error(errCapabilityUnavailable)}, 8)
	errs = append(errs, nil, errCapabilityUnavailable)
	rig := newCapabilityRig(errs...)
	rig.useRealBackoff(time.Millisecond)
	rig.run(t)

	rig.waitPuts(t, 9)
	want := []time.Duration{
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		40 * time.Second,
		80 * time.Second,
		160 * time.Second,
		300 * time.Second,
		300 * time.Second,
	}
	if got := rig.delays.recorded(); !slices.Equal(got, want) {
		t.Errorf("nominal delays = %v, want %v", got, want)
	}

	// The next failure starts over from the minimum, so acceptance reset the
	// backoff. No flush comes before this: its attempt finds an equal manifest,
	// and that would reset the backoff whether or not acceptance did.
	rig.source.set(manifestB)
	rig.reporter.Notify()
	rig.waitPuts(t, 11)
	if got := rig.delays.recorded(); !slices.Equal(got, append(want, 5*time.Second)) {
		t.Errorf("nominal delays = %v, want %v then 5s", got, want)
	}
}

func TestCapabilityReporter_EveryFailureClimbsTheSameBackoff(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "503", err: errCapabilityUnavailable},
		{name: "network error", err: errCapabilityNetwork},
		{name: "request timeout", err: errCapabilityTimeout},
		{name: "400", err: errCapabilityTooMany},
		// A Retry-After shorter than the backoff must not stop the climb, or a
		// control plane answering Retry-After: 1 would hold plexd at the 5-second
		// floor, about 720 attempts an hour.
		{name: "429 with Retry-After", err: &api.APIError{StatusCode: 429, RetryAfter: time.Millisecond}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rig := newCapabilityRig(tt.err, tt.err, tt.err)
			rig.useRealBackoff(time.Millisecond)
			rig.run(t)

			rig.waitPuts(t, 4)

			want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second}
			if got := rig.delays.recorded(); !slices.Equal(got, want) {
				t.Errorf("nominal delays = %v, want %v", got, want)
			}
		})
	}
}

func TestCapabilityReporter_RetriesEveryFailure(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantLog string
	}{
		{name: "503", err: errCapabilityUnavailable, wantLog: "HTTP 503"},
		{name: "network error", err: errCapabilityNetwork, wantLog: "connection refused"},
		{name: "request timeout", err: errCapabilityTimeout, wantLog: "context deadline exceeded"},
		{name: "400 names the problem code", err: errCapabilityTooMany, wantLog: "declared_hooks_too_many"},
		{name: "413", err: &api.APIError{StatusCode: 413, Code: "capabilities_body_too_large"}, wantLog: "capabilities_body_too_large"},
		{name: "422", err: &api.APIError{StatusCode: 422, Code: "manifest_invalid"}, wantLog: "manifest_invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rig := newCapabilityRig(tt.err)
			rig.reporter.retryMin = time.Millisecond
			rig.reporter.retryMax = time.Millisecond
			rig.run(t)

			rig.waitPuts(t, 2)
			rig.flush(t)

			rig.assertPuts(t, manifestA, manifestA)
			logs := rig.logs.String()
			line := logLine(t, logs, capabilitySendFailed)
			for _, want := range []string{"level=WARN", tt.wantLog, "retry_in=1ms"} {
				if !strings.Contains(line, want) {
					t.Errorf("failure line %q lacks %q", line, want)
				}
			}
			if got := countLogLines(logs, capabilityAccepted); got != 1 {
				t.Errorf("accepted lines = %d, want 1", got)
			}
		})
	}
}

func TestCapabilityReporter_WaitsAtLeastRetryAfter(t *testing.T) {
	const retryAfter = 40 * time.Millisecond
	rig := newCapabilityRig(&api.APIError{StatusCode: 429, RetryAfter: retryAfter})
	rig.reporter.retryMin = time.Millisecond
	rig.reporter.retryMax = time.Millisecond
	rig.run(t)

	rig.waitPuts(t, 2)

	_, sentAt := rig.client.recorded()
	if gap := sentAt[1].Sub(sentAt[0]); gap < retryAfter {
		t.Errorf("retry came %v after the 429, want at least %v", gap, retryAfter)
	}
	if line := logLine(t, rig.logs.String(), capabilitySendFailed); !strings.Contains(line, "retry_in=40ms") {
		t.Errorf("failure line %q does not report the RetryAfter wait", line)
	}
}

func TestCapabilityReporter_RetryCarriesTheNewestContent(t *testing.T) {
	rig := newCapabilityRig(errCapabilityUnavailable)
	rig.reporter.retryMin = time.Millisecond
	rig.reporter.retryMax = time.Millisecond
	rig.client.onCall = func(n int) {
		if n == 0 {
			rig.source.set(manifestB)
		}
	}
	rig.run(t)

	rig.waitPuts(t, 2)
	rig.assertPuts(t, manifestA, manifestB)
}

func TestCapabilityReporter_AcceptanceClearsTheFailureState(t *testing.T) {
	rig := newCapabilityRig(&api.APIError{StatusCode: 429, RetryAfter: time.Millisecond})
	rig.reporter.retryMin = time.Millisecond
	rig.reporter.retryMax = 8 * time.Millisecond
	stop := rig.run(t)

	// stop orders the reads below after the send. A flush would not do: its
	// attempt finds an equal manifest and resets the backoff by itself.
	rig.waitPuts(t, 2)
	stop()

	r := rig.reporter
	if r.accepted == nil || !reflect.DeepEqual(*r.accepted, manifestA) {
		t.Errorf("accepted = %+v, want the delivered manifest", r.accepted)
	}
	if r.attempted != nil {
		t.Errorf("attempted = %+v, want nil", r.attempted)
	}
	if !r.holdUntil.IsZero() {
		t.Errorf("holdUntil = %v, want zero", r.holdUntil)
	}
	if r.retryArmed {
		t.Error("retry still armed after acceptance")
	}
	if r.backoff != r.retryMin {
		t.Errorf("backoff = %v, want %v", r.backoff, r.retryMin)
	}
}

// ---------------------------------------------------------------------------
// Notifications during a wait
// ---------------------------------------------------------------------------

func TestCapabilityReporter_QueuedNotifyMakesNoSecondPutBeforeTheRetry(t *testing.T) {
	rig := newCapabilityRig(errCapabilityUnavailable)
	// A real boot has the scan's notification queued when the first PUT fails.
	rig.client.onCall = func(int) { rig.reporter.Notify() }
	rig.run(t)
	rig.waitPuts(t, 1)

	rig.waitBuilds(t, 2)
	rig.flush(t)

	rig.assertPuts(t, manifestA)
}

func TestCapabilityReporter_RepeatedNotifyLeavesTheRetryTimerAlone(t *testing.T) {
	const retry = 60 * time.Millisecond
	rig := newCapabilityRig(errCapabilityUnavailable)
	rig.reporter.retryMin = retry
	rig.reporter.retryMax = retry
	rig.run(t)
	rig.waitPuts(t, 1)

	// A retry timer reset by any of these would never fire, and an attempt on
	// any of these would land before the delay.
	halt := rig.notifyUntilStopped(t)
	rig.waitPuts(t, 2)
	halt()

	_, sentAt := rig.client.recorded()
	if gap := sentAt[1].Sub(sentAt[0]); gap < retry {
		t.Errorf("second PUT came %v after the first, want at least the retry delay %v", gap, retry)
	}
}

func TestCapabilityReporter_DifferentContentDuringBackoffSendsAndKeepsTheBackoff(t *testing.T) {
	rig := newCapabilityRig(errCapabilityUnavailable, errCapabilityUnavailable)
	rig.reporter.retryMax = 8 * capabilityNeverFires
	rig.run(t)
	rig.waitPuts(t, 1)

	rig.source.set(manifestB)
	rig.reporter.Notify()
	rig.waitPuts(t, 2)

	rig.source.set(manifestC)
	rig.reporter.Notify()
	rig.waitPuts(t, 3)

	rig.assertPuts(t, manifestA, manifestB, manifestC)
	want := []time.Duration{capabilityNeverFires, 2 * capabilityNeverFires}
	if got := rig.delays.recorded(); !slices.Equal(got, want) {
		t.Errorf("nominal delays = %v, want %v", got, want)
	}
}

func TestCapabilityReporter_NotifyDuringHoldSendsNothing(t *testing.T) {
	const hold = capabilityNeverFires
	rig := newCapabilityRig(&api.APIError{StatusCode: 429, RetryAfter: hold})
	clock := newFrozenClock()
	rig.reporter.now = clock.now
	rig.reporter.retryMin = time.Millisecond
	rig.reporter.retryMax = time.Millisecond
	rig.run(t)
	rig.waitPuts(t, 1)
	// The hold is measured when the failure is recorded, which follows the PUT,
	// so the clock must not move before that.
	rig.flush(t)

	rig.source.set(manifestB)
	advanceClock(clock, hold-time.Minute)
	rig.notifyAndSettle(t)
	rig.assertPuts(t, manifestA)

	advanceClock(clock, 2*time.Minute)
	rig.reporter.Notify()
	rig.waitPuts(t, 2)
	rig.assertPuts(t, manifestA, manifestB)
}

func TestCapabilityReporter_HoldEndsWithTheRetryAfter(t *testing.T) {
	// The Retry-After is shorter than the backoff, so the backoff sets the timer
	// and the hold ends first: the control plane asked for one second, and new
	// content has no reason to wait out the rest of a backoff.
	rig := newCapabilityRig(&api.APIError{StatusCode: 429, RetryAfter: time.Second})
	clock := newFrozenClock()
	rig.reporter.now = clock.now
	rig.reporter.retryMin = capabilityNeverFires
	rig.reporter.retryMax = capabilityNeverFires
	rig.run(t)
	rig.waitPuts(t, 1)
	rig.flush(t)

	rig.source.set(manifestB)
	advanceClock(clock, 2*time.Second)
	rig.reporter.Notify()
	rig.waitPuts(t, 2)

	rig.assertPuts(t, manifestA, manifestB)
}

func TestCapabilityReporter_ShortRetryAfterLeavesIdenticalContentToTheBackoff(t *testing.T) {
	// Past the hold, a notification with no news still leaves the send to the
	// retry timer, which the backoff set.
	rig := newCapabilityRig(&api.APIError{StatusCode: 429, RetryAfter: time.Second})
	clock := newFrozenClock()
	rig.reporter.now = clock.now
	rig.reporter.retryMin = capabilityNeverFires
	rig.reporter.retryMax = capabilityNeverFires
	rig.run(t)
	rig.waitPuts(t, 1)
	rig.flush(t)

	advanceClock(clock, 2*time.Second)
	rig.notifyAndSettle(t)

	rig.assertPuts(t, manifestA)
}

func TestCapabilityReporter_RetryTimerDeliversTheNewestContentAfterAHold(t *testing.T) {
	const hold = 40 * time.Millisecond
	rig := newCapabilityRig(&api.APIError{StatusCode: 429, RetryAfter: hold})
	rig.reporter.now = newFrozenClock().now
	rig.reporter.retryMin = time.Millisecond
	rig.reporter.retryMax = time.Millisecond
	rig.client.onCall = func(n int) {
		if n == 0 {
			rig.source.set(manifestB)
			rig.reporter.Notify()
		}
	}
	rig.run(t)

	rig.waitPuts(t, 2)

	rig.assertPuts(t, manifestA, manifestB)
	_, sentAt := rig.client.recorded()
	if gap := sentAt[1].Sub(sentAt[0]); gap < hold {
		t.Errorf("newest content went out %v after the 429, want at least the hold %v", gap, hold)
	}
}

func TestCapabilityReporter_HoldOutlivesARevertToTheAcceptedManifest(t *testing.T) {
	const hold = 40 * time.Millisecond
	rig := newCapabilityRig(nil, &api.APIError{StatusCode: 429, RetryAfter: hold})
	rig.reporter.now = newFrozenClock().now
	rig.reporter.retryMin = time.Millisecond
	rig.reporter.retryMax = time.Millisecond
	rig.client.onCall = func(n int) {
		if n == 1 {
			rig.source.set(manifestA)
			rig.reporter.Notify()
		}
	}
	rig.run(t)
	rig.waitPuts(t, 1)

	// The revert matches the accepted manifest and stops the retry, so nothing
	// is armed when the next change arrives with the hold still running.
	rig.source.set(manifestB)
	rig.reporter.Notify()
	rig.waitBuilds(t, 3)
	rig.flush(t)

	rig.source.set(manifestC)
	changedAt := time.Now()
	rig.reporter.Notify()
	rig.waitPuts(t, 3)

	rig.assertPuts(t, manifestA, manifestB, manifestC)
	_, sentAt := rig.client.recorded()
	if gap := sentAt[2].Sub(changedAt); gap < hold {
		t.Errorf("PUT came %v after the change, want the rest of the hold, %v", gap, hold)
	}
}

// ---------------------------------------------------------------------------
// What a failure says about the accepted manifest
// ---------------------------------------------------------------------------

// A failure that does not prove the write was refused must forget the accepted
// manifest: PUT B can commit and lose its response, and a revert to A would
// otherwise leave B in the row with nothing to correct it.
func TestCapabilityReporter_RevertAfterFailure(t *testing.T) {
	failures := []struct {
		name         string
		err          error
		wantReverted bool
	}{
		{name: "network error sends", err: errCapabilityNetwork, wantReverted: true},
		{name: "request timeout sends", err: errCapabilityTimeout, wantReverted: true},
		{name: "500 sends", err: &api.APIError{StatusCode: 500}, wantReverted: true},
		{name: "503 sends", err: errCapabilityUnavailable, wantReverted: true},
		{name: "wrapped 503 sends", err: fmt.Errorf("put: %w", errCapabilityUnavailable), wantReverted: true},
		{name: "400 skips", err: errCapabilityTooMany},
		{name: "wrapped 400 skips", err: fmt.Errorf("put: %w", errCapabilityTooMany)},
		{name: "429 skips", err: &api.APIError{StatusCode: 429}},
		{name: "refused credential skips", err: api.ErrCredentialRefused},
	}
	for _, viaTimer := range []bool{false, true} {
		for _, tt := range failures {
			t.Run(fmt.Sprintf("viaTimer=%v/%s", viaTimer, tt.name), func(t *testing.T) {
				rig := newCapabilityRig(nil, tt.err)
				if viaTimer {
					rig.reporter.retryMin = time.Millisecond
					rig.reporter.retryMax = time.Millisecond
				}
				rig.client.onCall = func(n int) {
					if n == 1 {
						rig.source.set(manifestA)
						if !viaTimer {
							rig.reporter.Notify()
						}
					}
				}
				stop := rig.run(t)
				rig.waitPuts(t, 1)

				rig.source.set(manifestB)
				rig.reporter.Notify()

				if tt.wantReverted {
					rig.waitPuts(t, 3)
					rig.assertPuts(t, manifestA, manifestB, manifestA)
					return
				}

				rig.waitBuilds(t, 3)
				rig.flush(t)
				rig.assertPuts(t, manifestA, manifestB)
				stop()
				if rig.reporter.retryArmed {
					t.Error("retry still armed with the accepted manifest current")
				}
			})
		}
	}
}

func TestCapabilityReporter_EqualManifestResetsTheBackoff(t *testing.T) {
	rig := newCapabilityRig(nil, errCapabilityTooMany, errCapabilityUnavailable)
	rig.reporter.retryMax = 8 * capabilityNeverFires
	rig.client.onCall = func(n int) {
		if n == 1 {
			rig.source.set(manifestA)
			rig.reporter.Notify()
		}
	}
	rig.run(t)
	rig.waitPuts(t, 1)

	rig.source.set(manifestB)
	rig.reporter.Notify()
	rig.waitBuilds(t, 3)
	rig.flush(t)

	rig.source.set(manifestC)
	rig.reporter.Notify()
	rig.waitPuts(t, 3)
	rig.flush(t)

	want := []time.Duration{capabilityNeverFires, capabilityNeverFires}
	if got := rig.delays.recorded(); !slices.Equal(got, want) {
		t.Errorf("nominal delays = %v, want %v", got, want)
	}
}

func TestCapabilityReporter_ReappliedContentSendsAfterARevert(t *testing.T) {
	rig := newCapabilityRig(nil, errCapabilityTooMany)
	rig.client.onCall = func(n int) {
		if n == 1 {
			rig.source.set(manifestA)
			rig.reporter.Notify()
		}
	}
	rig.run(t)
	rig.waitPuts(t, 1)

	rig.source.set(manifestB)
	rig.reporter.Notify()
	rig.waitBuilds(t, 3)
	rig.flush(t)

	// The revert stopped the retry, so no timer is left to deliver this. That
	// it matches the attempt that failed must not hold it back.
	rig.source.set(manifestB)
	rig.reporter.Notify()
	rig.waitPuts(t, 3)

	rig.assertPuts(t, manifestA, manifestB, manifestB)
}

// ---------------------------------------------------------------------------
// Refused credential
// ---------------------------------------------------------------------------

func TestCapabilityReporter_CredentialRefusedLogsAtDebugAndDelivers(t *testing.T) {
	refused := api.ErrCredentialRefused
	rig := newCapabilityRig(refused, refused, refused)
	rig.useRealBackoff(time.Millisecond)
	rig.run(t)

	rig.waitPuts(t, 4)
	rig.flush(t)

	rig.assertPuts(t, manifestA, manifestA, manifestA, manifestA)
	logs := rig.logs.String()
	if got := countLogLines(logs, capabilitySendFailed); got != 3 {
		t.Errorf("failure lines = %d, want 3; logs:\n%s", got, logs)
	}
	for line := range strings.SplitSeq(logs, "\n") {
		if strings.Contains(line, capabilitySendFailed) && !strings.Contains(line, "level=DEBUG") {
			t.Errorf("refusal logged above Debug: %q", line)
		}
	}
	if strings.Contains(logs, "level=WARN") {
		t.Errorf("logs hold a Warn for a refused credential:\n%s", logs)
	}
	if got := countLogLines(logs, capabilityAccepted); got != 1 {
		t.Errorf("accepted lines = %d, want 1", got)
	}
}

func TestCapabilityReporter_CredentialRefusedLeavesTheBackoffAlone(t *testing.T) {
	rig := newCapabilityRig(errCapabilityUnavailable, errCapabilityUnavailable, api.ErrCredentialRefused, errCapabilityUnavailable)
	rig.useRealBackoff(time.Millisecond)
	rig.run(t)

	rig.waitPuts(t, 5)

	// The refusal waits the minimum whatever the backoff has reached, so
	// delivery follows one short retry after the mark lifts, and the failure
	// after it carries on where the backoff stood.
	want := []time.Duration{5 * time.Second, 10 * time.Second, 5 * time.Second, 20 * time.Second}
	if got := rig.delays.recorded(); !slices.Equal(got, want) {
		t.Errorf("nominal delays = %v, want %v", got, want)
	}
}

func TestCapabilityReporter_CredentialRefusedIsNotRecordedAsAttempted(t *testing.T) {
	// A refusal involves no I/O, so a notification may try again at once: the
	// control plane has not seen this manifest and missed nothing by it.
	rig := newCapabilityRig(api.ErrCredentialRefused)
	rig.run(t)
	rig.waitPuts(t, 1)

	rig.reporter.Notify()
	rig.waitPuts(t, 2)

	rig.assertPuts(t, manifestA, manifestA)
}

// ---------------------------------------------------------------------------
// Hook metadata fallback
// ---------------------------------------------------------------------------

func TestCapabilityReporter_WideAcceptedOnFirstPut(t *testing.T) {
	const wideRetry = 5 * time.Millisecond
	rig := newCapabilityRig()
	rig.reporter.wideRetry = wideRetry
	rig.source.set(wideManifest("digest-a", "one"))
	stop := rig.run(t)

	rig.waitPuts(t, 1)
	rig.assertNoAttemptFor(t, 10*wideRetry)
	stop()

	rig.assertPuts(t, wideManifest("digest-a", "one"))
	line := logLine(t, rig.logs.String(), capabilityAccepted)
	if !strings.Contains(line, "hook_metadata=true") {
		t.Errorf("accepted line %q lacks hook_metadata=true", line)
	}
}

func TestCapabilityReporter_RefusalFallsBackToShort(t *testing.T) {
	// The accepted short PUT resets retryArmed and the backoff by itself, so
	// the recorded delays carry this test. wideRetry differs from retryMin so a
	// backoff arm cannot pass for the wide arm, and retryMax sits above
	// retryMin so a doubling would show.
	const wideRetry = 2 * capabilityNeverFires
	type refusal struct {
		name string
		err  error
	}
	tests := []refusal{
		{name: "400 malformed_capabilities_request", err: errCapabilityMalformed},
		{name: "400 declared_hook_invalid", err: &api.APIError{StatusCode: 400, Code: "declared_hook_invalid"}},
		{name: "400 declared_hooks_too_many", err: errCapabilityTooMany},
		{name: "413 capabilities_body_too_large", err: &api.APIError{StatusCode: 413, Code: "capabilities_body_too_large"}},
		{name: "413 with no code", err: &api.APIError{StatusCode: 413}},
		{name: "413 with a code plexd does not know", err: &api.APIError{StatusCode: 413, Code: "body_limit"}},
	}
	// The client wraps what it returns, so each refusal also arrives wrapped.
	for _, tt := range tests {
		tests = append(tests, refusal{name: "wrapped " + tt.name, err: fmt.Errorf("put capabilities: %w", tt.err)})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rig := newCapabilityRig(tt.err)
			rig.reporter.wideRetry = wideRetry
			rig.reporter.retryMax = 8 * capabilityNeverFires
			rig.source.set(wideManifest("digest-a", "one"))
			stop := rig.run(t)

			rig.waitPuts(t, 2)
			stop()

			rig.assertPuts(t, wideManifest("digest-a", "one"), manifestA)
			if got, want := rig.delays.recorded(), []time.Duration{wideRetry}; !slices.Equal(got, want) {
				t.Errorf("nominal delays = %v, want %v", got, want)
			}
			logs := rig.logs.String()
			if got := countLogLines(logs, capabilitySendFailed); got != 0 {
				t.Errorf("failure lines = %d, want 0; logs:\n%s", got, logs)
			}

			r := rig.reporter
			if r.retryArmed {
				t.Error("retry armed by a refusal that fell back")
			}
			if r.backoff != r.retryMin {
				t.Errorf("backoff = %v, want %v", r.backoff, r.retryMin)
			}
			if want := wideManifest("digest-a", "one"); r.refused == nil || !reflect.DeepEqual(*r.refused, want) {
				t.Errorf("refused = %+v, want the wide manifest", r.refused)
			}
			if r.accepted == nil || !reflect.DeepEqual(*r.accepted, manifestA) {
				t.Errorf("accepted = %+v, want the short form", r.accepted)
			}
		})
	}
}

func TestCapabilityReporter_FallbackLogs(t *testing.T) {
	rig := newCapabilityRig(errCapabilityMalformed)
	rig.reporter.wideRetry = 2 * capabilityNeverFires
	rig.source.set(wideManifest("digest-a", "one"))
	stop := rig.run(t)
	rig.waitPuts(t, 2)
	stop()

	logs := rig.logs.String()
	line := logLine(t, logs, capabilityWideRefused)
	for _, want := range []string{"level=WARN", "component=capability-report", "error=", "malformed_capabilities_request", "wide_retry_in=2h0m0s"} {
		if !strings.Contains(line, want) {
			t.Errorf("refused line %q lacks %q", line, want)
		}
	}
	if line := logLine(t, logs, capabilityAccepted); !strings.Contains(line, "hook_metadata=false") {
		t.Errorf("accepted line %q lacks hook_metadata=false", line)
	}
}

// wideRetry stays at the rig's hour, so only the jittered delay can bring the
// third PUT. The line reports the delay the timer really got.
func TestCapabilityReporter_WideTimerTakesTheJitteredDelay(t *testing.T) {
	rig := newCapabilityRig(errCapabilityMalformed)
	rig.delays.actual = 7 * time.Millisecond
	rig.source.set(wideManifest("digest-a", "one"))
	stop := rig.run(t)

	rig.waitPuts(t, 3)
	stop()

	line := logLine(t, rig.logs.String(), capabilityWideRefused)
	if !strings.Contains(line, "wide_retry_in=7ms") {
		t.Errorf("refused line %q lacks wide_retry_in=7ms", line)
	}
}

func TestCapabilityReporter_RefusalWithoutMetadataTakesTheBackoff(t *testing.T) {
	rig := newCapabilityRig(errCapabilityMalformed)
	rig.reporter.wideRetry = 2 * capabilityNeverFires
	rig.reporter.retryMax = 8 * capabilityNeverFires
	stop := rig.run(t)
	rig.waitPuts(t, 1)
	rig.flush(t)
	stop()

	rig.assertPuts(t, manifestA)
	if got, want := rig.delays.recorded(), []time.Duration{capabilityNeverFires}; !slices.Equal(got, want) {
		t.Errorf("nominal delays = %v, want %v", got, want)
	}
	logs := rig.logs.String()
	if got := countLogLines(logs, capabilitySendFailed); got != 1 {
		t.Errorf("failure lines = %d, want 1; logs:\n%s", got, logs)
	}
	if got := countLogLines(logs, capabilityWideRefused); got != 0 {
		t.Errorf("refused lines = %d, want 0; logs:\n%s", got, logs)
	}

	r := rig.reporter
	if !r.retryArmed {
		t.Error("no retry armed after an ordinary refusal")
	}
	if want := 2 * capabilityNeverFires; r.backoff != want {
		t.Errorf("backoff = %v, want %v", r.backoff, want)
	}
	if r.refused != nil {
		t.Errorf("refused = %+v, want nil", r.refused)
	}
}

func TestCapabilityReporter_OtherRefusalKeepsRetryingWide(t *testing.T) {
	rig := newCapabilityRig(&api.APIError{StatusCode: 400, Code: "binary_checksum_invalid"})
	rig.reporter.retryMin = time.Millisecond
	rig.reporter.retryMax = time.Millisecond
	rig.source.set(wideManifest("digest-a", "one"))
	rig.run(t)

	rig.waitPuts(t, 2)
	rig.flush(t)

	rig.assertPuts(t, wideManifest("digest-a", "one"), wideManifest("digest-a", "one"))
	if got, want := rig.delays.recorded(), []time.Duration{time.Millisecond}; !slices.Equal(got, want) {
		t.Errorf("nominal delays = %v, want %v", got, want)
	}
	logs := rig.logs.String()
	if got := countLogLines(logs, capabilitySendFailed); got != 1 {
		t.Errorf("failure lines = %d, want 1; logs:\n%s", got, logs)
	}
	if got := countLogLines(logs, capabilityWideRefused); got != 0 {
		t.Errorf("refused lines = %d, want 0; logs:\n%s", got, logs)
	}
}

func TestCapabilityReporter_WideFailureKeepsRetryingWide(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "network error", err: errCapabilityNetwork},
		{name: "503", err: errCapabilityUnavailable},
		{name: "refused credential", err: api.ErrCredentialRefused},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rig := newCapabilityRig(tt.err)
			rig.reporter.retryMin = time.Millisecond
			rig.reporter.retryMax = time.Millisecond
			rig.source.set(wideManifest("digest-a", "one"))
			rig.run(t)

			rig.waitPuts(t, 2)
			rig.flush(t)

			rig.assertPuts(t, wideManifest("digest-a", "one"), wideManifest("digest-a", "one"))
			logs := rig.logs.String()
			if got := countLogLines(logs, capabilityWideRefused); got != 0 {
				t.Errorf("refused lines = %d, want 0; logs:\n%s", got, logs)
			}
		})
	}
}

func TestCapabilityReporter_CancelledWidePutDoesNotFallBack(t *testing.T) {
	rig := newCapabilityRig()
	rig.client.block = true
	rig.source.set(wideManifest("digest-a", "one"))
	stop := rig.run(t)
	rig.waitPuts(t, 1)

	stop()

	rig.assertPuts(t, wideManifest("digest-a", "one"))
	logs := rig.logs.String()
	for _, msg := range []string{capabilitySendFailed, capabilityWideRefused} {
		if got := countLogLines(logs, msg); got != 0 {
			t.Errorf("lines with %q = %d for a cancelled request, want 0; logs:\n%s", msg, got, logs)
		}
	}
}

func TestCapabilityReporter_NotifyAfterFallbackSendsNothing(t *testing.T) {
	rig := newCapabilityRig(errCapabilityMalformed)
	rig.source.set(wideManifest("digest-a", "one"))
	rig.run(t)
	rig.waitPuts(t, 2)

	builds := rig.source.count()
	rig.notifyAndSettle(t)

	if got := rig.source.count(); got <= builds {
		t.Fatalf("builds = %d, want more than %d: the attempt never ran", got, builds)
	}
	rig.assertPuts(t, wideManifest("digest-a", "one"), manifestA)
}

func TestCapabilityReporter_DescriptionChangeAfterFallback(t *testing.T) {
	const wideRetry = 2 * capabilityNeverFires
	rig := newCapabilityRig(errCapabilityMalformed, nil, errCapabilityMalformed)
	rig.reporter.wideRetry = wideRetry
	rig.source.set(wideManifest("digest-a", "one"))
	rig.run(t)
	rig.waitPuts(t, 2)

	rig.source.set(wideManifest("digest-a", "two"))
	rig.reporter.Notify()
	rig.waitPuts(t, 3)
	rig.flush(t)

	// The short form of the new content is what the control plane holds.
	rig.assertPuts(t, wideManifest("digest-a", "one"), manifestA, wideManifest("digest-a", "two"))
	want := []time.Duration{wideRetry, wideRetry}
	if got := rig.delays.recorded(); !slices.Equal(got, want) {
		t.Errorf("nominal delays = %v, want %v", got, want)
	}
}

// The first refusal arms the timer for an hour, so only the second refusal's arm
// can bring the fourth PUT.
func TestCapabilityReporter_LaterRefusalRearmsTheWideTimer(t *testing.T) {
	rig := newCapabilityRig(errCapabilityMalformed, nil, errCapabilityMalformed)
	rig.client.onCall = func(n int) {
		if n == 1 {
			rig.delays.mu.Lock()
			rig.delays.actual = 5 * time.Millisecond
			rig.delays.mu.Unlock()
			rig.source.set(wideManifest("digest-a", "two"))
			rig.reporter.Notify()
		}
	}
	rig.source.set(wideManifest("digest-a", "one"))
	rig.run(t)

	rig.waitPuts(t, 4)
	rig.flush(t)

	two := wideManifest("digest-a", "two")
	rig.assertPuts(t, wideManifest("digest-a", "one"), manifestA, two, two)
}

// A failure of the new content grew the backoff, and the refusal that follows
// needs no PUT, because the control plane already holds its short form. stop
// comes before the read, not flush: a further attempt would clear the backoff
// on its own.
func TestCapabilityReporter_HeldShortFormClearsTheRetry(t *testing.T) {
	const retryMin = time.Millisecond
	rig := newCapabilityRig(errCapabilityMalformed, nil, &api.APIError{StatusCode: 429}, errCapabilityMalformed)
	rig.reporter.retryMin = retryMin
	rig.reporter.retryMax = 8 * retryMin
	rig.source.set(wideManifest("digest-a", "one"))
	stop := rig.run(t)
	rig.waitPuts(t, 2)

	rig.source.set(wideManifest("digest-a", "two"))
	rig.reporter.Notify()
	rig.waitPuts(t, 4)
	stop()

	two := wideManifest("digest-a", "two")
	rig.assertPuts(t, wideManifest("digest-a", "one"), manifestA, two, two)
	if got := rig.reporter.backoff; got != retryMin {
		t.Errorf("backoff = %v, want %v", got, retryMin)
	}
}

func TestCapabilityReporter_ChecksumChangeAfterFallback(t *testing.T) {
	rig := newCapabilityRig(errCapabilityMalformed, nil, errCapabilityMalformed)
	rig.source.set(wideManifest("digest-a", "one"))
	rig.run(t)
	rig.waitPuts(t, 2)

	rig.source.set(wideManifest("digest-b", "one"))
	rig.reporter.Notify()
	rig.waitPuts(t, 4)
	rig.flush(t)

	rig.assertPuts(t, wideManifest("digest-a", "one"), manifestA, wideManifest("digest-b", "one"), manifestB)
}

func TestCapabilityReporter_ChangedWideAcceptedAfterFallback(t *testing.T) {
	const wideRetry = 40 * time.Millisecond
	rig := newCapabilityRig(errCapabilityMalformed)
	rig.reporter.wideRetry = wideRetry
	rig.client.onCall = func(n int) {
		if n == 1 {
			rig.source.set(wideManifest("digest-a", "two"))
			rig.reporter.Notify()
		}
	}
	rig.source.set(wideManifest("digest-a", "one"))
	stop := rig.run(t)

	rig.waitPuts(t, 3)
	rig.flush(t)
	rig.assertNoAttemptFor(t, 2*wideRetry)
	stop()

	rig.assertPuts(t, wideManifest("digest-a", "one"), manifestA, wideManifest("digest-a", "two"))
	if rig.reporter.refused != nil {
		t.Errorf("refused = %+v, want nil", rig.reporter.refused)
	}
}

func TestCapabilityReporter_WideTimerStillRefused(t *testing.T) {
	const wideRetry = time.Millisecond
	// Past this list the fake accepts, which ends the run with a fifth PUT.
	rig := newCapabilityRig(errCapabilityMalformed, nil, errCapabilityMalformed, errCapabilityMalformed)
	rig.reporter.wideRetry = wideRetry
	rig.source.set(wideManifest("digest-a", "one"))
	stop := rig.run(t)

	rig.waitPuts(t, 5)
	stop()

	wide := wideManifest("digest-a", "one")
	rig.assertPuts(t, wide, manifestA, wide, wide, wide)
	want := []time.Duration{wideRetry, wideRetry, wideRetry}
	if got := rig.delays.recorded(); !slices.Equal(got, want) {
		t.Errorf("nominal delays = %v, want %v", got, want)
	}
	if got := countLogLines(rig.logs.String(), capabilityWideRefused); got != 3 {
		t.Errorf("refused lines = %d, want 3", got)
	}
}

func TestCapabilityReporter_WideTimerAccepted(t *testing.T) {
	const wideRetry = 5 * time.Millisecond
	rig := newCapabilityRig(errCapabilityMalformed)
	rig.reporter.wideRetry = wideRetry
	rig.source.set(wideManifest("digest-a", "one"))
	stop := rig.run(t)

	rig.waitPuts(t, 3)
	rig.assertNoAttemptFor(t, 10*wideRetry)
	stop()

	rig.assertPuts(t, wideManifest("digest-a", "one"), manifestA, wideManifest("digest-a", "one"))
	if got, want := rig.delays.recorded(), []time.Duration{wideRetry}; !slices.Equal(got, want) {
		t.Errorf("nominal delays = %v, want %v", got, want)
	}
	if got := countLogLines(rig.logs.String(), capabilityAccepted); got != 2 {
		t.Errorf("accepted lines = %d, want 2", got)
	}
	if rig.reporter.refused != nil {
		t.Errorf("refused = %+v, want nil", rig.reporter.refused)
	}
}

func TestCapabilityReporter_WideTimerRespectsTheHold(t *testing.T) {
	const hold = 150 * time.Millisecond
	rig := newCapabilityRig(errCapabilityMalformed, &api.APIError{StatusCode: 429, RetryAfter: hold})
	rig.reporter.now = newFrozenClock().now
	rig.reporter.retryMin = time.Millisecond
	rig.reporter.retryMax = time.Millisecond
	rig.reporter.wideRetry = time.Millisecond
	rig.source.set(wideManifest("digest-a", "one"))
	rig.run(t)

	// The second build is the wide timer's attempt, which the hold keeps off
	// the wire. It clears refused, so the retry that ends the hold carries wide.
	rig.waitBuilds(t, 2)
	rig.waitPuts(t, 3)
	rig.flush(t)

	rig.assertPuts(t, wideManifest("digest-a", "one"), manifestA, wideManifest("digest-a", "one"))
	_, sentAt := rig.client.recorded()
	if gap := sentAt[2].Sub(sentAt[1]); gap < hold {
		t.Errorf("wide form went out %v after the 429, want at least the hold %v", gap, hold)
	}
}

func TestCapabilityReporter_ShortFailureRetriesShort(t *testing.T) {
	const retryMin = time.Millisecond
	rig := newCapabilityRig(errCapabilityMalformed, errCapabilityUnavailable)
	rig.reporter.retryMin = retryMin
	rig.reporter.retryMax = 8 * retryMin
	rig.source.set(wideManifest("digest-a", "one"))
	rig.run(t)

	rig.waitPuts(t, 3)
	rig.flush(t)

	rig.assertPuts(t, wideManifest("digest-a", "one"), manifestA, manifestA)

	// retryMin on the second delay shows the refusal left the backoff alone.
	want := []time.Duration{capabilityNeverFires, retryMin}
	if got := rig.delays.recorded(); !slices.Equal(got, want) {
		t.Errorf("nominal delays = %v, want %v", got, want)
	}
}

func TestCapabilityReporter_WideTimerFailureRetriesWide(t *testing.T) {
	wide := wideManifest("digest-a", "one")
	tests := []struct {
		name string
		errs []error
		want []api.CapabilityManifestRequest
	}{
		{
			name: "until accepted",
			errs: []error{errCapabilityMalformed, nil, errCapabilityUnavailable},
			want: []api.CapabilityManifestRequest{wide, manifestA, wide, wide},
		},
		{
			// The 503 cleared accepted, so the short form goes out again, and
			// the re-armed timer then finds a control plane that accepts.
			name: "until refused",
			errs: []error{errCapabilityMalformed, nil, errCapabilityUnavailable, errCapabilityMalformed},
			want: []api.CapabilityManifestRequest{wide, manifestA, wide, wide, manifestA, wide},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rig := newCapabilityRig(tt.errs...)
			rig.reporter.retryMin = time.Millisecond
			rig.reporter.retryMax = time.Millisecond
			rig.reporter.wideRetry = time.Millisecond
			rig.source.set(wideManifest("digest-a", "one"))
			rig.run(t)

			rig.waitPuts(t, len(tt.want))
			rig.flush(t)

			rig.assertPuts(t, tt.want...)
		})
	}
}

func TestCapabilityReporter_MetadataRemovedAfterFallback(t *testing.T) {
	rig := newCapabilityRig(errCapabilityMalformed)
	rig.reporter.wideRetry = 5 * time.Millisecond
	rig.client.onCall = func(n int) {
		if n == 1 {
			rig.source.set(manifestA)
			rig.reporter.Notify()
		}
	}
	rig.source.set(wideManifest("digest-a", "one"))
	rig.run(t)

	// The boot, the notification and the wide timer, the last two in either
	// order. Each of those two finds the built manifest equal to the accepted
	// one.
	rig.waitBuilds(t, 3)
	rig.flush(t)

	rig.assertPuts(t, wideManifest("digest-a", "one"), manifestA)
}

func TestCapabilityReporter_CarriesHookMetadata(t *testing.T) {
	plain := api.DeclaredHook{Name: "a", Checksum: "x"}
	tests := []struct {
		name  string
		hooks []api.DeclaredHook
		want  bool
	}{
		{name: "no hooks", hooks: nil, want: false},
		{name: "name and checksum", hooks: []api.DeclaredHook{plain}, want: false},
		{name: "empty parameters", hooks: []api.DeclaredHook{{Name: "a", Checksum: "x", Parameters: []api.ActionParam{}}}, want: false},
		{name: "description", hooks: []api.DeclaredHook{{Name: "a", Checksum: "x", Description: "d"}}, want: true},
		{name: "parameters", hooks: []api.DeclaredHook{{Name: "a", Checksum: "x", Parameters: []api.ActionParam{{Name: "p"}}}}, want: true},
		{name: "timeout", hooks: []api.DeclaredHook{{Name: "a", Checksum: "x", TimeoutSeconds: 1}}, want: true},
		{name: "sandbox level", hooks: []api.DeclaredHook{{Name: "a", Checksum: "x", SandboxLevel: "none"}}, want: true},
		{name: "a later entry", hooks: []api.DeclaredHook{plain, {Name: "b", Checksum: "y", Description: "d"}}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := carriesHookMetadata(api.CapabilityManifestRequest{DeclaredHooks: tt.hooks})
			if got != tt.want {
				t.Errorf("carriesHookMetadata(%+v) = %v, want %v", tt.hooks, got, tt.want)
			}
		})
	}
}

func TestCapabilityReporter_WithoutHookMetadataLeavesTheOriginalWhole(t *testing.T) {
	// Only the entries change, so everything else goes out as built.
	withTheRest := func(m api.CapabilityManifestRequest) api.CapabilityManifestRequest {
		m.SSHHostKeyFingerprint = "SHA256:abc"
		m.PlexdHooks = []api.DiscoveredPlexdHook{{Name: "p", ImageDigest: "sha256:0"}}
		m.BuiltinActions = []api.ActionInfo{{Name: "a", Description: "d"}}
		return m
	}
	wide := withTheRest(wideManifest("digest-a", "one"))

	got := withoutHookMetadata(wide)

	if want := withTheRest(capabilityManifest("digest-a")); !reflect.DeepEqual(got, want) {
		t.Errorf("withoutHookMetadata() = %+v, want %+v", got, want)
	}
	if whole := withTheRest(wideManifest("digest-a", "one")); !reflect.DeepEqual(wide, whole) {
		t.Errorf("the original became %+v, want %+v", wide, whole)
	}
}

func TestCapabilityReporter_WithoutHookMetadataKeepsANilSliceNil(t *testing.T) {
	if got := withoutHookMetadata(api.CapabilityManifestRequest{}); got.DeclaredHooks != nil {
		t.Errorf("DeclaredHooks = %+v, want nil", got.DeclaredHooks)
	}
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

func TestCapabilityReporter_CancelledSendLogsNothing(t *testing.T) {
	rig := newCapabilityRig()
	rig.client.block = true
	stop := rig.run(t)
	rig.waitPuts(t, 1)

	stop()

	logs := rig.logs.String()
	if got := countLogLines(logs, capabilitySendFailed); got != 0 {
		t.Errorf("failure lines = %d for a cancelled request, want 0; logs:\n%s", got, logs)
	}
	if strings.Contains(logs, "level=WARN") {
		t.Errorf("logs hold a Warn for a cancelled request:\n%s", logs)
	}
}

func TestCapabilityReporter_RunReturnsNilWhenCancelled(t *testing.T) {
	tests := []struct {
		name  string
		errs  []error
		setup func(t *testing.T, rig *capabilityRig)
	}{
		{name: "idle"},
		{name: "waiting on the retry timer", errs: []error{errCapabilityUnavailable}},
		{
			name: "inside the quiet period",
			setup: func(t *testing.T, rig *capabilityRig) {
				t.Helper()
				rig.reporter.Notify()
				// Run took the notification once the channel is empty again.
				waitFor(t, capabilityTestWait, func() bool { return len(rig.reporter.notify) == 0 })
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rig := newCapabilityRig(tt.errs...)
			rig.reporter.quietPeriod = capabilityNeverFires
			stop := rig.run(t)
			rig.waitPuts(t, 1)
			if tt.setup != nil {
				tt.setup(t, rig)
			}

			// The rig fails the test unless Run returns nil in time.
			stop()
		})
	}
}

func TestCapabilityReporter_NotifyNeverBlocks(t *testing.T) {
	rig := newCapabilityRig()
	notifyMany := func() {
		t.Helper()
		done := make(chan struct{})
		go func() {
			defer close(done)
			for range 5 {
				rig.reporter.Notify()
			}
		}()
		select {
		case <-done:
		case <-time.After(capabilityTestWait):
			t.Fatal("Notify blocked")
		}
	}

	notifyMany()
	stop := rig.run(t)
	rig.waitPuts(t, 1)
	stop()
	notifyMany()
}
