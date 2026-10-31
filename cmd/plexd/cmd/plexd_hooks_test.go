package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/agent"
	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/kubernetes"
)

const (
	plexdHookTestDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// plexdHookTestWait bounds every wait on a condition. Only a failing test
	// reaches it.
	plexdHookTestWait = 10 * time.Second

	plexdHookWatchFailedMsg   = "plexd hook watch failed"
	plexdHookWatchRestoredMsg = "plexd hook watch restored"
	plexdHookWatchEndedMsg    = "plexd hook watch ended early"
	plexdHookDiscoveryFailMsg = "plexd hook discovery failed"
)

// fakeHookList is one scripted answer to ListPlexdHooks. block holds the call
// until its context ends, which is how a test catches a list in flight. gate holds
// it until the test closes the channel, which keeps its outcome from arriving
// before the test has looked at the state ahead of it.
type fakeHookList struct {
	hooks []kubernetes.PlexdHook
	err   error
	block bool
	gate  chan struct{}
}

// fakeHookWatch is one scripted answer to WatchPlexdHooks.
type fakeHookWatch struct {
	events chan kubernetes.PlexdHookEvent
	err    error

	// gate holds the open until the test closes it, which lets a test look at
	// the state an earlier cycle left behind.
	gate chan struct{}

	// closeOnEnd closes events when the watch context ends, as the real lister
	// does.
	closeOnEnd bool

	// holdUntilEnd keeps the open from returning until the watch context has
	// ended, so whatever runs after it meets an expired watch context for certain.
	holdUntilEnd bool
}

// fakeHookLister answers from a script and records what it was asked. The mutex
// is there because run reads it from another goroutine.
//
// Past the end of watches, an open parks until its context ends. That is what
// makes the counts exact: a test that sees run reach the parked open knows every
// earlier cycle finished, logging and backoff included, and nothing further can
// happen until run is stopped. Stopping releases the open, and the list that
// follows it fails on the cancelled context, so a test reads the list count first.
type fakeHookLister struct {
	// hooks and err answer every list that lists does not script. Set them before
	// the lister is used.
	hooks []kubernetes.PlexdHook
	err   error

	mu      sync.Mutex
	lists   []fakeHookList
	watches []fakeHookWatch

	namespace   string
	deadline    time.Time
	hasDeadline bool

	watchDeadline time.Time

	listCalls int
	openCalls int
}

func (f *fakeHookLister) ListPlexdHooks(ctx context.Context, namespace string) ([]kubernetes.PlexdHook, error) {
	f.mu.Lock()
	f.namespace = namespace
	f.deadline, f.hasDeadline = ctx.Deadline()
	f.listCalls++
	answer := fakeHookList{hooks: f.hooks, err: f.err}
	if len(f.lists) > 0 {
		answer, f.lists = f.lists[0], f.lists[1:]
	}
	f.mu.Unlock()

	if answer.block {
		<-ctx.Done()
	}
	if answer.gate != nil {
		select {
		case <-answer.gate:
		case <-ctx.Done():
		}
	}
	// A context that ran out fails the call, as it does on the real client.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	return answer.hooks, answer.err
}

func (f *fakeHookLister) WatchPlexdHooks(ctx context.Context, _ string) (<-chan kubernetes.PlexdHookEvent, error) {
	f.mu.Lock()
	f.openCalls++
	f.watchDeadline, _ = ctx.Deadline()
	if len(f.watches) == 0 {
		f.mu.Unlock()
		<-ctx.Done()
		return nil, fmt.Errorf("watch: %w", ctx.Err())
	}
	w := f.watches[0]
	f.watches = f.watches[1:]
	f.mu.Unlock()

	if w.gate != nil {
		select {
		case <-w.gate:
		case <-ctx.Done():
			return nil, fmt.Errorf("watch: %w", ctx.Err())
		}
	}
	if w.holdUntilEnd {
		<-ctx.Done()
	}
	if w.err != nil {
		return nil, w.err
	}
	if w.closeOnEnd {
		go func() {
			<-ctx.Done()
			close(w.events)
		}()
	}
	return w.events, nil
}

// counts returns how many lists and opens have started.
func (f *fakeHookLister) counts() (lists, opens int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listCalls, f.openCalls
}

// waitOpens blocks until open n has started. When n is the parked open, every
// cycle before it is over.
func (f *fakeHookLister) waitOpens(t *testing.T, n int) {
	t.Helper()
	waitPlexdHookCondition(t, fmt.Sprintf("open %d", n), func() bool {
		_, opens := f.counts()
		return opens >= n
	})
}

// waitLists blocks until list n has started.
func (f *fakeHookLister) waitLists(t *testing.T, n int) {
	t.Helper()
	waitPlexdHookCondition(t, fmt.Sprintf("list %d", n), func() bool {
		lists, _ := f.counts()
		return lists >= n
	})
}

func waitPlexdHookCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(plexdHookTestWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// inventoryRun is one run goroutine and what it reported.
type inventoryRun struct {
	t        *testing.T
	notifies atomic.Int32
	cancel   context.CancelFunc
	done     chan struct{}
}

// startInventory calls run on a goroutine of its own. The cleanup stops it, so no
// test leaves one behind.
func startInventory(t *testing.T, inv *plexdHookInventory) *inventoryRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &inventoryRun{t: t, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		inv.run(ctx, func() { r.notifies.Add(1) })
	}()
	t.Cleanup(r.stop)
	return r
}

// stop cancels run and waits for it to return.
func (r *inventoryRun) stop() {
	r.t.Helper()
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(plexdHookTestWait):
		r.t.Error("run did not return after its context was cancelled")
	}
}

var plexdHookTestEnv = &kubernetes.KubernetesEnvironment{InCluster: true, Namespace: "plexd-system"}

// newShortInventory builds an inventory through the constructor, boot list
// included, with its delays shortened. No stream in such a test lives long enough
// to count as stable, unless the test says otherwise.
func newShortInventory(t *testing.T, lister *fakeHookLister, rec *recordingHandler) *plexdHookInventory {
	t.Helper()
	inv := newPlexdHookInventory(context.Background(), plexdHookTestEnv,
		func(*kubernetes.KubernetesEnvironment) (plexdHookLister, error) { return lister, nil }, slog.New(rec))
	inv.listTimeout = plexdHookTestWait
	inv.watchTimeout = time.Hour
	inv.coalesce = time.Millisecond
	inv.stableStream = time.Hour
	inv.backoffMin = time.Millisecond
	inv.backoffMax = 8 * time.Millisecond
	inv.jitter = func(d time.Duration) time.Duration { return d }
	return inv
}

// backoffRecorder keeps each backoff the way it was before jitter.
type backoffRecorder struct {
	mu     sync.Mutex
	delays []time.Duration
}

// recordBackoff replaces inv's jitter to record every nominal backoff and to wait
// only a microsecond, so a test can assert the real delays without sitting them
// out. The watch timeout passes through unrecorded.
func recordBackoff(inv *plexdHookInventory) *backoffRecorder {
	r := &backoffRecorder{}
	watchTimeout := inv.watchTimeout
	inv.jitter = func(d time.Duration) time.Duration {
		if d == watchTimeout {
			return d
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.delays = append(r.delays, d)
		return time.Microsecond
	}
	return r
}

func (r *backoffRecorder) recorded() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.delays...)
}

// pinnedPlexdHook is a resource the conversion reports.
func pinnedPlexdHook(name, resourceVersion string) kubernetes.PlexdHook {
	return kubernetes.PlexdHook{
		Name:            name,
		ResourceVersion: resourceVersion,
		Spec:            kubernetes.PlexdHookSpec{JobTemplate: &kubernetes.PlexdHookJobTemplate{Image: "busybox@" + plexdHookTestDigest}},
	}
}

// reportedPlexdHooks is what the conversion makes of pinnedPlexdHook resources.
func reportedPlexdHooks(names ...string) []api.DiscoveredPlexdHook {
	out := make([]api.DiscoveredPlexdHook, 0, len(names))
	for _, name := range names {
		out = append(out, api.DiscoveredPlexdHook{Name: name, ImageDigest: plexdHookTestDigest, Sandbox: true})
	}
	return out
}

// closedStream is a stream that ended before anyone read from it.
func closedStream() chan kubernetes.PlexdHookEvent {
	events := make(chan kubernetes.PlexdHookEvent)
	close(events)
	return events
}

// streamWithEvent is a stream that holds one event and stays open.
func streamWithEvent() chan kubernetes.PlexdHookEvent {
	events := make(chan kubernetes.PlexdHookEvent, 1)
	events <- kubernetes.PlexdHookEvent{Type: "MODIFIED"}
	return events
}

// closedStreamWithEvent is a stream that holds one event and then ends.
func closedStreamWithEvent() chan kubernetes.PlexdHookEvent {
	events := streamWithEvent()
	close(events)
	return events
}

func sendPlexdHookEvent(t *testing.T, events chan<- kubernetes.PlexdHookEvent) {
	t.Helper()
	select {
	case events <- kubernetes.PlexdHookEvent{Type: "MODIFIED"}:
	case <-time.After(plexdHookTestWait):
		t.Fatal("nothing received the event")
	}
}

// Discovery never blocks or fails boot. Outside a cluster it says nothing;
// inside one, every way it can fail is one warning and no plexd_hooks.
func TestNewPlexdHookInventory(t *testing.T) {
	inCluster := &kubernetes.KubernetesEnvironment{InCluster: true, Namespace: "plexd-system\n", ServiceAccountToken: "/token"}
	listed := []kubernetes.PlexdHook{pinnedPlexdHook("nightly-backup", "1")}
	reported := reportedPlexdHooks("nightly-backup")
	transportErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}

	for _, tc := range []struct {
		name            string
		env             *kubernetes.KubernetesEnvironment
		constructErr    error
		listErr         error
		want            []api.DiscoveredPlexdHook
		wantWarnings    int
		wantConstructed bool
		wantListed      bool
	}{
		{name: "no environment"},
		{name: "not in cluster", env: &kubernetes.KubernetesEnvironment{}},
		{name: "blank namespace", env: &kubernetes.KubernetesEnvironment{InCluster: true, Namespace: " \n"}, wantWarnings: 1},
		{name: "lister construction fails", env: inCluster, constructErr: errors.New("no cluster CA"), wantWarnings: 1, wantConstructed: true},
		{name: "missing RBAC", env: inCluster, listErr: fmt.Errorf("list: %w", kubernetes.ErrUnauthorized), wantWarnings: 1, wantConstructed: true, wantListed: true},
		{name: "CRD not installed", env: inCluster, listErr: fmt.Errorf("list: %w", kubernetes.ErrNotFound), wantWarnings: 1, wantConstructed: true, wantListed: true},
		{name: "list times out", env: inCluster, listErr: fmt.Errorf("list: %w", context.DeadlineExceeded), wantWarnings: 1, wantConstructed: true, wantListed: true},
		{name: "transport error", env: inCluster, listErr: fmt.Errorf("list: %w", transportErr), wantWarnings: 1, wantConstructed: true, wantListed: true},
		{name: "listed", env: inCluster, want: reported, wantConstructed: true, wantListed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The fake returns hooks even alongside an error, so a caller that
			// used them anyway would show here.
			lister := &fakeHookLister{hooks: listed, err: tc.listErr}
			constructed := false
			newLister := func(*kubernetes.KubernetesEnvironment) (plexdHookLister, error) {
				constructed = true
				if tc.constructErr != nil {
					return nil, tc.constructErr
				}
				return lister, nil
			}

			rec := newRecordingHandler()
			start := time.Now()
			inv := newPlexdHookInventory(context.Background(), tc.env, newLister, slog.New(rec))
			end := time.Now()

			if got := inv.snapshot(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("snapshot = %+v, want %+v", got, tc.want)
			}
			if n := rec.countAt(slog.LevelWarn); n != tc.wantWarnings {
				t.Errorf("warnings = %d, want %d", n, tc.wantWarnings)
			}
			if constructed != tc.wantConstructed {
				t.Errorf("lister constructed = %v, want %v", constructed, tc.wantConstructed)
			}
			if listedNow := lister.namespace != ""; listedNow != tc.wantListed {
				t.Fatalf("list called = %v, want %v", listedNow, tc.wantListed)
			}
			if !tc.wantListed {
				return
			}
			if lister.namespace != "plexd-system" {
				t.Errorf("listed namespace %q, want the trimmed %q", lister.namespace, "plexd-system")
			}
			// The list runs under its own 10-second budget.
			if !lister.hasDeadline ||
				lister.deadline.Before(start.Add(plexdHookDiscoveryTimeout)) ||
				lister.deadline.After(end.Add(plexdHookDiscoveryTimeout)) {
				t.Errorf("list deadline = %v (set %v), want %v after the call", lister.deadline, lister.hasDeadline, plexdHookDiscoveryTimeout)
			}
		})
	}
}

// Tests shorten these fields, so nothing else would catch a wrong constant.
func TestNewPlexdHookInventory_PinsTheTiming(t *testing.T) {
	inv := newPlexdHookInventory(context.Background(), nil, nil, discardLogger())

	for _, tc := range []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"list timeout", inv.listTimeout, 10 * time.Second},
		{"watch timeout", inv.watchTimeout, 10 * time.Minute},
		{"coalesce", inv.coalesce, 1 * time.Second},
		{"stable stream", inv.stableStream, 1 * time.Minute},
		{"backoff min", inv.backoffMin, 5 * time.Second},
		{"backoff max", inv.backoffMax, 5 * time.Minute},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
	if reflect.ValueOf(inv.jitter).Pointer() != reflect.ValueOf(agent.Jitter).Pointer() {
		t.Error("jitter is not agent.Jitter")
	}
}

// With no lister there is nothing to watch, so run must neither call an API nor
// hold a goroutine.
func TestPlexdHookInventory_RunReturnsAtOnceWithoutALister(t *testing.T) {
	for _, tc := range []struct {
		name         string
		env          *kubernetes.KubernetesEnvironment
		constructErr error
	}{
		{name: "no environment"},
		{name: "outside a cluster", env: &kubernetes.KubernetesEnvironment{}},
		{name: "empty namespace", env: &kubernetes.KubernetesEnvironment{InCluster: true, Namespace: " \n"}},
		{name: "no lister", env: plexdHookTestEnv, constructErr: errors.New("no cluster CA")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lister := &fakeHookLister{}
			inv := newPlexdHookInventory(context.Background(), tc.env, func(*kubernetes.KubernetesEnvironment) (plexdHookLister, error) {
				if tc.constructErr != nil {
					return nil, tc.constructErr
				}
				return lister, nil
			}, discardLogger())

			run := startInventory(t, inv)
			select {
			case <-run.done:
			case <-time.After(plexdHookTestWait):
				t.Fatal("run did not return")
			}

			if lists, opens := lister.counts(); lists != 0 || opens != 0 {
				t.Errorf("lists = %d, opens = %d, want no API call", lists, opens)
			}
			if n := run.notifies.Load(); n != 0 {
				t.Errorf("notify called %d times, want 0", n)
			}
		})
	}
}

// A change reaches the snapshot and the reporter after the coalescing delay. The
// loop polls snapshot while run writes it, which is the reporter's access pattern
// and what the race detector needs to see. The bound is a lower one, so load
// cannot fail it; the upper bound of the "within 2 seconds" criterion is the
// 1-second constant pinned above.
func TestPlexdHookInventory_EventReplacesTheSnapshotAndNotifies(t *testing.T) {
	events := make(chan kubernetes.PlexdHookEvent)
	lister := &fakeHookLister{
		lists: []fakeHookList{
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1"), pinnedPlexdHook("b", "1")}},
		},
		watches: []fakeHookWatch{{events: events}},
	}
	inv := newShortInventory(t, lister, newRecordingHandler())
	inv.coalesce = 20 * time.Millisecond
	run := startInventory(t, inv)

	sent := time.Now()
	sendPlexdHookEvent(t, events)

	want := reportedPlexdHooks("a", "b")
	waitPlexdHookCondition(t, "the new snapshot", func() bool {
		return reflect.DeepEqual(inv.snapshot(), want)
	})
	waitPlexdHookCondition(t, "notify", func() bool { return run.notifies.Load() == 1 })
	if elapsed := time.Since(sent); elapsed < inv.coalesce {
		t.Errorf("list ran %v after the event, want at least the %v coalescing delay", elapsed, inv.coalesce)
	}
}

// An absent key means "none" to the control plane, so the snapshot has to go to
// nil, not to an empty slice, for a deletion to clear the row.
func TestPlexdHookInventory_LastDeletionClearsTheSnapshot(t *testing.T) {
	events := make(chan kubernetes.PlexdHookEvent)
	lister := &fakeHookLister{
		lists: []fakeHookList{
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
			{hooks: []kubernetes.PlexdHook{}},
		},
		watches: []fakeHookWatch{{events: events}},
	}
	inv := newShortInventory(t, lister, newRecordingHandler())
	if got, want := inv.snapshot(), reportedPlexdHooks("a"); !reflect.DeepEqual(got, want) {
		t.Fatalf("boot snapshot = %+v, want %+v", got, want)
	}
	run := startInventory(t, inv)

	sendPlexdHookEvent(t, events)
	waitPlexdHookCondition(t, "notify", func() bool { return run.notifies.Load() == 1 })

	got := inv.snapshot()
	if got != nil {
		t.Fatalf("snapshot = %#v, want nil", got)
	}
	raw, err := json.Marshal(api.CapabilityManifestRequest{BinaryVersion: "v1", PlexdHooks: got})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"plexd_hooks"`) {
		t.Errorf("manifest still carries the key: %s", raw)
	}
}

// A failed boot list leaves the manifest without plexd_hooks, and it stays that
// way through failed lists until one succeeds.
func TestPlexdHookInventory_FailedBootListStaysNilUntilAListSucceeds(t *testing.T) {
	listErr := fmt.Errorf("list: %w", kubernetes.ErrNotFound)
	gate := make(chan struct{})
	lister := &fakeHookLister{
		lists: []fakeHookList{
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}, err: listErr},
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}, err: listErr},
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
		},
		watches: []fakeHookWatch{
			{err: fmt.Errorf("watch: %w", kubernetes.ErrNotFound)},
			{events: make(chan kubernetes.PlexdHookEvent), gate: gate},
		},
	}
	inv := newShortInventory(t, lister, newRecordingHandler())
	if got := inv.snapshot(); got != nil {
		t.Fatalf("snapshot after the failed boot list = %+v, want nil", got)
	}
	run := startInventory(t, inv)

	// The second open is held, so the failed cycle before it is over and the
	// list that succeeds has not started.
	lister.waitOpens(t, 2)
	if got := inv.snapshot(); got != nil {
		t.Errorf("snapshot after a failed list = %+v, want nil", got)
	}
	if n := run.notifies.Load(); n != 0 {
		t.Errorf("notify called %d times after a failed list, want 0", n)
	}

	close(gate)
	want := reportedPlexdHooks("a")
	waitPlexdHookCondition(t, "the first snapshot", func() bool {
		return reflect.DeepEqual(inv.snapshot(), want)
	})
	waitPlexdHookCondition(t, "notify", func() bool { return run.notifies.Load() == 1 })
}

// Sending an absent key would erase every PlexdHook from the control plane's row
// on a transient failure, so a failed list changes nothing and backs off.
func TestPlexdHookInventory_FailedListKeepsTheSnapshot(t *testing.T) {
	boot := []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"deadline exceeded", fmt.Errorf("list: %w", context.DeadlineExceeded)},
		{"status 500", errors.New(`kubernetes: list plexdhooks in "plexd-system": unexpected status 500`)},
	} {
		for _, when := range []struct {
			name     string
			lists    []fakeHookList
			events   chan kubernetes.PlexdHookEvent
			coalesce time.Duration
		}{
			{"after an open", []fakeHookList{{hooks: boot}, {err: tc.err}}, make(chan kubernetes.PlexdHookEvent), 0},
			{"after an event", []fakeHookList{{hooks: boot}, {hooks: boot}, {err: tc.err}}, streamWithEvent(), 0},
			// The long coalesce keeps the timer out of it, so the close is what
			// runs the list.
			{"at stream close", []fakeHookList{{hooks: boot}, {hooks: boot}, {err: tc.err}}, closedStreamWithEvent(), time.Hour},
		} {
			t.Run(tc.name+"/"+when.name, func(t *testing.T) {
				lister := &fakeHookLister{lists: when.lists, watches: []fakeHookWatch{{events: when.events}}}
				rec := newRecordingHandler()
				inv := newShortInventory(t, lister, rec)
				if when.coalesce != 0 {
					inv.coalesce = when.coalesce
				}
				backoff := recordBackoff(inv)
				run := startInventory(t, inv)

				lister.waitOpens(t, 2)

				if got, want := inv.snapshot(), reportedPlexdHooks("a"); !reflect.DeepEqual(got, want) {
					t.Errorf("snapshot = %+v, want %+v", got, want)
				}
				if n := run.notifies.Load(); n != 0 {
					t.Errorf("notify called %d times, want 0", n)
				}
				if got, want := backoff.recorded(), []time.Duration{inv.backoffMin}; !reflect.DeepEqual(got, want) {
					t.Errorf("backoff = %v, want %v", got, want)
				}
				attrs := rec.attrsOf(slog.LevelWarn, plexdHookWatchFailedMsg)
				if attrs == nil {
					t.Fatalf("no %q warning", plexdHookWatchFailedMsg)
				}
				if attrs["error"] != tc.err.Error() {
					t.Errorf("error attr = %q, want %q", attrs["error"], tc.err)
				}
				if attrs["retry_in"] != time.Microsecond.String() {
					t.Errorf("retry_in attr = %q, want the jittered %v", attrs["retry_in"], time.Microsecond)
				}
			})
		}
	}
}

// One Warn when an outage starts, Debug while it lasts, one Info when it ends,
// and the same again for the next outage. The boot list succeeds here, so every
// warning belongs to run.
func TestPlexdHookInventory_OneWarnPerOutage(t *testing.T) {
	boot := fakeHookList{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"missing CRD", fmt.Errorf("list: %w", kubernetes.ErrNotFound)},
		{"timeout", fmt.Errorf("list: %w", context.DeadlineExceeded)},
		{"status 500", errors.New("unexpected status 500")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failed := fakeHookList{err: tc.err}
			lister := &fakeHookLister{
				lists: []fakeHookList{boot, failed, failed, failed, boot, failed, failed, boot},
				watches: []fakeHookWatch{
					{err: tc.err},
					{err: tc.err},
					{err: tc.err},
					{events: closedStream()},
					{err: tc.err},
					{err: tc.err},
					{events: closedStream()},
				},
			}
			rec := newRecordingHandler()
			inv := newShortInventory(t, lister, rec)
			run := startInventory(t, inv)

			lister.waitOpens(t, 8)
			run.stop()

			if n := run.notifies.Load(); n != 0 {
				t.Errorf("notify called %d times for lists equal to the boot list, want 0", n)
			}
			if n := rec.count(slog.LevelWarn, plexdHookWatchFailedMsg); n != 2 {
				t.Errorf("Warn count = %d, want one per outage, 2", n)
			}
			if n := rec.count(slog.LevelInfo, plexdHookWatchRestoredMsg); n != 2 {
				t.Errorf("Info count = %d, want one per recovery, 2", n)
			}
			if n := rec.count(slog.LevelDebug, plexdHookWatchFailedMsg); n != 3 {
				t.Errorf("Debug count = %d, want the 3 repeats", n)
			}
		})
	}
}

// Opens that succeed do not end an outage while their lists fail: only an open
// and its list together do. Without that, each cycle would log a Warn and an Info.
func TestPlexdHookInventory_GoodOpensDoNotEndAnOutageOfFailedLists(t *testing.T) {
	boot := fakeHookList{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}}
	failed := fakeHookList{err: errors.New("unexpected status 500")}
	lister := &fakeHookLister{
		lists:   []fakeHookList{boot, failed, failed, failed},
		watches: []fakeHookWatch{{events: closedStream()}, {events: closedStream()}, {events: closedStream()}},
	}
	rec := newRecordingHandler()
	inv := newShortInventory(t, lister, rec)
	run := startInventory(t, inv)

	lister.waitOpens(t, 4)
	run.stop()

	if n := rec.count(slog.LevelWarn, plexdHookWatchFailedMsg); n != 1 {
		t.Errorf("Warn count = %d, want 1 for the one outage", n)
	}
	if n := rec.count(slog.LevelInfo, plexdHookWatchRestoredMsg); n != 0 {
		t.Errorf("Info count = %d, want 0: no list succeeded", n)
	}
	if n := rec.count(slog.LevelDebug, plexdHookWatchFailedMsg); n != 2 {
		t.Errorf("Debug count = %d, want the 2 repeats", n)
	}
}

// A cluster with no CRD fails at boot and on every cycle after it, for as long as
// the pod lives, and that is one warning in total.
func TestPlexdHookInventory_MissingCRDWarnsOnceAcrossBootAndRun(t *testing.T) {
	notFound := fmt.Errorf("kubernetes: %w", kubernetes.ErrNotFound)
	lister := &fakeHookLister{
		err:     notFound,
		watches: []fakeHookWatch{{err: notFound}, {err: notFound}, {err: notFound}, {err: notFound}},
	}
	rec := newRecordingHandler()
	inv := newShortInventory(t, lister, rec)
	run := startInventory(t, inv)

	lister.waitOpens(t, 5)
	run.stop()

	if n := rec.countAt(slog.LevelWarn); n != 1 {
		t.Errorf("warnings = %d, want 1", n)
	}
	if n := rec.count(slog.LevelWarn, plexdHookDiscoveryFailMsg); n != 1 {
		t.Errorf("%q = %d, want the boot warning alone", plexdHookDiscoveryFailMsg, n)
	}
	if n := rec.count(slog.LevelDebug, plexdHookWatchFailedMsg); n != 4 {
		t.Errorf("Debug count = %d, want one per cycle, 4", n)
	}
	if got := inv.snapshot(); got != nil {
		t.Errorf("snapshot = %+v, want nil", got)
	}
}

// The CRD arriving after boot ends the outage the boot list began.
func TestPlexdHookInventory_RecoveryFromAFailedBootLogsOneInfo(t *testing.T) {
	notFound := fmt.Errorf("kubernetes: %w", kubernetes.ErrNotFound)
	lister := &fakeHookLister{
		lists: []fakeHookList{
			{err: notFound},
			{err: notFound},
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
		},
		watches: []fakeHookWatch{{err: notFound}, {events: closedStream()}, {events: closedStream()}},
	}
	rec := newRecordingHandler()
	inv := newShortInventory(t, lister, rec)
	run := startInventory(t, inv)

	lister.waitOpens(t, 4)
	run.stop()

	if n := rec.count(slog.LevelInfo, plexdHookWatchRestoredMsg); n != 1 {
		t.Errorf("Info count = %d, want 1", n)
	}
	if n := rec.countAt(slog.LevelWarn); n != 1 {
		t.Errorf("warnings = %d, want the boot warning alone", n)
	}
	if got, want := inv.snapshot(), reportedPlexdHooks("a"); !reflect.DeepEqual(got, want) {
		t.Errorf("snapshot = %+v, want %+v", got, want)
	}
	if n := run.notifies.Load(); n != 1 {
		t.Errorf("notify called %d times, want 1", n)
	}
}

// A role that grants list and not watch is degraded for as long as it runs: the
// list it gets is no recovery, so it warns once, never logs restored, and the
// warning names the failed open rather than the list that worked.
func TestPlexdHookInventory_FailedOpenWithAGoodListStaysDegraded(t *testing.T) {
	denied := fmt.Errorf("watch: %w", kubernetes.ErrUnauthorized)
	lister := &fakeHookLister{
		hooks:   []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")},
		watches: []fakeHookWatch{{err: denied}, {err: denied}, {err: denied}},
	}
	rec := newRecordingHandler()
	inv := newShortInventory(t, lister, rec)
	run := startInventory(t, inv)

	lister.waitOpens(t, 4)
	lists, _ := lister.counts()
	run.stop()

	if n := rec.count(slog.LevelWarn, plexdHookWatchFailedMsg); n != 1 {
		t.Errorf("Warn count = %d, want 1", n)
	}
	if n := rec.count(slog.LevelInfo, plexdHookWatchRestoredMsg); n != 0 {
		t.Errorf("Info count = %d, want 0", n)
	}
	if lists-1 != 3 {
		t.Errorf("lists after boot = %d, want one per cycle, 3", lists-1)
	}
	if attrs := rec.attrsOf(slog.LevelWarn, plexdHookWatchFailedMsg); attrs["error"] != denied.Error() {
		t.Errorf("error attr = %q, want the open's %q", attrs["error"], denied)
	}
}

// With both calls failing, the warning names the open: it is the one that says why
// no watch is running.
func TestPlexdHookInventory_FailedOpenAndListReportTheOpen(t *testing.T) {
	denied := fmt.Errorf("watch: %w", kubernetes.ErrUnauthorized)
	lister := &fakeHookLister{
		lists: []fakeHookList{
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
			{err: errors.New("unexpected status 500")},
		},
		watches: []fakeHookWatch{{err: denied}},
	}
	rec := newRecordingHandler()
	inv := newShortInventory(t, lister, rec)
	startInventory(t, inv)

	lister.waitOpens(t, 2)

	if attrs := rec.attrsOf(slog.LevelWarn, plexdHookWatchFailedMsg); attrs["error"] != denied.Error() {
		t.Errorf("error attr = %q, want the open's %q", attrs["error"], denied)
	}
}

// The real delays, read from the recorder rather than sat out: such a role settles
// at one list every 5 minutes.
func TestPlexdHookInventory_ListsEveryFiveMinutesWithoutWatch(t *testing.T) {
	denied := fmt.Errorf("watch: %w", kubernetes.ErrUnauthorized)
	const cycles = 9
	watches := make([]fakeHookWatch, cycles)
	for i := range watches {
		watches[i].err = denied
	}
	lister := &fakeHookLister{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}, watches: watches}
	inv := newShortInventory(t, lister, newRecordingHandler())
	inv.backoffMin = plexdHookBackoffMin
	inv.backoffMax = plexdHookBackoffMax
	backoff := recordBackoff(inv)
	startInventory(t, inv)

	lister.waitOpens(t, cycles+1)

	want := []time.Duration{
		5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 300 * time.Second, 300 * time.Second, 300 * time.Second,
	}
	if got := backoff.recorded(); !reflect.DeepEqual(got, want) {
		t.Errorf("backoff = %v, want %v", got, want)
	}
	if lists, _ := lister.counts(); lists-1 != cycles {
		t.Errorf("lists after boot = %d, want one per cycle, %d", lists-1, cycles)
	}
}

// A role with list and no watch has only this list to learn of a change from, so
// what it returns has to reach the snapshot and the reporter like any other list.
func TestPlexdHookInventory_FailedOpenListReachesTheSnapshot(t *testing.T) {
	a, b := pinnedPlexdHook("a", "1"), pinnedPlexdHook("b", "1")
	lister := &fakeHookLister{
		lists:   []fakeHookList{{hooks: []kubernetes.PlexdHook{a}}, {hooks: []kubernetes.PlexdHook{a, b}}},
		watches: []fakeHookWatch{{err: fmt.Errorf("watch: %w", kubernetes.ErrUnauthorized)}},
	}
	inv := newShortInventory(t, lister, newRecordingHandler())
	run := startInventory(t, inv)

	lister.waitOpens(t, 2)

	if got, want := inv.snapshot(), reportedPlexdHooks("a", "b"); !reflect.DeepEqual(got, want) {
		t.Errorf("snapshot = %+v, want %+v", got, want)
	}
	if n := run.notifies.Load(); n != 1 {
		t.Errorf("notify called %d times, want 1", n)
	}
}

// Nothing delivers an event for a resource deleted while no watch ran. The list
// after the next open is what notices, and no event is sent here.
func TestPlexdHookInventory_ListAfterAnOpenCatchesADeletion(t *testing.T) {
	both := []kubernetes.PlexdHook{pinnedPlexdHook("a", "1"), pinnedPlexdHook("b", "1")}
	lister := &fakeHookLister{
		lists: []fakeHookList{
			{hooks: both},
			{hooks: both},
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
		},
		watches: []fakeHookWatch{
			{err: errors.New("connection refused")},
			{events: make(chan kubernetes.PlexdHookEvent)},
		},
	}
	inv := newShortInventory(t, lister, newRecordingHandler())
	if got, want := inv.snapshot(), reportedPlexdHooks("a", "b"); !reflect.DeepEqual(got, want) {
		t.Fatalf("boot snapshot = %+v, want %+v", got, want)
	}
	run := startInventory(t, inv)

	want := reportedPlexdHooks("a")
	waitPlexdHookCondition(t, "the deletion", func() bool {
		return reflect.DeepEqual(inv.snapshot(), want)
	})
	waitPlexdHookCondition(t, "notify", func() bool { return run.notifies.Load() == 1 })
}

// A healthy pod re-lists the same resources twice per watch timeout. The omission
// warning is the sign the conversion ran, and it must not repeat for that. The
// lists come back in a different order, which the API server does not promise to
// keep, and that is no change either.
func TestPlexdHookInventory_SameVersionsSkipConversionAndNotify(t *testing.T) {
	unpinned := kubernetes.PlexdHook{
		Name:            "tag-pinned",
		ResourceVersion: "1",
		Spec:            kubernetes.PlexdHookSpec{JobTemplate: &kubernetes.PlexdHookJobTemplate{Image: "alpine:3.19"}},
	}
	changed := unpinned
	changed.ResourceVersion = "2"
	pinned := pinnedPlexdHook("a", "1")

	events := make(chan kubernetes.PlexdHookEvent)
	gate := make(chan struct{})
	lister := &fakeHookLister{
		lists: []fakeHookList{
			{hooks: []kubernetes.PlexdHook{pinned, unpinned}},
			{hooks: []kubernetes.PlexdHook{unpinned, pinned}},
			{hooks: []kubernetes.PlexdHook{pinned, unpinned}},
			{hooks: []kubernetes.PlexdHook{pinned, changed}, gate: gate},
		},
		watches: []fakeHookWatch{{events: events}},
	}
	rec := newRecordingHandler()
	inv := newShortInventory(t, lister, rec)
	run := startInventory(t, inv)

	sendPlexdHookEvent(t, events)
	lister.waitLists(t, 3)
	// The next event is taken only after the list above returned, so the list
	// and whatever it logged and notified are over. The list it leads to waits
	// at its gate until the assertions below have run.
	sendPlexdHookEvent(t, events)
	if n := run.notifies.Load(); n != 0 {
		t.Errorf("notify called %d times for unchanged lists, want 0", n)
	}
	if n := rec.count(slog.LevelWarn, plexdHookOmittedMsg); n != 1 {
		t.Errorf("omission warnings = %d, want the boot list's alone", n)
	}

	// Control: a new resourceVersion does convert and notify.
	close(gate)
	waitPlexdHookCondition(t, "notify", func() bool { return run.notifies.Load() == 1 })
	if n := rec.count(slog.LevelWarn, plexdHookOmittedMsg); n != 2 {
		t.Errorf("omission warnings = %d, want 2 after the change", n)
	}
}

// An open replays every resource as ADDED. The timer is an hour long here, so only
// the end of the stream can produce the list: each frame has to be received while
// it runs, and the 50 of them come to one list however they are scheduled.
func TestPlexdHookInventory_BurstCostsOneList(t *testing.T) {
	events := make(chan kubernetes.PlexdHookEvent)
	lister := &fakeHookLister{
		lists: []fakeHookList{
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "2")}},
		},
		watches: []fakeHookWatch{{events: events}},
	}
	inv := newShortInventory(t, lister, newRecordingHandler())
	inv.coalesce = time.Hour
	run := startInventory(t, inv)

	for range 50 {
		sendPlexdHookEvent(t, events)
	}
	if lists, _ := lister.counts(); lists != 2 {
		t.Fatalf("lists = %d during the burst, want the boot list and the one after the open", lists)
	}
	close(events)

	lister.waitOpens(t, 2)
	if lists, _ := lister.counts(); lists != 3 {
		t.Errorf("lists = %d, want the boot list, the one after the open, and one for the burst", lists)
	}
	if n := run.notifies.Load(); n != 1 {
		t.Errorf("notify called %d times, want 1", n)
	}
}

// The timer starts once and is not restarted, so events that never stop cannot
// hold the list off.
func TestPlexdHookInventory_SteadyEventsDoNotPostponeTheList(t *testing.T) {
	events := make(chan kubernetes.PlexdHookEvent)
	lister := &fakeHookLister{
		hooks:   []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")},
		watches: []fakeHookWatch{{events: events}},
	}
	inv := newShortInventory(t, lister, newRecordingHandler())
	inv.coalesce = 5 * time.Millisecond
	startInventory(t, inv)

	stop := make(chan struct{})
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		for {
			select {
			case events <- kubernetes.PlexdHookEvent{Type: "MODIFIED"}:
			case <-stop:
				return
			}
		}
	}()
	lister.waitLists(t, 3)
	close(stop)
	<-senderDone
}

// Lists run on run's context. On an expired watch context they would fail, and a
// healthy pod would raise an outage every 10 minutes. The open here returns only
// once its context has ended, so both the list after the open and the list that
// finishes the stream meet that case, and the fake fails a list whose context ended.
func TestPlexdHookInventory_ListOutlivesTheWatchContext(t *testing.T) {
	lister := &fakeHookLister{
		lists: []fakeHookList{
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}},
			{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "2")}},
		},
		watches: []fakeHookWatch{{events: streamWithEvent(), closeOnEnd: true, holdUntilEnd: true}},
	}
	rec := newRecordingHandler()
	inv := newShortInventory(t, lister, rec)
	inv.coalesce = time.Hour

	// Only the first watch times out, so the parked open stays parked.
	opens := 0
	inv.jitter = func(d time.Duration) time.Duration {
		if d != inv.watchTimeout {
			return d
		}
		if opens++; opens == 1 {
			return time.Millisecond
		}
		return d
	}
	run := startInventory(t, inv)

	lister.waitOpens(t, 2)
	run.stop()

	if n := rec.countAt(slog.LevelWarn); n != 0 {
		t.Errorf("warnings = %d, want 0", n)
	}
	if n := run.notifies.Load(); n != 1 {
		t.Errorf("notify called %d times, want the one list finishing the stream", n)
	}
}

// Both budgets hold after boot: every list has its own deadline, and each watch
// has the jittered timeout that ends a silently dead stream.
func TestPlexdHookInventory_RunAppliesTheListAndWatchBudgets(t *testing.T) {
	// The stream stays open, so no second open replaces the deadline it recorded.
	lister := &fakeHookLister{watches: []fakeHookWatch{{events: make(chan kubernetes.PlexdHookEvent)}}}
	inv := newShortInventory(t, lister, newRecordingHandler())
	inv.listTimeout = time.Hour
	inv.watchTimeout = 3 * time.Hour
	inv.jitter = func(d time.Duration) time.Duration {
		if d == inv.watchTimeout {
			return 2 * d
		}
		return d
	}

	start := time.Now()
	run := startInventory(t, inv)
	lister.waitLists(t, 2)
	end := time.Now()

	lister.mu.Lock()
	deadline, hasDeadline, watchDeadline := lister.deadline, lister.hasDeadline, lister.watchDeadline
	lister.mu.Unlock()

	if !hasDeadline || deadline.Before(start.Add(inv.listTimeout)) || deadline.After(end.Add(inv.listTimeout)) {
		t.Errorf("list deadline = %v (set %v), want %v after the call", deadline, hasDeadline, inv.listTimeout)
	}
	if want := 2 * inv.watchTimeout; watchDeadline.Before(start.Add(want)) || watchDeadline.After(end.Add(want)) {
		t.Errorf("watch deadline = %v, want the jittered %v after the open", watchDeadline, want)
	}
	run.stop()
}

// Shutdown cancels a list in flight. That is no failure, so it starts no outage
// and logs nothing.
func TestPlexdHookInventory_CancelledListLogsNothing(t *testing.T) {
	boot := fakeHookList{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}}
	for _, tc := range []struct {
		name  string
		lists []fakeHookList
		watch fakeHookWatch
		// listed is the list the cancellation lands on.
		listed int
	}{
		{
			name:   "list after an open",
			lists:  []fakeHookList{boot, {block: true}},
			watch:  fakeHookWatch{events: make(chan kubernetes.PlexdHookEvent)},
			listed: 2,
		},
		{
			name:   "list after a failed open",
			lists:  []fakeHookList{boot, {block: true}},
			watch:  fakeHookWatch{err: errors.New("connection refused")},
			listed: 2,
		},
		{
			name:   "list after an event",
			lists:  []fakeHookList{boot, boot, {block: true}},
			watch:  fakeHookWatch{events: streamWithEvent()},
			listed: 3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lister := &fakeHookLister{lists: tc.lists, watches: []fakeHookWatch{tc.watch}}
			rec := newRecordingHandler()
			run := startInventory(t, newShortInventory(t, lister, rec))

			lister.waitLists(t, tc.listed)
			run.stop()

			if n := rec.countAt(slog.LevelWarn); n != 0 {
				t.Errorf("warnings = %d, want 0", n)
			}
			if n := rec.count(slog.LevelDebug, plexdHookWatchFailedMsg); n != 0 {
				t.Errorf("Debug failures = %d, want 0", n)
			}
		})
	}
}

// A backoff can run for minutes, and shutdown does not wait for it.
func TestPlexdHookInventory_CancelEndsTheBackoff(t *testing.T) {
	lister := &fakeHookLister{watches: []fakeHookWatch{{err: errors.New("connection refused")}}}
	rec := newRecordingHandler()
	inv := newShortInventory(t, lister, rec)
	inv.backoffMin = time.Hour
	inv.backoffMax = time.Hour
	run := startInventory(t, inv)

	waitPlexdHookCondition(t, "the failure", func() bool {
		return rec.count(slog.LevelWarn, plexdHookWatchFailedMsg) == 1
	})
	run.stop()
}

// A stream that lived its minute resets the backoff and reopens at once, with no
// wait. A stable threshold of zero makes every stream count, whatever the clock
// does, so the delays are exact: without the reset the last one would be 4x.
func TestPlexdHookInventory_BackoffResetsAfterAStreamLived(t *testing.T) {
	refused := errors.New("connection refused")
	lister := &fakeHookLister{
		watches: []fakeHookWatch{{err: refused}, {err: refused}, {events: closedStream()}, {err: refused}},
	}
	inv := newShortInventory(t, lister, newRecordingHandler())
	inv.stableStream = 0
	d := inv.backoffMin
	backoff := recordBackoff(inv)
	startInventory(t, inv)

	lister.waitOpens(t, 5)

	if got, want := backoff.recorded(), []time.Duration{d, 2 * d, d}; !reflect.DeepEqual(got, want) {
		t.Errorf("backoff = %v, want %v", got, want)
	}
}

// The test above takes every stream as stable. This one measures: a stream held
// open past the threshold resets the backoff, so a healthy watch that ends on its
// timeout does not climb to the 5-minute wait. The sleep starts at the fourth list,
// which watchOnce makes after it reads the open's time, so a stall can only
// lengthen the stream.
func TestPlexdHookInventory_StreamPastTheThresholdResetsTheBackoff(t *testing.T) {
	const stable = 20 * time.Millisecond
	refused := errors.New("connection refused")
	events := make(chan kubernetes.PlexdHookEvent)
	lister := &fakeHookLister{
		watches: []fakeHookWatch{{err: refused}, {err: refused}, {events: events}, {err: refused}},
	}
	inv := newShortInventory(t, lister, newRecordingHandler())
	inv.stableStream = stable
	d := inv.backoffMin
	backoff := recordBackoff(inv)
	startInventory(t, inv)

	lister.waitLists(t, 4)
	time.Sleep(3 * stable)
	close(events)
	lister.waitOpens(t, 5)

	if got, want := backoff.recorded(), []time.Duration{d, 2 * d, d}; !reflect.DeepEqual(got, want) {
		t.Errorf("backoff = %v, want %v", got, want)
	}
}

// Age alone is no reset: a stream that ended on a failed list did not end well,
// however long it lived.
func TestPlexdHookInventory_FailedListDoesNotResetTheBackoff(t *testing.T) {
	refused := errors.New("connection refused")
	good := fakeHookList{hooks: []kubernetes.PlexdHook{pinnedPlexdHook("a", "1")}}
	lister := &fakeHookLister{
		lists: []fakeHookList{good, good, good, {err: errors.New("unexpected status 500")}, good},
		watches: []fakeHookWatch{
			{err: refused},
			{events: streamWithEvent()},
			{err: refused},
		},
	}
	inv := newShortInventory(t, lister, newRecordingHandler())
	inv.stableStream = 0
	d := inv.backoffMin
	backoff := recordBackoff(inv)
	startInventory(t, inv)

	lister.waitOpens(t, 4)

	if got, want := backoff.recorded(), []time.Duration{d, 2 * d, 4 * d}; !reflect.DeepEqual(got, want) {
		t.Errorf("backoff = %v, want %v", got, want)
	}
}

// An API server that drops every watch is not failing, but reopening at once would
// ask it for two requests in a tight loop. Such streams back off, stay at Debug and
// stay out of the outage accounting. Closing with nothing pending adds no list.
func TestPlexdHookInventory_StreamsEndingEarlyKeepBackingOff(t *testing.T) {
	const cycles = 5
	watches := make([]fakeHookWatch, cycles)
	for i := range watches {
		watches[i].events = closedStream()
	}
	lister := &fakeHookLister{watches: watches}
	rec := newRecordingHandler()
	inv := newShortInventory(t, lister, rec)
	d := inv.backoffMin
	backoff := recordBackoff(inv)
	run := startInventory(t, inv)

	lister.waitOpens(t, cycles+1)
	lists, _ := lister.counts()
	run.stop()

	if got, want := backoff.recorded(), []time.Duration{d, 2 * d, 4 * d, 8 * d, 8 * d}; !reflect.DeepEqual(got, want) {
		t.Errorf("backoff = %v, want %v", got, want)
	}
	if n := rec.count(slog.LevelDebug, plexdHookWatchEndedMsg); n != cycles {
		t.Errorf("Debug count = %d, want one per stream, %d", n, cycles)
	}
	if n := rec.countAt(slog.LevelWarn); n != 0 {
		t.Errorf("warnings = %d, want 0", n)
	}
	if n := rec.count(slog.LevelInfo, plexdHookWatchRestoredMsg); n != 0 {
		t.Errorf("Info count = %d, want 0: no outage began", n)
	}
	if lists-1 != cycles {
		t.Errorf("lists after boot = %d, want the one after each open, %d", lists-1, cycles)
	}
}
