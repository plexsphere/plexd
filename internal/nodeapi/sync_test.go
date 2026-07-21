package nodeapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"go.uber.org/goleak"
)

// putCall records a single PutStateReport invocation.
type putCall struct {
	key string
	req api.NodeStateReportRequest
}

// fakeReportClient records report calls and can be programmed to fail per key.
type fakeReportClient struct {
	mu        sync.Mutex
	puts      []putCall
	deletes   []string
	putErr    func(key string) error
	deleteErr func(key string) error
}

func (f *fakeReportClient) PutStateReport(_ context.Context, _, key string, req api.NodeStateReportRequest) (*api.NodeStateReportResponse, error) {
	f.mu.Lock()
	f.puts = append(f.puts, putCall{key: key, req: req})
	errFn := f.putErr
	f.mu.Unlock()
	if errFn != nil {
		if err := errFn(key); err != nil {
			return nil, err
		}
	}
	return &api.NodeStateReportResponse{Key: key, AcceptedAt: time.Now()}, nil
}

func (f *fakeReportClient) DeleteStateReport(_ context.Context, _, key string) error {
	f.mu.Lock()
	f.deletes = append(f.deletes, key)
	errFn := f.deleteErr
	f.mu.Unlock()
	if errFn != nil {
		return errFn(key)
	}
	return nil
}

func (f *fakeReportClient) putCalls() []putCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]putCall, len(f.puts))
	copy(out, f.puts)
	return out
}

func (f *fakeReportClient) deleteCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.deletes))
	copy(out, f.deletes)
	return out
}

// logRecorder is a slog.Handler that captures records for assertions.
type logRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *logRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (h *logRecorder) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.records = append(h.records, r.Clone())
	h.mu.Unlock()
	return nil
}

func (h *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *logRecorder) WithGroup(string) slog.Handler      { return h }

func (h *logRecorder) count(level slog.Level, msgSubstr string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.records {
		if r.Level == level && strings.Contains(r.Message, msgSubstr) {
			n++
		}
	}
	return n
}

// newTestSyncer builds a syncer over a recording logger and a shortened retry
// interval so timer-driven convergence is observable within a test.
func newTestSyncer(client ReportSyncClient, debounce time.Duration) (*ReportSyncer, *logRecorder) {
	rec := &logRecorder{}
	s := NewReportSyncer(client, debounce, slog.New(rec))
	s.retryInterval = 20 * time.Millisecond
	return s, rec
}

func reportEntry(key, payload string, version int) ReportEntry {
	return ReportEntry{
		Key:         key,
		ContentType: "application/json",
		Payload:     json.RawMessage(payload),
		Version:     version,
		UpdatedAt:   time.Now(),
	}
}

// dirtyKeys returns the currently pending keys in ascending order.
func dirtyKeys(s *ReportSyncer) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ks := make([]string, 0, len(s.dirty))
	for k := range s.dirty {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func TestReportSyncer_CoalescesAndOrdersKeys(t *testing.T) {
	client := &fakeReportClient{}
	s, _ := newTestSyncer(client, 10*time.Millisecond)

	// The same key twice before a flush: the last value must win.
	s.NotifyChange([]ReportEntry{reportEntry("cpu-load", `{"v":1}`, 1)}, nil)
	s.NotifyChange([]ReportEntry{reportEntry("cpu-load", `{"v":2}`, 2)}, nil)
	// Extra keys, notified out of order, to check ascending flush order.
	s.NotifyChange([]ReportEntry{reportEntry("status.mesh", `{"peers":3}`, 1)}, nil)
	s.NotifyChange([]ReportEntry{reportEntry("audit.count", `{"n":9}`, 1)}, nil)

	s.flush(context.Background(), "node-1")

	puts := client.putCalls()
	if len(puts) != 3 {
		t.Fatalf("PutStateReport calls = %d, want 3 (one per distinct key)", len(puts))
	}
	gotKeys := []string{puts[0].key, puts[1].key, puts[2].key}
	wantKeys := []string{"audit.count", "cpu-load", "status.mesh"}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Errorf("flush key order = %v, want %v", gotKeys, wantKeys)
	}
	for _, p := range puts {
		if p.key == "cpu-load" && p.req.Value != `{"v":2}` {
			t.Errorf("coalesced cpu-load value = %q, want %q", p.req.Value, `{"v":2}`)
		}
	}
}

func TestReportSyncer_PutBodyAndDelete(t *testing.T) {
	client := &fakeReportClient{}
	s, _ := newTestSyncer(client, 10*time.Millisecond)

	s.NotifyChange([]ReportEntry{reportEntry("cpu-load", `{"load":0.5}`, 1)}, nil)
	s.NotifyChange(nil, []string{"stale.key"})

	s.flush(context.Background(), "node-1")

	puts := client.putCalls()
	if len(puts) != 1 {
		t.Fatalf("PutStateReport calls = %d, want 1", len(puts))
	}
	if puts[0].req.Value != `{"load":0.5}` {
		t.Errorf("put value = %q, want %q", puts[0].req.Value, `{"load":0.5}`)
	}
	if puts[0].req.WorkloadTag != "" {
		t.Errorf("put workload_tag = %q, want empty", puts[0].req.WorkloadTag)
	}

	dels := client.deleteCalls()
	if len(dels) != 1 || dels[0] != "stale.key" {
		t.Errorf("DeleteStateReport calls = %v, want [stale.key]", dels)
	}
}

func TestReportSyncer_EmptyFlushNoHTTP(t *testing.T) {
	client := &fakeReportClient{}
	s, _ := newTestSyncer(client, 10*time.Millisecond)

	if s.flush(context.Background(), "node-1") {
		t.Error("empty flush returned true (retry armed), want false")
	}
	if len(client.putCalls()) != 0 || len(client.deleteCalls()) != 0 {
		t.Errorf("empty flush made HTTP calls: puts=%d deletes=%d",
			len(client.putCalls()), len(client.deleteCalls()))
	}
}

func TestReportSyncer_DeleteNotFoundIsSuccess(t *testing.T) {
	client := &fakeReportClient{
		deleteErr: func(string) error {
			return &api.APIError{StatusCode: 404, Code: "report_not_found"}
		},
	}
	s, _ := newTestSyncer(client, 10*time.Millisecond)

	s.NotifyChange(nil, []string{"gone.key"})
	if s.flush(context.Background(), "node-1") {
		t.Error("flush returned true, want false (404 delete is idempotent success)")
	}
	if got := dirtyKeys(s); len(got) != 0 {
		t.Errorf("dirty keys after 404 delete = %v, want none", got)
	}
}

func TestReportSyncer_InvalidReportDropsKey(t *testing.T) {
	client := &fakeReportClient{
		putErr: func(string) error {
			return &api.APIError{StatusCode: 400, Code: "invalid_report"}
		},
	}
	s, rec := newTestSyncer(client, 10*time.Millisecond)

	s.NotifyChange([]ReportEntry{reportEntry("cpu-load", `{"v":1}`, 1)}, nil)
	if s.flush(context.Background(), "node-1") {
		t.Error("flush returned true, want false (invalid_report drops the key)")
	}
	if got := dirtyKeys(s); len(got) != 0 {
		t.Errorf("dirty keys after invalid_report = %v, want none", got)
	}
	if n := rec.count(slog.LevelWarn, "refused report as invalid"); n != 1 {
		t.Errorf("warn logs for invalid_report = %d, want 1", n)
	}
}

func TestReportSyncer_NotProvisionedSuppressesAndLogsOnce(t *testing.T) {
	client := &fakeReportClient{
		putErr: func(string) error {
			return &api.APIError{StatusCode: 501, Code: "reports_not_provisioned"}
		},
	}
	s, rec := newTestSyncer(client, 10*time.Millisecond)

	s.NotifyChange([]ReportEntry{reportEntry("cpu-load", `{"v":1}`, 1)}, nil)
	s.NotifyChange([]ReportEntry{reportEntry("status.mesh", `{"v":1}`, 1)}, nil)

	// First flush hits the control plane, gets 501, keeps every key dirty and
	// enters the suppression window (aborting after the first key).
	if !s.flush(context.Background(), "node-1") {
		t.Error("first 501 flush returned false, want true (keys still dirty)")
	}
	if got := dirtyKeys(s); len(got) != 2 {
		t.Errorf("dirty keys after 501 = %v, want both keys", got)
	}
	callsAfterFirst := len(client.putCalls())
	if callsAfterFirst == 0 {
		t.Fatal("first flush made no PutStateReport call")
	}

	// A second flush inside the window is fully suppressed: no new HTTP attempt.
	if !s.flush(context.Background(), "node-1") {
		t.Error("suppressed flush returned false, want true (keys still dirty)")
	}
	if len(client.putCalls()) != callsAfterFirst {
		t.Errorf("suppressed flush made HTTP calls: %d, want %d",
			len(client.putCalls()), callsAfterFirst)
	}

	// Force the window to expire; the next flush retries and 501s again, but the
	// transition Info must not be logged a second time.
	s.notProvisionedUntil = time.Now().Add(-time.Minute)
	s.flush(context.Background(), "node-1")
	if len(client.putCalls()) <= callsAfterFirst {
		t.Error("post-window flush made no new HTTP attempt")
	}
	if n := rec.count(slog.LevelInfo, "not provisioned"); n != 1 {
		t.Errorf("not-provisioned Info logs = %d, want 1 across consecutive 501s", n)
	}
}

func TestReportSyncer_TransportErrorRetriesOnTimer(t *testing.T) {
	defer goleak.VerifyNone(t)

	var attempts int32
	client := &fakeReportClient{
		putErr: func(string) error {
			// Fail the first attempt with a wrapped transport error, then succeed.
			if atomic.AddInt32(&attempts, 1) == 1 {
				return fmt.Errorf("dial control plane: %w", context.DeadlineExceeded)
			}
			return nil
		},
	}
	s, _ := newTestSyncer(client, 10*time.Millisecond) // retryInterval shortened to 20ms

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, "node-1") }()

	// A single NotifyChange; the retry timer must re-flush without another one.
	s.NotifyChange([]ReportEntry{reportEntry("cpu-load", `{"v":1}`, 1)}, nil)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(dirtyKeys(s)) != 0 {
		time.Sleep(10 * time.Millisecond)
	}

	if got := dirtyKeys(s); len(got) != 0 {
		t.Errorf("dirty keys after timer retry = %v, want none", got)
	}
	if got := atomic.LoadInt32(&attempts); got < 2 {
		t.Errorf("PutStateReport attempts = %d, want >= 2 (initial failure + timer retry)", got)
	}

	cancel()
	<-done
}

func TestReportSyncer_CancellationPreservesDirty(t *testing.T) {
	client := &fakeReportClient{}
	// A long debounce so the change is never flushed before we cancel.
	s, _ := newTestSyncer(client, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, "node-1") }()

	s.NotifyChange([]ReportEntry{reportEntry("cpu-load", `{"v":1}`, 1)}, nil)
	// Let Run consume the signal and settle into the debounce wait.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run() = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}

	// The change was never flushed and survives in memory.
	if got := dirtyKeys(s); len(got) != 1 || got[0] != "cpu-load" {
		t.Errorf("dirty keys after cancel = %v, want [cpu-load]", got)
	}
	if len(client.putCalls()) != 0 {
		t.Errorf("PutStateReport called %d times, want 0", len(client.putCalls()))
	}
}

func TestReportSyncer_NoGoroutineLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := &fakeReportClient{}
	s, _ := newTestSyncer(client, 10*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, "node-1") }()

	s.NotifyChange([]ReportEntry{reportEntry("cpu-load", `{"v":1}`, 1)}, nil)
	time.Sleep(50 * time.Millisecond)

	cancel()
	<-done
}

// TestReportSyncer_RecreateDuringFlushStaysDirty covers the delete-then-recreate
// race: while a PUT is in flight the local consumer deletes the key and PUTs new
// content. StateCache.PutReport restarts the version at 1 for a key that no
// longer exists, so the replacement carries the same version as the entry being
// published. The syncer must not read that as "unchanged" and drop the key —
// the new payload would then never reach the control plane.
func TestReportSyncer_RecreateDuringFlushStaysDirty(t *testing.T) {
	client := &fakeReportClient{}
	s, _ := newTestSyncer(client, 10*time.Millisecond)

	var once sync.Once
	client.putErr = func(key string) error {
		once.Do(func() {
			s.NotifyChange(nil, []string{key})
			s.NotifyChange([]ReportEntry{reportEntry(key, `{"state":"degraded"}`, 1)}, nil)
		})
		return nil
	}

	s.NotifyChange([]ReportEntry{reportEntry("app-health", `{"state":"ok"}`, 1)}, nil)
	s.flush(context.Background(), "node-1")

	if got := dirtyKeys(s); !reflect.DeepEqual(got, []string{"app-health"}) {
		t.Fatalf("dirty keys after raced recreate = %v, want [app-health]", got)
	}

	s.flush(context.Background(), "node-1")

	puts := client.putCalls()
	if len(puts) != 2 {
		t.Fatalf("PutStateReport calls = %d, want 2 (the raced payload is republished)", len(puts))
	}
	if puts[1].req.Value != `{"state":"degraded"}` {
		t.Errorf("republished value = %q, want %q", puts[1].req.Value, `{"state":"degraded"}`)
	}
}
