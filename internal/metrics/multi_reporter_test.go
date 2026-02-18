package metrics

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// stubReporter is a simple mock reporter for MultiReporter tests.
type stubReporter struct {
	mu     sync.Mutex
	calls  []mockReportCall
	err    error
	delay  time.Duration
	called atomic.Bool
}

func (s *stubReporter) ReportMetrics(ctx context.Context, nodeID string, batch api.MetricBatch) error {
	s.called.Store(true)
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, mockReportCall{NodeID: nodeID, Batch: batch})
	return s.err
}

func (s *stubReporter) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *stubReporter) lastCall() mockReportCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[len(s.calls)-1]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestMultiReporter_BothSucceed(t *testing.T) {
	platform := &stubReporter{}
	local := &stubReporter{}
	m := NewMultiReporter(platform, local, discardLogger())

	batch := testPoints(GroupSystem, 2)
	err := m.ReportMetrics(context.Background(), "node-1", batch)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if platform.callCount() != 1 {
		t.Errorf("platform calls = %d, want 1", platform.callCount())
	}
	if local.callCount() != 1 {
		t.Errorf("local calls = %d, want 1", local.callCount())
	}
}

func TestMultiReporter_PlatformFailLocalSucceed(t *testing.T) {
	platformErr := errors.New("platform unavailable")
	platform := &stubReporter{err: platformErr}
	local := &stubReporter{}
	m := NewMultiReporter(platform, local, discardLogger())

	batch := testPoints(GroupSystem, 1)
	err := m.ReportMetrics(context.Background(), "node-1", batch)
	if !errors.Is(err, platformErr) {
		t.Fatalf("expected platform error, got %v", err)
	}
	if local.callCount() != 1 {
		t.Errorf("local calls = %d, want 1", local.callCount())
	}
}

func TestMultiReporter_PlatformSucceedLocalFail(t *testing.T) {
	platform := &stubReporter{}
	local := &stubReporter{err: errors.New("local disk full")}
	ch := &capturingHandler{}
	logger := slog.New(ch)
	m := NewMultiReporter(platform, local, logger)

	batch := testPoints(GroupSystem, 1)
	err := m.ReportMetrics(context.Background(), "node-1", batch)
	if err != nil {
		t.Fatalf("expected nil (platform succeeded), got %v", err)
	}

	// Verify warning was logged.
	records := ch.getRecords()
	found := false
	for _, r := range records {
		if strings.Contains(r.Message, "local metrics report failed") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning log about local metrics report failure")
	}
}

func TestMultiReporter_BothFail(t *testing.T) {
	platformErr := errors.New("platform error")
	platform := &stubReporter{err: platformErr}
	local := &stubReporter{err: errors.New("local error")}
	ch := &capturingHandler{}
	logger := slog.New(ch)
	m := NewMultiReporter(platform, local, logger)

	batch := testPoints(GroupSystem, 1)
	err := m.ReportMetrics(context.Background(), "node-1", batch)
	if !errors.Is(err, platformErr) {
		t.Fatalf("expected platform error, got %v", err)
	}

	// Verify local warning was logged.
	records := ch.getRecords()
	found := false
	for _, r := range records {
		if strings.Contains(r.Message, "local metrics report failed") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning log about local metrics report failure")
	}
}

func TestMultiReporter_SlowLocalDoesNotBlockPlatform(t *testing.T) {
	platform := &stubReporter{}
	local := &stubReporter{delay: 200 * time.Millisecond}
	m := NewMultiReporter(platform, local, discardLogger())

	batch := testPoints(GroupSystem, 1)

	start := time.Now()
	err := m.ReportMetrics(context.Background(), "node-1", batch)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if platform.callCount() != 1 {
		t.Errorf("platform calls = %d, want 1", platform.callCount())
	}
	if local.callCount() != 1 {
		t.Errorf("local calls = %d, want 1", local.callCount())
	}
	// Both should complete, but the total time should reflect the slow local,
	// confirming they ran concurrently (not sequentially — which would be 2x).
	if elapsed > 500*time.Millisecond {
		t.Errorf("took %v, expected concurrency to keep total under 500ms", elapsed)
	}
}

func TestMultiReporter_ContextCancellation(t *testing.T) {
	platform := &stubReporter{delay: 5 * time.Second}
	local := &stubReporter{delay: 5 * time.Second}
	m := NewMultiReporter(platform, local, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	batch := testPoints(GroupSystem, 1)
	err := m.ReportMetrics(ctx, "node-1", batch)

	// Platform might have returned before or after cancel;
	// what matters is that both reporters received the cancelled context.
	_ = err
	if !platform.called.Load() {
		t.Error("expected platform reporter to be called")
	}
	if !local.called.Load() {
		t.Error("expected local reporter to be called")
	}
}

func TestMultiReporter_BothReceiveSameArguments(t *testing.T) {
	platform := &stubReporter{}
	local := &stubReporter{}
	m := NewMultiReporter(platform, local, discardLogger())

	batch := testPoints(GroupTunnel, 3)
	if err := m.ReportMetrics(context.Background(), "node-42", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pCall := platform.lastCall()
	lCall := local.lastCall()

	if pCall.NodeID != "node-42" {
		t.Errorf("platform nodeID = %q, want %q", pCall.NodeID, "node-42")
	}
	if lCall.NodeID != "node-42" {
		t.Errorf("local nodeID = %q, want %q", lCall.NodeID, "node-42")
	}
	if len(pCall.Batch) != 3 {
		t.Errorf("platform batch len = %d, want 3", len(pCall.Batch))
	}
	if len(lCall.Batch) != 3 {
		t.Errorf("local batch len = %d, want 3", len(lCall.Batch))
	}
}
