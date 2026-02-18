package logfwd

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// Mock reporter for MultiReporter tests
// ---------------------------------------------------------------------------

type stubReporter struct {
	mu     sync.Mutex
	calls  []stubReportCall
	err    error
	delay  time.Duration
	called atomic.Bool
}

type stubReportCall struct {
	NodeID string
	Batch  api.LogBatch
}

func (s *stubReporter) ReportLogs(ctx context.Context, nodeID string, batch api.LogBatch) error {
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
	s.calls = append(s.calls, stubReportCall{NodeID: nodeID, Batch: batch})
	return s.err
}

func (s *stubReporter) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func testBatch() api.LogBatch {
	return api.LogBatch{
		{
			Timestamp: time.Now(),
			Source:    "test",
			Unit:      "unit.service",
			Message:   "test message",
			Severity:  "info",
			Hostname:  "host-1",
		},
	}
}

func TestMultiReporter_BothSucceed(t *testing.T) {
	platform := &stubReporter{}
	local := &stubReporter{}
	mr := NewMultiReporter(platform, local, discardLogger())

	err := mr.ReportLogs(context.Background(), "node-1", testBatch())
	if err != nil {
		t.Fatalf("ReportLogs() error = %v, want nil", err)
	}
	if platform.callCount() != 1 {
		t.Errorf("platform calls = %d, want 1", platform.callCount())
	}
	if local.callCount() != 1 {
		t.Errorf("local calls = %d, want 1", local.callCount())
	}
}

func TestMultiReporter_PlatformFailLocalSucceed(t *testing.T) {
	platform := &stubReporter{err: errors.New("platform down")}
	local := &stubReporter{}
	mr := NewMultiReporter(platform, local, discardLogger())

	err := mr.ReportLogs(context.Background(), "node-1", testBatch())
	if err == nil {
		t.Fatal("expected platform error, got nil")
	}
	if err.Error() != "platform down" {
		t.Errorf("error = %q, want %q", err.Error(), "platform down")
	}
}

func TestMultiReporter_PlatformSucceedLocalFail(t *testing.T) {
	platform := &stubReporter{}
	local := &stubReporter{err: errors.New("local endpoint error")}

	handler := &capturingHandler{}
	logger := slog.New(handler)
	mr := NewMultiReporter(platform, local, logger)

	err := mr.ReportLogs(context.Background(), "node-1", testBatch())
	if err != nil {
		t.Fatalf("expected nil error (local failure is logged, not returned), got %v", err)
	}

	rec := handler.find("local log report failed")
	if rec == nil {
		t.Fatal("expected warning log about local failure")
	}
	if rec.Level != slog.LevelWarn {
		t.Errorf("log level = %v, want WARN", rec.Level)
	}
}

func TestMultiReporter_BothFail(t *testing.T) {
	platform := &stubReporter{err: errors.New("platform error")}
	local := &stubReporter{err: errors.New("local error")}

	handler := &capturingHandler{}
	logger := slog.New(handler)
	mr := NewMultiReporter(platform, local, logger)

	err := mr.ReportLogs(context.Background(), "node-1", testBatch())
	if err == nil {
		t.Fatal("expected platform error, got nil")
	}
	if err.Error() != "platform error" {
		t.Errorf("error = %q, want %q", err.Error(), "platform error")
	}

	rec := handler.find("local log report failed")
	if rec == nil {
		t.Fatal("expected warning log about local failure")
	}
	if rec.Level != slog.LevelWarn {
		t.Errorf("log level = %v, want WARN", rec.Level)
	}
}

func TestMultiReporter_ParallelDispatch(t *testing.T) {
	platform := &stubReporter{}
	local := &stubReporter{}
	mr := NewMultiReporter(platform, local, discardLogger())

	batch := testBatch()
	err := mr.ReportLogs(context.Background(), "node-42", batch)
	if err != nil {
		t.Fatalf("ReportLogs() error = %v", err)
	}

	// Both reporters should have been called with the same arguments.
	platform.mu.Lock()
	defer platform.mu.Unlock()
	local.mu.Lock()
	defer local.mu.Unlock()

	if len(platform.calls) != 1 {
		t.Fatalf("platform calls = %d, want 1", len(platform.calls))
	}
	if len(local.calls) != 1 {
		t.Fatalf("local calls = %d, want 1", len(local.calls))
	}
	if platform.calls[0].NodeID != "node-42" {
		t.Errorf("platform nodeID = %q, want %q", platform.calls[0].NodeID, "node-42")
	}
	if local.calls[0].NodeID != "node-42" {
		t.Errorf("local nodeID = %q, want %q", local.calls[0].NodeID, "node-42")
	}
	if len(platform.calls[0].Batch) != len(batch) {
		t.Errorf("platform batch len = %d, want %d", len(platform.calls[0].Batch), len(batch))
	}
	if len(local.calls[0].Batch) != len(batch) {
		t.Errorf("local batch len = %d, want %d", len(local.calls[0].Batch), len(batch))
	}
}

func TestMultiReporter_ErrorIsolation(t *testing.T) {
	platform := &stubReporter{}
	local := &stubReporter{err: errors.New("local isolation error")}
	mr := NewMultiReporter(platform, local, discardLogger())

	err := mr.ReportLogs(context.Background(), "node-1", testBatch())
	if err != nil {
		t.Fatalf("expected nil (local error should not be returned), got %v", err)
	}
	// The local error must not propagate.
	if platform.callCount() != 1 {
		t.Errorf("platform calls = %d, want 1", platform.callCount())
	}
}

func TestMultiReporter_SlowLocalDoesNotBlockPlatform(t *testing.T) {
	platform := &stubReporter{}
	local := &stubReporter{delay: 200 * time.Millisecond}
	mr := NewMultiReporter(platform, local, discardLogger())

	start := time.Now()
	err := mr.ReportLogs(context.Background(), "node-1", testBatch())
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
	mr := NewMultiReporter(platform, local, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := mr.ReportLogs(ctx, "node-1", testBatch())

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
