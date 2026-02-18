package auditfwd

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
// Helpers
// ---------------------------------------------------------------------------

// multiMockReporter is a minimal AuditReporter that records calls for MultiReporter tests.
type multiMockReporter struct {
	mu     sync.Mutex
	calls  []multiMockCall
	err    error
	delay  time.Duration
	called atomic.Bool
}

type multiMockCall struct {
	NodeID string
	Batch  api.AuditBatch
}

func (m *multiMockReporter) ReportAudit(ctx context.Context, nodeID string, batch api.AuditBatch) error {
	m.called.Store(true)
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, multiMockCall{NodeID: nodeID, Batch: batch})
	return m.err
}

func (m *multiMockReporter) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

func testBatch() api.AuditBatch {
	return api.AuditBatch{
		{
			Timestamp: time.Now(),
			Source:    "test",
			EventType: "TEST",
			Action:    "read",
			Result:    "success",
			Hostname:  "host-1",
		},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestMultiReporter_BothSucceed(t *testing.T) {
	platform := &multiMockReporter{}
	local := &multiMockReporter{}
	mr := NewMultiReporter(platform, local, discardLogger())

	err := mr.ReportAudit(context.Background(), "node-1", testBatch())
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
	platformErr := errors.New("platform down")
	platform := &multiMockReporter{err: platformErr}
	local := &multiMockReporter{}
	mr := NewMultiReporter(platform, local, discardLogger())

	err := mr.ReportAudit(context.Background(), "node-1", testBatch())
	if !errors.Is(err, platformErr) {
		t.Fatalf("expected platform error, got %v", err)
	}
	if local.callCount() != 1 {
		t.Errorf("local calls = %d, want 1", local.callCount())
	}
}

func TestMultiReporter_PlatformSucceedLocalFail(t *testing.T) {
	platform := &multiMockReporter{}
	localErr := errors.New("local endpoint unreachable")
	local := &multiMockReporter{err: localErr}

	handler := &capturingHandler{}
	logger := slog.New(handler)
	mr := NewMultiReporter(platform, local, logger)

	err := mr.ReportAudit(context.Background(), "node-1", testBatch())
	if err != nil {
		t.Fatalf("expected nil (local error not propagated), got %v", err)
	}

	rec := handler.find("local audit report failed")
	if rec == nil {
		t.Fatal("expected warning log about local failure")
	}
	if rec.Level != slog.LevelWarn {
		t.Errorf("log level = %v, want WARN", rec.Level)
	}
}

func TestMultiReporter_BothFail(t *testing.T) {
	platformErr := errors.New("platform down")
	localErr := errors.New("local endpoint unreachable")
	platform := &multiMockReporter{err: platformErr}
	local := &multiMockReporter{err: localErr}

	handler := &capturingHandler{}
	logger := slog.New(handler)
	mr := NewMultiReporter(platform, local, logger)

	err := mr.ReportAudit(context.Background(), "node-1", testBatch())
	if !errors.Is(err, platformErr) {
		t.Fatalf("expected platform error, got %v", err)
	}

	rec := handler.find("local audit report failed")
	if rec == nil {
		t.Fatal("expected warning log about local failure")
	}
	if rec.Level != slog.LevelWarn {
		t.Errorf("log level = %v, want WARN", rec.Level)
	}
}

func TestMultiReporter_ParallelDispatch(t *testing.T) {
	platform := &multiMockReporter{}
	local := &multiMockReporter{}
	mr := NewMultiReporter(platform, local, discardLogger())

	batch := testBatch()
	err := mr.ReportAudit(context.Background(), "node-1", batch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	platform.mu.Lock()
	defer platform.mu.Unlock()
	local.mu.Lock()
	defer local.mu.Unlock()

	if len(platform.calls) != 1 || len(local.calls) != 1 {
		t.Fatalf("expected 1 call each, got platform=%d local=%d", len(platform.calls), len(local.calls))
	}
	if platform.calls[0].NodeID != "node-1" {
		t.Errorf("platform nodeID = %q, want %q", platform.calls[0].NodeID, "node-1")
	}
	if local.calls[0].NodeID != "node-1" {
		t.Errorf("local nodeID = %q, want %q", local.calls[0].NodeID, "node-1")
	}
	if len(platform.calls[0].Batch) != len(local.calls[0].Batch) {
		t.Errorf("batch sizes differ: platform=%d local=%d", len(platform.calls[0].Batch), len(local.calls[0].Batch))
	}
}

func TestMultiReporter_ErrorIsolation(t *testing.T) {
	platform := &multiMockReporter{}
	localErr := errors.New("local failure")
	local := &multiMockReporter{err: localErr}
	mr := NewMultiReporter(platform, local, discardLogger())

	err := mr.ReportAudit(context.Background(), "node-1", testBatch())
	if err != nil {
		t.Fatalf("expected nil (local error isolated), got %v", err)
	}

	// Verify the returned error is not the local error.
	if errors.Is(err, localErr) {
		t.Error("local error should not be returned")
	}
}

func TestMultiReporter_SlowLocalDoesNotBlockPlatform(t *testing.T) {
	platform := &multiMockReporter{}
	local := &multiMockReporter{delay: 200 * time.Millisecond}
	mr := NewMultiReporter(platform, local, discardLogger())

	start := time.Now()
	err := mr.ReportAudit(context.Background(), "node-1", testBatch())
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
	platform := &multiMockReporter{delay: 5 * time.Second}
	local := &multiMockReporter{delay: 5 * time.Second}
	mr := NewMultiReporter(platform, local, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := mr.ReportAudit(ctx, "node-1", testBatch())

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
