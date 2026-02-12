package logfwd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// mockLogSource records calls and returns configured results.
type mockLogSource struct {
	mu      sync.Mutex
	calls   int
	entries []api.LogEntry
	err     error
}

func (m *mockLogSource) Collect(_ context.Context) ([]api.LogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.entries, nil
}

func (m *mockLogSource) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// mockReportCall records a single ReportLogs invocation.
type mockReportCall struct {
	NodeID string
	Batch  api.LogBatch
}

// mockLogReporter records ReportLogs calls.
type mockLogReporter struct {
	mu    sync.Mutex
	calls []mockReportCall
	err   error

	// errOnce causes the first call to fail, then succeeds.
	errOnce bool
}

func (m *mockLogReporter) ReportLogs(_ context.Context, nodeID string, batch api.LogBatch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockReportCall{NodeID: nodeID, Batch: batch})
	if m.err != nil {
		if m.errOnce {
			err := m.err
			m.err = nil
			return err
		}
		return m.err
	}
	return nil
}

func (m *mockLogReporter) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// panicSource is a LogSource that panics on every Collect call.
type panicSource struct {
	msg string
}

func (p *panicSource) Collect(_ context.Context) ([]api.LogEntry, error) {
	panic(p.msg)
}

// ---------------------------------------------------------------------------
// Log capture handler for warning tests
// ---------------------------------------------------------------------------

type logRecord struct {
	Level   slog.Level
	Message string
	Attrs   map[string]any
}

type capturingHandler struct {
	mu      sync.Mutex
	records []logRecord
}

func (h *capturingHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := logRecord{Level: r.Level, Message: r.Message, Attrs: make(map[string]any)}
	r.Attrs(func(a slog.Attr) bool {
		rec.Attrs[a.Key] = a.Value.Any()
		return true
	})
	h.records = append(h.records, rec)
	return nil
}

func (h *capturingHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *capturingHandler) find(msg string) *logRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Message == msg {
			return &r
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// waitFor polls condition every 5ms until it returns true or the 2s deadline
// is reached. On timeout it calls t.Fatal with the provided message.
func waitFor(t *testing.T, condition func() bool, msg string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if condition() {
			return
		}
		select {
		case <-deadline:
			t.Fatal(msg)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func testForwarderConfig(collect, report time.Duration) Config {
	return Config{
		Enabled:         true,
		CollectInterval: collect,
		ReportInterval:  report,
		BatchSize:       DefaultBatchSize,
	}
}

func testEntries(source string, n int) []api.LogEntry {
	entries := make([]api.LogEntry, n)
	for i := range entries {
		entries[i] = api.LogEntry{
			Timestamp: time.Now(),
			Source:    source,
			Unit:      "test.service",
			Message:   fmt.Sprintf("test message %d", i),
			Severity:  "info",
			Hostname:  "test-host",
		}
	}
	return entries
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestForwarder_Run_DisabledReturnsNil(t *testing.T) {
	cfg := Config{Enabled: false, BatchSize: 100}
	src := &mockLogSource{entries: testEntries("journald", 1)}
	rep := &mockLogReporter{}
	f := NewForwarder(cfg, []LogSource{src}, rep, "node-1", "host-1", discardLogger())

	err := f.Run(context.Background())
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	if src.callCount() != 0 {
		t.Errorf("expected 0 source calls, got %d", src.callCount())
	}
	if rep.callCount() != 0 {
		t.Errorf("expected 0 reporter calls, got %d", rep.callCount())
	}
}

func TestForwarder_Run_CollectsAndReports(t *testing.T) {
	cfg := testForwarderConfig(25*time.Millisecond, 80*time.Millisecond)
	entries := testEntries("journald", 1)
	src := &mockLogSource{entries: entries}
	rep := &mockLogReporter{}
	f := NewForwarder(cfg, []LogSource{src}, rep, "node-1", "host-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()

	waitFor(t, func() bool { return rep.callCount() >= 1 }, "timed out waiting for report call")

	cancel()
	<-done

	rep.mu.Lock()
	defer rep.mu.Unlock()
	call := rep.calls[0]
	if call.NodeID != "node-1" {
		t.Errorf("expected node-1, got %s", call.NodeID)
	}
	if len(call.Batch) == 0 {
		t.Error("expected non-empty batch")
	}
}

func TestForwarder_Run_SkipsEmptyBatch(t *testing.T) {
	// Use no sources so there's nothing to collect.
	cfg := testForwarderConfig(time.Hour, 60*time.Millisecond)
	rep := &mockLogReporter{}
	f := NewForwarder(cfg, nil, rep, "node-1", "host-1", discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = f.Run(ctx)

	// No sources means no entries — reporter should not be called.
	if rep.callCount() != 0 {
		t.Errorf("expected 0 reporter calls for empty buffer, got %d", rep.callCount())
	}
}

func TestForwarder_Run_RetainsOnReportError(t *testing.T) {
	// Directly test flush retains buffer on reporter failure.
	cfg := Config{
		Enabled:         true,
		CollectInterval: time.Hour,
		ReportInterval:  time.Hour,
		BatchSize:       100,
	}
	rep := &mockLogReporter{err: errors.New("network error")}
	f := NewForwarder(cfg, nil, rep, "node-1", "host-1", discardLogger())

	// Manually buffer 5 entries.
	entries := testEntries("journald", 5)
	f.mu.Lock()
	f.buffer = append(f.buffer, entries...)
	f.mu.Unlock()

	// Flush should fail and retain entries.
	f.flush(context.Background())

	f.mu.Lock()
	bufLen := len(f.buffer)
	f.mu.Unlock()

	if bufLen != 5 {
		t.Errorf("expected 5 entries retained in buffer after report error, got %d", bufLen)
	}
}

func TestForwarder_Run_DropsOldestWhenOverCapacity(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		CollectInterval: time.Hour,
		ReportInterval:  time.Hour,
		BatchSize:       10, // capacity = 2*10 = 20
	}
	rep := &mockLogReporter{}
	f := NewForwarder(cfg, nil, rep, "node-1", "host-1", discardLogger())

	// Manually fill buffer with 25 entries (exceeds capacity of 20).
	entries := make([]api.LogEntry, 25)
	for i := range entries {
		entries[i] = api.LogEntry{
			Timestamp: time.Now(),
			Source:    "test",
			Message:   fmt.Sprintf("msg-%d", i),
			Severity:  "info",
			Hostname:  "host-1",
		}
	}

	f.mu.Lock()
	f.buffer = append(f.buffer, entries...)
	f.enforceCapacity()
	bufLen := len(f.buffer)
	// The oldest should be dropped, newest kept.
	firstMsg := f.buffer[0].Message
	f.mu.Unlock()

	if bufLen != 20 {
		t.Errorf("expected buffer capped at 20 (2*BatchSize), got %d", bufLen)
	}
	// Entries 0-4 should have been dropped, so first remaining should be index 5.
	if firstMsg != "msg-5" {
		t.Errorf("expected oldest entries dropped, first Message = %q, want %q", firstMsg, "msg-5")
	}
}

func TestForwarder_Run_StopsOnContextCancel(t *testing.T) {
	cfg := testForwarderConfig(30*time.Millisecond, time.Hour)
	src := &mockLogSource{entries: testEntries("journald", 1)}
	rep := &mockLogReporter{}
	f := NewForwarder(cfg, []LogSource{src}, rep, "node-1", "host-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()

	waitFor(t, func() bool { return src.callCount() >= 1 }, "timed out waiting for collect call")

	cancel()
	err := <-done

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestForwarder_Run_IsolatesSourceError(t *testing.T) {
	cfg := testForwarderConfig(50*time.Millisecond, 100*time.Millisecond)
	badSrc := &mockLogSource{err: errors.New("disk failure")}
	goodEntries := testEntries("syslog", 1)
	goodSrc := &mockLogSource{entries: goodEntries}
	rep := &mockLogReporter{}
	f := NewForwarder(cfg, []LogSource{badSrc, goodSrc}, rep, "node-1", "host-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()

	waitFor(t, func() bool { return rep.callCount() >= 1 }, "timed out waiting for report with partial source results")

	cancel()
	<-done

	rep.mu.Lock()
	defer rep.mu.Unlock()
	if len(rep.calls[0].Batch) == 0 {
		t.Error("expected entries from successful source in batch")
	}
	for _, e := range rep.calls[0].Batch {
		if e.Source != "syslog" {
			t.Errorf("expected source %q, got %q", "syslog", e.Source)
		}
	}
}

func TestForwarder_Run_RecoversSourcePanic(t *testing.T) {
	cfg := testForwarderConfig(50*time.Millisecond, 100*time.Millisecond)
	pSrc := &panicSource{msg: "test panic"}
	goodEntries := testEntries("syslog", 1)
	goodSrc := &mockLogSource{entries: goodEntries}
	rep := &mockLogReporter{}
	f := NewForwarder(cfg, []LogSource{pSrc, goodSrc}, rep, "node-1", "host-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()

	waitFor(t, func() bool { return rep.callCount() >= 1 }, "timed out waiting for report after panic recovery")

	cancel()
	<-done

	rep.mu.Lock()
	defer rep.mu.Unlock()
	if len(rep.calls[0].Batch) == 0 {
		t.Error("expected entries from good source despite panic in another source")
	}
	for _, e := range rep.calls[0].Batch {
		if e.Source != "syslog" {
			t.Errorf("expected source %q, got %q", "syslog", e.Source)
		}
	}
}

func TestForwarder_Run_BatchSizeRespected(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		CollectInterval: time.Hour,
		ReportInterval:  time.Hour,
		BatchSize:       3,
	}
	rep := &mockLogReporter{}
	f := NewForwarder(cfg, nil, rep, "node-1", "host-1", discardLogger())

	// Buffer 7 entries.
	f.mu.Lock()
	f.buffer = testEntries("journald", 7)
	f.mu.Unlock()

	f.flush(context.Background())

	// Should have sent 3 batches: 3+3+1.
	if rep.callCount() != 3 {
		t.Fatalf("expected 3 report calls for 7 entries with batch size 3, got %d", rep.callCount())
	}
	rep.mu.Lock()
	defer rep.mu.Unlock()
	if len(rep.calls[0].Batch) != 3 {
		t.Errorf("batch[0] size = %d, want 3", len(rep.calls[0].Batch))
	}
	if len(rep.calls[1].Batch) != 3 {
		t.Errorf("batch[1] size = %d, want 3", len(rep.calls[1].Batch))
	}
	if len(rep.calls[2].Batch) != 1 {
		t.Errorf("batch[2] size = %d, want 1", len(rep.calls[2].Batch))
	}
}

func TestForwarder_Run_MultipleSources(t *testing.T) {
	cfg := testForwarderConfig(30*time.Millisecond, 80*time.Millisecond)
	entries1 := testEntries("journald", 1)
	entries2 := testEntries("syslog", 2)
	src1 := &mockLogSource{entries: entries1}
	src2 := &mockLogSource{entries: entries2}
	rep := &mockLogReporter{}
	f := NewForwarder(cfg, []LogSource{src1, src2}, rep, "node-1", "host-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()

	waitFor(t, func() bool { return rep.callCount() >= 1 }, "timed out waiting for report with multiple sources")

	cancel()
	<-done

	rep.mu.Lock()
	defer rep.mu.Unlock()

	// First report should contain entries from both sources.
	batch := rep.calls[0].Batch
	if len(batch) < 3 {
		t.Errorf("expected at least 3 entries (1+2), got %d", len(batch))
	}

	sources := make(map[string]int)
	for _, e := range batch {
		sources[e.Source]++
	}
	if sources["journald"] < 1 {
		t.Errorf("expected at least 1 journald entry, got %d", sources["journald"])
	}
	if sources["syslog"] < 2 {
		t.Errorf("expected at least 2 syslog entries, got %d", sources["syslog"])
	}
}

func TestForwarder_Run_DropsOldestLogsWarning(t *testing.T) {
	handler := &capturingHandler{}
	logger := slog.New(handler)

	cfg := Config{
		Enabled:         true,
		CollectInterval: time.Hour,
		ReportInterval:  time.Hour,
		BatchSize:       5, // capacity = 10
	}
	rep := &mockLogReporter{}
	f := NewForwarder(cfg, nil, rep, "node-1", "host-1", logger)

	// Manually buffer 15 entries (exceeds capacity of 10).
	f.mu.Lock()
	f.buffer = append(f.buffer, testEntries("test", 15)...)
	f.enforceCapacity()
	f.mu.Unlock()

	rec := handler.find("buffer overflow, dropping oldest entries")
	if rec == nil {
		t.Fatal("expected warning log about dropping entries")
	}
	if rec.Level != slog.LevelWarn {
		t.Errorf("log level = %v, want WARN", rec.Level)
	}
	dropped, ok := rec.Attrs["dropped"]
	if !ok {
		t.Fatal("expected 'dropped' attribute in log")
	}
	if dropped != int64(5) {
		t.Errorf("dropped = %v, want 5", dropped)
	}
}
