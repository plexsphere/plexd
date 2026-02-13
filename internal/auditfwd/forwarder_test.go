package auditfwd

import (
	"context"
	"encoding/json"
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

// mockAuditSource records calls and returns configured results.
type mockAuditSource struct {
	mu      sync.Mutex
	calls   int
	entries []api.AuditEntry
	err     error
}

func (m *mockAuditSource) Collect(_ context.Context) ([]api.AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.entries, nil
}

func (m *mockAuditSource) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// mockReportCall records a single ReportAudit invocation.
type mockReportCall struct {
	NodeID string
	Batch  api.AuditBatch
}

// mockAuditReporter records ReportAudit calls.
type mockAuditReporter struct {
	mu    sync.Mutex
	calls []mockReportCall
	err   error

	// errOnce causes the first call to fail, then succeeds.
	errOnce bool
}

func (m *mockAuditReporter) ReportAudit(_ context.Context, nodeID string, batch api.AuditBatch) error {
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

func (m *mockAuditReporter) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// auditPanicSource is an AuditSource that panics on every Collect call.
type auditPanicSource struct {
	msg string
}

func (p *auditPanicSource) Collect(_ context.Context) ([]api.AuditEntry, error) {
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

func testAuditEntries(source string, n int) []api.AuditEntry {
	entries := make([]api.AuditEntry, n)
	for i := range entries {
		subj, _ := json.Marshal(fmt.Sprintf("subject-%d", i))
		obj, _ := json.Marshal(fmt.Sprintf("object-%d", i))
		entries[i] = api.AuditEntry{
			Timestamp: time.Now(),
			Source:    source,
			EventType: "SYSCALL",
			Subject:   subj,
			Object:    obj,
			Action:    "open",
			Result:    "success",
			Hostname:  "test-host",
			Raw:       fmt.Sprintf("raw audit entry %d", i),
		}
	}
	return entries
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestForwarder_Run_DisabledReturnsNil(t *testing.T) {
	cfg := Config{Enabled: false, BatchSize: 100}
	src := &mockAuditSource{entries: testAuditEntries("auditd", 1)}
	rep := &mockAuditReporter{}
	f := NewForwarder(cfg, []AuditSource{src}, rep, "node-1", "host-1", discardLogger())

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
	entries := testAuditEntries("auditd", 1)
	src := &mockAuditSource{entries: entries}
	rep := &mockAuditReporter{}
	f := NewForwarder(cfg, []AuditSource{src}, rep, "node-1", "host-1", discardLogger())

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
	cfg := testForwarderConfig(time.Hour, 60*time.Millisecond)
	rep := &mockAuditReporter{}
	f := NewForwarder(cfg, nil, rep, "node-1", "host-1", discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = f.Run(ctx)

	if rep.callCount() != 0 {
		t.Errorf("expected 0 reporter calls for empty buffer, got %d", rep.callCount())
	}
}

func TestForwarder_Run_RetainsOnReportError(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		CollectInterval: time.Hour,
		ReportInterval:  time.Hour,
		BatchSize:       100,
	}
	rep := &mockAuditReporter{err: errors.New("network error")}
	f := NewForwarder(cfg, nil, rep, "node-1", "host-1", discardLogger())

	entries := testAuditEntries("auditd", 5)
	f.mu.Lock()
	f.buffer = append(f.buffer, entries...)
	f.mu.Unlock()

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
	rep := &mockAuditReporter{}
	f := NewForwarder(cfg, nil, rep, "node-1", "host-1", discardLogger())

	entries := make([]api.AuditEntry, 25)
	for i := range entries {
		subj, _ := json.Marshal(fmt.Sprintf("subj-%d", i))
		obj, _ := json.Marshal(fmt.Sprintf("obj-%d", i))
		entries[i] = api.AuditEntry{
			Timestamp: time.Now(),
			Source:    "test",
			EventType: "SYSCALL",
			Subject:   subj,
			Object:    obj,
			Action:    "open",
			Result:    "success",
			Hostname:  "host-1",
			Raw:       fmt.Sprintf("raw-%d", i),
		}
	}

	f.mu.Lock()
	f.buffer = append(f.buffer, entries...)
	f.enforceCapacity()
	bufLen := len(f.buffer)
	firstRaw := f.buffer[0].Raw
	f.mu.Unlock()

	if bufLen != 20 {
		t.Errorf("expected buffer capped at 20 (2*BatchSize), got %d", bufLen)
	}
	if firstRaw != "raw-5" {
		t.Errorf("expected oldest entries dropped, first Raw = %q, want %q", firstRaw, "raw-5")
	}
}

func TestForwarder_Run_StopsOnContextCancel(t *testing.T) {
	cfg := testForwarderConfig(30*time.Millisecond, time.Hour)
	src := &mockAuditSource{entries: testAuditEntries("auditd", 1)}
	rep := &mockAuditReporter{}
	f := NewForwarder(cfg, []AuditSource{src}, rep, "node-1", "host-1", discardLogger())

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
	badSrc := &mockAuditSource{err: errors.New("disk failure")}
	goodEntries := testAuditEntries("k8s-audit", 1)
	goodSrc := &mockAuditSource{entries: goodEntries}
	rep := &mockAuditReporter{}
	f := NewForwarder(cfg, []AuditSource{badSrc, goodSrc}, rep, "node-1", "host-1", discardLogger())

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
		if e.Source != "k8s-audit" {
			t.Errorf("expected source %q, got %q", "k8s-audit", e.Source)
		}
	}
}

func TestForwarder_Run_RecoversSourcePanic(t *testing.T) {
	cfg := testForwarderConfig(50*time.Millisecond, 100*time.Millisecond)
	pSrc := &auditPanicSource{msg: "test panic"}
	goodEntries := testAuditEntries("k8s-audit", 1)
	goodSrc := &mockAuditSource{entries: goodEntries}
	rep := &mockAuditReporter{}
	f := NewForwarder(cfg, []AuditSource{pSrc, goodSrc}, rep, "node-1", "host-1", discardLogger())

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
		if e.Source != "k8s-audit" {
			t.Errorf("expected source %q, got %q", "k8s-audit", e.Source)
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
	rep := &mockAuditReporter{}
	f := NewForwarder(cfg, nil, rep, "node-1", "host-1", discardLogger())

	f.mu.Lock()
	f.buffer = testAuditEntries("auditd", 7)
	f.mu.Unlock()

	f.flush(context.Background())

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
	entries1 := testAuditEntries("auditd", 1)
	entries2 := testAuditEntries("k8s-audit", 2)
	src1 := &mockAuditSource{entries: entries1}
	src2 := &mockAuditSource{entries: entries2}
	rep := &mockAuditReporter{}
	f := NewForwarder(cfg, []AuditSource{src1, src2}, rep, "node-1", "host-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()

	waitFor(t, func() bool { return rep.callCount() >= 1 }, "timed out waiting for report with multiple sources")

	cancel()
	<-done

	rep.mu.Lock()
	defer rep.mu.Unlock()

	batch := rep.calls[0].Batch
	if len(batch) < 3 {
		t.Errorf("expected at least 3 entries (1+2), got %d", len(batch))
	}

	sources := make(map[string]int)
	for _, e := range batch {
		sources[e.Source]++
	}
	if sources["auditd"] < 1 {
		t.Errorf("expected at least 1 auditd entry, got %d", sources["auditd"])
	}
	if sources["k8s-audit"] < 2 {
		t.Errorf("expected at least 2 k8s-audit entries, got %d", sources["k8s-audit"])
	}
}

func TestForwarder_Run_DropsOldestEntriesWarning(t *testing.T) {
	handler := &capturingHandler{}
	logger := slog.New(handler)

	cfg := Config{
		Enabled:         true,
		CollectInterval: time.Hour,
		ReportInterval:  time.Hour,
		BatchSize:       5, // capacity = 10
	}
	rep := &mockAuditReporter{}
	f := NewForwarder(cfg, nil, rep, "node-1", "host-1", logger)

	f.mu.Lock()
	f.buffer = append(f.buffer, testAuditEntries("test", 15)...)
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

func TestForwarder_RegisterSource(t *testing.T) {
	cfg := testForwarderConfig(25*time.Millisecond, 80*time.Millisecond)
	rep := &mockAuditReporter{}
	f := NewForwarder(cfg, nil, rep, "node-1", "host-1", discardLogger())

	src := &mockAuditSource{entries: testAuditEntries("auditd", 1)}
	f.RegisterSource(src)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()

	waitFor(t, func() bool { return rep.callCount() >= 1 }, "timed out waiting for report after RegisterSource")

	cancel()
	<-done

	if src.callCount() < 1 {
		t.Errorf("expected at least 1 source call after RegisterSource, got %d", src.callCount())
	}
}
