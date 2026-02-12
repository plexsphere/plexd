package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

func testConfig(collect, report time.Duration) Config {
	return Config{
		Enabled:         true,
		CollectInterval: collect,
		ReportInterval:  report,
		BatchSize:       DefaultBatchSize,
	}
}

func testPoints(group string, n int) []api.MetricPoint {
	pts := make([]api.MetricPoint, n)
	for i := range pts {
		pts[i] = api.MetricPoint{
			Timestamp: time.Now(),
			Group:     group,
			Data:      json.RawMessage(`{}`),
		}
	}
	return pts
}

func TestManager_RunDisabled(t *testing.T) {
	cfg := Config{Enabled: false, BatchSize: 100}
	coll := &mockCollector{points: testPoints(GroupSystem, 1)}
	rep := &mockReporter{}
	m := NewManager(cfg, []Collector{coll}, rep, "node-1", discardLogger())

	err := m.Run(context.Background())
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	if coll.callCount() != 0 {
		t.Errorf("expected 0 collector calls, got %d", coll.callCount())
	}
	if rep.callCount() != 0 {
		t.Errorf("expected 0 reporter calls, got %d", rep.callCount())
	}
}

func TestManager_CollectsAtInterval(t *testing.T) {
	cfg := testConfig(50*time.Millisecond, time.Hour)
	coll := &mockCollector{points: testPoints(GroupSystem, 1)}
	rep := &mockReporter{}
	m := NewManager(cfg, []Collector{coll}, rep, "node-1", discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	_ = m.Run(ctx)

	// +1 for initial immediate collect.
	if n := coll.callCount(); n < 3 {
		t.Errorf("expected at least 3 collector calls (1 immediate + 2 ticks), got %d", n)
	}
}

func TestManager_ReportsAtInterval(t *testing.T) {
	cfg := testConfig(25*time.Millisecond, 80*time.Millisecond)
	pts := testPoints(GroupSystem, 1)
	coll := &mockCollector{points: pts}
	rep := &mockReporter{}
	m := NewManager(cfg, []Collector{coll}, rep, "node-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	// Wait for at least 1 report call.
	deadline := time.After(2 * time.Second)
	for {
		if rep.callCount() >= 1 {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("timed out waiting for report call")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

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

func TestManager_CollectorErrorContinues(t *testing.T) {
	cfg := testConfig(50*time.Millisecond, 100*time.Millisecond)
	badColl := &mockCollector{err: errors.New("disk failure")}
	goodPts := testPoints(GroupTunnel, 1)
	goodColl := &mockCollector{points: goodPts}
	rep := &mockReporter{}
	m := NewManager(cfg, []Collector{badColl, goodColl}, rep, "node-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	for {
		if rep.callCount() >= 1 {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("timed out waiting for report with partial collector results")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	<-done

	rep.mu.Lock()
	defer rep.mu.Unlock()
	if len(rep.calls[0].Batch) == 0 {
		t.Error("expected points from successful collector in batch")
	}
	for _, p := range rep.calls[0].Batch {
		if p.Group != GroupTunnel {
			t.Errorf("expected group %s, got %s", GroupTunnel, p.Group)
		}
	}
}

func TestManager_ReporterErrorContinues(t *testing.T) {
	cfg := testConfig(25*time.Millisecond, 60*time.Millisecond)
	coll := &mockCollector{points: testPoints(GroupSystem, 1)}
	rep := &mockReporter{err: errors.New("network error")}
	m := NewManager(cfg, []Collector{coll}, rep, "node-1", discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	err := m.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}

	// Reporter should have been called despite errors.
	if rep.callCount() < 1 {
		t.Error("expected at least 1 reporter call despite errors")
	}
}

func TestManager_FlushOnShutdown(t *testing.T) {
	cfg := testConfig(30*time.Millisecond, time.Hour) // long report interval — no scheduled report
	pts := testPoints(GroupSystem, 2)
	coll := &mockCollector{points: pts}
	rep := &mockReporter{}
	m := NewManager(cfg, []Collector{coll}, rep, "node-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	// Wait for at least one collect cycle.
	deadline := time.After(2 * time.Second)
	for {
		if coll.callCount() >= 1 {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("timed out waiting for collector call")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	<-done

	// Flush on shutdown should have reported the buffered points.
	if rep.callCount() < 1 {
		t.Fatal("expected flush on shutdown to call reporter")
	}
	rep.mu.Lock()
	defer rep.mu.Unlock()
	if len(rep.calls[0].Batch) == 0 {
		t.Error("expected non-empty batch on shutdown flush")
	}
}

func TestManager_EmptyFlushSkipsReport(t *testing.T) {
	// Use no collectors so there's nothing to collect.
	cfg := testConfig(time.Hour, 60*time.Millisecond)
	rep := &mockReporter{}
	m := NewManager(cfg, nil, rep, "node-1", discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = m.Run(ctx)

	// No collectors means no points — reporter should not be called.
	if rep.callCount() != 0 {
		t.Errorf("expected 0 reporter calls for empty buffer, got %d", rep.callCount())
	}
}

func TestManager_MultipleCollectors(t *testing.T) {
	cfg := testConfig(30*time.Millisecond, 80*time.Millisecond)
	pts1 := testPoints(GroupSystem, 1)
	pts2 := testPoints(GroupTunnel, 2)
	coll1 := &mockCollector{points: pts1}
	coll2 := &mockCollector{points: pts2}
	rep := &mockReporter{}
	m := NewManager(cfg, []Collector{coll1, coll2}, rep, "node-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	for {
		if rep.callCount() >= 1 {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("timed out waiting for report with multiple collectors")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	<-done

	rep.mu.Lock()
	defer rep.mu.Unlock()

	// First report should contain points from both collectors.
	batch := rep.calls[0].Batch
	if len(batch) < 3 {
		t.Errorf("expected at least 3 points (1+2), got %d", len(batch))
	}

	groups := make(map[string]int)
	for _, p := range batch {
		groups[p.Group]++
	}
	if groups[GroupSystem] < 1 {
		t.Errorf("expected at least 1 system point, got %d", groups[GroupSystem])
	}
	if groups[GroupTunnel] < 2 {
		t.Errorf("expected at least 2 tunnel points, got %d", groups[GroupTunnel])
	}
}

func TestManager_RetainOnReportError(t *testing.T) {
	// Directly test flush retains buffer on reporter failure.
	cfg := Config{
		Enabled:         true,
		CollectInterval: time.Hour,
		ReportInterval:  time.Hour,
		BatchSize:       100,
	}
	rep := &mockReporter{err: errors.New("network error")}
	m := NewManager(cfg, nil, rep, "node-1", discardLogger())

	// Manually buffer 5 points.
	pts := testPoints(GroupSystem, 5)
	m.mu.Lock()
	m.buffer = append(m.buffer, pts...)
	m.mu.Unlock()

	// Flush should fail and retain points.
	m.flush(context.Background())

	m.mu.Lock()
	bufLen := len(m.buffer)
	m.mu.Unlock()

	if bufLen != 5 {
		t.Errorf("expected 5 points retained in buffer after report error, got %d", bufLen)
	}
}

func TestManager_DropOldestOverCapacity(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		CollectInterval: time.Hour,
		ReportInterval:  time.Hour,
		BatchSize:       10, // capacity = 2*10 = 20
	}
	rep := &mockReporter{}
	m := NewManager(cfg, nil, rep, "node-1", discardLogger())

	// Manually fill buffer with 25 points (exceeds capacity of 20).
	pts := make([]api.MetricPoint, 25)
	for i := range pts {
		pts[i] = api.MetricPoint{
			Timestamp: time.Now(),
			Group:     GroupSystem,
			PeerID:    string(rune('a' + i)),
			Data:      json.RawMessage(`{}`),
		}
	}

	m.mu.Lock()
	m.buffer = append(m.buffer, pts...)
	m.enforceCapacity()
	bufLen := len(m.buffer)
	// The oldest should be dropped, newest kept.
	firstPeerID := m.buffer[0].PeerID
	m.mu.Unlock()

	if bufLen != 20 {
		t.Errorf("expected buffer capped at 20 (2*BatchSize), got %d", bufLen)
	}
	// Points 0-4 should have been dropped, so first remaining should be index 5 ('f').
	if firstPeerID != string(rune('a'+5)) {
		t.Errorf("expected oldest points dropped, first PeerID = %q, want %q", firstPeerID, string(rune('a'+5)))
	}
}

func TestManager_CollectorPanicRecovery(t *testing.T) {
	cfg := testConfig(50*time.Millisecond, 100*time.Millisecond)
	panicColl := &panicCollector{msg: "test panic"}
	goodPts := testPoints(GroupTunnel, 1)
	goodColl := &mockCollector{points: goodPts}
	rep := &mockReporter{}
	m := NewManager(cfg, []Collector{panicColl, goodColl}, rep, "node-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	// Wait for at least 1 report with data from good collector.
	deadline := time.After(2 * time.Second)
	for {
		if rep.callCount() >= 1 {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("timed out waiting for report after panic recovery")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	<-done

	rep.mu.Lock()
	defer rep.mu.Unlock()
	if len(rep.calls[0].Batch) == 0 {
		t.Error("expected points from good collector despite panic in another collector")
	}
	for _, p := range rep.calls[0].Batch {
		if p.Group != GroupTunnel {
			t.Errorf("expected group %s, got %s", GroupTunnel, p.Group)
		}
	}
}

func TestManager_FlushRespectsBatchSize(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		CollectInterval: time.Hour,
		ReportInterval:  time.Hour,
		BatchSize:       3,
	}
	rep := &mockReporter{}
	m := NewManager(cfg, nil, rep, "node-1", discardLogger())

	// Buffer 7 points.
	m.mu.Lock()
	m.buffer = testPoints(GroupSystem, 7)
	m.mu.Unlock()

	m.flush(context.Background())

	// Should have sent 3 batches: 3+3+1.
	if rep.callCount() != 3 {
		t.Fatalf("expected 3 report calls for 7 points with batch size 3, got %d", rep.callCount())
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

func TestManager_RegisterCollector(t *testing.T) {
	cfg := testConfig(50*time.Millisecond, time.Hour)
	rep := &mockReporter{}
	m := NewManager(cfg, nil, rep, "node-1", discardLogger())

	coll := &mockCollector{points: testPoints(GroupSystem, 1)}
	m.RegisterCollector(coll)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = m.Run(ctx)

	if coll.callCount() < 1 {
		t.Error("expected registered collector to be called at least once")
	}
}

func TestManager_ApplyDefaultsInConstructor(t *testing.T) {
	// Zero-value config should get defaults applied.
	m := NewManager(Config{}, nil, &mockReporter{}, "node-1", discardLogger())

	if m.cfg.CollectInterval != DefaultCollectInterval {
		t.Errorf("CollectInterval = %v, want %v", m.cfg.CollectInterval, DefaultCollectInterval)
	}
	if m.cfg.ReportInterval != DefaultReportInterval {
		t.Errorf("ReportInterval = %v, want %v", m.cfg.ReportInterval, DefaultReportInterval)
	}
	if m.cfg.BatchSize != DefaultBatchSize {
		t.Errorf("BatchSize = %d, want %d", m.cfg.BatchSize, DefaultBatchSize)
	}
	if !m.cfg.Enabled {
		t.Error("Enabled = false, want true")
	}
}

func TestManager_InitialCollectCycle(t *testing.T) {
	cfg := testConfig(time.Hour, time.Hour) // long intervals — only initial cycle fires
	coll := &mockCollector{points: testPoints(GroupSystem, 1)}
	rep := &mockReporter{}
	m := NewManager(cfg, []Collector{coll}, rep, "node-1", discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_ = m.Run(ctx)

	// The initial immediate collect should have run.
	if coll.callCount() < 1 {
		t.Error("expected initial collect cycle to run immediately")
	}
}
