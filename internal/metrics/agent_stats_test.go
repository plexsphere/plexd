package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type mockReconnectCounter struct {
	count int
}

func (m *mockReconnectCounter) ReconnectCount() int {
	return m.count
}

func TestAgentStatsCollector_Collect(t *testing.T) {
	counter := &mockReconnectCounter{count: 3}
	c := NewAgentStatsCollector(time.Now().Add(-10*time.Second), counter, discardLogger())

	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("len(points) = %d, want 1", len(points))
	}

	pt := points[0]
	if pt.Group != GroupAgent {
		t.Errorf("Group = %q, want %q", pt.Group, GroupAgent)
	}
	if pt.PeerID != "" {
		t.Errorf("PeerID = %q, want empty", pt.PeerID)
	}
	if pt.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}

	var stats AgentStats
	if err := json.Unmarshal(pt.Data, &stats); err != nil {
		t.Fatalf("json.Unmarshal(Data) error = %v", err)
	}
	if stats.GoroutineCount <= 0 {
		t.Errorf("GoroutineCount = %d, want > 0", stats.GoroutineCount)
	}
	if stats.HeapAllocBytes == 0 {
		t.Error("HeapAllocBytes = 0, want > 0")
	}
	if stats.HeapSysBytes == 0 {
		t.Error("HeapSysBytes = 0, want > 0")
	}
	if stats.ReconnectCount != 3 {
		t.Errorf("ReconnectCount = %d, want 3", stats.ReconnectCount)
	}
}

func TestAgentStatsCollector_UptimeIncreases(t *testing.T) {
	start := time.Now().Add(-5 * time.Second)
	c := NewAgentStatsCollector(start, nil, discardLogger())

	points1, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("first Collect() error = %v", err)
	}
	var stats1 AgentStats
	if err := json.Unmarshal(points1[0].Data, &stats1); err != nil {
		t.Fatalf("unmarshal first: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	points2, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() error = %v", err)
	}
	var stats2 AgentStats
	if err := json.Unmarshal(points2[0].Data, &stats2); err != nil {
		t.Fatalf("unmarshal second: %v", err)
	}

	if stats2.UptimeSeconds <= stats1.UptimeSeconds {
		t.Errorf("UptimeSeconds did not increase: %v <= %v", stats2.UptimeSeconds, stats1.UptimeSeconds)
	}
	if stats1.UptimeSeconds < 5.0 {
		t.Errorf("UptimeSeconds = %v, want >= 5.0 (started 5s ago)", stats1.UptimeSeconds)
	}
}

func TestAgentStatsCollector_NilReconnectCounter(t *testing.T) {
	c := NewAgentStatsCollector(time.Now(), nil, discardLogger())

	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	var stats AgentStats
	if err := json.Unmarshal(points[0].Data, &stats); err != nil {
		t.Fatalf("json.Unmarshal(Data) error = %v", err)
	}
	if stats.ReconnectCount != 0 {
		t.Errorf("ReconnectCount = %d, want 0 (nil counter)", stats.ReconnectCount)
	}
}

func TestAgentStatsCollector_ContextCancelled(t *testing.T) {
	c := NewAgentStatsCollector(time.Now(), nil, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	points, err := c.Collect(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if points != nil {
		t.Errorf("expected nil points, got %v", points)
	}
}

func TestAgentStatsCollector_AllFieldsInJSON(t *testing.T) {
	c := NewAgentStatsCollector(time.Now().Add(-time.Minute), &mockReconnectCounter{count: 1}, discardLogger())

	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(points[0].Data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(Data) error = %v", err)
	}

	requiredKeys := []string{
		"goroutine_count",
		"heap_alloc_bytes",
		"heap_sys_bytes",
		"gc_pause_total_ns",
		"gc_num_gc",
		"uptime_seconds",
		"reconnect_count",
	}
	for _, key := range requiredKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("JSON output missing key %q", key)
		}
	}
}
