package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestSystemCollector_Collect(t *testing.T) {
	reader := &mockSystemReader{
		stats: &SystemStats{
			CPUUsagePercent:  42.5,
			MemoryUsedBytes:  1024,
			MemoryTotalBytes: 4096,
			DiskUsedBytes:    2048,
			DiskTotalBytes:   8192,
			NetworkRxBytes:   100,
			NetworkTxBytes:   200,
		},
	}
	c := NewSystemCollector(reader, discardLogger())

	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("len(points) = %d, want 1", len(points))
	}

	pt := points[0]
	if pt.Group != GroupSystem {
		t.Errorf("Group = %q, want %q", pt.Group, GroupSystem)
	}
	if pt.PeerID != "" {
		t.Errorf("PeerID = %q, want empty", pt.PeerID)
	}
	if pt.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}
	if pt.Data == nil {
		t.Error("Data is nil")
	}
}

func TestSystemCollector_CollectError(t *testing.T) {
	reader := &mockSystemReader{
		err: errors.New("disk on fire"),
	}
	c := NewSystemCollector(reader, discardLogger())

	points, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("Collect() error = nil, want error")
	}
	if points != nil {
		t.Errorf("points = %v, want nil", points)
	}
	if !errors.Is(err, reader.err) {
		t.Errorf("error does not wrap original: %v", err)
	}
}

func TestSystemCollector_CollectData(t *testing.T) {
	want := &SystemStats{
		CPUUsagePercent:  75.3,
		MemoryUsedBytes:  2048,
		MemoryTotalBytes: 8192,
		DiskUsedBytes:    4096,
		DiskTotalBytes:   16384,
		NetworkRxBytes:   500,
		NetworkTxBytes:   600,
	}
	reader := &mockSystemReader{stats: want}
	c := NewSystemCollector(reader, discardLogger())

	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	var got SystemStats
	if err := json.Unmarshal(points[0].Data, &got); err != nil {
		t.Fatalf("json.Unmarshal(Data) error = %v", err)
	}
	if got.CPUUsagePercent != want.CPUUsagePercent {
		t.Errorf("CPUUsagePercent = %v, want %v", got.CPUUsagePercent, want.CPUUsagePercent)
	}
	if got.MemoryUsedBytes != want.MemoryUsedBytes {
		t.Errorf("MemoryUsedBytes = %v, want %v", got.MemoryUsedBytes, want.MemoryUsedBytes)
	}
	if got.MemoryTotalBytes != want.MemoryTotalBytes {
		t.Errorf("MemoryTotalBytes = %v, want %v", got.MemoryTotalBytes, want.MemoryTotalBytes)
	}
	if got.DiskUsedBytes != want.DiskUsedBytes {
		t.Errorf("DiskUsedBytes = %v, want %v", got.DiskUsedBytes, want.DiskUsedBytes)
	}
	if got.DiskTotalBytes != want.DiskTotalBytes {
		t.Errorf("DiskTotalBytes = %v, want %v", got.DiskTotalBytes, want.DiskTotalBytes)
	}
	if got.NetworkRxBytes != want.NetworkRxBytes {
		t.Errorf("NetworkRxBytes = %v, want %v", got.NetworkRxBytes, want.NetworkRxBytes)
	}
	if got.NetworkTxBytes != want.NetworkTxBytes {
		t.Errorf("NetworkTxBytes = %v, want %v", got.NetworkTxBytes, want.NetworkTxBytes)
	}
}

func TestSystemCollector_CollectContextCancelled(t *testing.T) {
	reader := &mockSystemReader{
		stats: &SystemStats{CPUUsagePercent: 50},
	}
	c := NewSystemCollector(reader, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

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
