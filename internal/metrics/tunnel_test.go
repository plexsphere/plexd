package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestTunnelCollector_Collect(t *testing.T) {
	now := time.Now()
	reader := &mockTunnelStatsReader{
		stats: []TunnelStats{
			{
				PeerID:             "peer-a",
				LastHandshakeTime:  now,
				RxBytes:            100,
				TxBytes:            200,
				HandshakeSucceeded: true,
			},
			{
				PeerID:             "peer-b",
				LastHandshakeTime:  now.Add(-time.Minute),
				RxBytes:            300,
				TxBytes:            400,
				HandshakeSucceeded: false,
			},
		},
	}
	c := NewTunnelCollector(reader, discardLogger())

	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(points) != 2 {
		t.Fatalf("len(points) = %d, want 2", len(points))
	}

	for i, wantPeerID := range []string{"peer-a", "peer-b"} {
		pt := points[i]
		if pt.Group != GroupTunnel {
			t.Errorf("points[%d].Group = %q, want %q", i, pt.Group, GroupTunnel)
		}
		if pt.PeerID != wantPeerID {
			t.Errorf("points[%d].PeerID = %q, want %q", i, pt.PeerID, wantPeerID)
		}
		if pt.Timestamp.IsZero() {
			t.Errorf("points[%d].Timestamp is zero", i)
		}
		if pt.Data == nil {
			t.Errorf("points[%d].Data is nil", i)
		}
	}
}

func TestTunnelCollector_CollectEmpty(t *testing.T) {
	reader := &mockTunnelStatsReader{
		stats: []TunnelStats{},
	}
	c := NewTunnelCollector(reader, discardLogger())

	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if points == nil {
		t.Fatal("points is nil, want empty slice")
	}
	if len(points) != 0 {
		t.Errorf("len(points) = %d, want 0", len(points))
	}
}

func TestTunnelCollector_CollectError(t *testing.T) {
	reader := &mockTunnelStatsReader{
		err: errors.New("wireguard exploded"),
	}
	c := NewTunnelCollector(reader, discardLogger())

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

func TestTunnelCollector_CollectData(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	want := TunnelStats{
		PeerID:             "peer-x",
		LastHandshakeTime:  now,
		RxBytes:            999,
		TxBytes:            888,
		HandshakeSucceeded: true,
	}
	reader := &mockTunnelStatsReader{
		stats: []TunnelStats{want},
	}
	c := NewTunnelCollector(reader, discardLogger())

	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	var got TunnelStats
	if err := json.Unmarshal(points[0].Data, &got); err != nil {
		t.Fatalf("json.Unmarshal(Data) error = %v", err)
	}
	if got.PeerID != want.PeerID {
		t.Errorf("PeerID = %q, want %q", got.PeerID, want.PeerID)
	}
	if !got.LastHandshakeTime.Equal(want.LastHandshakeTime) {
		t.Errorf("LastHandshakeTime = %v, want %v", got.LastHandshakeTime, want.LastHandshakeTime)
	}
	if got.RxBytes != want.RxBytes {
		t.Errorf("RxBytes = %d, want %d", got.RxBytes, want.RxBytes)
	}
	if got.TxBytes != want.TxBytes {
		t.Errorf("TxBytes = %d, want %d", got.TxBytes, want.TxBytes)
	}
	if got.HandshakeSucceeded != want.HandshakeSucceeded {
		t.Errorf("HandshakeSucceeded = %v, want %v", got.HandshakeSucceeded, want.HandshakeSucceeded)
	}
}

func TestTunnelCollector_StaleHandshakeDetection(t *testing.T) {
	now := time.Now()
	threshold := 5 * time.Minute
	reader := &mockTunnelStatsReader{
		stats: []TunnelStats{
			{
				PeerID:             "peer-fresh",
				LastHandshakeTime:  now.Add(-time.Minute), // 1m ago, not stale
				RxBytes:            100,
				TxBytes:            200,
				HandshakeSucceeded: true,
			},
			{
				PeerID:             "peer-stale",
				LastHandshakeTime:  now.Add(-10 * time.Minute), // 10m ago, stale
				RxBytes:            300,
				TxBytes:            400,
				HandshakeSucceeded: true,
			},
			{
				PeerID:             "peer-zero",
				LastHandshakeTime:  time.Time{}, // zero time, not stale
				RxBytes:            0,
				TxBytes:            0,
				HandshakeSucceeded: false,
			},
		},
	}
	c := NewTunnelCollectorWithThreshold(reader, discardLogger(), threshold)

	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(points) != 3 {
		t.Fatalf("len(points) = %d, want 3", len(points))
	}

	// peer-fresh: not stale.
	var fresh TunnelStats
	if err := json.Unmarshal(points[0].Data, &fresh); err != nil {
		t.Fatalf("unmarshal peer-fresh: %v", err)
	}
	if fresh.HandshakeStale {
		t.Error("peer-fresh: HandshakeStale = true, want false")
	}

	// peer-stale: stale.
	var stale TunnelStats
	if err := json.Unmarshal(points[1].Data, &stale); err != nil {
		t.Fatalf("unmarshal peer-stale: %v", err)
	}
	if !stale.HandshakeStale {
		t.Error("peer-stale: HandshakeStale = false, want true")
	}

	// peer-zero: zero time, not stale.
	var zero TunnelStats
	if err := json.Unmarshal(points[2].Data, &zero); err != nil {
		t.Fatalf("unmarshal peer-zero: %v", err)
	}
	if zero.HandshakeStale {
		t.Error("peer-zero: HandshakeStale = true, want false (zero time should not be stale)")
	}
}

func TestTunnelCollector_DefaultStaleThreshold(t *testing.T) {
	reader := &mockTunnelStatsReader{stats: []TunnelStats{}}
	c := NewTunnelCollector(reader, discardLogger())
	if c.staleThreshold != DefaultStaleThreshold {
		t.Errorf("staleThreshold = %v, want %v", c.staleThreshold, DefaultStaleThreshold)
	}
}

func TestTunnelCollector_CustomThresholdNegativeFallsBack(t *testing.T) {
	reader := &mockTunnelStatsReader{stats: []TunnelStats{}}
	c := NewTunnelCollectorWithThreshold(reader, discardLogger(), -1*time.Minute)
	if c.staleThreshold != DefaultStaleThreshold {
		t.Errorf("staleThreshold = %v, want %v (fallback for negative)", c.staleThreshold, DefaultStaleThreshold)
	}
}
