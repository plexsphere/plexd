package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

func TestLatencyCollector_Collect(t *testing.T) {
	pinger := &mockPinger{
		results: map[string]struct {
			rtt int64
			err error
		}{
			"peer-a": {rtt: 1000000, err: nil},
			"peer-b": {rtt: 2000000, err: nil},
		},
	}
	lister := &mockPeerLister{peers: []string{"peer-a", "peer-b"}}

	c := NewLatencyCollector(pinger, lister, discardLogger())
	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(points) != 2 {
		t.Fatalf("expected 2 points, got %d", len(points))
	}

	for i, wantPeer := range []string{"peer-a", "peer-b"} {
		if points[i].PeerID != wantPeer {
			t.Errorf("point[%d].PeerID = %q, want %q", i, points[i].PeerID, wantPeer)
		}
		if points[i].Group != GroupLatency {
			t.Errorf("point[%d].Group = %q, want %q", i, points[i].Group, GroupLatency)
		}
	}
}

func TestLatencyCollector_CollectNoPeers(t *testing.T) {
	pinger := &mockPinger{}
	lister := &mockPeerLister{peers: []string{}}

	c := NewLatencyCollector(pinger, lister, discardLogger())
	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if points == nil {
		t.Fatal("expected empty slice, got nil")
	}
	if len(points) != 0 {
		t.Fatalf("expected 0 points, got %d", len(points))
	}
}

func TestLatencyCollector_CollectPingError(t *testing.T) {
	pinger := &mockPinger{
		results: map[string]struct {
			rtt int64
			err error
		}{
			"peer-ok":   {rtt: 5000000, err: nil},
			"peer-fail": {rtt: 0, err: errors.New("timeout")},
		},
	}
	lister := &mockPeerLister{peers: []string{"peer-ok", "peer-fail"}}

	c := NewLatencyCollector(pinger, lister, discardLogger())
	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(points) != 2 {
		t.Fatalf("expected 2 points, got %d", len(points))
	}

	// peer-ok should have correct RTT.
	var okResult LatencyResult
	if err := json.Unmarshal(points[0].Data, &okResult); err != nil {
		t.Fatalf("unmarshal point[0]: %v", err)
	}
	if okResult.RTTNano != 5000000 {
		t.Errorf("peer-ok RTTNano = %d, want 5000000", okResult.RTTNano)
	}

	// peer-fail should have RTTNano=-1.
	var failResult LatencyResult
	if err := json.Unmarshal(points[1].Data, &failResult); err != nil {
		t.Fatalf("unmarshal point[1]: %v", err)
	}
	if failResult.RTTNano != -1 {
		t.Errorf("peer-fail RTTNano = %d, want -1", failResult.RTTNano)
	}
}

func TestLatencyCollector_CollectData(t *testing.T) {
	pinger := &mockPinger{
		results: map[string]struct {
			rtt int64
			err error
		}{
			"peer-x": {rtt: 42000, err: nil},
		},
	}
	lister := &mockPeerLister{peers: []string{"peer-x"}}

	c := NewLatencyCollector(pinger, lister, discardLogger())
	points, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("expected 1 point, got %d", len(points))
	}

	var result LatencyResult
	if err := json.Unmarshal(points[0].Data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.PeerID != "peer-x" {
		t.Errorf("PeerID = %q, want %q", result.PeerID, "peer-x")
	}
	if result.RTTNano != 42000 {
		t.Errorf("RTTNano = %d, want 42000", result.RTTNano)
	}
}

func TestLatencyCollector_CollectContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	pinger := &mockPinger{
		results: map[string]struct {
			rtt int64
			err error
		}{
			"peer-1": {rtt: 100, err: nil},
			"peer-2": {rtt: 200, err: nil},
			"peer-3": {rtt: 300, err: nil},
		},
	}

	// Cancel context after first peer is pinged.
	cancelAfterFirst := &cancellingPinger{
		inner:      pinger,
		cancelAt:   1, // cancel after peer-1 (index 0) completes, before peer-2
		cancelFunc: cancel,
	}

	lister := &mockPeerLister{peers: []string{"peer-1", "peer-2", "peer-3"}}

	c := NewLatencyCollector(cancelAfterFirst, lister, discardLogger())
	points, err := c.Collect(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	// Should have at least the first peer's result.
	if len(points) < 1 {
		t.Fatalf("expected at least 1 partial result, got %d", len(points))
	}
	if points[0].PeerID != "peer-1" {
		t.Errorf("points[0].PeerID = %q, want %q", points[0].PeerID, "peer-1")
	}
}

// cancellingPinger wraps a Pinger and cancels the context after N calls.
type cancellingPinger struct {
	inner      Pinger
	cancelAt   int
	cancelFunc context.CancelFunc

	mu    sync.Mutex
	count int
}

func (p *cancellingPinger) Ping(ctx context.Context, peerID string) (int64, error) {
	rtt, err := p.inner.Ping(ctx, peerID)

	p.mu.Lock()
	p.count++
	n := p.count
	p.mu.Unlock()

	if n >= p.cancelAt {
		p.cancelFunc()
	}
	return rtt, err
}
