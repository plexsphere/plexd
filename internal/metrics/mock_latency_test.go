package metrics

import (
	"context"
	"sync"
)

// mockPinger is a test double for Pinger.
type mockPinger struct {
	mu sync.Mutex

	// results maps peerID to (rttNano, error).
	results map[string]struct {
		rtt int64
		err error
	}

	// calls records the peer IDs passed to Ping.
	calls []string
}

func (m *mockPinger) Ping(ctx context.Context, peerID string) (int64, error) {
	m.mu.Lock()
	m.calls = append(m.calls, peerID)
	results := m.results
	m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	if results != nil {
		if r, ok := results[peerID]; ok {
			return r.rtt, r.err
		}
	}
	return 0, nil
}

// mockPeerLister is a test double for PeerLister.
type mockPeerLister struct {
	mu    sync.Mutex
	peers []string
}

func (m *mockPeerLister) PeerIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.peers))
	copy(out, m.peers)
	return out
}
