package metrics

import (
	"context"
	"sync"
)

// mockTunnelStatsReader is a test double for TunnelStatsReader.
type mockTunnelStatsReader struct {
	mu    sync.Mutex
	stats []TunnelStats
	err   error
	calls int
}

func (m *mockTunnelStatsReader) ReadTunnelStats(ctx context.Context) ([]TunnelStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.stats, m.err
}
