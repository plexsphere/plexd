package metrics

import (
	"context"
	"sync"
)

// mockSystemReader is a test double for SystemReader.
type mockSystemReader struct {
	mu    sync.Mutex
	stats *SystemStats
	err   error
	calls int
}

func (m *mockSystemReader) ReadStats(ctx context.Context) (*SystemStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.stats, m.err
}
