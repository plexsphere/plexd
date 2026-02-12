package metrics

import (
	"context"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
)

// mockCollector records calls and returns configured results.
type mockCollector struct {
	mu     sync.Mutex
	calls  int
	points []api.MetricPoint
	err    error
}

func (m *mockCollector) Collect(_ context.Context) ([]api.MetricPoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.points, nil
}

func (m *mockCollector) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// mockReportCall records a single ReportMetrics invocation.
type mockReportCall struct {
	NodeID string
	Batch  api.MetricBatch
}

// mockReporter records ReportMetrics calls.
type mockReporter struct {
	mu    sync.Mutex
	calls []mockReportCall
	err   error

	// errOnce causes the first call to fail, then succeeds.
	errOnce bool
}

func (m *mockReporter) ReportMetrics(_ context.Context, nodeID string, batch api.MetricBatch) error {
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

func (m *mockReporter) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// panicCollector is a Collector that panics on every Collect call.
type panicCollector struct {
	msg string
}

func (p *panicCollector) Collect(_ context.Context) ([]api.MetricPoint, error) {
	panic(p.msg)
}
