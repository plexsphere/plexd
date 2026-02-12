package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// MetricsReporter abstracts the control plane metrics reporting API.
type MetricsReporter interface {
	ReportMetrics(ctx context.Context, nodeID string, batch api.MetricBatch) error
}

// Manager orchestrates metric collection and reporting.
type Manager struct {
	cfg        Config
	collectors []Collector
	reporter   MetricsReporter
	nodeID     string
	logger     *slog.Logger

	mu     sync.Mutex
	buffer []api.MetricPoint
}

// NewManager creates a new Manager. Config defaults are applied automatically.
func NewManager(cfg Config, collectors []Collector, reporter MetricsReporter, nodeID string, logger *slog.Logger) *Manager {
	cfg.ApplyDefaults()
	return &Manager{
		cfg:        cfg,
		collectors: collectors,
		reporter:   reporter,
		nodeID:     nodeID,
		logger:     logger,
	}
}

// RegisterCollector adds a collector to the manager.
// Must be called before Run; it is not safe for concurrent use.
func (m *Manager) RegisterCollector(c Collector) {
	m.collectors = append(m.collectors, c)
}

// Run starts the collect and report loops. It blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	if !m.cfg.Enabled {
		m.logger.Info("metrics disabled, skipping collection", "component", "metrics")
		return nil
	}

	// First cycle runs immediately.
	m.collect(ctx)

	collectTicker := time.NewTicker(m.cfg.CollectInterval)
	defer collectTicker.Stop()

	reportTicker := time.NewTicker(m.cfg.ReportInterval)
	defer reportTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.flush(context.Background())
			return ctx.Err()
		case <-collectTicker.C:
			m.collect(ctx)
		case <-reportTicker.C:
			m.flush(ctx)
		}
	}
}

// collect runs all collectors with panic recovery and appends results to the buffer.
func (m *Manager) collect(ctx context.Context) {
	for _, c := range m.collectors {
		points, err := m.safeCollect(ctx, c)
		if err != nil {
			m.logger.Warn("collector failed", "component", "metrics", "error", err)
			continue
		}
		m.mu.Lock()
		m.buffer = append(m.buffer, points...)
		m.enforceCapacity()
		m.mu.Unlock()
	}
}

// safeCollect calls a collector with panic recovery.
func (m *Manager) safeCollect(ctx context.Context, c Collector) (points []api.MetricPoint, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("collector panicked: %v\n%s", v, debug.Stack())
		}
	}()
	return c.Collect(ctx)
}

// enforceCapacity drops the oldest points when buffer exceeds 2*BatchSize.
// Must be called with m.mu held.
func (m *Manager) enforceCapacity() {
	limit := 2 * m.cfg.BatchSize
	if len(m.buffer) > limit {
		m.buffer = m.buffer[len(m.buffer)-limit:]
	}
}

// flush sends buffered metrics to the reporter in batches of BatchSize.
// On reporter error, unsent data is retained in the buffer.
func (m *Manager) flush(ctx context.Context) {
	m.mu.Lock()
	batch := m.buffer
	m.buffer = nil
	m.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	batchSize := m.cfg.BatchSize
	for len(batch) > 0 {
		chunk := batch[:min(batchSize, len(batch))]

		if err := m.reporter.ReportMetrics(ctx, m.nodeID, chunk); err != nil {
			m.logger.Warn("metrics report failed", "component", "metrics", "error", err)
			// Retain unsent data: put remaining batch back into buffer.
			m.mu.Lock()
			m.buffer = append(batch, m.buffer...)
			m.enforceCapacity()
			m.mu.Unlock()
			return
		}

		batch = batch[len(chunk):]
	}
}
