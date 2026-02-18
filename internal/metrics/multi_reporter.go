package metrics

import (
	"context"
	"log/slog"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
)

// MultiReporter fans out metric reporting to both a platform and a local
// MetricsReporter concurrently. The platform error is surfaced to the caller;
// a local error is logged as a warning but does not fail the call.
type MultiReporter struct {
	platform MetricsReporter
	local    MetricsReporter
	logger   *slog.Logger
}

// NewMultiReporter creates a MultiReporter that reports to both platform and
// local reporters.
func NewMultiReporter(platform, local MetricsReporter, logger *slog.Logger) *MultiReporter {
	return &MultiReporter{
		platform: platform,
		local:    local,
		logger:   logger,
	}
}

// ReportMetrics sends the batch to both reporters concurrently. The platform
// error is returned; a local error is logged as a warning.
func (m *MultiReporter) ReportMetrics(ctx context.Context, nodeID string, batch api.MetricBatch) error {
	var (
		wg          sync.WaitGroup
		platformErr error
		localErr    error
	)

	wg.Add(2)

	go func() {
		defer wg.Done()
		platformErr = m.platform.ReportMetrics(ctx, nodeID, batch)
	}()

	go func() {
		defer wg.Done()
		localErr = m.local.ReportMetrics(ctx, nodeID, batch)
	}()

	wg.Wait()

	if localErr != nil {
		m.logger.Warn("local metrics report failed", "component", "metrics", "error", localErr)
	}

	return platformErr
}
