package logfwd

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// Forwarder orchestrates log collection and reporting.
type Forwarder struct {
	cfg      Config
	sources  []LogSource
	reporter LogReporter
	nodeID   string
	hostname string
	logger   *slog.Logger

	mu     sync.Mutex
	buffer []api.LogEntry
}

// NewForwarder creates a new Forwarder. Config defaults are applied automatically.
func NewForwarder(cfg Config, sources []LogSource, reporter LogReporter, nodeID string, hostname string, logger *slog.Logger) *Forwarder {
	cfg.ApplyDefaults()
	return &Forwarder{
		cfg:      cfg,
		sources:  sources,
		reporter: reporter,
		nodeID:   nodeID,
		hostname: hostname,
		logger:   logger,
	}
}

// RegisterSource adds a log source to the forwarder.
// Must be called before Run; it is not safe for concurrent use.
func (f *Forwarder) RegisterSource(s LogSource) {
	f.sources = append(f.sources, s)
}

// Run starts the collect and report loops. It blocks until ctx is cancelled.
func (f *Forwarder) Run(ctx context.Context) error {
	if !f.cfg.Enabled {
		f.logger.Info("log forwarding disabled, skipping", "component", "logfwd")
		return nil
	}

	// First cycle runs immediately.
	f.collect(ctx)

	collectTicker := time.NewTicker(f.cfg.CollectInterval)
	defer collectTicker.Stop()

	reportTicker := time.NewTicker(f.cfg.ReportInterval)
	defer reportTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			f.flush(context.Background())
			return ctx.Err()
		case <-collectTicker.C:
			f.collect(ctx)
		case <-reportTicker.C:
			f.flush(ctx)
		}
	}
}

// collect runs all sources with panic recovery and appends results to the buffer.
func (f *Forwarder) collect(ctx context.Context) {
	for _, s := range f.sources {
		entries, err := f.safeCollect(ctx, s)
		if err != nil {
			f.logger.Warn("source failed", "component", "logfwd", "error", err)
			continue
		}
		f.mu.Lock()
		f.buffer = append(f.buffer, entries...)
		f.enforceCapacity()
		f.mu.Unlock()
	}
}

// safeCollect calls a source with panic recovery.
func (f *Forwarder) safeCollect(ctx context.Context, s LogSource) (entries []api.LogEntry, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("source panicked: %v\n%s", v, debug.Stack())
		}
	}()
	return s.Collect(ctx)
}

// enforceCapacity drops the oldest entries when buffer exceeds 2*BatchSize.
// Must be called with f.mu held.
func (f *Forwarder) enforceCapacity() {
	limit := 2 * f.cfg.BatchSize
	if len(f.buffer) > limit {
		dropped := len(f.buffer) - limit
		f.logger.Warn("buffer overflow, dropping oldest entries", "component", "logfwd", "dropped", dropped)
		f.buffer = f.buffer[len(f.buffer)-limit:]
	}
}

// flush sends buffered log entries to the reporter in batches of BatchSize.
// On reporter error, unsent data is retained in the buffer.
func (f *Forwarder) flush(ctx context.Context) {
	f.mu.Lock()
	batch := f.buffer
	f.buffer = nil
	f.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	batchSize := f.cfg.BatchSize
	for len(batch) > 0 {
		chunk := batch[:min(batchSize, len(batch))]

		if err := f.reporter.ReportLogs(ctx, f.nodeID, chunk); err != nil {
			f.logger.Warn("log report failed", "component", "logfwd", "error", err)
			// Retain unsent data: put remaining batch back into buffer.
			f.mu.Lock()
			f.buffer = append(batch, f.buffer...)
			f.enforceCapacity()
			f.mu.Unlock()
			return
		}

		batch = batch[len(chunk):]
	}
}
