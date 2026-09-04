package metrics

import (
	"context"
	"log/slog"
	"sync"
)

// degradeLog keeps track of which system metrics a reader has already reported
// as unavailable. The macOS and Windows readers are best-effort: a source that
// is missing or blocked on a host stays missing for the lifetime of the
// process, so it costs one warning instead of one per collect cycle. The
// metric names the readers pass are cpu, memory, load, disk and network.
type degradeLog struct {
	logger *slog.Logger
	mu     sync.Mutex
	warned map[string]bool
}

// newDegradeLog creates a degradeLog writing to logger. A nil logger discards
// every message.
func newDegradeLog(logger *slog.Logger) *degradeLog {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &degradeLog{
		logger: logger,
		warned: make(map[string]bool),
	}
}

// report records that metric could not be read. The first report for a metric
// logs at warn level, every later one at debug level.
func (d *degradeLog) report(metric string, err error) {
	d.mu.Lock()
	level := slog.LevelDebug
	if !d.warned[metric] {
		d.warned[metric] = true
		level = slog.LevelWarn
	}
	d.mu.Unlock()

	d.logger.Log(context.Background(), level, "system metric unavailable",
		"component", "metrics",
		"metric", metric,
		"error", err,
	)
}
