package nodeapi

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ReportSyncClient is the interface for syncing reports to the control plane.
type ReportSyncClient interface {
	SyncReports(ctx context.Context, nodeID string, req api.ReportSyncRequest) error
}

// ReportSyncer buffers report changes and syncs them to the control plane
// with debouncing to coalesce rapid updates.
type ReportSyncer struct {
	client         ReportSyncClient
	nodeID         string
	debouncePeriod time.Duration
	logger         *slog.Logger

	mu       sync.Mutex
	entries  []api.ReportEntry
	deleted  []string
	pending  bool
	notifyCh chan struct{}
}

// NewReportSyncer creates a new ReportSyncer.
func NewReportSyncer(client ReportSyncClient, nodeID string, debouncePeriod time.Duration, logger *slog.Logger) *ReportSyncer {
	return &ReportSyncer{
		client:         client,
		nodeID:         nodeID,
		debouncePeriod: debouncePeriod,
		logger:         logger,
		notifyCh:       make(chan struct{}, 1),
	}
}

// NotifyChange buffers report changes and signals the run loop.
// Entries are appended; later entries for the same key overwrite earlier ones.
// Deleted keys are appended.
func (s *ReportSyncer) NotifyChange(entries []api.ReportEntry, deleted []string) {
	s.mu.Lock()
	s.entries = append(s.entries, entries...)
	s.deleted = append(s.deleted, deleted...)
	s.pending = true
	s.mu.Unlock()

	// Non-blocking send to signal the run loop.
	select {
	case s.notifyCh <- struct{}{}:
	default:
	}
}

// Run loops, waiting for change notifications, debouncing, and flushing.
// It returns ctx.Err() when the context is cancelled.
func (s *ReportSyncer) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.notifyCh:
			// Debounce: wait for the debounce period, collecting more changes.
			timer := time.NewTimer(s.debouncePeriod)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			// Flush
			s.flush(ctx)
		}
	}
}

func (s *ReportSyncer) flush(ctx context.Context) {
	s.mu.Lock()
	entries := s.entries
	deleted := s.deleted
	s.entries = nil
	s.deleted = nil
	s.pending = false
	s.mu.Unlock()

	if len(entries) == 0 && len(deleted) == 0 {
		return
	}

	req := api.ReportSyncRequest{
		Entries: entries,
		Deleted: deleted,
	}

	if err := s.client.SyncReports(ctx, s.nodeID, req); err != nil {
		if ctx.Err() != nil {
			return
		}
		s.logger.Warn("report sync failed",
			"component", "nodeapi",
			"error", err,
			"entries_count", len(entries),
			"deleted_count", len(deleted),
		)
		// Re-buffer on failure.
		s.mu.Lock()
		s.entries = append(entries, s.entries...)
		s.deleted = append(deleted, s.deleted...)
		s.pending = true
		s.mu.Unlock()
		// Signal to retry.
		select {
		case s.notifyCh <- struct{}{}:
		default:
		}
		return
	}

	s.logger.Info("report sync completed",
		"component", "nodeapi",
		"entries_count", len(entries),
		"deleted_count", len(deleted),
	)
}
