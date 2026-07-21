package nodeapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ReportSyncClient publishes per-key node state reports to the control plane.
type ReportSyncClient interface {
	PutStateReport(ctx context.Context, nodeID, key string, req api.NodeStateReportRequest) (*api.NodeStateReportResponse, error)
	DeleteStateReport(ctx context.Context, nodeID, key string) error
}

const (
	// defaultReportRetryInterval is how long the run loop waits before
	// re-flushing keys left dirty by a retryable failure, absent a new local
	// mutation. Stored as a field so tests can shorten it.
	defaultReportRetryInterval = 30 * time.Second

	// notProvisionedSuppression is how long the syncer suppresses every HTTP
	// attempt after the control plane reports that report ingest is not
	// provisioned, so a node that is simply not yet enrolled does not hammer
	// the endpoint.
	notProvisionedSuppression = 5 * time.Minute
)

// ReportSyncer reconciles per-key report changes to the control plane. Changes
// are held in a dirty map keyed by report key; a nil value marks a pending
// delete. NotifyChange debounces to coalesce bursts, flush walks the dirty keys
// in ascending order publishing one at a time, and keys left dirty by a
// retryable failure are re-flushed on a timer so state converges without a new
// local mutation.
type ReportSyncer struct {
	client         ReportSyncClient
	debouncePeriod time.Duration
	retryInterval  time.Duration
	logger         *slog.Logger

	mu    sync.Mutex
	dirty map[string]*ReportEntry // nil value = delete pending

	// notProvisioned and notProvisionedUntil are read and written only from the
	// single Run goroutine. notProvisioned gates the once-only Info transition
	// logs; notProvisionedUntil is the deadline until which HTTP is suppressed.
	notProvisioned      bool
	notProvisionedUntil time.Time

	notifyCh chan struct{}
}

// NewReportSyncer creates a ReportSyncer. The node ID is supplied later to Run
// because the syncer is constructed in NewServer, before the node has
// registered and its ID is known.
func NewReportSyncer(client ReportSyncClient, debouncePeriod time.Duration, logger *slog.Logger) *ReportSyncer {
	if logger == nil {
		logger = slog.Default()
	}
	return &ReportSyncer{
		client:         client,
		debouncePeriod: debouncePeriod,
		retryInterval:  defaultReportRetryInterval,
		logger:         logger,
		dirty:          make(map[string]*ReportEntry),
		notifyCh:       make(chan struct{}, 1),
	}
}

// NotifyChange merges report changes into the dirty map and wakes the run loop.
// entries are pending PUTs and deleted keys are pending deletes; the last change
// to a given key wins.
func (s *ReportSyncer) NotifyChange(entries []ReportEntry, deleted []string) {
	s.mu.Lock()
	for i := range entries {
		e := entries[i]
		s.dirty[e.Key] = &e
	}
	for _, key := range deleted {
		s.dirty[key] = nil
	}
	s.mu.Unlock()

	// Non-blocking signal to the run loop.
	select {
	case s.notifyCh <- struct{}{}:
	default:
	}
}

// Run reconciles report changes to the control plane for nodeID until ctx is
// cancelled, at which point it returns ctx.Err(). Dirty state is preserved in
// memory across the return so a subsequent Run resumes where this one left off.
func (s *ReportSyncer) Run(ctx context.Context, nodeID string) error {
	var retry *time.Timer
	var retryC <-chan time.Time
	stopRetry := func() {
		if retry != nil {
			retry.Stop()
			retry = nil
			retryC = nil
		}
	}
	armRetry := func() {
		stopRetry()
		retry = time.NewTimer(s.retryInterval)
		retryC = retry.C
	}
	defer stopRetry()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.notifyCh:
			// Debounce: coalesce a burst of changes before flushing.
			timer := time.NewTimer(s.debouncePeriod)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			stopRetry()
			if s.flush(ctx, nodeID) {
				armRetry()
			}
		case <-retryC:
			retry = nil
			retryC = nil
			if s.flush(ctx, nodeID) {
				armRetry()
			}
		}
	}
}

// syncOutcome is the per-key result of a flush attempt.
type syncOutcome int

const (
	// syncOK: the control plane acknowledged the change (or the change is a
	// no-op it already reflects); clear the key if still unchanged.
	syncOK syncOutcome = iota
	// syncKeepDirty: a transient failure; leave the key dirty and retry later.
	syncKeepDirty
	// syncNotProvisioned: report ingest is not provisioned; abort the flush and
	// suppress HTTP for the suppression window.
	syncNotProvisioned
)

// flush snapshots the dirty map and reconciles each key to the control plane in
// ascending key order. It returns true when dirty keys remain for a retryable
// reason and the run loop should arm the retry timer.
func (s *ReportSyncer) flush(ctx context.Context, nodeID string) bool {
	// While report ingest is known not to be provisioned, suppress every HTTP
	// attempt until the window elapses; the keys stay dirty for the next round.
	if s.notProvisioned && time.Now().Before(s.notProvisionedUntil) {
		return s.hasDirty()
	}

	s.mu.Lock()
	snapshot := make(map[string]*ReportEntry, len(s.dirty))
	for k, v := range s.dirty {
		snapshot[k] = v
	}
	s.mu.Unlock()

	if len(snapshot) == 0 {
		return false
	}

	keys := make([]string, 0, len(snapshot))
	for k := range snapshot {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	retry := false
	for _, key := range keys {
		if ctx.Err() != nil {
			// Shutting down: leave the remaining keys dirty for the next Run.
			return false
		}
		switch s.syncKey(ctx, nodeID, key, snapshot[key]) {
		case syncOK:
			s.markProvisioned()
			s.clearIfUnchanged(key, snapshot[key])
		case syncKeepDirty:
			retry = true
		case syncNotProvisioned:
			s.enterNotProvisioned()
			// Abort: every remaining key stays dirty until the window elapses.
			return true
		}
	}
	return retry
}

// syncKey publishes a single key: a nil entry is a delete, otherwise a PUT.
func (s *ReportSyncer) syncKey(ctx context.Context, nodeID, key string, entry *ReportEntry) syncOutcome {
	if entry == nil {
		err := s.client.DeleteStateReport(ctx, nodeID, key)
		if err == nil {
			return syncOK
		}
		var apiErr *api.APIError
		if errors.As(err, &apiErr) {
			if apiErr.StatusCode == 404 && apiErr.Code == "report_not_found" {
				// Idempotent: the report is already absent upstream.
				s.logger.Debug("report already absent on control plane", "key", key)
				return syncOK
			}
			if apiErr.StatusCode == 501 && apiErr.Code == "reports_not_provisioned" {
				return syncNotProvisioned
			}
		}
		s.logger.Warn("report delete failed", "key", key, "error", err)
		return syncKeepDirty
	}

	_, err := s.client.PutStateReport(ctx, nodeID, key, api.NodeStateReportRequest{Value: string(entry.Payload)})
	if err == nil {
		return syncOK
	}
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == 400 && apiErr.Code == "invalid_report" {
			// Permanent refusal: dropping the key avoids retrying forever. This
			// is unreachable once the local API validates the same grammar and
			// value cap, and is kept as defense in depth.
			s.logger.Warn("control plane refused report as invalid; dropping key", "key", key)
			return syncOK
		}
		if apiErr.StatusCode == 501 && apiErr.Code == "reports_not_provisioned" {
			return syncNotProvisioned
		}
	}
	s.logger.Warn("report put failed", "key", key, "error", err)
	return syncKeepDirty
}

// clearIfUnchanged removes key from the dirty map only if it still holds the
// snapshotted state, so a change that raced the flush stays dirty for the next
// round. For a PUT the pending payload must match; for a delete the pending
// entry must still be nil.
//
// The version alone is not an identity: StateCache.PutReport restarts at 1 for
// a key that does not exist, so a DELETE followed by a fresh PUT that races an
// in-flight publish produces a different payload at the same version 1. The
// payload is what the PUT actually carried upstream, so comparing the bytes is
// what decides whether the publish satisfied the pending change.
func (s *ReportSyncer) clearIfUnchanged(key string, snapped *ReportEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.dirty[key]
	if !ok {
		return
	}
	if snapped == nil {
		if cur == nil {
			delete(s.dirty, key)
		}
		return
	}
	if cur != nil && cur.Version == snapped.Version && bytes.Equal(cur.Payload, snapped.Payload) {
		delete(s.dirty, key)
	}
}

// hasDirty reports whether any keys are still pending.
func (s *ReportSyncer) hasDirty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.dirty) > 0
}

// enterNotProvisioned records the not-provisioned state and arms the suppression
// window. The Info transition is logged only on the first entry, not on every
// repeated 501.
func (s *ReportSyncer) enterNotProvisioned() {
	if !s.notProvisioned {
		s.logger.Info("report ingest not provisioned; suppressing report sync",
			"suppression", notProvisionedSuppression)
	}
	s.notProvisioned = true
	s.notProvisionedUntil = time.Now().Add(notProvisionedSuppression)
}

// markProvisioned clears the not-provisioned state after the first successful
// exchange that follows it, logging the recovery once.
func (s *ReportSyncer) markProvisioned() {
	if s.notProvisioned {
		s.logger.Info("report ingest provisioned; resuming report sync")
		s.notProvisioned = false
		s.notProvisionedUntil = time.Time{}
	}
}
