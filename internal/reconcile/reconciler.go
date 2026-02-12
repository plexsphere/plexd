package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// StateFetcher retrieves desired state and reports drift to the control plane.
type StateFetcher interface {
	FetchState(ctx context.Context, nodeID string) (*api.StateResponse, error)
	ReportDrift(ctx context.Context, nodeID string, req api.DriftReport) error
}

// ReconcileHandler is a function invoked when drift is detected.
type ReconcileHandler func(ctx context.Context, desired *api.StateResponse, diff StateDiff) error

// Reconciler periodically compares desired state against a local snapshot
// and invokes registered handlers to correct drift.
type Reconciler struct {
	client    StateFetcher
	cfg       Config
	logger    *slog.Logger
	snapshot  *stateSnapshot
	handlers  []ReconcileHandler
	triggerCh chan struct{}
}

// NewReconciler creates a new Reconciler with the given configuration.
// Config defaults are applied automatically.
func NewReconciler(client StateFetcher, cfg Config, logger *slog.Logger) *Reconciler {
	cfg.ApplyDefaults()
	return &Reconciler{
		client:    client,
		cfg:       cfg,
		logger:    logger,
		snapshot:  NewStateSnapshot(),
		triggerCh: make(chan struct{}, 1),
	}
}

// RegisterHandler adds a reconciliation handler invoked on drift detection.
// Handlers are called in registration order.
// RegisterHandler must be called before Run; it is not safe for concurrent use.
func (r *Reconciler) RegisterHandler(handler ReconcileHandler) {
	r.handlers = append(r.handlers, handler)
}

// TriggerReconcile requests an immediate reconciliation cycle.
// Multiple rapid calls are coalesced — only one extra cycle runs.
func (r *Reconciler) TriggerReconcile() {
	select {
	case r.triggerCh <- struct{}{}:
	default:
		// Already a trigger pending; coalesce.
	}
}

// Run starts the reconciliation loop. It blocks until ctx is cancelled.
// The first cycle runs immediately; subsequent cycles run at cfg.Interval
// or when TriggerReconcile is called.
func (r *Reconciler) Run(ctx context.Context, nodeID string) error {
	if r.client == nil {
		return errors.New("reconcile: client is nil")
	}
	if nodeID == "" {
		return errors.New("reconcile: nodeID is empty")
	}

	r.logger.Info("reconciler started",
		"component", "reconcile",
		"node_id", nodeID,
		"interval", r.cfg.Interval,
	)

	// First cycle runs immediately.
	r.runCycle(ctx, nodeID)

	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("reconciler stopped",
				"component", "reconcile",
				"node_id", nodeID,
			)
			return ctx.Err()

		case <-ticker.C:
			r.runCycle(ctx, nodeID)

		case <-r.triggerCh:
			r.runCycle(ctx, nodeID)
			// Reset the ticker after a triggered cycle.
			ticker.Reset(r.cfg.Interval)
		}
	}
}

// runCycle performs a single reconciliation cycle: fetch → diff → handle → report → update snapshot.
func (r *Reconciler) runCycle(ctx context.Context, nodeID string) {
	start := time.Now()

	desired, err := r.client.FetchState(ctx, nodeID)
	if err != nil {
		// Don't log if the context was cancelled (graceful shutdown).
		if ctx.Err() == nil {
			r.logger.Warn("FetchState failed",
				"component", "reconcile",
				"node_id", nodeID,
				"error", err,
			)
		}
		return
	}

	current := r.snapshot.Get()
	diff := ComputeDiff(desired, &current)

	if diff.IsEmpty() {
		r.logger.Debug("no drift detected",
			"component", "reconcile",
			"node_id", nodeID,
			"duration", time.Since(start),
		)
		return
	}

	// Invoke all handlers, tracking which had errors.
	handlerFailed := r.invokeHandlers(ctx, desired, diff)

	// Build and report drift.
	report := BuildDriftReport(diff)
	if err := r.client.ReportDrift(ctx, nodeID, report); err != nil {
		if ctx.Err() == nil {
			r.logger.Warn("ReportDrift failed",
				"component", "reconcile",
				"node_id", nodeID,
				"error", err,
			)
		}
	}

	// Update snapshot only if no handler failed.
	if !handlerFailed {
		r.snapshot.Update(desired)
	}

	r.logger.Info("reconciliation cycle completed",
		"component", "reconcile",
		"node_id", nodeID,
		"drift_count", len(report.Corrections),
		"duration", time.Since(start),
		"handler_failed", handlerFailed,
	)
}

// invokeHandlers calls each registered handler with panic recovery.
// Returns true if any handler returned an error or panicked.
func (r *Reconciler) invokeHandlers(ctx context.Context, desired *api.StateResponse, diff StateDiff) bool {
	anyFailed := false
	for i, handler := range r.handlers {
		if err := r.safeInvoke(ctx, handler, desired, diff); err != nil {
			r.logger.Error("handler failed",
				"component", "reconcile",
				"handler_index", i,
				"error", err,
			)
			anyFailed = true
		}
	}
	return anyFailed
}

// safeInvoke calls a handler with panic recovery.
func (r *Reconciler) safeInvoke(ctx context.Context, handler ReconcileHandler, desired *api.StateResponse, diff StateDiff) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("handler panicked: %v\n%s", v, debug.Stack())
		}
	}()
	return handler(ctx, desired, diff)
}
