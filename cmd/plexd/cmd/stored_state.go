package cmd

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/statestore"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// storedStateClockTolerance is how far a stored state's saved_at may lie
// ahead of the clock under a maximum age: the skew the control plane
// tolerates on a heartbeat. A clock further behind cannot measure the age,
// so it cannot honor the limit either.
const storedStateClockTolerance = 60 * time.Second

// storedStateDeps is what restoreStoredState applies the stored state
// through.
type storedStateDeps struct {
	store      *statestore.Store
	reconciler *reconcile.Reconciler
	// edgePSKs is nil when edge PSKs are off.
	edgePSKs *wireguard.EdgePSKs
	// failureDetection is the WireGuard manager's failure-detection dispatch
	// handler; nil when WireGuard did not come up.
	failureDetection reconcile.DispatchHandler
	// policy is the Enforcer's dispatch handler.
	policy reconcile.DispatchHandler
	// secretInventory are the bridge's secret inventory handlers, of the
	// ingress, user access and site-to-site managers that exist; empty
	// outside bridge mode.
	secretInventory []reconcile.DispatchHandler
	logger          *slog.Logger
}

// restoreStoredState applies the desired state of the last successful pull,
// which the state store kept in the data directory, before the reconciler's
// first pull, so a node that restarts while the control plane is unreachable
// comes back with the peers, the PSKs and the policy it last applied. It is
// a pull's apply without the pull: the failure-detection, policy and secret
// inventory dispatch handlers and then the reconcile handlers get the stored
// blocks, and the first successful pull diffs against them. The bridge
// managers take the stored inventory, names and versions, before the stored
// bridge block, so a part whose Secret the control plane serves fetches it
// and comes up at the restore; without the control plane it stays down with
// its reason until a pull. It runs on the goroutine that then runs the
// reconciler.
//
// A state that is missing, unreadable, another node's, older than the
// maximum age stored with it, or saved further ahead of the clock than
// storedStateClockTolerance under a maximum age is not restored, and the
// node starts as it would without one; the next successful pull overwrites
// the file. Without a maximum age the age is not checked. A restore marker
// brackets the apply, so a stored state that kills the process while it is
// applied is discarded at the next start (see statestore.Store.Load).
func restoreStoredState(ctx context.Context, d storedStateDeps) {
	file, err := d.store.Load()
	switch {
	case errors.Is(err, statestore.ErrNoState):
		d.logger.Debug("no stored state")
		return
	case errors.Is(err, statestore.ErrInterrupted):
		d.logger.Warn("stored state discarded, the previous restore did not complete")
		return
	case errors.Is(err, statestore.ErrForeign):
		d.logger.Warn("stored state belongs to another node, not restored")
		return
	case err != nil:
		d.logger.Warn("stored state unusable, not restored", "error", err)
		return
	}

	// The stored limit holds for the run, also when the state is not
	// restored, until a pull says otherwise.
	d.reconciler.SetMaxAgeSeconds(file.MaxAgeSeconds)
	age := time.Since(file.SavedAt)
	if maxAge := d.reconciler.MaxAge(); maxAge > 0 {
		if age > maxAge {
			d.logger.Warn("stored state older than the limit, not restored",
				"age", age,
				"max_age", maxAge,
				"saved_at", file.SavedAt,
			)
			return
		}
		if age < -storedStateClockTolerance {
			d.logger.Warn("stored state is newer than the clock, not restored",
				"age", age,
				"max_age", maxAge,
				"saved_at", file.SavedAt,
			)
			return
		}
	}

	if err := d.store.BeginRestore(); err != nil {
		d.logger.Warn("stored state not restored, the restore marker cannot be written", "error", err)
		return
	}
	edgePSKs := 0
	if d.edgePSKs != nil {
		edgePSKs = d.edgePSKs.Restore(file.EdgePSKs)
	}
	snapshot := &api.NodeStateSnapshot{
		Peers:            file.Peers,
		Policy:           file.Policy,
		Bridge:           file.Bridge,
		Secrets:          file.Secrets,
		SharedSubnets:    file.SharedSubnets,
		FailureDetection: file.FailureDetection,
	}
	if d.failureDetection != nil {
		d.failureDetection(ctx, snapshot)
	}
	d.policy(ctx, snapshot)
	for _, handler := range d.secretInventory {
		handler(ctx, snapshot)
	}
	failed := d.reconciler.Restore(ctx, snapshot, age)
	if err := d.store.EndRestore(); err != nil {
		d.logger.Warn("stored state restore marker not removed, the next start discards the stored state", "error", err)
	}

	fingerprint := ""
	if file.Policy != nil {
		fingerprint = file.Policy.Fingerprint
	}
	d.logger.Info("stored state restored",
		"peers", len(file.Peers),
		"policy_fingerprint", fingerprint,
		"edge_psks", edgePSKs,
		"saved_at", file.SavedAt,
		"age", age,
		"handler_failed", failed,
	)
}
