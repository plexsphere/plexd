package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// HandleSiteToSiteTunnelAssigned returns an api.EventHandler that adds a
// site-to-site tunnel when a site_to_site_tunnel_assigned SSE event is received.
func HandleSiteToSiteTunnelAssigned(mgr *SiteToSiteManager, logger *slog.Logger) api.EventHandler {
	return func(_ context.Context, envelope api.SignedEnvelope) error {
		var tunnel api.SiteToSiteTunnel
		if err := json.Unmarshal(envelope.Payload, &tunnel); err != nil {
			logger.Error("site_to_site_tunnel_assigned: parse payload failed",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("bridge: site_to_site_tunnel_assigned: parse payload: %w", err)
		}

		if err := mgr.AddTunnel(tunnel); err != nil {
			return fmt.Errorf("bridge: site_to_site_tunnel_assigned: %w", err)
		}
		return nil
	}
}

// HandleSiteToSiteTunnelRevoked returns an api.EventHandler that removes a
// site-to-site tunnel when a site_to_site_tunnel_revoked SSE event is received.
func HandleSiteToSiteTunnelRevoked(mgr *SiteToSiteManager, logger *slog.Logger) api.EventHandler {
	return func(_ context.Context, envelope api.SignedEnvelope) error {
		var payload struct {
			TunnelID string `json:"tunnel_id"`
		}
		if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
			logger.Error("site_to_site_tunnel_revoked: parse payload failed",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("bridge: site_to_site_tunnel_revoked: parse payload: %w", err)
		}

		mgr.RemoveTunnel(payload.TunnelID)
		return nil
	}
}

// HandleSiteToSiteConfigUpdated returns an api.EventHandler that triggers
// reconciliation when a site_to_site_config_updated SSE event is received.
// Follows the HandleBridgeConfigUpdated pattern: payload is ignored, reconcile
// cycle will fetch the full desired state.
func HandleSiteToSiteConfigUpdated(trigger ReconcileTrigger) api.EventHandler {
	return func(_ context.Context, _ api.SignedEnvelope) error {
		trigger.TriggerReconcile()
		return nil
	}
}

// SiteToSiteReconcileHandler returns a reconcile.ReconcileHandler that updates
// site-to-site tunnels when the desired SiteToSiteConfig changes. It diffs the
// desired tunnels against the currently active tunnels: adding missing tunnels,
// removing stale tunnels, and restarting changed tunnels (same ID, different config).
func SiteToSiteReconcileHandler(mgr *SiteToSiteManager, logger *slog.Logger) reconcile.ReconcileHandler {
	return func(_ context.Context, desired *api.StateResponse, _ reconcile.StateDiff) error {
		if desired == nil || desired.SiteToSiteConfig == nil {
			return nil
		}

		// Build desired set for diffing.
		desiredSet := make(map[string]api.SiteToSiteTunnel, len(desired.SiteToSiteConfig.Tunnels))
		for _, t := range desired.SiteToSiteConfig.Tunnels {
			desiredSet[t.TunnelID] = t
		}

		currentIDs := mgr.TunnelIDs()
		currentSet := make(map[string]struct{}, len(currentIDs))
		for _, id := range currentIDs {
			currentSet[id] = struct{}{}
		}

		// Remove stale tunnels (present locally but not in desired state)
		// and detect changed tunnels (same ID, different config).
		for _, id := range currentIDs {
			desiredTunnel, inDesired := desiredSet[id]
			if !inDesired {
				// Stale tunnel — remove.
				mgr.RemoveTunnel(id)
				continue
			}
			// Check if the tunnel config changed (requires restart).
			currentTunnel, ok := mgr.GetTunnel(id)
			if ok && !reflect.DeepEqual(currentTunnel, desiredTunnel) {
				mgr.RemoveTunnel(id)
				delete(currentSet, id) // mark for re-add below
			}
		}

		// Add missing and changed tunnels.
		var errs []error
		for _, tunnel := range desired.SiteToSiteConfig.Tunnels {
			if _, ok := currentSet[tunnel.TunnelID]; ok {
				continue
			}
			if err := mgr.AddTunnel(tunnel); err != nil {
				logger.Error("site-to-site reconcile: add tunnel failed",
					"tunnel_id", tunnel.TunnelID,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		return errors.Join(errs...)
	}
}
