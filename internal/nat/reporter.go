package nat

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/plexsphere/plexd/internal/api"
)

// EndpointReporter abstracts the control plane endpoint reporting API.
type EndpointReporter interface {
	ReportEndpoint(ctx context.Context, nodeID string, req api.EndpointReport) (*api.EndpointResponse, error)
}

// PeerUpdater abstracts WireGuard peer endpoint updates.
type PeerUpdater interface {
	UpdatePeer(peer api.Peer) error
}

// reportAndApply reports the discovered endpoint to the control plane and applies
// peer endpoint updates from the response.
func reportAndApply(ctx context.Context, reporter EndpointReporter, updater PeerUpdater, nodeID string, result *DiscoveryResult, logger *slog.Logger) error {
	resp, err := reporter.ReportEndpoint(ctx, nodeID, api.EndpointReport{
		PublicEndpoint: result.Endpoint,
		NATType:        string(result.NATType),
	})
	if err != nil {
		return fmt.Errorf("nat: report endpoint: %w", err)
	}
	if resp == nil {
		return nil
	}

	for _, pe := range resp.PeerEndpoints {
		if pe.Endpoint == "" {
			continue
		}
		if err := updater.UpdatePeer(api.Peer{ID: pe.PeerID, Endpoint: pe.Endpoint}); err != nil {
			logger.Warn("failed to update peer endpoint",
				"component", "nat",
				"peer_id", pe.PeerID,
				"error", err,
			)
		}
	}

	return nil
}
