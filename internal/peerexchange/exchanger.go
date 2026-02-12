package peerexchange

import (
	"context"
	"log/slog"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/nat"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// Exchanger orchestrates peer endpoint exchange: STUN discovery,
// control plane reporting, and WireGuard peer endpoint updates.
type Exchanger struct {
	discoverer *nat.Discoverer
	wgManager  *wireguard.Manager
	cpClient   *api.ControlPlane
	cfg        Config
	logger     *slog.Logger
}

// NewExchanger creates a new Exchanger.
func NewExchanger(discoverer *nat.Discoverer, wgManager *wireguard.Manager, cpClient *api.ControlPlane, cfg Config, logger *slog.Logger) *Exchanger {
	cfg.ApplyDefaults()
	return &Exchanger{
		discoverer: discoverer,
		wgManager:  wgManager,
		cpClient:   cpClient,
		cfg:        cfg,
		logger:     logger,
	}
}

// RegisterHandlers registers SSE event handlers for peer endpoint changes.
// Must be called before the SSEManager is started.
// Handlers are registered regardless of whether NAT is enabled, because
// inbound peer endpoint updates must still be processed.
func (e *Exchanger) RegisterHandlers(sseManager *api.SSEManager) {
	sseManager.RegisterHandler(api.EventPeerEndpointChanged, wireguard.HandlePeerEndpointChanged(e.wgManager))
	e.logger.Debug("peer_endpoint_changed handler registered", "component", "exchange")
}

// Run starts the endpoint exchange loop. If NAT is disabled, it returns nil
// immediately. Otherwise, it delegates to nat.Discoverer.Run.
// It blocks until ctx is cancelled.
func (e *Exchanger) Run(ctx context.Context, nodeID string) error {
	if !e.cfg.Enabled {
		e.logger.Info("NAT traversal disabled, skipping endpoint exchange", "component", "exchange")
		return nil
	}

	e.logger.Info("starting endpoint exchange", "component", "exchange", "node_id", nodeID)

	reporter := &controlPlaneReporter{client: e.cpClient}
	return e.discoverer.Run(ctx, reporter, e.wgManager, nodeID)
}

// LastResult returns the most recently discovered NAT info.
func (e *Exchanger) LastResult() *api.NATInfo {
	return e.discoverer.LastResult()
}

// controlPlaneReporter adapts *api.ControlPlane to the nat.EndpointReporter interface.
type controlPlaneReporter struct {
	client *api.ControlPlane
}

func (r *controlPlaneReporter) ReportEndpoint(ctx context.Context, nodeID string, req api.EndpointReport) (*api.EndpointResponse, error) {
	return r.client.ReportEndpoint(ctx, nodeID, req)
}
