package nat

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// DiscoveryResult holds the outcome of a STUN discovery cycle.
type DiscoveryResult struct {
	Endpoint string  // "ip:port" format
	NATType  NATType
}

// Discoverer performs STUN-based NAT traversal to discover the node's public endpoint.
type Discoverer struct {
	client    STUNClient
	cfg       Config
	localPort int
	logger    *slog.Logger

	mu         sync.RWMutex
	lastResult *api.NATInfo
}

// NewDiscoverer creates a new Discoverer.
func NewDiscoverer(client STUNClient, cfg Config, localPort int, logger *slog.Logger) *Discoverer {
	return &Discoverer{
		client:    client,
		cfg:       cfg,
		localPort: localPort,
		logger:    logger,
	}
}

// Discover performs STUN binding requests to discover the public endpoint and classify NAT type.
func (d *Discoverer) Discover(ctx context.Context) (*DiscoveryResult, error) {
	var firstAddr MappedAddress
	var firstServer string
	firstFound := false

	// Try each STUN server in order to get a first successful binding.
	remainingStart := 0
	for i, server := range d.cfg.STUNServers {
		addr, err := d.client.Bind(ctx, server, d.localPort)
		if err != nil {
			d.logger.Warn("STUN binding failed", "component", "nat", "server", server, "error", err)
			continue
		}
		firstAddr = addr
		firstServer = server
		firstFound = true
		remainingStart = i + 1
		d.logger.Debug("STUN binding succeeded", "component", "nat", "server", server, "endpoint", addr.String())
		break
	}

	if !firstFound {
		return nil, fmt.Errorf("nat: discover: all STUN servers failed")
	}

	// Check if mapped port matches local port — indicates no NAT.
	if firstAddr.Port == d.localPort {
		endpoint := firstAddr.String()
		d.updateLastResult(endpoint, NATNone, firstServer)
		return &DiscoveryResult{Endpoint: endpoint, NATType: NATNone}, nil
	}

	// Try remaining servers to get a second binding for NAT classification.
	natType := NATUnknown
	for _, server := range d.cfg.STUNServers[remainingStart:] {
		secondAddr, err := d.client.Bind(ctx, server, d.localPort)
		if err != nil {
			d.logger.Warn("STUN binding failed", "component", "nat", "server", server, "error", err)
			continue
		}

		if firstAddr.IP.Equal(secondAddr.IP) && firstAddr.Port == secondAddr.Port {
			natType = NATFullCone
		} else {
			natType = NATSymmetric
		}
		break
	}

	if natType == NATUnknown {
		d.logger.Warn("NAT classification incomplete: no second STUN server responded", "component", "nat")
	}

	endpoint := firstAddr.String()
	d.updateLastResult(endpoint, natType, firstServer)
	return &DiscoveryResult{Endpoint: endpoint, NATType: natType}, nil
}

func (d *Discoverer) updateLastResult(endpoint string, natType NATType, stunServer string) {
	d.mu.Lock()
	d.lastResult = &api.NATInfo{
		PublicEndpoint: endpoint,
		Type:           string(natType),
	}
	d.mu.Unlock()

	d.logger.Info("endpoint discovered",
		"component", "nat",
		"endpoint", endpoint,
		"nat_type", string(natType),
		"stun_server", stunServer,
	)
}

// LastResult returns the most recently discovered NAT info, or nil if no discovery has succeeded.
func (d *Discoverer) LastResult() *api.NATInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.lastResult
}

// Run performs initial STUN discovery, reports the endpoint, then enters a refresh loop.
// It blocks until ctx is cancelled or an unrecoverable error occurs.
func (d *Discoverer) Run(ctx context.Context, reporter EndpointReporter, updater PeerUpdater, nodeID string) error {
	result, err := d.Discover(ctx)
	if err != nil {
		return fmt.Errorf("nat: initial discovery: %w", err)
	}

	if err := reportAndApply(ctx, reporter, updater, nodeID, result, d.logger); err != nil {
		d.logger.Warn("endpoint report failed", "component", "nat", "error", err)
	}

	prevEndpoint := result.Endpoint

	ticker := time.NewTicker(d.cfg.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			result, err := d.Discover(ctx)
			if err != nil {
				d.logger.Warn("STUN refresh failed", "component", "nat", "error", err)
				continue
			}

			if result.Endpoint != prevEndpoint {
				d.logger.Info("endpoint changed",
					"component", "nat",
					"old_endpoint", prevEndpoint,
					"new_endpoint", result.Endpoint,
				)
			}
			prevEndpoint = result.Endpoint

			if err := reportAndApply(ctx, reporter, updater, nodeID, result, d.logger); err != nil {
				d.logger.Warn("endpoint report failed", "component", "nat", "error", err)
			}
		}
	}
}
