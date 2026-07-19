package nat

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// endpointReportMargin is how far before the server-side stale_after deadline
// the node re-reports its endpoint, leaving headroom for request latency.
const endpointReportMargin = 30 * time.Second

// endpointRejectionEscalation is how many consecutive control-plane
// rejections the report loop tolerates at Warn before escalating to Error. A
// rejection means the control plane no longer holds this node's peer record,
// and re-reporting cannot clear that: the node stays unreachable for peers
// behind symmetric NAT while every other health signal remains green. A
// persistent run needs operator attention, not another quiet retry.
const endpointRejectionEscalation = 3

// DiscoveryResult holds the outcome of a STUN discovery cycle.
type DiscoveryResult struct {
	Endpoint string // "ip:port" format
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

	// rejections counts consecutive control-plane endpoint rejections. It is
	// owned by the Run loop and never read concurrently.
	rejections int
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

// bind performs a STUN binding against server and rejects a mapped address
// that is not usable as a public endpoint. STUN responses are
// unauthenticated (see MappedAddress.Routable), so a non-routable address is
// treated exactly like a failed binding: the caller falls through to the
// next server rather than publishing it.
func (d *Discoverer) bind(ctx context.Context, server string) (MappedAddress, error) {
	addr, err := d.client.Bind(ctx, server, d.localPort)
	if err != nil {
		return MappedAddress{}, err
	}
	if !addr.Routable() {
		return MappedAddress{}, fmt.Errorf("nat: stun: non-routable mapped address %s", addr)
	}
	return addr, nil
}

// Discover performs STUN binding requests to discover the public endpoint and classify NAT type.
func (d *Discoverer) Discover(ctx context.Context) (*DiscoveryResult, error) {
	var firstAddr MappedAddress
	var firstServer string
	firstFound := false

	// Try each STUN server in order to get a first successful binding.
	remainingStart := 0
	for i, server := range d.cfg.STUNServers {
		addr, err := d.bind(ctx, server)
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
		secondAddr, err := d.bind(ctx, server)
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

// reportEndpoint reports result and returns the server's stale_after
// deadline, logging any failure. Consecutive rejections are counted so a
// control plane that has forgotten this node's peer record cannot stay a
// silent per-cycle Warn forever: after endpointRejectionEscalation cycles
// the condition is logged at Error, which is alertable. A successful report
// clears the streak; a transient failure leaves it intact, since it says
// nothing about whether the peer record came back.
func (d *Discoverer) reportEndpoint(ctx context.Context, reporter EndpointReporter, nodeID string, result *DiscoveryResult) time.Time {
	staleAfter, err := report(ctx, reporter, nodeID, result)
	switch {
	case err == nil:
		d.rejections = 0
	case errors.Is(err, errEndpointRejected):
		d.rejections++
		level := slog.LevelWarn
		if d.rejections >= endpointRejectionEscalation {
			level = slog.LevelError
		}
		d.logger.Log(ctx, level, "endpoint report rejected, this node is not registered as a peer",
			"component", "nat",
			"error", err,
			"consecutive_rejections", d.rejections,
		)
	default:
		d.logger.Warn("endpoint report failed", "component", "nat", "error", err)
	}
	return staleAfter
}

// LastResult returns the most recently discovered NAT info, or nil if no discovery has succeeded.
func (d *Discoverer) LastResult() *api.NATInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.lastResult
}

// Run performs initial STUN discovery, reports the endpoint, then enters a refresh loop.
// It blocks until ctx is cancelled or an unrecoverable error occurs.
func (d *Discoverer) Run(ctx context.Context, reporter EndpointReporter, nodeID string) error {
	result, err := d.Discover(ctx)
	if err != nil {
		return fmt.Errorf("nat: initial discovery: %w", err)
	}

	staleAfter := d.reportEndpoint(ctx, reporter, nodeID, result)

	prevEndpoint := result.Endpoint

	timer := time.NewTimer(d.nextDelay(staleAfter))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			result, err := d.Discover(ctx)
			if err != nil {
				d.logger.Warn("STUN refresh failed", "component", "nat", "error", err)
				timer.Reset(d.nextDelay(time.Time{}))
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

			staleAfter := d.reportEndpoint(ctx, reporter, nodeID, result)
			timer.Reset(d.nextDelay(staleAfter))
		}
	}
}

// nextDelay computes the wait before the next report cycle. A zero
// staleAfter (absent deadline or failed report) falls back to the
// configured refresh interval. Otherwise the node re-reports
// endpointReportMargin before the server-side deadline, floored at
// MinReportInterval; the refresh interval caps the delay. The floor applies
// to the deadline term only so sub-interval configurations keep working.
//
// A deadline shorter than the configured refresh interval means the control
// plane — not the operator — is setting the cadence, driving both the STUN
// queries and the endpoint PUTs above the configured rate. That is
// legitimate when the server's TTL is genuinely short, but it is also what a
// misconfigured or hostile control plane would do to the whole fleet, so
// each shortened cycle is logged and MinReportInterval bounds how far it can
// go.
func (d *Discoverer) nextDelay(staleAfter time.Time) time.Duration {
	if staleAfter.IsZero() {
		return d.cfg.RefreshInterval
	}
	deadlineDelay := time.Until(staleAfter) - endpointReportMargin
	delay := min(d.cfg.RefreshInterval, max(d.cfg.MinReportInterval, deadlineDelay))
	if delay < d.cfg.RefreshInterval {
		d.logger.Warn("control plane deadline shortens the endpoint report cadence",
			"component", "nat",
			"delay", delay,
			"refresh_interval", d.cfg.RefreshInterval,
			"min_report_interval", d.cfg.MinReportInterval,
			"stale_after", staleAfter,
		)
	}
	return delay
}
