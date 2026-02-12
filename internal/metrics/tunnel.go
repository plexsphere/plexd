package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// DefaultStaleThreshold is the default duration after which a handshake is considered stale.
const DefaultStaleThreshold = 5 * time.Minute

// TunnelStats holds tunnel health data for a single peer.
type TunnelStats struct {
	PeerID             string    `json:"peer_id"`
	LastHandshakeTime  time.Time `json:"last_handshake_time"`
	RxBytes            uint64    `json:"rx_bytes"`
	TxBytes            uint64    `json:"tx_bytes"`
	HandshakeSucceeded bool      `json:"handshake_succeeded"`
	HandshakeStale     bool      `json:"handshake_stale"`
}

// TunnelStatsReader abstracts WireGuard tunnel stats retrieval.
type TunnelStatsReader interface {
	ReadTunnelStats(ctx context.Context) ([]TunnelStats, error)
}

// TunnelCollector implements Collector for per-peer tunnel metrics.
type TunnelCollector struct {
	reader         TunnelStatsReader
	logger         *slog.Logger
	staleThreshold time.Duration
}

// NewTunnelCollector creates a new TunnelCollector.
// StaleThreshold defaults to DefaultStaleThreshold (5m).
func NewTunnelCollector(reader TunnelStatsReader, logger *slog.Logger) *TunnelCollector {
	return NewTunnelCollectorWithThreshold(reader, logger, DefaultStaleThreshold)
}

// NewTunnelCollectorWithThreshold creates a TunnelCollector with a custom stale threshold.
func NewTunnelCollectorWithThreshold(reader TunnelStatsReader, logger *slog.Logger, staleThreshold time.Duration) *TunnelCollector {
	if staleThreshold <= 0 {
		staleThreshold = DefaultStaleThreshold
	}
	return &TunnelCollector{
		reader:         reader,
		logger:         logger,
		staleThreshold: staleThreshold,
	}
}

// Collect reads tunnel stats and returns a MetricPoint per peer.
// Handshakes older than StaleThreshold are marked as stale.
func (c *TunnelCollector) Collect(ctx context.Context) ([]api.MetricPoint, error) {
	stats, err := c.reader.ReadTunnelStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("metrics: tunnel: %w", err)
	}

	now := time.Now()
	points := make([]api.MetricPoint, 0, len(stats))
	for _, s := range stats {
		if !s.LastHandshakeTime.IsZero() && now.Sub(s.LastHandshakeTime) > c.staleThreshold {
			s.HandshakeStale = true
		}

		data, err := json.Marshal(s)
		if err != nil {
			return nil, fmt.Errorf("metrics: tunnel: %w", err)
		}
		points = append(points, api.MetricPoint{
			Timestamp: now,
			Group:     GroupTunnel,
			PeerID:    s.PeerID,
			Data:      data,
		})
	}

	return points, nil
}
