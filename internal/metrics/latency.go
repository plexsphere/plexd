package metrics

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// LatencyResult holds the latency measurement for a single peer.
type LatencyResult struct {
	PeerID  string `json:"peer_id"`
	RTTNano int64  `json:"rtt_nano"`
}

// Pinger abstracts the latency measurement mechanism.
type Pinger interface {
	Ping(ctx context.Context, peerID string) (rttNano int64, err error)
}

// PeerLister provides the list of current peer IDs to measure.
type PeerLister interface {
	PeerIDs() []string
}

// LatencyCollector implements Collector for peer latency metrics.
type LatencyCollector struct {
	pinger Pinger
	lister PeerLister
	logger *slog.Logger
}

// NewLatencyCollector creates a new LatencyCollector.
func NewLatencyCollector(pinger Pinger, lister PeerLister, logger *slog.Logger) *LatencyCollector {
	return &LatencyCollector{
		pinger: pinger,
		lister: lister,
		logger: logger,
	}
}

// Collect measures latency to all known peers and returns the results as MetricPoints.
func (c *LatencyCollector) Collect(ctx context.Context) ([]api.MetricPoint, error) {
	peers := c.lister.PeerIDs()
	if len(peers) == 0 {
		return []api.MetricPoint{}, nil
	}

	points := make([]api.MetricPoint, 0, len(peers))
	for _, peerID := range peers {
		if err := ctx.Err(); err != nil {
			return points, err
		}

		rtt, err := c.pinger.Ping(ctx, peerID)
		if err != nil {
			c.logger.Warn("metrics: latency: ping failed",
				slog.String("peer_id", peerID),
				slog.Any("error", err),
			)
			rtt = -1
		}

		result := LatencyResult{
			PeerID:  peerID,
			RTTNano: rtt,
		}
		data, _ := json.Marshal(result)

		points = append(points, api.MetricPoint{
			Timestamp: time.Now(),
			Group:     GroupLatency,
			PeerID:    peerID,
			Data:      data,
		})
	}
	return points, nil
}
