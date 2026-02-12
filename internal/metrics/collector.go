package metrics

import (
	"context"

	"github.com/plexsphere/plexd/internal/api"
)

// Metric group constants identify the subsystem a metric belongs to.
const (
	GroupSystem  = "system"
	GroupTunnel  = "tunnel"
	GroupLatency = "latency"
)

// Collector collects metrics from a specific subsystem.
type Collector interface {
	Collect(ctx context.Context) ([]api.MetricPoint, error)
}

