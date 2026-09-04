package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// SystemStats holds the raw system resource readings.
type SystemStats struct {
	CPUUsagePercent  float64 `json:"cpu_usage_percent"`
	MemoryUsedBytes  uint64  `json:"memory_used_bytes"`
	MemoryTotalBytes uint64  `json:"memory_total_bytes"`
	DiskUsedBytes    uint64  `json:"disk_used_bytes"`
	DiskTotalBytes   uint64  `json:"disk_total_bytes"`
	NetworkRxBytes   uint64  `json:"network_rx_bytes"`
	NetworkTxBytes   uint64  `json:"network_tx_bytes"`
	LoadAvg1         float64 `json:"load_avg_1"`
	LoadAvg5         float64 `json:"load_avg_5"`
	LoadAvg15        float64 `json:"load_avg_15"`
}

// SystemReader abstracts OS-level system metrics retrieval.
type SystemReader interface {
	ReadStats(ctx context.Context) (*SystemStats, error)
}

// cpuSampleInterval is the delay between two CPU samples for usage calculation.
const cpuSampleInterval = 100 * time.Millisecond

// SystemCollector implements Collector for system resource metrics.
type SystemCollector struct {
	reader SystemReader
	logger *slog.Logger
}

// NewSystemCollector creates a new SystemCollector.
func NewSystemCollector(reader SystemReader, logger *slog.Logger) *SystemCollector {
	return &SystemCollector{reader: reader, logger: logger}
}

// Collect reads system stats and returns a single MetricPoint.
func (c *SystemCollector) Collect(ctx context.Context) ([]api.MetricPoint, error) {
	stats, err := c.reader.ReadStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("metrics: system: %w", err)
	}

	data, err := json.Marshal(stats)
	if err != nil {
		return nil, fmt.Errorf("metrics: system: %w", err)
	}

	return []api.MetricPoint{
		{
			Timestamp: time.Now(),
			Group:     GroupSystem,
			Data:      data,
		},
	}, nil
}
