package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ReconnectCounter provides the current reconnect count.
type ReconnectCounter interface {
	ReconnectCount() int
}

// AgentStats holds agent runtime metrics.
type AgentStats struct {
	GoroutineCount int     `json:"goroutine_count"`
	HeapAllocBytes uint64  `json:"heap_alloc_bytes"`
	HeapSysBytes   uint64  `json:"heap_sys_bytes"`
	GCPauseTotalNs uint64  `json:"gc_pause_total_ns"`
	GCNumGC        uint32  `json:"gc_num_gc"`
	UptimeSeconds  float64 `json:"uptime_seconds"`
	ReconnectCount int     `json:"reconnect_count"`
}

// AgentStatsCollector implements Collector for agent runtime metrics.
type AgentStatsCollector struct {
	startTime  time.Time
	reconnects ReconnectCounter
	logger     *slog.Logger
}

// NewAgentStatsCollector creates a new AgentStatsCollector.
// The reconnects parameter may be nil if reconnect counting is not available.
func NewAgentStatsCollector(startTime time.Time, reconnects ReconnectCounter, logger *slog.Logger) *AgentStatsCollector {
	return &AgentStatsCollector{
		startTime:  startTime,
		reconnects: reconnects,
		logger:     logger,
	}
}

// Collect reads Go runtime stats and returns a single MetricPoint.
func (c *AgentStatsCollector) Collect(ctx context.Context) ([]api.MetricPoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("metrics: agent: %w", err)
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	stats := AgentStats{
		GoroutineCount: runtime.NumGoroutine(),
		HeapAllocBytes: mem.HeapAlloc,
		HeapSysBytes:   mem.HeapSys,
		GCPauseTotalNs: mem.PauseTotalNs,
		GCNumGC:        mem.NumGC,
		UptimeSeconds:  time.Since(c.startTime).Seconds(),
	}

	if c.reconnects != nil {
		stats.ReconnectCount = c.reconnects.ReconnectCount()
	}

	data, err := json.Marshal(stats)
	if err != nil {
		return nil, fmt.Errorf("metrics: agent: %w", err)
	}

	return []api.MetricPoint{
		{
			Timestamp: time.Now(),
			Group:     GroupAgent,
			Data:      data,
		},
	}, nil
}
