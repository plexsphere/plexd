package metrics

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// namedValue pairs a wire sample name with its numeric value during flattening.
type namedValue struct {
	name  string
	value float64
}

// toSamples flattens an internal MetricPoint into the control-plane MetricSample
// wire format, emitting one sample per numeric field of the collector's data
// struct. Every sample carries the point's timestamp and the wire group constant
// for the point's internal group. Non-finite values (NaN/Inf) are skipped
// individually with a Debug log so a single bad field does not fail the whole
// batch at json.Marshal time.
func toSamples(p api.MetricPoint, logger *slog.Logger) ([]api.MetricSample, error) {
	if len(p.Data) == 0 {
		return nil, fmt.Errorf("metrics: convert: empty data for group %q", p.Group)
	}
	// Metrics ingest rejects a zero timestamp with 400 ingest_batch_malformed,
	// and that verdict covers the whole batch — one unstamped point would
	// discard every other sample flushed with it. Reject the point here so the
	// caller skips just this one, as the log and audit reporters already do.
	if p.Timestamp.IsZero() {
		return nil, fmt.Errorf("metrics: convert: zero timestamp for group %q", p.Group)
	}

	var (
		wireGroup string
		labels    map[string]string
		values    []namedValue
	)

	switch p.Group {
	case GroupSystem:
		var s SystemStats
		if err := json.Unmarshal(p.Data, &s); err != nil {
			return nil, fmt.Errorf("metrics: convert: unmarshal group %q: %w", p.Group, err)
		}
		wireGroup = api.MetricGroupNodeResources
		values = []namedValue{
			{"cpu_usage_percent", s.CPUUsagePercent},
			{"memory_used_bytes", float64(s.MemoryUsedBytes)},
			{"memory_total_bytes", float64(s.MemoryTotalBytes)},
			{"disk_used_bytes", float64(s.DiskUsedBytes)},
			{"disk_total_bytes", float64(s.DiskTotalBytes)},
			{"network_rx_bytes", float64(s.NetworkRxBytes)},
			{"network_tx_bytes", float64(s.NetworkTxBytes)},
			{"load_avg_1", s.LoadAvg1},
			{"load_avg_5", s.LoadAvg5},
			{"load_avg_15", s.LoadAvg15},
		}

	case GroupTunnel:
		var s TunnelStats
		if err := json.Unmarshal(p.Data, &s); err != nil {
			return nil, fmt.Errorf("metrics: convert: unmarshal group %q: %w", p.Group, err)
		}
		wireGroup = api.MetricGroupTunnelHealth
		labels = map[string]string{"peer_id": p.PeerID}
		var lastHandshake float64
		if !s.LastHandshakeTime.IsZero() {
			lastHandshake = float64(s.LastHandshakeTime.Unix())
		}
		values = []namedValue{
			{"rx_bytes", float64(s.RxBytes)},
			{"tx_bytes", float64(s.TxBytes)},
			{"handshake_succeeded", boolToFloat(s.HandshakeSucceeded)},
			{"handshake_stale", boolToFloat(s.HandshakeStale)},
			{"packet_loss_percent", s.PacketLossPercent},
			{"last_handshake_timestamp_seconds", lastHandshake},
		}

	case GroupLatency:
		var r LatencyResult
		if err := json.Unmarshal(p.Data, &r); err != nil {
			return nil, fmt.Errorf("metrics: convert: unmarshal group %q: %w", p.Group, err)
		}
		wireGroup = api.MetricGroupPeerLatency
		labels = map[string]string{"peer_id": p.PeerID}
		// The ping-failure sentinel (-1) is carried through verbatim rather than
		// scaled to nanoseconds so the control plane can recognize it.
		rttSeconds := float64(r.RTTNano) / 1e9
		if r.RTTNano == -1 {
			rttSeconds = -1
		}
		values = []namedValue{
			{"rtt_seconds", rttSeconds},
		}

	case GroupAgent:
		var a AgentStats
		if err := json.Unmarshal(p.Data, &a); err != nil {
			return nil, fmt.Errorf("metrics: convert: unmarshal group %q: %w", p.Group, err)
		}
		wireGroup = api.MetricGroupAgentStats
		values = []namedValue{
			{"goroutine_count", float64(a.GoroutineCount)},
			{"heap_alloc_bytes", float64(a.HeapAllocBytes)},
			{"heap_sys_bytes", float64(a.HeapSysBytes)},
			{"gc_pause_total_ns", float64(a.GCPauseTotalNs)},
			{"gc_num_gc", float64(a.GCNumGC)},
			{"uptime_seconds", a.UptimeSeconds},
			{"reconnect_count", float64(a.ReconnectCount)},
		}

	default:
		return nil, fmt.Errorf("metrics: convert: unknown group %q", p.Group)
	}

	return buildSamples(wireGroup, labels, p.Timestamp, values, logger), nil
}

// buildSamples materializes one MetricSample per value, dropping non-finite
// values (NaN/Inf) with a Debug log that names the skipped field. A single
// non-finite field would otherwise fail json.Marshal for the entire batch, so
// it is skipped rather than propagated.
func buildSamples(group string, labels map[string]string, ts time.Time, values []namedValue, logger *slog.Logger) []api.MetricSample {
	samples := make([]api.MetricSample, 0, len(values))
	for _, v := range values {
		if math.IsNaN(v.value) || math.IsInf(v.value, 0) {
			logger.Debug("metrics: convert: skipping non-finite sample",
				slog.String("group", group),
				slog.String("name", v.name),
			)
			continue
		}
		samples = append(samples, api.MetricSample{
			Group:     group,
			Name:      v.name,
			Value:     v.value,
			Labels:    labels,
			Timestamp: ts,
		})
	}
	return samples
}

// boolToFloat maps a boolean sample to the 1/0 the wire format uses.
func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
