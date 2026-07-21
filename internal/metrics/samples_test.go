package metrics

import (
	"encoding/json"
	"log/slog"
	"maps"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// mustData marshals a collector data struct the way the collectors do, so tests
// feed toSamples exactly the wire bytes it would see in production.
func mustData(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal test data: %v", err)
	}
	return data
}

func sampleNames(samples []api.MetricSample) []string {
	names := make([]string, len(samples))
	for i, s := range samples {
		names[i] = s.Name
	}
	return names
}

func sampleValue(t *testing.T, samples []api.MetricSample, name string) float64 {
	t.Helper()
	for _, s := range samples {
		if s.Name == name {
			return s.Value
		}
	}
	t.Fatalf("sample %q not found in %v", name, sampleNames(samples))
	return 0
}

func TestToSamples_GroupTable(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	handshake := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name       string
		point      api.MetricPoint
		wireGroup  string
		wantNames  []string
		wantLabels map[string]string
	}{
		{
			name: "system maps to node_resources",
			point: api.MetricPoint{
				Timestamp: ts,
				Group:     GroupSystem,
				Data: mustData(t, SystemStats{
					CPUUsagePercent:  42.5,
					MemoryUsedBytes:  1024,
					MemoryTotalBytes: 4096,
					DiskUsedBytes:    2048,
					DiskTotalBytes:   8192,
					NetworkRxBytes:   100,
					NetworkTxBytes:   200,
					LoadAvg1:         0.5,
					LoadAvg5:         1.0,
					LoadAvg15:        1.5,
				}),
			},
			wireGroup: api.MetricGroupNodeResources,
			wantNames: []string{
				"cpu_usage_percent", "memory_used_bytes", "memory_total_bytes",
				"disk_used_bytes", "disk_total_bytes", "network_rx_bytes",
				"network_tx_bytes", "load_avg_1", "load_avg_5", "load_avg_15",
			},
			wantLabels: nil,
		},
		{
			name: "tunnel maps to tunnel_health",
			point: api.MetricPoint{
				Timestamp: ts,
				Group:     GroupTunnel,
				PeerID:    "peer-a",
				Data: mustData(t, TunnelStats{
					PeerID:             "peer-a",
					LastHandshakeTime:  handshake,
					RxBytes:            10,
					TxBytes:            20,
					HandshakeSucceeded: true,
					HandshakeStale:     false,
					PacketLossPercent:  1.5,
				}),
			},
			wireGroup: api.MetricGroupTunnelHealth,
			wantNames: []string{
				"rx_bytes", "tx_bytes", "handshake_succeeded", "handshake_stale",
				"packet_loss_percent", "last_handshake_timestamp_seconds",
			},
			wantLabels: map[string]string{"peer_id": "peer-a"},
		},
		{
			name: "latency maps to peer_latency",
			point: api.MetricPoint{
				Timestamp: ts,
				Group:     GroupLatency,
				PeerID:    "peer-b",
				Data:      mustData(t, LatencyResult{PeerID: "peer-b", RTTNano: 2_000_000}),
			},
			wireGroup:  api.MetricGroupPeerLatency,
			wantNames:  []string{"rtt_seconds"},
			wantLabels: map[string]string{"peer_id": "peer-b"},
		},
		{
			name: "agent maps to agent_stats",
			point: api.MetricPoint{
				Timestamp: ts,
				Group:     GroupAgent,
				Data: mustData(t, AgentStats{
					GoroutineCount: 12,
					HeapAllocBytes: 1000,
					HeapSysBytes:   2000,
					GCPauseTotalNs: 3000,
					GCNumGC:        4,
					UptimeSeconds:  5.5,
					ReconnectCount: 2,
				}),
			},
			wireGroup: api.MetricGroupAgentStats,
			wantNames: []string{
				"goroutine_count", "heap_alloc_bytes", "heap_sys_bytes",
				"gc_pause_total_ns", "gc_num_gc", "uptime_seconds", "reconnect_count",
			},
			wantLabels: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			samples, err := toSamples(tt.point, discardLogger())
			if err != nil {
				t.Fatalf("toSamples() error = %v", err)
			}
			if got := sampleNames(samples); !slices.Equal(got, tt.wantNames) {
				t.Errorf("names = %v, want %v", got, tt.wantNames)
			}
			for _, s := range samples {
				if s.Group != tt.wireGroup {
					t.Errorf("sample %q Group = %q, want %q", s.Name, s.Group, tt.wireGroup)
				}
				if !s.Timestamp.Equal(tt.point.Timestamp) {
					t.Errorf("sample %q Timestamp = %v, want %v", s.Name, s.Timestamp, tt.point.Timestamp)
				}
				if !maps.Equal(s.Labels, tt.wantLabels) {
					t.Errorf("sample %q Labels = %v, want %v", s.Name, s.Labels, tt.wantLabels)
				}
			}
		})
	}
}

func TestToSamples_MappedValues(t *testing.T) {
	ts := time.Now()
	handshake := time.Unix(1_700_000_000, 0)

	tunnel := api.MetricPoint{
		Timestamp: ts,
		Group:     GroupTunnel,
		PeerID:    "peer-a",
		Data: mustData(t, TunnelStats{
			PeerID:             "peer-a",
			LastHandshakeTime:  handshake,
			RxBytes:            10,
			TxBytes:            20,
			HandshakeSucceeded: true,
			HandshakeStale:     false,
			PacketLossPercent:  1.5,
		}),
	}
	samples, err := toSamples(tunnel, discardLogger())
	if err != nil {
		t.Fatalf("toSamples() error = %v", err)
	}
	if got := sampleValue(t, samples, "handshake_succeeded"); got != 1 {
		t.Errorf("handshake_succeeded = %v, want 1", got)
	}
	if got := sampleValue(t, samples, "handshake_stale"); got != 0 {
		t.Errorf("handshake_stale = %v, want 0", got)
	}
	if got := sampleValue(t, samples, "rx_bytes"); got != 10 {
		t.Errorf("rx_bytes = %v, want 10", got)
	}
	if got := sampleValue(t, samples, "last_handshake_timestamp_seconds"); got != float64(handshake.Unix()) {
		t.Errorf("last_handshake_timestamp_seconds = %v, want %v", got, float64(handshake.Unix()))
	}

	latency := api.MetricPoint{
		Timestamp: ts,
		Group:     GroupLatency,
		PeerID:    "peer-b",
		Data:      mustData(t, LatencyResult{PeerID: "peer-b", RTTNano: 2_000_000}),
	}
	samples, err = toSamples(latency, discardLogger())
	if err != nil {
		t.Fatalf("toSamples() error = %v", err)
	}
	if got := sampleValue(t, samples, "rtt_seconds"); got != 0.002 {
		t.Errorf("rtt_seconds = %v, want 0.002", got)
	}
}

func TestToSamples_SystemEmptyObjectEmitsZeroSamples(t *testing.T) {
	p := api.MetricPoint{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage("{}")}

	samples, err := toSamples(p, discardLogger())
	if err != nil {
		t.Fatalf("toSamples() error = %v", err)
	}
	if len(samples) != 10 {
		t.Fatalf("len(samples) = %d, want 10", len(samples))
	}
	for _, s := range samples {
		if s.Value != 0 {
			t.Errorf("sample %q value = %v, want 0", s.Name, s.Value)
		}
	}
}

func TestToSamples_EmptyDataError(t *testing.T) {
	cases := []struct {
		name string
		data json.RawMessage
	}{
		{"nil data", nil},
		{"empty data", json.RawMessage{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := api.MetricPoint{Timestamp: time.Now(), Group: GroupSystem, Data: tc.data}

			_, err := toSamples(p, discardLogger())
			if err == nil {
				t.Fatal("toSamples() error = nil, want error")
			}
			const want = `metrics: convert: empty data for group "system"`
			if err.Error() != want {
				t.Errorf("error = %q, want %q", err.Error(), want)
			}
		})
	}
}

// TestToSamples_ZeroTimestampError pins the zero-timestamp rejection. Metrics
// ingest answers 400 ingest_batch_malformed for an unstamped record and that
// verdict discards the whole batch, so an unstamped point must be rejected here
// and skipped by the caller rather than shipped with its neighbours.
func TestToSamples_ZeroTimestampError(t *testing.T) {
	p := api.MetricPoint{Group: GroupSystem, Data: json.RawMessage(`{"cpu_usage_percent":12.5}`)}

	_, err := toSamples(p, discardLogger())
	if err == nil {
		t.Fatal("toSamples() error = nil, want error")
	}
	const want = `metrics: convert: zero timestamp for group "system"`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestToSamples_UnknownGroupError(t *testing.T) {
	p := api.MetricPoint{Timestamp: time.Now(), Group: "bogus", Data: json.RawMessage("{}")}

	_, err := toSamples(p, discardLogger())
	if err == nil {
		t.Fatal("toSamples() error = nil, want error")
	}
	const want = `metrics: convert: unknown group "bogus"`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestToSamples_UnmarshalError(t *testing.T) {
	p := api.MetricPoint{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage("not json")}

	_, err := toSamples(p, discardLogger())
	if err == nil {
		t.Fatal("toSamples() error = nil, want error")
	}
	if !strings.Contains(err.Error(), `metrics: convert: unmarshal group "system"`) {
		t.Errorf("error = %q, want unmarshal-group prefix", err.Error())
	}
}

func TestToSamples_LatencyFailureSentinel(t *testing.T) {
	p := api.MetricPoint{
		Timestamp: time.Now(),
		Group:     GroupLatency,
		PeerID:    "peer-x",
		Data:      mustData(t, LatencyResult{PeerID: "peer-x", RTTNano: -1}),
	}

	samples, err := toSamples(p, discardLogger())
	if err != nil {
		t.Fatalf("toSamples() error = %v", err)
	}
	if got := sampleValue(t, samples, "rtt_seconds"); got != -1 {
		t.Errorf("rtt_seconds = %v, want -1 (failure sentinel carried verbatim)", got)
	}
}

func TestToSamples_TunnelZeroHandshake(t *testing.T) {
	p := api.MetricPoint{
		Timestamp: time.Now(),
		Group:     GroupTunnel,
		PeerID:    "peer-y",
		Data: mustData(t, TunnelStats{
			PeerID:            "peer-y",
			LastHandshakeTime: time.Time{}, // zero time — never handshaked
			RxBytes:           1,
			TxBytes:           2,
		}),
	}

	samples, err := toSamples(p, discardLogger())
	if err != nil {
		t.Fatalf("toSamples() error = %v", err)
	}
	if got := sampleValue(t, samples, "last_handshake_timestamp_seconds"); got != 0 {
		t.Errorf("last_handshake_timestamp_seconds = %v, want 0 for zero handshake time", got)
	}
}

// TestBuildSamples_SkipsNonFinite exercises the NaN/Inf guard directly. A
// non-finite value cannot enter toSamples through JSON (encoding/json rejects
// overflowing numbers and cannot represent NaN), so the emit helper is driven
// with crafted values to prove only the offending sample is dropped and the
// skip is logged at Debug naming the field.
func TestBuildSamples_SkipsNonFinite(t *testing.T) {
	cases := []struct {
		name string
		bad  float64
	}{
		{"nan", math.NaN()},
		{"positive inf", math.Inf(1)},
		{"negative inf", math.Inf(-1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := &capturingHandler{}
			logger := slog.New(ch)
			ts := time.Now()

			values := []namedValue{
				{"first", 1},
				{"skipped_field", tc.bad},
				{"last", 3},
			}
			samples := buildSamples(api.MetricGroupNodeResources, nil, ts, values, logger)

			if got := sampleNames(samples); !slices.Equal(got, []string{"first", "last"}) {
				t.Fatalf("names = %v, want [first last]", got)
			}

			var logged bool
			for _, r := range ch.getRecords() {
				if r.Level != slog.LevelDebug {
					continue
				}
				r.Attrs(func(a slog.Attr) bool {
					if a.Key == "name" && a.Value.String() == "skipped_field" {
						logged = true
						return false
					}
					return true
				})
			}
			if !logged {
				t.Error("expected a Debug log naming the skipped field")
			}
		})
	}
}
