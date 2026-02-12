package metrics

import "testing"

func TestGroupConstants(t *testing.T) {
	if GroupSystem != "system" {
		t.Errorf("GroupSystem = %q, want %q", GroupSystem, "system")
	}
	if GroupTunnel != "tunnel" {
		t.Errorf("GroupTunnel = %q, want %q", GroupTunnel, "tunnel")
	}
	if GroupLatency != "latency" {
		t.Errorf("GroupLatency = %q, want %q", GroupLatency, "latency")
	}
}
