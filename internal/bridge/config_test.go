package bridge

import (
	"strings"
	"testing"
)

func TestConfig_ApplyDefaults(t *testing.T) {
	var cfg Config
	cfg.ApplyDefaults()

	if cfg.Enabled {
		t.Error("Enabled should default to false")
	}
	if cfg.EnableNAT != nil {
		t.Error("EnableNAT should remain nil after ApplyDefaults")
	}
	if !cfg.natEnabled() {
		t.Error("natEnabled() should return true for nil EnableNAT")
	}
	if cfg.AccessInterface != "" {
		t.Error("AccessInterface should remain empty")
	}
	if len(cfg.AccessSubnets) != 0 {
		t.Error("AccessSubnets should remain empty")
	}
}

func TestConfig_NatEnabled(t *testing.T) {
	tests := []struct {
		name      string
		enableNAT *bool
		want      bool
	}{
		{"nil defaults to true", nil, true},
		{"explicit true", BoolPtr(true), true},
		{"explicit false", BoolPtr(false), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{EnableNAT: tt.enableNAT}
			if got := cfg.natEnabled(); got != tt.want {
				t.Errorf("natEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Validate_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil when disabled, got: %v", err)
	}
}

func TestConfig_Validate_MissingAccessInterface(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		AccessSubnets: []string{"10.0.0.0/24"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error for missing AccessInterface")
	}
	want := "bridge: config: AccessInterface is required when enabled"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestConfig_Validate_MissingAccessSubnets(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error for missing AccessSubnets")
	}
	want := "bridge: config: at least one AccessSubnet is required when enabled"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestConfig_Validate_InvalidCIDR(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"not-a-cidr"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error for invalid CIDR")
	}
	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("error should mention invalid CIDR, got: %v", err)
	}
}

func TestConfig_Validate_ValidConfig(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24", "192.168.1.0/24"},
		EnableNAT:       BoolPtr(true),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil for valid config, got: %v", err)
	}
}
