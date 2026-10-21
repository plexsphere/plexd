package wireguard

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if cfg.InterfaceName != "plexd0" {
		t.Errorf("InterfaceName = %q, want %q", cfg.InterfaceName, "plexd0")
	}
	if cfg.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want %d", cfg.ListenPort, 51820)
	}
}

func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	cfg := Config{
		InterfaceName: "mesh0",
	}
	cfg.ApplyDefaults()

	if cfg.InterfaceName != "mesh0" {
		t.Errorf("InterfaceName = %q, want %q", cfg.InterfaceName, "mesh0")
	}
	if cfg.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want %d", cfg.ListenPort, 51820)
	}
}

func TestConfig_ValidateRejectsInvalidPort(t *testing.T) {
	cfg := Config{ListenPort: 0}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() = nil, want error for port 0")
	}

	cfg = Config{ListenPort: 70000}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() = nil, want error for port 70000")
	}
}

func TestConfig_ValidateRejectsNegativeMTU(t *testing.T) {
	cfg := Config{ListenPort: 51820, MTU: -1}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for negative MTU")
	}
	if err.Error() != "wireguard: config: MTU must not be negative" {
		t.Errorf("Validate() error = %q, want %q", err.Error(), "wireguard: config: MTU must not be negative")
	}
}

func TestConfig_ValidateAcceptsDefaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestConfig_ValidateAcceptsCustomValues(t *testing.T) {
	cfg := Config{
		InterfaceName: "mesh0",
		ListenPort:    51821,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestConfig_EdgePSKEnabled(t *testing.T) {
	enabled, disabled := true, false
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"unset", Config{}, true},
		{"true", Config{EdgePSK: &enabled}, true},
		{"false", Config{EdgePSK: &disabled}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.ApplyDefaults()
			if got := tt.cfg.EdgePSKEnabled(); got != tt.want {
				t.Errorf("EdgePSKEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_EdgePSKYAML(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("edge_psk: false\n"), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if cfg.EdgePSKEnabled() {
		t.Error("edge_psk: false parsed as enabled")
	}
}
