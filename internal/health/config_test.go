package health

import (
	"testing"
)

func boolPtr(v bool) *bool { return &v }

func TestConfig_ApplyDefaults(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		wantListen  string
		wantEnabled bool
	}{
		{
			name: "an omitted health block is enabled on the loopback default",
			cfg:  Config{},
			// Loopback, not the wildcard: the endpoints are unauthenticated,
			// so the default must not answer on the node's NICs or on the
			// WireGuard interface once the mesh is up.
			wantListen: "127.0.0.1:9101",
			// Enabled by default because the shipped DaemonSet probes /healthz
			// and /readyz unconditionally. With a default of off, an operator
			// who never heard of the health block gets a refused probe, a failed
			// liveness check and a restart loop that tears the WireGuard
			// interface and the firewall chain down on every node.
			wantEnabled: true,
		},
		{
			name:        "an explicit false disables the listener",
			cfg:         Config{Enabled: boolPtr(false)},
			wantListen:  "127.0.0.1:9101",
			wantEnabled: false,
		},
		{
			name:        "an explicit wildcard bind stays opt-in",
			cfg:         Config{Enabled: boolPtr(true), Listen: ":9101"},
			wantListen:  ":9101",
			wantEnabled: true,
		},
		{
			name:        "explicit listen is preserved",
			cfg:         Config{Listen: "127.0.0.1:8080"},
			wantListen:  "127.0.0.1:8080",
			wantEnabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.ApplyDefaults()

			if cfg.Listen != tt.wantListen {
				t.Errorf("Listen = %q, want %q", cfg.Listen, tt.wantListen)
			}
			if cfg.IsEnabled() != tt.wantEnabled {
				t.Errorf("IsEnabled() = %v, want %v", cfg.IsEnabled(), tt.wantEnabled)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	t.Run("empty listen is rejected", func(t *testing.T) {
		cfg := Config{}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("Validate() = nil, want error for empty Listen")
		}
		if err.Error() != "health: config: Listen is required" {
			t.Errorf("Validate() error = %q, want %q", err.Error(), "health: config: Listen is required")
		}
	})

	t.Run("defaulted config is valid", func(t *testing.T) {
		cfg := Config{}
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})

	t.Run("explicit listen is valid", func(t *testing.T) {
		cfg := Config{Listen: "127.0.0.1:8080"}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})
}
