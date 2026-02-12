package peerexchange

import (
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/nat"
)

func TestConfig_ApplyDefaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if !cfg.Enabled {
		t.Error("Enabled = false, want true")
	}
	if len(cfg.STUNServers) != len(nat.DefaultSTUNServers) {
		t.Fatalf("STUNServers length = %d, want %d", len(cfg.STUNServers), len(nat.DefaultSTUNServers))
	}
	for i, s := range cfg.STUNServers {
		if s != nat.DefaultSTUNServers[i] {
			t.Errorf("STUNServers[%d] = %q, want %q", i, s, nat.DefaultSTUNServers[i])
		}
	}
	if cfg.RefreshInterval != 60*time.Second {
		t.Errorf("RefreshInterval = %v, want %v", cfg.RefreshInterval, 60*time.Second)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, 5*time.Second)
	}
}

func TestConfig_ValidateRejectsEmptySTUNServers(t *testing.T) {
	cfg := Config{}
	cfg.Enabled = true
	cfg.STUNServers = []string{}
	cfg.RefreshInterval = 60 * time.Second
	cfg.Timeout = 5 * time.Second

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty STUNServers")
	}
}

func TestConfig_ValidateRejectsLowRefreshInterval(t *testing.T) {
	cfg := Config{}
	cfg.Enabled = true
	cfg.STUNServers = nat.DefaultSTUNServers
	cfg.RefreshInterval = 5 * time.Second
	cfg.Timeout = 5 * time.Second

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for low RefreshInterval")
	}
}

func TestConfig_ValidateDisabledSkipsValidation(t *testing.T) {
	cfg := Config{}
	cfg.Enabled = false
	cfg.STUNServers = nil
	cfg.RefreshInterval = 0
	cfg.Timeout = 0

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for disabled config", err)
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
	cfg := Config{}
	cfg.Enabled = true
	cfg.STUNServers = []string{"stun.example.com:3478"}
	cfg.RefreshInterval = 30 * time.Second
	cfg.Timeout = 10 * time.Second

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
