package bridge

import (
	"strings"
	"testing"
	"time"
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

func TestConfig_ApplyDefaults_RelayFields(t *testing.T) {
	var cfg Config
	cfg.ApplyDefaults()

	if cfg.RelayEnabled {
		t.Error("RelayEnabled should default to false")
	}
	if cfg.RelayListenPort != DefaultRelayListenPort {
		t.Errorf("RelayListenPort = %d, want %d", cfg.RelayListenPort, DefaultRelayListenPort)
	}
	if cfg.MaxRelaySessions != DefaultMaxRelaySessions {
		t.Errorf("MaxRelaySessions = %d, want %d", cfg.MaxRelaySessions, DefaultMaxRelaySessions)
	}
	if cfg.SessionTTL != DefaultSessionTTL {
		t.Errorf("SessionTTL = %v, want %v", cfg.SessionTTL, DefaultSessionTTL)
	}
}

func TestConfig_Validate_RelayDisabled(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		RelayEnabled:    false,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil when relay is disabled, got: %v", err)
	}
}

func TestConfig_Validate_RelayWithoutBridge(t *testing.T) {
	cfg := Config{
		Enabled:      false,
		RelayEnabled: true,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error when relay enabled without bridge")
	}
	want := "bridge: config: relay requires bridge mode to be enabled"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestConfig_Validate_RelayBoundaryPorts(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"port 1 (min valid)", 1, false},
		{"port 65535 (max valid)", 65535, false},
		{"port 65536 (just over max)", 65536, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:          true,
				AccessInterface:  "eth1",
				AccessSubnets:    []string{"10.0.0.0/24"},
				RelayEnabled:     true,
				RelayListenPort:  tt.port,
				MaxRelaySessions: 100,
				SessionTTL:       5 * time.Minute,
			}
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate should return error for out-of-range port")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate should return nil for valid port %d, got: %v", tt.port, err)
			}
		})
	}
}

func TestConfig_Validate_RelayInvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"port zero", 0},
		{"port too high", 70000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:          true,
				AccessInterface:  "eth1",
				AccessSubnets:    []string{"10.0.0.0/24"},
				RelayEnabled:     true,
				RelayListenPort:  tt.port,
				MaxRelaySessions: 100,
				SessionTTL:       5 * time.Minute,
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate should return error for invalid port")
			}
			want := "bridge: config: RelayListenPort must be between 1 and 65535"
			if err.Error() != want {
				t.Errorf("got %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestConfig_Validate_RelayInvalidMaxSessions(t *testing.T) {
	tests := []struct {
		name        string
		maxSessions int
	}{
		{"zero sessions", 0},
		{"negative sessions", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:          true,
				AccessInterface:  "eth1",
				AccessSubnets:    []string{"10.0.0.0/24"},
				RelayEnabled:     true,
				RelayListenPort:  51821,
				MaxRelaySessions: tt.maxSessions,
				SessionTTL:       5 * time.Minute,
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate should return error for invalid MaxRelaySessions")
			}
			want := "bridge: config: MaxRelaySessions must be positive when relay is enabled"
			if err.Error() != want {
				t.Errorf("got %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestConfig_Validate_RelayInvalidSessionTTL(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		AccessInterface:  "eth1",
		AccessSubnets:    []string{"10.0.0.0/24"},
		RelayEnabled:     true,
		RelayListenPort:  51821,
		MaxRelaySessions: 100,
		SessionTTL:       10 * time.Second,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error for SessionTTL below 30s")
	}
	want := "bridge: config: SessionTTL must be at least 30s"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestConfig_Validate_RelayValidConfig(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		AccessInterface:  "eth1",
		AccessSubnets:    []string{"10.0.0.0/24"},
		RelayEnabled:     true,
		RelayListenPort:  51821,
		MaxRelaySessions: 100,
		SessionTTL:       5 * time.Minute,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil for valid relay config, got: %v", err)
	}
}

func TestConfig_ApplyDefaults_UserAccessFields(t *testing.T) {
	var cfg Config
	cfg.ApplyDefaults()

	if cfg.UserAccessEnabled {
		t.Error("UserAccessEnabled should default to false")
	}
	if cfg.UserAccessInterfaceName != DefaultUserAccessInterfaceName {
		t.Errorf("UserAccessInterfaceName = %q, want %q", cfg.UserAccessInterfaceName, DefaultUserAccessInterfaceName)
	}
	if cfg.UserAccessListenPort != DefaultUserAccessListenPort {
		t.Errorf("UserAccessListenPort = %d, want %d", cfg.UserAccessListenPort, DefaultUserAccessListenPort)
	}
	if cfg.MaxAccessPeers != DefaultMaxAccessPeers {
		t.Errorf("MaxAccessPeers = %d, want %d", cfg.MaxAccessPeers, DefaultMaxAccessPeers)
	}
}

func TestConfig_Validate_UserAccessWithoutBridge(t *testing.T) {
	cfg := Config{
		Enabled:           false,
		UserAccessEnabled: true,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error when user access enabled without bridge")
	}
	want := "bridge: config: user access requires bridge mode to be enabled"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestConfig_Validate_UserAccessInvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"port zero", 0},
		{"port too high", 70000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:                true,
				AccessInterface:        "eth1",
				AccessSubnets:          []string{"10.0.0.0/24"},
				UserAccessEnabled:      true,
				UserAccessInterfaceName: "wg-access",
				UserAccessListenPort:   tt.port,
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate should return error for invalid port")
			}
			want := "bridge: config: UserAccessListenPort must be between 1 and 65535"
			if err.Error() != want {
				t.Errorf("got %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestConfig_Validate_UserAccessBoundaryPorts(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"port 1 (min valid)", 1, false},
		{"port 65535 (max valid)", 65535, false},
		{"port 65536 (just over max)", 65536, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:                true,
				AccessInterface:        "eth1",
				AccessSubnets:          []string{"10.0.0.0/24"},
				UserAccessEnabled:      true,
				UserAccessInterfaceName: "wg-access",
				UserAccessListenPort:   tt.port,
				MaxAccessPeers:         50,
			}
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate should return error for out-of-range port")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate should return nil for valid port %d, got: %v", tt.port, err)
			}
		})
	}
}

func TestConfig_Validate_UserAccessValidConfig(t *testing.T) {
	cfg := Config{
		Enabled:                true,
		AccessInterface:        "eth1",
		AccessSubnets:          []string{"10.0.0.0/24"},
		UserAccessEnabled:      true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:   51822,
		MaxAccessPeers:         50,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil for valid user access config, got: %v", err)
	}
}

func TestConfig_Validate_UserAccessMissingAccessSubnets(t *testing.T) {
	cfg := Config{
		Enabled:                true,
		AccessInterface:        "eth1",
		UserAccessEnabled:      true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:   51822,
		MaxAccessPeers:         50,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error when AccessSubnets is empty")
	}
	want := "bridge: config: at least one AccessSubnet is required when enabled"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestConfig_Validate_UserAccessInvalidMaxPeers(t *testing.T) {
	tests := []struct {
		name     string
		maxPeers int
	}{
		{"zero peers", 0},
		{"negative peers", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:                true,
				AccessInterface:        "eth1",
				AccessSubnets:          []string{"10.0.0.0/24"},
				UserAccessEnabled:      true,
				UserAccessInterfaceName: "wg-access",
				UserAccessListenPort:   51822,
				MaxAccessPeers:         tt.maxPeers,
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate should return error for invalid MaxAccessPeers")
			}
			want := "bridge: config: MaxAccessPeers must be positive when user access is enabled"
			if err.Error() != want {
				t.Errorf("got %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestConfig_Validate_UserAccessDisabled(t *testing.T) {
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		UserAccessEnabled: false,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil when user access is disabled, got: %v", err)
	}
}
