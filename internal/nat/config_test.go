package nat

import (
	"slices"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if !cfg.Enabled {
		t.Error("Enabled = false, want true")
	}
	if len(cfg.STUNServers) != len(DefaultSTUNServers) {
		t.Fatalf("STUNServers length = %d, want %d", len(cfg.STUNServers), len(DefaultSTUNServers))
	}
	for i, s := range cfg.STUNServers {
		if s != DefaultSTUNServers[i] {
			t.Errorf("STUNServers[%d] = %q, want %q", i, s, DefaultSTUNServers[i])
		}
	}
	if cfg.RefreshInterval != 60*time.Second {
		t.Errorf("RefreshInterval = %v, want %v", cfg.RefreshInterval, 60*time.Second)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, 5*time.Second)
	}
	if cfg.MinReportInterval != DefaultMinReportInterval {
		t.Errorf("MinReportInterval = %v, want %v", cfg.MinReportInterval, DefaultMinReportInterval)
	}
}

func TestConfig_DefaultsPreserveExplicitDisabled(t *testing.T) {
	cfg := Config{
		Enabled:     false,
		STUNServers: []string{"stun.example.com:3478"},
	}
	cfg.ApplyDefaults()

	if cfg.Enabled {
		t.Error("Enabled = true, want false when explicitly configured with other non-zero fields")
	}
}

func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	custom := []string{"stun.example.com:3478"}
	cfg := Config{
		STUNServers: custom,
	}
	cfg.ApplyDefaults()

	if len(cfg.STUNServers) != 1 || cfg.STUNServers[0] != "stun.example.com:3478" {
		t.Errorf("STUNServers = %v, want %v", cfg.STUNServers, custom)
	}
	if cfg.RefreshInterval != 60*time.Second {
		t.Errorf("RefreshInterval = %v, want %v", cfg.RefreshInterval, 60*time.Second)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, 5*time.Second)
	}
}

func TestConfig_ValidateRejectsEmptySTUNServers(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{},
		RefreshInterval: 60 * time.Second,
		Timeout:         5 * time.Second,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty STUNServers")
	}
	want := "nat: config: STUNServers must not be empty when enabled"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateRejectsLowRefreshInterval(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		STUNServers:     DefaultSTUNServers,
		RefreshInterval: 5 * time.Second,
		Timeout:         5 * time.Second,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for low RefreshInterval")
	}
	want := "nat: config: RefreshInterval must be at least 10s"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateRejectsNonPositiveTimeout(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		STUNServers:     DefaultSTUNServers,
		RefreshInterval: 60 * time.Second,
		Timeout:         0,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for zero Timeout")
	}
	want := "nat: config: Timeout must be positive"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}

	cfg.Timeout = -1 * time.Second
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for negative Timeout")
	}
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateRejectsNonPositiveMinReportInterval(t *testing.T) {
	cfg := Config{
		Enabled:           true,
		STUNServers:       DefaultSTUNServers,
		RefreshInterval:   60 * time.Second,
		Timeout:           5 * time.Second,
		MinReportInterval: 0,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for zero MinReportInterval")
	}
	want := "nat: config: MinReportInterval must be positive"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateDisabledSkipsSTUNValidation(t *testing.T) {
	cfg := Config{
		Enabled:         false,
		STUNServers:     nil,
		RefreshInterval: 0,
		Timeout:         0,
	}
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
	cfg := Config{
		Enabled:           true,
		STUNServers:       []string{"stun.example.com:3478"},
		RefreshInterval:   30 * time.Second,
		Timeout:           10 * time.Second,
		MinReportInterval: 15 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestConfig_LocalCandidatesEnabled(t *testing.T) {
	enabled, disabled := true, false
	tests := []struct {
		name  string
		value *bool
		want  bool
	}{
		{name: "nil", value: nil, want: true},
		{name: "true", value: &enabled, want: true},
		{name: "false", value: &disabled, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{LocalCandidates: tt.value}
			if got := cfg.LocalCandidatesEnabled(); got != tt.want {
				t.Errorf("LocalCandidatesEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_ValidateRejectsEmptyCandidateInterface(t *testing.T) {
	const want = "nat: config: CandidateInterfaces must not contain an empty name"
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "enabled", cfg: Config{
			Enabled:             true,
			STUNServers:         DefaultSTUNServers,
			RefreshInterval:     60 * time.Second,
			Timeout:             5 * time.Second,
			MinReportInterval:   10 * time.Second,
			CandidateInterfaces: []string{"ens3", " "},
		}},
		// The publisher runs whether or not STUN traversal is enabled, so the
		// check must not hide behind the Enabled early return.
		{name: "disabled", cfg: Config{
			Enabled:             false,
			CandidateInterfaces: []string{"ens3", " "},
		}},
		{name: "empty string", cfg: Config{
			Enabled:             false,
			CandidateInterfaces: []string{""},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want error for an empty CandidateInterfaces entry")
			}
			if err.Error() != want {
				t.Errorf("Validate() error = %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestConfig_ValidateAcceptsCandidateInterfaces(t *testing.T) {
	cfg := Config{CandidateInterfaces: []string{"ens3", "eth1"}}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestConfig_LocalCandidatesYAML(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("local_candidates: false\ncandidate_interfaces: [ens3]\n"), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if cfg.LocalCandidatesEnabled() {
		t.Error("local_candidates: false parsed as enabled")
	}
	if want := []string{"ens3"}; !slices.Equal(cfg.CandidateInterfaces, want) {
		t.Errorf("CandidateInterfaces = %v, want %v", cfg.CandidateInterfaces, want)
	}

	var unset Config
	if err := yaml.Unmarshal([]byte("refresh_interval: 30s\n"), &unset); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if !unset.LocalCandidatesEnabled() {
		t.Error("absent local_candidates parsed as disabled, want enabled")
	}
}
