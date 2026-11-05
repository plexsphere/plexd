package actions

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func boolPtr(v bool) *bool { return &v }

func TestConfig_ApplyDefaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if !cfg.IsEnabled() {
		t.Error("IsEnabled() = false, want true for an unset Enabled")
	}
	if cfg.HooksDir != DefaultHooksDir {
		t.Errorf("HooksDir = %q, want %q", cfg.HooksDir, DefaultHooksDir)
	}
	if cfg.MaxConcurrent != DefaultMaxConcurrent {
		t.Errorf("MaxConcurrent = %d, want %d", cfg.MaxConcurrent, DefaultMaxConcurrent)
	}
	if cfg.MaxActionTimeout != 10*time.Minute {
		t.Errorf("MaxActionTimeout = %v, want %v", cfg.MaxActionTimeout, 10*time.Minute)
	}
	if cfg.MaxOutputBytes != DefaultMaxOutputBytes {
		t.Errorf("MaxOutputBytes = %d, want %d", cfg.MaxOutputBytes, DefaultMaxOutputBytes)
	}
}

// TestConfig_DefaultsPreserveExplicitDisabled pins the kill switch against
// defaulting. The bare case is the one that matters: an operator writing only
// `actions:\n  enabled: false` leaves every other field zero, and Enabled is
// the only switch that stops the control plane from running actions and hooks
// on the node — defaulting must not flip it back on.
func TestConfig_DefaultsPreserveExplicitDisabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"only enabled set", Config{Enabled: boolPtr(false)}},
		{"with other non-zero fields", Config{Enabled: boolPtr(false), MaxConcurrent: 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.ApplyDefaults()

			if cfg.IsEnabled() {
				t.Error("IsEnabled() = true, want false for an explicit enabled: false")
			}
		})
	}
}

// TestConfig_MarshalYAMLRendersEffectiveEnabled pins what config.dump shows for
// the switch that gates remote execution. Enabled is a pointer, so an unset one
// would marshal as `enabled: null` — and an operator auditing which nodes accept
// control-plane execution reads a null as unset, which for this field reads as
// off while it means on.
func TestConfig_MarshalYAMLRendersEffectiveEnabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"unset renders the effective default", Config{}, "enabled: true"},
		{"explicit false is preserved", Config{Enabled: boolPtr(false)}, "enabled: false"},
		{"explicit true is preserved", Config{Enabled: boolPtr(true)}, "enabled: true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := yaml.Marshal(tt.cfg)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !strings.Contains(string(out), tt.want) {
				t.Errorf("Marshal() = %q, want it to contain %q", out, tt.want)
			}
		})
	}
}

// TestConfig_MarshalYAMLAsAgentField covers the shape config.dump actually
// marshals: the Config sits in the agent config as a value field, so the
// marshaler has to be reached through the enclosing struct.
func TestConfig_MarshalYAMLAsAgentField(t *testing.T) {
	out, err := yaml.Marshal(struct {
		Actions Config `yaml:"actions"`
	}{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(out), "enabled: null") {
		t.Errorf("Marshal() = %q, want no null for the execution kill switch", out)
	}
	if !strings.Contains(string(out), "enabled: true") {
		t.Errorf("Marshal() = %q, want it to contain %q", out, "enabled: true")
	}
}

// TestConfig_RolloutsEnabledDefaultsToTrue pins that a node which says nothing
// about rolled-out hooks accepts them: an omitted key, whether the actions
// block is empty or only sets other fields, reads as on after defaulting.
func TestConfig_RolloutsEnabledDefaultsToTrue(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"empty block", "{}\n"},
		{"other keys only", "enabled: true\nmax_concurrent: 3\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			if err := yaml.Unmarshal([]byte(tt.doc), &cfg); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			cfg.ApplyDefaults()

			if cfg.RolloutsEnabled != nil {
				t.Errorf("RolloutsEnabled = %v, want nil for an omitted key", *cfg.RolloutsEnabled)
			}
			if !cfg.IsRolloutsEnabled() {
				t.Error("IsRolloutsEnabled() = false, want true for an omitted rollouts_enabled")
			}
		})
	}
}

// TestConfig_DefaultsPreserveExplicitRolloutsDisabled pins the node owner's
// veto against defaulting. An operator who writes `rollouts_enabled: false`
// refuses scripts the control plane delivers, and a defaulting pass that turned
// it back on would install them anyway.
func TestConfig_DefaultsPreserveExplicitRolloutsDisabled(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"only rollouts_enabled set", "rollouts_enabled: false\n"},
		{"with actions enabled", "enabled: true\nrollouts_enabled: false\nmax_concurrent: 3\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			if err := yaml.Unmarshal([]byte(tt.doc), &cfg); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			cfg.ApplyDefaults()

			if cfg.IsRolloutsEnabled() {
				t.Error("IsRolloutsEnabled() = true, want false for an explicit rollouts_enabled: false")
			}
			// The veto is about delivered scripts only: it must not reach the
			// switch that gates builtins and hand-placed hooks.
			if !cfg.IsEnabled() {
				t.Error("IsEnabled() = false, want true: rollouts_enabled must not disable actions")
			}
		})
	}
}

// TestConfig_MarshalYAMLRendersEffectiveRolloutsEnabled pins what config.dump
// shows for the veto on rolled-out hooks. Like Enabled it is a pointer, so an
// unset one would marshal as null, which an operator reads as off while it
// means on. The dump is decoded rather than searched, because the text
// "enabled: true" is also a substring of "rollouts_enabled: true".
func TestConfig_MarshalYAMLRendersEffectiveRolloutsEnabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"unset renders the effective default", Config{}, true},
		{"explicit false is preserved", Config{RolloutsEnabled: boolPtr(false)}, false},
		{"explicit true is preserved", Config{RolloutsEnabled: boolPtr(true)}, true},
		{"independent of enabled", Config{Enabled: boolPtr(false)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := yaml.Marshal(struct {
				Actions Config `yaml:"actions"`
			}{tt.cfg})
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var dump struct {
				Actions map[string]any `yaml:"actions"`
			}
			if err := yaml.Unmarshal(out, &dump); err != nil {
				t.Fatalf("Unmarshal(%q): %v", out, err)
			}
			got, ok := dump.Actions["rollouts_enabled"]
			if !ok {
				t.Fatalf("Marshal() = %q, want a rollouts_enabled key", out)
			}
			if got != tt.want {
				t.Errorf("rollouts_enabled = %v, want %v (dump %q)", got, tt.want, out)
			}
		})
	}
}

func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	cfg := Config{
		MaxConcurrent: 10,
		HooksDir:      "/custom/hooks",
	}
	cfg.ApplyDefaults()

	if cfg.MaxConcurrent != 10 {
		t.Errorf("MaxConcurrent = %d, want 10", cfg.MaxConcurrent)
	}
	if cfg.HooksDir != "/custom/hooks" {
		t.Errorf("HooksDir = %q, want %q", cfg.HooksDir, "/custom/hooks")
	}
}

func TestConfig_ValidateRejectsLowMaxConcurrent(t *testing.T) {
	cfg := Config{
		Enabled:          boolPtr(true),
		MaxConcurrent:    0,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   1048576,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for low MaxConcurrent")
	}
	want := "actions: config: MaxConcurrent must be at least 1"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateRejectsLowMaxActionTimeout(t *testing.T) {
	cfg := Config{
		Enabled:          boolPtr(true),
		MaxConcurrent:    5,
		MaxActionTimeout: 5 * time.Second,
		MaxOutputBytes:   1048576,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for low MaxActionTimeout")
	}
	want := "actions: config: MaxActionTimeout must be at least 10s"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateRejectsLowMaxOutputBytes(t *testing.T) {
	cfg := Config{
		Enabled:          boolPtr(true),
		MaxConcurrent:    5,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   512,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for low MaxOutputBytes")
	}
	want := "actions: config: MaxOutputBytes must be at least 1024"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateDisabledSkipsValidation(t *testing.T) {
	cfg := Config{
		Enabled:          boolPtr(false),
		MaxConcurrent:    0,
		MaxActionTimeout: 0,
		MaxOutputBytes:   0,
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
		Enabled:          boolPtr(true),
		HooksDir:         "/etc/plexd/hooks",
		MaxConcurrent:    10,
		MaxActionTimeout: 30 * time.Minute,
		MaxOutputBytes:   2 << 20,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
