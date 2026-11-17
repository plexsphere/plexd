package integrity

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func boolPtr(v bool) *bool { return &v }

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if !cfg.IsEnabled() {
		t.Error("IsEnabled() = false, want true for an absent integrity block")
	}
	if !cfg.IsWatchEnabled() {
		t.Error("IsWatchEnabled() = false, want true for an absent integrity block")
	}
	if cfg.VerifyInterval != DefaultVerifyInterval {
		t.Errorf("VerifyInterval = %v, want %v", cfg.VerifyInterval, DefaultVerifyInterval)
	}
}

func TestConfig_DefaultsPreserveExplicitDisabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"only enabled set", Config{Enabled: boolPtr(false)}},
		{"with an interval", Config{Enabled: boolPtr(false), VerifyInterval: 2 * time.Minute}},
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

func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	cfg := Config{
		VerifyInterval: 10 * time.Minute,
	}
	cfg.ApplyDefaults()

	if cfg.VerifyInterval != 10*time.Minute {
		t.Errorf("VerifyInterval = %v, want %v", cfg.VerifyInterval, 10*time.Minute)
	}
}

// TestConfig_ExplicitFalseSurvivesDefaults parses the integrity block the way
// ParseConfig does and applies defaults on top: an explicit false must come
// back false, and an omitted switch must come back on whatever else the block
// sets. A plain bool cannot tell the two apart, which is why both switches are
// pointers.
func TestConfig_ExplicitFalseSurvivesDefaults(t *testing.T) {
	tests := []struct {
		name         string
		doc          string
		wantEnabled  bool
		wantWatch    bool
		wantInterval time.Duration
	}{
		{"enabled false", "integrity: {enabled: false}\n", false, true, DefaultVerifyInterval},
		{"watch_enabled false", "integrity: {watch_enabled: false}\n", true, false, DefaultVerifyInterval},
		{"interval only", "integrity: {verify_interval: 10m}\n", true, true, 10 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc struct {
				Integrity Config `yaml:"integrity"`
			}
			if err := yaml.Unmarshal([]byte(tt.doc), &doc); err != nil {
				t.Fatalf("Unmarshal(%q): %v", tt.doc, err)
			}
			cfg := doc.Integrity
			cfg.ApplyDefaults()

			if got := cfg.IsEnabled(); got != tt.wantEnabled {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.wantEnabled)
			}
			if got := cfg.IsWatchEnabled(); got != tt.wantWatch {
				t.Errorf("IsWatchEnabled() = %v, want %v", got, tt.wantWatch)
			}
			if cfg.VerifyInterval != tt.wantInterval {
				t.Errorf("VerifyInterval = %v, want %v", cfg.VerifyInterval, tt.wantInterval)
			}
		})
	}
}

// TestConfig_MarshalYAMLRendersEffectiveSwitches pins what config.dump shows
// for the two switches. Both are pointers, so an unset one would marshal as
// null, which reads as off while it means on. The dump is decoded rather than
// searched, because "enabled: true" is also a substring of
// "watch_enabled: true".
func TestConfig_MarshalYAMLRendersEffectiveSwitches(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		wantEnabled bool
		wantWatch   bool
	}{
		{"unset renders the effective defaults", Config{}, true, true},
		{"explicit false is preserved", Config{Enabled: boolPtr(false), WatchEnabled: boolPtr(false)}, false, false},
		{"explicit true is preserved", Config{Enabled: boolPtr(true), WatchEnabled: boolPtr(true)}, true, true},
		{"switches are independent", Config{WatchEnabled: boolPtr(false)}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := yaml.Marshal(struct {
				Integrity Config `yaml:"integrity"`
			}{tt.cfg})
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var dump struct {
				Integrity map[string]any `yaml:"integrity"`
			}
			if err := yaml.Unmarshal(out, &dump); err != nil {
				t.Fatalf("Unmarshal(%q): %v", out, err)
			}
			for key, want := range map[string]bool{"enabled": tt.wantEnabled, "watch_enabled": tt.wantWatch} {
				got, ok := dump.Integrity[key]
				if !ok {
					t.Errorf("Marshal() = %q, want a %s key", out, key)
					continue
				}
				if got != want {
					t.Errorf("%s = %v, want %v (dump %q)", key, got, want, out)
				}
			}
		})
	}
}

func TestConfig_ValidateRejectsLowVerifyInterval(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"explicitly enabled", Config{Enabled: boolPtr(true), VerifyInterval: 10 * time.Second}},
		{"enabled by default", Config{VerifyInterval: 10 * time.Second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want error for low VerifyInterval")
			}
			want := "integrity: config: VerifyInterval must be at least 30s when enabled"
			if err.Error() != want {
				t.Errorf("Validate() error = %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestConfig_ValidateDisabledSkipsValidation(t *testing.T) {
	for _, interval := range []time.Duration{0, 10 * time.Second} {
		cfg := Config{
			Enabled:        boolPtr(false),
			VerifyInterval: interval,
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() with VerifyInterval %v = %v, want nil for disabled config", interval, err)
		}
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
		Enabled:        boolPtr(true),
		BinaryPath:     "/usr/local/bin/plexd",
		HooksDir:       "/etc/plexd/hooks",
		VerifyInterval: 10 * time.Minute,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
