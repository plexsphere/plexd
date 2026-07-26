package policy

import "testing"

// boolPtr returns a pointer to b, for setting Config.Enabled explicitly.
func boolPtr(b bool) *bool { return &b }

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if !cfg.IsEnabled() {
		t.Error("IsEnabled() = false, want true")
	}
	if cfg.ChainName != DefaultChainName {
		t.Errorf("ChainName = %q, want %q", cfg.ChainName, DefaultChainName)
	}
}

// An operator's explicit `enabled: false` is the only way to run a node without
// the deny-by-default baseline, so ApplyDefaults must not turn it back on — not
// even on a config that sets nothing else. ChainName used to double as the
// "explicitly constructed" marker, which made a bare `enabled: false` silently
// enabled again.
func TestConfig_DefaultsPreserveExplicitDisabled(t *testing.T) {
	cfg := Config{Enabled: boolPtr(false)}
	cfg.ApplyDefaults()

	if cfg.IsEnabled() {
		t.Error("IsEnabled() = true, want false after an explicit enabled: false")
	}
	if cfg.ChainName != DefaultChainName {
		t.Errorf("ChainName = %q, want %q (defaulted even while disabled)", cfg.ChainName, DefaultChainName)
	}
}

// The converse: naming a chain says nothing about whether enforcement is
// wanted, so a config that sets only ChainName stays enabled.
func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	cfg := Config{ChainName: "CUSTOM-CHAIN"}
	cfg.ApplyDefaults()

	if cfg.ChainName != "CUSTOM-CHAIN" {
		t.Errorf("ChainName = %q, want %q", cfg.ChainName, "CUSTOM-CHAIN")
	}
	if !cfg.IsEnabled() {
		t.Error("IsEnabled() = false, want true when only ChainName was set")
	}
}

func TestConfig_IsEnabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"unset", Config{}, true},
		{"explicit true", Config{Enabled: boolPtr(true)}, true},
		{"explicit false", Config{Enabled: boolPtr(false)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsEnabled(); got != tt.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_ValidateRejectsEmptyChainName(t *testing.T) {
	cfg := Config{
		Enabled:   boolPtr(true),
		ChainName: "",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty ChainName")
	}
	want := "policy: config: ChainName must not be empty when enabled"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateDisabledSkipsValidation(t *testing.T) {
	cfg := Config{
		Enabled:   boolPtr(false),
		ChainName: "",
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
		Enabled:   boolPtr(true),
		ChainName: "MY-CUSTOM-CHAIN",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
