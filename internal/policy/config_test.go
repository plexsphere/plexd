package policy

import "testing"

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if !cfg.Enabled {
		t.Error("Enabled = false, want true")
	}
	if cfg.ChainName != DefaultChainName {
		t.Errorf("ChainName = %q, want %q", cfg.ChainName, DefaultChainName)
	}
}

func TestConfig_DefaultsPreserveExplicitDisabled(t *testing.T) {
	cfg := Config{
		Enabled:   false,
		ChainName: "CUSTOM-CHAIN",
	}
	cfg.ApplyDefaults()

	if cfg.Enabled {
		t.Error("Enabled = true, want false when explicitly configured with non-zero ChainName")
	}
}

func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	cfg := Config{
		ChainName: "CUSTOM-CHAIN",
	}
	cfg.ApplyDefaults()

	if cfg.ChainName != "CUSTOM-CHAIN" {
		t.Errorf("ChainName = %q, want %q", cfg.ChainName, "CUSTOM-CHAIN")
	}
}

func TestConfig_ValidateRejectsEmptyChainName(t *testing.T) {
	cfg := Config{
		Enabled:   true,
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
		Enabled:   false,
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
		Enabled:   true,
		ChainName: "MY-CUSTOM-CHAIN",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
