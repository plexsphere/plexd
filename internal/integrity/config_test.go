package integrity

import (
	"testing"
	"time"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if !cfg.Enabled {
		t.Error("Enabled = false, want true")
	}
	if cfg.VerifyInterval != DefaultVerifyInterval {
		t.Errorf("VerifyInterval = %v, want %v", cfg.VerifyInterval, DefaultVerifyInterval)
	}
}

func TestConfig_DefaultsPreserveExplicitDisabled(t *testing.T) {
	cfg := Config{
		Enabled:        false,
		VerifyInterval: 2 * time.Minute,
	}
	cfg.ApplyDefaults()

	if cfg.Enabled {
		t.Error("Enabled = true, want false when explicitly configured with non-zero VerifyInterval")
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

func TestConfig_ValidateRejectsLowVerifyInterval(t *testing.T) {
	cfg := Config{
		Enabled:        true,
		VerifyInterval: 10 * time.Second,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for low VerifyInterval")
	}
	want := "integrity: config: VerifyInterval must be at least 30s when enabled"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateDisabledSkipsValidation(t *testing.T) {
	cfg := Config{
		Enabled:        false,
		VerifyInterval: 0,
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
		Enabled:        true,
		BinaryPath:     "/usr/local/bin/plexd",
		HooksDir:       "/etc/plexd/hooks",
		VerifyInterval: 10 * time.Minute,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
