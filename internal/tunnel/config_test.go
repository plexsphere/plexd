package tunnel

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
	if cfg.MaxSessions != DefaultMaxSessions {
		t.Errorf("MaxSessions = %d, want %d", cfg.MaxSessions, DefaultMaxSessions)
	}
	if cfg.DefaultTimeout != DefaultTimeout {
		t.Errorf("DefaultTimeout = %v, want %v", cfg.DefaultTimeout, DefaultTimeout)
	}
}

func TestConfig_DefaultsPreserveExplicitDisabled(t *testing.T) {
	cfg := Config{
		Enabled:     false,
		MaxSessions: 5,
	}
	cfg.ApplyDefaults()

	if cfg.Enabled {
		t.Error("Enabled = true, want false when explicitly configured with non-zero MaxSessions")
	}
}

func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	cfg := Config{
		MaxSessions: 20,
	}
	cfg.ApplyDefaults()

	if cfg.MaxSessions != 20 {
		t.Errorf("MaxSessions = %d, want %d", cfg.MaxSessions, 20)
	}
}

func TestConfig_ValidateRejectsInvalidMaxSessions(t *testing.T) {
	cfg := Config{
		Enabled:        true,
		MaxSessions:    0,
		DefaultTimeout: 5 * time.Minute,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for MaxSessions 0")
	}
	want := "tunnel: config: MaxSessions must be positive when enabled"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}

	cfg = Config{
		Enabled:        true,
		MaxSessions:    -1,
		DefaultTimeout: 5 * time.Minute,
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for MaxSessions -1")
	}
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateRejectsShortTimeout(t *testing.T) {
	cfg := Config{
		Enabled:        true,
		MaxSessions:    10,
		DefaultTimeout: 30 * time.Second,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for DefaultTimeout < 1m")
	}
	want := "tunnel: config: DefaultTimeout must be at least 1m when enabled"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateDisabledSkipsValidation(t *testing.T) {
	cfg := Config{
		Enabled:        false,
		MaxSessions:    0,
		DefaultTimeout: 0,
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
		MaxSessions:    50,
		DefaultTimeout: 10 * time.Minute,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
