package actions

import (
	"testing"
	"time"
)

func TestConfig_ApplyDefaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if !cfg.Enabled {
		t.Error("Enabled = false, want true")
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

func TestConfig_DefaultsPreserveExplicitDisabled(t *testing.T) {
	cfg := Config{
		Enabled:       false,
		MaxConcurrent: 3,
	}
	cfg.ApplyDefaults()

	if cfg.Enabled {
		t.Error("Enabled = true, want false when explicitly configured with other non-zero fields")
	}
}

func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	cfg := Config{
		MaxConcurrent: 10,
	}
	cfg.ApplyDefaults()

	if cfg.MaxConcurrent != 10 {
		t.Errorf("MaxConcurrent = %d, want 10", cfg.MaxConcurrent)
	}
}

func TestConfig_ValidateRejectsLowMaxConcurrent(t *testing.T) {
	cfg := Config{
		Enabled:          true,
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
		Enabled:          true,
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
		Enabled:          true,
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
		Enabled:          false,
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
		Enabled:          true,
		HooksDir:         "/etc/plexd/hooks",
		MaxConcurrent:    10,
		MaxActionTimeout: 30 * time.Minute,
		MaxOutputBytes:   2 << 20,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
