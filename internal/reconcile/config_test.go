package reconcile

import (
	"testing"
	"time"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if cfg.Interval != 60*time.Second {
		t.Errorf("Interval = %v, want %v", cfg.Interval, 60*time.Second)
	}
}

func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	cfg := Config{
		Interval: 30 * time.Second,
	}
	cfg.ApplyDefaults()

	if cfg.Interval != 30*time.Second {
		t.Errorf("Interval = %v, want %v", cfg.Interval, 30*time.Second)
	}
}

func TestConfig_ValidateRejectsNegativeInterval(t *testing.T) {
	cfg := Config{Interval: -1 * time.Second}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for negative Interval")
	}
}

func TestConfig_ValidateRejectsSubSecondInterval(t *testing.T) {
	cfg := Config{Interval: 500 * time.Millisecond}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for sub-second Interval")
	}
}

func TestConfig_ValidateAcceptsValidInterval(t *testing.T) {
	cfg := Config{Interval: 30 * time.Second}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestConfig_ValidateAcceptsDefaultInterval(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
