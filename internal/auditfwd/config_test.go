package auditfwd

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
	if cfg.CollectInterval != 5*time.Second {
		t.Errorf("CollectInterval = %v, want %v", cfg.CollectInterval, 5*time.Second)
	}
	if cfg.ReportInterval != 15*time.Second {
		t.Errorf("ReportInterval = %v, want %v", cfg.ReportInterval, 15*time.Second)
	}
	if cfg.BatchSize != DefaultBatchSize {
		t.Errorf("BatchSize = %d, want %d", cfg.BatchSize, DefaultBatchSize)
	}
}

func TestConfig_DefaultsPreserveExplicitDisabled(t *testing.T) {
	cfg := Config{
		Enabled:         false,
		CollectInterval: 15 * time.Second,
	}
	cfg.ApplyDefaults()

	if cfg.Enabled {
		t.Error("Enabled = true, want false when explicitly configured with other non-zero fields")
	}
}

func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	cfg := Config{
		CollectInterval: 15 * time.Second,
	}
	cfg.ApplyDefaults()

	if cfg.CollectInterval != 15*time.Second {
		t.Errorf("CollectInterval = %v, want %v", cfg.CollectInterval, 15*time.Second)
	}
	if cfg.ReportInterval != 15*time.Second {
		t.Errorf("ReportInterval = %v, want %v", cfg.ReportInterval, 15*time.Second)
	}
}

func TestConfig_ValidateRejectsLowCollectInterval(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		CollectInterval: 500 * time.Millisecond,
		ReportInterval:  15 * time.Second,
		BatchSize:       500,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for low CollectInterval")
	}
	want := "auditfwd: config: CollectInterval must be at least 1s"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateRejectsReportIntervalBelowCollect(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		CollectInterval: 30 * time.Second,
		ReportInterval:  20 * time.Second,
		BatchSize:       500,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for ReportInterval < CollectInterval")
	}
	want := "auditfwd: config: ReportInterval must be >= CollectInterval"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateDisabledSkipsValidation(t *testing.T) {
	cfg := Config{
		Enabled:         false,
		CollectInterval: 0,
		ReportInterval:  0,
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
		Enabled:         true,
		CollectInterval: 10 * time.Second,
		ReportInterval:  30 * time.Second,
		BatchSize:       50,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestConfig_ValidateRejectsBatchSizeZero(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		CollectInterval: 10 * time.Second,
		ReportInterval:  30 * time.Second,
		BatchSize:       0,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for BatchSize=0")
	}
	want := "auditfwd: config: BatchSize must be at least 1"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_DefaultsBatchSizePreservesExisting(t *testing.T) {
	cfg := Config{
		BatchSize: 50,
	}
	cfg.ApplyDefaults()

	if cfg.BatchSize != 50 {
		t.Errorf("BatchSize = %d, want 50", cfg.BatchSize)
	}
}

func TestConfig_ValidateAcceptsMinimumCollectInterval(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		CollectInterval: time.Second,
		ReportInterval:  15 * time.Second,
		BatchSize:       500,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for CollectInterval=1s", err)
	}
}
