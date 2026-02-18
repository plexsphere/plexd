package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if !cfg.Enabled {
		t.Error("Enabled = false, want true")
	}
	if cfg.CollectInterval != 15*time.Second {
		t.Errorf("CollectInterval = %v, want %v", cfg.CollectInterval, 15*time.Second)
	}
	if cfg.ReportInterval != 60*time.Second {
		t.Errorf("ReportInterval = %v, want %v", cfg.ReportInterval, 60*time.Second)
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
	if cfg.ReportInterval != 60*time.Second {
		t.Errorf("ReportInterval = %v, want %v", cfg.ReportInterval, 60*time.Second)
	}
}

func TestConfig_ValidateRejectsLowCollectInterval(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		CollectInterval: 3 * time.Second,
		ReportInterval:  60 * time.Second,
		BatchSize:       100,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for low CollectInterval")
	}
	want := "metrics: config: CollectInterval must be at least 5s"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateRejectsLowReportInterval(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		CollectInterval: 5 * time.Second,
		ReportInterval:  8 * time.Second,
		BatchSize:       100,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for low ReportInterval")
	}
	want := "metrics: config: ReportInterval must be at least 10s"
	if err.Error() != want {
		t.Errorf("Validate() error = %q, want %q", err.Error(), want)
	}
}

func TestConfig_ValidateRejectsReportLessThanCollect(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		CollectInterval: 30 * time.Second,
		ReportInterval:  20 * time.Second,
		BatchSize:       100,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for ReportInterval < CollectInterval")
	}
	want := "metrics: config: ReportInterval must be >= CollectInterval"
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

func TestConfig_ValidateRejectsZeroBatchSize(t *testing.T) {
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
	want := "metrics: config: BatchSize must be > 0"
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

func TestConfig_ValidateLocalEndpoint(t *testing.T) {
	validBase := Config{
		Enabled:         true,
		CollectInterval: 10 * time.Second,
		ReportInterval:  60 * time.Second,
		BatchSize:       100,
	}

	tests := []struct {
		name       string
		endpoint   api.LocalEndpointConfig
		enabled    bool
		wantErr    bool
		errContain string
	}{
		{
			name:     "valid HTTPS endpoint",
			enabled:  true,
			endpoint: api.LocalEndpointConfig{URL: "https://metrics.local:9090/ingest", SecretKey: "local-metrics-token"},
		},
		{
			name:       "rejects HTTP endpoint",
			enabled:    true,
			endpoint:   api.LocalEndpointConfig{URL: "http://metrics.local:9090/ingest", SecretKey: "local-metrics-token"},
			wantErr:    true,
			errContain: "metrics",
		},
		{
			name:       "requires secret key",
			enabled:    true,
			endpoint:   api.LocalEndpointConfig{URL: "https://metrics.local:9090/ingest"},
			wantErr:    true,
			errContain: "SecretKey",
		},
		{
			name:     "disabled config skips endpoint validation",
			enabled:  false,
			endpoint: api.LocalEndpointConfig{URL: "http://invalid-but-disabled"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBase
			cfg.Enabled = tt.enabled
			cfg.LocalEndpoint = tt.endpoint

			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Validate() = nil, want error containing %q", tt.errContain)
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("Validate() error = %q, want error containing %q", err.Error(), tt.errContain)
				}
				return
			}
			if err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}
