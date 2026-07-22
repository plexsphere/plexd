package api

import (
	"testing"
	"time"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{BaseURL: "https://api.example.com"}
	cfg.ApplyDefaults()

	if cfg.ConnectTimeout != 10*time.Second {
		t.Errorf("ConnectTimeout = %v, want %v", cfg.ConnectTimeout, 10*time.Second)
	}
	if cfg.RequestTimeout != 30*time.Second {
		t.Errorf("RequestTimeout = %v, want %v", cfg.RequestTimeout, 30*time.Second)
	}
	if cfg.SSEIdleTimeout != 90*time.Second {
		t.Errorf("SSEIdleTimeout = %v, want %v", cfg.SSEIdleTimeout, 90*time.Second)
	}
	if cfg.TLSInsecureSkipVerify {
		t.Error("TLSInsecureSkipVerify = true, want false")
	}
}

func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	cfg := Config{
		BaseURL:        "https://api.example.com",
		ConnectTimeout: 5 * time.Second,
	}
	cfg.ApplyDefaults()

	if cfg.ConnectTimeout != 5*time.Second {
		t.Errorf("ConnectTimeout = %v, want %v", cfg.ConnectTimeout, 5*time.Second)
	}
	if cfg.RequestTimeout != 30*time.Second {
		t.Errorf("RequestTimeout = %v, want %v", cfg.RequestTimeout, 30*time.Second)
	}
	if cfg.SSEIdleTimeout != 90*time.Second {
		t.Errorf("SSEIdleTimeout = %v, want %v", cfg.SSEIdleTimeout, 90*time.Second)
	}
}

func TestConfig_ValidateRequiresBaseURL(t *testing.T) {
	cfg := Config{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty BaseURL")
	}
	if err.Error() != "api: config: BaseURL is required" {
		t.Errorf("Validate() error = %q, want %q", err.Error(), "api: config: BaseURL is required")
	}
}

func TestConfig_ValidateAcceptsValidURL(t *testing.T) {
	cfg := Config{BaseURL: "https://api.example.com"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestConfig_SSEReprobeIntervalDefault(t *testing.T) {
	cfg := Config{BaseURL: "https://api.example.com"}
	cfg.ApplyDefaults()
	if cfg.SSEReprobeInterval != DefaultSSEReprobeInterval {
		t.Errorf("SSEReprobeInterval = %v, want %v", cfg.SSEReprobeInterval, DefaultSSEReprobeInterval)
	}
}

func TestConfig_ValidateSSEReprobeInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		wantErr  string
	}{
		{"negative", -time.Second, "api: config: SSEReprobeInterval must not be negative"},
		{"below one second", 500 * time.Millisecond, "api: config: SSEReprobeInterval must be at least 1s"},
		{"one second is valid", 5 * time.Second, ""},
		{"zero is valid before defaults", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{BaseURL: "https://api.example.com", SSEReprobeInterval: tt.interval}
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want %q", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Errorf("Validate() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}
