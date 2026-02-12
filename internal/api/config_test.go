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
