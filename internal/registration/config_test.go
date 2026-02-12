package registration

import (
	"testing"
	"time"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{DataDir: "/var/lib/plexd"}
	cfg.ApplyDefaults()

	if cfg.MaxRetryDuration != 5*time.Minute {
		t.Errorf("MaxRetryDuration = %v, want %v", cfg.MaxRetryDuration, 5*time.Minute)
	}
	if cfg.TokenFile != "/etc/plexd/bootstrap-token" {
		t.Errorf("TokenFile = %q, want %q", cfg.TokenFile, "/etc/plexd/bootstrap-token")
	}
	if cfg.TokenEnv != "PLEXD_BOOTSTRAP_TOKEN" {
		t.Errorf("TokenEnv = %q, want %q", cfg.TokenEnv, "PLEXD_BOOTSTRAP_TOKEN")
	}
	if cfg.UseMetadata {
		t.Error("UseMetadata = true, want false")
	}
	if cfg.Hostname != "" {
		t.Errorf("Hostname = %q, want empty", cfg.Hostname)
	}
	if cfg.TokenValue != "" {
		t.Errorf("TokenValue = %q, want empty", cfg.TokenValue)
	}
}

func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	cfg := Config{
		DataDir:          "/var/lib/plexd",
		TokenFile:        "/custom/token",
		TokenEnv:         "CUSTOM_TOKEN",
		MaxRetryDuration: 10 * time.Minute,
	}
	cfg.ApplyDefaults()

	if cfg.TokenFile != "/custom/token" {
		t.Errorf("TokenFile = %q, want %q", cfg.TokenFile, "/custom/token")
	}
	if cfg.TokenEnv != "CUSTOM_TOKEN" {
		t.Errorf("TokenEnv = %q, want %q", cfg.TokenEnv, "CUSTOM_TOKEN")
	}
	if cfg.MaxRetryDuration != 10*time.Minute {
		t.Errorf("MaxRetryDuration = %v, want %v", cfg.MaxRetryDuration, 10*time.Minute)
	}
}

func TestConfig_ValidateRequiresDataDir(t *testing.T) {
	cfg := Config{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty DataDir")
	}
	if err.Error() != "registration: config: DataDir is required" {
		t.Errorf("Validate() error = %q, want %q", err.Error(), "registration: config: DataDir is required")
	}
}

func TestConfig_ValidateAcceptsValidConfig(t *testing.T) {
	cfg := Config{DataDir: "/var/lib/plexd"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
