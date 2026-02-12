package nodeapi

import (
	"testing"
	"time"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{DataDir: "/var/lib/plexd"}
	cfg.ApplyDefaults()

	if cfg.SocketPath != "/var/run/plexd/api.sock" {
		t.Errorf("SocketPath = %q, want %q", cfg.SocketPath, "/var/run/plexd/api.sock")
	}
	if cfg.HTTPEnabled {
		t.Error("HTTPEnabled = true, want false")
	}
	if cfg.HTTPListen != "127.0.0.1:9100" {
		t.Errorf("HTTPListen = %q, want %q", cfg.HTTPListen, "127.0.0.1:9100")
	}
	if cfg.DebouncePeriod != 5*time.Second {
		t.Errorf("DebouncePeriod = %v, want %v", cfg.DebouncePeriod, 5*time.Second)
	}
	if cfg.ShutdownTimeout != 5*time.Second {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, 5*time.Second)
	}
}

func TestConfig_DefaultsPreserveExisting(t *testing.T) {
	cfg := Config{
		DataDir:         "/var/lib/plexd",
		SocketPath:      "/tmp/custom.sock",
		HTTPListen:      "0.0.0.0:8080",
		DebouncePeriod:  10 * time.Second,
		ShutdownTimeout: 30 * time.Second,
	}
	cfg.ApplyDefaults()

	if cfg.SocketPath != "/tmp/custom.sock" {
		t.Errorf("SocketPath = %q, want %q", cfg.SocketPath, "/tmp/custom.sock")
	}
	if cfg.HTTPListen != "0.0.0.0:8080" {
		t.Errorf("HTTPListen = %q, want %q", cfg.HTTPListen, "0.0.0.0:8080")
	}
	if cfg.DebouncePeriod != 10*time.Second {
		t.Errorf("DebouncePeriod = %v, want %v", cfg.DebouncePeriod, 10*time.Second)
	}
	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, 30*time.Second)
	}
}

func TestConfig_ValidateRequiresDataDir(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty DataDir")
	}
	if err.Error() != "nodeapi: config: DataDir is required" {
		t.Errorf("Validate() error = %q, want %q", err.Error(), "nodeapi: config: DataDir is required")
	}
}

func TestConfig_CustomValuesOverrideDefaults(t *testing.T) {
	cfg := Config{
		DataDir:         "/var/lib/plexd",
		SocketPath:      "/tmp/custom.sock",
		HTTPEnabled:     true,
		HTTPListen:      "0.0.0.0:8080",
		HTTPTokenFile:   "/etc/plexd/token",
		DebouncePeriod:  10 * time.Second,
		ShutdownTimeout: 30 * time.Second,
	}
	cfg.ApplyDefaults()

	if cfg.SocketPath != "/tmp/custom.sock" {
		t.Errorf("SocketPath = %q, want %q", cfg.SocketPath, "/tmp/custom.sock")
	}
	if !cfg.HTTPEnabled {
		t.Error("HTTPEnabled = false, want true")
	}
	if cfg.HTTPListen != "0.0.0.0:8080" {
		t.Errorf("HTTPListen = %q, want %q", cfg.HTTPListen, "0.0.0.0:8080")
	}
	if cfg.HTTPTokenFile != "/etc/plexd/token" {
		t.Errorf("HTTPTokenFile = %q, want %q", cfg.HTTPTokenFile, "/etc/plexd/token")
	}
	if cfg.DebouncePeriod != 10*time.Second {
		t.Errorf("DebouncePeriod = %v, want %v", cfg.DebouncePeriod, 10*time.Second)
	}
	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, 30*time.Second)
	}
}

func TestConfig_ValidateAcceptsValid(t *testing.T) {
	cfg := Config{
		DataDir:         "/var/lib/plexd",
		SocketPath:      "/tmp/custom.sock",
		DebouncePeriod:  10 * time.Second,
		ShutdownTimeout: 30 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestConfig_ValidateAcceptsDefaults(t *testing.T) {
	cfg := Config{DataDir: "/var/lib/plexd"}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
