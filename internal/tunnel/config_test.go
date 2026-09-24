package tunnel

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
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

func TestConfig_SSHSessionsAllowed(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want bool
	}{
		{"key absent", "enabled: true\n", true},
		{"explicit true", "ssh_sessions_enabled: true\n", true},
		{"explicit false", "ssh_sessions_enabled: false\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			if err := yaml.Unmarshal([]byte(tc.yaml), &cfg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := cfg.SSHSessionsAllowed(); got != tc.want {
				t.Errorf("SSHSessionsAllowed() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConfig_ValidateSessionSigningPublicKey(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	const prefix = "tunnel: config: session_signing_public_key: "

	for _, tc := range []struct {
		name    string
		enabled bool
		key     string
		wantErr bool
	}{
		{"empty", true, "", false},
		{"valid", true, valid, false},
		{"invalid", true, "not base64!", true},
		{"invalid under enabled: false", false, "not base64!", true},
		{"short key", true, base64.StdEncoding.EncodeToString(make([]byte, 31)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Enabled: tc.enabled, MaxSessions: 1, DefaultTimeout: time.Minute, SessionSigningPublicKey: tc.key}
			err := cfg.Validate()
			if !tc.wantErr {
				if err != nil {
					t.Errorf("Validate() error: %v", err)
				}
				return
			}
			if err == nil || !strings.HasPrefix(err.Error(), prefix) {
				t.Errorf("Validate() error = %v, want prefix %q", err, prefix)
			}
		})
	}
}
