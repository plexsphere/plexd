package meshdns

import (
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

// boolPtr returns a pointer to b, for setting Config.Enabled explicitly.
func boolPtr(b bool) *bool { return &b }

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()

	if !cfg.IsEnabled() {
		t.Error("IsEnabled() = false, want true")
	}
	if cfg.Enabled != nil {
		t.Errorf("Enabled = %v, want nil (ApplyDefaults leaves it untouched)", *cfg.Enabled)
	}
	if cfg.ListenPort != DefaultListenPort {
		t.Errorf("ListenPort = %d, want %d", cfg.ListenPort, DefaultListenPort)
	}
	// The Name Resolution Policy Table sends to port 53 only, so Windows
	// listens there; every other platform keeps an unprivileged port.
	want := 5354
	if runtime.GOOS == "windows" {
		want = 53
	}
	if DefaultListenPort != want {
		t.Errorf("DefaultListenPort = %d on %s, want %d", DefaultListenPort, runtime.GOOS, want)
	}
}

// An existing deployment sets no dns key and gets the resolver, while
// `enabled: false` is the Node operator's way out and must survive
// ApplyDefaults. The wrapper stands in for the agent config, which nests the
// block under dns.
func TestConfig_YAML(t *testing.T) {
	tests := []struct {
		name        string
		doc         string
		wantEnabled bool
		wantPort    int
	}{
		{"no dns key", "log_level: info\n", true, DefaultListenPort},
		{"enabled false", "dns: {enabled: false}\n", false, DefaultListenPort},
		{"enabled true", "dns: {enabled: true}\n", true, DefaultListenPort},
		{"listen port only", "dns:\n  listen_port: 5300\n", true, 5300},
		{"disabled with port", "dns:\n  enabled: false\n  listen_port: 5300\n", false, 5300},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc struct {
				DNS Config `yaml:"dns"`
			}
			if err := yaml.Unmarshal([]byte(tt.doc), &doc); err != nil {
				t.Fatalf("yaml.Unmarshal: %v", err)
			}
			doc.DNS.ApplyDefaults()
			if got := doc.DNS.IsEnabled(); got != tt.wantEnabled {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.wantEnabled)
			}
			if doc.DNS.ListenPort != tt.wantPort {
				t.Errorf("ListenPort = %d, want %d", doc.DNS.ListenPort, tt.wantPort)
			}
		})
	}
}

func TestConfig_DefaultsPreserveExplicitDisabled(t *testing.T) {
	cfg := Config{Enabled: boolPtr(false)}
	cfg.ApplyDefaults()

	if cfg.IsEnabled() {
		t.Error("IsEnabled() = true, want false after an explicit enabled: false")
	}
	if cfg.ListenPort != DefaultListenPort {
		t.Errorf("ListenPort = %d, want %d (defaulted even while disabled)", cfg.ListenPort, DefaultListenPort)
	}
}

func TestConfig_DefaultsPreserveListenPort(t *testing.T) {
	cfg := Config{ListenPort: 5300}
	cfg.ApplyDefaults()

	if cfg.ListenPort != 5300 {
		t.Errorf("ListenPort = %d, want 5300", cfg.ListenPort)
	}
	if !cfg.IsEnabled() {
		t.Error("IsEnabled() = false, want true when only ListenPort was set")
	}
}

func TestConfig_IsEnabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"unset", Config{}, true},
		{"explicit true", Config{Enabled: boolPtr(true)}, true},
		{"explicit false", Config{Enabled: boolPtr(false)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsEnabled(); got != tt.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	const wantErr = "meshdns: config: ListenPort must be between 1 and 65535"
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"port 70000", Config{ListenPort: 70000}, true},
		{"port -1", Config{ListenPort: -1}, true},
		{"port 0 without defaults", Config{ListenPort: 0}, true},
		{"port 65536 explicitly enabled", Config{Enabled: boolPtr(true), ListenPort: 65536}, true},
		{"port 1", Config{ListenPort: 1}, false},
		{"port 65535", Config{ListenPort: 65535}, false},
		{"default port", Config{ListenPort: DefaultListenPort}, false},
		{"port 70000 disabled", Config{Enabled: boolPtr(false), ListenPort: 70000}, false},
		{"port -1 disabled", Config{Enabled: boolPtr(false), ListenPort: -1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if !tt.wantErr {
				if err != nil {
					t.Errorf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want %q", wantErr)
			}
			if err.Error() != wantErr {
				t.Errorf("Validate() error = %q, want %q", err.Error(), wantErr)
			}
		})
	}
}

func TestConfig_ValidateAcceptsDefaults(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
