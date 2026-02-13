package packaging

import (
	"testing"
)

func TestInstallConfig_ApplyDefaults(t *testing.T) {
	cfg := InstallConfig{}
	cfg.ApplyDefaults()

	if cfg.BinaryPath != "/usr/local/bin/plexd" {
		t.Errorf("BinaryPath = %q, want %q", cfg.BinaryPath, "/usr/local/bin/plexd")
	}
	if cfg.ConfigDir != "/etc/plexd" {
		t.Errorf("ConfigDir = %q, want %q", cfg.ConfigDir, "/etc/plexd")
	}
	if cfg.DataDir != "/var/lib/plexd" {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, "/var/lib/plexd")
	}
	if cfg.RunDir != "/var/run/plexd" {
		t.Errorf("RunDir = %q, want %q", cfg.RunDir, "/var/run/plexd")
	}
	if cfg.ServiceName != "plexd" {
		t.Errorf("ServiceName = %q, want %q", cfg.ServiceName, "plexd")
	}
	if cfg.UnitFilePath != "/etc/systemd/system/plexd.service" {
		t.Errorf("UnitFilePath = %q, want %q", cfg.UnitFilePath, "/etc/systemd/system/plexd.service")
	}
	if cfg.APIBaseURL != "" {
		t.Errorf("APIBaseURL = %q, want empty", cfg.APIBaseURL)
	}
	if cfg.TokenValue != "" {
		t.Errorf("TokenValue = %q, want empty", cfg.TokenValue)
	}
	if cfg.TokenFile != "" {
		t.Errorf("TokenFile = %q, want empty", cfg.TokenFile)
	}
}

func TestInstallConfig_CustomValues(t *testing.T) {
	cfg := InstallConfig{
		BinaryPath:   "/opt/plexd/bin/plexd",
		ConfigDir:    "/opt/plexd/etc",
		DataDir:      "/opt/plexd/data",
		RunDir:       "/opt/plexd/run",
		UnitFilePath: "/usr/lib/systemd/system/plexd.service",
		ServiceName:  "plexd-custom",
		APIBaseURL:   "https://api.example.com",
		TokenValue:   "my-token",
		TokenFile:    "/custom/token",
	}
	cfg.ApplyDefaults()

	if cfg.BinaryPath != "/opt/plexd/bin/plexd" {
		t.Errorf("BinaryPath = %q, want %q", cfg.BinaryPath, "/opt/plexd/bin/plexd")
	}
	if cfg.ConfigDir != "/opt/plexd/etc" {
		t.Errorf("ConfigDir = %q, want %q", cfg.ConfigDir, "/opt/plexd/etc")
	}
	if cfg.DataDir != "/opt/plexd/data" {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, "/opt/plexd/data")
	}
	if cfg.RunDir != "/opt/plexd/run" {
		t.Errorf("RunDir = %q, want %q", cfg.RunDir, "/opt/plexd/run")
	}
	if cfg.UnitFilePath != "/usr/lib/systemd/system/plexd.service" {
		t.Errorf("UnitFilePath = %q, want %q", cfg.UnitFilePath, "/usr/lib/systemd/system/plexd.service")
	}
	if cfg.ServiceName != "plexd-custom" {
		t.Errorf("ServiceName = %q, want %q", cfg.ServiceName, "plexd-custom")
	}
	if cfg.APIBaseURL != "https://api.example.com" {
		t.Errorf("APIBaseURL = %q, want %q", cfg.APIBaseURL, "https://api.example.com")
	}
	if cfg.TokenValue != "my-token" {
		t.Errorf("TokenValue = %q, want %q", cfg.TokenValue, "my-token")
	}
	if cfg.TokenFile != "/custom/token" {
		t.Errorf("TokenFile = %q, want %q", cfg.TokenFile, "/custom/token")
	}
}

func TestInstallConfig_Validate(t *testing.T) {
	cfg := InstallConfig{}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestInstallConfig_Validate_EmptyFields(t *testing.T) {
	tests := []struct {
		name    string
		cfg     InstallConfig
		wantErr string
	}{
		{
			name: "empty BinaryPath",
			cfg: InstallConfig{
				ConfigDir:   "/etc/plexd",
				DataDir:     "/var/lib/plexd",
				RunDir:      "/var/run/plexd",
				ServiceName: "plexd",
			},
			wantErr: "packaging: config: BinaryPath is required",
		},
		{
			name: "empty ConfigDir",
			cfg: InstallConfig{
				BinaryPath:  "/usr/local/bin/plexd",
				DataDir:     "/var/lib/plexd",
				RunDir:      "/var/run/plexd",
				ServiceName: "plexd",
			},
			wantErr: "packaging: config: ConfigDir is required",
		},
		{
			name: "empty DataDir",
			cfg: InstallConfig{
				BinaryPath:  "/usr/local/bin/plexd",
				ConfigDir:   "/etc/plexd",
				RunDir:      "/var/run/plexd",
				ServiceName: "plexd",
			},
			wantErr: "packaging: config: DataDir is required",
		},
		{
			name: "empty RunDir",
			cfg: InstallConfig{
				BinaryPath:  "/usr/local/bin/plexd",
				ConfigDir:   "/etc/plexd",
				DataDir:     "/var/lib/plexd",
				ServiceName: "plexd",
			},
			wantErr: "packaging: config: RunDir is required",
		},
		{
			name: "empty ServiceName",
			cfg: InstallConfig{
				BinaryPath: "/usr/local/bin/plexd",
				ConfigDir:  "/etc/plexd",
				DataDir:    "/var/lib/plexd",
				RunDir:     "/var/run/plexd",
			},
			wantErr: "packaging: config: ServiceName is required",
		},
		{
			name: "empty UnitFilePath",
			cfg: InstallConfig{
				BinaryPath:  "/usr/local/bin/plexd",
				ConfigDir:   "/etc/plexd",
				DataDir:     "/var/lib/plexd",
				RunDir:      "/var/run/plexd",
				ServiceName: "plexd",
			},
			wantErr: "packaging: config: UnitFilePath is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error %q", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Errorf("Validate() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}
