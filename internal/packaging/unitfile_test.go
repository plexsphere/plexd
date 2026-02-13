package packaging

import (
	"strings"
	"testing"
)

func TestGenerateUnitFile_DefaultConfig(t *testing.T) {
	cfg := InstallConfig{}
	output := GenerateUnitFile(cfg)

	// Check sections exist
	if !strings.Contains(output, "[Unit]") {
		t.Error("output missing [Unit] section")
	}
	if !strings.Contains(output, "[Service]") {
		t.Error("output missing [Service] section")
	}
	if !strings.Contains(output, "[Install]") {
		t.Error("output missing [Install] section")
	}

	// Check key directives
	if !strings.Contains(output, "Type=simple") {
		t.Error("output missing Type=simple")
	}
	if !strings.Contains(output, "After=network-online.target") {
		t.Error("output missing After=network-online.target")
	}
	if !strings.Contains(output, "Restart=always") {
		t.Error("output missing Restart=always")
	}
	if !strings.Contains(output, "RestartSec=5s") {
		t.Error("output missing RestartSec=5s")
	}
	if !strings.Contains(output, "WantedBy=multi-user.target") {
		t.Error("output missing WantedBy=multi-user.target")
	}
}

func TestGenerateUnitFile_SecurityHardening(t *testing.T) {
	cfg := InstallConfig{}
	output := GenerateUnitFile(cfg)

	if !strings.Contains(output, "ProtectSystem=full") {
		t.Error("output missing ProtectSystem=full")
	}
	if !strings.Contains(output, "ProtectHome=true") {
		t.Error("output missing ProtectHome=true")
	}
	if !strings.Contains(output, "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW") {
		t.Error("output missing AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW")
	}
	if !strings.Contains(output, "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW") {
		t.Error("output missing CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW")
	}
}

func TestGenerateUnitFile_EnvironmentFile(t *testing.T) {
	cfg := InstallConfig{}
	output := GenerateUnitFile(cfg)

	if !strings.Contains(output, "EnvironmentFile=-/etc/plexd/environment") {
		t.Error("output missing EnvironmentFile=-/etc/plexd/environment")
	}
}

func TestGenerateUnitFile_CustomBinaryPath(t *testing.T) {
	cfg := InstallConfig{
		BinaryPath: "/opt/plexd/bin/plexd",
	}
	output := GenerateUnitFile(cfg)

	if !strings.Contains(output, "ExecStart=/opt/plexd/bin/plexd up --config") {
		t.Errorf("output missing custom ExecStart, got:\n%s", output)
	}
}

func TestGenerateUnitFile_CrashLoopProtection(t *testing.T) {
	cfg := InstallConfig{}
	output := GenerateUnitFile(cfg)

	if !strings.Contains(output, "StartLimitBurst=5") {
		t.Error("output missing StartLimitBurst=5")
	}
	if !strings.Contains(output, "StartLimitIntervalSec=60") {
		t.Error("output missing StartLimitIntervalSec=60")
	}
}

func TestGenerateUnitFile_FileDescriptorLimit(t *testing.T) {
	cfg := InstallConfig{}
	output := GenerateUnitFile(cfg)

	if !strings.Contains(output, "LimitNOFILE=65536") {
		t.Error("output missing LimitNOFILE=65536")
	}
}

func TestGenerateUnitFile_CustomPaths(t *testing.T) {
	cfg := InstallConfig{
		BinaryPath: "/opt/plexd/bin/plexd",
		ConfigDir:  "/opt/plexd/etc",
		DataDir:    "/opt/plexd/data",
		RunDir:     "/opt/plexd/run",
	}
	output := GenerateUnitFile(cfg)

	if !strings.Contains(output, "ExecStart=/opt/plexd/bin/plexd up --config /opt/plexd/etc/config.yaml") {
		t.Errorf("output missing custom ExecStart with config path, got:\n%s", output)
	}
	if !strings.Contains(output, "EnvironmentFile=-/opt/plexd/etc/environment") {
		t.Errorf("output missing custom EnvironmentFile, got:\n%s", output)
	}
	if !strings.Contains(output, "ReadWritePaths=/opt/plexd/data /opt/plexd/run") {
		t.Errorf("output missing custom ReadWritePaths, got:\n%s", output)
	}
}
