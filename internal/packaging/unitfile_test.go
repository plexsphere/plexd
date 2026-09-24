package packaging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/tunnel"
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
	// ConfigDir is set explicitly rather than defaulted: a systemd unit is a
	// Linux artifact whatever host generates it, so the rendering under test
	// is the Linux one on every runner.
	cfg := InstallConfig{ConfigDir: "/etc/plexd"}
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

func TestGenerateUnitFile_SessionHelperSocketDependency(t *testing.T) {
	output := GenerateUnitFile(InstallConfig{})

	for _, line := range []string{
		"Wants=plexd-session-helper.socket",
		"After=plexd-session-helper.socket",
		"Also=plexd-session-helper.socket",
		// The sandbox stays: the helper is what runs outside it.
		"ProtectSystem=full",
		"ProtectHome=true",
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW",
	} {
		if !strings.Contains(output, "\n"+line+"\n") {
			t.Errorf("unit file missing %q, got:\n%s", line, output)
		}
	}
	unit, install, _ := strings.Cut(output, "[Install]")
	if !strings.Contains(install, "Also=plexd-session-helper.socket") || strings.Contains(unit, "Also=") {
		t.Errorf("Also= must sit in [Install], got:\n%s", output)
	}
}

func TestGenerateSessionHelperSocketUnit(t *testing.T) {
	want := `[Unit]
Description=plexd session helper socket

[Socket]
ListenStream=/run/plexd-session-helper.sock
SocketMode=0600
SocketUser=root
SocketGroup=root
Accept=yes
MaxConnections=512
TriggerLimitIntervalSec=0

[Install]
WantedBy=sockets.target
`
	if got := GenerateSessionHelperSocketUnit(); got != want {
		t.Errorf("socket unit =\n%s\nwant\n%s", got, want)
	}
	// plexd dials the path the socket listens on.
	if sessionHelperSocketPath != tunnel.DefaultSessionHelperSocket {
		t.Errorf("socket path %q differs from the path plexd dials, %q", sessionHelperSocketPath, tunnel.DefaultSessionHelperSocket)
	}
}

func TestGenerateSessionHelperServiceUnit(t *testing.T) {
	want := `[Unit]
Description=plexd session helper (one mediated ssh process)
CollectMode=inactive-or-failed

[Service]
Type=simple
ExecStart=/opt/plexd/bin/plexd session-helper --config /srv/plexd/config.yaml
StandardInput=null
StandardOutput=journal
StandardError=journal
KillMode=control-group
`
	got := GenerateSessionHelperServiceUnit(InstallConfig{BinaryPath: "/opt/plexd/bin/plexd", ConfigDir: "/srv/plexd"})
	if got != want {
		t.Errorf("service unit =\n%s\nwant\n%s", got, want)
	}
	// The unit runs outside the sandbox on purpose.
	for _, directive := range []string{"Protect", "CapabilityBoundingSet", "ReadWritePaths", "NoNewPrivileges"} {
		if strings.Contains(got, directive) {
			t.Errorf("service unit carries the sandbox directive %s", directive)
		}
	}
}

// TestDeployUnitsMatchGenerators keeps the unit files the repository ships,
// which the systemd e2e suite installs, byte-identical to what plexd install
// writes. The config is spelled out rather than defaulted, so the Linux
// rendering is compared on every runner; defaults_linux_test.go pins these
// paths as the Linux defaults.
func TestDeployUnitsMatchGenerators(t *testing.T) {
	cfg := InstallConfig{
		BinaryPath: "/usr/local/bin/plexd",
		ConfigDir:  "/etc/plexd",
		DataDir:    "/var/lib/plexd",
		RunDir:     "/var/run/plexd",
	}
	for _, tc := range []struct {
		file string
		want string
	}{
		{"plexd.service", GenerateUnitFile(cfg)},
		{"plexd-session-helper.socket", GenerateSessionHelperSocketUnit()},
		{"plexd-session-helper@.service", GenerateSessionHelperServiceUnit(cfg)},
	} {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", tc.file))
			if err != nil {
				t.Fatalf("read the shipped unit: %v", err)
			}
			if string(data) != tc.want {
				t.Errorf("deploy/systemd/%s differs from the generator:\n%s\nwant\n%s", tc.file, data, tc.want)
			}
		})
	}
}
