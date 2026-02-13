package packaging

import (
	"fmt"
	"path/filepath"
)

// GenerateUnitFile produces a complete systemd unit file for the plexd service.
// It calls cfg.ApplyDefaults() to fill in zero-valued fields before generating the output.
func GenerateUnitFile(cfg InstallConfig) string {
	cfg.ApplyDefaults()

	configPath := filepath.Join(cfg.ConfigDir, "config.yaml")
	envPath := filepath.Join(cfg.ConfigDir, "environment")

	return fmt.Sprintf(`[Unit]
Description=plexd node agent
After=network-online.target
Wants=network-online.target
StartLimitBurst=5
StartLimitIntervalSec=60

[Service]
Type=simple
ExecStart=%s up --config %s
Restart=always
RestartSec=5s
LimitNOFILE=65536
EnvironmentFile=-%s
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
ProtectSystem=full
ProtectHome=true
ReadWritePaths=%s %s

[Install]
WantedBy=multi-user.target
`, cfg.BinaryPath, configPath, envPath, cfg.DataDir, cfg.RunDir)
}
