package packaging

import (
	"fmt"
	"path"
)

// The units of the session helper, which starts the processes of mediated ssh
// sessions outside plexd's sandbox. Their files live beside plexd.service.
const (
	SessionHelperSocketUnitName  = "plexd-session-helper.socket"
	SessionHelperServiceUnitName = "plexd-session-helper@.service"
)

// sessionHelperSocketPath is where the helper socket listens. It is
// tunnel.DefaultSessionHelperSocket, which plexd dials; a test pins that the two
// agree, since packaging does not import tunnel.
const sessionHelperSocketPath = "/run/plexd-session-helper.sock"

// GenerateUnitFile produces a complete systemd unit file for the plexd service.
// It calls cfg.ApplyDefaults() to fill in zero-valued fields before generating the output.
//
// The unit wants the session helper socket and is ordered after it, and
// enabling plexd enables the socket too (Also=), so `systemctl enable --now
// plexd` brings both up.
func GenerateUnitFile(cfg InstallConfig) string {
	cfg.ApplyDefaults()

	// path, not filepath: a systemd unit is a Linux artifact, so its paths are
	// slash-separated whatever host generates the file.
	configPath := path.Join(cfg.ConfigDir, "config.yaml")
	envPath := path.Join(cfg.ConfigDir, "environment")

	return fmt.Sprintf(`[Unit]
Description=plexd node agent
After=network-online.target
Wants=network-online.target
Wants=plexd-session-helper.socket
After=plexd-session-helper.socket
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
Also=plexd-session-helper.socket
`, cfg.BinaryPath, configPath, envPath, cfg.DataDir, cfg.RunDir)
}

// GenerateSessionHelperSocketUnit produces plexd-session-helper.socket. It is
// root-only (0600), and Accept=yes starts one helper instance per connection.
//
// systemd's defaults for Accept=yes would let one session holder break ssh
// sessions for the whole node: MaxConnections=64 is below the 400 processes
// plexd's defaults allow (10 sessions of 4 connections of 10 channels), and
// going past the trigger limit of 200 per 2 s fails the socket until an
// operator restarts it. MaxConnections is therefore raised above plexd's own
// bound, which is what limits the helpers, and the trigger limit is turned off.
func GenerateSessionHelperSocketUnit() string {
	return fmt.Sprintf(`[Unit]
Description=plexd session helper socket

[Socket]
ListenStream=%s
SocketMode=0600
SocketUser=root
SocketGroup=root
Accept=yes
MaxConnections=512
TriggerLimitIntervalSec=0

[Install]
WantedBy=sockets.target
`, sessionHelperSocketPath)
}

// GenerateSessionHelperServiceUnit produces plexd-session-helper@.service, the
// template each connection to the socket instantiates. It calls
// cfg.ApplyDefaults() to fill in zero-valued fields.
//
// The unit deliberately carries no sandbox directives: it exists to run
// outside plexd's sandbox, where a shell can become the login user. Its guard
// is the helper's own check of the session token against a key plexd cannot
// write. KillMode=control-group takes down whatever a session left behind.
func GenerateSessionHelperServiceUnit(cfg InstallConfig) string {
	cfg.ApplyDefaults()
	return fmt.Sprintf(`[Unit]
Description=plexd session helper (one mediated ssh process)
CollectMode=inactive-or-failed

[Service]
Type=simple
ExecStart=%s session-helper --config %s
StandardInput=null
StandardOutput=journal
StandardError=journal
KillMode=control-group
`, cfg.BinaryPath, path.Join(cfg.ConfigDir, "config.yaml"))
}
