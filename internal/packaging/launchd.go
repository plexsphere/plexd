package packaging

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

const (
	// launchdLabelPrefix turns the service name into the reverse-DNS label
	// launchd keys the daemon by: plexd becomes com.plexsphere.plexd.
	launchdLabelPrefix = "com.plexsphere."

	// launchdDomain is the domain a LaunchDaemon lives in.
	launchdDomain = "system"

	// newsyslogConfDir holds the rotation rule for the daemon's log file.
	newsyslogConfDir = "/etc/newsyslog.d"
)

// launchctlRunner runs launchctl with args and returns its combined output.
// It is a seam so the manager is testable without launchd; execLaunchctl in
// launchd_darwin.go is the implementation that drives the real binary.
type launchctlRunner func(ctx context.Context, args ...string) ([]byte, error)

func launchdLabel(service string) string  { return launchdLabelPrefix + service }
func launchdTarget(service string) string { return launchdDomain + "/" + launchdLabel(service) }

// xmlEscape renders s as XML character data, so a path holding &, < or > does
// not produce a plist launchd refuses to parse.
func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		// strings.Builder never fails a write, so EscapeText cannot fail here.
		return s
	}
	return b.String()
}

// GenerateLaunchdPlist produces the LaunchDaemon property list for the plexd
// service. It calls cfg.ApplyDefaults() to fill in zero-valued fields before
// generating the output.
//
// KeepAlive with ThrottleInterval is the launchd form of the unit file's
// Restart=always and RestartSec=5s. launchd has no StartLimitBurst
// counterpart, so a daemon that exits on a configuration error restarts every
// five seconds until an operator boots it out.
func GenerateLaunchdPlist(cfg InstallConfig) string {
	cfg.ApplyDefaults()

	// path, not filepath: a launchd plist is a macOS artifact, so its paths are
	// slash-separated whatever host generates the file.
	configPath := path.Join(cfg.ConfigDir, "config.yaml")
	logPath := path.Join(cfg.LogDir, DaemonLogFile)

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>up</string>
		<string>--config</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
	<key>SoftResourceLimits</key>
	<dict>
		<key>NumberOfFiles</key>
		<integer>65536</integer>
	</dict>
	<key>HardResourceLimits</key>
	<dict>
		<key>NumberOfFiles</key>
		<integer>65536</integer>
	</dict>
</dict>
</plist>
`,
		xmlEscape(launchdLabel(cfg.ServiceName)),
		xmlEscape(cfg.BinaryPath),
		xmlEscape(configPath),
		xmlEscape(logPath),
		xmlEscape(logPath),
	)
}

// GenerateNewsyslogConf produces the newsyslog rule for the daemon's log file:
// rotate at 10 MiB, keep five generations, bzip2 the rotated files. launchd
// appends to StandardOutPath forever, so without this rule the file grows
// without bound.
func GenerateNewsyslogConf(cfg InstallConfig) string {
	cfg.ApplyDefaults()
	logPath := path.Join(cfg.LogDir, DaemonLogFile)
	return fmt.Sprintf("# plexd log rotation, written by plexd install\n%s\t644\t5\t10240\t*\tJ\n", logPath)
}

// launchdManager is the ServiceManager for macOS. The plist in
// /Library/LaunchDaemons is the definition; launchctl is driven through a
// launchctlRunner so the file flow is testable without launchd.
type launchdManager struct {
	run          launchctlRunner
	newsyslogDir string
	logger       *slog.Logger
}

// NewLaunchdManager returns the launchd ServiceManager driving launchctl through run.
func NewLaunchdManager(run launchctlRunner, logger *slog.Logger) ServiceManager {
	return &launchdManager{run: run, newsyslogDir: newsyslogConfDir, logger: logger}
}

func (m *launchdManager) Name() string { return "launchd" }

func (m *launchdManager) Available() bool {
	_, err := exec.LookPath("launchctl")
	return err == nil
}

func (m *launchdManager) Registered(cfg InstallConfig) (bool, error) {
	if cfg.UnitFilePath == "" {
		return false, errors.New("packaging: config: UnitFilePath is required")
	}
	if _, err := os.Stat(cfg.UnitFilePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("packaging: stat plist: %w", err)
	}
	return true, nil
}

// Register writes the plist and the rotation rule and runs no launchctl
// command: launchd loads /Library/LaunchDaemons at boot, and plexd install
// registers without starting on every platform.
func (m *launchdManager) Register(cfg InstallConfig) error {
	if cfg.UnitFilePath == "" {
		return errors.New("packaging: config: UnitFilePath is required")
	}
	if cfg.LogDir == "" {
		return errors.New("packaging: config: LogDir is required")
	}

	if err := os.MkdirAll(filepath.Dir(cfg.UnitFilePath), 0o755); err != nil {
		return fmt.Errorf("packaging: create plist directory: %w", err)
	}
	// The installer runs as root, so the file lands root:wheel 0644, which
	// launchd requires before it loads a daemon.
	if err := os.WriteFile(cfg.UnitFilePath, []byte(GenerateLaunchdPlist(cfg)), 0o644); err != nil {
		return fmt.Errorf("packaging: write plist: %w", err)
	}
	m.logger.Info("plist written", "path", cfg.UnitFilePath)

	if err := os.MkdirAll(m.newsyslogDir, 0o755); err != nil {
		return fmt.Errorf("packaging: create newsyslog directory: %w", err)
	}
	confPath := filepath.Join(m.newsyslogDir, launchdLabel(cfg.ServiceName)+".conf")
	if err := os.WriteFile(confPath, []byte(GenerateNewsyslogConf(cfg)), 0o644); err != nil {
		return fmt.Errorf("packaging: write newsyslog config: %w", err)
	}
	m.logger.Info("newsyslog config written", "path", confPath)
	return nil
}

func (m *launchdManager) Unregister(cfg InstallConfig) error {
	// bootout is best effort: the daemon may not be loaded.
	if out, err := m.run(context.Background(), "bootout", launchdTarget(cfg.ServiceName)); err != nil {
		m.logger.Info("bootout", "output", strings.TrimSpace(string(out)), "error", err)
	}

	if err := os.Remove(cfg.UnitFilePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("packaging: remove plist: %w", err)
	}
	m.logger.Info("plist removed", "path", cfg.UnitFilePath)

	confPath := filepath.Join(m.newsyslogDir, launchdLabel(cfg.ServiceName)+".conf")
	if err := os.Remove(confPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("packaging: remove newsyslog config: %w", err)
	}
	return nil
}

func (m *launchdManager) Start(cfg InstallConfig) error {
	out, err := m.run(context.Background(), "bootstrap", launchdDomain, cfg.UnitFilePath)
	if err != nil {
		return fmt.Errorf("packaging: launchctl bootstrap: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Stop boots the daemon out rather than calling launchctl stop, because
// KeepAlive would restart a stopped daemon immediately.
func (m *launchdManager) Stop(cfg InstallConfig) error {
	status, err := m.Status(cfg)
	if err != nil {
		return err
	}
	if status != StatusRunning {
		return nil
	}
	out, err := m.run(context.Background(), "bootout", launchdTarget(cfg.ServiceName))
	if err != nil {
		return fmt.Errorf("packaging: launchctl bootout: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Restart kickstarts the daemon with -k, which terminates it and lets launchd
// bring it back. When the daemon issues this against itself, the launchctl
// child may die with it, the same best effort systemctl has inside the
// daemon's cgroup on Linux.
func (m *launchdManager) Restart(ctx context.Context, cfg InstallConfig) error {
	out, err := m.run(ctx, "kickstart", "-k", launchdTarget(cfg.ServiceName))
	if err != nil {
		return fmt.Errorf("packaging: launchctl kickstart: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (m *launchdManager) Status(cfg InstallConfig) (ServiceStatus, error) {
	registered, err := m.Registered(cfg)
	if err != nil {
		return "", err
	}
	if !registered {
		return "", ErrNotRegistered
	}

	out, err := m.run(context.Background(), "print", launchdTarget(cfg.ServiceName))
	if err != nil {
		// A non-zero exit means launchd does not hold the daemon.
		return StatusStopped, nil
	}
	if strings.Contains(string(out), "state = running") {
		return StatusRunning, nil
	}
	return StatusStopped, nil
}
