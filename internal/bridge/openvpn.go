package bridge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/fsutil"
)

// openvpnFilePrefix begins the name of every file the OpenVPNProvider keeps
// for a tunnel: plexd-openvpn-<id>.conf, .key and .sock.
const openvpnFilePrefix = "plexd-openvpn-"

// The lines that frame an OpenVPN static key, as openvpn --genkey writes it.
const (
	openvpnStaticKeyBegin = "-----BEGIN OpenVPN Static key V1-----"
	openvpnStaticKeyEnd   = "-----END OpenVPN Static key V1-----"
)

// openvpnManagementTimeout bounds one read of a tunnel's state over its
// management socket: the dial, the command and the reply.
const openvpnManagementTimeout = 2 * time.Second

// OpenVPNProvider runs the OpenVPN side of openvpn site-to-site tunnels.
// Each tunnel is a point-to-point connection with a static key on the
// persistent tun device the SiteToSiteManager created, served by an openvpn
// process of its own with a management socket the provider reads the
// tunnel's state from. The remote site sets the same cipher and digest,
// AES-256-CBC and SHA256, and the same static key without a direction.
//
// All methods are safe for concurrent use.
type OpenVPNProvider struct {
	exec      CommandExecutor
	configDir string
	logger    *slog.Logger

	// mu protects handles.
	mu sync.Mutex
	// handles holds the openvpn process of each tunnel by id.
	handles map[string]CommandHandle
}

// NewOpenVPNProvider returns an OpenVPNProvider that keeps the files of its
// tunnels in configDir and starts openvpn through exec.
func NewOpenVPNProvider(exec CommandExecutor, configDir string, logger *slog.Logger) *OpenVPNProvider {
	return &OpenVPNProvider{
		exec:      exec,
		configDir: configDir,
		logger:    logger,
		handles:   make(map[string]CommandHandle),
	}
}

// Name returns the kind the provider serves.
func (p *OpenVPNProvider) Name() string {
	return api.SiteToSiteKindOpenVPN
}

// path returns the path of the tunnel's file with the given extension.
func (p *OpenVPNProvider) path(tunnelID, ext string) string {
	return filepath.Join(p.configDir, openvpnFilePrefix+tunnelID+ext)
}

// CreateTunnel writes the tunnel's static key to plexd-openvpn-<id>.key and
// its configuration to plexd-openvpn-<id>.conf, both with mode 0600, in
// configDir, which it creates with mode 0700, and starts
// openvpn --config <that file> under ctx, which the process ends with. A Key
// without the lines that frame an OpenVPN static key is refused before
// anything is written, and a failed start removes both files.
func (p *OpenVPNProvider) CreateTunnel(ctx context.Context, cfg TunnelConfig) error {
	if err := ValidateTunnelConfig(cfg); err != nil {
		return fmt.Errorf("bridge: openvpn: %w", err)
	}
	if !openvpnStaticKey(cfg.Key) {
		return fmt.Errorf("bridge: openvpn: tunnel %s: the key is no OpenVPN static key", cfg.TunnelID)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, running := p.handles[cfg.TunnelID]; running {
		return fmt.Errorf("bridge: openvpn: tunnel %s already runs", cfg.TunnelID)
	}
	if err := ensureTunnelConfigDir(p.configDir); err != nil {
		return fmt.Errorf("bridge: openvpn: create %s: %w", p.configDir, err)
	}
	keyPath, confPath := p.path(cfg.TunnelID, ".key"), p.path(cfg.TunnelID, ".conf")
	if err := fsutil.WriteFileAtomic(p.configDir, filepath.Base(keyPath), []byte(cfg.Key+"\n"), 0600); err != nil {
		return fmt.Errorf("bridge: openvpn: write the key of %s: %w", cfg.TunnelID, err)
	}
	conf := openvpnConfig(cfg, keyPath, p.path(cfg.TunnelID, ".sock"))
	if err := fsutil.WriteFileAtomic(p.configDir, filepath.Base(confPath), conf, 0600); err != nil {
		_ = os.Remove(keyPath)
		return fmt.Errorf("bridge: openvpn: write the configuration of %s: %w", cfg.TunnelID, err)
	}

	handle, err := p.exec.Start(ctx, "openvpn", "--config", confPath)
	if err != nil {
		_ = os.Remove(confPath)
		_ = os.Remove(keyPath)
		return fmt.Errorf("bridge: openvpn: start the tunnel %s: %w", cfg.TunnelID, err)
	}
	p.handles[cfg.TunnelID] = handle

	p.logger.Debug("openvpn started",
		"component", "bridge",
		"tunnel_id", cfg.TunnelID,
		"interface", cfg.InterfaceName,
	)
	return nil
}

// openvpnStaticKey reports whether key holds the two lines that frame an
// OpenVPN static key.
func openvpnStaticKey(key string) bool {
	var begin, end bool
	for _, line := range strings.Split(key, "\n") {
		switch strings.TrimSpace(line) {
		case openvpnStaticKeyBegin:
			begin = true
		case openvpnStaticKeyEnd:
			end = true
		}
	}
	return begin && end
}

// RemoveTunnel stops the tunnel's openvpn process and removes its three
// files: the configuration, the key and the management socket. Idempotent: a
// tunnel without a process or files returns nil.
func (p *OpenVPNProvider) RemoveTunnel(_ context.Context, tunnelID string) error {
	if !api.ValidSiteToSiteTunnelID(tunnelID) {
		return fmt.Errorf("bridge: openvpn: invalid tunnel id %q", tunnelID)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error
	if handle, ok := p.handles[tunnelID]; ok {
		delete(p.handles, tunnelID)
		if err := handle.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("bridge: openvpn: stop the tunnel %s: %w", tunnelID, err))
		}
	}
	for _, ext := range []string{".conf", ".key", ".sock"} {
		if _, err := removeIfExists(p.path(tunnelID, ext)); err != nil {
			errs = append(errs, fmt.Errorf("bridge: openvpn: remove a file of %s: %w", tunnelID, err))
		}
	}
	return errors.Join(errs...)
}

// Established asks the tunnel's openvpn process for its state over the
// management socket: it dials the socket, writes "state", reads the reply to
// the line END, and reports whether the second comma-separated field of the
// last state line is CONNECTED. The read is bounded by 2 s and by ctx.
func (p *OpenVPNProvider) Established(ctx context.Context, tunnelID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, openvpnManagementTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", p.path(tunnelID, ".sock"))
	if err != nil {
		return false, fmt.Errorf("bridge: openvpn: dial the management socket of %s: %w", tunnelID, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return false, fmt.Errorf("bridge: openvpn: management socket of %s: %w", tunnelID, err)
		}
	}
	if _, err := conn.Write([]byte("state\n")); err != nil {
		return false, fmt.Errorf("bridge: openvpn: management socket of %s: %w", tunnelID, err)
	}

	var last string
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		switch {
		case line == "END":
			fields := strings.Split(last, ",")
			return len(fields) > 1 && fields[1] == "CONNECTED", nil
		case strings.HasPrefix(line, ">"):
			// A real-time notification, such as the greeting.
		case strings.HasPrefix(line, "ERROR:"):
			return false, fmt.Errorf("bridge: openvpn: management socket of %s: %s", tunnelID, line)
		default:
			last = line
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("bridge: openvpn: management socket of %s: %w", tunnelID, err)
	}
	return false, fmt.Errorf("bridge: openvpn: management socket of %s: the reply ended without END", tunnelID)
}

// Reset removes every plexd-openvpn-* file of configDir. A configDir that
// does not exist is no error. A process of an earlier plexd is not this
// provider's to stop: it ends with the unit's control group, and its tun
// device is deleted with the tunnel links.
func (p *OpenVPNProvider) Reset(_ context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	entries, err := os.ReadDir(p.configDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("bridge: openvpn: reset: %w", err)
	}
	var errs []error
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), openvpnFilePrefix) {
			continue
		}
		if ok, err := removeIfExists(filepath.Join(p.configDir, entry.Name())); err != nil {
			errs = append(errs, fmt.Errorf("bridge: openvpn: reset: %w", err))
		} else if ok {
			removed++
		}
	}
	if removed > 0 {
		p.logger.Info("openvpn files of an earlier process removed",
			"component", "bridge",
			"files", removed,
		)
	}
	return errors.Join(errs...)
}

// openvpnConfig returns the configuration of the tunnel cfg describes: a
// static-key tunnel over UDP to RemoteHost on RemotePort, on the persistent
// tun device InterfaceName without tunnel addresses, with AES-256-CBC and
// SHA256, a keepalive of 10 s that restarts after 60 s of silence, and a
// management socket at sockPath. allow-deprecated-insecure-static-crypto
// keeps a static key working where the release deprecates it; OpenVPN 2.6
// refuses the option alone as unknown and accepts it behind
// ignore-unknown-option.
func openvpnConfig(cfg TunnelConfig, keyPath, sockPath string) []byte {
	var b strings.Builder
	b.WriteString("ignore-unknown-option allow-deprecated-insecure-static-crypto\n")
	b.WriteString("allow-deprecated-insecure-static-crypto\n")
	fmt.Fprintf(&b, "dev %s\n", cfg.InterfaceName)
	b.WriteString("dev-type tun\n")
	b.WriteString("persist-tun\n")
	b.WriteString("proto udp\n")
	fmt.Fprintf(&b, "remote %s %d\n", cfg.RemoteHost, cfg.RemotePort)
	b.WriteString("nobind\n")
	fmt.Fprintf(&b, "secret %s\n", keyPath)
	b.WriteString("cipher AES-256-CBC\n")
	b.WriteString("auth SHA256\n")
	b.WriteString("ping 10\n")
	b.WriteString("ping-restart 60\n")
	fmt.Fprintf(&b, "management %s unix\n", sockPath)
	b.WriteString("verb 3\n")
	return []byte(b.String())
}
