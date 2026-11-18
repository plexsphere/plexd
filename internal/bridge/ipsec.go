package bridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/fsutil"
)

// ipsecFilePrefix and ipsecFileSuffix frame the name of each connection file
// the IPsecProvider writes: plexd-<id>.conf.
const (
	ipsecFilePrefix = "plexd-"
	ipsecFileSuffix = ".conf"
)

// IPsecProvider runs the strongSwan side of ipsec site-to-site tunnels. Each
// tunnel is a route-based IKEv2 connection bound to the xfrm interface the
// SiteToSiteManager created, written as <confDir>/plexd-<id>.conf and loaded
// with swanctl. The host runs the strongSwan daemon and includes
// <confDir>/*.conf in /etc/swanctl/swanctl.conf; swanctl --load-all reads
// that file, so a connection plexd writes loads beside the host's own and
// unloads when its file is gone.
//
// All methods are safe for concurrent use.
type IPsecProvider struct {
	exec    CommandExecutor
	confDir string
	logger  *slog.Logger

	// mu serialises the file writes and the loads that read them: a load
	// reads every file of confDir.
	mu sync.Mutex
}

// NewIPsecProvider returns an IPsecProvider that writes its connection files
// into confDir and runs swanctl through exec.
func NewIPsecProvider(exec CommandExecutor, confDir string, logger *slog.Logger) *IPsecProvider {
	return &IPsecProvider{exec: exec, confDir: confDir, logger: logger}
}

// Name returns the kind the provider serves.
func (p *IPsecProvider) Name() string {
	return api.SiteToSiteKindIPsec
}

// ipsecConnName returns the name of the strongSwan connection, and of its
// child, for the tunnel with the given id.
func ipsecConnName(tunnelID string) string {
	return ipsecFilePrefix + tunnelID
}

// confPath returns the path of the tunnel's connection file.
func (p *IPsecProvider) confPath(tunnelID string) string {
	return filepath.Join(p.confDir, ipsecConnName(tunnelID)+ipsecFileSuffix)
}

// load runs swanctl --load-all --clear --noprompt, which loads every
// connection and secret of the host's swanctl.conf, the included files of
// confDir among them, and unloads those no file holds any more.
func (p *IPsecProvider) load(ctx context.Context) error {
	if _, err := p.exec.Run(ctx, "swanctl", "--load-all", "--clear", "--noprompt"); err != nil {
		return fmt.Errorf("swanctl --load-all: %w", err)
	}
	return nil
}

// CreateTunnel writes the tunnel's connection file with mode 0600 into
// confDir, which it creates with mode 0700, loads it with
// swanctl --load-all --clear --noprompt and checks with swanctl --list-conns
// that strongSwan holds the connection. The pre-shared key is written in its
// hex form, which carries any key without quoting.
//
// An empty Key is refused before anything is written. A failed load removes
// the file and returns the error wrapped, so exec.ErrNotFound stays visible;
// unless swanctl is missing, it loads again without the file, since a load
// that failed on another part of the host's configuration may still have
// loaded the connection. When --list-conns does not list
// the connection, because the host's swanctl.conf does not include confDir,
// the file is removed and loaded away again, and the error names the include
// line; a failed --list-conns is undone the same way.
func (p *IPsecProvider) CreateTunnel(ctx context.Context, cfg TunnelConfig) error {
	if err := ValidateTunnelConfig(cfg); err != nil {
		return fmt.Errorf("bridge: ipsec: %w", err)
	}
	if cfg.Key == "" {
		return fmt.Errorf("bridge: ipsec: tunnel %s: the pre-shared key is empty", cfg.TunnelID)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if err := ensureTunnelConfigDir(p.confDir); err != nil {
		return fmt.Errorf("bridge: ipsec: create %s: %w", p.confDir, err)
	}
	name := ipsecConnName(cfg.TunnelID)
	if err := fsutil.WriteFileAtomic(p.confDir, name+ipsecFileSuffix, swanctlConfig(cfg), 0600); err != nil {
		return fmt.Errorf("bridge: ipsec: write the connection of %s: %w", cfg.TunnelID, err)
	}
	path := p.confPath(cfg.TunnelID)

	if err := p.load(ctx); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			_ = os.Remove(path)
		} else {
			p.unload(ctx, path)
		}
		return fmt.Errorf("bridge: ipsec: load the connection of %s: %w", cfg.TunnelID, err)
	}
	out, err := p.exec.Run(ctx, "swanctl", "--list-conns")
	if err != nil {
		p.unload(ctx, path)
		return fmt.Errorf("bridge: ipsec: list the connections for %s: swanctl --list-conns: %w", cfg.TunnelID, err)
	}
	if !listsConnection(out, name) {
		p.unload(ctx, path)
		return fmt.Errorf(`bridge: ipsec: strongSwan did not load the connection, add "include %s" to /etc/swanctl/swanctl.conf`,
			filepath.Join(p.confDir, "*"+ipsecFileSuffix))
	}

	p.logger.Debug("ipsec connection loaded",
		"component", "bridge",
		"tunnel_id", cfg.TunnelID,
		"connection", name,
		"interface", cfg.InterfaceName,
	)
	return nil
}

// unload removes the connection file at path and runs the load again, so
// strongSwan drops what the file held. A failed load is logged: the caller
// returns the error that made it unload.
func (p *IPsecProvider) unload(ctx context.Context, path string) {
	_ = os.Remove(path)
	if err := p.load(ctx); err != nil {
		p.logger.Warn("bridge: ipsec: unload failed",
			"component", "bridge",
			"file", path,
			"error", err,
		)
	}
}

// listsConnection reports whether the output of swanctl --list-conns holds a
// line that starts with the connection's name and a colon. The children of a
// connection are indented, so a child of the same name does not count.
func listsConnection(out []byte, name string) bool {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), name+":") {
			return true
		}
	}
	return false
}

// RemoveTunnel removes the tunnel's connection file, loads again, which
// unloads the connection, and terminates its IKE security association with
// swanctl --terminate --ike plexd-<id>. The terminate's result is ignored: it
// fails once the unload has closed the connection. Without a file it runs
// nothing.
func (p *IPsecProvider) RemoveTunnel(ctx context.Context, tunnelID string) error {
	if !api.ValidSiteToSiteTunnelID(tunnelID) {
		return fmt.Errorf("bridge: ipsec: invalid tunnel id %q", tunnelID)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	removed, err := removeIfExists(p.confPath(tunnelID))
	if err != nil {
		return fmt.Errorf("bridge: ipsec: remove the connection of %s: %w", tunnelID, err)
	}
	if !removed {
		return nil
	}
	loadErr := p.load(ctx)
	p.terminate(ctx, ipsecConnName(tunnelID))
	if loadErr != nil {
		return fmt.Errorf("bridge: ipsec: unload the connection of %s: %w", tunnelID, loadErr)
	}
	return nil
}

// terminate runs swanctl --terminate --ike name and ignores its result.
func (p *IPsecProvider) terminate(ctx context.Context, name string) {
	_, _ = p.exec.Run(ctx, "swanctl", "--terminate", "--ike", name)
}

// Established runs swanctl --list-sas --ike plexd-<id> --raw and reports
// whether the output holds both state=ESTABLISHED, the IKE security
// association, and state=INSTALLED, a child security association.
func (p *IPsecProvider) Established(ctx context.Context, tunnelID string) (bool, error) {
	out, err := p.exec.Run(ctx, "swanctl", "--list-sas", "--ike", ipsecConnName(tunnelID), "--raw")
	if err != nil {
		return false, fmt.Errorf("bridge: ipsec: list the security associations of %s: %w", tunnelID, err)
	}
	return bytes.Contains(out, []byte("state=ESTABLISHED")) && bytes.Contains(out, []byte("state=INSTALLED")), nil
}

// Reset removes every plexd-*.conf file of confDir. When it removed one, it
// loads again and terminates the IKE security association of each removed
// connection, ignoring the terminates' results. A host without swanctl is no
// error, and neither is a confDir that does not exist.
func (p *IPsecProvider) Reset(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	entries, err := os.ReadDir(p.confDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("bridge: ipsec: reset: %w", err)
	}
	var removed []string
	var errs []error
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasPrefix(name, ipsecFilePrefix) || !strings.HasSuffix(name, ipsecFileSuffix) {
			continue
		}
		if err := os.Remove(filepath.Join(p.confDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("bridge: ipsec: reset: %w", err))
			continue
		}
		removed = append(removed, strings.TrimSuffix(name, ipsecFileSuffix))
	}
	if len(removed) == 0 {
		return errors.Join(errs...)
	}
	if err := p.load(ctx); err != nil && !errors.Is(err, exec.ErrNotFound) {
		errs = append(errs, fmt.Errorf("bridge: ipsec: reset: %w", err))
	}
	for _, name := range removed {
		p.terminate(ctx, name)
	}
	p.logger.Info("ipsec connections of an earlier process removed",
		"component", "bridge",
		"connections", removed,
	)
	return errors.Join(errs...)
}

// swanctlConfig returns the connection file of the tunnel cfg describes: an
// IKEv2 connection to RemoteHost on RemotePort, authenticated on both sides
// with the pre-shared key, bound to the xfrm interface InterfaceID in both
// directions, with one child between LocalSubnets and RemoteSubnets that
// starts at once and again after a close, and the key as a hex secret.
func swanctlConfig(cfg TunnelConfig) []byte {
	name := ipsecConnName(cfg.TunnelID)
	ifID := strconv.FormatUint(uint64(cfg.InterfaceID), 10)

	var b strings.Builder
	b.WriteString("connections {\n")
	fmt.Fprintf(&b, "    %s {\n", name)
	b.WriteString("        version = 2\n")
	fmt.Fprintf(&b, "        remote_addrs = %s\n", cfg.RemoteHost)
	fmt.Fprintf(&b, "        remote_port = %d\n", cfg.RemotePort)
	b.WriteString("        dpd_delay = 30s\n")
	fmt.Fprintf(&b, "        if_id_in = %s\n", ifID)
	fmt.Fprintf(&b, "        if_id_out = %s\n", ifID)
	b.WriteString("        local {\n")
	b.WriteString("            auth = psk\n")
	b.WriteString("        }\n")
	b.WriteString("        remote {\n")
	b.WriteString("            auth = psk\n")
	b.WriteString("        }\n")
	b.WriteString("        children {\n")
	fmt.Fprintf(&b, "            %s {\n", name)
	fmt.Fprintf(&b, "                local_ts = %s\n", strings.Join(cfg.LocalSubnets, ","))
	fmt.Fprintf(&b, "                remote_ts = %s\n", strings.Join(cfg.RemoteSubnets, ","))
	b.WriteString("                start_action = start\n")
	b.WriteString("                close_action = start\n")
	b.WriteString("                dpd_action = restart\n")
	b.WriteString("            }\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	b.WriteString("secrets {\n")
	fmt.Fprintf(&b, "    ike-%s {\n", name)
	fmt.Fprintf(&b, "        secret = 0x%s\n", hex.EncodeToString([]byte(cfg.Key)))
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return []byte(b.String())
}
