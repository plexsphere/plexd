//go:build linux

package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/tunnel"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// writeJournalctlStub creates an executable journalctl stub in a temporary
// directory and points $PATH at it, so the availability probe resolves
// deterministically regardless of the host.
func writeJournalctlStub(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	stub := filepath.Join(dir, "journalctl")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write journalctl stub: %v", err)
	}
	t.Setenv("PATH", dir)
}

func TestNewSystemLogSource_ReturnsJournaldSourceWhenJournalctlPresent(t *testing.T) {
	writeJournalctlStub(t)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	src := newSystemLogSource("host", logger)
	if src == nil {
		t.Fatal("newSystemLogSource() = nil, want a source when journalctl is on PATH")
	}
	if _, ok := src.(*logfwd.JournaldSource); !ok {
		t.Errorf("newSystemLogSource() = %T, want *logfwd.JournaldSource", src)
	}
	if buf.Len() != 0 {
		t.Errorf("log output = %q, want none when journalctl is available", buf.String())
	}
}

func TestNewSystemLogSource_ReturnsNilWhenJournalctlMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	if src := newSystemLogSource("host", logger); src != nil {
		t.Errorf("newSystemLogSource() = %v, want nil when journalctl is missing", src)
	}

	out := buf.String()
	if !strings.Contains(out, "journald not available") {
		t.Errorf("log output = %q, want a journald-not-available notice", out)
	}
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("log output = %q, want the notice at INFO level", out)
	}
}

func TestNewSystemReader_Linux(t *testing.T) {
	reader := newSystemReader(discardLogger())
	if reader == nil {
		t.Fatal("newSystemReader() = nil, want the procfs reader on Linux")
	}
	if _, ok := reader.(*metrics.LinuxSystemReader); !ok {
		t.Errorf("newSystemReader() = %T, want *metrics.LinuxSystemReader", reader)
	}
}

// TestNewMeshRewriter_Linux pins that Linux builds no in-process rewriter,
// even for a bridge that serves: nftables rewrites in the kernel.
func TestNewMeshRewriter_Linux(t *testing.T) {
	if got := newMeshRewriter(true, discardLogger()); got != nil {
		t.Errorf("newMeshRewriter(true) = %p, want nil on Linux", got)
	}
}

// TestNewNATExempter_Linux pins that Linux exempts no tunnel's link from the
// bridge NAT, which masquerades only what leaves the access interface.
func TestNewNATExempter_Linux(t *testing.T) {
	if got := newNATExempter(nil); got != nil {
		t.Errorf("newNATExempter(nil) = %#v, want nil on Linux", got)
	}
	if got := newNATExempter(newFirewallController(discardLogger(), "plexd0")); got != nil {
		t.Errorf("newNATExempter(fw) = %#v, want nil on Linux", got)
	}
}

// TestNewAccessController_Linux pins the netlink access controller, which
// takes no in-process rewriter.
func TestNewAccessController_Linux(t *testing.T) {
	ctrl := newAccessController(discardLogger(), nil)
	if ctrl == nil {
		t.Fatal("newAccessController() = nil, want the netlink access controller on Linux")
	}
	if _, ok := ctrl.(*bridge.NetlinkAccessController); !ok {
		t.Errorf("newAccessController() = %T, want *bridge.NetlinkAccessController", ctrl)
	}
}

// TestNewVPNController_Linux pins the mesh IP as behaviour-neutral on Linux:
// the tunnel link stays unnumbered whatever identity the node came up with.
func TestNewVPNController_Linux(t *testing.T) {
	ctrl := newVPNController(discardLogger(), "10.42.0.5", nil)
	if ctrl == nil {
		t.Fatal("newVPNController() = nil, want the netlink tunnel controller on Linux")
	}
	if _, ok := ctrl.(*bridge.NetlinkVPNController); !ok {
		t.Errorf("newVPNController() = %T, want *bridge.NetlinkVPNController", ctrl)
	}
}

// TestNewMeshSourceRewriter_Linux pins that the netlink route controller is
// the mesh source rewriter on Linux, and that any other route controller, a
// nil one included, yields an untyped nil, which serves no user access
// provider. The in-process rewriter changes neither.
func TestNewMeshSourceRewriter_Linux(t *testing.T) {
	routes := newRouteController(discardLogger(), nil)
	rewriter := newMeshSourceRewriter(routes, nil, nil)
	if rewriter == nil {
		t.Fatal("newMeshSourceRewriter() = nil, want the netlink route controller on Linux")
	}
	if got, ok := rewriter.(*bridge.NetlinkRouteController); !ok || got != routes {
		t.Errorf("newMeshSourceRewriter() = %T %p, want the route controller %p itself", rewriter, rewriter, routes)
	}
	if got, ok := newMeshSourceRewriter(routes, nil, wireguard.NewMeshRewriter(discardLogger())).(*bridge.NetlinkRouteController); !ok || got != routes {
		t.Errorf("newMeshSourceRewriter(routes, nil, rewriter) = %T %p, want the route controller %p itself", got, got, routes)
	}
	if got := newMeshSourceRewriter(nil, nil, nil); got != nil {
		t.Errorf("newMeshSourceRewriter(nil, nil, nil) = %#v, want nil", got)
	}
	var typedNil *bridge.NetlinkRouteController
	if got := newMeshSourceRewriter(typedNil, nil, nil); got != nil {
		t.Errorf("newMeshSourceRewriter(typed nil, nil, nil) = %#v, want an untyped nil", got)
	}
}

// TestNewTunnelProviders_Linux pins the two providers a Linux bridge serves
// ipsec and openvpn tunnels with.
func TestNewTunnelProviders_Linux(t *testing.T) {
	providers := newTunnelProviders(t.TempDir(), discardLogger())
	if _, ok := providers[api.SiteToSiteKindIPsec].(*bridge.IPsecProvider); !ok {
		t.Errorf("ipsec provider = %T, want *bridge.IPsecProvider", providers[api.SiteToSiteKindIPsec])
	}
	if _, ok := providers[api.SiteToSiteKindOpenVPN].(*bridge.OpenVPNProvider); !ok {
		t.Errorf("openvpn provider = %T, want *bridge.OpenVPNProvider", providers[api.SiteToSiteKindOpenVPN])
	}
	if len(providers) != 2 {
		t.Errorf("newTunnelProviders() = %v, want the ipsec and the openvpn provider alone", providers)
	}
}

const helperSocketWarning = "plexd-session-helper.socket is not listening; ssh sessions run inside plexd's own sandbox and cannot switch users"

func TestNewSessionLauncher_WarnsWithoutSocketUnderSystemd(t *testing.T) {
	if _, err := os.Stat("/run/plexd-session-helper.sock"); err == nil {
		t.Skip("this host runs plexd-session-helper.socket")
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := api.NewEd25519Verifier("kid", pub)

	t.Run("under systemd", func(t *testing.T) {
		t.Setenv("INVOCATION_ID", "0123456789abcdef")
		logs := newRecordingHandler()
		if newSessionLauncher(verifier, slog.New(logs)) == nil {
			t.Fatal("newSessionLauncher() = nil, want a launcher on Linux")
		}
		if n := logs.count(slog.LevelWarn, helperSocketWarning); n != 1 {
			t.Errorf("warned %d times, want 1", n)
		}
	})

	t.Run("outside systemd", func(t *testing.T) {
		t.Setenv("INVOCATION_ID", "")
		logs := newRecordingHandler()
		if newSessionLauncher(verifier, slog.New(logs)) == nil {
			t.Fatal("newSessionLauncher() = nil, want a launcher on Linux")
		}
		if n := logs.countAt(slog.LevelWarn); n != 0 {
			t.Errorf("warned %d times without systemd, want 0", n)
		}
	})
}

// Hosts without the helper socket start the child helper with exactly this
// command line, so the session-helper command must accept it as child mode and
// decode every key it carries.
func TestSessionHelperChildArgs_ParseAsChildMode(t *testing.T) {
	var keys []ed25519.PublicKey
	for i := 0; i < 2; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, pub)
	}
	prevChild, prevKeys := sessionHelperChild, sessionHelperTrustedKeys
	t.Cleanup(func() { sessionHelperChild, sessionHelperTrustedKeys = prevChild, prevKeys })
	sessionHelperChild, sessionHelperTrustedKeys = false, nil

	args := sessionHelperChildArgs(keys)
	if args[0] != sessionHelperCmd.Name() {
		t.Fatalf("args[0] = %q, want the %s command", args[0], sessionHelperCmd.Name())
	}
	if err := sessionHelperCmd.ParseFlags(args[1:]); err != nil {
		t.Fatalf("ParseFlags(%q) error: %v", args[1:], err)
	}
	socket, err := selectHelperMode("", "", os.Getpid(), sessionHelperChild, sessionHelperTrustedKeys)
	if err != nil || socket {
		t.Fatalf("selectHelperMode() = %v, %v; want child mode", socket, err)
	}
	if len(sessionHelperTrustedKeys) != len(keys) {
		t.Fatalf("parsed %d trusted keys, want %d", len(sessionHelperTrustedKeys), len(keys))
	}
	for i, s := range sessionHelperTrustedKeys {
		key, err := tunnel.ParseSessionSigningPublicKey(s)
		if err != nil {
			t.Fatalf("trusted key %d: %v", i, err)
		}
		if !key.Equal(keys[i]) {
			t.Errorf("trusted key %d differs from the key it was built from", i)
		}
	}
}
