package bridge

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const openvpnTestID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e3"

// openvpnTestKey is a static key in the form openvpn --genkey writes it,
// with its comment, cut to two lines of key material.
const openvpnTestKey = `#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
6acef03f62675b4b1bbd03e53b187727
423cea742242106cb2916a8a4c829756
-----END OpenVPN Static key V1-----`

// openvpnTestConfig returns the TunnelConfig of an openvpn tunnel.
func openvpnTestConfig() TunnelConfig {
	return TunnelConfig{
		TunnelID:      openvpnTestID,
		InterfaceName: "ov-s2s-a0a0a0e3",
		RemoteHost:    "vpn.office.example.com",
		RemotePort:    1194,
		LocalSubnets:  []string{"10.99.0.0/24"},
		RemoteSubnets: []string{"10.40.0.0/16"},
		Key:           openvpnTestKey,
	}
}

// newTestOpenVPNProvider returns a provider over a mock executor whose Start
// hands out handle, with a configDir that does not exist yet under dir.
func newTestOpenVPNProvider(t *testing.T, dir string) (*OpenVPNProvider, *mockCommandExecutor, *mockCommandHandle, string) {
	t.Helper()
	runner := newMockCommandExecutor()
	handle := &mockCommandHandle{}
	runner.startHandle = handle
	configDir := filepath.Join(dir, "tunnels")
	return NewOpenVPNProvider(runner, configDir, discardLogger()), runner, handle, configDir
}

// shortTempDir returns a directory short enough that a management socket in
// it stays below the limit of a Unix socket path: 104 bytes on macOS, where
// t.TempDir() lies under a long $TMPDIR, and 108 on Windows, where %TEMP%
// lies under the user's profile. On Windows it is the root of the volume
// %TEMP% is on, such as C:\.
func shortTempDir(t *testing.T) string {
	t.Helper()
	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = filepath.VolumeName(os.TempDir()) + `\`
	}
	dir, err := os.MkdirTemp(base, "ov")
	if err != nil {
		t.Fatalf("create a temp directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestOpenVPNProvider_Name(t *testing.T) {
	p, _, _, _ := newTestOpenVPNProvider(t, t.TempDir())
	var _ TunnelProvider = p
	if got := p.Name(); got != "openvpn" {
		t.Errorf("Name() = %q, want openvpn", got)
	}
}

// TestOpenVPNProvider_CreateTunnel checks the key file, the configuration of
// boundary 5, their modes, and the start of openvpn under the caller's
// context.
func TestOpenVPNProvider_CreateTunnel(t *testing.T) {
	p, runner, _, configDir := newTestOpenVPNProvider(t, t.TempDir())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := p.CreateTunnel(ctx, openvpnTestConfig()); err != nil {
		t.Fatalf("CreateTunnel: %v", err)
	}

	keyPath := filepath.Join(configDir, "plexd-openvpn-"+openvpnTestID+".key")
	confPath := filepath.Join(configDir, "plexd-openvpn-"+openvpnTestID+".conf")
	sockPath := filepath.Join(configDir, "plexd-openvpn-"+openvpnTestID+".sock")
	want := "ignore-unknown-option allow-deprecated-insecure-static-crypto\n" +
		"allow-deprecated-insecure-static-crypto\n" +
		"dev ov-s2s-a0a0a0e3\n" +
		"dev-type tun\n" +
		"persist-tun\n" +
		"proto udp\n" +
		"remote vpn.office.example.com 1194\n" +
		"nobind\n" +
		"secret " + keyPath + "\n" +
		"cipher AES-256-CBC\n" +
		"auth SHA256\n" +
		"ping 10\n" +
		"ping-restart 60\n" +
		"management " + sockPath + " unix\n" +
		"verb 3\n"
	conf, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read the configuration: %v", err)
	}
	if string(conf) != want {
		t.Errorf("configuration =\n%s\nwant\n%s", conf, want)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read the key: %v", err)
	}
	if string(key) != openvpnTestKey+"\n" {
		t.Errorf("key file =\n%s\nwant the static key", key)
	}
	assertPerm(t, confPath, 0600)
	assertPerm(t, keyPath, 0600)
	assertPerm(t, configDir, 0700)

	starts := runner.execCallsFor("Start")
	if len(starts) != 1 {
		t.Fatalf("Start calls = %d, want 1", len(starts))
	}
	if got := callLines(starts)[0]; !slices.Equal(got, []string{"Start", "openvpn", "--config", confPath}) {
		t.Errorf("Start = %q, want openvpn --config %s", got, confPath)
	}
	assertCallDeadline(t, starts[0], 0, 0)
	if len(runner.execCallsFor("Run")) != 0 {
		t.Errorf("Run calls = %q, want none", callLines(runner.execCallsFor("Run")))
	}

	// A second create of the same tunnel is refused while it runs.
	if err := p.CreateTunnel(ctx, openvpnTestConfig()); err == nil {
		t.Error("a second CreateTunnel of a running tunnel = nil, want an error")
	}
}

// TestOpenVPNProvider_CreateTunnel_Refused checks that a key without the
// lines that frame a static key, and a config that fails
// ValidateTunnelConfig, write nothing and start nothing.
func TestOpenVPNProvider_CreateTunnel_Refused(t *testing.T) {
	for name, adjust := range map[string]func(*TunnelConfig){
		"empty key":       func(c *TunnelConfig) { c.Key = "" },
		"a WireGuard key": func(c *TunnelConfig) { c.Key = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=" },
		"no end line": func(c *TunnelConfig) {
			c.Key = strings.TrimSuffix(openvpnTestKey, "-----END OpenVPN Static key V1-----")
		},
		"no begin line": func(c *TunnelConfig) {
			c.Key = strings.Replace(openvpnTestKey, "-----BEGIN OpenVPN Static key V1-----\n", "", 1)
		},
		"remote host with LF":  func(c *TunnelConfig) { c.RemoteHost = "vpn.office.example.com\nup /bin/sh" },
		"interface name of 16": func(c *TunnelConfig) { c.InterfaceName = "ov-s2s-a0a0a0e3x" },
	} {
		t.Run(name, func(t *testing.T) {
			p, runner, _, configDir := newTestOpenVPNProvider(t, t.TempDir())
			cfg := openvpnTestConfig()
			adjust(&cfg)
			if err := p.CreateTunnel(t.Context(), cfg); err == nil {
				t.Fatal("CreateTunnel = nil, want an error")
			}
			if len(runner.allCalls()) != 0 {
				t.Errorf("commands = %q, want none", callLines(runner.allCalls()))
			}
			requireNoFile(t, configDir)
		})
	}
}

// TestOpenVPNProvider_CreateTunnel_StartFails checks that a failed start
// removes both files and returns the error wrapped.
func TestOpenVPNProvider_CreateTunnel_StartFails(t *testing.T) {
	p, runner, _, configDir := newTestOpenVPNProvider(t, t.TempDir())
	runner.startErr = &exec.Error{Name: "openvpn", Err: exec.ErrNotFound}
	runner.startHandle = nil
	err := p.CreateTunnel(t.Context(), openvpnTestConfig())
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("CreateTunnel = %v, want it to wrap exec.ErrNotFound", err)
	}
	if got := dirNames(t, configDir); len(got) != 0 {
		t.Errorf("configDir holds %q, want nothing", got)
	}

	// The failed tunnel holds no process: the next create starts one.
	runner.startErr = nil
	runner.startHandle = &mockCommandHandle{}
	if err := p.CreateTunnel(t.Context(), openvpnTestConfig()); err != nil {
		t.Fatalf("CreateTunnel after the failed start: %v", err)
	}
}

// serveManagement listens on the tunnel's management socket in configDir and
// answers one connection: it reads the command, which it sends on cmds, and
// writes reply.
func serveManagement(t *testing.T, configDir, reply string) <-chan string {
	t.Helper()
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(configDir, "plexd-openvpn-"+openvpnTestID+".sock"))
	if err != nil {
		t.Fatalf("listen on the management socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cmds := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n"))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return
		}
		cmds <- line
		_, _ = conn.Write([]byte(reply))
	}()
	return cmds
}

func TestOpenVPNProvider_Established(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply string
		want  bool
	}{
		{"connected", "1795002867,CONNECTED,SUCCESS,,172.25.0.3,1194,,\r\nEND\r\n", true},
		{"assigning an address", "1795002884,ASSIGN_IP,,,,,,\r\nEND\r\n", false},
		{"resolving", "1795002884,RESOLVE,,,,,,\r\nEND\r\n", false},
		{"the last line counts", "1795002860,CONNECTED,SUCCESS,,172.25.0.3,1194,,\r\n1795002884,RECONNECTING,ping-restart,,,,,\r\nEND\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _, configDir := newTestOpenVPNProvider(t, shortTempDir(t))
			cmds := serveManagement(t, configDir, tc.reply)
			got, err := p.Established(t.Context(), openvpnTestID)
			if err != nil {
				t.Fatalf("Established: %v", err)
			}
			if got != tc.want {
				t.Errorf("Established() = %v, want %v", got, tc.want)
			}
			if cmd := <-cmds; cmd != "state\n" {
				t.Errorf("command = %q, want \"state\\n\"", cmd)
			}
		})
	}

	t.Run("nothing listens", func(t *testing.T) {
		p, _, _, _ := newTestOpenVPNProvider(t, shortTempDir(t))
		if got, err := p.Established(t.Context(), openvpnTestID); err == nil || got {
			t.Errorf("Established() = %v, %v, want false and an error", got, err)
		}
	})

	t.Run("reply without END", func(t *testing.T) {
		p, _, _, configDir := newTestOpenVPNProvider(t, shortTempDir(t))
		serveManagement(t, configDir, "1795002867,CONNECTED,SUCCESS,,172.25.0.3,1194,,\r\n")
		if got, err := p.Established(t.Context(), openvpnTestID); err == nil || got {
			t.Errorf("Established() = %v, %v, want false and an error", got, err)
		}
	})
}

// TestOpenVPNProvider_RemoveTunnel checks that a removal stops the process
// and removes the three files, and that a second one changes nothing.
func TestOpenVPNProvider_RemoveTunnel(t *testing.T) {
	p, _, handle, configDir := newTestOpenVPNProvider(t, t.TempDir())
	if err := p.CreateTunnel(t.Context(), openvpnTestConfig()); err != nil {
		t.Fatalf("CreateTunnel: %v", err)
	}
	// The process creates its management socket.
	if err := os.WriteFile(filepath.Join(configDir, "plexd-openvpn-"+openvpnTestID+".sock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "plexd-openvpn-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e9.conf"), nil, 0600); err != nil {
		t.Fatal(err)
	}

	if err := p.RemoveTunnel(t.Context(), openvpnTestID); err != nil {
		t.Fatalf("RemoveTunnel: %v", err)
	}
	if handle.stopCalls() != 1 {
		t.Errorf("Stop calls = %d, want 1", handle.stopCalls())
	}
	if got := dirNames(t, configDir); !slices.Equal(got, []string{"plexd-openvpn-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e9.conf"}) {
		t.Errorf("configDir holds %q, want another tunnel's file alone", got)
	}

	if err := p.RemoveTunnel(t.Context(), openvpnTestID); err != nil {
		t.Fatalf("second RemoveTunnel: %v", err)
	}
	if handle.stopCalls() != 1 {
		t.Errorf("Stop calls after a second removal = %d, want still 1", handle.stopCalls())
	}

	t.Run("a failed stop", func(t *testing.T) {
		p, runner, _, configDir := newTestOpenVPNProvider(t, t.TempDir())
		errStop := errors.New("process gone")
		runner.startHandle = &mockCommandHandle{stopErr: errStop}
		if err := p.CreateTunnel(t.Context(), openvpnTestConfig()); err != nil {
			t.Fatalf("CreateTunnel: %v", err)
		}
		if err := p.RemoveTunnel(t.Context(), openvpnTestID); !errors.Is(err, errStop) {
			t.Errorf("RemoveTunnel = %v, want the stop's error", err)
		}
		if got := dirNames(t, configDir); len(got) != 0 {
			t.Errorf("configDir holds %q, want the files removed all the same", got)
		}
	})
}

// TestOpenVPNProvider_Reset checks that a missing directory is no error and
// that every plexd-openvpn-* file is removed while other files stay.
func TestOpenVPNProvider_Reset(t *testing.T) {
	p, runner, _, configDir := newTestOpenVPNProvider(t, t.TempDir())
	if err := p.Reset(t.Context()); err != nil {
		t.Fatalf("Reset of a missing directory = %v, want nil", err)
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"plexd-openvpn-" + openvpnTestID + ".conf",
		"plexd-openvpn-" + openvpnTestID + ".key",
		"plexd-openvpn-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e9.conf",
		"other.conf",
	} {
		if err := os.WriteFile(filepath.Join(configDir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Reset(t.Context()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if got := dirNames(t, configDir); !slices.Equal(got, []string{"other.conf"}) {
		t.Errorf("configDir holds %q, want other.conf alone", got)
	}
	if len(runner.allCalls()) != 0 {
		t.Errorf("commands = %q, want none", callLines(runner.allCalls()))
	}
}
