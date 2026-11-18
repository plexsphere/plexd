package bridge

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const ipsecTestID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2"

// newTestIPsecProvider returns a provider over a mock executor whose
// swanctl --list-conns lists the test tunnel's connection, with a confDir
// that does not exist yet.
func newTestIPsecProvider(t *testing.T) (*IPsecProvider, *mockCommandExecutor, string) {
	t.Helper()
	runner := newMockCommandExecutor()
	runner.runOutputs["swanctl --list-conns"] = swanctlListConns(ipsecTestID)
	confDir := filepath.Join(t.TempDir(), "run", "swanctl")
	return NewIPsecProvider(runner, confDir, discardLogger()), runner, confDir
}

// swanctlLoad is the command line of a load.
var swanctlLoad = []string{"Run", "swanctl", "--load-all", "--clear", "--noprompt"}

// swanctlTerminate returns the command line of a terminate of the tunnel's
// connection.
func swanctlTerminate(id string) []string {
	return []string{"Run", "swanctl", "--terminate", "--ike", "plexd-" + id}
}

// requireCommands fails unless runner ran exactly want, in order.
func requireCommands(t *testing.T, runner *mockCommandExecutor, want ...[]string) {
	t.Helper()
	got := callLines(runner.allCalls())
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("commands =\n  %q\nwant\n  %q", got, want)
	}
}

// requireNoFile fails unless path does not exist.
func requireNoFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %s = %v, want it gone", path, err)
	}
}

func TestIPsecProvider_Name(t *testing.T) {
	p, _, _ := newTestIPsecProvider(t)
	var _ TunnelProvider = p
	if got := p.Name(); got != "ipsec" {
		t.Errorf("Name() = %q, want ipsec", got)
	}
}

// TestIPsecProvider_CreateTunnel checks the connection file, its mode and
// its directory's mode, and the commands that load it, under the caller's
// context.
func TestIPsecProvider_CreateTunnel(t *testing.T) {
	p, runner, confDir := newTestIPsecProvider(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := p.CreateTunnel(ctx, validTunnelConfig()); err != nil {
		t.Fatalf("CreateTunnel: %v", err)
	}

	const want = `connections {
    plexd-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2 {
        version = 2
        remote_addrs = 203.0.113.10
        remote_port = 500
        dpd_delay = 30s
        if_id_in = 2694881506
        if_id_out = 2694881506
        local {
            auth = psk
        }
        remote {
            auth = psk
        }
        children {
            plexd-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2 {
                local_ts = 10.99.0.0/24
                remote_ts = 10.30.0.0/16,10.31.0.0/16
                start_action = start
                close_action = start
                dpd_action = restart
            }
        }
    }
}
secrets {
    ike-plexd-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2 {
        secret = 0x7333
    }
}
`
	path := filepath.Join(confDir, "plexd-"+ipsecTestID+".conf")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the connection file: %v", err)
	}
	if string(data) != want {
		t.Errorf("connection file =\n%s\nwant\n%s", data, want)
	}
	assertPerm(t, path, 0600)
	assertPerm(t, confDir, 0700)
	if got := dirNames(t, confDir); !slices.Equal(got, []string{"plexd-" + ipsecTestID + ".conf"}) {
		t.Errorf("confDir holds %q, want the connection file alone", got)
	}

	requireCommands(t, runner, swanctlLoad, []string{"Run", "swanctl", "--list-conns"})
	for _, c := range runner.allCalls() {
		assertCallDeadline(t, c, 29*time.Second, 30*time.Second)
	}
}

// TestIPsecProvider_CreateTunnel_NotIncluded lists no connection after the
// load: the file is removed, the load runs again and the error names the
// include line. A child of the same name, indented, does not count.
func TestIPsecProvider_CreateTunnel_NotIncluded(t *testing.T) {
	for name, listing := range map[string][]byte{
		"nothing listed":    nil,
		"another tunnel":    swanctlListConns("0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e9"),
		"a child alone":     []byte("host-conn: IKEv2\n  plexd-" + ipsecTestID + ": TUNNEL\n"),
		"a longer name too": []byte("plexd-" + ipsecTestID + "x: IKEv2\n"),
	} {
		t.Run(name, func(t *testing.T) {
			p, runner, confDir := newTestIPsecProvider(t)
			runner.runOutputs["swanctl --list-conns"] = listing
			err := p.CreateTunnel(t.Context(), validTunnelConfig())
			want := `bridge: ipsec: strongSwan did not load the connection, add "include ` + filepath.Join(confDir, "*.conf") + `" to /etc/swanctl/swanctl.conf`
			if err == nil || err.Error() != want {
				t.Fatalf("CreateTunnel = %v, want %q", err, want)
			}
			requireNoFile(t, filepath.Join(confDir, "plexd-"+ipsecTestID+".conf"))
			requireCommands(t, runner, swanctlLoad, []string{"Run", "swanctl", "--list-conns"}, swanctlLoad)
		})
	}
}

// TestIPsecProvider_CreateTunnel_Refused checks that an empty key and a
// remote host with a line break write nothing and run nothing.
func TestIPsecProvider_CreateTunnel_Refused(t *testing.T) {
	for name, adjust := range map[string]func(*TunnelConfig){
		"empty key":                 func(c *TunnelConfig) { c.Key = "" },
		"remote host with an LF":    func(c *TunnelConfig) { c.RemoteHost = "203.0.113.10\n" },
		"remote host with a CRLF":   func(c *TunnelConfig) { c.RemoteHost = "203.0.113.10\r\n" },
		"remote subnet not a CIDR":  func(c *TunnelConfig) { c.RemoteSubnets = []string{"10.30.0.0"} },
		"interface name of 16":      func(c *TunnelConfig) { c.InterfaceName = "xf-s2s-a0a0a0e2x" },
		"tunnel id outside the set": func(c *TunnelConfig) { c.TunnelID = "../x" },
	} {
		t.Run(name, func(t *testing.T) {
			p, runner, confDir := newTestIPsecProvider(t)
			cfg := validTunnelConfig()
			adjust(&cfg)
			if strings.Contains(name, "remote host") {
				if err := ValidateTunnelConfig(cfg); err == nil {
					t.Fatal("ValidateTunnelConfig accepts a remote host with a line break")
				}
			}
			if err := p.CreateTunnel(t.Context(), cfg); err == nil {
				t.Fatal("CreateTunnel = nil, want an error")
			}
			if len(runner.allCalls()) != 0 {
				t.Errorf("commands = %q, want none", callLines(runner.allCalls()))
			}
			requireNoFile(t, confDir)
		})
	}
}

// TestIPsecProvider_CreateTunnel_LoadFails checks that a failed load removes
// the file and returns the error wrapped, a missing swanctl included, that a
// load that failed with swanctl present runs again without the file, since
// it may have loaded the connection, and that a failed listing removes the
// file and loads again.
func TestIPsecProvider_CreateTunnel_LoadFails(t *testing.T) {
	t.Run("swanctl missing", func(t *testing.T) {
		p, runner, confDir := newTestIPsecProvider(t)
		runner.runErrors["swanctl --load-all --clear --noprompt"] = &exec.Error{Name: "swanctl", Err: exec.ErrNotFound}
		err := p.CreateTunnel(t.Context(), validTunnelConfig())
		if !errors.Is(err, exec.ErrNotFound) {
			t.Fatalf("CreateTunnel = %v, want it to wrap exec.ErrNotFound", err)
		}
		requireNoFile(t, filepath.Join(confDir, "plexd-"+ipsecTestID+".conf"))
		requireCommands(t, runner, swanctlLoad)
	})

	t.Run("daemon not running", func(t *testing.T) {
		p, runner, confDir := newTestIPsecProvider(t)
		errRefused := errors.New("exit status 111")
		runner.runErrors["swanctl --load-all --clear --noprompt"] = errRefused
		if err := p.CreateTunnel(t.Context(), validTunnelConfig()); !errors.Is(err, errRefused) {
			t.Fatalf("CreateTunnel = %v, want it to wrap the load's error", err)
		}
		requireNoFile(t, filepath.Join(confDir, "plexd-"+ipsecTestID+".conf"))
		requireCommands(t, runner, swanctlLoad, swanctlLoad)
	})

	t.Run("listing fails", func(t *testing.T) {
		p, runner, confDir := newTestIPsecProvider(t)
		errList := errors.New("exit status 1")
		runner.runErrors["swanctl --list-conns"] = errList
		if err := p.CreateTunnel(t.Context(), validTunnelConfig()); !errors.Is(err, errList) {
			t.Fatalf("CreateTunnel = %v, want it to wrap the listing's error", err)
		}
		requireNoFile(t, filepath.Join(confDir, "plexd-"+ipsecTestID+".conf"))
		requireCommands(t, runner, swanctlLoad, []string{"Run", "swanctl", "--list-conns"}, swanctlLoad)
	})
}

func TestIPsecProvider_Established(t *testing.T) {
	saKey := "swanctl --list-sas --ike plexd-" + ipsecTestID + " --raw"
	for _, tc := range []struct {
		name   string
		output []byte
		want   bool
	}{
		{"established and installed", []byte("list-sa event {plexd-" + ipsecTestID + " {state=ESTABLISHED child-sas {plexd-" + ipsecTestID + "-1 {state=INSTALLED}}}}"), true},
		{"the stand-in's answer", swanctlListSAs(ipsecTestID, "ESTABLISHED", "INSTALLED"), true},
		{"connecting", swanctlListSAs(ipsecTestID, "CONNECTING", "INSTALLING"), false},
		{"established without a child", []byte("list-sa event {plexd-" + ipsecTestID + " {state=ESTABLISHED child-sas {}}}"), false},
		{"empty output", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, runner, _ := newTestIPsecProvider(t)
			runner.runOutputs[saKey] = tc.output
			got, err := p.Established(t.Context(), ipsecTestID)
			if err != nil {
				t.Fatalf("Established: %v", err)
			}
			if got != tc.want {
				t.Errorf("Established() = %v, want %v", got, tc.want)
			}
			requireCommands(t, runner, []string{"Run", "swanctl", "--list-sas", "--ike", "plexd-" + ipsecTestID, "--raw"})
		})
	}

	t.Run("failed command", func(t *testing.T) {
		p, runner, _ := newTestIPsecProvider(t)
		errList := errors.New("exit status 111")
		runner.runErrors[saKey] = errList
		runner.runOutputs[saKey] = swanctlListSAs(ipsecTestID, "ESTABLISHED", "INSTALLED")
		got, err := p.Established(t.Context(), ipsecTestID)
		if !errors.Is(err, errList) || got {
			t.Errorf("Established() = %v, %v, want false and the command's error", got, err)
		}
	})
}

// TestIPsecProvider_RemoveTunnel checks that a removal loads the connection
// away and terminates it, ignoring a failed terminate, and that it runs
// nothing without a file.
func TestIPsecProvider_RemoveTunnel(t *testing.T) {
	p, runner, confDir := newTestIPsecProvider(t)
	if err := p.CreateTunnel(t.Context(), validTunnelConfig()); err != nil {
		t.Fatalf("CreateTunnel: %v", err)
	}
	runner.callList = nil
	runner.runErrors["swanctl --terminate --ike plexd-"+ipsecTestID] = errors.New("exit status 1")

	if err := p.RemoveTunnel(t.Context(), ipsecTestID); err != nil {
		t.Fatalf("RemoveTunnel = %v, want the failed terminate ignored", err)
	}
	requireNoFile(t, filepath.Join(confDir, "plexd-"+ipsecTestID+".conf"))
	requireCommands(t, runner, swanctlLoad, swanctlTerminate(ipsecTestID))

	runner.callList = nil
	if err := p.RemoveTunnel(t.Context(), ipsecTestID); err != nil {
		t.Fatalf("second RemoveTunnel: %v", err)
	}
	if len(runner.allCalls()) != 0 {
		t.Errorf("commands without a file = %q, want none", callLines(runner.allCalls()))
	}

	if err := p.RemoveTunnel(t.Context(), "../x"); err == nil {
		t.Error("RemoveTunnel accepts an id that is a path")
	}
}

// TestIPsecProvider_Reset checks that a missing directory is no error and
// runs nothing, and that two leftover files are removed with one load and a
// terminate each, while the host's own files stay.
func TestIPsecProvider_Reset(t *testing.T) {
	t.Run("missing directory", func(t *testing.T) {
		p, runner, _ := newTestIPsecProvider(t)
		if err := p.Reset(t.Context()); err != nil {
			t.Fatalf("Reset = %v, want nil", err)
		}
		if len(runner.allCalls()) != 0 {
			t.Errorf("commands = %q, want none", callLines(runner.allCalls()))
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		p, runner, confDir := newTestIPsecProvider(t)
		if err := os.MkdirAll(confDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := p.Reset(t.Context()); err != nil {
			t.Fatalf("Reset = %v, want nil", err)
		}
		if len(runner.allCalls()) != 0 {
			t.Errorf("commands = %q, want none", callLines(runner.allCalls()))
		}
	})

	const otherID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e8"
	leftovers := func(t *testing.T, confDir string) {
		t.Helper()
		if err := os.MkdirAll(confDir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"plexd-" + ipsecTestID + ".conf", "plexd-" + otherID + ".conf", "host.conf", "plexd-notes.txt"} {
			if err := os.WriteFile(filepath.Join(confDir, name), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("two files", func(t *testing.T) {
		p, runner, confDir := newTestIPsecProvider(t)
		leftovers(t, confDir)
		runner.runErrors["swanctl --terminate --ike plexd-"+otherID] = errors.New("exit status 1")
		if err := p.Reset(t.Context()); err != nil {
			t.Fatalf("Reset = %v, want nil", err)
		}
		if got := dirNames(t, confDir); !slices.Equal(got, []string{"host.conf", "plexd-notes.txt"}) {
			t.Errorf("confDir holds %q, want the host's files alone", got)
		}
		requireCommands(t, runner, swanctlLoad, swanctlTerminate(ipsecTestID), swanctlTerminate(otherID))
	})

	t.Run("swanctl missing", func(t *testing.T) {
		p, runner, confDir := newTestIPsecProvider(t)
		leftovers(t, confDir)
		runner.runErrors["swanctl --load-all --clear --noprompt"] = &exec.Error{Name: "swanctl", Err: exec.ErrNotFound}
		if err := p.Reset(t.Context()); err != nil {
			t.Fatalf("Reset = %v, want a missing swanctl ignored", err)
		}
		if got := dirNames(t, confDir); !slices.Equal(got, []string{"host.conf", "plexd-notes.txt"}) {
			t.Errorf("confDir holds %q, want the host's files alone", got)
		}
	})

	t.Run("failed load", func(t *testing.T) {
		p, runner, confDir := newTestIPsecProvider(t)
		leftovers(t, confDir)
		errLoad := errors.New("exit status 111")
		runner.runErrors["swanctl --load-all --clear --noprompt"] = errLoad
		if err := p.Reset(t.Context()); !errors.Is(err, errLoad) {
			t.Fatalf("Reset = %v, want the load's error", err)
		}
	})
}
