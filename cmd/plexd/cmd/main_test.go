package cmd

import (
	"log/slog"
	"os"
	"testing"

	"github.com/plexsphere/plexd/internal/meshdns"
)

// TestMain turns the mesh DNS subsystem off for every test of the package
// before any of them runs. No test may reach the real system bus: on Linux the
// registrar talks to systemd-resolved, on macOS it writes configd's dynamic
// store with scutil, and a run that starts no resolver, as well as every
// drain, reverts the mesh interface's resolver settings. On a developer
// machine that runs plexd, a revert from a test would drop the live
// registration of that node. A test that exercises the
// wiring installs a recording fake with useMeshDNSRegistrar.
func TestMain(m *testing.M) {
	meshDNSRegistrar = func(*slog.Logger) meshdns.Registrar { return nil }
	os.Exit(m.Run())
}

// TestMain_KeepsTestsOffTheSystemBus pins the guard TestMain installs: a test
// that does not call useMeshDNSRegistrar gets no registrar at all, so runUp
// starts no resolver and calls nothing on the host's resolver.
func TestMain_KeepsTestsOffTheSystemBus(t *testing.T) {
	if r := meshDNSRegistrar(slog.Default()); r != nil {
		t.Errorf("meshDNSRegistrar() = %T, want nil: a test without useMeshDNSRegistrar must not reach the system bus", r)
	}
}
