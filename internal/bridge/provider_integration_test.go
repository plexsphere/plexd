// Integration tests — UserAccess with VPN Provider
package bridge

import (
	"errors"
	"testing"
)

// providerTestConfig returns a standard Config for provider integration tests.
func providerTestConfig() Config {
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()
	return cfg
}

// TestProviderIntegration_SetupProviderError wires a UserAccessManager with
// each vendor client over a mock executor and verifies that Setup fails
// without running a command of the client, since the manager has no join key
// to hand over, and rolls back the WG interface and forwarding, leaving the
// manager inactive.
func TestProviderIntegration_SetupProviderError(t *testing.T) {
	tests := []struct {
		name   string
		client func(CommandExecutor) UserAccessClient
	}{
		{"tailscale", func(e CommandExecutor) UserAccessClient { return NewTailscaleProvider(e, discardLogger()) }},
		{"netbird", func(e CommandExecutor) UserAccessClient { return NewNetbirdProvider(e, discardLogger()) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := &mockAccessController{}
			routes := &mockRouteController{}
			runner := newMockCommandExecutor()

			mgr := NewUserAccessManager(ctrl, routes, providerTestConfig(), discardLogger(), tc.client(runner))

			err := mgr.Setup()
			if !errors.Is(err, errNoJoinKey) {
				t.Fatalf("Setup error = %v, want one wrapping errNoJoinKey", err)
			}

			// The client ran no command.
			if calls := runner.allCalls(); len(calls) != 0 {
				t.Errorf("client ran %q, want no command", callLines(calls))
			}

			// Provider rollback: WG interface and forwarding should be rolled back.
			removeCalls := ctrl.accessCallsFor("RemoveInterface")
			if len(removeCalls) != 1 {
				t.Errorf("expected 1 RemoveInterface rollback call, got %d", len(removeCalls))
			}
			fwdCalls := routes.callsFor("DisableForwarding")
			if len(fwdCalls) != 1 {
				t.Errorf("expected 1 DisableForwarding rollback call, got %d", len(fwdCalls))
			}

			// Manager should be inactive.
			if mgr.UserAccessStatus() != nil {
				t.Error("UserAccessStatus should be nil after failed setup")
			}
		})
	}
}
