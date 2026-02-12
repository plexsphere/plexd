package bridge

import (
	"fmt"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// UserAccessManager tests
// ---------------------------------------------------------------------------

func TestUserAccessManager_Setup_Enabled(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Verify CreateInterface called.
	createCalls := ctrl.accessCallsFor("CreateInterface")
	if len(createCalls) != 1 {
		t.Fatalf("expected 1 CreateInterface call, got %d", len(createCalls))
	}
	if createCalls[0].Args[0] != "wg-access" {
		t.Errorf("CreateInterface name = %v, want wg-access", createCalls[0].Args[0])
	}
	if createCalls[0].Args[1] != 51822 {
		t.Errorf("CreateInterface listenPort = %v, want 51822", createCalls[0].Args[1])
	}

	// Verify EnableForwarding called.
	fwdCalls := routes.callsFor("EnableForwarding")
	if len(fwdCalls) != 1 {
		t.Fatalf("expected 1 EnableForwarding call, got %d", len(fwdCalls))
	}
	if fwdCalls[0].Args[0] != "wg-access" {
		t.Errorf("EnableForwarding meshIface = %v, want wg-access", fwdCalls[0].Args[0])
	}
	if fwdCalls[0].Args[1] != "eth1" {
		t.Errorf("EnableForwarding accessIface = %v, want eth1", fwdCalls[0].Args[1])
	}
}

func TestUserAccessManager_Setup_Disabled(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		UserAccessEnabled: false,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// No calls should have been made.
	if len(ctrl.accessCallsFor("CreateInterface")) != 0 {
		t.Error("CreateInterface should not be called when disabled")
	}
	if len(routes.callsFor("EnableForwarding")) != 0 {
		t.Error("EnableForwarding should not be called when disabled")
	}
}

func TestUserAccessManager_Setup_CreateInterfaceError(t *testing.T) {
	ctrl := &mockAccessController{
		createInterfaceErr: fmt.Errorf("injected error"),
	}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	err := mgr.Setup()
	if err == nil {
		t.Fatal("Setup should return error")
	}

	if mgr.UserAccessStatus() != nil {
		t.Error("UserAccessStatus should be nil after failed setup")
	}
}

func TestUserAccessManager_Setup_EnableForwardingError(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{
		enableForwardingErr: fmt.Errorf("forwarding error"),
	}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	err := mgr.Setup()
	if err == nil {
		t.Fatal("Setup should return error when forwarding fails")
	}

	// Interface should have been rolled back.
	removeCalls := ctrl.accessCallsFor("RemoveInterface")
	if len(removeCalls) != 1 {
		t.Errorf("expected 1 RemoveInterface rollback call, got %d", len(removeCalls))
	}

	if mgr.UserAccessStatus() != nil {
		t.Error("UserAccessStatus should be nil after failed setup")
	}
}

func TestUserAccessManager_Teardown(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add two peers so teardown has work to do.
	if err := mgr.AddPeer(api.UserAccessPeer{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := mgr.AddPeer(api.UserAccessPeer{PublicKey: "pk-2", AllowedIPs: []string{"10.99.0.2/32"}, Label: "bob"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	ctrl.resetAccess()
	routes.reset()

	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// Verify all peers removed individually.
	removePeerCalls := ctrl.accessCallsFor("RemovePeer")
	if len(removePeerCalls) != 2 {
		t.Errorf("expected 2 RemovePeer calls, got %d", len(removePeerCalls))
	}

	// Verify DisableForwarding called.
	fwdCalls := routes.callsFor("DisableForwarding")
	if len(fwdCalls) != 1 {
		t.Fatalf("expected 1 DisableForwarding call, got %d", len(fwdCalls))
	}

	// Verify RemoveInterface called.
	removeIfaceCalls := ctrl.accessCallsFor("RemoveInterface")
	if len(removeIfaceCalls) != 1 {
		t.Fatalf("expected 1 RemoveInterface call, got %d", len(removeIfaceCalls))
	}
	if removeIfaceCalls[0].Args[0] != "wg-access" {
		t.Errorf("RemoveInterface name = %v, want wg-access", removeIfaceCalls[0].Args[0])
	}

	// Status should be nil after teardown.
	if mgr.UserAccessStatus() != nil {
		t.Error("UserAccessStatus should be nil after teardown")
	}
}

func TestUserAccessManager_Teardown_AggregatesErrors(t *testing.T) {
	ctrl := &mockAccessController{
		removePeerErr:      fmt.Errorf("remove peer error"),
		removeInterfaceErr: fmt.Errorf("remove iface error"),
	}
	routes := &mockRouteController{
		disableForwardingErr: fmt.Errorf("disable fwd error"),
	}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := mgr.AddPeer(api.UserAccessPeer{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	err := mgr.Teardown()
	if err == nil {
		t.Fatal("Teardown should return aggregated errors")
	}

	// Despite errors, manager should be marked inactive.
	if mgr.UserAccessStatus() != nil {
		t.Error("UserAccessStatus should be nil after teardown even with errors")
	}
}

func TestUserAccessManager_Teardown_Idempotent(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		UserAccessEnabled: false,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	// Teardown when not active should return nil.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	if len(ctrl.accessCallsFor("RemoveInterface")) != 0 {
		t.Error("RemoveInterface should not be called when not active")
	}
}

// ---------------------------------------------------------------------------
// AddPeer / RemovePeer tests
// ---------------------------------------------------------------------------

func TestUserAccessManager_AddPeer(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.resetAccess()

	peer := api.UserAccessPeer{
		PublicKey:  "pk-1",
		AllowedIPs: []string{"10.99.0.1/32"},
		PSK:       "psk-1",
		Label:     "alice",
	}
	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	configureCalls := ctrl.accessCallsFor("ConfigurePeer")
	if len(configureCalls) != 1 {
		t.Fatalf("expected 1 ConfigurePeer call, got %d", len(configureCalls))
	}

	status := mgr.UserAccessStatus()
	if status == nil || status.PeerCount != 1 {
		t.Errorf("PeerCount = %v, want 1", status)
	}
}

func TestUserAccessManager_AddPeer_MaxReached(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
		MaxAccessPeers:          2,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add up to max.
	if err := mgr.AddPeer(api.UserAccessPeer{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"}); err != nil {
		t.Fatalf("AddPeer 1: %v", err)
	}
	if err := mgr.AddPeer(api.UserAccessPeer{PublicKey: "pk-2", AllowedIPs: []string{"10.99.0.2/32"}, Label: "bob"}); err != nil {
		t.Fatalf("AddPeer 2: %v", err)
	}

	// Third add should fail.
	err := mgr.AddPeer(api.UserAccessPeer{PublicKey: "pk-3", AllowedIPs: []string{"10.99.0.3/32"}, Label: "charlie"})
	if err == nil {
		t.Fatal("AddPeer should return error when max peers reached")
	}
}

func TestUserAccessManager_AddPeer_Duplicate(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	peer := api.UserAccessPeer{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"}

	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("first AddPeer: %v", err)
	}

	err := mgr.AddPeer(peer)
	if err == nil {
		t.Fatal("AddPeer should return error for duplicate peer")
	}
}

func TestUserAccessManager_RemovePeer(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	peer := api.UserAccessPeer{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"}
	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	ctrl.resetAccess()

	mgr.RemovePeer("pk-1")

	removeCalls := ctrl.accessCallsFor("RemovePeer")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemovePeer call, got %d", len(removeCalls))
	}

	if mgr.UserAccessStatus().PeerCount != 0 {
		t.Errorf("PeerCount = %d, want 0", mgr.UserAccessStatus().PeerCount)
	}

	// Removing non-existent peer is a no-op.
	ctrl.resetAccess()
	mgr.RemovePeer("nonexistent")
	if len(ctrl.accessCallsFor("RemovePeer")) != 0 {
		t.Error("RemovePeer should not call controller for unknown key")
	}
}

// ---------------------------------------------------------------------------
// UserAccessStatus tests
// ---------------------------------------------------------------------------

func TestUserAccessManager_UserAccessStatus_Active(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	status := mgr.UserAccessStatus()
	if status == nil {
		t.Fatal("UserAccessStatus should not be nil when active")
	}
	if !status.Enabled {
		t.Error("Enabled should be true")
	}
	if status.InterfaceName != "wg-access" {
		t.Errorf("InterfaceName = %q, want %q", status.InterfaceName, "wg-access")
	}
	if status.ListenPort != 51822 {
		t.Errorf("ListenPort = %d, want 51822", status.ListenPort)
	}
	if status.PeerCount != 0 {
		t.Errorf("PeerCount = %d, want 0", status.PeerCount)
	}
}

func TestUserAccessManager_UserAccessStatus_Disabled(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		UserAccessEnabled: false,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	if status := mgr.UserAccessStatus(); status != nil {
		t.Errorf("UserAccessStatus should be nil when not active, got %+v", status)
	}
}

// ---------------------------------------------------------------------------
// UserAccessCapabilities tests
// ---------------------------------------------------------------------------

func TestUserAccessManager_UserAccessCapabilities_Enabled(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	caps := mgr.UserAccessCapabilities()
	if caps == nil {
		t.Fatal("UserAccessCapabilities should not be nil when enabled")
	}
	if caps["user_access"] != "true" {
		t.Errorf("user_access = %q, want %q", caps["user_access"], "true")
	}
	if caps["access_listen_port"] != "51822" {
		t.Errorf("access_listen_port = %q, want %q", caps["access_listen_port"], "51822")
	}
}

func TestUserAccessManager_UserAccessCapabilities_Disabled(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		UserAccessEnabled: false,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

	if caps := mgr.UserAccessCapabilities(); caps != nil {
		t.Errorf("UserAccessCapabilities should be nil when disabled, got %v", caps)
	}
}
