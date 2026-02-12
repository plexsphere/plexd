package bridge

import (
	"fmt"
	"testing"
)

func TestManager_Setup_Enabled(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24", "192.168.1.0/24"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Verify EnableForwarding called.
	fwdCalls := ctrl.callsFor("EnableForwarding")
	if len(fwdCalls) != 1 {
		t.Fatalf("expected 1 EnableForwarding call, got %d", len(fwdCalls))
	}
	if fwdCalls[0].Args[0] != "wg0" || fwdCalls[0].Args[1] != "eth1" {
		t.Errorf("EnableForwarding args = %v, want [wg0 eth1]", fwdCalls[0].Args)
	}

	// Verify AddRoute called for each subnet.
	routeCalls := ctrl.callsFor("AddRoute")
	if len(routeCalls) != 2 {
		t.Fatalf("expected 2 AddRoute calls, got %d", len(routeCalls))
	}
	if routeCalls[0].Args[0] != "10.0.0.0/24" {
		t.Errorf("AddRoute[0] subnet = %v, want 10.0.0.0/24", routeCalls[0].Args[0])
	}
	if routeCalls[1].Args[0] != "192.168.1.0/24" {
		t.Errorf("AddRoute[1] subnet = %v, want 192.168.1.0/24", routeCalls[1].Args[0])
	}

	// Verify AddNATMasquerade called.
	natCalls := ctrl.callsFor("AddNATMasquerade")
	if len(natCalls) != 1 {
		t.Fatalf("expected 1 AddNATMasquerade call, got %d", len(natCalls))
	}
	if natCalls[0].Args[0] != "eth1" {
		t.Errorf("AddNATMasquerade iface = %v, want eth1", natCalls[0].Args[0])
	}
}

func TestManager_Setup_Disabled(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled: false,
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// No calls should have been made.
	if len(ctrl.callsFor("EnableForwarding")) != 0 {
		t.Error("EnableForwarding should not be called when disabled")
	}
	if len(ctrl.callsFor("AddRoute")) != 0 {
		t.Error("AddRoute should not be called when disabled")
	}
	if len(ctrl.callsFor("AddNATMasquerade")) != 0 {
		t.Error("AddNATMasquerade should not be called when disabled")
	}
}

func TestManager_Setup_RollbackOnRouteFailure(t *testing.T) {
	ctrl := &mockRouteController{
		addRouteErrFor: map[string]error{
			"192.168.1.0/24": fmt.Errorf("injected error"),
		},
	}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24", "192.168.1.0/24", "172.16.0.0/16"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	err := mgr.Setup("wg0")
	if err == nil {
		t.Fatal("Setup should return error")
	}

	// Verify rollback: RemoveRoute called for the first subnet.
	removeCalls := ctrl.callsFor("RemoveRoute")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemoveRoute rollback call, got %d", len(removeCalls))
	}
	if removeCalls[0].Args[0] != "10.0.0.0/24" {
		t.Errorf("rollback subnet = %v, want 10.0.0.0/24", removeCalls[0].Args[0])
	}

	// Verify DisableForwarding called (rollback).
	disableCalls := ctrl.callsFor("DisableForwarding")
	if len(disableCalls) != 1 {
		t.Fatalf("expected 1 DisableForwarding call, got %d", len(disableCalls))
	}

	// Bridge should NOT be active.
	if mgr.BridgeStatus() != nil {
		t.Error("BridgeStatus should be nil after failed setup")
	}
}

func TestManager_Setup_WithoutNAT(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		EnableNAT:       BoolPtr(false),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Verify AddNATMasquerade was NOT called.
	natCalls := ctrl.callsFor("AddNATMasquerade")
	if len(natCalls) != 0 {
		t.Errorf("expected 0 AddNATMasquerade calls, got %d", len(natCalls))
	}

	// Verify routes were still added.
	routeCalls := ctrl.callsFor("AddRoute")
	if len(routeCalls) != 1 {
		t.Fatalf("expected 1 AddRoute call, got %d", len(routeCalls))
	}
}

func TestManager_Setup_NATDefaultTrue(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		// EnableNAT is nil — should default to true.
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Verify AddNATMasquerade WAS called (default behavior).
	natCalls := ctrl.callsFor("AddNATMasquerade")
	if len(natCalls) != 1 {
		t.Fatalf("expected 1 AddNATMasquerade call with nil EnableNAT, got %d", len(natCalls))
	}
}

func TestManager_Setup_RollbackOnNATFailure(t *testing.T) {
	ctrl := &mockRouteController{
		addNATMasqueradeErr: fmt.Errorf("injected NAT error"),
	}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24", "192.168.1.0/24"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	err := mgr.Setup("wg0")
	if err == nil {
		t.Fatal("Setup should return error on NAT failure")
	}

	// Verify routes were rolled back.
	removeCalls := ctrl.callsFor("RemoveRoute")
	if len(removeCalls) != 2 {
		t.Fatalf("expected 2 RemoveRoute rollback calls, got %d", len(removeCalls))
	}

	// Verify forwarding was disabled (rollback).
	disableCalls := ctrl.callsFor("DisableForwarding")
	if len(disableCalls) != 1 {
		t.Fatalf("expected 1 DisableForwarding call, got %d", len(disableCalls))
	}

	// Bridge should NOT be active.
	if mgr.BridgeStatus() != nil {
		t.Error("BridgeStatus should be nil after failed setup")
	}

	// activeRoutes should be empty.
	if len(mgr.activeRoutes) != 0 {
		t.Errorf("activeRoutes should be empty, got %d entries", len(mgr.activeRoutes))
	}

	// Subsequent Teardown should be safe (idempotent).
	ctrl.reset()
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown after failed setup: %v", err)
	}
	// Teardown should be a no-op since active=false.
	if len(ctrl.callsFor("RemoveRoute")) != 0 {
		t.Error("Teardown should be no-op after failed setup")
	}
}

func TestManager_Teardown(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24", "192.168.1.0/24"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.reset()

	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// Verify RemoveRoute called for all subnets.
	removeCalls := ctrl.callsFor("RemoveRoute")
	if len(removeCalls) != 2 {
		t.Fatalf("expected 2 RemoveRoute calls, got %d", len(removeCalls))
	}

	// Verify RemoveNATMasquerade called.
	natCalls := ctrl.callsFor("RemoveNATMasquerade")
	if len(natCalls) != 1 {
		t.Fatalf("expected 1 RemoveNATMasquerade call, got %d", len(natCalls))
	}

	// Verify DisableForwarding called.
	disableCalls := ctrl.callsFor("DisableForwarding")
	if len(disableCalls) != 1 {
		t.Fatalf("expected 1 DisableForwarding call, got %d", len(disableCalls))
	}
}

func TestManager_Teardown_Idempotent(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled: false,
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	// Teardown when not active should return nil.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// No calls should have been made.
	if len(ctrl.callsFor("RemoveRoute")) != 0 {
		t.Error("RemoveRoute should not be called when not active")
	}
	if len(ctrl.callsFor("RemoveNATMasquerade")) != 0 {
		t.Error("RemoveNATMasquerade should not be called when not active")
	}
	if len(ctrl.callsFor("DisableForwarding")) != 0 {
		t.Error("DisableForwarding should not be called when not active")
	}
}

func TestManager_Teardown_PartialFailure(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24", "192.168.1.0/24"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Inject error for one subnet removal.
	ctrl.reset()
	ctrl.removeRouteErrFor = map[string]error{
		"10.0.0.0/24": fmt.Errorf("injected remove error"),
	}

	err := mgr.Teardown()
	if err == nil {
		t.Fatal("Teardown should return error on partial failure")
	}

	// Verify teardown continued despite the error: DisableForwarding should still be called.
	disableCalls := ctrl.callsFor("DisableForwarding")
	if len(disableCalls) != 1 {
		t.Fatalf("expected 1 DisableForwarding call, got %d", len(disableCalls))
	}

	// Bridge should be inactive after teardown.
	if mgr.BridgeStatus() != nil {
		t.Error("BridgeStatus should be nil after teardown")
	}
}

func TestManager_BridgeStatus_Active(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24", "192.168.1.0/24"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	info := mgr.BridgeStatus()
	if info == nil {
		t.Fatal("BridgeStatus should not be nil when active")
	}
	if !info.Enabled {
		t.Error("BridgeInfo.Enabled should be true")
	}
	if info.AccessInterface != "eth1" {
		t.Errorf("BridgeInfo.AccessInterface = %q, want %q", info.AccessInterface, "eth1")
	}
	if info.ActiveRoutes != 2 {
		t.Errorf("BridgeInfo.ActiveRoutes = %d, want 2", info.ActiveRoutes)
	}
}

func TestManager_BridgeStatus_Disabled(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled: false,
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	if info := mgr.BridgeStatus(); info != nil {
		t.Errorf("BridgeStatus should be nil when not active, got %+v", info)
	}
}

func TestManager_BridgeCapabilities(t *testing.T) {
	ctrl := &mockRouteController{}

	// Enabled case.
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24", "192.168.1.0/24"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	caps := mgr.BridgeCapabilities()
	if caps == nil {
		t.Fatal("BridgeCapabilities should not be nil when enabled")
	}
	if caps["bridge"] != "true" {
		t.Errorf("caps[bridge] = %q, want %q", caps["bridge"], "true")
	}
	if caps["access_interface"] != "eth1" {
		t.Errorf("caps[access_interface] = %q, want %q", caps["access_interface"], "eth1")
	}
	if caps["access_subnet_0"] != "10.0.0.0/24" {
		t.Errorf("caps[access_subnet_0] = %q, want %q", caps["access_subnet_0"], "10.0.0.0/24")
	}
	if caps["access_subnet_1"] != "192.168.1.0/24" {
		t.Errorf("caps[access_subnet_1] = %q, want %q", caps["access_subnet_1"], "192.168.1.0/24")
	}

	// Disabled case.
	cfgDisabled := Config{Enabled: false}
	mgrDisabled := NewManager(ctrl, cfgDisabled, discardLogger())
	if caps := mgrDisabled.BridgeCapabilities(); caps != nil {
		t.Errorf("BridgeCapabilities should be nil when disabled, got %v", caps)
	}
}

func TestManager_UpdateRoutes(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24", "192.168.1.0/24"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.reset()

	// Update: keep 10.0.0.0/24, remove 192.168.1.0/24, add 172.16.0.0/16.
	newSubnets := []string{"10.0.0.0/24", "172.16.0.0/16"}
	if err := mgr.UpdateRoutes(newSubnets); err != nil {
		t.Fatalf("UpdateRoutes: %v", err)
	}

	// Verify stale route removed.
	removeCalls := ctrl.callsFor("RemoveRoute")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemoveRoute call, got %d", len(removeCalls))
	}
	if removeCalls[0].Args[0] != "192.168.1.0/24" {
		t.Errorf("RemoveRoute subnet = %v, want 192.168.1.0/24", removeCalls[0].Args[0])
	}

	// Verify new route added.
	addCalls := ctrl.callsFor("AddRoute")
	if len(addCalls) != 1 {
		t.Fatalf("expected 1 AddRoute call, got %d", len(addCalls))
	}
	if addCalls[0].Args[0] != "172.16.0.0/16" {
		t.Errorf("AddRoute subnet = %v, want 172.16.0.0/16", addCalls[0].Args[0])
	}

	// Verify status reflects updated routes.
	info := mgr.BridgeStatus()
	if info == nil {
		t.Fatal("BridgeStatus should not be nil")
	}
	if info.ActiveRoutes != 2 {
		t.Errorf("ActiveRoutes = %d, want 2", info.ActiveRoutes)
	}
}
