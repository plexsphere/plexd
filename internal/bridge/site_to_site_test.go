package bridge

import (
	"fmt"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// SiteToSiteManager Setup tests
// ---------------------------------------------------------------------------

func TestSiteToSiteManager_Setup_Disabled(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: false,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Manager should not be active.
	if mgr.SiteToSiteStatus() != nil {
		t.Error("SiteToSiteStatus should be nil when disabled")
	}
}

func TestSiteToSiteManager_Setup_Enabled(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	status := mgr.SiteToSiteStatus()
	if status == nil {
		t.Fatal("SiteToSiteStatus should not be nil when active")
	}
	if !status.Enabled {
		t.Error("Enabled should be true")
	}
	if status.TunnelCount != 0 {
		t.Errorf("TunnelCount = %d, want 0", status.TunnelCount)
	}
}

// ---------------------------------------------------------------------------
// SiteToSiteManager Teardown tests
// ---------------------------------------------------------------------------

func TestSiteToSiteManager_Teardown_Inactive(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: false,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	// Teardown when not active should return nil.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	if len(vpn.vpnCallsFor("RemoveTunnelInterface")) != 0 {
		t.Error("RemoveTunnelInterface should not be called when not active")
	}
}

func TestSiteToSiteManager_Teardown_Active(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add two tunnels so teardown has work to do.
	tunnel1 := api.SiteToSiteTunnel{
		TunnelID:        "t-1",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-1",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.1.0.0/24"},
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}
	tunnel2 := api.SiteToSiteTunnel{
		TunnelID:        "t-2",
		RemoteEndpoint:  "5.6.7.8:51824",
		RemotePublicKey: "rpk-2",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.2.0.0/24"},
		InterfaceName:   "wg-s2s-1",
		ListenPort:      51824,
	}
	if err := mgr.AddTunnel(tunnel1); err != nil {
		t.Fatalf("AddTunnel 1: %v", err)
	}
	if err := mgr.AddTunnel(tunnel2); err != nil {
		t.Fatalf("AddTunnel 2: %v", err)
	}
	vpn.resetVPN()
	routes.reset()

	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// Verify routes removed for both tunnels.
	removeRouteCalls := routes.callsFor("RemoveRoute")
	if len(removeRouteCalls) != 2 {
		t.Errorf("expected 2 RemoveRoute calls, got %d", len(removeRouteCalls))
	}

	// Verify forwarding disabled for both tunnels.
	disableFwdCalls := routes.callsFor("DisableForwarding")
	if len(disableFwdCalls) != 2 {
		t.Errorf("expected 2 DisableForwarding calls, got %d", len(disableFwdCalls))
	}

	// Verify interfaces removed for both tunnels.
	removeIfaceCalls := vpn.vpnCallsFor("RemoveTunnelInterface")
	if len(removeIfaceCalls) != 2 {
		t.Errorf("expected 2 RemoveTunnelInterface calls, got %d", len(removeIfaceCalls))
	}

	// Status should be nil after teardown.
	if mgr.SiteToSiteStatus() != nil {
		t.Error("SiteToSiteStatus should be nil after teardown")
	}

	// TunnelIDs should be empty.
	if ids := mgr.TunnelIDs(); len(ids) != 0 {
		t.Errorf("TunnelIDs should be empty after teardown, got %v", ids)
	}
}

func TestSiteToSiteManager_Teardown_AggregatesErrors(t *testing.T) {
	vpn := &mockVPNController{
		removeErr: fmt.Errorf("remove iface error"),
	}
	routes := &mockRouteController{
		removeRouteErr: fmt.Errorf("remove route error"),
	}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	tunnel := api.SiteToSiteTunnel{
		TunnelID:        "t-1",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-1",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.1.0.0/24"},
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}
	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	err := mgr.Teardown()
	if err == nil {
		t.Fatal("Teardown should return aggregated errors")
	}

	// Despite errors, manager should be marked inactive.
	if mgr.SiteToSiteStatus() != nil {
		t.Error("SiteToSiteStatus should be nil after teardown even with errors")
	}
}

// ---------------------------------------------------------------------------
// SiteToSiteManager AddTunnel tests
// ---------------------------------------------------------------------------

func TestSiteToSiteManager_AddTunnel_Success(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	vpn.resetVPN()
	routes.reset()

	tunnel := api.SiteToSiteTunnel{
		TunnelID:        "t-1",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-1",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.1.0.0/24", "10.2.0.0/24"},
		PSK:             "psk-1",
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}
	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	// Verify CreateTunnelInterface called.
	createCalls := vpn.vpnCallsFor("CreateTunnelInterface")
	if len(createCalls) != 1 {
		t.Fatalf("expected 1 CreateTunnelInterface call, got %d", len(createCalls))
	}
	if createCalls[0].Args[0] != "wg-s2s-0" {
		t.Errorf("CreateTunnelInterface name = %v, want wg-s2s-0", createCalls[0].Args[0])
	}
	if createCalls[0].Args[1] != 51823 {
		t.Errorf("CreateTunnelInterface listenPort = %v, want 51823", createCalls[0].Args[1])
	}

	// Verify ConfigureTunnelPeer called.
	configureCalls := vpn.vpnCallsFor("ConfigureTunnelPeer")
	if len(configureCalls) != 1 {
		t.Fatalf("expected 1 ConfigureTunnelPeer call, got %d", len(configureCalls))
	}
	if configureCalls[0].Args[0] != "wg-s2s-0" {
		t.Errorf("ConfigureTunnelPeer iface = %v, want wg-s2s-0", configureCalls[0].Args[0])
	}
	if configureCalls[0].Args[1] != "rpk-1" {
		t.Errorf("ConfigureTunnelPeer publicKey = %v, want rpk-1", configureCalls[0].Args[1])
	}
	if configureCalls[0].Args[3] != "1.2.3.4:51823" {
		t.Errorf("ConfigureTunnelPeer endpoint = %v, want 1.2.3.4:51823", configureCalls[0].Args[3])
	}
	if configureCalls[0].Args[4] != "psk-1" {
		t.Errorf("ConfigureTunnelPeer psk = %v, want psk-1", configureCalls[0].Args[4])
	}

	// Verify EnableForwarding called between tunnel and mesh interfaces.
	fwdCalls := routes.callsFor("EnableForwarding")
	if len(fwdCalls) != 1 {
		t.Fatalf("expected 1 EnableForwarding call, got %d", len(fwdCalls))
	}
	if fwdCalls[0].Args[0] != "wg-s2s-0" {
		t.Errorf("EnableForwarding tunnelIface = %v, want wg-s2s-0", fwdCalls[0].Args[0])
	}
	if fwdCalls[0].Args[1] != "wg0" {
		t.Errorf("EnableForwarding meshIface = %v, want wg0", fwdCalls[0].Args[1])
	}

	// Verify AddRoute called for each remote subnet.
	addRouteCalls := routes.callsFor("AddRoute")
	if len(addRouteCalls) != 2 {
		t.Fatalf("expected 2 AddRoute calls, got %d", len(addRouteCalls))
	}
	if addRouteCalls[0].Args[0] != "10.1.0.0/24" {
		t.Errorf("AddRoute[0] subnet = %v, want 10.1.0.0/24", addRouteCalls[0].Args[0])
	}
	if addRouteCalls[0].Args[1] != "wg-s2s-0" {
		t.Errorf("AddRoute[0] iface = %v, want wg-s2s-0", addRouteCalls[0].Args[1])
	}
	if addRouteCalls[1].Args[0] != "10.2.0.0/24" {
		t.Errorf("AddRoute[1] subnet = %v, want 10.2.0.0/24", addRouteCalls[1].Args[0])
	}

	// Verify tunnel is tracked.
	ids := mgr.TunnelIDs()
	if len(ids) != 1 || ids[0] != "t-1" {
		t.Errorf("TunnelIDs = %v, want [t-1]", ids)
	}

	// Verify status reflects the tunnel.
	status := mgr.SiteToSiteStatus()
	if status == nil || status.TunnelCount != 1 {
		t.Errorf("TunnelCount = %v, want 1", status)
	}
}

func TestSiteToSiteManager_AddTunnel_Inactive(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	// Do NOT call Setup — manager is inactive.
	tunnel := api.SiteToSiteTunnel{
		TunnelID:        "t-1",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-1",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.1.0.0/24"},
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}

	err := mgr.AddTunnel(tunnel)
	if err == nil {
		t.Fatal("AddTunnel should return error when manager is inactive")
	}

	// Verify no controller calls were made.
	if len(vpn.vpnCallsFor("CreateTunnelInterface")) != 0 {
		t.Error("CreateTunnelInterface should not be called when manager is inactive")
	}
}

func TestSiteToSiteManager_AddTunnel_Duplicate(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	tunnel := api.SiteToSiteTunnel{
		TunnelID:        "t-1",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-1",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.1.0.0/24"},
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}

	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("first AddTunnel: %v", err)
	}

	err := mgr.AddTunnel(tunnel)
	if err == nil {
		t.Fatal("AddTunnel should return error for duplicate tunnel ID")
	}
}

func TestSiteToSiteManager_AddTunnel_MaxReached(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:              true,
		AccessInterface:      "eth1",
		AccessSubnets:        []string{"10.0.0.0/24"},
		SiteToSiteEnabled:    true,
		MaxSiteToSiteTunnels: 2,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add up to max.
	for i := 0; i < 2; i++ {
		tunnel := api.SiteToSiteTunnel{
			TunnelID:        fmt.Sprintf("t-%d", i),
			RemoteEndpoint:  fmt.Sprintf("1.2.3.%d:51823", i),
			RemotePublicKey: fmt.Sprintf("rpk-%d", i),
			LocalSubnets:    []string{"10.0.0.0/24"},
			RemoteSubnets:   []string{fmt.Sprintf("10.%d.0.0/24", i+1)},
			InterfaceName:   fmt.Sprintf("wg-s2s-%d", i),
			ListenPort:      51823 + i,
		}
		if err := mgr.AddTunnel(tunnel); err != nil {
			t.Fatalf("AddTunnel %d: %v", i, err)
		}
	}

	// Third should fail.
	err := mgr.AddTunnel(api.SiteToSiteTunnel{
		TunnelID:        "t-extra",
		RemoteEndpoint:  "9.9.9.9:51825",
		RemotePublicKey: "rpk-extra",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.99.0.0/24"},
		InterfaceName:   "wg-s2s-extra",
		ListenPort:      51825,
	})
	if err == nil {
		t.Fatal("AddTunnel should return error when max tunnels reached")
	}
}

func TestSiteToSiteManager_AddTunnel_CreateInterfaceError(t *testing.T) {
	vpn := &mockVPNController{
		createErr: fmt.Errorf("create interface error"),
	}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	tunnel := api.SiteToSiteTunnel{
		TunnelID:        "t-1",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-1",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.1.0.0/24"},
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}

	err := mgr.AddTunnel(tunnel)
	if err == nil {
		t.Fatal("AddTunnel should return error when CreateTunnelInterface fails")
	}

	// Verify no tunnel is tracked.
	if len(mgr.TunnelIDs()) != 0 {
		t.Error("no tunnel should be tracked after create error")
	}

	// Verify no peer was configured or routes added.
	if len(vpn.vpnCallsFor("ConfigureTunnelPeer")) != 0 {
		t.Error("ConfigureTunnelPeer should not be called after create error")
	}
	if len(routes.callsFor("AddRoute")) != 0 {
		t.Error("AddRoute should not be called after create error")
	}
}

func TestSiteToSiteManager_AddTunnel_ConfigurePeerError(t *testing.T) {
	vpn := &mockVPNController{
		configureErr: fmt.Errorf("configure peer error"),
	}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	tunnel := api.SiteToSiteTunnel{
		TunnelID:        "t-1",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-1",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.1.0.0/24"},
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}

	err := mgr.AddTunnel(tunnel)
	if err == nil {
		t.Fatal("AddTunnel should return error when ConfigureTunnelPeer fails")
	}

	// Verify rollback: interface should have been removed.
	removeCalls := vpn.vpnCallsFor("RemoveTunnelInterface")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemoveTunnelInterface rollback call, got %d", len(removeCalls))
	}
	if removeCalls[0].Args[0] != "wg-s2s-0" {
		t.Errorf("RemoveTunnelInterface name = %v, want wg-s2s-0", removeCalls[0].Args[0])
	}

	// Verify no tunnel is tracked.
	if len(mgr.TunnelIDs()) != 0 {
		t.Error("no tunnel should be tracked after configure error")
	}

	// Verify no forwarding was enabled.
	if len(routes.callsFor("EnableForwarding")) != 0 {
		t.Error("EnableForwarding should not be called after configure error")
	}

	// Verify no routes were added.
	if len(routes.callsFor("AddRoute")) != 0 {
		t.Error("AddRoute should not be called after configure error")
	}
}

func TestSiteToSiteManager_AddTunnel_AddRouteError(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{
		// Fail on the second subnet only.
		addRouteErrFor: map[string]error{
			"10.2.0.0/24": fmt.Errorf("add route error"),
		},
	}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	tunnel := api.SiteToSiteTunnel{
		TunnelID:        "t-1",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-1",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.1.0.0/24", "10.2.0.0/24"},
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}

	err := mgr.AddTunnel(tunnel)
	if err == nil {
		t.Fatal("AddTunnel should return error when AddRoute fails")
	}

	// Verify rollback: first successfully added route should be removed.
	removeRouteCalls := routes.callsFor("RemoveRoute")
	if len(removeRouteCalls) != 1 {
		t.Fatalf("expected 1 RemoveRoute rollback call, got %d", len(removeRouteCalls))
	}
	if removeRouteCalls[0].Args[0] != "10.1.0.0/24" {
		t.Errorf("RemoveRoute subnet = %v, want 10.1.0.0/24", removeRouteCalls[0].Args[0])
	}

	// Verify rollback: forwarding disabled, peer and interface removed.
	disableFwdCalls := routes.callsFor("DisableForwarding")
	if len(disableFwdCalls) != 1 {
		t.Fatalf("expected 1 DisableForwarding rollback call, got %d", len(disableFwdCalls))
	}
	removePeerCalls := vpn.vpnCallsFor("RemoveTunnelPeer")
	if len(removePeerCalls) != 1 {
		t.Fatalf("expected 1 RemoveTunnelPeer rollback call, got %d", len(removePeerCalls))
	}
	removeIfaceCalls := vpn.vpnCallsFor("RemoveTunnelInterface")
	if len(removeIfaceCalls) != 1 {
		t.Fatalf("expected 1 RemoveTunnelInterface rollback call, got %d", len(removeIfaceCalls))
	}

	// Verify no tunnel is tracked.
	if len(mgr.TunnelIDs()) != 0 {
		t.Error("no tunnel should be tracked after route error")
	}
}

func TestSiteToSiteManager_AddTunnel_EnableForwardingError(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{
		enableForwardingErr: fmt.Errorf("enable forwarding error"),
	}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	tunnel := api.SiteToSiteTunnel{
		TunnelID:        "t-1",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-1",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.1.0.0/24"},
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}

	err := mgr.AddTunnel(tunnel)
	if err == nil {
		t.Fatal("AddTunnel should return error when EnableForwarding fails")
	}

	// Verify rollback: peer and interface should be removed.
	removePeerCalls := vpn.vpnCallsFor("RemoveTunnelPeer")
	if len(removePeerCalls) != 1 {
		t.Fatalf("expected 1 RemoveTunnelPeer rollback call, got %d", len(removePeerCalls))
	}
	removeIfaceCalls := vpn.vpnCallsFor("RemoveTunnelInterface")
	if len(removeIfaceCalls) != 1 {
		t.Fatalf("expected 1 RemoveTunnelInterface rollback call, got %d", len(removeIfaceCalls))
	}

	// Verify no routes were added.
	if len(routes.callsFor("AddRoute")) != 0 {
		t.Error("AddRoute should not be called after forwarding error")
	}

	// Verify no tunnel is tracked.
	if len(mgr.TunnelIDs()) != 0 {
		t.Error("no tunnel should be tracked after forwarding error")
	}
}

func TestSiteToSiteManager_AddTunnel_EmptyRemoteSubnets(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	vpn.resetVPN()
	routes.reset()

	tunnel := api.SiteToSiteTunnel{
		TunnelID:        "t-empty",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-empty",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{}, // empty
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}
	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("AddTunnel with empty RemoteSubnets: %v", err)
	}

	// Verify interface was created.
	createCalls := vpn.vpnCallsFor("CreateTunnelInterface")
	if len(createCalls) != 1 {
		t.Fatalf("expected 1 CreateTunnelInterface call, got %d", len(createCalls))
	}

	// Verify peer was configured.
	configureCalls := vpn.vpnCallsFor("ConfigureTunnelPeer")
	if len(configureCalls) != 1 {
		t.Fatalf("expected 1 ConfigureTunnelPeer call, got %d", len(configureCalls))
	}

	// Verify forwarding was enabled.
	fwdCalls := routes.callsFor("EnableForwarding")
	if len(fwdCalls) != 1 {
		t.Fatalf("expected 1 EnableForwarding call, got %d", len(fwdCalls))
	}

	// Verify no routes were added (empty subnets).
	if len(routes.callsFor("AddRoute")) != 0 {
		t.Error("AddRoute should not be called with empty RemoteSubnets")
	}

	// Verify tunnel is tracked.
	ids := mgr.TunnelIDs()
	if len(ids) != 1 || ids[0] != "t-empty" {
		t.Errorf("TunnelIDs = %v, want [t-empty]", ids)
	}

	// Verify status reflects the tunnel.
	status := mgr.SiteToSiteStatus()
	if status == nil || status.TunnelCount != 1 {
		t.Errorf("TunnelCount = %v, want 1", status)
	}
}

// ---------------------------------------------------------------------------
// SiteToSiteManager RemoveTunnel tests
// ---------------------------------------------------------------------------

func TestSiteToSiteManager_RemoveTunnel_Success(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	tunnel := api.SiteToSiteTunnel{
		TunnelID:        "t-1",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-1",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.1.0.0/24"},
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}
	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}
	vpn.resetVPN()
	routes.reset()

	mgr.RemoveTunnel("t-1")

	// Verify RemoveRoute called.
	removeRouteCalls := routes.callsFor("RemoveRoute")
	if len(removeRouteCalls) != 1 {
		t.Fatalf("expected 1 RemoveRoute call, got %d", len(removeRouteCalls))
	}
	if removeRouteCalls[0].Args[0] != "10.1.0.0/24" {
		t.Errorf("RemoveRoute subnet = %v, want 10.1.0.0/24", removeRouteCalls[0].Args[0])
	}

	// Verify DisableForwarding called between tunnel and mesh interfaces.
	disableFwdCalls := routes.callsFor("DisableForwarding")
	if len(disableFwdCalls) != 1 {
		t.Fatalf("expected 1 DisableForwarding call, got %d", len(disableFwdCalls))
	}
	if disableFwdCalls[0].Args[0] != "wg-s2s-0" {
		t.Errorf("DisableForwarding tunnelIface = %v, want wg-s2s-0", disableFwdCalls[0].Args[0])
	}
	if disableFwdCalls[0].Args[1] != "wg0" {
		t.Errorf("DisableForwarding meshIface = %v, want wg0", disableFwdCalls[0].Args[1])
	}

	// Verify RemoveTunnelPeer called.
	removePeerCalls := vpn.vpnCallsFor("RemoveTunnelPeer")
	if len(removePeerCalls) != 1 {
		t.Fatalf("expected 1 RemoveTunnelPeer call, got %d", len(removePeerCalls))
	}

	// Verify RemoveTunnelInterface called.
	removeIfaceCalls := vpn.vpnCallsFor("RemoveTunnelInterface")
	if len(removeIfaceCalls) != 1 {
		t.Fatalf("expected 1 RemoveTunnelInterface call, got %d", len(removeIfaceCalls))
	}
	if removeIfaceCalls[0].Args[0] != "wg-s2s-0" {
		t.Errorf("RemoveTunnelInterface name = %v, want wg-s2s-0", removeIfaceCalls[0].Args[0])
	}

	// Verify tunnel is no longer tracked.
	if ids := mgr.TunnelIDs(); len(ids) != 0 {
		t.Errorf("TunnelIDs = %v, want empty", ids)
	}

	status := mgr.SiteToSiteStatus()
	if status == nil || status.TunnelCount != 0 {
		t.Errorf("TunnelCount = %v, want 0", status)
	}
}

func TestSiteToSiteManager_RemoveTunnel_NotFound(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Remove non-existent tunnel should not panic or call controller.
	mgr.RemoveTunnel("nonexistent")

	if len(vpn.vpnCallsFor("RemoveTunnelInterface")) != 0 {
		t.Error("RemoveTunnelInterface should not be called for non-existent tunnel")
	}
	if len(vpn.vpnCallsFor("RemoveTunnelPeer")) != 0 {
		t.Error("RemoveTunnelPeer should not be called for non-existent tunnel")
	}
	if len(routes.callsFor("RemoveRoute")) != 0 {
		t.Error("RemoveRoute should not be called for non-existent tunnel")
	}
}

func TestSiteToSiteManager_RemoveTunnel_Inactive(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	// Do NOT call Setup — manager is inactive.
	// Should not panic or call controller.
	mgr.RemoveTunnel("any-tunnel")

	if len(vpn.vpnCallsFor("RemoveTunnelInterface")) != 0 {
		t.Error("RemoveTunnelInterface should not be called when manager is inactive")
	}
}

// ---------------------------------------------------------------------------
// SiteToSiteManager GetTunnel tests
// ---------------------------------------------------------------------------

func TestSiteToSiteManager_GetTunnel_Exists(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	tunnel := api.SiteToSiteTunnel{
		TunnelID:        "t-get",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-get",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.1.0.0/24"},
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}
	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	got, ok := mgr.GetTunnel("t-get")
	if !ok {
		t.Fatal("GetTunnel should return true for existing tunnel")
	}
	if got.TunnelID != tunnel.TunnelID {
		t.Errorf("GetTunnel TunnelID = %q, want %q", got.TunnelID, tunnel.TunnelID)
	}
	if got.RemoteEndpoint != tunnel.RemoteEndpoint {
		t.Errorf("GetTunnel RemoteEndpoint = %q, want %q", got.RemoteEndpoint, tunnel.RemoteEndpoint)
	}
}

func TestSiteToSiteManager_GetTunnel_NotFound(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	_, ok := mgr.GetTunnel("nonexistent")
	if ok {
		t.Error("GetTunnel should return false for non-existent tunnel")
	}
}

// ---------------------------------------------------------------------------
// SiteToSiteManager TunnelIDs tests
// ---------------------------------------------------------------------------

func TestSiteToSiteManager_TunnelIDs(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Empty initially.
	if ids := mgr.TunnelIDs(); len(ids) != 0 {
		t.Errorf("TunnelIDs should be empty initially, got %v", ids)
	}

	// Add two tunnels.
	for i := 0; i < 2; i++ {
		tunnel := api.SiteToSiteTunnel{
			TunnelID:        fmt.Sprintf("t-%d", i),
			RemoteEndpoint:  fmt.Sprintf("1.2.3.%d:51823", i),
			RemotePublicKey: fmt.Sprintf("rpk-%d", i),
			LocalSubnets:    []string{"10.0.0.0/24"},
			RemoteSubnets:   []string{fmt.Sprintf("10.%d.0.0/24", i+1)},
			InterfaceName:   fmt.Sprintf("wg-s2s-%d", i),
			ListenPort:      51823 + i,
		}
		if err := mgr.AddTunnel(tunnel); err != nil {
			t.Fatalf("AddTunnel %d: %v", i, err)
		}
	}

	ids := mgr.TunnelIDs()
	if len(ids) != 2 {
		t.Fatalf("TunnelIDs count = %d, want 2", len(ids))
	}

	// Check both IDs are present (order not guaranteed).
	found := make(map[string]bool)
	for _, id := range ids {
		found[id] = true
	}
	if !found["t-0"] || !found["t-1"] {
		t.Errorf("TunnelIDs = %v, want t-0 and t-1", ids)
	}
}

// ---------------------------------------------------------------------------
// SiteToSiteManager SiteToSiteStatus tests
// ---------------------------------------------------------------------------

func TestSiteToSiteManager_SiteToSiteStatus_Active(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add a tunnel.
	tunnel := api.SiteToSiteTunnel{
		TunnelID:        "t-1",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-1",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"10.1.0.0/24"},
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}
	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	status := mgr.SiteToSiteStatus()
	if status == nil {
		t.Fatal("SiteToSiteStatus should not be nil when active")
	}
	if !status.Enabled {
		t.Error("Enabled should be true")
	}
	if status.TunnelCount != 1 {
		t.Errorf("TunnelCount = %d, want 1", status.TunnelCount)
	}
}

func TestSiteToSiteManager_SiteToSiteStatus_Inactive(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: false,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if status := mgr.SiteToSiteStatus(); status != nil {
		t.Errorf("SiteToSiteStatus should be nil when not active, got %+v", status)
	}
}

// ---------------------------------------------------------------------------
// SiteToSiteManager SiteToSiteCapabilities tests
// ---------------------------------------------------------------------------

func TestSiteToSiteManager_SiteToSiteCapabilities_Enabled(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	caps := mgr.SiteToSiteCapabilities()
	if caps == nil {
		t.Fatal("SiteToSiteCapabilities should not be nil when enabled")
	}
	if caps["site_to_site"] != "true" {
		t.Errorf("site_to_site = %q, want %q", caps["site_to_site"], "true")
	}
	if caps["max_site_to_site_tunnels"] != "10" {
		t.Errorf("max_site_to_site_tunnels = %q, want %q", caps["max_site_to_site_tunnels"], "10")
	}
}

func TestSiteToSiteManager_SiteToSiteCapabilities_Disabled(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: false,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger())

	if caps := mgr.SiteToSiteCapabilities(); caps != nil {
		t.Errorf("SiteToSiteCapabilities should be nil when disabled, got %v", caps)
	}
}
