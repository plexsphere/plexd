package bridge

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/wireguard"
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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)
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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)
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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)
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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

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

	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

	if caps := mgr.SiteToSiteCapabilities(); caps != nil {
		t.Errorf("SiteToSiteCapabilities should be nil when disabled, got %v", caps)
	}
}

// ---------------------------------------------------------------------------
// mockTunnelProvider — test double for TunnelProvider
// ---------------------------------------------------------------------------

type mockTunnelProvider struct {
	mu        sync.Mutex
	calls     []mockCall
	createErr error
	removeErr error
	stopErr   error
	tunnels   map[string]bool
}

func newMockTunnelProvider() *mockTunnelProvider {
	return &mockTunnelProvider{tunnels: make(map[string]bool)}
}

func (p *mockTunnelProvider) Name() string { return "mock-tunnel" }

func (p *mockTunnelProvider) CreateTunnel(_ context.Context, cfg TunnelConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, mockCall{Method: "CreateTunnel", Args: []interface{}{cfg.TunnelID}})
	if p.createErr != nil {
		return p.createErr
	}
	p.tunnels[cfg.TunnelID] = true
	return nil
}

func (p *mockTunnelProvider) RemoveTunnel(tunnelID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, mockCall{Method: "RemoveTunnel", Args: []interface{}{tunnelID}})
	if p.removeErr != nil {
		return p.removeErr
	}
	delete(p.tunnels, tunnelID)
	return nil
}

func (p *mockTunnelProvider) TunnelStatus(tunnelID string) TunnelStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tunnels[tunnelID] {
		return TunnelStatus{TunnelID: tunnelID, Running: true}
	}
	return TunnelStatus{TunnelID: tunnelID}
}

func (p *mockTunnelProvider) ActiveTunnels() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for id := range p.tunnels {
		ids = append(ids, id)
	}
	return ids
}

func (p *mockTunnelProvider) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, mockCall{Method: "Stop"})
	return p.stopErr
}

func (p *mockTunnelProvider) callsFor(method string) []mockCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	var result []mockCall
	for _, c := range p.calls {
		if c.Method == method {
			result = append(result, c)
		}
	}
	return result
}

// Verify mockTunnelProvider satisfies TunnelProvider at compile time.
var _ TunnelProvider = (*mockTunnelProvider)(nil)

// ---------------------------------------------------------------------------
// SiteToSiteManager TunnelProvider delegation tests
// ---------------------------------------------------------------------------

func TestSiteToSiteManager_AddTunnel_ProviderDelegation(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	provider := newMockTunnelProvider()
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	providers := map[string]TunnelProvider{
		"ipsec": provider,
	}
	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), providers)

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	vpn.resetVPN()
	routes.reset()

	tunnel := api.SiteToSiteTunnel{
		TunnelID:       "t-ipsec-1",
		RemoteEndpoint: "203.0.113.1:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		PSK:            "shared-secret",
		ProviderType:   "ipsec",
	}
	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	// Verify provider.CreateTunnel was called.
	createCalls := provider.callsFor("CreateTunnel")
	if len(createCalls) != 1 {
		t.Fatalf("expected 1 CreateTunnel call, got %d", len(createCalls))
	}
	if createCalls[0].Args[0] != "t-ipsec-1" {
		t.Errorf("CreateTunnel tunnelID = %v, want t-ipsec-1", createCalls[0].Args[0])
	}

	// Verify NO VPNController calls were made.
	if len(vpn.vpnCallsFor("CreateTunnelInterface")) != 0 {
		t.Error("CreateTunnelInterface should not be called for provider-managed tunnel")
	}
	if len(vpn.vpnCallsFor("ConfigureTunnelPeer")) != 0 {
		t.Error("ConfigureTunnelPeer should not be called for provider-managed tunnel")
	}

	// Verify NO RouteController calls were made.
	if len(routes.callsFor("EnableForwarding")) != 0 {
		t.Error("EnableForwarding should not be called for provider-managed tunnel")
	}
	if len(routes.callsFor("AddRoute")) != 0 {
		t.Error("AddRoute should not be called for provider-managed tunnel")
	}

	// Verify tunnel is tracked.
	ids := mgr.TunnelIDs()
	if len(ids) != 1 || ids[0] != "t-ipsec-1" {
		t.Errorf("TunnelIDs = %v, want [t-ipsec-1]", ids)
	}

	// Verify GetTunnel returns the tunnel.
	got, ok := mgr.GetTunnel("t-ipsec-1")
	if !ok {
		t.Fatal("GetTunnel should return true for provider-managed tunnel")
	}
	if got.ProviderType != "ipsec" {
		t.Errorf("GetTunnel ProviderType = %q, want %q", got.ProviderType, "ipsec")
	}
}

func TestSiteToSiteManager_AddTunnel_ProviderNotFound(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	// No providers registered.
	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), nil)

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	tunnel := api.SiteToSiteTunnel{
		TunnelID:       "t-unknown-1",
		RemoteEndpoint: "203.0.113.1:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		ProviderType:   "unknown",
	}

	err := mgr.AddTunnel(tunnel)
	if err == nil {
		t.Fatal("AddTunnel should return error for unsupported provider type")
	}

	// Verify error message mentions the unsupported provider type.
	want := "unsupported provider type: unknown"
	if got := err.Error(); !contains(got, want) {
		t.Errorf("error = %q, want to contain %q", got, want)
	}

	// Verify no tunnel is tracked.
	if len(mgr.TunnelIDs()) != 0 {
		t.Error("no tunnel should be tracked after unsupported provider error")
	}
}

func TestSiteToSiteManager_AddTunnel_ProviderError(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	provider := newMockTunnelProvider()
	provider.createErr = fmt.Errorf("provider create failed")
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	providers := map[string]TunnelProvider{
		"ipsec": provider,
	}
	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), providers)

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	tunnel := api.SiteToSiteTunnel{
		TunnelID:       "t-fail-1",
		RemoteEndpoint: "203.0.113.1:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		ProviderType:   "ipsec",
	}

	err := mgr.AddTunnel(tunnel)
	if err == nil {
		t.Fatal("AddTunnel should return error when provider.CreateTunnel fails")
	}

	// Verify no tunnel is tracked.
	if len(mgr.TunnelIDs()) != 0 {
		t.Error("no tunnel should be tracked after provider create error")
	}

	// Verify NO VPNController calls were made.
	if len(vpn.vpnCallsFor("CreateTunnelInterface")) != 0 {
		t.Error("CreateTunnelInterface should not be called when provider fails")
	}
}

func TestSiteToSiteManager_RemoveTunnel_ProviderDelegation(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	provider := newMockTunnelProvider()
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	providers := map[string]TunnelProvider{
		"ipsec": provider,
	}
	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), providers)

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add a provider-managed tunnel.
	tunnel := api.SiteToSiteTunnel{
		TunnelID:       "t-ipsec-rm",
		RemoteEndpoint: "203.0.113.1:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		ProviderType:   "ipsec",
	}
	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}
	vpn.resetVPN()
	routes.reset()

	// Remove the tunnel.
	mgr.RemoveTunnel("t-ipsec-rm")

	// Verify provider.RemoveTunnel was called.
	removeCalls := provider.callsFor("RemoveTunnel")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemoveTunnel call, got %d", len(removeCalls))
	}
	if removeCalls[0].Args[0] != "t-ipsec-rm" {
		t.Errorf("RemoveTunnel tunnelID = %v, want t-ipsec-rm", removeCalls[0].Args[0])
	}

	// Verify NO VPNController calls were made.
	if len(vpn.vpnCallsFor("RemoveTunnelInterface")) != 0 {
		t.Error("RemoveTunnelInterface should not be called for provider-managed tunnel")
	}
	if len(vpn.vpnCallsFor("RemoveTunnelPeer")) != 0 {
		t.Error("RemoveTunnelPeer should not be called for provider-managed tunnel")
	}

	// Verify NO RouteController calls were made.
	if len(routes.callsFor("RemoveRoute")) != 0 {
		t.Error("RemoveRoute should not be called for provider-managed tunnel")
	}
	if len(routes.callsFor("DisableForwarding")) != 0 {
		t.Error("DisableForwarding should not be called for provider-managed tunnel")
	}

	// Verify tunnel is no longer tracked.
	if ids := mgr.TunnelIDs(); len(ids) != 0 {
		t.Errorf("TunnelIDs = %v, want empty", ids)
	}
}

func TestSiteToSiteManager_Teardown_StopsProviders(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	provider := newMockTunnelProvider()
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	providers := map[string]TunnelProvider{
		"ipsec": provider,
	}
	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), providers)

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add a provider-managed tunnel.
	tunnel := api.SiteToSiteTunnel{
		TunnelID:       "t-ipsec-td",
		RemoteEndpoint: "203.0.113.1:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		ProviderType:   "ipsec",
	}
	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// Verify provider.RemoveTunnel was called for the active tunnel.
	removeCalls := provider.callsFor("RemoveTunnel")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemoveTunnel call, got %d", len(removeCalls))
	}
	if removeCalls[0].Args[0] != "t-ipsec-td" {
		t.Errorf("RemoveTunnel tunnelID = %v, want t-ipsec-td", removeCalls[0].Args[0])
	}

	// Verify provider.Stop was called.
	stopCalls := provider.callsFor("Stop")
	if len(stopCalls) != 1 {
		t.Fatalf("expected 1 Stop call, got %d", len(stopCalls))
	}

	// Verify manager is inactive.
	if mgr.SiteToSiteStatus() != nil {
		t.Error("SiteToSiteStatus should be nil after teardown")
	}
}

func TestSiteToSiteManager_SiteToSiteStatus_WithProviders(t *testing.T) {
	vpn := &mockVPNController{}
	routes := &mockRouteController{}
	ipsecProvider := newMockTunnelProvider()
	openvpnProvider := newMockTunnelProvider()
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	providers := map[string]TunnelProvider{
		"openvpn": openvpnProvider,
		"ipsec":   ipsecProvider,
	}
	mgr := NewSiteToSiteManager(vpn, routes, cfg, discardLogger(), providers)

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

	// Verify TunnelProviderNames is populated and sorted.
	if len(status.TunnelProviderNames) != 2 {
		t.Fatalf("TunnelProviderNames count = %d, want 2", len(status.TunnelProviderNames))
	}
	if status.TunnelProviderNames[0] != "ipsec" {
		t.Errorf("TunnelProviderNames[0] = %q, want %q", status.TunnelProviderNames[0], "ipsec")
	}
	if status.TunnelProviderNames[1] != "openvpn" {
		t.Errorf("TunnelProviderNames[1] = %q, want %q", status.TunnelProviderNames[1], "openvpn")
	}
}

// contains reports whether s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// SiteToSiteManager kernel interface name tests
// ---------------------------------------------------------------------------

// namerVPNController is a mockVPNController that also reports kernel interface
// names, the way the macOS bridge controller does.
type namerVPNController struct {
	*mockVPNController
	names map[string]string
}

func (c *namerVPNController) OSInterfaceName(name string) (string, bool) {
	osName, ok := c.names[name]
	return osName, ok
}

var _ wireguard.OSInterfaceNamer = (*namerVPNController)(nil)

// newUtunNamer returns a VPN controller that resolves wg-s2s-0 to utun9.
func newUtunNamer() *namerVPNController {
	return &namerVPNController{
		mockVPNController: &mockVPNController{},
		names:             map[string]string{"wg-s2s-0": "utun9"},
	}
}

// newActiveS2SManager returns a manager set up on mesh interface wg0 over vpn,
// its route controller, and the buffer its debug logger writes to.
func newActiveS2SManager(t *testing.T, vpn VPNController) (*SiteToSiteManager, *mockRouteController, *bytes.Buffer) {
	t.Helper()

	routes := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	logger, buf := debugLogger()
	mgr := NewSiteToSiteManager(vpn, routes, cfg, logger, nil)
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return mgr, routes, buf
}

// kernelNameTunnel returns the tunnel the kernel name tests add, carrying the
// given remote subnets.
func kernelNameTunnel(subnets ...string) api.SiteToSiteTunnel {
	return api.SiteToSiteTunnel{
		TunnelID:        "t-1",
		RemoteEndpoint:  "1.2.3.4:51823",
		RemotePublicKey: "rpk-1",
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   subnets,
		InterfaceName:   "wg-s2s-0",
		ListenPort:      51823,
	}
}

// onlyRouteCall returns the single recorded call to method on routes.
func onlyRouteCall(t *testing.T, routes *mockRouteController, method string) mockCall {
	t.Helper()
	calls := routes.callsFor(method)
	if len(calls) != 1 {
		t.Fatalf("%s calls = %d, want 1", method, len(calls))
	}
	return calls[0]
}

// onlyVPNCall returns the single recorded call to method on vpn.
func onlyVPNCall(t *testing.T, vpn *mockVPNController, method string) mockVPNCall {
	t.Helper()
	calls := vpn.vpnCallsFor(method)
	if len(calls) != 1 {
		t.Fatalf("%s calls = %d, want 1", method, len(calls))
	}
	return calls[0]
}

func TestSiteToSiteManager_AddTunnel_ResolvesKernelName(t *testing.T) {
	vpn := newUtunNamer()
	mgr, routes, buf := newActiveS2SManager(t, vpn)

	if err := mgr.AddTunnel(kernelNameTunnel("10.1.0.0/24")); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	// The route controller sees the name the kernel gave the interface.
	fwd := onlyRouteCall(t, routes, "EnableForwarding")
	if fwd.Args[0] != "utun9" || fwd.Args[1] != "wg0" {
		t.Errorf("EnableForwarding args = %v, want [utun9 wg0]", fwd.Args)
	}
	add := onlyRouteCall(t, routes, "AddRoute")
	if add.Args[0] != "10.1.0.0/24" || add.Args[1] != "utun9" {
		t.Errorf("AddRoute args = %v, want [10.1.0.0/24 utun9]", add.Args)
	}

	// The VPN controller keeps the configured name.
	create := onlyVPNCall(t, vpn.mockVPNController, "CreateTunnelInterface")
	if create.Args[0] != "wg-s2s-0" {
		t.Errorf("CreateTunnelInterface iface = %v, want wg-s2s-0", create.Args[0])
	}
	configure := onlyVPNCall(t, vpn.mockVPNController, "ConfigureTunnelPeer")
	if configure.Args[0] != "wg-s2s-0" {
		t.Errorf("ConfigureTunnelPeer iface = %v, want wg-s2s-0", configure.Args[0])
	}

	logged := buf.String()
	for _, want := range []string{
		"level=DEBUG",
		`msg="tunnel interface resolved"`,
		"tunnel_id=t-1",
		"interface=wg-s2s-0",
		"os_interface=utun9",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("log = %q, want it to contain %q", logged, want)
		}
	}
}

func TestSiteToSiteManager_AddTunnel_AddRouteError_KernelName(t *testing.T) {
	vpn := newUtunNamer()
	mgr, routes, _ := newActiveS2SManager(t, vpn)
	// Fail on the second subnet so the first one has to be rolled back.
	routes.addRouteErrFor = map[string]error{
		"10.2.0.0/24": fmt.Errorf("add route error"),
	}

	if err := mgr.AddTunnel(kernelNameTunnel("10.1.0.0/24", "10.2.0.0/24")); err == nil {
		t.Fatal("AddTunnel should return an error when AddRoute fails")
	}

	remove := onlyRouteCall(t, routes, "RemoveRoute")
	if remove.Args[0] != "10.1.0.0/24" || remove.Args[1] != "utun9" {
		t.Errorf("RemoveRoute args = %v, want [10.1.0.0/24 utun9]", remove.Args)
	}
	disable := onlyRouteCall(t, routes, "DisableForwarding")
	if disable.Args[0] != "utun9" || disable.Args[1] != "wg0" {
		t.Errorf("DisableForwarding args = %v, want [utun9 wg0]", disable.Args)
	}

	removePeer := onlyVPNCall(t, vpn.mockVPNController, "RemoveTunnelPeer")
	if removePeer.Args[0] != "wg-s2s-0" {
		t.Errorf("RemoveTunnelPeer iface = %v, want wg-s2s-0", removePeer.Args[0])
	}
	removeIface := onlyVPNCall(t, vpn.mockVPNController, "RemoveTunnelInterface")
	if removeIface.Args[0] != "wg-s2s-0" {
		t.Errorf("RemoveTunnelInterface iface = %v, want wg-s2s-0", removeIface.Args[0])
	}
}

func TestSiteToSiteManager_RemoveTunnel_KernelName(t *testing.T) {
	vpn := newUtunNamer()
	mgr, routes, _ := newActiveS2SManager(t, vpn)

	if err := mgr.AddTunnel(kernelNameTunnel("10.1.0.0/24")); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}
	vpn.resetVPN()
	routes.reset()

	mgr.RemoveTunnel("t-1")

	remove := onlyRouteCall(t, routes, "RemoveRoute")
	if remove.Args[0] != "10.1.0.0/24" || remove.Args[1] != "utun9" {
		t.Errorf("RemoveRoute args = %v, want [10.1.0.0/24 utun9]", remove.Args)
	}
	disable := onlyRouteCall(t, routes, "DisableForwarding")
	if disable.Args[0] != "utun9" || disable.Args[1] != "wg0" {
		t.Errorf("DisableForwarding args = %v, want [utun9 wg0]", disable.Args)
	}

	removePeer := onlyVPNCall(t, vpn.mockVPNController, "RemoveTunnelPeer")
	if removePeer.Args[0] != "wg-s2s-0" {
		t.Errorf("RemoveTunnelPeer iface = %v, want wg-s2s-0", removePeer.Args[0])
	}
	removeIface := onlyVPNCall(t, vpn.mockVPNController, "RemoveTunnelInterface")
	if removeIface.Args[0] != "wg-s2s-0" {
		t.Errorf("RemoveTunnelInterface iface = %v, want wg-s2s-0", removeIface.Args[0])
	}
}

func TestSiteToSiteManager_Teardown_KernelName(t *testing.T) {
	vpn := newUtunNamer()
	mgr, routes, _ := newActiveS2SManager(t, vpn)

	if err := mgr.AddTunnel(kernelNameTunnel("10.1.0.0/24")); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}
	vpn.resetVPN()
	routes.reset()

	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	remove := onlyRouteCall(t, routes, "RemoveRoute")
	if remove.Args[0] != "10.1.0.0/24" || remove.Args[1] != "utun9" {
		t.Errorf("RemoveRoute args = %v, want [10.1.0.0/24 utun9]", remove.Args)
	}
	disable := onlyRouteCall(t, routes, "DisableForwarding")
	if disable.Args[0] != "utun9" || disable.Args[1] != "wg0" {
		t.Errorf("DisableForwarding args = %v, want [utun9 wg0]", disable.Args)
	}

	// Teardown drops the whole interface and never touches the peer.
	removeIface := onlyVPNCall(t, vpn.mockVPNController, "RemoveTunnelInterface")
	if removeIface.Args[0] != "wg-s2s-0" {
		t.Errorf("RemoveTunnelInterface iface = %v, want wg-s2s-0", removeIface.Args[0])
	}
}

func TestSiteToSiteManager_AddTunnel_NamerUnresolved(t *testing.T) {
	tests := []struct {
		name string
		vpn  VPNController
	}{
		{
			name: "namer without a match",
			vpn: &namerVPNController{
				mockVPNController: &mockVPNController{},
				names:             map[string]string{},
			},
		},
		{
			name: "controller is no namer",
			vpn:  &mockVPNController{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, routes, buf := newActiveS2SManager(t, tt.vpn)

			if err := mgr.AddTunnel(kernelNameTunnel("10.1.0.0/24")); err != nil {
				t.Fatalf("AddTunnel: %v", err)
			}

			fwd := onlyRouteCall(t, routes, "EnableForwarding")
			if fwd.Args[0] != "wg-s2s-0" || fwd.Args[1] != "wg0" {
				t.Errorf("EnableForwarding args = %v, want [wg-s2s-0 wg0]", fwd.Args)
			}
			add := onlyRouteCall(t, routes, "AddRoute")
			if add.Args[0] != "10.1.0.0/24" || add.Args[1] != "wg-s2s-0" {
				t.Errorf("AddRoute args = %v, want [10.1.0.0/24 wg-s2s-0]", add.Args)
			}

			if logged := buf.String(); strings.Contains(logged, "tunnel interface resolved") {
				t.Errorf("log = %q, want no resolved line for the configured name", logged)
			}
		})
	}
}
