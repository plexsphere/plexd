package bridge

import (
	"context"
	"errors"
	"strings"
	"testing"
)

var _ TunnelProvider = (*OpenVPNProvider)(nil)

// newTestOpenVPNProvider creates an OpenVPNProvider with configDir set to a temp directory.
func newTestOpenVPNProvider(t *testing.T, exec CommandExecutor, routes RouteController) *OpenVPNProvider {
	t.Helper()
	p := NewOpenVPNProvider(exec, routes, discardLogger())
	p.configDir = t.TempDir()
	return p
}

func TestOpenVPNProvider_ImplementsInterface(t *testing.T) {
	var p TunnelProvider = NewOpenVPNProvider(newMockCommandExecutor(), &mockRouteController{}, discardLogger())
	if p.Name() != "openvpn" {
		t.Fatalf("expected name %q, got %q", "openvpn", p.Name())
	}
}

func TestOpenVPNProvider_Name(t *testing.T) {
	p := NewOpenVPNProvider(newMockCommandExecutor(), &mockRouteController{}, discardLogger())
	if got := p.Name(); got != "openvpn" {
		t.Fatalf("Name() = %q, want %q", got, "openvpn")
	}
}

func TestOpenVPNProvider_CreateTunnel_Success(t *testing.T) {
	handle := &mockCommandHandle{}
	exec := newMockCommandExecutor()
	exec.startHandle = handle
	routes := &mockRouteController{}
	p := newTestOpenVPNProvider(t, exec, routes)

	cfg := TunnelConfig{
		TunnelID:       "tun1",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24", "10.2.0.0/24"},
		RemoteEndpoint: "203.0.113.1:1194",
		PSK:            "secret123",
	}

	if err := p.CreateTunnel(context.Background(), cfg); err != nil {
		t.Fatalf("CreateTunnel() error: %v", err)
	}

	// Verify routes were added.
	addCalls := routes.callsFor("AddRoute")
	if len(addCalls) != 2 {
		t.Fatalf("expected 2 AddRoute calls, got %d", len(addCalls))
	}
	if addCalls[0].Args[0] != "10.1.0.0/24" || addCalls[0].Args[1] != "tun-tun1" {
		t.Errorf("AddRoute[0] = %v, want (10.1.0.0/24, tun-tun1)", addCalls[0].Args)
	}
	if addCalls[1].Args[0] != "10.2.0.0/24" || addCalls[1].Args[1] != "tun-tun1" {
		t.Errorf("AddRoute[1] = %v, want (10.2.0.0/24, tun-tun1)", addCalls[1].Args)
	}

	// Verify tunnel status.
	status := p.TunnelStatus("tun1")
	if !status.Running {
		t.Error("expected tunnel to be running")
	}
	if status.InterfaceName != "tun-tun1" {
		t.Errorf("InterfaceName = %q, want %q", status.InterfaceName, "tun-tun1")
	}
}

func TestOpenVPNProvider_CreateTunnel_Duplicate(t *testing.T) {
	exec := newMockCommandExecutor()
	exec.startHandle = &mockCommandHandle{}
	p := newTestOpenVPNProvider(t, exec, &mockRouteController{})

	cfg := TunnelConfig{
		TunnelID:       "tun1",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		RemoteEndpoint: "203.0.113.1:1194",
		PSK:            "secret",
	}

	if err := p.CreateTunnel(context.Background(), cfg); err != nil {
		t.Fatalf("first CreateTunnel() error: %v", err)
	}

	err := p.CreateTunnel(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for duplicate tunnel, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "already exists") {
		t.Errorf("error = %q, want substring %q", got, "already exists")
	}
}

func TestOpenVPNProvider_CreateTunnel_StartError(t *testing.T) {
	startErr := errors.New("openvpn start failed")
	exec := newMockCommandExecutor()
	exec.startErr = startErr
	p := newTestOpenVPNProvider(t, exec, &mockRouteController{})

	cfg := TunnelConfig{
		TunnelID:       "tun1",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		RemoteEndpoint: "203.0.113.1:1194",
		PSK:            "secret",
	}

	err := p.CreateTunnel(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, startErr) {
		t.Errorf("error = %v, want wrapped %v", err, startErr)
	}

	// Tunnel should not be tracked.
	if len(p.ActiveTunnels()) != 0 {
		t.Error("expected no active tunnels after start error")
	}
}

func TestOpenVPNProvider_CreateTunnel_RouteError(t *testing.T) {
	routeErr := errors.New("route add failed")
	handle := &mockCommandHandle{}
	exec := newMockCommandExecutor()
	exec.startHandle = handle
	routes := &mockRouteController{
		addRouteErrFor: map[string]error{
			"10.2.0.0/24": routeErr, // second subnet fails
		},
	}
	p := newTestOpenVPNProvider(t, exec, routes)

	cfg := TunnelConfig{
		TunnelID:       "tun1",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24", "10.2.0.0/24"},
		RemoteEndpoint: "203.0.113.1:1194",
		PSK:            "secret",
	}

	err := p.CreateTunnel(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, routeErr) {
		t.Errorf("error = %v, want wrapped %v", err, routeErr)
	}

	// Verify rollback: first route was removed.
	removeCalls := routes.callsFor("RemoveRoute")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemoveRoute rollback call, got %d", len(removeCalls))
	}
	if removeCalls[0].Args[0] != "10.1.0.0/24" {
		t.Errorf("RemoveRoute[0] subnet = %v, want 10.1.0.0/24", removeCalls[0].Args[0])
	}

	// Tunnel should not be tracked.
	if len(p.ActiveTunnels()) != 0 {
		t.Error("expected no active tunnels after route error")
	}
}

func TestOpenVPNProvider_RemoveTunnel_Success(t *testing.T) {
	handle := &mockCommandHandle{}
	exec := newMockCommandExecutor()
	exec.startHandle = handle
	routes := &mockRouteController{}
	p := newTestOpenVPNProvider(t, exec, routes)

	cfg := TunnelConfig{
		TunnelID:       "tun1",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		RemoteEndpoint: "203.0.113.1:1194",
		PSK:            "secret",
	}

	if err := p.CreateTunnel(context.Background(), cfg); err != nil {
		t.Fatalf("CreateTunnel() error: %v", err)
	}

	if err := p.RemoveTunnel("tun1"); err != nil {
		t.Fatalf("RemoveTunnel() error: %v", err)
	}

	// Verify route removal.
	removeCalls := routes.callsFor("RemoveRoute")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemoveRoute call, got %d", len(removeCalls))
	}

	// Verify tunnel is gone.
	status := p.TunnelStatus("tun1")
	if status.Running {
		t.Error("expected tunnel to not be running after removal")
	}
}

func TestOpenVPNProvider_RemoveTunnel_Idempotent(t *testing.T) {
	p := NewOpenVPNProvider(newMockCommandExecutor(), &mockRouteController{}, discardLogger())

	// Removing a non-existent tunnel should not error.
	if err := p.RemoveTunnel("nonexistent"); err != nil {
		t.Fatalf("RemoveTunnel(nonexistent) error: %v", err)
	}
}

func TestOpenVPNProvider_TunnelStatus_Active(t *testing.T) {
	exec := newMockCommandExecutor()
	exec.startHandle = &mockCommandHandle{}
	p := newTestOpenVPNProvider(t, exec, &mockRouteController{})

	cfg := TunnelConfig{
		TunnelID:       "active1",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		RemoteEndpoint: "203.0.113.1:1194",
		PSK:            "secret",
	}

	if err := p.CreateTunnel(context.Background(), cfg); err != nil {
		t.Fatalf("CreateTunnel() error: %v", err)
	}

	status := p.TunnelStatus("active1")
	if !status.Running {
		t.Error("expected Running=true")
	}
	if status.TunnelID != "active1" {
		t.Errorf("TunnelID = %q, want %q", status.TunnelID, "active1")
	}
	if status.InterfaceName != "tun-active1" {
		t.Errorf("InterfaceName = %q, want %q", status.InterfaceName, "tun-active1")
	}
}

func TestOpenVPNProvider_TunnelStatus_NotFound(t *testing.T) {
	p := NewOpenVPNProvider(newMockCommandExecutor(), &mockRouteController{}, discardLogger())

	status := p.TunnelStatus("missing")
	if status.Running {
		t.Error("expected Running=false for missing tunnel")
	}
	if status.TunnelID != "missing" {
		t.Errorf("TunnelID = %q, want %q", status.TunnelID, "missing")
	}
	if status.InterfaceName != "" {
		t.Errorf("InterfaceName = %q, want empty", status.InterfaceName)
	}
}

func TestOpenVPNProvider_ActiveTunnels(t *testing.T) {
	exec := newMockCommandExecutor()
	exec.startHandle = &mockCommandHandle{}
	p := newTestOpenVPNProvider(t, exec, &mockRouteController{})

	for _, id := range []string{"tun-b", "tun-a"} {
		cfg := TunnelConfig{
			TunnelID:       id,
			LocalSubnets:   []string{"10.0.0.0/24"},
			RemoteSubnets:  []string{"10.1.0.0/24"},
			RemoteEndpoint: "203.0.113.1:1194",
			PSK:            "secret",
		}
		if err := p.CreateTunnel(context.Background(), cfg); err != nil {
			t.Fatalf("CreateTunnel(%s) error: %v", id, err)
		}
	}

	active := p.ActiveTunnels()
	if len(active) != 2 {
		t.Fatalf("ActiveTunnels() len = %d, want 2", len(active))
	}
	// Sorted order.
	if active[0] != "tun-a" || active[1] != "tun-b" {
		t.Errorf("ActiveTunnels() = %v, want [tun-a tun-b]", active)
	}
}

func TestOpenVPNProvider_Stop(t *testing.T) {
	exec := newMockCommandExecutor()
	exec.startHandle = &mockCommandHandle{}
	routes := &mockRouteController{}
	p := newTestOpenVPNProvider(t, exec, routes)

	for _, id := range []string{"tun1", "tun2"} {
		cfg := TunnelConfig{
			TunnelID:       id,
			LocalSubnets:   []string{"10.0.0.0/24"},
			RemoteSubnets:  []string{"10.1.0.0/24"},
			RemoteEndpoint: "203.0.113.1:1194",
			PSK:            "secret",
		}
		if err := p.CreateTunnel(context.Background(), cfg); err != nil {
			t.Fatalf("CreateTunnel(%s) error: %v", id, err)
		}
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	if len(p.ActiveTunnels()) != 0 {
		t.Error("expected no active tunnels after Stop")
	}

	// Stop is idempotent.
	if err := p.Stop(); err != nil {
		t.Fatalf("second Stop() error: %v", err)
	}
}
