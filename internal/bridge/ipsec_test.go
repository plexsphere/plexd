package bridge

import (
	"context"
	"errors"
	"strings"
	"testing"
)

var _ TunnelProvider = (*IPsecProvider)(nil)

// newTestIPsecProvider creates an IPsecProvider with configDir set to a temp directory.
func newTestIPsecProvider(t *testing.T, exec CommandExecutor, routes RouteController) *IPsecProvider {
	t.Helper()
	p := NewIPsecProvider(exec, routes, discardLogger())
	p.configDir = t.TempDir()
	return p
}

func TestIPsecProvider_ImplementsInterface(t *testing.T) {
	// Compile-time check is above; this test exists for clarity.
	var p TunnelProvider = NewIPsecProvider(newMockCommandExecutor(), &mockRouteController{}, discardLogger())
	if p.Name() != "ipsec" {
		t.Fatalf("expected name %q, got %q", "ipsec", p.Name())
	}
}

func TestIPsecProvider_Name(t *testing.T) {
	p := NewIPsecProvider(newMockCommandExecutor(), &mockRouteController{}, discardLogger())
	if got := p.Name(); got != "ipsec" {
		t.Fatalf("Name() = %q, want %q", got, "ipsec")
	}
}

func TestIPsecProvider_CreateTunnel_Success(t *testing.T) {
	exec := newMockCommandExecutor()
	routes := &mockRouteController{}
	p := newTestIPsecProvider(t, exec, routes)

	cfg := TunnelConfig{
		TunnelID:       "tun1",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24", "10.2.0.0/24"},
		RemoteEndpoint: "203.0.113.1",
		PSK:            "secret123",
	}

	if err := p.CreateTunnel(context.Background(), cfg); err != nil {
		t.Fatalf("CreateTunnel() error: %v", err)
	}

	// Verify exec calls.
	calls := exec.allCalls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 exec calls, got %d", len(calls))
	}
	if calls[0].Name != "swanctl" || calls[0].Args[0] != "--load-conns" {
		t.Errorf("call[0] = %v %v, want swanctl --load-conns ...", calls[0].Name, calls[0].Args)
	}
	if calls[1].Name != "swanctl" || calls[1].Args[0] != "--initiate" {
		t.Errorf("call[1] = %v %v, want swanctl --initiate ...", calls[1].Name, calls[1].Args)
	}

	// Verify routes were added.
	addCalls := routes.callsFor("AddRoute")
	if len(addCalls) != 2 {
		t.Fatalf("expected 2 AddRoute calls, got %d", len(addCalls))
	}
	if addCalls[0].Args[0] != "10.1.0.0/24" || addCalls[0].Args[1] != "ipsec-tun1" {
		t.Errorf("AddRoute[0] = %v, want (10.1.0.0/24, ipsec-tun1)", addCalls[0].Args)
	}
	if addCalls[1].Args[0] != "10.2.0.0/24" || addCalls[1].Args[1] != "ipsec-tun1" {
		t.Errorf("AddRoute[1] = %v, want (10.2.0.0/24, ipsec-tun1)", addCalls[1].Args)
	}

	// Verify tunnel status.
	status := p.TunnelStatus("tun1")
	if !status.Running {
		t.Error("expected tunnel to be running")
	}
	if status.InterfaceName != "ipsec-tun1" {
		t.Errorf("InterfaceName = %q, want %q", status.InterfaceName, "ipsec-tun1")
	}
}

func TestIPsecProvider_CreateTunnel_Duplicate(t *testing.T) {
	exec := newMockCommandExecutor()
	p := newTestIPsecProvider(t, exec, &mockRouteController{})

	cfg := TunnelConfig{
		TunnelID:       "tun1",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		RemoteEndpoint: "203.0.113.1",
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

func TestIPsecProvider_CreateTunnel_LoadConnsError(t *testing.T) {
	loadErr := errors.New("swanctl load failed")
	exec := newMockCommandExecutor()
	p := newTestIPsecProvider(t, exec, &mockRouteController{})
	// Inject error for swanctl --load-conns using the provider's config dir.
	exec.runErrors[commandKey("swanctl", "--load-conns", "--file", p.configDir+"/plexd-ipsec-tun1.conf")] = loadErr

	cfg := TunnelConfig{
		TunnelID:       "tun1",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		RemoteEndpoint: "203.0.113.1",
		PSK:            "secret",
	}

	err := p.CreateTunnel(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, loadErr) {
		t.Errorf("error = %v, want wrapped %v", err, loadErr)
	}

	// Tunnel should not be tracked.
	if len(p.ActiveTunnels()) != 0 {
		t.Error("expected no active tunnels after load error")
	}
}

func TestIPsecProvider_CreateTunnel_InitiateError(t *testing.T) {
	initErr := errors.New("swanctl initiate failed")
	exec := newMockCommandExecutor()
	exec.runErrors[commandKey("swanctl", "--initiate", "--child", "tun1")] = initErr

	p := newTestIPsecProvider(t, exec, &mockRouteController{})

	cfg := TunnelConfig{
		TunnelID:       "tun1",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		RemoteEndpoint: "203.0.113.1",
		PSK:            "secret",
	}

	err := p.CreateTunnel(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, initErr) {
		t.Errorf("error = %v, want wrapped %v", err, initErr)
	}

	// Verify rollback: terminate was called.
	calls := exec.allCalls()
	foundTerminate := false
	for _, c := range calls {
		if c.Name == "swanctl" && len(c.Args) > 0 && c.Args[0] == "--terminate" {
			foundTerminate = true
			break
		}
	}
	if !foundTerminate {
		t.Error("expected swanctl --terminate rollback call")
	}

	// Tunnel should not be tracked.
	if len(p.ActiveTunnels()) != 0 {
		t.Error("expected no active tunnels after initiate error")
	}
}

func TestIPsecProvider_RemoveTunnel_Success(t *testing.T) {
	exec := newMockCommandExecutor()
	routes := &mockRouteController{}
	p := newTestIPsecProvider(t, exec, routes)

	cfg := TunnelConfig{
		TunnelID:       "tun1",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		RemoteEndpoint: "203.0.113.1",
		PSK:            "secret",
	}

	if err := p.CreateTunnel(context.Background(), cfg); err != nil {
		t.Fatalf("CreateTunnel() error: %v", err)
	}

	if err := p.RemoveTunnel("tun1"); err != nil {
		t.Fatalf("RemoveTunnel() error: %v", err)
	}

	// Verify terminate was called.
	calls := exec.allCalls()
	lastCall := calls[len(calls)-1]
	if lastCall.Name != "swanctl" || lastCall.Args[0] != "--terminate" {
		t.Errorf("last call = %v %v, want swanctl --terminate ...", lastCall.Name, lastCall.Args)
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

func TestIPsecProvider_RemoveTunnel_Idempotent(t *testing.T) {
	p := NewIPsecProvider(newMockCommandExecutor(), &mockRouteController{}, discardLogger())

	// Removing a non-existent tunnel should not error.
	if err := p.RemoveTunnel("nonexistent"); err != nil {
		t.Fatalf("RemoveTunnel(nonexistent) error: %v", err)
	}
}

func TestIPsecProvider_TunnelStatus_Active(t *testing.T) {
	exec := newMockCommandExecutor()
	p := newTestIPsecProvider(t, exec, &mockRouteController{})

	cfg := TunnelConfig{
		TunnelID:       "active1",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		RemoteEndpoint: "203.0.113.1",
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
	if status.InterfaceName != "ipsec-active1" {
		t.Errorf("InterfaceName = %q, want %q", status.InterfaceName, "ipsec-active1")
	}
}

func TestIPsecProvider_TunnelStatus_NotFound(t *testing.T) {
	p := NewIPsecProvider(newMockCommandExecutor(), &mockRouteController{}, discardLogger())

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

func TestIPsecProvider_ActiveTunnels(t *testing.T) {
	exec := newMockCommandExecutor()
	p := newTestIPsecProvider(t, exec, &mockRouteController{})

	for _, id := range []string{"tun-b", "tun-a"} {
		cfg := TunnelConfig{
			TunnelID:       id,
			LocalSubnets:   []string{"10.0.0.0/24"},
			RemoteSubnets:  []string{"10.1.0.0/24"},
			RemoteEndpoint: "203.0.113.1",
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

func TestIPsecProvider_Stop(t *testing.T) {
	exec := newMockCommandExecutor()
	routes := &mockRouteController{}
	p := newTestIPsecProvider(t, exec, routes)

	for _, id := range []string{"tun1", "tun2"} {
		cfg := TunnelConfig{
			TunnelID:       id,
			LocalSubnets:   []string{"10.0.0.0/24"},
			RemoteSubnets:  []string{"10.1.0.0/24"},
			RemoteEndpoint: "203.0.113.1",
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
