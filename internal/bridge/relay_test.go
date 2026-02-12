package bridge

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

func newTestUDPConn(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func startTestRelay(t *testing.T, maxSessions int, sessionTTL time.Duration) *Relay {
	t.Helper()
	relay := NewRelay(0, maxSessions, sessionTTL, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := relay.Start(ctx); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(func() { relay.Stop() })
	return relay
}

func TestRelaySession_ForwardAtoB(t *testing.T) {
	relay := startTestRelay(t, 100, 5*time.Minute)

	peerA := newTestUDPConn(t)
	peerB := newTestUDPConn(t)

	assignment := api.RelaySessionAssignment{
		SessionID:     "sess-1",
		PeerAEndpoint: peerA.LocalAddr().String(),
		PeerBEndpoint: peerB.LocalAddr().String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	if err := relay.AddSession(assignment); err != nil {
		t.Fatalf("AddSession: %v", err)
	}

	relayAddr, err := net.ResolveUDPAddr("udp", relay.ListenAddr().String())
	if err != nil {
		t.Fatalf("resolve relay addr: %v", err)
	}
	msg := []byte("hello from A")
	if _, err := peerA.WriteToUDP(msg, relayAddr); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1024)
	peerB.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peerB.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hello from A" {
		t.Errorf("got %q, want %q", string(buf[:n]), "hello from A")
	}
}

func TestRelaySession_ForwardBtoA(t *testing.T) {
	relay := startTestRelay(t, 100, 5*time.Minute)

	peerA := newTestUDPConn(t)
	peerB := newTestUDPConn(t)

	assignment := api.RelaySessionAssignment{
		SessionID:     "sess-1",
		PeerAEndpoint: peerA.LocalAddr().String(),
		PeerBEndpoint: peerB.LocalAddr().String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	if err := relay.AddSession(assignment); err != nil {
		t.Fatalf("AddSession: %v", err)
	}

	relayAddr, err := net.ResolveUDPAddr("udp", relay.ListenAddr().String())
	if err != nil {
		t.Fatalf("resolve relay addr: %v", err)
	}
	msg := []byte("hello from B")
	if _, err := peerB.WriteToUDP(msg, relayAddr); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1024)
	peerA.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peerA.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hello from B" {
		t.Errorf("got %q, want %q", string(buf[:n]), "hello from B")
	}
}

func TestRelaySession_DropUnknownSource(t *testing.T) {
	relay := startTestRelay(t, 100, 5*time.Minute)

	peerA := newTestUDPConn(t)
	peerB := newTestUDPConn(t)
	unknown := newTestUDPConn(t)

	assignment := api.RelaySessionAssignment{
		SessionID:     "sess-1",
		PeerAEndpoint: peerA.LocalAddr().String(),
		PeerBEndpoint: peerB.LocalAddr().String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	if err := relay.AddSession(assignment); err != nil {
		t.Fatalf("AddSession: %v", err)
	}

	relayAddr, err := net.ResolveUDPAddr("udp", relay.ListenAddr().String())
	if err != nil {
		t.Fatalf("resolve relay addr: %v", err)
	}

	if _, err := unknown.WriteToUDP([]byte("unknown"), relayAddr); err != nil {
		t.Fatalf("write: %v", err)
	}

	peerA.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1024)
	_, _, err = peerA.ReadFromUDP(buf)
	if err == nil {
		t.Error("peer A should not receive packet from unknown source")
	}

	peerB.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err = peerB.ReadFromUDP(buf)
	if err == nil {
		t.Error("peer B should not receive packet from unknown source")
	}
}

func TestRelaySession_CloseIdempotent(t *testing.T) {
	session := &RelaySession{
		SessionID: "sess-1",
		logger:    discardLogger(),
	}

	if err := session.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestRelay_Start_And_Stop(t *testing.T) {
	relay := NewRelay(0, 100, 5*time.Minute, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := relay.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if relay.ListenAddr() == nil {
		t.Fatal("ListenAddr should not be nil after Start")
	}

	if err := relay.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if err := relay.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestRelay_AddSession(t *testing.T) {
	relay := startTestRelay(t, 100, 5*time.Minute)

	peerA := newTestUDPConn(t)
	peerB := newTestUDPConn(t)

	assignment := api.RelaySessionAssignment{
		SessionID:     "sess-1",
		PeerAEndpoint: peerA.LocalAddr().String(),
		PeerBEndpoint: peerB.LocalAddr().String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	if err := relay.AddSession(assignment); err != nil {
		t.Fatalf("AddSession: %v", err)
	}

	if relay.ActiveCount() != 1 {
		t.Errorf("ActiveCount = %d, want 1", relay.ActiveCount())
	}

	ids := relay.SessionIDs()
	if len(ids) != 1 || ids[0] != "sess-1" {
		t.Errorf("SessionIDs = %v, want [sess-1]", ids)
	}
}

func TestRelay_AddSession_Duplicate(t *testing.T) {
	relay := startTestRelay(t, 100, 5*time.Minute)

	peerA := newTestUDPConn(t)
	peerB := newTestUDPConn(t)

	assignment := api.RelaySessionAssignment{
		SessionID:     "sess-1",
		PeerAEndpoint: peerA.LocalAddr().String(),
		PeerBEndpoint: peerB.LocalAddr().String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	if err := relay.AddSession(assignment); err != nil {
		t.Fatalf("first AddSession: %v", err)
	}

	peerC := newTestUDPConn(t)
	peerD := newTestUDPConn(t)
	dup := api.RelaySessionAssignment{
		SessionID:     "sess-1",
		PeerAEndpoint: peerC.LocalAddr().String(),
		PeerBEndpoint: peerD.LocalAddr().String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	err := relay.AddSession(dup)
	if err == nil {
		t.Fatal("AddSession should return error for duplicate session ID")
	}
}

func TestRelay_AddSession_MaxReached(t *testing.T) {
	relay := startTestRelay(t, 1, 5*time.Minute)

	peerA := newTestUDPConn(t)
	peerB := newTestUDPConn(t)

	assignment := api.RelaySessionAssignment{
		SessionID:     "sess-1",
		PeerAEndpoint: peerA.LocalAddr().String(),
		PeerBEndpoint: peerB.LocalAddr().String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	if err := relay.AddSession(assignment); err != nil {
		t.Fatalf("first AddSession: %v", err)
	}

	peerC := newTestUDPConn(t)
	peerD := newTestUDPConn(t)
	second := api.RelaySessionAssignment{
		SessionID:     "sess-2",
		PeerAEndpoint: peerC.LocalAddr().String(),
		PeerBEndpoint: peerD.LocalAddr().String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	err := relay.AddSession(second)
	if err == nil {
		t.Fatal("AddSession should return error when max sessions reached")
	}
}

func TestRelay_RemoveSession(t *testing.T) {
	relay := startTestRelay(t, 100, 5*time.Minute)

	peerA := newTestUDPConn(t)
	peerB := newTestUDPConn(t)

	assignment := api.RelaySessionAssignment{
		SessionID:     "sess-1",
		PeerAEndpoint: peerA.LocalAddr().String(),
		PeerBEndpoint: peerB.LocalAddr().String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	if err := relay.AddSession(assignment); err != nil {
		t.Fatalf("AddSession: %v", err)
	}

	relay.RemoveSession("sess-1")
	if relay.ActiveCount() != 0 {
		t.Errorf("ActiveCount = %d, want 0", relay.ActiveCount())
	}

	// Removing non-existent session is a no-op.
	relay.RemoveSession("nonexistent")
}

func TestRelay_Stop_ClosesAllSessions(t *testing.T) {
	relay := startTestRelay(t, 100, 5*time.Minute)

	for i := 0; i < 3; i++ {
		peerA := newTestUDPConn(t)
		peerB := newTestUDPConn(t)
		assignment := api.RelaySessionAssignment{
			SessionID:     fmt.Sprintf("sess-%d", i),
			PeerAEndpoint: peerA.LocalAddr().String(),
			PeerBEndpoint: peerB.LocalAddr().String(),
			ExpiresAt:     time.Now().Add(5 * time.Minute),
		}
		if err := relay.AddSession(assignment); err != nil {
			t.Fatalf("AddSession %d: %v", i, err)
		}
	}

	if relay.ActiveCount() != 3 {
		t.Fatalf("ActiveCount = %d, want 3", relay.ActiveCount())
	}

	if err := relay.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if relay.ActiveCount() != 0 {
		t.Errorf("ActiveCount after Stop = %d, want 0", relay.ActiveCount())
	}
}

func TestRelay_AddSession_EmptySessionID(t *testing.T) {
	relay := startTestRelay(t, 100, 5*time.Minute)

	peerA := newTestUDPConn(t)
	peerB := newTestUDPConn(t)

	assignment := api.RelaySessionAssignment{
		SessionID:     "",
		PeerAEndpoint: peerA.LocalAddr().String(),
		PeerBEndpoint: peerB.LocalAddr().String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	err := relay.AddSession(assignment)
	if err == nil {
		t.Fatal("AddSession should return error for empty session ID")
	}
	want := "bridge: relay: empty session ID"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestRelay_AddSession_SameEndpoints(t *testing.T) {
	relay := startTestRelay(t, 100, 5*time.Minute)

	peerA := newTestUDPConn(t)

	assignment := api.RelaySessionAssignment{
		SessionID:     "sess-same",
		PeerAEndpoint: peerA.LocalAddr().String(),
		PeerBEndpoint: peerA.LocalAddr().String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	err := relay.AddSession(assignment)
	if err == nil {
		t.Fatal("AddSession should return error when peer A and peer B endpoints are the same")
	}
	if !strings.Contains(err.Error(), "must differ") {
		t.Errorf("error should mention endpoints must differ, got: %v", err)
	}
}

func TestRelay_AddSession_InvalidEndpointFormat(t *testing.T) {
	tests := []struct {
		name          string
		peerAEndpoint string
		peerBEndpoint string
		wantContains  string
	}{
		{
			name:          "peer A malformed host:port",
			peerAEndpoint: "not-a-host:port:extra",
			peerBEndpoint: "127.0.0.1:9000",
			wantContains:  "resolve peer A endpoint",
		},
		{
			name:          "peer B malformed host:port",
			peerAEndpoint: "127.0.0.1:9000",
			peerBEndpoint: "not-a-host:port:extra",
			wantContains:  "resolve peer B endpoint",
		},
		{
			name:          "peer A invalid port",
			peerAEndpoint: "127.0.0.1:99999",
			peerBEndpoint: "127.0.0.1:9000",
			wantContains:  "resolve peer A endpoint",
		},
		{
			name:          "peer B invalid port",
			peerAEndpoint: "127.0.0.1:9000",
			peerBEndpoint: "127.0.0.1:99999",
			wantContains:  "resolve peer B endpoint",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			relay := startTestRelay(t, 100, 5*time.Minute)
			assignment := api.RelaySessionAssignment{
				SessionID:     "sess-invalid",
				PeerAEndpoint: tt.peerAEndpoint,
				PeerBEndpoint: tt.peerBEndpoint,
				ExpiresAt:     time.Now().Add(5 * time.Minute),
			}
			err := relay.AddSession(assignment)
			if err == nil {
				t.Fatal("AddSession should return error for invalid endpoint format")
			}
			if !strings.Contains(err.Error(), tt.wantContains) {
				t.Errorf("error should contain %q, got: %v", tt.wantContains, err)
			}
		})
	}
}

func TestRelay_SessionExpiry(t *testing.T) {
	relay := startTestRelay(t, 100, 100*time.Millisecond)

	peerA := newTestUDPConn(t)
	peerB := newTestUDPConn(t)

	assignment := api.RelaySessionAssignment{
		SessionID:     "sess-expiry",
		PeerAEndpoint: peerA.LocalAddr().String(),
		PeerBEndpoint: peerB.LocalAddr().String(),
		ExpiresAt:     time.Now().Add(100 * time.Millisecond),
	}
	if err := relay.AddSession(assignment); err != nil {
		t.Fatalf("AddSession: %v", err)
	}

	if relay.ActiveCount() != 1 {
		t.Fatalf("ActiveCount = %d, want 1", relay.ActiveCount())
	}

	// Wait for expiry.
	time.Sleep(300 * time.Millisecond)

	if relay.ActiveCount() != 0 {
		t.Errorf("ActiveCount after expiry = %d, want 0", relay.ActiveCount())
	}
}
