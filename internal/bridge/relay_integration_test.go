package bridge

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// TestRelayIntegration_FullFlow starts a real UDP relay, adds a session with
// two local UDP sockets as peers, sends a packet from peer A, verifies peer B
// receives it, then sends from B and verifies A receives.
func TestRelayIntegration_FullFlow(t *testing.T) {
	relay := startTestRelay(t, 100, 5*time.Minute)

	peerA := newTestUDPConn(t)
	peerB := newTestUDPConn(t)

	assignment := api.RelaySessionAssignment{
		SessionID:     "integration-sess-1",
		PeerAID:       "peer-a",
		PeerAEndpoint: peerA.LocalAddr().String(),
		PeerBID:       "peer-b",
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

	// A -> relay -> B
	msgAB := []byte("hello from A to B")
	if _, err := peerA.WriteToUDP(msgAB, relayAddr); err != nil {
		t.Fatalf("peerA write: %v", err)
	}

	buf := make([]byte, 1024)
	peerB.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peerB.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peerB read: %v", err)
	}
	if string(buf[:n]) != "hello from A to B" {
		t.Errorf("peerB got %q, want %q", string(buf[:n]), "hello from A to B")
	}

	// B -> relay -> A
	msgBA := []byte("hello from B to A")
	if _, err := peerB.WriteToUDP(msgBA, relayAddr); err != nil {
		t.Fatalf("peerB write: %v", err)
	}

	peerA.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = peerA.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peerA read: %v", err)
	}
	if string(buf[:n]) != "hello from B to A" {
		t.Errorf("peerA got %q, want %q", string(buf[:n]), "hello from B to A")
	}

	// Verify session is tracked.
	if relay.ActiveCount() != 1 {
		t.Errorf("ActiveCount = %d, want 1", relay.ActiveCount())
	}

	// Remove session and verify packet is no longer forwarded.
	relay.RemoveSession("integration-sess-1")
	if relay.ActiveCount() != 0 {
		t.Errorf("ActiveCount after remove = %d, want 0", relay.ActiveCount())
	}

	// Send another packet — should be dropped (no session).
	if _, err := peerA.WriteToUDP([]byte("dropped"), relayAddr); err != nil {
		t.Fatalf("peerA write after remove: %v", err)
	}
	peerB.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err = peerB.ReadFromUDP(buf)
	if err == nil {
		t.Error("peerB should not receive packet after session removal")
	}
}

// TestRelayIntegration_ReconcileSessionSync wires a Relay with a real
// Reconciler and verifies that reconciliation adds missing sessions and
// removes stale sessions from the desired state.
func TestRelayIntegration_ReconcileSessionSync(t *testing.T) {
	relay := startTestRelay(t, 100, 5*time.Minute)

	peerA := newTestUDPConn(t)
	peerB := newTestUDPConn(t)
	peerC := newTestUDPConn(t)
	peerD := newTestUDPConn(t)

	// Initial desired state: one session.
	state1 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		RelayConfig: &api.RelayConfig{
			Sessions: []api.RelaySessionAssignment{
				{
					SessionID:     "reconcile-sess-1",
					PeerAID:       "peer-a",
					PeerAEndpoint: peerA.LocalAddr().String(),
					PeerBID:       "peer-b",
					PeerBEndpoint: peerB.LocalAddr().String(),
					ExpiresAt:     time.Now().Add(5 * time.Minute),
				},
			},
		},
		Metadata: map[string]string{"version": "1"},
	}

	fetcher := &integrationStateFetcher{state: state1}
	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, discardLogger())
	rec.RegisterHandler(RelayReconcileHandler(relay, discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-relay") }()

	// Wait for initial cycle to add the session.
	waitForCondition(t, 2*time.Second, func() bool { return relay.ActiveCount() == 1 })

	ids := relay.SessionIDs()
	if len(ids) != 1 || ids[0] != "reconcile-sess-1" {
		t.Errorf("SessionIDs = %v, want [reconcile-sess-1]", ids)
	}

	// Update state: replace sess-1 with sess-2, bump metadata.
	state2 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		RelayConfig: &api.RelayConfig{
			Sessions: []api.RelaySessionAssignment{
				{
					SessionID:     "reconcile-sess-2",
					PeerAID:       "peer-c",
					PeerAEndpoint: peerC.LocalAddr().String(),
					PeerBID:       "peer-d",
					PeerBEndpoint: peerD.LocalAddr().String(),
					ExpiresAt:     time.Now().Add(5 * time.Minute),
				},
			},
		},
		Metadata: map[string]string{"version": "2"},
	}
	fetcher.setState(state2)
	rec.TriggerReconcile()

	// Wait for reconciliation to swap sessions.
	waitForCondition(t, 2*time.Second, func() bool {
		ids := relay.SessionIDs()
		return len(ids) == 1 && ids[0] == "reconcile-sess-2"
	})

	if relay.ActiveCount() != 1 {
		t.Errorf("ActiveCount = %d, want 1", relay.ActiveCount())
	}

	// Update state: empty sessions — all removed.
	state3 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		RelayConfig: &api.RelayConfig{
			Sessions: []api.RelaySessionAssignment{},
		},
		Metadata: map[string]string{"version": "3"},
	}
	fetcher.setState(state3)
	rec.TriggerReconcile()

	waitForCondition(t, 2*time.Second, func() bool { return relay.ActiveCount() == 0 })

	cancel()
	<-done
}

// TestRelayIntegration_ConcurrentNoRace exercises concurrent AddSession,
// RemoveSession, and packet forwarding to verify no data races under -race.
func TestRelayIntegration_ConcurrentNoRace(t *testing.T) {
	relay := startTestRelay(t, 200, 5*time.Minute)

	relayAddr, err := net.ResolveUDPAddr("udp", relay.ListenAddr().String())
	if err != nil {
		t.Fatalf("resolve relay addr: %v", err)
	}

	// Pre-create peer sockets for sessions.
	const numSessions = 20
	type peerPair struct {
		a, b *net.UDPConn
	}
	peers := make([]peerPair, numSessions)
	for i := range peers {
		peers[i] = peerPair{
			a: newTestUDPConn(t),
			b: newTestUDPConn(t),
		}
	}

	var wg sync.WaitGroup
	var addErrors atomic.Int32

	// Concurrent AddSession.
	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			assignment := api.RelaySessionAssignment{
				SessionID:     fmt.Sprintf("race-sess-%d", idx),
				PeerAID:       fmt.Sprintf("peer-a-%d", idx),
				PeerAEndpoint: peers[idx].a.LocalAddr().String(),
				PeerBID:       fmt.Sprintf("peer-b-%d", idx),
				PeerBEndpoint: peers[idx].b.LocalAddr().String(),
				ExpiresAt:     time.Now().Add(5 * time.Minute),
			}
			if err := relay.AddSession(assignment); err != nil {
				addErrors.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if errs := addErrors.Load(); errs != 0 {
		t.Fatalf("AddSession errors = %d, want 0", errs)
	}

	if relay.ActiveCount() != numSessions {
		t.Fatalf("ActiveCount = %d, want %d", relay.ActiveCount(), numSessions)
	}

	// Concurrent packet forwarding + session removal.
	for i := 0; i < numSessions; i++ {
		wg.Add(2)
		// Send packets from peer A.
		go func(idx int) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("data-%d", idx))
			peers[idx].a.WriteToUDP(msg, relayAddr)
		}(i)

		// Remove odd-numbered sessions concurrently with forwarding.
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 1 {
				relay.RemoveSession(fmt.Sprintf("race-sess-%d", idx))
			}
		}(i)
	}
	wg.Wait()

	// After removing odd sessions (indices 1,3,5,...,19), 10 even sessions remain.
	expectedRemaining := numSessions / 2
	if relay.ActiveCount() != expectedRemaining {
		t.Errorf("ActiveCount = %d, want %d", relay.ActiveCount(), expectedRemaining)
	}

	// Verify SessionIDs only contains even sessions.
	ids := relay.SessionIDs()
	idSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	for i := 0; i < numSessions; i++ {
		id := fmt.Sprintf("race-sess-%d", i)
		if i%2 == 0 {
			if !idSet[id] {
				t.Errorf("expected %s to be present", id)
			}
		} else {
			if idSet[id] {
				t.Errorf("expected %s to be removed", id)
			}
		}
	}
}
