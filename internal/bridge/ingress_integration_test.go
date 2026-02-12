package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Integration tests — Ingress
// ---------------------------------------------------------------------------

// TestIngressIntegration_FullLifecycle wires an IngressManager with real TCP
// listeners, verifies Setup -> AddRule -> proxy traffic -> RemoveRule -> Teardown.
func TestIngressIntegration_FullLifecycle(t *testing.T) {
	ctrl := &mockIngressController{}
	cfg := Config{
		Enabled:        true,
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	// Setup.
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if mgr.IngressStatus() == nil {
		t.Fatal("should be active after Setup")
	}

	// --- Step 1: Add a rule and verify tracking ---
	rule1 := api.IngressRule{
		RuleID:     "rule-lifecycle-1",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:8080",
		Mode:       "tcp",
	}
	if err := mgr.AddRule(rule1); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	ids := mgr.RuleIDs()
	if len(ids) != 1 || ids[0] != "rule-lifecycle-1" {
		t.Errorf("RuleIDs = %v, want [rule-lifecycle-1]", ids)
	}
	status := mgr.IngressStatus()
	if status.RuleCount != 1 {
		t.Errorf("RuleCount = %d, want 1", status.RuleCount)
	}

	// Remove the basic rule before the proxy test.
	mgr.RemoveRule("rule-lifecycle-1")
	if len(mgr.RuleIDs()) != 0 {
		t.Errorf("RuleIDs after remove = %v, want empty", mgr.RuleIDs())
	}

	// --- Step 2: Proxy traffic test ---
	// Start a TCP echo server.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// Add an ingress rule pointing to the echo server.
	proxyRule := api.IngressRule{
		RuleID:     "rule-proxy",
		ListenPort: 0,
		TargetAddr: echoLn.Addr().String(),
		Mode:       "tcp",
	}
	if err := mgr.AddRule(proxyRule); err != nil {
		t.Fatalf("AddRule proxy: %v", err)
	}

	// Get the listener address from the active rule.
	mgr.mu.Lock()
	ar := mgr.activeRules["rule-proxy"]
	listenerAddr := ar.listener.Addr().String()
	mgr.mu.Unlock()

	// Connect to the ingress listener, send data, verify echo.
	conn, err := net.DialTimeout("tcp", listenerAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial ingress listener: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	msg := []byte("hello")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("echo = %q, want %q", string(buf), "hello")
	}

	conn.Close()

	// --- Step 3: Remove rule and verify ---
	mgr.RemoveRule("rule-proxy")
	ids = mgr.RuleIDs()
	if len(ids) != 0 {
		t.Errorf("RuleIDs after proxy remove = %v, want empty", ids)
	}
	status = mgr.IngressStatus()
	if status.RuleCount != 0 {
		t.Errorf("RuleCount after remove = %d, want 0", status.RuleCount)
	}

	// --- Step 4: Teardown ---
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if mgr.IngressStatus() != nil {
		t.Error("should be inactive after Teardown")
	}

	// Second teardown is no-op.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

// TestIngressIntegration_ReconcileDrift wires an IngressManager with a real
// Reconciler and verifies that reconciliation correctly adds missing rules and
// removes stale rules.
func TestIngressIntegration_ReconcileDrift(t *testing.T) {
	ctrl := &mockIngressController{}
	cfg := Config{
		Enabled:        true,
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.resetIngress()

	// Initial state: one ingress rule.
	state1 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		IngressConfig: &api.IngressConfig{
			Enabled: true,
			Rules: []api.IngressRule{
				{RuleID: "rule-1", ListenPort: 0, TargetAddr: "10.0.0.5:8080", Mode: "tcp"},
			},
		},
		Metadata: map[string]string{"version": "1"},
	}
	fetcher := &integrationStateFetcher{state: state1}

	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, discardLogger())
	rec.RegisterHandler(IngressReconcileHandler(mgr, discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-ingress") }()

	// Wait for initial cycle: rule-1 should be added (1 Listen call).
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ctrl.ingressCallsFor("Listen")) >= 1
	})

	// Update: replace rule-1 with rule-2 and rule-3, bump metadata.
	state2 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		IngressConfig: &api.IngressConfig{
			Enabled: true,
			Rules: []api.IngressRule{
				{RuleID: "rule-2", ListenPort: 0, TargetAddr: "10.0.0.6:9090", Mode: "tcp"},
				{RuleID: "rule-3", ListenPort: 0, TargetAddr: "10.0.0.7:3000", Mode: "tcp"},
			},
		},
		Metadata: map[string]string{"version": "2"},
	}
	fetcher.setState(state2)
	rec.TriggerReconcile()

	// Wait for: 1 Close (rule-1 removed) + 2 more Listen (rule-2, rule-3 added) = total 3 Listen.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ctrl.ingressCallsFor("Listen")) >= 3 &&
			len(ctrl.ingressCallsFor("Close")) >= 1
	})

	// Update: empty rules — all removed.
	state3 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		IngressConfig: &api.IngressConfig{
			Enabled: true,
			Rules:   []api.IngressRule{},
		},
		Metadata: map[string]string{"version": "3"},
	}
	fetcher.setState(state3)
	rec.TriggerReconcile()

	// Wait for 2 more Close calls (rule-2, rule-3 removed) = total 3 Close.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ctrl.ingressCallsFor("Close")) >= 3
	})

	cancel()
	<-done

	// Clean up any remaining listeners/goroutines.
	mgr.Teardown()
}

// TestIngressIntegration_ConcurrentAccess exercises concurrent SSE events
// (config updates, rule assignments, and rule revocations) alongside the
// reconcile loop to verify no data races. Run with -race.
func TestIngressIntegration_ConcurrentAccess(t *testing.T) {
	ctrl := &mockIngressController{}
	cfg := Config{
		Enabled:        true,
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	var cycle atomic.Int32
	states := []*api.StateResponse{
		{
			Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
			IngressConfig: &api.IngressConfig{
				Enabled: true,
				Rules: []api.IngressRule{
					{RuleID: "rule-conc-1", ListenPort: 0, TargetAddr: "10.0.0.5:8080", Mode: "tcp"},
				},
			},
		},
		{
			Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
			IngressConfig: &api.IngressConfig{
				Enabled: true,
				Rules: []api.IngressRule{
					{RuleID: "rule-conc-1", ListenPort: 0, TargetAddr: "10.0.0.5:8080", Mode: "tcp"},
					{RuleID: "rule-conc-2", ListenPort: 0, TargetAddr: "10.0.0.6:9090", Mode: "tcp"},
				},
			},
		},
	}

	fetcher := &alternatingBridgeFetcher{
		states: states,
		cycle:  &cycle,
	}

	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: 30 * time.Millisecond}, discardLogger())
	rec.RegisterHandler(IngressReconcileHandler(mgr, discardLogger()))

	dispatcher := api.NewEventDispatcher(discardLogger())
	dispatcher.Register(api.EventIngressConfigUpdated, HandleIngressConfigUpdated(rec))
	dispatcher.Register(api.EventIngressRuleAssigned, HandleIngressRuleAssigned(mgr, discardLogger()))
	dispatcher.Register(api.EventIngressRuleRevoked, HandleIngressRuleRevoked(mgr, discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-ingress") }()

	// Concurrently dispatch SSE events while the reconcile loop runs.
	var wg sync.WaitGroup

	// Config update dispatchers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			envelope := api.SignedEnvelope{
				EventType: api.EventIngressConfigUpdated,
				EventID:   "concurrent-config-evt",
			}
			dispatcher.Dispatch(ctx, envelope)
		}()
	}

	// Rule assignment dispatchers — use unique rule IDs per goroutine.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rule := api.IngressRule{
				RuleID:     fmt.Sprintf("rule-sse-%d", idx),
				ListenPort: 0,
				TargetAddr: "10.0.0.5:8080",
				Mode:       "tcp",
			}
			payload, _ := json.Marshal(rule)
			envelope := api.SignedEnvelope{
				EventType: api.EventIngressRuleAssigned,
				EventID:   fmt.Sprintf("assign-evt-%d", idx),
				Payload:   payload,
			}
			dispatcher.Dispatch(ctx, envelope)
		}(i)
	}

	// Rule revocation dispatchers — revoke the same rule IDs we're adding above.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload, _ := json.Marshal(struct {
				RuleID string `json:"rule_id"`
			}{RuleID: fmt.Sprintf("rule-sse-%d", idx)})
			envelope := api.SignedEnvelope{
				EventType: api.EventIngressRuleRevoked,
				EventID:   fmt.Sprintf("revoke-evt-%d", idx),
				Payload:   payload,
			}
			dispatcher.Dispatch(ctx, envelope)
		}(i)
	}

	// Let the reconcile loop run several cycles.
	time.Sleep(300 * time.Millisecond)

	wg.Wait()
	cancel()
	<-done

	// Clean up any remaining listeners/goroutines.
	mgr.Teardown()

	// Test passes if no race detected. Verify some activity occurred.
	if n := fetcher.getFetchCount(); n < 2 {
		t.Errorf("FetchState calls = %d, want >= 2", n)
	}
}
