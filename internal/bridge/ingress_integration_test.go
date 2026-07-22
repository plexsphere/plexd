package bridge

import (
	"context"
	"io"
	"net"
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

	mgr := NewIngressManager(ctrl, cfg, discardLogger(), nil)

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
				_, _ = io.Copy(c, c)
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

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

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

	mgr := NewIngressManager(ctrl, cfg, discardLogger(), nil)
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.resetIngress()

	// Initial state: one ingress rule.
	state1 := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			Ingress: &api.IngressConfig{
				Enabled: true,
				Rules: []api.IngressRule{
					{RuleID: "rule-1", ListenPort: 0, TargetAddr: "10.0.0.5:8080", Mode: "tcp"},
				},
			},
		},
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

	// Update: replace rule-1 with rule-2 and rule-3.
	state2 := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			Ingress: &api.IngressConfig{
				Enabled: true,
				Rules: []api.IngressRule{
					{RuleID: "rule-2", ListenPort: 0, TargetAddr: "10.0.0.6:9090", Mode: "tcp"},
					{RuleID: "rule-3", ListenPort: 0, TargetAddr: "10.0.0.7:3000", Mode: "tcp"},
				},
			},
		},
	}
	fetcher.setState(state2)
	rec.TriggerReconcile()

	// Wait for: 1 Close (rule-1 removed) + 2 more Listen (rule-2, rule-3 added) = total 3 Listen.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ctrl.ingressCallsFor("Listen")) >= 3 &&
			len(ctrl.ingressCallsFor("Close")) >= 1
	})

	// Update: empty rules — all removed.
	state3 := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			Ingress: &api.IngressConfig{
				Enabled: true,
				Rules:   []api.IngressRule{},
			},
		},
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
	_ = mgr.Teardown()
}
