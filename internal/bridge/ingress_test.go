package bridge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// IngressManager tests
// ---------------------------------------------------------------------------

func TestIngressManager_Setup_Disabled(t *testing.T) {
	ctrl := &mockIngressController{}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: false,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Manager should not be active.
	if mgr.IngressStatus() != nil {
		t.Error("IngressStatus should be nil when disabled")
	}
}

func TestIngressManager_Setup_Enabled(t *testing.T) {
	ctrl := &mockIngressController{}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	status := mgr.IngressStatus()
	if status == nil {
		t.Fatal("IngressStatus should not be nil when active")
	}
	if !status.Enabled {
		t.Error("Enabled should be true")
	}
	if status.RuleCount != 0 {
		t.Errorf("RuleCount = %d, want 0", status.RuleCount)
	}
	if status.ConnectionCount != 0 {
		t.Errorf("ConnectionCount = %d, want 0", status.ConnectionCount)
	}
}

func TestIngressManager_AddRule_StartsListener(t *testing.T) {
	ctrl := &mockIngressController{}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	rule := api.IngressRule{
		RuleID:     "rule-1",
		ListenPort: 0, // Use port 0 for ephemeral port
		TargetAddr: "10.0.0.5:8080",
		Mode:       "tcp",
	}

	// Override listenFn to use port 0 for testing
	ctrl.listenFn = func(addr string, tlsCfg *tls.Config) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}

	if err := mgr.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	// Verify Listen was called.
	listenCalls := ctrl.ingressCallsFor("Listen")
	if len(listenCalls) != 1 {
		t.Fatalf("expected 1 Listen call, got %d", len(listenCalls))
	}

	// Verify rule is tracked.
	ids := mgr.RuleIDs()
	if len(ids) != 1 || ids[0] != "rule-1" {
		t.Errorf("RuleIDs = %v, want [rule-1]", ids)
	}

	// Verify status reflects the rule.
	status := mgr.IngressStatus()
	if status == nil || status.RuleCount != 1 {
		t.Errorf("RuleCount = %v, want 1", status)
	}

	// Cleanup.
	_ = mgr.Teardown()
}

func TestIngressManager_AddRule_DuplicateRejects(t *testing.T) {
	ctrl := &mockIngressController{
		listenFn: func(addr string, tlsCfg *tls.Config) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	rule := api.IngressRule{
		RuleID:     "rule-1",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:8080",
		Mode:       "tcp",
	}

	if err := mgr.AddRule(rule); err != nil {
		t.Fatalf("first AddRule: %v", err)
	}

	err := mgr.AddRule(rule)
	if err == nil {
		t.Fatal("AddRule should return error for duplicate rule ID")
	}

	// Cleanup.
	_ = mgr.Teardown()
}

func TestIngressManager_AddRule_MaxRulesReject(t *testing.T) {
	ctrl := &mockIngressController{
		listenFn: func(addr string, tlsCfg *tls.Config) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: true,
		MaxIngressRules: 2,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add up to max.
	for i := 0; i < 2; i++ {
		rule := api.IngressRule{
			RuleID:     fmt.Sprintf("rule-%d", i),
			ListenPort: 0,
			TargetAddr: "10.0.0.5:8080",
			Mode:       "tcp",
		}
		if err := mgr.AddRule(rule); err != nil {
			t.Fatalf("AddRule %d: %v", i, err)
		}
	}

	// Third should fail.
	err := mgr.AddRule(api.IngressRule{
		RuleID:     "rule-extra",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:8080",
		Mode:       "tcp",
	})
	if err == nil {
		t.Fatal("AddRule should return error when max rules reached")
	}

	// Cleanup.
	_ = mgr.Teardown()
}

func TestIngressManager_RemoveRule_StopsListener(t *testing.T) {
	ctrl := &mockIngressController{
		listenFn: func(addr string, tlsCfg *tls.Config) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	rule := api.IngressRule{
		RuleID:     "rule-1",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:8080",
		Mode:       "tcp",
	}
	if err := mgr.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	ctrl.resetIngress()

	mgr.RemoveRule("rule-1")

	// Verify Close was called.
	closeCalls := ctrl.ingressCallsFor("Close")
	if len(closeCalls) != 1 {
		t.Fatalf("expected 1 Close call, got %d", len(closeCalls))
	}

	// Verify rule is no longer tracked.
	ids := mgr.RuleIDs()
	if len(ids) != 0 {
		t.Errorf("RuleIDs = %v, want empty", ids)
	}

	status := mgr.IngressStatus()
	if status == nil || status.RuleCount != 0 {
		t.Errorf("RuleCount = %v, want 0", status)
	}
}

func TestIngressManager_RemoveRule_NonexistentNoop(t *testing.T) {
	ctrl := &mockIngressController{}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Remove non-existent rule should not panic or call Close.
	mgr.RemoveRule("nonexistent")

	closeCalls := ctrl.ingressCallsFor("Close")
	if len(closeCalls) != 0 {
		t.Errorf("Close should not be called for non-existent rule, got %d calls", len(closeCalls))
	}
}

func TestIngressManager_Teardown(t *testing.T) {
	ctrl := &mockIngressController{
		listenFn: func(addr string, tlsCfg *tls.Config) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add two rules so teardown has work to do.
	for i := 0; i < 2; i++ {
		rule := api.IngressRule{
			RuleID:     fmt.Sprintf("rule-%d", i),
			ListenPort: 0,
			TargetAddr: "10.0.0.5:8080",
			Mode:       "tcp",
		}
		if err := mgr.AddRule(rule); err != nil {
			t.Fatalf("AddRule %d: %v", i, err)
		}
	}
	ctrl.resetIngress()

	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// Verify Close was called for both rules.
	closeCalls := ctrl.ingressCallsFor("Close")
	if len(closeCalls) != 2 {
		t.Errorf("expected 2 Close calls, got %d", len(closeCalls))
	}

	// Status should be nil after teardown.
	if mgr.IngressStatus() != nil {
		t.Error("IngressStatus should be nil after teardown")
	}

	// RuleIDs should be empty.
	if ids := mgr.RuleIDs(); len(ids) != 0 {
		t.Errorf("RuleIDs should be empty after teardown, got %v", ids)
	}
}

func TestIngressManager_Teardown_Idempotent(t *testing.T) {
	ctrl := &mockIngressController{}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: false,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	// Teardown when not active should return nil.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("first Teardown: %v", err)
	}
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}

	if len(ctrl.ingressCallsFor("Close")) != 0 {
		t.Error("Close should not be called when not active")
	}
}

// errorListener wraps a net.Listener so that Close always returns an error
// but still actually closes the underlying listener.
type errorListener struct {
	net.Listener
	closeErr error
}

func (e *errorListener) Close() error {
	e.Listener.Close()
	return e.closeErr
}

func TestIngressManager_Teardown_AggregatesErrors(t *testing.T) {
	injectedErr := fmt.Errorf("injected close error")

	ctrl := &mockIngressController{
		listenFn: func(addr string, tlsCfg *tls.Config) (net.Listener, error) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			// Wrap listener so Close returns an error but still closes.
			return &errorListener{Listener: ln, closeErr: injectedErr}, nil
		},
	}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	rule := api.IngressRule{
		RuleID:     "rule-1",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:8080",
		Mode:       "tcp",
	}
	if err := mgr.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	err := mgr.Teardown()
	if err == nil {
		t.Fatal("Teardown should return aggregated errors")
	}

	// Despite errors, manager should be marked inactive.
	if mgr.IngressStatus() != nil {
		t.Error("IngressStatus should be nil after teardown even with errors")
	}
}

func TestIngressManager_IngressStatus_Active(t *testing.T) {
	ctrl := &mockIngressController{
		listenFn: func(addr string, tlsCfg *tls.Config) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add a rule.
	rule := api.IngressRule{
		RuleID:     "rule-1",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:8080",
		Mode:       "tcp",
	}
	if err := mgr.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	status := mgr.IngressStatus()
	if status == nil {
		t.Fatal("IngressStatus should not be nil when active")
	}
	if !status.Enabled {
		t.Error("Enabled should be true")
	}
	if status.RuleCount != 1 {
		t.Errorf("RuleCount = %d, want 1", status.RuleCount)
	}
	if status.ConnectionCount != 0 {
		t.Errorf("ConnectionCount = %d, want 0", status.ConnectionCount)
	}

	// Cleanup.
	_ = mgr.Teardown()
}

func TestIngressManager_IngressStatus_Inactive(t *testing.T) {
	ctrl := &mockIngressController{}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: false,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if status := mgr.IngressStatus(); status != nil {
		t.Errorf("IngressStatus should be nil when not active, got %+v", status)
	}
}

func TestIngressManager_IngressCapabilities(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		ctrl := &mockIngressController{}
		cfg := Config{
			Enabled:        true,
			AccessInterface: "eth1",
			AccessSubnets:  []string{"10.0.0.0/24"},
			IngressEnabled: true,
		}
		cfg.ApplyDefaults()

		mgr := NewIngressManager(ctrl, cfg, discardLogger())

		caps := mgr.IngressCapabilities()
		if caps == nil {
			t.Fatal("IngressCapabilities should not be nil when enabled")
		}
		if caps["ingress"] != "true" {
			t.Errorf("ingress = %q, want %q", caps["ingress"], "true")
		}
		if caps["max_ingress_rules"] != "20" {
			t.Errorf("max_ingress_rules = %q, want %q", caps["max_ingress_rules"], "20")
		}
	})

	t.Run("disabled", func(t *testing.T) {
		ctrl := &mockIngressController{}
		cfg := Config{
			Enabled:        true,
			AccessInterface: "eth1",
			AccessSubnets:  []string{"10.0.0.0/24"},
			IngressEnabled: false,
		}
		cfg.ApplyDefaults()

		mgr := NewIngressManager(ctrl, cfg, discardLogger())

		if caps := mgr.IngressCapabilities(); caps != nil {
			t.Errorf("IngressCapabilities should be nil when disabled, got %v", caps)
		}
	})
}

func TestIngressManager_AddRule_TLSTerminate_InvalidCert(t *testing.T) {
	ctrl := &mockIngressController{
		listenFn: func(addr string, tlsCfg *tls.Config) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	rule := api.IngressRule{
		RuleID:     "tls-rule-1",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:443",
		Mode:       "terminate",
		CertPEM:    "not-a-valid-cert",
		KeyPEM:     "not-a-valid-key",
	}

	err := mgr.AddRule(rule)
	if err == nil {
		t.Fatal("AddRule should return error for invalid TLS cert/key")
	}

	// Verify no listener was created (Listen should not be called since TLS parse fails first).
	listenCalls := ctrl.ingressCallsFor("Listen")
	if len(listenCalls) != 0 {
		t.Errorf("Listen should not be called when TLS cert is invalid, got %d calls", len(listenCalls))
	}
}

// ---------------------------------------------------------------------------
// TLS terminate mode with valid cert
// ---------------------------------------------------------------------------

func TestIngressManager_AddRule_TLSTerminate_ValidCert(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)

	ctrl := &mockIngressController{
		listenFn: func(addr string, tlsCfg *tls.Config) (net.Listener, error) {
			if tlsCfg == nil {
				t.Error("expected non-nil TLS config for terminate mode")
			}
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	cfg := Config{
		Enabled:        true,
		AccessInterface: "eth1",
		AccessSubnets:  []string{"10.0.0.0/24"},
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	rule := api.IngressRule{
		RuleID:     "tls-rule-valid",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:443",
		Mode:       "terminate",
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
	}

	if err := mgr.AddRule(rule); err != nil {
		t.Fatalf("AddRule with valid TLS cert: %v", err)
	}

	listenCalls := ctrl.ingressCallsFor("Listen")
	if len(listenCalls) != 1 {
		t.Fatalf("expected 1 Listen call, got %d", len(listenCalls))
	}

	// Cleanup.
	_ = mgr.Teardown()
}

func TestIngressManager_AddRule_InactiveRejects(t *testing.T) {
	ctrl := &mockIngressController{
		listenFn: func(addr string, tlsCfg *tls.Config) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		IngressEnabled:  true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	// Do NOT call Setup — manager is inactive.
	rule := api.IngressRule{
		RuleID:     "rule-1",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:8080",
		Mode:       "tcp",
	}

	err := mgr.AddRule(rule)
	if err == nil {
		t.Fatal("AddRule should return error when manager is inactive")
	}

	// Verify no listener was created.
	if len(ctrl.ingressCallsFor("Listen")) != 0 {
		t.Error("Listen should not be called when manager is inactive")
	}
}

func TestIngressManager_RemoveRule_InactiveNoop(t *testing.T) {
	ctrl := &mockIngressController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		IngressEnabled:  true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())

	// Do NOT call Setup — manager is inactive.
	// Should not panic or call Close.
	mgr.RemoveRule("any-rule")

	if len(ctrl.ingressCallsFor("Close")) != 0 {
		t.Error("Close should not be called when manager is inactive")
	}
}

func TestIngressManager_GetRule(t *testing.T) {
	ctrl := &mockIngressController{
		listenFn: func(addr string, tlsCfg *tls.Config) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		IngressEnabled:  true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger())
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	defer func() { _ = mgr.Teardown() }()

	rule := api.IngressRule{
		RuleID:     "rule-get",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:8080",
		Mode:       "tcp",
	}
	if err := mgr.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	got, ok := mgr.GetRule("rule-get")
	if !ok {
		t.Fatal("GetRule should return true for existing rule")
	}
	if got != rule {
		t.Errorf("GetRule = %+v, want %+v", got, rule)
	}

	_, ok = mgr.GetRule("nonexistent")
	if ok {
		t.Error("GetRule should return false for non-existent rule")
	}
}

// generateSelfSignedCert creates a self-signed certificate for testing.
func generateSelfSignedCert(t *testing.T) (certPEM string, keyPEM string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certBlock), string(keyBlock)
}
