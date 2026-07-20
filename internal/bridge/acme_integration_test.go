// Integration tests — ACME and SNI with Ingress

package bridge

import (
	"context"
	"crypto/tls"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Integration tests — ACME with Ingress
// ---------------------------------------------------------------------------

// TestACMEIntegration_ManagerLifecycle tests ACMEManager standalone lifecycle:
// Setup -> Active -> TLSConfig -> AllowedHosts -> Teardown -> inactive.
func TestACMEIntegration_ManagerLifecycle(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"example.com", "www.example.com"},
		Email:        "admin@example.com",
	}

	mgr := NewACMEManager(cfg, discardLogger())

	// Setup succeeds.
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Active() returns true after Setup.
	if !mgr.Active() {
		t.Fatal("should be active after Setup")
	}

	// TLSConfig() returns non-nil with GetCertificate set.
	tlsCfg := mgr.TLSConfig()
	if tlsCfg == nil {
		t.Fatal("TLSConfig should not be nil after Setup")
	}
	if tlsCfg.GetCertificate == nil {
		t.Error("TLSConfig.GetCertificate should be set")
	}

	// AllowedHosts() returns the configured hosts.
	hosts := mgr.AllowedHosts()
	if len(hosts) != 2 {
		t.Fatalf("AllowedHosts len = %d, want 2", len(hosts))
	}
	if hosts[0] != "example.com" || hosts[1] != "www.example.com" {
		t.Errorf("AllowedHosts = %v, want [example.com www.example.com]", hosts)
	}

	// Teardown succeeds.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// Active() returns false after Teardown.
	if mgr.Active() {
		t.Error("should not be active after Teardown")
	}

	// TLSConfig() returns nil after Teardown.
	if mgr.TLSConfig() != nil {
		t.Error("TLSConfig should be nil after Teardown")
	}

	// Second teardown is no-op.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

// TestACMEIntegration_SetupValidation tests ACMEManager setup validation for
// various invalid configurations.
func TestACMEIntegration_SetupValidation(t *testing.T) {
	// Enabled=false: Setup is no-op, Active()=false.
	t.Run("disabled", func(t *testing.T) {
		cfg := ACMEConfig{
			Enabled: false,
		}
		mgr := NewACMEManager(cfg, discardLogger())

		if err := mgr.Setup(); err != nil {
			t.Fatalf("Setup: %v", err)
		}
		if mgr.Active() {
			t.Error("manager should not be active when disabled")
		}
	})

	// Empty CacheDir: Setup returns error.
	t.Run("empty_cache_dir", func(t *testing.T) {
		cfg := ACMEConfig{
			Enabled:      true,
			CacheDir:     "",
			AllowedHosts: []string{"example.com"},
		}
		mgr := NewACMEManager(cfg, discardLogger())

		err := mgr.Setup()
		if err == nil {
			t.Fatal("Setup should return error for empty CacheDir")
		}
		if mgr.Active() {
			t.Error("manager should not be active after failed Setup")
		}
	})

	// Empty AllowedHosts: Setup returns error.
	t.Run("empty_allowed_hosts", func(t *testing.T) {
		cfg := ACMEConfig{
			Enabled:      true,
			CacheDir:     t.TempDir(),
			AllowedHosts: []string{},
		}
		mgr := NewACMEManager(cfg, discardLogger())

		err := mgr.Setup()
		if err == nil {
			t.Fatal("Setup should return error for empty AllowedHosts")
		}
		if mgr.Active() {
			t.Error("manager should not be active after failed Setup")
		}
	})
}

// TestACMEIntegration_IngressWithACMEMode wires IngressManager with ACMEManager
// and verifies that ACME mode rules are added and removed correctly.
func TestACMEIntegration_IngressWithACMEMode(t *testing.T) {
	// Create and setup ACMEManager.
	acmeCfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"example.com"},
		Email:        "admin@example.com",
	}
	acmeMgr := NewACMEManager(acmeCfg, discardLogger())
	if err := acmeMgr.Setup(); err != nil {
		t.Fatalf("ACME Setup: %v", err)
	}

	// Create IngressManager with ACMEManager.
	ctrl := &mockIngressController{}
	cfg := Config{
		Enabled:        true,
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger(), acmeMgr)

	// Setup IngressManager.
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Ingress Setup: %v", err)
	}
	ctrl.resetIngress()

	// AddRule with Mode="acme" succeeds.
	rule := api.IngressRule{
		RuleID:     "acme-rule-1",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:8080",
		Mode:       "acme",
		Hostname:   "example.com",
	}
	if err := mgr.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	// Verify the listener was created (Listen was called with a non-nil TLS config).
	listenCalls := ctrl.ingressCallsFor("Listen")
	if len(listenCalls) != 1 {
		t.Fatalf("Listen calls = %d, want 1", len(listenCalls))
	}
	if listenCalls[0].Args[1] == nil {
		t.Error("Listen should have been called with non-nil TLS config for ACME mode")
	}

	// Verify the rule is tracked.
	ids := mgr.RuleIDs()
	if len(ids) != 1 || ids[0] != "acme-rule-1" {
		t.Errorf("RuleIDs = %v, want [acme-rule-1]", ids)
	}

	// RemoveRule works.
	mgr.RemoveRule("acme-rule-1")
	if len(mgr.RuleIDs()) != 0 {
		t.Errorf("RuleIDs after remove = %v, want empty", mgr.RuleIDs())
	}

	closeCalls := ctrl.ingressCallsFor("Close")
	if len(closeCalls) != 1 {
		t.Errorf("Close calls = %d, want 1", len(closeCalls))
	}

	// Teardown both managers.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Ingress Teardown: %v", err)
	}
	if err := acmeMgr.Teardown(); err != nil {
		t.Fatalf("ACME Teardown: %v", err)
	}
}

// TestACMEIntegration_IngressACMEModeErrors tests error cases for ACME mode
// in IngressManager.
func TestACMEIntegration_IngressACMEModeErrors(t *testing.T) {
	// AddRule with Mode="acme" when ACMEManager is nil.
	t.Run("nil_acme_manager", func(t *testing.T) {
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

		rule := api.IngressRule{
			RuleID:     "acme-nil-1",
			ListenPort: 0,
			TargetAddr: "10.0.0.5:8080",
			Mode:       "acme",
			Hostname:   "example.com",
		}
		err := mgr.AddRule(rule)
		if err == nil {
			t.Fatal("AddRule should return error when ACMEManager is nil")
		}
		if !strings.Contains(err.Error(), "ACME mode requires ACMEManager") {
			t.Errorf("error = %q, want to contain %q", err.Error(), "ACME mode requires ACMEManager")
		}

		_ = mgr.Teardown()
	})

	// AddRule with Mode="acme" when hostname is empty.
	t.Run("empty_hostname", func(t *testing.T) {
		acmeCfg := ACMEConfig{
			Enabled:      true,
			CacheDir:     t.TempDir(),
			AllowedHosts: []string{"example.com"},
		}
		acmeMgr := NewACMEManager(acmeCfg, discardLogger())
		if err := acmeMgr.Setup(); err != nil {
			t.Fatalf("ACME Setup: %v", err)
		}

		ctrl := &mockIngressController{}
		cfg := Config{
			Enabled:        true,
			IngressEnabled: true,
		}
		cfg.ApplyDefaults()

		mgr := NewIngressManager(ctrl, cfg, discardLogger(), acmeMgr)
		if err := mgr.Setup(); err != nil {
			t.Fatalf("Setup: %v", err)
		}

		rule := api.IngressRule{
			RuleID:     "acme-no-host-1",
			ListenPort: 0,
			TargetAddr: "10.0.0.5:8080",
			Mode:       "acme",
			Hostname:   "",
		}
		err := mgr.AddRule(rule)
		if err == nil {
			t.Fatal("AddRule should return error when hostname is empty")
		}
		if !strings.Contains(err.Error(), "hostname is required for ACME mode") {
			t.Errorf("error = %q, want to contain %q", err.Error(), "hostname is required for ACME mode")
		}

		_ = mgr.Teardown()
		_ = acmeMgr.Teardown()
	})

	// AddRule with Mode="acme" when ACME manager is not active (not Setup).
	t.Run("acme_not_active", func(t *testing.T) {
		acmeCfg := ACMEConfig{
			Enabled:      true,
			CacheDir:     t.TempDir(),
			AllowedHosts: []string{"example.com"},
		}
		// Create but do NOT Setup — manager is not active.
		acmeMgr := NewACMEManager(acmeCfg, discardLogger())

		ctrl := &mockIngressController{}
		cfg := Config{
			Enabled:        true,
			IngressEnabled: true,
		}
		cfg.ApplyDefaults()

		mgr := NewIngressManager(ctrl, cfg, discardLogger(), acmeMgr)
		if err := mgr.Setup(); err != nil {
			t.Fatalf("Setup: %v", err)
		}

		rule := api.IngressRule{
			RuleID:     "acme-inactive-1",
			ListenPort: 0,
			TargetAddr: "10.0.0.5:8080",
			Mode:       "acme",
			Hostname:   "example.com",
		}
		err := mgr.AddRule(rule)
		if err == nil {
			t.Fatal("AddRule should return error when ACME manager is not active")
		}
		if !strings.Contains(err.Error(), "ACME manager is not active") {
			t.Errorf("error = %q, want to contain %q", err.Error(), "ACME manager is not active")
		}

		_ = mgr.Teardown()
	})
}

// TestACMEIntegration_TLSConfigProperties tests that TLSConfig returns a
// properly configured *tls.Config.
func TestACMEIntegration_TLSConfigProperties(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"example.com"},
		Email:        "admin@example.com",
	}

	mgr := NewACMEManager(cfg, discardLogger())
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	tlsCfg := mgr.TLSConfig()
	if tlsCfg == nil {
		t.Fatal("TLSConfig should not be nil after Setup")
	}

	// Verify MinVersion = tls.VersionTLS12.
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", tlsCfg.MinVersion, tls.VersionTLS12)
	}

	// Verify GetCertificate is non-nil (it's the autocert.Manager's GetCertificate).
	if tlsCfg.GetCertificate == nil {
		t.Error("GetCertificate should be set")
	}

	// Cleanup.
	_ = mgr.Teardown()
}

// TestACMEIntegration_ConcurrentTLSConfigAccess exercises concurrent access
// to ACMEManager methods to verify no data races. Run with -race.
func TestACMEIntegration_ConcurrentTLSConfigAccess(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"example.com", "app.example.com"},
		Email:        "admin@example.com",
		// Use a non-routable ACME directory URL to prevent real HTTP
		// connections that would leak HTTP/2 goroutines (detected by goleak).
		ACMEDirectoryURL: "https://192.0.2.1:1/directory",
	}

	mgr := NewACMEManager(cfg, discardLogger())
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// TLSConfig() — should not race.
			tlsCfg := mgr.TLSConfig()
			if tlsCfg == nil {
				t.Error("TLSConfig should not be nil while active")
			}

			// Active() — should not race.
			if !mgr.Active() {
				t.Error("Active should be true while active")
			}

			// AllowedHosts() — should not race.
			hosts := mgr.AllowedHosts()
			if len(hosts) != 2 {
				t.Errorf("AllowedHosts len = %d, want 2", len(hosts))
			}

			// GetCertificate(nil) — the underlying autocert.Manager
			// panics on nil hello, so we recover. This verifies the
			// method doesn't deadlock or race.
			func() {
				defer func() { _ = recover() }()
				_, _ = mgr.GetCertificate(nil)
			}()
		}()
	}

	wg.Wait()

	// Cleanup.
	_ = mgr.Teardown()
}

// TestACMEIntegration_IngressReconcileWithACME wires IngressManager with
// ACMEManager and a real Reconciler. Verifies that reconciliation correctly
// adds ACME mode rules, then updates them when state changes.
func TestACMEIntegration_IngressReconcileWithACME(t *testing.T) {
	// Create and setup ACMEManager.
	acmeCfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"app.example.com", "api.example.com"},
		Email:        "admin@example.com",
	}
	acmeMgr := NewACMEManager(acmeCfg, discardLogger())
	if err := acmeMgr.Setup(); err != nil {
		t.Fatalf("ACME Setup: %v", err)
	}

	// Create IngressManager with ACMEManager.
	ctrl := &mockIngressController{}
	cfg := Config{
		Enabled:        true,
		IngressEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewIngressManager(ctrl, cfg, discardLogger(), acmeMgr)
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Ingress Setup: %v", err)
	}
	ctrl.resetIngress()

	// Initial state: one ACME ingress rule.
	state1 := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			Ingress: &api.IngressConfig{
				Enabled: true,
				Rules: []api.IngressRule{
					{
						RuleID:     "acme-reconcile-1",
						ListenPort: 0,
						TargetAddr: "10.0.0.5:8080",
						Mode:       "acme",
						Hostname:   "app.example.com",
					},
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
	go func() { done <- rec.Run(ctx, "node-acme") }()

	// Wait for initial cycle: acme-reconcile-1 should be added (1 Listen call).
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ctrl.ingressCallsFor("Listen")) >= 1
	})

	ids := mgr.RuleIDs()
	if len(ids) != 1 || ids[0] != "acme-reconcile-1" {
		t.Errorf("RuleIDs after initial reconcile = %v, want [acme-reconcile-1]", ids)
	}

	// Update state: remove acme-reconcile-1, add acme-reconcile-2.
	state2 := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			Ingress: &api.IngressConfig{
				Enabled: true,
				Rules: []api.IngressRule{
					{
						RuleID:     "acme-reconcile-2",
						ListenPort: 0,
						TargetAddr: "10.0.0.6:9090",
						Mode:       "acme",
						Hostname:   "api.example.com",
					},
				},
			},
		},
	}
	fetcher.setState(state2)
	rec.TriggerReconcile()

	// Wait for: 1 Close (acme-reconcile-1 removed) + 1 more Listen (acme-reconcile-2 added).
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ctrl.ingressCallsFor("Listen")) >= 2 &&
			len(ctrl.ingressCallsFor("Close")) >= 1
	})

	ids = mgr.RuleIDs()
	if len(ids) != 1 || ids[0] != "acme-reconcile-2" {
		t.Errorf("RuleIDs after second reconcile = %v, want [acme-reconcile-2]", ids)
	}

	cancel()
	<-done

	// Clean up any remaining listeners/goroutines.
	_ = mgr.Teardown()
	_ = acmeMgr.Teardown()
}
