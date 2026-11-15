// Integration tests — ACME with Ingress

package bridge

import (
	"crypto/tls"
	"strings"
	"sync"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
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

// TestACMEIntegration_ACMERuleIsHeldNotServed applies an acme rule with an
// active ACMEManager: the block names no certificate source yet, so the rule
// is held and not served, and its port opens no listener.
func TestACMEIntegration_ACMERuleIsHeldNotServed(t *testing.T) {
	acmeMgr := NewACMEManager(ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"example.com"},
		Email:        "admin@example.com",
	}, discardLogger())
	if err := acmeMgr.Setup(); err != nil {
		t.Fatalf("ACME Setup: %v", err)
	}
	defer func() { _ = acmeMgr.Teardown() }()

	ctrl := newLoopbackIngressController(t)
	cfg := Config{Enabled: true, IngressEnabled: true}
	cfg.ApplyDefaults()
	mgr := NewIngressManager(ctrl, cfg, discardLogger(), acmeMgr)
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Ingress Setup: %v", err)
	}
	defer func() { _ = mgr.Teardown() }()

	rule := api.IngressRule{
		ID:            "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f1",
		Slug:          "api",
		ListenPort:    443,
		Mode:          api.IngressModeACME,
		SNIHost:       "example.com",
		TargetNodeID:  "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1",
		TargetAddress: "10.0.0.5",
		TargetPort:    8080,
	}
	if err := mgr.Apply([]api.IngressRule{rule}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	states := mgr.RuleStates()
	if len(states) != 1 || states[0].Served || states[0].Reason != IngressReasonModeNotServed {
		t.Fatalf("RuleStates = %+v, want one state with reason %q", states, IngressReasonModeNotServed)
	}
	if got := len(ctrl.ingressCallsFor("Listen")); got != 0 {
		t.Errorf("Listen calls = %d, want 0", got)
	}
	status := mgr.IngressStatus()
	if status.RuleCount != 0 || !status.ACMEEnabled {
		t.Errorf("IngressStatus = %+v, want no served rule and ACMEEnabled", status)
	}
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

			// GetCertificate() — should not race. The hello carries no
			// server name, so autocert refuses it before it reads its
			// cache or the network. Never pass a nil hello: autocert
			// dereferences it, and on windows/amd64 the access
			// violation that raises can corrupt the heap
			// (golang/go#81238).
			cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{})
			if cert != nil || err == nil || !strings.HasPrefix(err.Error(), "acme/autocert: ") {
				t.Errorf("GetCertificate(empty hello) = %v, %v; want nil and an acme/autocert error", cert, err)
			}
		}()
	}

	wg.Wait()

	// Cleanup.
	_ = mgr.Teardown()
}
