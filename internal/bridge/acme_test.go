package bridge

import (
	"crypto/tls"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ACMEManager tests
// ---------------------------------------------------------------------------

func TestACMEManager_NewACMEManager(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     "/tmp/acme-test",
		AllowedHosts: []string{"example.com"},
		Email:        "admin@example.com",
	}

	mgr := NewACMEManager(cfg, discardLogger())

	if mgr == nil {
		t.Fatal("NewACMEManager returned nil")
	}
	if mgr.Active() {
		t.Error("new manager should not be active before Setup")
	}
	if mgr.TLSConfig() != nil {
		t.Error("TLSConfig should be nil before Setup")
	}
}

func TestACMEManager_Setup_Disabled(t *testing.T) {
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
	if mgr.TLSConfig() != nil {
		t.Error("TLSConfig should be nil when disabled")
	}
}

func TestACMEManager_Setup_Success(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"example.com", "www.example.com"},
		Email:        "admin@example.com",
	}

	mgr := NewACMEManager(cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	if !mgr.Active() {
		t.Error("manager should be active after Setup")
	}
	if mgr.TLSConfig() == nil {
		t.Error("TLSConfig should not be nil after Setup")
	}
}

func TestACMEManager_Setup_MissingCacheDir(t *testing.T) {
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

	if !strings.Contains(err.Error(), "bridge: acme:") {
		t.Errorf("error should contain 'bridge: acme:', got %q", err.Error())
	}

	if mgr.Active() {
		t.Error("manager should not be active after failed Setup")
	}
}

func TestACMEManager_Setup_MissingAllowedHosts(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: nil,
	}

	mgr := NewACMEManager(cfg, discardLogger())

	err := mgr.Setup()
	if err == nil {
		t.Fatal("Setup should return error for empty AllowedHosts")
	}

	if !strings.Contains(err.Error(), "bridge: acme:") {
		t.Errorf("error should contain 'bridge: acme:', got %q", err.Error())
	}

	if mgr.Active() {
		t.Error("manager should not be active after failed Setup")
	}
}

func TestACMEManager_Teardown_Success(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"example.com"},
	}

	mgr := NewACMEManager(cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !mgr.Active() {
		t.Fatal("manager should be active after Setup")
	}

	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	if mgr.Active() {
		t.Error("manager should not be active after Teardown")
	}
	if mgr.TLSConfig() != nil {
		t.Error("TLSConfig should be nil after Teardown")
	}
}

func TestACMEManager_Teardown_Idempotent(t *testing.T) {
	cfg := ACMEConfig{
		Enabled: false,
	}

	mgr := NewACMEManager(cfg, discardLogger())

	// Teardown when not active should return nil.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("first Teardown: %v", err)
	}
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

func TestACMEManager_TLSConfig_NotActive(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"example.com"},
	}

	mgr := NewACMEManager(cfg, discardLogger())

	// Not yet set up — should return nil.
	if mgr.TLSConfig() != nil {
		t.Error("TLSConfig should be nil when not active")
	}
}

func TestACMEManager_TLSConfig_Active(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"example.com"},
	}

	mgr := NewACMEManager(cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	tlsCfg := mgr.TLSConfig()
	if tlsCfg == nil {
		t.Fatal("TLSConfig should not be nil when active")
	}

	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", tlsCfg.MinVersion, tls.VersionTLS12)
	}

	if tlsCfg.GetCertificate == nil {
		t.Error("GetCertificate should be set")
	}

	// Cleanup.
	_ = mgr.Teardown()
}

func TestACMEManager_GetCertificate_NotActive(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"example.com"},
	}

	mgr := NewACMEManager(cfg, discardLogger())

	_, err := mgr.GetCertificate(&tls.ClientHelloInfo{})
	if err == nil {
		t.Fatal("GetCertificate should return error when not active")
	}

	if !strings.Contains(err.Error(), "bridge: acme:") {
		t.Errorf("error should contain 'bridge: acme:', got %q", err.Error())
	}
}

func TestACMEManager_AllowedHosts(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"a.example.com", "b.example.com"},
	}

	mgr := NewACMEManager(cfg, discardLogger())

	hosts := mgr.AllowedHosts()
	if len(hosts) != 2 {
		t.Fatalf("AllowedHosts len = %d, want 2", len(hosts))
	}
	if hosts[0] != "a.example.com" || hosts[1] != "b.example.com" {
		t.Errorf("AllowedHosts = %v, want [a.example.com b.example.com]", hosts)
	}

	// Mutating the returned slice should not affect the original.
	hosts[0] = "mutated.example.com"

	hostsAgain := mgr.AllowedHosts()
	if hostsAgain[0] != "a.example.com" {
		t.Errorf("AllowedHosts was mutated: got %q, want %q", hostsAgain[0], "a.example.com")
	}
}

func TestACMEManager_Active(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{"example.com"},
	}

	mgr := NewACMEManager(cfg, discardLogger())

	if mgr.Active() {
		t.Error("should not be active before Setup")
	}

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	if !mgr.Active() {
		t.Error("should be active after Setup")
	}

	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	if mgr.Active() {
		t.Error("should not be active after Teardown")
	}
}

func TestACMEManager_Setup_WithACMEDirectoryURL(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:          true,
		CacheDir:         t.TempDir(),
		AllowedHosts:     []string{"example.com"},
		ACMEDirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
	}

	mgr := NewACMEManager(cfg, discardLogger())

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	if !mgr.Active() {
		t.Error("manager should be active after Setup with custom directory URL")
	}

	// Cleanup.
	_ = mgr.Teardown()
}

func TestACMEManager_Setup_WithEmptyAllowedHosts(t *testing.T) {
	cfg := ACMEConfig{
		Enabled:      true,
		CacheDir:     t.TempDir(),
		AllowedHosts: []string{},
	}

	mgr := NewACMEManager(cfg, discardLogger())

	err := mgr.Setup()
	if err == nil {
		t.Fatal("Setup should return error for empty AllowedHosts slice")
	}

	if !strings.Contains(err.Error(), "bridge: acme:") {
		t.Errorf("error should contain 'bridge: acme:', got %q", err.Error())
	}
}
