package kubernetes

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesConfig_ApplyDefaults_InCluster(t *testing.T) {
	env := &KubernetesEnvironment{
		InCluster: true,
		Namespace: "plexd-system",
		NodeName:  "node-1",
	}
	cfg := Config{}
	cfg.ApplyDefaults(env)

	if !cfg.Enabled {
		t.Error("Enabled = false, want true when InCluster")
	}
	if !cfg.CRDEnabled {
		t.Error("CRDEnabled = false, want true when InCluster")
	}
	if cfg.Namespace != "plexd-system" {
		t.Errorf("Namespace = %q, want %q", cfg.Namespace, "plexd-system")
	}
	if cfg.AuditLogPath != DefaultAuditLogPath {
		t.Errorf("AuditLogPath = %q, want %q", cfg.AuditLogPath, DefaultAuditLogPath)
	}
	if cfg.CRDSyncInterval != DefaultCRDSyncInterval {
		t.Errorf("CRDSyncInterval = %v, want %v", cfg.CRDSyncInterval, DefaultCRDSyncInterval)
	}
	if cfg.TokenPath != DefaultTokenPath {
		t.Errorf("TokenPath = %q, want %q", cfg.TokenPath, DefaultTokenPath)
	}
}

func TestKubernetesConfig_ApplyDefaults_NotInCluster(t *testing.T) {
	env := &KubernetesEnvironment{
		InCluster: false,
	}
	cfg := Config{}
	cfg.ApplyDefaults(env)

	if cfg.Enabled {
		t.Error("Enabled = true, want false when not InCluster")
	}
	if cfg.CRDEnabled {
		t.Error("CRDEnabled = true, want false when not InCluster")
	}
	if cfg.Namespace != "" {
		t.Errorf("Namespace = %q, want empty", cfg.Namespace)
	}
}

func TestKubernetesConfig_ApplyDefaults_NilEnv(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults(nil)

	if cfg.Enabled {
		t.Error("Enabled = true, want false with nil env")
	}
	if cfg.AuditLogPath != DefaultAuditLogPath {
		t.Errorf("AuditLogPath = %q, want %q", cfg.AuditLogPath, DefaultAuditLogPath)
	}
	if cfg.CRDSyncInterval != DefaultCRDSyncInterval {
		t.Errorf("CRDSyncInterval = %v, want %v", cfg.CRDSyncInterval, DefaultCRDSyncInterval)
	}
	if cfg.TokenPath != DefaultTokenPath {
		t.Errorf("TokenPath = %q, want %q", cfg.TokenPath, DefaultTokenPath)
	}
}

func TestKubernetesConfig_ApplyDefaults_PreservesExisting(t *testing.T) {
	env := &KubernetesEnvironment{
		InCluster: true,
		Namespace: "auto-ns",
	}
	cfg := Config{
		Namespace:       "custom-ns",
		AuditLogPath:    "/custom/audit.log",
		CRDSyncInterval: 30 * time.Second,
		TokenPath:       "/custom/token",
	}
	cfg.ApplyDefaults(env)

	if cfg.Namespace != "custom-ns" {
		t.Errorf("Namespace = %q, want %q (should preserve explicit value)", cfg.Namespace, "custom-ns")
	}
	if cfg.AuditLogPath != "/custom/audit.log" {
		t.Errorf("AuditLogPath = %q, want %q", cfg.AuditLogPath, "/custom/audit.log")
	}
}

func TestKubernetesConfig_Validate_ValidConfig(t *testing.T) {
	cfg := Config{Enabled: true, Namespace: "plexd-system"}
	cfg.ApplyDefaults(nil)
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestKubernetesConfig_Validate_DisabledSkipsValidation(t *testing.T) {
	cfg := Config{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for disabled config", err)
	}
}

func TestKubernetesConfig_Validate_MissingNamespace(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		Namespace:       "",
		AuditLogPath:    DefaultAuditLogPath,
		CRDSyncInterval: DefaultCRDSyncInterval,
		TokenPath:       DefaultTokenPath,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty Namespace")
	}
	want := "Namespace is required when Kubernetes is enabled"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("Validate() error = %q, want to contain %q", err.Error(), want)
	}
}

func TestKubernetesConfig_Validate_RejectsEmptyAuditLogPath(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		Namespace:       "plexd-system",
		AuditLogPath:    "",
		CRDSyncInterval: 10 * time.Second,
		TokenPath:       DefaultTokenPath,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty AuditLogPath")
	}
}

func TestKubernetesConfig_Validate_RejectsLowCRDSyncInterval(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		Namespace:       "plexd-system",
		AuditLogPath:    DefaultAuditLogPath,
		CRDSyncInterval: 500 * time.Millisecond,
		TokenPath:       DefaultTokenPath,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for low CRDSyncInterval")
	}
}

func TestKubernetesConfig_Validate_RejectsEmptyTokenPath(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		Namespace:       "plexd-system",
		AuditLogPath:    DefaultAuditLogPath,
		CRDSyncInterval: 10 * time.Second,
		TokenPath:       "",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty TokenPath")
	}
}
