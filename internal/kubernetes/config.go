package kubernetes

import (
	"errors"
	"time"
)

// DefaultAuditLogPath is the default path to the Kubernetes audit log.
const DefaultAuditLogPath = "/var/log/kubernetes/audit/audit.log"

// DefaultCRDSyncInterval is the default interval for syncing CRD state.
const DefaultCRDSyncInterval = 10 * time.Second

// Config holds the configuration for the Kubernetes integration.
type Config struct {
	// Enabled controls whether Kubernetes integration is active.
	// Default: false (must be explicitly enabled).
	Enabled bool

	// CRDEnabled controls whether CRD management is active.
	// Default: true when Enabled is true.
	CRDEnabled bool

	// Namespace overrides the auto-detected namespace. If empty, the
	// namespace is read from the service account metadata at runtime.
	Namespace string

	// AuditLogPath is the filesystem path to the Kubernetes audit log.
	// Default: /var/log/kubernetes/audit/audit.log.
	AuditLogPath string

	// CRDSyncInterval controls how often CRD state is reconciled.
	// Must be at least 1s. Default: 10s.
	CRDSyncInterval time.Duration

	// TokenPath is the filesystem path to the service account token.
	// Default: /var/run/secrets/kubernetes.io/serviceaccount/token.
	TokenPath string
}

// ApplyDefaults sets default values for zero-valued fields. If env is non-nil
// and InCluster is true, auto-detected values are used for unset fields.
func (c *Config) ApplyDefaults(env *KubernetesEnvironment) {
	if env != nil && env.InCluster {
		c.Enabled = true
		c.CRDEnabled = true
		if c.Namespace == "" {
			c.Namespace = env.Namespace
		}
	}
	if c.AuditLogPath == "" {
		c.AuditLogPath = DefaultAuditLogPath
	}
	if c.CRDSyncInterval == 0 {
		c.CRDSyncInterval = DefaultCRDSyncInterval
	}
	if c.TokenPath == "" {
		c.TokenPath = DefaultTokenPath
	}
}

// Validate checks that configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Namespace == "" {
		return errors.New("kubernetes: config: Namespace is required when Kubernetes is enabled")
	}
	if c.AuditLogPath == "" {
		return errors.New("kubernetes: config: AuditLogPath must not be empty")
	}
	if c.CRDSyncInterval < time.Second {
		return errors.New("kubernetes: config: CRDSyncInterval must be at least 1s")
	}
	if c.TokenPath == "" {
		return errors.New("kubernetes: config: TokenPath must not be empty")
	}
	return nil
}
