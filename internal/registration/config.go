package registration

import (
	"errors"
	"time"
)

// Config holds the configuration for the agent registration process.
// Config is passed as a constructor argument — no file I/O in this package.
type Config struct {
	// DataDir is the path to the data directory (required).
	DataDir string `yaml:"data_dir"`

	// ProjectID is the platform project UUID the node registers into
	// (required for fresh registration).
	ProjectID string `yaml:"project_id"`

	// ResourceHandle is the platform Resource handle the node binds to
	// (required for fresh registration).
	ResourceHandle string `yaml:"resource_handle"`

	// RequestedResourceID is an optional override used when substrate naming
	// differs from the platform handle.
	RequestedResourceID string `yaml:"requested_resource_id"`

	// TokenFile is the path to the bootstrap token file.
	// Default: /etc/plexd/bootstrap-token
	TokenFile string `yaml:"token_file"`

	// TokenEnv is the environment variable name for the bootstrap token.
	// Default: PLEXD_BOOTSTRAP_TOKEN
	TokenEnv string `yaml:"token_env"`

	// TokenValue is a direct token value override.
	TokenValue string `yaml:"token_value"`

	// UseMetadata enables cloud metadata service for registration.
	// Default: false
	UseMetadata bool `yaml:"use_metadata"`

	// MetadataTokenPath is the metadata key path used to retrieve the
	// bootstrap token from an instance metadata service (e.g. IMDS).
	// Default: /plexd/bootstrap-token
	MetadataTokenPath string `yaml:"metadata_token_path"`

	// MetadataTimeout is the maximum time to wait for a metadata service
	// response.
	// Default: 2s
	MetadataTimeout time.Duration `yaml:"metadata_timeout"`

	// MaxRetryDuration is the maximum duration to retry registration.
	// Default: 5m
	MaxRetryDuration time.Duration `yaml:"max_retry_duration"`
}

// DefaultTokenFile is the default path to the bootstrap token file.
const DefaultTokenFile = "/etc/plexd/bootstrap-token"

// DefaultTokenEnv is the default environment variable name for the bootstrap token.
const DefaultTokenEnv = "PLEXD_BOOTSTRAP_TOKEN"

// DefaultMetadataTokenPath is the default metadata key path for the bootstrap token.
const DefaultMetadataTokenPath = "/plexd/bootstrap-token"

// DefaultMetadataProjectIDPath is the default metadata key path for the project ID.
const DefaultMetadataProjectIDPath = "/plexd/project-id"

// DefaultMetadataResourceHandlePath is the default metadata key path for the resource handle.
const DefaultMetadataResourceHandlePath = "/plexd/resource-handle"

// DefaultMetadataRequestedResourceIDPath is the default metadata key path for the requested resource ID.
const DefaultMetadataRequestedResourceIDPath = "/plexd/requested-resource-id"

// DefaultMetadataTimeout is the default timeout for metadata service requests.
const DefaultMetadataTimeout = 2 * time.Second

// DefaultMaxRetryDuration is the default maximum retry duration.
const DefaultMaxRetryDuration = 5 * time.Minute

// ApplyDefaults sets default values for zero-valued fields.
func (c *Config) ApplyDefaults() {
	if c.TokenFile == "" {
		c.TokenFile = DefaultTokenFile
	}
	if c.TokenEnv == "" {
		c.TokenEnv = DefaultTokenEnv
	}
	if c.MetadataTokenPath == "" {
		c.MetadataTokenPath = DefaultMetadataTokenPath
	}
	if c.MetadataTimeout == 0 {
		c.MetadataTimeout = DefaultMetadataTimeout
	}
	if c.MaxRetryDuration == 0 {
		c.MaxRetryDuration = DefaultMaxRetryDuration
	}
}

// Validate checks that required fields are set.
func (c *Config) Validate() error {
	if c.DataDir == "" {
		return errors.New("registration: config: DataDir is required")
	}
	return nil
}
