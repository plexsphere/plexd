package registration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

const maxTokenLength = 512

const maxValueLength = 4096

// TokenResult holds the resolved token and its source metadata.
type TokenResult struct {
	Value    string // the token value
	FilePath string // non-empty if the token was read from a file (for cleanup)
}

// MetadataProvider reads a value from a cloud metadata service at a given path.
type MetadataProvider interface {
	ReadValue(ctx context.Context, path string) (string, error)
}

// TokenResolver resolves the bootstrap token from multiple sources.
type TokenResolver struct {
	cfg      *Config
	metadata MetadataProvider // nil = skip metadata source
}

// NewTokenResolver creates a new TokenResolver.
func NewTokenResolver(cfg *Config, metadata MetadataProvider) *TokenResolver {
	return &TokenResolver{cfg: cfg, metadata: metadata}
}

// Resolve locates a bootstrap token by checking sources in priority order:
// direct value, file, environment variable, metadata service.
func (r *TokenResolver) Resolve(ctx context.Context) (*TokenResult, error) {
	// 1a. Direct value.
	if v := strings.TrimSpace(r.cfg.TokenValue); v != "" {
		if err := validateToken(v); err != nil {
			return nil, err
		}
		return &TokenResult{Value: v}, nil
	}

	// 1b. File.
	if r.cfg.TokenFile != "" {
		data, err := os.ReadFile(r.cfg.TokenFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("registration: read token file %q: %w", r.cfg.TokenFile, err)
		}
		if err == nil {
			if v := strings.TrimSpace(string(data)); v != "" {
				if err := validateToken(v); err != nil {
					return nil, err
				}
				return &TokenResult{Value: v, FilePath: r.cfg.TokenFile}, nil
			}
		}
	}

	// 1c. Environment variable.
	if r.cfg.TokenEnv != "" {
		if v := strings.TrimSpace(os.Getenv(r.cfg.TokenEnv)); v != "" {
			if err := validateToken(v); err != nil {
				return nil, err
			}
			return &TokenResult{Value: v}, nil
		}
	}

	// 1d. Metadata service. The token is the one input whose absence stops
	// registration, so a read error must surface — reporting a transient IMDS
	// failure or a misconfigured path as "no token found" sends the operator to
	// audit the wrong thing. Only ErrMetadataNotFound ("not provisioned") falls
	// through to the next source.
	if r.cfg.UseMetadata && r.metadata != nil {
		token, err := r.metadata.ReadValue(ctx, r.cfg.MetadataTokenPath)
		if err != nil && !errors.Is(err, ErrMetadataNotFound) {
			return nil, fmt.Errorf("registration: read token from metadata: %w", err)
		}
		if err == nil {
			v := strings.TrimSpace(token)
			if v != "" {
				if err := validateToken(v); err != nil {
					return nil, err
				}
				return &TokenResult{Value: v}, nil
			}
		}
	}

	// No source provided a token.
	metadataStatus := "no"
	if r.cfg.UseMetadata {
		metadataStatus = "yes"
	}
	return nil, fmt.Errorf("registration: no bootstrap token found (checked: direct value, file [%s], env [%s], metadata [%s])",
		r.cfg.TokenFile, r.cfg.TokenEnv, metadataStatus)
}

// ResolveValue resolves the registration input named name from a direct
// setting or the cloud metadata service. A non-empty trimmed direct value
// always wins; otherwise, when metadata is enabled and a provider is set, the
// value at metadataPath is read. A path the metadata service does not serve
// (ErrMetadataNotFound) means "not provisioned" and yields an empty string, so
// optional inputs stay optional. Every other read error is returned: a
// transient IMDS failure must not be reported as a missing config setting.
func (r *TokenResolver) ResolveValue(ctx context.Context, name, direct, metadataPath string) (string, error) {
	if v := strings.TrimSpace(direct); v != "" {
		if err := validateValue(name, v, maxValueLength); err != nil {
			return "", err
		}
		return v, nil
	}

	if r.cfg.UseMetadata && r.metadata != nil {
		raw, err := r.metadata.ReadValue(ctx, metadataPath)
		switch {
		case errors.Is(err, ErrMetadataNotFound):
			return "", nil
		case err != nil:
			return "", fmt.Errorf("registration: read %s from metadata: %w", name, err)
		}
		if v := strings.TrimSpace(raw); v != "" {
			if err := validateValue(name, v, maxValueLength); err != nil {
				return "", err
			}
			return v, nil
		}
	}

	return "", nil
}

func validateToken(token string) error {
	return validateValue("token", token, maxTokenLength)
}

func validateValue(name, v string, maxLen int) error {
	if len(v) > maxLen {
		return fmt.Errorf("registration: %s exceeds maximum length of %d bytes", name, maxLen)
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7E {
			return fmt.Errorf("registration: %s contains non-printable characters", name)
		}
	}
	return nil
}
