package registration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

const maxTokenLength = 512

// TokenResult holds the resolved token and its source metadata.
type TokenResult struct {
	Value    string // the token value
	FilePath string // non-empty if the token was read from a file (for cleanup)
}

// MetadataProvider reads a bootstrap token from a cloud metadata service.
type MetadataProvider interface {
	ReadToken(ctx context.Context) (string, error)
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

	// 1d. Metadata service.
	if r.cfg.UseMetadata && r.metadata != nil {
		token, err := r.metadata.ReadToken(ctx)
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

func validateToken(token string) error {
	if len(token) > maxTokenLength {
		return fmt.Errorf("registration: token exceeds maximum length of %d bytes", maxTokenLength)
	}
	for i := 0; i < len(token); i++ {
		if token[i] < 0x20 || token[i] > 0x7E {
			return errors.New("registration: token contains non-printable characters")
		}
	}
	return nil
}
