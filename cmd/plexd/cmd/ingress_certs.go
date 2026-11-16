package cmd

import (
	"context"
	"fmt"

	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/nodeapi"
)

// ingressCertFetcher reads the certificate Secret of a bridge's terminate
// rule: it fetches the sealed envelope of one version with the node's own
// credential and opens it under the node secret key. Neither the value nor the
// key reaches an error.
type ingressCertFetcher struct {
	client nodeapi.SecretFetcher
	nodeID string
	nsk    []byte
}

var _ bridge.CertificateSecretFetcher = ingressCertFetcher{}

// FetchCertificateSecret returns the plaintext of version of the Secret name.
// It refuses an envelope of another version, so a certificate is always the
// version the secret inventory listed.
func (f ingressCertFetcher) FetchCertificateSecret(ctx context.Context, name string, version int) ([]byte, error) {
	env, err := f.client.FetchSecret(ctx, f.nodeID, name, version)
	if err != nil {
		return nil, fmt.Errorf("fetch secret %q version %d: %w", name, version, err)
	}
	if env.Version != version {
		return nil, fmt.Errorf("fetch secret %q: asked for version %d, got %d", name, version, env.Version)
	}
	value, err := nodeapi.DecryptSecret(f.nsk, env.Data)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret %q version %d: %w", name, version, err)
	}
	return []byte(value), nil
}
