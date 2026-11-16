package cmd

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// fakeIngressSecretFetcher answers FetchSecret with env or err and records
// the arguments of the last call.
type fakeIngressSecretFetcher struct {
	env *api.SecretEnvelope
	err error

	nodeID  string
	name    string
	version int
}

func (f *fakeIngressSecretFetcher) FetchSecret(_ context.Context, nodeID, name string, version int) (*api.SecretEnvelope, error) {
	f.nodeID, f.name, f.version = nodeID, name, version
	return f.env, f.err
}

// sealIngressSecret seals plaintext under nsk as the control plane seals a
// secret: AES-256-GCM, <12-byte nonce> || <ciphertext + 16-byte tag>, no AAD.
func sealIngressSecret(t *testing.T, nsk, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(nsk)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

// ingressTestNSK returns a random 32-byte node secret key.
func ingressTestNSK(t *testing.T) []byte {
	t.Helper()
	nsk := make([]byte, 32)
	if _, err := rand.Read(nsk); err != nil {
		t.Fatalf("nsk: %v", err)
	}
	return nsk
}

func TestIngressCertFetcher_FetchCertificateSecret(t *testing.T) {
	nsk := ingressTestNSK(t)
	value := []byte("-----BEGIN CERTIFICATE-----\nnot checked here\n-----END CERTIFICATE-----\n")

	t.Run("decrypts the envelope", func(t *testing.T) {
		client := &fakeIngressSecretFetcher{env: &api.SecretEnvelope{Data: sealIngressSecret(t, nsk, value), Version: 3}}
		f := ingressCertFetcher{client: client, nodeID: "node-1", nsk: nsk}
		got, err := f.FetchCertificateSecret(t.Context(), "tls", 3)
		if err != nil {
			t.Fatalf("FetchCertificateSecret: %v", err)
		}
		if !bytes.Equal(got, value) {
			t.Errorf("value = %q, want %q", got, value)
		}
		if client.nodeID != "node-1" || client.name != "tls" || client.version != 3 {
			t.Errorf("FetchSecret(%q, %q, %d), want (node-1, tls, 3)", client.nodeID, client.name, client.version)
		}
	})

	t.Run("fetch error", func(t *testing.T) {
		client := &fakeIngressSecretFetcher{err: fmt.Errorf("api: %w", api.ErrNotFound)}
		f := ingressCertFetcher{client: client, nodeID: "node-1", nsk: nsk}
		_, err := f.FetchCertificateSecret(t.Context(), "tls", 3)
		if !errors.Is(err, api.ErrNotFound) {
			t.Fatalf("err = %v, want one that wraps api.ErrNotFound", err)
		}
		if !strings.HasPrefix(err.Error(), `fetch secret "tls" version 3:`) {
			t.Errorf("err = %q, want the prefix %q", err, `fetch secret "tls" version 3:`)
		}
	})

	t.Run("another version", func(t *testing.T) {
		client := &fakeIngressSecretFetcher{env: &api.SecretEnvelope{Data: sealIngressSecret(t, nsk, value), Version: 4}}
		f := ingressCertFetcher{client: client, nodeID: "node-1", nsk: nsk}
		_, err := f.FetchCertificateSecret(t.Context(), "tls", 3)
		const want = `fetch secret "tls": asked for version 3, got 4`
		if err == nil || err.Error() != want {
			t.Errorf("err = %v, want %q", err, want)
		}
	})

	t.Run("sealed under another key", func(t *testing.T) {
		client := &fakeIngressSecretFetcher{env: &api.SecretEnvelope{Data: sealIngressSecret(t, ingressTestNSK(t), value), Version: 3}}
		f := ingressCertFetcher{client: client, nodeID: "node-1", nsk: nsk}
		_, err := f.FetchCertificateSecret(t.Context(), "tls", 3)
		if err == nil || !strings.HasPrefix(err.Error(), `decrypt secret "tls" version 3:`) {
			t.Fatalf("err = %v, want the prefix %q", err, `decrypt secret "tls" version 3:`)
		}
		if strings.Contains(err.Error(), string(value)) {
			t.Errorf("err = %q carries the value", err)
		}
	})
}
