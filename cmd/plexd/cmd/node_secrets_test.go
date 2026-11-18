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

// fakeNodeSecretClient answers FetchSecret with env or err and records
// the arguments of the last call.
type fakeNodeSecretClient struct {
	env *api.SecretEnvelope
	err error

	nodeID  string
	name    string
	version int
}

func (f *fakeNodeSecretClient) FetchSecret(_ context.Context, nodeID, name string, version int) (*api.SecretEnvelope, error) {
	f.nodeID, f.name, f.version = nodeID, name, version
	return f.env, f.err
}

// sealNodeSecret seals plaintext under nsk as the control plane seals a
// secret: AES-256-GCM, <12-byte nonce> || <ciphertext + 16-byte tag>, no AAD.
func sealNodeSecret(t *testing.T, nsk, plaintext []byte) []byte {
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

// nodeSecretTestNSK returns a random 32-byte node secret key.
func nodeSecretTestNSK(t *testing.T) []byte {
	t.Helper()
	nsk := make([]byte, 32)
	if _, err := rand.Read(nsk); err != nil {
		t.Fatalf("nsk: %v", err)
	}
	return nsk
}

func TestNodeSecretFetcher_FetchCertificateSecret(t *testing.T) {
	nsk := nodeSecretTestNSK(t)
	value := []byte("-----BEGIN CERTIFICATE-----\nnot checked here\n-----END CERTIFICATE-----\n")

	t.Run("decrypts the envelope", func(t *testing.T) {
		client := &fakeNodeSecretClient{env: &api.SecretEnvelope{Data: sealNodeSecret(t, nsk, value), Version: 3}}
		f := nodeSecretFetcher{client: client, nodeID: "node-1", nsk: nsk}
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
		client := &fakeNodeSecretClient{err: fmt.Errorf("api: %w", api.ErrNotFound)}
		f := nodeSecretFetcher{client: client, nodeID: "node-1", nsk: nsk}
		_, err := f.FetchCertificateSecret(t.Context(), "tls", 3)
		if !errors.Is(err, api.ErrNotFound) {
			t.Fatalf("err = %v, want one that wraps api.ErrNotFound", err)
		}
		if !strings.HasPrefix(err.Error(), `fetch secret "tls" version 3:`) {
			t.Errorf("err = %q, want the prefix %q", err, `fetch secret "tls" version 3:`)
		}
	})

	t.Run("another version", func(t *testing.T) {
		client := &fakeNodeSecretClient{env: &api.SecretEnvelope{Data: sealNodeSecret(t, nsk, value), Version: 4}}
		f := nodeSecretFetcher{client: client, nodeID: "node-1", nsk: nsk}
		_, err := f.FetchCertificateSecret(t.Context(), "tls", 3)
		const want = `fetch secret "tls": asked for version 3, got 4`
		if err == nil || err.Error() != want {
			t.Errorf("err = %v, want %q", err, want)
		}
	})

	t.Run("sealed under another key", func(t *testing.T) {
		client := &fakeNodeSecretClient{env: &api.SecretEnvelope{Data: sealNodeSecret(t, nodeSecretTestNSK(t), value), Version: 3}}
		f := nodeSecretFetcher{client: client, nodeID: "node-1", nsk: nsk}
		_, err := f.FetchCertificateSecret(t.Context(), "tls", 3)
		if err == nil || !strings.HasPrefix(err.Error(), `decrypt secret "tls" version 3:`) {
			t.Fatalf("err = %v, want the prefix %q", err, `decrypt secret "tls" version 3:`)
		}
		if strings.Contains(err.Error(), string(value)) {
			t.Errorf("err = %q carries the value", err)
		}
	})
}

// TestNodeSecretFetcher_FetchSecretValue pins that the join key of a vendor
// user access provider is fetched as a certificate is: the value comes back
// as it was sealed, surrounding white space included, and an envelope of
// another version is refused.
func TestNodeSecretFetcher_FetchSecretValue(t *testing.T) {
	nsk := nodeSecretTestNSK(t)
	value := []byte("tskey-auth-0123456789\n")
	client := &fakeNodeSecretClient{env: &api.SecretEnvelope{Data: sealNodeSecret(t, nsk, value), Version: 3}}
	f := nodeSecretFetcher{client: client, nodeID: "node-1", nsk: nsk}
	got, err := f.FetchSecretValue(t.Context(), "ts-join", 3)
	if err != nil || !bytes.Equal(got, value) {
		t.Fatalf("FetchSecretValue = %q, %v, want %q", got, err, value)
	}
	if client.nodeID != "node-1" || client.name != "ts-join" || client.version != 3 {
		t.Errorf("FetchSecret(%q, %q, %d), want (node-1, ts-join, 3)", client.nodeID, client.name, client.version)
	}
	client.env.Version = 4
	const want = `fetch secret "ts-join": asked for version 3, got 4`
	if _, err := f.FetchSecretValue(t.Context(), "ts-join", 3); err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
}
