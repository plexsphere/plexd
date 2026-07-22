package cmd

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/nat"
)

// TestRedactSensitiveLine_SecretKey verifies that the existing redaction logic
// automatically covers the secret_key YAML key used by LocalEndpointConfig.
func TestRedactSensitiveLine_SecretKey(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "secret_key with value is redacted",
			line: "    secret_key: my-secret-token",
			want: "    secret_key: '[REDACTED]'",
		},
		{
			name: "secret_key with empty value is unchanged",
			line: "    secret_key: ",
			want: "    secret_key: ",
		},
		{
			name: "secret_key with quoted empty is unchanged",
			line: `    secret_key: ""`,
			want: `    secret_key: ""`,
		},
		{
			name: "url is not redacted",
			line: "    url: https://metrics.local:9090/ingest",
			want: "    url: https://metrics.local:9090/ingest",
		},
		{
			name: "tls_insecure_skip_verify is not redacted",
			line: "    tls_insecure_skip_verify: false",
			want: "    tls_insecure_skip_verify: false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactSensitiveLine(tt.line)
			if got != tt.want {
				t.Errorf("redactSensitiveLine(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestBuildHeartbeatRequest(t *testing.T) {
	t.Run("nil NAT info yields empty non-nil summary", func(t *testing.T) {
		req := buildHeartbeatRequest("checksum-abc", "1.2.3", nil)

		if req.NATSummary == nil {
			t.Fatal("NATSummary = nil, want non-nil empty map")
		}
		if len(req.NATSummary) != 0 {
			t.Errorf("NATSummary = %v, want empty", req.NATSummary)
		}

		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(data), `"nat_summary":{}`) {
			t.Errorf("marshaled request should contain nat_summary as {}, got: %s", data)
		}
		if strings.Contains(string(data), `"nat_summary":null`) {
			t.Errorf("marshaled request must not contain nat_summary as null, got: %s", data)
		}

		if req.ClientNow.IsZero() {
			t.Error("ClientNow is zero, want a fresh timestamp")
		}
		if req.ClientNow.Location() != time.UTC {
			t.Errorf("ClientNow location = %v, want UTC", req.ClientNow.Location())
		}
		if req.BinaryChecksum != "checksum-abc" {
			t.Errorf("BinaryChecksum = %q, want %q", req.BinaryChecksum, "checksum-abc")
		}
		if req.BinaryVersion != "1.2.3" {
			t.Errorf("BinaryVersion = %q, want %q", req.BinaryVersion, "1.2.3")
		}
	})

	t.Run("populated NAT info maps through Wire", func(t *testing.T) {
		req := buildHeartbeatRequest("checksum-abc", "1.2.3", &nat.DiscoveryResult{
			Endpoint: "203.0.113.9:51820",
			NATType:  nat.NATNone,
		})

		if got := req.NATSummary["endpoint"]; got != "203.0.113.9:51820" {
			t.Errorf("summary endpoint = %v, want %q", got, "203.0.113.9:51820")
		}
		// NATNone maps through Wire() to the full_cone traversal posture.
		if got := req.NATSummary["nat_type"]; got != "full_cone" {
			t.Errorf("summary nat_type = %v, want %q", got, "full_cone")
		}
	})
}

// signRotationEnvelope builds an envelope signed over its canonical bytes with
// the given key and key id, used to prove which key the verifier accepts.
func signRotationEnvelope(t *testing.T, priv ed25519.PrivateKey, keyID string) api.Envelope {
	t.Helper()
	env := api.Envelope{
		ID:       "evt-rot-1",
		Type:     api.EventPolicyUpdated,
		KeyID:    keyID,
		IssuedAt: time.Now().UTC(),
		Payload:  json.RawMessage(`{}`),
	}
	canonical, err := api.CanonicalBytes(env)
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))
	return env
}

func TestSigningKeyRotatedHandler(t *testing.T) {
	oldPub, oldPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("valid rotation installs new key id", func(t *testing.T) {
		verifier := api.NewEd25519Verifier("kid-old", oldPub)
		newPub, newPriv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		rot := api.SigningKeyRotation{
			KeyID:     "kid-new",
			PublicKey: base64.StdEncoding.EncodeToString(newPub),
		}
		payload, err := json.Marshal(rot)
		if err != nil {
			t.Fatal(err)
		}
		if err := signingKeyRotatedHandler(verifier, logger)(context.Background(), api.Envelope{Payload: payload}); err != nil {
			t.Fatalf("handler returned error: %v", err)
		}
		if err := verifier.Verify(context.Background(), signRotationEnvelope(t, newPriv, "kid-new")); err != nil {
			t.Errorf("envelope under new kid failed to verify: %v", err)
		}
	})

	t.Run("malformed payload leaves keys unchanged", func(t *testing.T) {
		verifier := api.NewEd25519Verifier("kid-old", oldPub)
		err := signingKeyRotatedHandler(verifier, logger)(context.Background(), api.Envelope{Payload: json.RawMessage(`not-json`)})
		if err == nil {
			t.Fatal("expected wrapped error for malformed payload, got nil")
		}
		if err := verifier.Verify(context.Background(), signRotationEnvelope(t, oldPriv, "kid-old")); err != nil {
			t.Errorf("envelope under old kid failed to verify after malformed rotation: %v", err)
		}
	})
}
