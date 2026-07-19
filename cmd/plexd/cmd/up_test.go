package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
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
		req := buildHeartbeatRequest("checksum-abc", "1.2.3", &api.NATInfo{
			PublicEndpoint: "203.0.113.9:51820",
			Type:           "none",
		})

		if got := req.NATSummary["endpoint"]; got != "203.0.113.9:51820" {
			t.Errorf("summary endpoint = %v, want %q", got, "203.0.113.9:51820")
		}
		// Type "none" maps through Wire() to the full_cone traversal posture.
		if got := req.NATSummary["nat_type"]; got != "full_cone" {
			t.Errorf("summary nat_type = %v, want %q", got, "full_cone")
		}
	})
}

func TestDecodeSigningKeys_CurrentOnly(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(pub)
	logger := slog.Default()

	keys := api.SigningKeys{Current: encoded}
	current, previous, expires := decodeSigningKeys(keys, logger)

	if len(current) != ed25519.PublicKeySize {
		t.Errorf("current key length = %d, want %d", len(current), ed25519.PublicKeySize)
	}
	if len(previous) != 0 {
		t.Errorf("previous key should be nil, got len %d", len(previous))
	}
	if !expires.IsZero() {
		t.Errorf("expires should be zero, got %v", expires)
	}
}

func TestDecodeSigningKeys_WithPreviousAndExpiry(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Add(time.Hour)
	keys := api.SigningKeys{
		Current:           base64.StdEncoding.EncodeToString(pub1),
		Previous:          base64.StdEncoding.EncodeToString(pub2),
		TransitionExpires: &now,
	}
	logger := slog.Default()

	current, previous, expires := decodeSigningKeys(keys, logger)

	if len(current) != ed25519.PublicKeySize {
		t.Errorf("current key length = %d, want %d", len(current), ed25519.PublicKeySize)
	}
	if len(previous) != ed25519.PublicKeySize {
		t.Errorf("previous key length = %d, want %d", len(previous), ed25519.PublicKeySize)
	}
	if !expires.Equal(now) {
		t.Errorf("expires = %v, want %v", expires, now)
	}
}

func TestDecodeSigningKeys_InvalidBase64(t *testing.T) {
	keys := api.SigningKeys{
		Current:  "not-valid-base64!",
		Previous: "also-invalid!!",
	}
	logger := slog.Default()

	current, previous, _ := decodeSigningKeys(keys, logger)

	if len(current) != 0 {
		t.Errorf("current should be nil for invalid base64, got len %d", len(current))
	}
	if len(previous) != 0 {
		t.Errorf("previous should be nil for invalid base64, got len %d", len(previous))
	}
}

func TestDecodeSigningKeys_Empty(t *testing.T) {
	keys := api.SigningKeys{}
	logger := slog.Default()

	current, previous, expires := decodeSigningKeys(keys, logger)

	if len(current) != 0 {
		t.Errorf("current should be nil for empty keys, got len %d", len(current))
	}
	if len(previous) != 0 {
		t.Errorf("previous should be nil for empty keys, got len %d", len(previous))
	}
	if !expires.IsZero() {
		t.Errorf("expires should be zero for empty keys, got %v", expires)
	}
}
