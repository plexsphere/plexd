package cmd

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/agent"
	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/nat"
	"github.com/plexsphere/plexd/internal/nodeapi"
	"github.com/plexsphere/plexd/internal/policy"
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

// TestLoadMergedConfig_AbsentFile exercises the loader runUp calls: an absent
// config file is not fatal, the CLI flags are merged on top of the defaults,
// and the result is what validation then runs against. Without the flag the
// merged config has no base URL; with it, the file-less run validates.
func TestLoadMergedConfig_AbsentFile(t *testing.T) {
	oldAPIURL := apiURL
	t.Cleanup(func() { apiURL = oldAPIURL })

	apiURL = ""
	cfg, found, err := loadMergedConfig("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("loadMergedConfig for an absent file should not fail, got: %v", err)
	}
	if found {
		t.Error("found = true, want false for an absent config file")
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error for a missing base URL")
	} else if err.Error() != "api: config: BaseURL is required" {
		t.Errorf("Validate() error = %q, want %q", err.Error(), "api: config: BaseURL is required")
	}

	apiURL = "https://api.example.com"
	cfg, _, err = loadMergedConfig("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("loadMergedConfig: %v", err)
	}
	if cfg.API.BaseURL != apiURL {
		t.Errorf("API.BaseURL = %q, want the --api value %q", cfg.API.BaseURL, apiURL)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for a config-less run with --api", err)
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

// TestDeliveryModePublisher verifies the publisher surfaces the delivery mode as
// the delivery_mode metadata key, that a later transition overwrites it, and
// that it is held apart from the snapshot-owned metadata map so a reconcile that
// rewrites that map cannot drop it.
func TestDeliveryModePublisher(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := nodeapi.NewStateCache(t.TempDir(), logger)

	// Seed an unrelated metadata key the publisher must preserve.
	cache.UpdateMetadata(map[string]string{"region": "eu-central"})

	publish := deliveryModePublisher(cache, logger)

	publish(api.DeliveryModePullOnly)
	if got, _ := cache.GetMetadataKey("delivery_mode"); got != "pull_only" {
		t.Errorf("delivery_mode = %q, want pull_only", got)
	}
	if got := cache.GetMetadata()["region"]; got != "eu-central" {
		t.Errorf("pre-existing region key = %q, want eu-central (must survive)", got)
	}

	// A reconcile that rewrites the snapshot metadata must not drop delivery_mode.
	cache.UpdateMetadata(map[string]string{"env": "prod"})
	if got, _ := cache.GetMetadataKey("delivery_mode"); got != "pull_only" {
		t.Errorf("delivery_mode after metadata rewrite = %q, want pull_only", got)
	}

	publish(api.DeliveryModeStreaming)
	if got, _ := cache.GetMetadataKey("delivery_mode"); got != "streaming" {
		t.Errorf("delivery_mode after update = %q, want streaming", got)
	}
}

// TestApplyEnvOverrides_NodeAPI locks down the node-API branches of
// applyEnvOverrides: the three working overrides (socket, http_enabled,
// http_listen) and a regression guard proving the removed
// PLEXD_NODE_API_ENABLED variable is no longer read. Every subtest pins all
// four variables via t.Setenv so ambient CI values cannot leak in; t.Setenv
// restores the environment on cleanup and forbids t.Parallel, so none is used.
func TestApplyEnvOverrides_NodeAPI(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		t.Setenv("PLEXD_NODE_API_ENABLED", "")
		t.Setenv("PLEXD_NODE_API_SOCKET", "/tmp/x.sock")
		t.Setenv("PLEXD_NODE_API_HTTP_ENABLED", "1")
		t.Setenv("PLEXD_NODE_API_HTTP_LISTEN", "127.0.0.1:9999")

		cfg := agent.AgentConfig{}
		applyEnvOverrides(&cfg)

		if cfg.NodeAPI.SocketPath != "/tmp/x.sock" {
			t.Errorf("SocketPath = %q, want %q", cfg.NodeAPI.SocketPath, "/tmp/x.sock")
		}
		if cfg.NodeAPI.HTTPEnabled != true {
			t.Errorf("HTTPEnabled = %v, want true", cfg.NodeAPI.HTTPEnabled)
		}
		if cfg.NodeAPI.HTTPListen != "127.0.0.1:9999" {
			t.Errorf("HTTPListen = %q, want %q", cfg.NodeAPI.HTTPListen, "127.0.0.1:9999")
		}
	})

	t.Run("http_enabled coercion", func(t *testing.T) {
		tests := []struct {
			value string
			want  bool
		}{
			{"true", true},
			{"1", true},
			{"false", false},
			{"0", false},
			{"yes", false},
		}
		for _, tt := range tests {
			t.Run(tt.value, func(t *testing.T) {
				t.Setenv("PLEXD_NODE_API_ENABLED", "")
				t.Setenv("PLEXD_NODE_API_SOCKET", "")
				t.Setenv("PLEXD_NODE_API_HTTP_ENABLED", tt.value)
				t.Setenv("PLEXD_NODE_API_HTTP_LISTEN", "")

				cfg := agent.AgentConfig{}
				applyEnvOverrides(&cfg)

				if cfg.NodeAPI.HTTPEnabled != tt.want {
					t.Errorf("HTTPEnabled for %q = %v, want %v", tt.value, cfg.NodeAPI.HTTPEnabled, tt.want)
				}
			})
		}
	})

	t.Run("empty values leave zero config", func(t *testing.T) {
		t.Setenv("PLEXD_NODE_API_ENABLED", "")
		t.Setenv("PLEXD_NODE_API_SOCKET", "")
		t.Setenv("PLEXD_NODE_API_HTTP_ENABLED", "")
		t.Setenv("PLEXD_NODE_API_HTTP_LISTEN", "")

		cfg := agent.AgentConfig{}
		applyEnvOverrides(&cfg)

		if cfg.NodeAPI != (nodeapi.Config{}) {
			t.Errorf("NodeAPI = %+v, want zero value", cfg.NodeAPI)
		}
	})

	t.Run("removed PLEXD_NODE_API_ENABLED is inert", func(t *testing.T) {
		t.Setenv("PLEXD_NODE_API_ENABLED", "false")
		t.Setenv("PLEXD_NODE_API_SOCKET", "")
		t.Setenv("PLEXD_NODE_API_HTTP_ENABLED", "")
		t.Setenv("PLEXD_NODE_API_HTTP_LISTEN", "")

		cfg := agent.AgentConfig{}
		applyEnvOverrides(&cfg)

		if cfg.NodeAPI != (nodeapi.Config{}) {
			t.Errorf("NodeAPI = %+v, want zero value (PLEXD_NODE_API_ENABLED must be ignored)", cfg.NodeAPI)
		}
	})
}

// TestApplyEnvOverrides_ActionsEnabled covers the one override that can turn
// action execution back on where nothing else can: on the file-less path
// ParseConfig comes up with an explicit false, so a value this handler
// misreads leaves the whole fleet without remote diagnostics or upgrades. A
// spelling ParseBool accepts must not be read as a disable, and a value it does
// not accept must leave the setting alone rather than silently disable it.
func TestApplyEnvOverrides_ActionsEnabled(t *testing.T) {
	tests := []struct {
		name  string
		value string
		// want is the effective setting after the override is applied on top of
		// an explicit enabled: false, as the file-less path produces it.
		want bool
	}{
		{"true", "true", true},
		{"True", "True", true},
		{"TRUE", "TRUE", true},
		{"1", "1", true},
		{"t", "t", true},
		{"false", "false", false},
		{"False", "False", false},
		{"0", "0", false},
		// Not a bool: the config file's value stands, and the operator gets a
		// warning rather than a silent disable.
		{"yes", "yes", false},
		{"on", "on", false},
		{"empty value is inert", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PLEXD_ACTIONS_ENABLED", tt.value)

			disabled := false
			cfg := agent.AgentConfig{}
			cfg.Actions.Enabled = &disabled
			applyEnvOverrides(&cfg)

			if got := cfg.Actions.IsEnabled(); got != tt.want {
				t.Errorf("Actions.IsEnabled() for %q = %v, want %v", tt.value, got, tt.want)
			}
		})
	}

	// The mirror case: an unparseable value must not undo a config file that
	// enabled execution either.
	t.Run("unparseable leaves an enabled config alone", func(t *testing.T) {
		t.Setenv("PLEXD_ACTIONS_ENABLED", "yes")

		enabled := true
		cfg := agent.AgentConfig{}
		cfg.Actions.Enabled = &enabled
		applyEnvOverrides(&cfg)

		if !cfg.Actions.IsEnabled() {
			t.Error("Actions.IsEnabled() = false, want true: an unparseable value must not disable execution")
		}
	})
}

// failingFirewallController fails its pre-flight probe. Every other method
// panics: a failed pre-flight must abort startup before anything reaches the
// firewall, and a node running with enforcement disabled must not touch it
// either.
type failingFirewallController struct{ err error }

func (f *failingFirewallController) Probe() error { return f.err }

func (f *failingFirewallController) EnsureChain(string) error {
	panic("EnsureChain called without a passing pre-flight probe")
}

func (f *failingFirewallController) ApplyRules(string, []policy.FirewallRule) error {
	panic("ApplyRules called without a passing pre-flight probe")
}

func (f *failingFirewallController) FlushChain(string) error {
	panic("FlushChain called without a passing pre-flight probe")
}

func (f *failingFirewallController) DeleteChain(string) error {
	panic("DeleteChain called without a passing pre-flight probe")
}

// countingControlPlane starts a control plane that records every request it
// receives and rejects each one permanently, so a registration attempt fails on
// its first try instead of retrying into the test's deadline.
func countingControlPlane(t *testing.T) (baseURL string, requests *atomic.Int32) {
	t.Helper()
	requests = &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, requests
}

// writeUpConfig writes a config file that validates and points at apiBase,
// with policyBlock appended verbatim, and makes runUp read it. The health
// listener is off so the test does not bind the node's health port.
func writeUpConfig(t *testing.T, apiBase, policyBlock string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := fmt.Sprintf(`mode: node
data_dir: %s
log_level: error
api:
  base_url: %s
registration:
  project_id: 0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0
  resource_handle: preflight-test
  token_value: psb_test_preflight_token
  max_retry_duration: 1s
health:
  enabled: false
%s`, dir, apiBase, policyBlock)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	oldCfgFile, oldAPIURL, oldMode, oldLogLevel := cfgFile, apiURL, mode, logLevel
	oldProject, oldHandle, oldResourceID := projectID, resourceHandle, requestedResourceID
	t.Cleanup(func() {
		cfgFile, apiURL, mode, logLevel = oldCfgFile, oldAPIURL, oldMode, oldLogLevel
		projectID, resourceHandle, requestedResourceID = oldProject, oldHandle, oldResourceID
	})
	cfgFile, apiURL, mode, logLevel = path, "", "", ""
	projectID, resourceHandle, requestedResourceID = "", "", ""
}

// useFirewallController points runUp's platform seam at ctrl for one test.
func useFirewallController(t *testing.T, ctrl policy.FirewallController) {
	t.Helper()
	old := firewallController
	t.Cleanup(func() { firewallController = old })
	firewallController = func(*slog.Logger) policy.FirewallController { return ctrl }
}

// A node that cannot install the deny-by-default baseline has to fail before it
// registers: registration spends a one-shot bootstrap token and creates an
// upstream identity, and where data_dir is ephemeral neither survives the
// restart — leaving a node the control plane knows about, a token nobody can
// reuse, and a container crash-looping on the same fatal step.
func TestRunUp_PolicyPreflightAbortsBeforeRegistration(t *testing.T) {
	apiBase, requests := countingControlPlane(t)
	probeErr := errors.New("operation not permitted")
	useFirewallController(t, &failingFirewallController{err: probeErr})
	writeUpConfig(t, apiBase, "policy:\n  chain_name: plexd-mesh\n")

	err := runUp(upCmd, nil)
	if err == nil {
		t.Fatal("runUp() = nil, want the pre-flight failure")
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("control plane received %d requests, want 0 (nothing may be spent before the check)", got)
	}
	if !errors.Is(err, probeErr) {
		t.Errorf("error does not wrap the probe failure: %v", err)
	}
	// The kernel names neither the capability nor the way out, so the message
	// has to. Both halves are what the operator reading this line acts on.
	for _, want := range []string{"CAP_NET_ADMIN", "policy.enabled: false", "operation not permitted"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}

// policy.enabled: false is the opt-out the pre-flight failure points at, so it
// has to survive the config merge and leave the check a no-op — including on a
// host whose backend would fail the probe.
func TestRunUp_PolicyDisabledSkipsPreflight(t *testing.T) {
	apiBase, requests := countingControlPlane(t)
	useFirewallController(t, &failingFirewallController{err: errors.New("operation not permitted")})
	writeUpConfig(t, apiBase, "policy:\n  enabled: false\n")

	err := runUp(upCmd, nil)
	if err == nil {
		t.Fatal("runUp() = nil, want the registration failure")
	}
	if strings.Contains(err.Error(), "pre-flight") {
		t.Fatalf("runUp() error = %v, want startup to proceed past the pre-flight", err)
	}
	if !strings.Contains(err.Error(), "registration") {
		t.Fatalf("runUp() error = %v, want the registration failure", err)
	}
	if requests.Load() == 0 {
		t.Error("control plane received no requests, want the registration attempt")
	}
}
