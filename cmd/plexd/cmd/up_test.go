package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/agent"
	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/health"
	"github.com/plexsphere/plexd/internal/nat"
	"github.com/plexsphere/plexd/internal/nodeapi"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/registration"
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

// TestApplyEnvOverrides_PolicyEnabled covers the override that lets a container
// which cannot program nftables start at all: with enforcement on, `plexd up`
// aborts on the firewall pre-flight, and without a config file this variable is
// the only way to reach the opt-out. The stakes run both ways — a value misread
// as a disable drops the deny-by-default posture on a node that could enforce,
// and a value misread as an enable strands a node that cannot.
func TestApplyEnvOverrides_PolicyEnabled(t *testing.T) {
	tests := []struct {
		name  string
		value string
		// want is the effective setting after the override is applied on top of
		// a zero-valued policy block, where nil already reads as enabled.
		want bool
	}{
		{"true", "true", true},
		{"True", "True", true},
		{"TRUE", "TRUE", true},
		{"1", "1", true},
		{"t", "t", true},
		{"false", "false", false},
		{"False", "False", false},
		{"FALSE", "FALSE", false},
		{"0", "0", false},
		{"f", "f", false},
		// Not a bool: the default stands, and the operator gets a warning
		// rather than a silently unenforced node.
		{"yes", "yes", true},
		{"off", "off", true},
		{"empty value is inert", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PLEXD_POLICY_ENABLED", tt.value)

			cfg := agent.AgentConfig{}
			applyEnvOverrides(&cfg)

			if got := cfg.Policy.IsEnabled(); got != tt.want {
				t.Errorf("Policy.IsEnabled() for %q = %v, want %v", tt.value, got, tt.want)
			}
		})
	}

	// The mirror case, and the one that costs a node its startup: an
	// unparseable value must not re-enable enforcement on a config that turned
	// it off, because that node fails the pre-flight and never comes up.
	t.Run("unparseable leaves a disabled config alone", func(t *testing.T) {
		t.Setenv("PLEXD_POLICY_ENABLED", "yes")

		disabled := false
		cfg := agent.AgentConfig{}
		cfg.Policy.Enabled = &disabled
		applyEnvOverrides(&cfg)

		if cfg.Policy.IsEnabled() {
			t.Error("Policy.IsEnabled() = true, want false: an unparseable value must not re-enable enforcement")
		}
	})

	t.Run("unset leaves the config untouched", func(t *testing.T) {
		t.Setenv("PLEXD_POLICY_ENABLED", "")

		cfg := agent.AgentConfig{}
		applyEnvOverrides(&cfg)

		if cfg.Policy != (policy.Config{}) {
			t.Errorf("Policy = %+v, want zero value", cfg.Policy)
		}
	})
}

// TestApplyEnvOverrides_Health covers the two health overrides. health.listen
// is the one a Pod-network deployment needs: the kubelet dials the Pod IP, and
// the loopback default answers nothing there, so without this variable a
// file-less Deployment cannot be probed at all.
func TestApplyEnvOverrides_Health(t *testing.T) {
	t.Run("listen is applied verbatim", func(t *testing.T) {
		t.Setenv("PLEXD_HEALTH_ENABLED", "")
		t.Setenv("PLEXD_HEALTH_LISTEN", "0.0.0.0:9101")

		cfg := agent.AgentConfig{}
		applyEnvOverrides(&cfg)

		if cfg.Health.Listen != "0.0.0.0:9101" {
			t.Errorf("Health.Listen = %q, want %q", cfg.Health.Listen, "0.0.0.0:9101")
		}
	})

	// No syntax check runs here on purpose: an address the kernel refuses has
	// to reach the bind error in runUp, which names the address and the port
	// collision that is the likely cause on a host-networked node.
	t.Run("an unbindable listen value is passed through", func(t *testing.T) {
		t.Setenv("PLEXD_HEALTH_ENABLED", "")
		t.Setenv("PLEXD_HEALTH_LISTEN", "not-an-address")

		cfg := agent.AgentConfig{}
		applyEnvOverrides(&cfg)

		if cfg.Health.Listen != "not-an-address" {
			t.Errorf("Health.Listen = %q, want the value passed through unvalidated", cfg.Health.Listen)
		}
		if err := cfg.Health.Validate(); err != nil {
			t.Errorf("Health.Validate() = %v, want nil: the address is checked at bind time, not here", err)
		}
	})

	t.Run("enabled coercion", func(t *testing.T) {
		tests := []struct {
			name  string
			value string
			want  bool
		}{
			{"true", "true", true},
			{"1", "1", true},
			{"false", "false", false},
			{"False", "False", false},
			{"0", "0", false},
			// Not a bool: the listener stays on. Disabling it on a typo would
			// unbind the probe target, and the kubelet answers an unbound
			// probe target with a restart loop that tears down the data plane
			// on every pass.
			{"yes", "yes", true},
			{"empty value is inert", "", true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Setenv("PLEXD_HEALTH_ENABLED", tt.value)
				t.Setenv("PLEXD_HEALTH_LISTEN", "")

				cfg := agent.AgentConfig{}
				applyEnvOverrides(&cfg)

				if got := cfg.Health.IsEnabled(); got != tt.want {
					t.Errorf("Health.IsEnabled() for %q = %v, want %v", tt.value, got, tt.want)
				}
			})
		}
	})

	t.Run("unparseable leaves a disabled config alone", func(t *testing.T) {
		t.Setenv("PLEXD_HEALTH_ENABLED", "yes")
		t.Setenv("PLEXD_HEALTH_LISTEN", "")

		disabled := false
		cfg := agent.AgentConfig{}
		cfg.Health.Enabled = &disabled
		applyEnvOverrides(&cfg)

		if cfg.Health.IsEnabled() {
			t.Error("Health.IsEnabled() = true, want false: an unparseable value must not re-enable the listener")
		}
	})

	t.Run("unset leaves the config untouched", func(t *testing.T) {
		t.Setenv("PLEXD_HEALTH_ENABLED", "")
		t.Setenv("PLEXD_HEALTH_LISTEN", "")

		cfg := agent.AgentConfig{}
		applyEnvOverrides(&cfg)

		if cfg.Health != (health.Config{}) {
			t.Errorf("Health = %+v, want zero value", cfg.Health)
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
// with extraYAML appended verbatim as further top-level blocks, and makes runUp
// read it. The health listener is off so the test does not bind the node's
// health port. It returns the data_dir the config names, which is where a test
// that needs runUp to resume an identity seeds one.
func writeUpConfig(t *testing.T, apiBase, extraYAML string) string {
	t.Helper()

	// The two blocks this helper pins in the file are also reachable from the
	// environment, so an ambient PLEXD_POLICY_ENABLED or PLEXD_HEALTH_* would
	// override what the config says and quietly change what the test exercises.
	// A caller that wants one of them sets it after this call: t.Setenv cleanup
	// is LIFO, so the later value wins and both are still restored.
	t.Setenv("PLEXD_POLICY_ENABLED", "")
	t.Setenv("PLEXD_HEALTH_ENABLED", "")
	t.Setenv("PLEXD_HEALTH_LISTEN", "")

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
%s`, dir, apiBase, extraYAML)
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
	return dir
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

// The same opt-out, reached from the environment instead of the file. This is
// the path a restricted container takes: the ConfigMap is mounted optional and
// absent, so the policy block defaults to enabled and the pre-flight is fatal
// — PLEXD_POLICY_ENABLED=false is the only thing standing between that node and
// a crash loop. Proven through runUp rather than applyEnvOverrides alone,
// because the override has to survive the merge and land in the config the
// enforcer is built from.
func TestRunUp_PolicyDisabledFromEnvSkipsPreflight(t *testing.T) {
	apiBase, requests := countingControlPlane(t)
	useFirewallController(t, &failingFirewallController{err: errors.New("operation not permitted")})
	// No policy block: the file leaves enforcement at its default of on, so the
	// environment is what turns it off.
	writeUpConfig(t, apiBase, "")
	t.Setenv("PLEXD_POLICY_ENABLED", "false")

	err := runUp(upCmd, nil)
	if err == nil {
		t.Fatal("runUp() = nil, want the registration failure")
	}
	if strings.Contains(err.Error(), "pre-flight") {
		t.Fatalf("runUp() error = %v, want PLEXD_POLICY_ENABLED=false to make the pre-flight a no-op", err)
	}
	if !strings.Contains(err.Error(), "registration") {
		t.Fatalf("runUp() error = %v, want the registration failure", err)
	}
	if requests.Load() == 0 {
		t.Error("control plane received no requests, want the registration attempt")
	}
}

// The control case for the test above: without the variable, the identical
// file-and-backend combination aborts on the pre-flight. Without this, a bug
// that disabled enforcement unconditionally would leave both tests green.
func TestRunUp_PolicyEnvUnsetKeepsPreflightFatal(t *testing.T) {
	apiBase, requests := countingControlPlane(t)
	probeErr := errors.New("operation not permitted")
	useFirewallController(t, &failingFirewallController{err: probeErr})
	writeUpConfig(t, apiBase, "")

	err := runUp(upCmd, nil)
	if err == nil {
		t.Fatal("runUp() = nil, want the pre-flight failure")
	}
	if !errors.Is(err, probeErr) {
		t.Errorf("error does not wrap the probe failure: %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("control plane received %d requests, want 0 (the pre-flight must abort first)", got)
	}
}

// A file that says one thing and an environment that says the other: the
// environment wins, in both directions. The precedence is what the shipped
// DaemonSet depends on staying predictable — its ConfigMap keeps working
// because nothing sets these variables, not because the file outranks them.
func TestRunUp_PolicyEnvOverridesFile(t *testing.T) {
	t.Run("env false beats file true", func(t *testing.T) {
		apiBase, requests := countingControlPlane(t)
		useFirewallController(t, &failingFirewallController{err: errors.New("operation not permitted")})
		writeUpConfig(t, apiBase, "policy:\n  enabled: true\n")
		t.Setenv("PLEXD_POLICY_ENABLED", "false")

		err := runUp(upCmd, nil)
		if err == nil || strings.Contains(err.Error(), "pre-flight") {
			t.Fatalf("runUp() error = %v, want the environment's false to win over the file's true", err)
		}
		if requests.Load() == 0 {
			t.Error("control plane received no requests, want the registration attempt")
		}
	})

	t.Run("env true beats file false", func(t *testing.T) {
		apiBase, _ := countingControlPlane(t)
		probeErr := errors.New("operation not permitted")
		useFirewallController(t, &failingFirewallController{err: probeErr})
		writeUpConfig(t, apiBase, "policy:\n  enabled: false\n")
		t.Setenv("PLEXD_POLICY_ENABLED", "true")

		err := runUp(upCmd, nil)
		if err == nil || !errors.Is(err, probeErr) {
			t.Fatalf("runUp() error = %v, want the environment's true to win and the pre-flight to run", err)
		}
	})
}

// freePort returns a port nothing is listening on, by taking one from the
// kernel and handing it straight back. A test that needs to reach the health
// listener has to know its address in advance, and health.Listen offers no way
// to report the port it settled on.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return port
}

// PLEXD_HEALTH_LISTEN has to reach the socket that actually binds, not just the
// config struct — the point of the variable is that a probe can reach the
// listener, and only a served response proves that. The file here says the
// listener is off, so a 200 also proves PLEXD_HEALTH_ENABLED turned it back on:
// the two variables together are the whole file-less arrangement.
//
// The address is a loopback port rather than the 0.0.0.0 a Pod-network
// Deployment would use — a wildcard bind in a test claims a port on every
// interface of whatever machine runs it. What that costs is coverage of the
// wildcard itself, which is a kernel behaviour, not a plexd one; what is under
// test is that the address plexd binds is the one the environment named.
func TestRunUp_HealthListenFromEnvIsServed(t *testing.T) {
	// A control plane that holds its first request open, so registration is
	// still in flight while the probe runs. The health listener starts before
	// registration precisely so a probe during a slow one gets an answer, and
	// that is the window this test occupies.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	useFirewallController(t, &failingFirewallController{err: errors.New("operation not permitted")})
	writeUpConfig(t, srv.URL, "policy:\n  enabled: false\n")
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	t.Setenv("PLEXD_HEALTH_ENABLED", "true")
	t.Setenv("PLEXD_HEALTH_LISTEN", addr)

	upErr := make(chan error, 1)
	go func() { upErr <- runUp(upCmd, nil) }()
	// Whatever the probe finds, registration has to be let go or runUp never
	// returns and the goroutine outlives the test.
	defer func() {
		close(release)
		if err := <-upErr; err == nil {
			t.Error("runUp() = nil, want the registration failure")
		} else if strings.Contains(err.Error(), "health listener cannot bind") {
			t.Errorf("runUp() error = %v, want %s to bind", err, addr)
		}
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s/healthz = %d, want 200", addr, resp.StatusCode)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET %s/healthz never succeeded: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The failure mode the variable is verbatim for: an address the kernel refuses
// surfaces through the bind error, which names the address, rather than
// through a validation path that would have to guess at the cause.
func TestRunUp_HealthListenFromEnvSurfacesBindError(t *testing.T) {
	apiBase, requests := countingControlPlane(t)
	useFirewallController(t, &failingFirewallController{err: errors.New("operation not permitted")})
	writeUpConfig(t, apiBase, "policy:\n  enabled: false\n")
	t.Setenv("PLEXD_HEALTH_ENABLED", "true")
	t.Setenv("PLEXD_HEALTH_LISTEN", "not-an-address")

	err := runUp(upCmd, nil)
	if err == nil {
		t.Fatal("runUp() = nil, want the bind failure")
	}
	if !strings.Contains(err.Error(), "health listener cannot bind") {
		t.Fatalf("runUp() error = %v, want the bind error", err)
	}
	if !strings.Contains(err.Error(), "not-an-address") {
		t.Errorf("error %q does not name the rejected address", err.Error())
	}
	// The listener starts before registration, so a bad address must not have
	// spent the bootstrap token on the way to failing.
	if got := requests.Load(); got != 0 {
		t.Errorf("control plane received %d requests, want 0", got)
	}
}

// The node id and secret the fixture control plane hands back, and the values a
// seeded on-disk identity carries. The two differ so a test can tell which of
// the two registrar paths produced the credential the daemon then presents.
const (
	upTestNodeID     = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3"
	upResumedNodeID  = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b7"
	upTestSigningKID = "did:web:plexsphere.com#key-2026-04"
)

var (
	// The nsk travels and is stored as standard-padded base64 of 32 bytes; the
	// bearer envelope carries those bytes decoded.
	upTestNSKBytes    = bytes.Repeat([]byte{0x2a}, 32)
	upTestNSK         = base64.StdEncoding.EncodeToString(upTestNSKBytes)
	upResumedNSKBytes = bytes.Repeat([]byte{0x5b}, 32)
	upResumedNSK      = base64.StdEncoding.EncodeToString(upResumedNSKBytes)
	upTestSigningKey  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize))
)

// wantBearerEnvelope spells out the credential the control plane admits —
// nsk_plexd_<base64url(node_id_bytes || nsk_bytes)>, unpadded — from the raw
// material rather than by calling NodeIdentity.BearerToken, so the assertion
// pins the wire format itself instead of agreeing with whatever the producer
// currently emits.
func wantBearerEnvelope(t *testing.T, nodeID string, nsk []byte) string {
	t.Helper()
	idBytes, err := hex.DecodeString(strings.ReplaceAll(nodeID, "-", ""))
	if err != nil {
		t.Fatalf("decode node id %q: %v", nodeID, err)
	}
	payload := make([]byte, 0, len(idBytes)+len(nsk))
	payload = append(payload, idBytes...)
	payload = append(payload, nsk...)
	return "Bearer nsk_plexd_" + base64.RawURLEncoding.EncodeToString(payload)
}

// authRecordingControlPlane admits registrations and records the Authorization
// header of every request that follows one. Every non-register route answers
// 200 with an empty JSON object: what the daemon makes of those responses is
// not under test, only the credential it presents while asking.
type authRecordingControlPlane struct {
	mu            sync.Mutex
	registrations int
	paths         []string
	auth          map[string]string
}

func newAuthRecordingControlPlane(t *testing.T) (*authRecordingControlPlane, string) {
	t.Helper()
	cp := &authRecordingControlPlane{auth: make(map[string]string)}
	srv := httptest.NewServer(http.HandlerFunc(cp.serve))
	t.Cleanup(srv.Close)
	return cp, srv.URL
}

func (cp *authRecordingControlPlane) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodPost && r.URL.Path == "/v1/register" {
		cp.mu.Lock()
		cp.registrations++
		cp.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(api.RegisterResponse{
			NodeID:           upTestNodeID,
			MeshIP:           "100.64.0.1",
			SigningPublicKey: upTestSigningKey,
			SigningKeyID:     upTestSigningKID,
			NSK:              upTestNSK,
			DomainMeshCIDR:   "100.64.0.0/10",
			PeerSnapshot:     []api.RegisterPeer{},
		})
		return
	}

	cp.mu.Lock()
	if _, seen := cp.auth[r.URL.Path]; !seen {
		cp.paths = append(cp.paths, r.URL.Path)
	}
	cp.auth[r.URL.Path] = r.Header.Get("Authorization")
	cp.mu.Unlock()
	_, _ = w.Write([]byte("{}"))
}

func (cp *authRecordingControlPlane) registerCount() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.registrations
}

// authFor returns the Authorization header last seen on path, and whether the
// path was requested at all.
func (cp *authRecordingControlPlane) authFor(path string) (string, bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	auth, ok := cp.auth[path]
	return auth, ok
}

// allAuth returns the Authorization header last seen on each path.
func (cp *authRecordingControlPlane) allAuth() map[string]string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	out := make(map[string]string, len(cp.auth))
	for path, auth := range cp.auth {
		out[path] = auth
	}
	return out
}

// waitForAuthenticatedCall blocks until the daemon issues a request that is not
// the registration itself. Which route arrives first is not fixed —
// capabilities, heartbeat, the reconcile pull and the event stream all start
// within moments of each other — so the test waits for any of them rather than
// for a named one.
func (cp *authRecordingControlPlane) waitForAuthenticatedCall(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		cp.mu.Lock()
		seen := len(cp.paths)
		cp.mu.Unlock()
		if seen > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no authenticated request reached the control plane after registration")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// assertEveryCallPresentsEnvelope checks the credential on every
// post-registration request recorded so far. POST /v1/register is the only
// route that sends no bearer, so everything else the daemon asks for must carry
// the envelope — they all go through the one client, and which routes have run
// by now is a matter of scheduling.
func assertEveryCallPresentsEnvelope(t *testing.T, cp *authRecordingControlPlane, want, rawNSK string) {
	t.Helper()
	for path, got := range cp.allAuth() {
		switch got {
		case want:
		case "Bearer " + rawNSK:
			t.Errorf("Authorization on %s is the raw nsk, which the control plane refuses with 401: %q", path, got)
		default:
			t.Errorf("Authorization on %s = %q, want the bearer envelope %q", path, got, want)
		}
	}
}

// upDaemonYAML is the extra config a test needs to run the whole daemon rather
// than stop at registration: no firewall enforcement, no tunnel listener, and a
// node-API socket inside the test's own directory.
func upDaemonYAML(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`policy:
  enabled: false
tunnel:
  enabled: false
node_api:
  socket_path: %s
`, filepath.Join(t.TempDir(), "api.sock"))
}

// startRunUp runs the daemon against a context the test owns and returns the
// shutdown func, which cancels that context and waits for runUp to return.
func startRunUp(t *testing.T) func() {
	t.Helper()
	// The firewall seam is nil rather than a controller: with enforcement off
	// nothing should reach a backend, and a nil one turns a call that does into
	// a skipped no-op instead of a panic in a daemon goroutine.
	useFirewallController(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	previous := upCmd.Context()
	upCmd.SetContext(ctx)

	errCh := make(chan error, 1)
	go func() { errCh <- runUp(upCmd, nil) }()

	return func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("runUp() = %v, want a clean shutdown", err)
			}
		case <-time.After(drainTimeout + 30*time.Second):
			t.Error("runUp did not return after its context was cancelled")
		}
		upCmd.SetContext(previous)
	}
}

// seedIdentity writes the identity files LoadIdentity reads, so the next runUp
// resumes this node instead of registering a new one.
func seedIdentity(t *testing.T, dataDir, nodeID, nsk string) {
	t.Helper()
	err := registration.SaveIdentity(dataDir, &registration.NodeIdentity{
		NodeID:           nodeID,
		MeshIP:           "100.64.0.7",
		SigningPublicKey: upTestSigningKey,
		SigningKeyID:     upTestSigningKID,
		DomainMeshCIDR:   "100.64.0.0/10",
		PrivateKey:       bytes.Repeat([]byte{0x33}, 32),
		NodeSecretKey:    nsk,
	})
	if err != nil {
		t.Fatalf("seed identity in %s: %v", dataDir, err)
	}
}

// The credential runUp leaves on the shared control-plane client is the one
// every later call presents: heartbeat, reconcile pull, state reports,
// capability updates, metrics and audit ingest all go through that single
// client. Only the bearer envelope the registrar assembles is admitted, so a
// raw nsk left here answers 401 on all of them at once while the node still
// logs a successful registration and holds a mesh address — the failure this
// pins is a node that looks healthy and reports nothing.
//
// Both registrar paths are covered, because both arm the client and either one
// can be undone by a later assignment.
func TestRunUp_PresentsBearerEnvelopeAfterRegistration(t *testing.T) {
	t.Run("fresh registration", func(t *testing.T) {
		cp, apiBase := newAuthRecordingControlPlane(t)
		writeUpConfig(t, apiBase, upDaemonYAML(t))

		shutdown := startRunUp(t)
		defer shutdown()

		cp.waitForAuthenticatedCall(t)
		assertEveryCallPresentsEnvelope(t, cp, wantBearerEnvelope(t, upTestNodeID, upTestNSKBytes), upTestNSK)
		if n := cp.registerCount(); n != 1 {
			t.Errorf("control plane saw %d registrations, want 1", n)
		}
	})

	t.Run("resumed identity", func(t *testing.T) {
		cp, apiBase := newAuthRecordingControlPlane(t)
		dataDir := writeUpConfig(t, apiBase, upDaemonYAML(t))
		seedIdentity(t, dataDir, upResumedNodeID, upResumedNSK)

		shutdown := startRunUp(t)
		defer shutdown()

		cp.waitForAuthenticatedCall(t)
		assertEveryCallPresentsEnvelope(t, cp, wantBearerEnvelope(t, upResumedNodeID, upResumedNSKBytes), upResumedNSK)
		// A resumed identity contacts no one to load itself, so a registration
		// here would mean the daemon spent a bootstrap token it did not need.
		if n := cp.registerCount(); n != 0 {
			t.Errorf("control plane saw %d registrations, want 0 for a resumed identity", n)
		}
	})
}

// The heartbeat's auth-failure fallback is the only recovery the agent can
// perform on its own from a refused credential, and re-arming the client after
// it is what turned that recovery into the thing that guaranteed the failure:
// Register leaves the envelope on the client, an assignment after it replaced
// the envelope with a credential the control plane answers 401 to, and the next
// heartbeat one interval later failed the same way, indefinitely.
func TestReRegisterOnAuthFailure_LeavesTheRegistrarsEnvelopeArmed(t *testing.T) {
	cp, apiBase := newAuthRecordingControlPlane(t)
	client, err := api.NewControlPlane(api.Config{BaseURL: apiBase}, "test", discardLogger())
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	// What a 401 heartbeat means: the credential on the client is one the
	// control plane no longer accepts.
	client.SetAuthToken("stale-credential")

	registrar := newRegistrar(client, registration.Config{
		DataDir:          t.TempDir(),
		TokenValue:       "psb_test_token",
		ProjectID:        "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0",
		ResourceHandle:   "auth-failure-test",
		MaxRetryDuration: time.Second,
	}, discardLogger())

	reRegisterOnAuthFailure(context.Background(), registrar, discardLogger())()

	if n := cp.registerCount(); n != 1 {
		t.Fatalf("control plane saw %d registrations, want 1 from the fallback", n)
	}

	// The credential is only observable in what the client sends, which is also
	// the only form in which it matters.
	if _, err := client.Heartbeat(context.Background(), upTestNodeID, api.HeartbeatRequest{}); err != nil {
		t.Fatalf("Heartbeat after re-registration: %v", err)
	}
	path := "/v1/nodes/" + upTestNodeID + "/heartbeat"
	got, ok := cp.authFor(path)
	if !ok {
		t.Fatalf("control plane saw no request on %s", path)
	}
	if want := wantBearerEnvelope(t, upTestNodeID, upTestNSKBytes); got != want {
		t.Errorf("Authorization after the fallback = %q, want the new identity's envelope %q", got, want)
	}
	if got == "Bearer "+upTestNSK {
		t.Error("the fallback left the raw nsk on the client, so the next heartbeat 401s the same way")
	}
	if got == "Bearer stale-credential" {
		t.Error("the fallback left the refused credential on the client")
	}
}

// The one rule that keeps the two layers from drifting apart again: the
// registrar owns the client's bearer, and nothing else assigns it. The
// production code is the subject — a test may still arm a client to set a
// scenario up, as the fallback test above does.
func TestNoProductionCodeOutsideRegistrationSetsTheBearer(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	// Where the credential is legitimately owned or defined.
	allowed := map[string]bool{
		filepath.Join("internal", "registration", "registrar.go"): true,
		filepath.Join("internal", "api", "client.go"):             true,
	}

	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(src), "SetAuthToken(") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !allowed[rel] {
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the tree: %v", err)
	}
	for _, file := range offenders {
		t.Errorf("%s sets the control-plane bearer: Register arms the client with the envelope on every path, so an assignment here can only replace it with something the control plane refuses", file)
	}
}

// ---------------------------------------------------------------------------
// Capability manifest and the digest that travels with it
// ---------------------------------------------------------------------------

// declaredHooks re-encodes each hook's digest into the manifest's wire form and
// drops what it cannot convert. Dropping matters more than converting: the
// manifest is validated as a whole, so one unusable entry would cost the binary
// version and digest of the entire report.
func TestDeclaredHooks(t *testing.T) {
	sum := sha256.Sum256([]byte("hook payload"))
	hexDigest := hex.EncodeToString(sum[:])
	wantChecksum := base64.StdEncoding.EncodeToString(sum[:])

	got := declaredHooks([]api.HookInfo{
		{Name: "post-install", Checksum: hexDigest},
		{Name: "no-checksum"},
		{Name: "not-a-digest", Checksum: "zzzz"},
		{Name: "nightly", Checksum: hexDigest},
	}, discardLogger())

	want := []api.DeclaredHook{
		{Name: "post-install", Checksum: wantChecksum},
		{Name: "nightly", Checksum: wantChecksum},
	}
	if len(got) != len(want) {
		t.Fatalf("declaredHooks returned %d entries (%+v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Nil rather than an empty slice: the field is omitempty, and `null` where
	// the contract expects an array is a decode failure upstream.
	if got := declaredHooks(nil, discardLogger()); got != nil {
		t.Errorf("declaredHooks(nil) = %+v, want nil", got)
	}
	if got := declaredHooks([]api.HookInfo{{Name: "bad", Checksum: "zzzz"}}, discardLogger()); got != nil {
		t.Errorf("declaredHooks with no convertible entry = %+v, want nil", got)
	}
}

// What the daemon actually puts on the wire for the two operations that carry
// the binary digest. Both were refused by the control plane before: the
// heartbeat sent hex where the field is `format: byte`, and the manifest sent a
// nested `binary` object plus a `builtin_actions` list the handler rejects as
// unknown fields — gzip-compressed on top, which the handler read as JSON.
func TestRunUp_CapabilityManifestAndHeartbeatAreContractShaped(t *testing.T) {
	type capture struct {
		body     []byte
		encoding string
	}
	var (
		mu    sync.Mutex
		calls = map[string]capture{}
	)
	record := func(name string, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls[name] = capture{body: raw, encoding: r.Header.Get("Content-Encoding")}
		mu.Unlock()
	}
	get := func(name string) (capture, bool) {
		mu.Lock()
		defer mu.Unlock()
		c, ok := calls[name]
		return c, ok
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/register":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(api.RegisterResponse{
				NodeID:           upTestNodeID,
				MeshIP:           "100.64.0.1",
				SigningPublicKey: upTestSigningKey,
				SigningKeyID:     upTestSigningKID,
				NSK:              upTestNSK,
				DomainMeshCIDR:   "100.64.0.0/10",
				PeerSnapshot:     []api.RegisterPeer{},
			})
			return
		case strings.HasSuffix(r.URL.Path, "/capabilities"):
			record("capabilities", r)
			w.WriteHeader(http.StatusNoContent)
			return
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			record("heartbeat", r)
		}
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)

	writeUpConfig(t, srv.URL, upDaemonYAML(t))
	shutdown := startRunUp(t)
	defer shutdown()

	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, ok := get("capabilities"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the daemon never reported its capability manifest")
		}
		time.Sleep(10 * time.Millisecond)
	}

	caps, _ := get("capabilities")
	// Not compressed: only the three ingest operations accept an encoding.
	if caps.encoding != "" {
		t.Errorf("capabilities Content-Encoding = %q, want none", caps.encoding)
	}
	// Strict decoding, as the handler does — an unknown field fails here.
	var manifest api.CapabilityManifestRequest
	dec := json.NewDecoder(bytes.NewReader(caps.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		t.Fatalf("manifest is not contract-shaped: %v (body: %s)", err, caps.body)
	}
	if strings.TrimSpace(manifest.BinaryVersion) == "" {
		t.Error("binary_version is empty, which the handler refuses")
	}
	assertWireDigest(t, "binary_checksum", manifest.BinaryChecksum)
	if fp := manifest.SSHHostKeyFingerprint; fp != "" && !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("ssh_host_key_fingerprint = %q, want the SHA256:<base64> form", fp)
	}

	// The heartbeat carries the same digest and must carry it the same way.
	for {
		if _, ok := get("heartbeat"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the daemon never sent a heartbeat")
		}
		time.Sleep(10 * time.Millisecond)
	}
	hb, _ := get("heartbeat")
	var beat api.HeartbeatRequest
	if err := json.Unmarshal(hb.body, &beat); err != nil {
		t.Fatalf("decode heartbeat: %v (body: %s)", err, hb.body)
	}
	assertWireDigest(t, "heartbeat binary_checksum", beat.BinaryChecksum)
}

// assertWireDigest checks a checksum field is the form the contract's
// `format: byte` declares: 32 bytes, standard-padded base64. Hex is the shape
// that was refused, and it decodes as base64 to 48 bytes — so the length check
// is what separates the two.
func assertWireDigest(t *testing.T, field, value string) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Errorf("%s = %q, which is not standard base64: %v", field, value, err)
		return
	}
	if len(raw) != sha256.Size {
		t.Errorf("%s = %q decodes to %d bytes, want %d (a hex digest decodes to 48)", field, value, len(raw), sha256.Size)
	}
}
