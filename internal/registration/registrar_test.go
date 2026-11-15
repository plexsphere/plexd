package registration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

const (
	testProjectID      = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0"
	testResourceHandle = "edge-router-01"
	// testNodeID and testNodeIDAlt are the canonical UUIDs the fixture control
	// plane issues as node_id. The bearer envelope embeds their 16 raw bytes,
	// so unlike the mock-era free-form ids they must parse as UUIDs.
	testNodeID    = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3"
	testNodeIDAlt = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b7"
)

// nonceRe matches a canonical lowercase UUIDv4 (the nonce format plexd sends).
var nonceRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

var (
	// testNSK is a valid nsk: 32 bytes in the standard-padded base64 form the
	// register contract specifies.
	testNSK = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, 32))
	// testNSKAlt is a second, distinct valid nsk for tests that assert which
	// response the persisted identity was built from.
	testNSKAlt = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5b}, 32))
)

// wantBearer assembles the bearer envelope expected on the Authorization
// header after registration. The exact wire form is pinned by the BearerToken
// tests in identity_test.go; the registrar tests only assert that the client
// presents what BearerToken assembles.
func wantBearer(t *testing.T, nodeID, nsk string) string {
	t.Helper()
	id := &NodeIdentity{NodeID: nodeID, NodeSecretKey: nsk}
	bearer, err := id.BearerToken()
	if err != nil {
		t.Fatalf("BearerToken(%q): %v", nodeID, err)
	}
	return bearer
}

// testServer creates an httptest.Server and a ControlPlane client connected to it.
func testServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *api.ControlPlane) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cfg := api.Config{BaseURL: srv.URL}
	client, err := api.NewControlPlane(cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	return srv, client
}

// newSuccessResponse returns a fully-populated new-contract register response.
func newSuccessResponse() api.RegisterResponse {
	return api.RegisterResponse{
		NodeID:           testNodeID,
		MeshIP:           "100.64.0.1",
		SigningPublicKey: "signing-key-base64",
		SigningKeyID:     "did:web:plexsphere.com#key-2026-04",
		NSK:              testNSK,
		DomainMeshCIDR:   "100.64.0.0/10",
		PeerSnapshot:     []api.RegisterPeer{},
	}
}

func successHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/register" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(newSuccessResponse())
	}
}

// writeProblem writes an RFC 9457 application/problem+json error response.
func writeProblem(w http.ResponseWriter, status int, code, detail string) {
	body := map[string]any{
		"type":     "about:blank",
		"title":    http.StatusText(status),
		"status":   status,
		"detail":   detail,
		"instance": "/v1/register",
	}
	if code != "" {
		body["type"] = "https://api.plexsphere.com/problems/" + code
		body["code"] = code
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// fakeMetadataProvider serves registration inputs keyed by metadata path.
type fakeMetadataProvider struct {
	values map[string]string
}

func (f *fakeMetadataProvider) ReadValue(_ context.Context, path string) (string, error) {
	v, ok := f.values[path]
	if !ok {
		return "", ErrMetadataNotFound
	}
	return v, nil
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Now()}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	ch := make(chan time.Time, 1)
	ch <- c.now
	return ch
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRegistrar_SuccessfulRegistration(t *testing.T) {
	var reqCount atomic.Int32
	var mu sync.Mutex
	var capturedReq api.RegisterRequest
	var capturedRawBody, registerAuth, postAuth string

	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/register" {
			reqCount.Add(1)
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			capturedRawBody = string(body)
			registerAuth = r.Header.Get("Authorization")
			mu.Unlock()
			_ = json.Unmarshal(body, &capturedReq)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(newSuccessResponse())
			return
		}
		// Subsequent calls (heartbeat) observe the post-register auth token.
		mu.Lock()
		postAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	dataDir := t.TempDir()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("boot-token-123"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	reg := NewRegistrar(client, Config{
		DataDir:        dataDir,
		TokenFile:      tokenFile,
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, discardLogger())

	identity, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Verify identity fields, including the new signing_key_id and domain_mesh_cidr.
	if identity.NodeID != testNodeID {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, testNodeID)
	}
	if identity.MeshIP != "100.64.0.1" {
		t.Errorf("MeshIP = %q, want %q", identity.MeshIP, "100.64.0.1")
	}
	if identity.SigningPublicKey != "signing-key-base64" {
		t.Errorf("SigningPublicKey = %q, want %q", identity.SigningPublicKey, "signing-key-base64")
	}
	if identity.SigningKeyID != "did:web:plexsphere.com#key-2026-04" {
		t.Errorf("SigningKeyID = %q, want %q", identity.SigningKeyID, "did:web:plexsphere.com#key-2026-04")
	}
	if identity.DomainMeshCIDR != "100.64.0.0/10" {
		t.Errorf("DomainMeshCIDR = %q, want %q", identity.DomainMeshCIDR, "100.64.0.0/10")
	}
	if identity.NodeSecretKey != testNSK {
		t.Errorf("NodeSecretKey = %q, want %q", identity.NodeSecretKey, testNSK)
	}
	if len(identity.PrivateKey) != 32 {
		t.Errorf("PrivateKey length = %d, want 32", len(identity.PrivateKey))
	}

	// Verify request payload carries the new fields and omits requested_resource_id.
	mu.Lock()
	req := capturedReq
	rawBody := capturedRawBody
	auth := registerAuth
	mu.Unlock()
	if req.ProjectID != testProjectID {
		t.Errorf("request project_id = %q, want %q", req.ProjectID, testProjectID)
	}
	if req.ResourceHandle != testResourceHandle {
		t.Errorf("request resource_handle = %q, want %q", req.ResourceHandle, testResourceHandle)
	}
	if req.BootstrapToken != "boot-token-123" {
		t.Errorf("request bootstrap_token = %q, want %q", req.BootstrapToken, "boot-token-123")
	}
	if req.PublicKey == "" {
		t.Error("request public_key is empty")
	}
	if strings.Contains(rawBody, "requested_resource_id") {
		t.Errorf("request should omit requested_resource_id when unset, got: %s", rawBody)
	}

	// Register is security: [] — no Authorization header is sent.
	if auth != "" {
		t.Errorf("register Authorization = %q, want empty", auth)
	}

	// Verify identity persisted to disk, including the new fields.
	loaded, err := LoadIdentity(dataDir)
	if err != nil {
		t.Fatalf("LoadIdentity after registration: %v", err)
	}
	if loaded.NodeID != testNodeID {
		t.Errorf("persisted NodeID = %q, want %q", loaded.NodeID, testNodeID)
	}
	if loaded.SigningKeyID != "did:web:plexsphere.com#key-2026-04" {
		t.Errorf("persisted SigningKeyID = %q, want %q", loaded.SigningKeyID, "did:web:plexsphere.com#key-2026-04")
	}
	if loaded.DomainMeshCIDR != "100.64.0.0/10" {
		t.Errorf("persisted DomainMeshCIDR = %q, want %q", loaded.DomainMeshCIDR, "100.64.0.0/10")
	}

	// After success the client authenticates subsequent calls with the
	// bearer envelope assembled from node_id and nsk — never the raw nsk.
	if _, err := client.Heartbeat(context.Background(), testNodeID, api.HeartbeatRequest{}); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	mu.Lock()
	gotPost := postAuth
	mu.Unlock()
	if want := "Bearer " + wantBearer(t, testNodeID, testNSK); gotPost != want {
		t.Errorf("post-register Authorization = %q, want %q", gotPost, want)
	}

	if reqCount.Load() != 1 {
		t.Errorf("request count = %d, want 1", reqCount.Load())
	}
}

func TestRegistrar_ClearsAuthHeaderOnReRegistration(t *testing.T) {
	var mu sync.Mutex
	var registerAuth string

	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		registerAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(newSuccessResponse())
	})

	// Simulate a stale NSK left over from a previous registration.
	client.SetAuthToken("stale-nsk")

	reg := NewRegistrar(client, Config{
		DataDir:        t.TempDir(),
		TokenValue:     "boot-token",
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, discardLogger())

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if registerAuth != "" {
		t.Errorf("register Authorization = %q, want empty (stale NSK must be cleared)", registerAuth)
	}
}

// The nonce is what lets the control plane recognise a retry of a request it
// may already have committed. A fresh nonce per attempt makes every retry a
// brand-new registration, so a lost 201 response would spend two redemptions
// of the bootstrap token and strand an allocated node ID and mesh IP.
func TestRegistrar_NonceStableAcrossRetries(t *testing.T) {
	var reqCount atomic.Int32
	var mu sync.Mutex
	var nonces []string

	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		var req api.RegisterRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		nonces = append(nonces, req.Nonce)
		mu.Unlock()

		if reqCount.Add(1) <= 2 {
			writeProblem(w, http.StatusServiceUnavailable, "pool_exhausted", "address pool exhausted")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(newSuccessResponse())
	})

	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "boot-token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 30 * time.Second,
	}, discardLogger())
	reg.SetClock(newFakeClock())

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if reqCount.Load() != 3 {
		t.Fatalf("request count = %d, want 3", reqCount.Load())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(nonces) != 3 {
		t.Fatalf("captured %d nonces, want 3", len(nonces))
	}
	for i, n := range nonces {
		if !nonceRe.MatchString(n) {
			t.Errorf("nonce[%d] = %q does not match UUIDv4 pattern", i, n)
		}
		if n != nonces[0] {
			t.Errorf("nonce[%d] = %q, want %q; retries must reuse the nonce of the registration they retry", i, n, nonces[0])
		}
	}
}

func TestRegistrar_MissingProjectIDFailsBeforeHTTP(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusCreated)
	})

	reg := NewRegistrar(client, Config{
		DataDir:        t.TempDir(),
		TokenValue:     "boot-token",
		ResourceHandle: testResourceHandle,
	}, discardLogger())

	_, err := reg.Register(context.Background())
	if err == nil {
		t.Fatal("Register: expected error, got nil")
	}
	want := "registration: project_id is required (set registration.project_id, --project-id, or PLEXD_PROJECT_ID)"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if reqCount.Load() != 0 {
		t.Errorf("request count = %d, want 0 (must fail before any HTTP call)", reqCount.Load())
	}
}

func TestRegistrar_MissingResourceHandleFailsBeforeHTTP(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusCreated)
	})

	reg := NewRegistrar(client, Config{
		DataDir:    t.TempDir(),
		TokenValue: "boot-token",
		ProjectID:  testProjectID,
	}, discardLogger())

	_, err := reg.Register(context.Background())
	if err == nil {
		t.Fatal("Register: expected error, got nil")
	}
	want := "registration: resource_handle is required (set registration.resource_handle, --resource-handle, or PLEXD_RESOURCE_HANDLE)"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if reqCount.Load() != 0 {
		t.Errorf("request count = %d, want 0 (must fail before any HTTP call)", reqCount.Load())
	}
}

func TestRegistrar_422StopsAfterOneAttempt(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		writeProblem(w, http.StatusUnprocessableEntity, "", "empty resource_handle")
	})

	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "boot-token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 30 * time.Second,
	}, discardLogger())
	reg.SetClock(newFakeClock())

	_, err := reg.Register(context.Background())
	if err == nil {
		t.Fatal("Register: expected error, got nil")
	}
	if reqCount.Load() != 1 {
		t.Errorf("request count = %d, want 1 (no retry on 422)", reqCount.Load())
	}
}

func TestRegistrar_403TokenExpiredStops(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		writeProblem(w, http.StatusForbidden, "token_expired", "bootstrap token expired")
	})

	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "boot-token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 30 * time.Second,
	}, discardLogger())
	reg.SetClock(newFakeClock())

	_, err := reg.Register(context.Background())
	if err == nil {
		t.Fatal("Register: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "token_expired") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "token_expired")
	}
	if reqCount.Load() != 1 {
		t.Errorf("request count = %d, want 1 (no retry on 403)", reqCount.Load())
	}
}

func TestRegistrar_IMDSFallbackFillsProjectAndResource(t *testing.T) {
	var capturedReq api.RegisterRequest
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&capturedReq)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(newSuccessResponse())
	})

	reg := NewRegistrar(client, Config{
		DataDir:     t.TempDir(),
		TokenValue:  "boot-token",
		UseMetadata: true,
	}, discardLogger())
	reg.SetMetadataProvider(&fakeMetadataProvider{values: map[string]string{
		DefaultMetadataProjectIDPath:      testProjectID,
		DefaultMetadataResourceHandlePath: "imds-resource",
	}})

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if capturedReq.ProjectID != testProjectID {
		t.Errorf("request project_id = %q, want %q", capturedReq.ProjectID, testProjectID)
	}
	if capturedReq.ResourceHandle != "imds-resource" {
		t.Errorf("request resource_handle = %q, want %q", capturedReq.ResourceHandle, "imds-resource")
	}
}

func TestRegistrar_SkipsRegistrationIfIdentityExists(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	dataDir := t.TempDir()

	// Pre-save identity.
	existing := &NodeIdentity{
		NodeID:           testNodeID,
		MeshIP:           "100.64.0.99",
		SigningPublicKey: "existing-spk",
		PrivateKey:       make([]byte, 32),
		NodeSecretKey:    testNSK,
	}
	if err := SaveIdentity(dataDir, existing); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	reg := NewRegistrar(client, Config{
		DataDir:    dataDir,
		TokenValue: "unused-token",
	}, discardLogger())

	identity, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if identity.NodeID != testNodeID {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, testNodeID)
	}

	// Verify no HTTP requests were made.
	if reqCount.Load() != 0 {
		t.Errorf("request count = %d, want 0", reqCount.Load())
	}
}

// Resuming a persisted identity must arm the shared client with the bearer
// envelope, exactly like a fresh registration does — the resume path is what
// every restart takes, so a raw-nsk regression here silently 401s the whole
// fleet after its next rollout.
func TestRegistrar_ResumedIdentityPresentsEnvelope(t *testing.T) {
	var mu sync.Mutex
	var gotAuth string
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	dataDir := t.TempDir()
	existing := &NodeIdentity{
		NodeID:           testNodeID,
		MeshIP:           "100.64.0.99",
		SigningPublicKey: "existing-spk",
		PrivateKey:       make([]byte, 32),
		NodeSecretKey:    testNSK,
	}
	if err := SaveIdentity(dataDir, existing); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	reg := NewRegistrar(client, Config{
		DataDir:    dataDir,
		TokenValue: "unused-token",
	}, discardLogger())

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := client.Heartbeat(context.Background(), testNodeID, api.HeartbeatRequest{}); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if want := "Bearer " + wantBearer(t, testNodeID, testNSK); gotAuth != want {
		t.Errorf("post-resume Authorization = %q, want %q", gotAuth, want)
	}
}

// An identity whose node_id is not a canonical UUID (a mock-era leftover)
// cannot form the bearer envelope; the registrar must treat it like corrupt
// identity files and fall through to a fresh registration.
func TestRegistrar_ReRegistersOnNonUUIDIdentity(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(newSuccessResponse())
	})

	dataDir := t.TempDir()
	existing := &NodeIdentity{
		NodeID:           "node-mock-era",
		MeshIP:           "100.64.0.99",
		SigningPublicKey: "existing-spk",
		PrivateKey:       make([]byte, 32),
		NodeSecretKey:    testNSK,
	}
	if err := SaveIdentity(dataDir, existing); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	reg := NewRegistrar(client, Config{
		DataDir:        dataDir,
		TokenValue:     "boot-token",
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, discardLogger())

	identity, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if identity.NodeID != testNodeID {
		t.Errorf("NodeID = %q, want the freshly registered %q", identity.NodeID, testNodeID)
	}
	if reqCount.Load() != 1 {
		t.Errorf("request count = %d, want 1 (fresh registration)", reqCount.Load())
	}
}

func TestRegistrar_ReRegistersOnCorruptIdentity(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := newSuccessResponse()
		resp.NodeID = testNodeIDAlt
		resp.MeshIP = "100.64.0.2"
		resp.NSK = testNSKAlt
		_ = json.NewEncoder(w).Encode(resp)
	})

	dataDir := t.TempDir()
	// Write corrupt identity.json.
	if err := os.WriteFile(filepath.Join(dataDir, "identity.json"), []byte("{bad json"), 0600); err != nil {
		t.Fatalf("write corrupt identity: %v", err)
	}

	reg := NewRegistrar(client, Config{
		DataDir:        dataDir,
		TokenValue:     "boot-token",
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, discardLogger())

	identity, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if identity.NodeID != testNodeIDAlt {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, testNodeIDAlt)
	}

	// Verify a registration request was made.
	if reqCount.Load() != 1 {
		t.Errorf("request count = %d, want 1", reqCount.Load())
	}

	// Verify new identity overwrites corrupt files.
	loaded, err := LoadIdentity(dataDir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if loaded.NodeID != testNodeIDAlt {
		t.Errorf("persisted NodeID = %q, want %q", loaded.NodeID, testNodeIDAlt)
	}
}

func TestRegistrar_401FailsImmediately(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid token"))
	})

	reg := NewRegistrar(client, Config{
		DataDir:        t.TempDir(),
		TokenValue:     "bad-token",
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, discardLogger())

	_, err := reg.Register(context.Background())
	if err == nil {
		t.Fatal("Register: expected error, got nil")
	}

	if reqCount.Load() != 1 {
		t.Errorf("request count = %d, want 1 (no retry on 401)", reqCount.Load())
	}
}

func TestRegistrar_409FailsImmediately(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("already registered"))
	})

	reg := NewRegistrar(client, Config{
		DataDir:        t.TempDir(),
		TokenValue:     "token",
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, discardLogger())

	_, err := reg.Register(context.Background())
	if err == nil {
		t.Fatal("Register: expected error, got nil")
	}

	if reqCount.Load() != 1 {
		t.Errorf("request count = %d, want 1 (no retry on 409)", reqCount.Load())
	}
}

func TestRegistrar_RetriesOnTransientError(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("service unavailable"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := newSuccessResponse()
		resp.NodeID = testNodeIDAlt
		resp.MeshIP = "100.64.0.3"
		_ = json.NewEncoder(w).Encode(resp)
	})

	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 30 * time.Second,
	}, discardLogger())
	// Use fake clock so retries are instant.
	reg.SetClock(newFakeClock())

	identity, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if identity.NodeID != testNodeIDAlt {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, testNodeIDAlt)
	}

	if reqCount.Load() != 3 {
		t.Errorf("request count = %d, want 3", reqCount.Load())
	}
}

func TestRegistrar_Retry429RespectsRetryAfter(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("rate limited"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := newSuccessResponse()
		resp.NodeID = testNodeIDAlt
		resp.MeshIP = "100.64.0.4"
		_ = json.NewEncoder(w).Encode(resp)
	})

	fc := newFakeClock()
	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 30 * time.Second,
	}, discardLogger())
	reg.SetClock(fc)

	identity, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if identity.NodeID != testNodeIDAlt {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, testNodeIDAlt)
	}
	if reqCount.Load() != 2 {
		t.Errorf("request count = %d, want 2", reqCount.Load())
	}
}

func TestRegistrar_RetryTimeout(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	})

	fc := newFakeClock()
	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 100 * time.Millisecond,
	}, discardLogger())
	reg.SetClock(fc)

	_, err := reg.Register(context.Background())
	if err == nil {
		t.Fatal("Register: expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "retry timeout") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "retry timeout")
	}
}

func TestRegistrar_ContextCancellationStopsRetry(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Create a clock that cancels context on first After call (during retry wait).
	clockThatCancels := &cancellingClock{cancel: cancel}

	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 10 * time.Second,
	}, discardLogger())
	reg.SetClock(clockThatCancels)

	_, err := reg.Register(ctx)
	if err == nil {
		t.Fatal("Register: expected context error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

// cancellingClock cancels a context when After is called, then blocks on the returned channel.
type cancellingClock struct {
	cancel context.CancelFunc
	mu     sync.Mutex
	now    time.Time
}

func (c *cancellingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *cancellingClock) After(d time.Duration) <-chan time.Time {
	c.cancel()
	// Return a channel that never fires, so the select picks up ctx.Done().
	return make(chan time.Time)
}

func TestRegistrar_DeletesTokenFileAfterRegistration(t *testing.T) {
	_, client := testServer(t, successHandler(t))

	tokenFile := filepath.Join(t.TempDir(), "bootstrap-token")
	if err := os.WriteFile(tokenFile, []byte("delete-me-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	reg := NewRegistrar(client, Config{
		DataDir:        t.TempDir(),
		TokenFile:      tokenFile,
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, discardLogger())

	_, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Token file should be deleted.
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Errorf("token file still exists after registration")
	}
}

func TestRegistrar_TokenDeletionFailureDoesNotFailRegistration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on windows")
	}
	_, client := testServer(t, successHandler(t))

	// Create token file in a directory, then make it read-only so deletion fails.
	tokenDir := t.TempDir()
	tokenFile := filepath.Join(tokenDir, "bootstrap-token")
	if err := os.WriteFile(tokenFile, []byte("protected-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	// Make directory read-only to prevent file deletion.
	if err := os.Chmod(tokenDir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(tokenDir, 0700)
	})

	reg := NewRegistrar(client, Config{
		DataDir:        t.TempDir(),
		TokenFile:      tokenFile,
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, discardLogger())

	identity, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if identity.NodeID != testNodeID {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, testNodeID)
	}
}

// tokenInReadOnlyDir writes a token file with the given mode into a directory
// it then makes read-only, the way plexd's systemd unit leaves /etc/plexd: the
// unlink fails, and the file's own mode decides whether it can be emptied.
// Root ignores both modes, so the caller is skipped there.
func tokenInReadOnlyDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory and file modes")
	}
	tokenDir := t.TempDir()
	tokenFile := filepath.Join(tokenDir, "bootstrap-token")
	if err := os.WriteFile(tokenFile, []byte("spent-token"), mode); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	if err := os.Chmod(tokenDir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(tokenDir, 0700)
	})
	return tokenFile
}

func TestRegistrar_EmptiesTokenFileWhenRemoveFails(t *testing.T) {
	tokenFile := tokenInReadOnlyDir(t, 0600)
	_, client := testServer(t, successHandler(t))

	var logs bytes.Buffer
	reg := NewRegistrar(client, Config{
		DataDir:        t.TempDir(),
		TokenFile:      tokenFile,
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, slog.New(slog.NewTextHandler(&logs, nil)))

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	info, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("token file size = %d, want 0", info.Size())
	}
	out := logs.String()
	if !strings.Contains(out, `level=INFO msg="token file emptied, it could not be removed"`) {
		t.Errorf("logs = %q, want the emptied record at INFO", out)
	}
	if !strings.Contains(out, " path="+tokenFile+" ") {
		t.Errorf("logs = %q, want path=%s", out, tokenFile)
	}
	if strings.Contains(out, "failed to delete token file") {
		t.Errorf("logs = %q, want no deletion warning", out)
	}
	if strings.Contains(out, "spent-token") {
		t.Error("logs leak the bootstrap token")
	}
}

func TestRegistrar_WarnsWhenTokenFileCannotBeEmptied(t *testing.T) {
	tokenFile := tokenInReadOnlyDir(t, 0400)
	_, client := testServer(t, successHandler(t))

	var logs bytes.Buffer
	reg := NewRegistrar(client, Config{
		DataDir:        t.TempDir(),
		TokenFile:      tokenFile,
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, slog.New(slog.NewTextHandler(&logs, nil)))

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	data, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if string(data) != "spent-token" {
		t.Errorf("token file = %q, want it unchanged", data)
	}
	out := logs.String()
	if !strings.Contains(out, `level=WARN msg="failed to delete token file"`) {
		t.Errorf("logs = %q, want the deletion warning at WARN", out)
	}
	// The leading space keeps truncate_error= from satisfying the error= check.
	for _, attr := range []string{
		` error="remove ` + tokenFile + `: permission denied"`,
		` truncate_error="truncate ` + tokenFile + `: permission denied"`,
	} {
		if !strings.Contains(out, attr) {
			t.Errorf("logs = %q, want %s", out, attr)
		}
	}
	if strings.Contains(out, "token file emptied") {
		t.Errorf("logs = %q, want no emptied record", out)
	}
}

func TestRegistrar_TokenFileGoneBeforeCleanup(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "bootstrap-token")
	if err := os.WriteFile(tokenFile, []byte("vanishing-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	register := successHandler(t)
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		// The file disappears while the registration is in flight.
		if err := os.Remove(tokenFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove token file: %v", err)
		}
		register(w, r)
	})

	var logs bytes.Buffer
	reg := NewRegistrar(client, Config{
		DataDir:        t.TempDir(),
		TokenFile:      tokenFile,
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, slog.New(slog.NewTextHandler(&logs, nil)))

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	out := logs.String()
	for _, msg := range []string{"failed to delete token file", "token file emptied"} {
		if strings.Contains(out, msg) {
			t.Errorf("logs = %q, want no %q record for a file that is already gone", out, msg)
		}
	}
	if _, err := os.Stat(tokenFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat token file = %v, want it still absent", err)
	}
}

func TestRegistrar_LeavesTokenFileWhenTokenNotFromFile(t *testing.T) {
	_, client := testServer(t, successHandler(t))

	tokenFile := filepath.Join(t.TempDir(), "bootstrap-token")
	if err := os.WriteFile(tokenFile, []byte("file-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	reg := NewRegistrar(client, Config{
		DataDir:        t.TempDir(),
		TokenValue:     "direct-token",
		TokenFile:      tokenFile,
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, discardLogger())

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// The direct value won, so the file was never read and is not spent.
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if string(data) != "file-token" {
		t.Errorf("token file = %q, want it unchanged", data)
	}
}

func TestRegistrar_IsRegistered(t *testing.T) {
	dataDir := t.TempDir()

	// No client needed for IsRegistered.
	reg := NewRegistrar(nil, Config{DataDir: dataDir}, discardLogger())

	if reg.IsRegistered() {
		t.Error("IsRegistered() = true on empty dir, want false")
	}

	// Save identity.
	id := &NodeIdentity{
		NodeID:           "node-1",
		MeshIP:           "100.64.0.1",
		SigningPublicKey: "spk",
		PrivateKey:       make([]byte, 32),
		NodeSecretKey:    testNSK,
	}
	if err := SaveIdentity(dataDir, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	if !reg.IsRegistered() {
		t.Error("IsRegistered() = false after SaveIdentity, want true")
	}
}

func TestRegistrar_FullFlow(t *testing.T) {
	var mu sync.Mutex
	var capturedReq api.RegisterRequest
	var capturedRawBody string

	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/register" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		capturedRawBody = string(body)
		mu.Unlock()
		_ = json.Unmarshal(body, &capturedReq)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := newSuccessResponse()
		resp.NodeID = testNodeIDAlt
		resp.MeshIP = "100.64.0.10"
		resp.NSK = testNSKAlt
		resp.PeerSnapshot = []api.RegisterPeer{
			{NodeID: "p1", MeshIP: "100.64.0.11", PublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	dataDir := t.TempDir()
	tokenDir := t.TempDir()
	tokenFile := filepath.Join(tokenDir, "token")
	if err := os.WriteFile(tokenFile, []byte("full-flow-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	reg := NewRegistrar(client, Config{
		DataDir:             dataDir,
		TokenFile:           tokenFile,
		ProjectID:           testProjectID,
		ResourceHandle:      "full-flow-resource",
		RequestedResourceID: "substrate-override",
	}, discardLogger())

	// Step 1: Register.
	identity, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Step 2: Verify identity.
	if identity.NodeID != testNodeIDAlt {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, testNodeIDAlt)
	}
	if identity.MeshIP != "100.64.0.10" {
		t.Errorf("MeshIP = %q, want %q", identity.MeshIP, "100.64.0.10")
	}
	if identity.NodeSecretKey != testNSKAlt {
		t.Errorf("NodeSecretKey = %q, want %q", identity.NodeSecretKey, testNSKAlt)
	}
	if len(identity.PrivateKey) != 32 {
		t.Errorf("PrivateKey length = %d, want 32", len(identity.PrivateKey))
	}

	// Step 3: Verify request fields, including requested_resource_id when set.
	mu.Lock()
	req := capturedReq
	rawBody := capturedRawBody
	mu.Unlock()
	if req.ProjectID != testProjectID {
		t.Errorf("request ProjectID = %q, want %q", req.ProjectID, testProjectID)
	}
	if req.ResourceHandle != "full-flow-resource" {
		t.Errorf("request ResourceHandle = %q, want %q", req.ResourceHandle, "full-flow-resource")
	}
	if req.BootstrapToken != "full-flow-token" {
		t.Errorf("request BootstrapToken = %q, want %q", req.BootstrapToken, "full-flow-token")
	}
	if req.RequestedResourceID != "substrate-override" {
		t.Errorf("request RequestedResourceID = %q, want %q", req.RequestedResourceID, "substrate-override")
	}
	if req.PublicKey == "" {
		t.Error("request PublicKey is empty")
	}
	if !strings.Contains(rawBody, "requested_resource_id") {
		t.Errorf("request should include requested_resource_id when set, got: %s", rawBody)
	}

	// Step 4: Verify identity persisted.
	loaded, err := LoadIdentity(dataDir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if loaded.NodeID != testNodeIDAlt {
		t.Errorf("loaded NodeID = %q, want %q", loaded.NodeID, testNodeIDAlt)
	}

	// Step 5: Verify token file deleted.
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Error("token file should be deleted after registration")
	}

	// Step 6: Subsequent Register call returns cached identity.
	identity2, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}
	if identity2.NodeID != testNodeIDAlt {
		t.Errorf("second call NodeID = %q, want %q", identity2.NodeID, testNodeIDAlt)
	}
}

// nsk is standard-padded base64 per the register contract and doubles as the
// AES-256-GCM key for secret envelopes. Storing the encoded text verbatim
// would key AES off a 64-symbol alphabet instead of the 256 bits the
// credential carries, so a malformed nsk must fail loudly at registration
// rather than surface later as "decryption failed" on every secret.
func TestRegistrar_RejectsMalformedNSK(t *testing.T) {
	tests := []struct {
		name string
		nsk  string
	}{
		{"not base64", "nsk-secret-value"},
		{"decodes to 31 bytes", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, 31))},
		{"decodes to 33 bytes", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, 33))},
		{"empty", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				resp := newSuccessResponse()
				resp.NSK = tc.nsk
				_ = json.NewEncoder(w).Encode(resp)
			})

			dataDir := t.TempDir()
			reg := NewRegistrar(client, Config{
				DataDir:        dataDir,
				TokenValue:     "boot-token",
				ProjectID:      testProjectID,
				ResourceHandle: testResourceHandle,
			}, discardLogger())

			if _, err := reg.Register(context.Background()); err == nil {
				t.Fatal("expected error for malformed nsk, got nil")
			}
			// A rejected nsk must not be persisted as an identity.
			if _, err := LoadIdentity(dataDir); !errors.Is(err, ErrNotRegistered) {
				t.Errorf("LoadIdentity after rejected nsk = %v, want ErrNotRegistered", err)
			}
		})
	}
}

// A valid nsk decodes to the raw AES-256-GCM key; the Authorization header
// carries the envelope BearerToken assembles from it, never this decoded key
// nor the stored encoded form.
func TestNodeIdentity_SecretKeyDecodesNSK(t *testing.T) {
	id := &NodeIdentity{NodeSecretKey: testNSK}
	key, err := id.SecretKey()
	if err != nil {
		t.Fatalf("SecretKey: %v", err)
	}
	if !bytes.Equal(key, bytes.Repeat([]byte{0x2a}, 32)) {
		t.Errorf("SecretKey = %x, want 32 x 0x2a", key)
	}
}

// The client is shared with the heartbeat, SSE, state, and reconcile paths. A
// registration that fails must leave whatever credential the client already
// holds in place: POST /v1/register is security: [] and a failed Register
// leaves the shared token alone, so a previous nsk still authenticates later
// calls.
func TestRegistrar_LeavesPreviousAuthTokenOnFailedRegistration(t *testing.T) {
	var registerAuth, followupAuth string
	var mu sync.Mutex

	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/register" {
			mu.Lock()
			registerAuth = r.Header.Get("Authorization")
			mu.Unlock()
			writeProblem(w, http.StatusUnprocessableEntity, "", "resource_handle is required")
			return
		}
		// A subsequent call (heartbeat, SSE, …) on the shared client.
		mu.Lock()
		followupAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	client.SetAuthToken("previous-nsk")

	reg := NewRegistrar(client, Config{
		DataDir:        t.TempDir(),
		TokenValue:     "boot-token",
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, discardLogger())

	if _, err := reg.Register(context.Background()); err == nil {
		t.Fatal("expected registration to fail, got nil")
	}

	// Register itself is security: [] — no header travels with the call.
	mu.Lock()
	got := registerAuth
	mu.Unlock()
	if got != "" {
		t.Errorf("register Authorization = %q, want empty", got)
	}

	// The previous credential must still authenticate later requests.
	if _, err := client.Heartbeat(context.Background(), testNodeID, api.HeartbeatRequest{}); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	mu.Lock()
	gotFollowup := followupAuth
	mu.Unlock()
	if gotFollowup != "Bearer previous-nsk" {
		t.Errorf("follow-up Authorization = %q, want %q", gotFollowup, "Bearer previous-nsk")
	}
}

// project_id is the most common misconfiguration, and each resolution may hit
// the metadata service. Checking it as soon as it resolves avoids paying for
// the later lookups on a request already guaranteed to fail.
func TestRegistrar_MissingProjectIDSkipsLaterMetadataLookups(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("control plane must not be contacted when project_id is missing")
	})

	meta := &countingMetadataProvider{}
	reg := NewRegistrar(client, Config{
		DataDir:     t.TempDir(),
		TokenValue:  "boot-token",
		UseMetadata: true,
	}, discardLogger())
	reg.SetMetadataProvider(meta)

	_, err := reg.Register(context.Background())
	if err == nil || !strings.Contains(err.Error(), "project_id is required") {
		t.Fatalf("error = %v, want 'project_id is required'", err)
	}
	for _, path := range []string{DefaultMetadataResourceHandlePath, DefaultMetadataRequestedResourceIDPath} {
		if meta.count(path) != 0 {
			t.Errorf("%s read %d times, want 0 once project_id is known missing", path, meta.count(path))
		}
	}
}

// countingMetadataProvider records how often each path was read and serves no
// values, so every lookup reports "not provisioned".
type countingMetadataProvider struct {
	mu     sync.Mutex
	counts map[string]int
}

func (p *countingMetadataProvider) ReadValue(_ context.Context, path string) (string, error) {
	p.mu.Lock()
	if p.counts == nil {
		p.counts = map[string]int{}
	}
	p.counts[path]++
	p.mu.Unlock()
	return "", ErrMetadataNotFound
}

func (p *countingMetadataProvider) count(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counts[path]
}

// A node registered before nsk became base64 carries a raw 32-byte secret on
// disk. Upgrading plexd in place must keep that identity: forcing a fresh
// registration would brick the node because its bootstrap token was already
// consumed and deleted during the original registration. So the legacy identity
// loads and Register never contacts the control plane.
func TestRegistrar_KeepsLegacyRawNSKIdentity(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("control plane must not be contacted when a legacy identity is on disk")
		w.WriteHeader(http.StatusInternalServerError)
	})

	dataDir := t.TempDir()
	const legacyNSK = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
	writeIdentityFiles(t, dataDir, legacyNSK)

	reg := NewRegistrar(client, Config{
		DataDir:        dataDir,
		TokenValue:     "boot-token",
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, discardLogger())

	identity, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// writeIdentityFiles writes identity.json with node_id testNodeID: legacy
	// here means the pre-base64 nsk form, not a mock-era node id — real
	// enrolments always carried the control plane's UUID.
	if identity.NodeID != testNodeID {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, testNodeID)
	}
	// The raw secret doubles as the AES-256-GCM key and remains usable.
	key, err := identity.SecretKey()
	if err != nil {
		t.Fatalf("SecretKey: %v", err)
	}
	if string(key) != legacyNSK {
		t.Errorf("SecretKey = %q, want %q", key, legacyNSK)
	}
}

// Retry-After is server-controlled and unbounded, and the retry deadline is
// only checked between attempts — so the sleep itself must be capped, or one
// "Retry-After: 86400" parks registration for a day. That holds for every 429
// but token_rate_limited: the per-IP limiter's rate_limited, and a 429 without
// a code, say nothing about the token and keep the budget.
func TestRegistrar_RetryAfterCappedByMaxRetryDuration(t *testing.T) {
	for _, code := range []string{"", "rate_limited"} {
		t.Run("code="+code, func(t *testing.T) {
			_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "86400")
				writeProblem(w, http.StatusTooManyRequests, code, "rate limited")
			})

			const maxRetry = 5 * time.Second
			clk := &recordingClock{fakeClock: newFakeClock()}
			reg := NewRegistrar(client, Config{
				DataDir:          t.TempDir(),
				TokenValue:       "token",
				ProjectID:        testProjectID,
				ResourceHandle:   testResourceHandle,
				MaxRetryDuration: maxRetry,
			}, discardLogger())
			reg.SetClock(clk)

			_, err := reg.Register(context.Background())
			if err == nil {
				t.Fatal("Register: expected retry timeout error, got nil")
			}
			if !strings.Contains(err.Error(), "retry timeout") {
				t.Errorf("error = %q, want to contain %q", err.Error(), "retry timeout")
			}

			delays := clk.Delays()
			if len(delays) == 0 {
				t.Fatal("no retry delay recorded")
			}
			for i, d := range delays {
				if d > maxRetry {
					t.Errorf("delay[%d] = %v, want <= MaxRetryDuration (%v)", i, d, maxRetry)
				}
			}
		})
	}
}

// rateLimitedRequests records what a tokenRateLimitedServer was sent.
type rateLimitedRequests struct {
	count      atomic.Int32
	mu         sync.Mutex
	nonces     []string
	publicKeys []string
}

func (r *rateLimitedRequests) seen() (nonces, publicKeys []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.nonces...), append([]string(nil), r.publicKeys...)
}

// tokenRateLimitedServer answers the first limited registrations with 429
// token_rate_limited, the refusal of the rate limit of the token's
// BootstrapToken policy, and every later one with after. retryAfter is sent as
// the Retry-After header unless it is empty. A nil after answers 201.
func tokenRateLimitedServer(t *testing.T, limited int, retryAfter string, after http.HandlerFunc) (*api.ControlPlane, *rateLimitedRequests) {
	t.Helper()
	if after == nil {
		after = successHandler(t)
	}
	reqs := &rateLimitedRequests{}
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body api.RegisterRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		reqs.mu.Lock()
		reqs.nonces = append(reqs.nonces, body.Nonce)
		reqs.publicKeys = append(reqs.publicKeys, body.PublicKey)
		reqs.mu.Unlock()
		if int(reqs.count.Add(1)) > limited {
			after(w, r)
			return
		}
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		writeProblem(w, http.StatusTooManyRequests, "token_rate_limited",
			"POST /v1/register: the BootstrapToken was redeemed as often as the rate limit of its bootstrap token policy allows")
	})
	return client, reqs
}

// assertDelayIn fails unless delay lies in [lo, hi].
func assertDelayIn(t *testing.T, i int, delay, lo, hi time.Duration) {
	t.Helper()
	if delay < lo || delay > hi {
		t.Errorf("delay[%d] = %v, want in [%v, %v]", i, delay, lo, hi)
	}
}

// A token rate-limited by its BootstrapToken policy is valid and the control
// plane is answering, so registration waits the whole Retry-After even when it
// is far beyond max_retry_duration, and asks again with the same request: the
// refusal did not count as a redemption, so the same nonce can still succeed.
func TestRegistrar_TokenRateLimitWaitsPastMaxRetryDuration(t *testing.T) {
	client, reqs := tokenRateLimitedServer(t, 2, "3600", nil)

	clk := &recordingClock{fakeClock: newFakeClock()}
	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 5 * time.Second,
	}, discardLogger())
	reg.SetClock(clk)

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if got := reqs.count.Load(); got != 3 {
		t.Fatalf("request count = %d, want 3", got)
	}
	nonces, keys := reqs.seen()
	for i := 1; i < len(nonces); i++ {
		if nonces[i] != nonces[0] {
			t.Errorf("request %d nonce = %q, want %q (the first attempt's)", i+1, nonces[i], nonces[0])
		}
		if keys[i] != keys[0] {
			t.Errorf("request %d public_key = %q, want %q (the first attempt's)", i+1, keys[i], keys[0])
		}
	}

	delays := clk.Delays()
	if len(delays) != 2 {
		t.Fatalf("recorded %d delays (%v), want 2", len(delays), delays)
	}
	for i, d := range delays {
		assertDelayIn(t, i, d, 3600*time.Second, 3630*time.Second)
	}
}

// Without a usable hint the wait falls back to the backoff interval, doubling
// from 1s. A Retry-After of 0, one that is not an integer, a negative one, and
// one so large that its conversion to a duration wraps to a few hundred
// nanoseconds all count as no hint: registration never waits less than a
// second, so a broken header cannot turn the wait into a busy loop.
func TestRegistrar_TokenRateLimitWithoutRetryAfterBacksOff(t *testing.T) {
	for _, retryAfter := range []string{"", "0", "soon", "-5", "20211507185753197"} {
		t.Run("Retry-After="+retryAfter, func(t *testing.T) {
			client, reqs := tokenRateLimitedServer(t, 3, retryAfter, nil)

			clk := &recordingClock{fakeClock: newFakeClock()}
			reg := NewRegistrar(client, Config{
				DataDir:          t.TempDir(),
				TokenValue:       "token",
				ProjectID:        testProjectID,
				ResourceHandle:   testResourceHandle,
				MaxRetryDuration: 30 * time.Second,
			}, discardLogger())
			reg.SetClock(clk)

			if _, err := reg.Register(context.Background()); err != nil {
				t.Fatalf("Register: %v", err)
			}
			if got := reqs.count.Load(); got != 4 {
				t.Fatalf("request count = %d, want 4", got)
			}

			delays := clk.Delays()
			if len(delays) != 3 {
				t.Fatalf("recorded %d delays (%v), want 3", len(delays), delays)
			}
			assertDelayIn(t, 0, delays[0], 1*time.Second, 1100*time.Millisecond)
			assertDelayIn(t, 1, delays[1], 2*time.Second, 2200*time.Millisecond)
			assertDelayIn(t, 2, delays[2], 4*time.Second, 4400*time.Millisecond)
		})
	}
}

// The longest window a BootstrapToken policy can state is 720 hours, so a
// hint beyond it is clamped rather than parking registration for months.
func TestRegistrar_TokenRateLimitClampsRetryAfter(t *testing.T) {
	client, _ := tokenRateLimitedServer(t, 1, "5184000", nil)

	clk := &recordingClock{fakeClock: newFakeClock()}
	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 5 * time.Second,
	}, discardLogger())
	reg.SetClock(clk)

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	delays := clk.Delays()
	if len(delays) != 1 {
		t.Fatalf("recorded %d delays (%v), want 1", len(delays), delays)
	}
	assertDelayIn(t, 0, delays[0], 720*time.Hour, 720*time.Hour+30*time.Second)
}

// Nodes that share a token are told to come back at the same instant, so each
// wait grows by a random amount: over many waits on the same hint, not one is
// shorter than the hint, none is longer than its tenth or 30s allows, and they
// are not all the bare hint.
func TestRegistrar_TokenRateLimitSpreadsWaits(t *testing.T) {
	const waits = 20
	client, _ := tokenRateLimitedServer(t, waits, "3600", nil)

	clk := &recordingClock{fakeClock: newFakeClock()}
	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 5 * time.Second,
	}, discardLogger())
	reg.SetClock(clk)

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	delays := clk.Delays()
	if len(delays) != waits {
		t.Fatalf("recorded %d delays, want %d", len(delays), waits)
	}
	spread := false
	for i, d := range delays {
		assertDelayIn(t, i, d, 3600*time.Second, 3630*time.Second)
		if d > 3600*time.Second {
			spread = true
		}
	}
	if !spread {
		t.Errorf("all %d waits were exactly the 3600s hint, want them spread: %v", waits, delays)
	}
}

func TestTokenRateLimitSpread(t *testing.T) {
	for _, tt := range []struct {
		delay time.Duration
		limit time.Duration
	}{
		{3600 * time.Second, 30 * time.Second},
		{720 * time.Hour, 30 * time.Second},
		{5 * time.Second, 500 * time.Millisecond},
		{time.Second, 100 * time.Millisecond},
	} {
		t.Run(tt.delay.String(), func(t *testing.T) {
			positive := false
			for range 300 {
				got := tokenRateLimitSpread(tt.delay)
				if got < 0 || got > tt.limit {
					t.Fatalf("tokenRateLimitSpread(%v) = %v, want in [0, %v]", tt.delay, got, tt.limit)
				}
				if got > 0 {
					positive = true
				}
			}
			if !positive {
				t.Errorf("tokenRateLimitSpread(%v) was 0 in 300 draws, want a spread", tt.delay)
			}
		})
	}
	for _, delay := range []time.Duration{0, 9 * time.Nanosecond, -time.Second} {
		if got := tokenRateLimitSpread(delay); got != 0 {
			t.Errorf("tokenRateLimitSpread(%v) = %v, want 0", delay, got)
		}
	}
}

// The budget starts again after each rate-limit wait. A control plane that
// then fails transiently gets the whole max_retry_duration, measured from the
// end of the wait: with a 5s budget the 503 backoff of 1s, 2s and 4s (±25%)
// fits four attempts before the budget runs out on the fifth request overall.
func TestRegistrar_TokenRateLimitRestartsRetryBudget(t *testing.T) {
	client, reqs := tokenRateLimitedServer(t, 1, "600", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	})

	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 5 * time.Second,
	}, discardLogger())
	reg.SetClock(newFakeClock())

	_, err := reg.Register(context.Background())
	if err == nil {
		t.Fatal("Register: expected retry timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "retry timeout") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "retry timeout")
	}
	if !errors.Is(err, api.ErrServer) {
		t.Errorf("errors.Is(err, api.ErrServer) = false for %v, want the last 503 wrapped", err)
	}
	if got := reqs.count.Load(); got != 5 {
		t.Errorf("request count = %d, want 5 (one 429, then four 503s inside the restarted budget)", got)
	}
}

// The rate-limit branch runs before the budget check. A control plane that
// fails transiently until the 5s budget is spent and then answers
// token_rate_limited is waited out, not given up on: the 503 backoff of 1s, 2s
// and 4s (±25%) puts the fourth request past the budget, and that request is
// the 429.
func TestRegistrar_TokenRateLimitAfterSpentBudgetIsWaited(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch n := reqCount.Add(1); {
		case n <= 3:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("service unavailable"))
		case n == 4:
			w.Header().Set("Retry-After", "60")
			writeProblem(w, http.StatusTooManyRequests, "token_rate_limited", "rate limited by the bootstrap token policy")
		default:
			successHandler(t)(w, r)
		}
	})

	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 5 * time.Second,
	}, discardLogger())
	reg.SetClock(newFakeClock())

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v, want the 429 after the spent budget waited out", err)
	}
	if got := reqCount.Load(); got != 5 {
		t.Errorf("request count = %d, want 5", got)
	}
}

// A cancelled context ends the rate-limit wait at once, however long the hint.
func TestRegistrar_TokenRateLimitContextCancelled(t *testing.T) {
	client, reqs := tokenRateLimitedServer(t, 1, "3600", nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 5 * time.Second,
	}, discardLogger())
	reg.SetClock(&cancellingClock{cancel: cancel})

	_, err := reg.Register(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Register error = %v, want context.Canceled", err)
	}
	if got := reqs.count.Load(); got != 1 {
		t.Errorf("request count = %d, want 1", got)
	}
}

// The observer sees each wait start and end, also when the context ends it, so
// the health listener's mark never outlives the wait it names.
func TestRegistrar_TokenRateLimitObserver(t *testing.T) {
	newRegistrar := func(t *testing.T, client *api.ControlPlane) *Registrar {
		return NewRegistrar(client, Config{
			DataDir:          t.TempDir(),
			TokenValue:       "token",
			ProjectID:        testProjectID,
			ResourceHandle:   testResourceHandle,
			MaxRetryDuration: 5 * time.Second,
		}, discardLogger())
	}

	t.Run("two waits, then registered", func(t *testing.T) {
		client, _ := tokenRateLimitedServer(t, 2, "10", nil)
		reg := newRegistrar(t, client)
		reg.SetClock(newFakeClock())
		var seen []bool
		reg.SetRateLimitObserver(func(limited bool) { seen = append(seen, limited) })

		if _, err := reg.Register(context.Background()); err != nil {
			t.Fatalf("Register: %v", err)
		}
		if want := []bool{true, false, true, false}; !slices.Equal(seen, want) {
			t.Errorf("observer saw %v, want %v", seen, want)
		}
	})

	t.Run("wait ended by the context", func(t *testing.T) {
		client, _ := tokenRateLimitedServer(t, 1, "10", nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		reg := newRegistrar(t, client)
		reg.SetClock(&cancellingClock{cancel: cancel})
		var seen []bool
		reg.SetRateLimitObserver(func(limited bool) { seen = append(seen, limited) })

		if _, err := reg.Register(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Register error = %v, want context.Canceled", err)
		}
		if want := []bool{true, false}; !slices.Equal(seen, want) {
			t.Errorf("observer saw %v, want %v", seen, want)
		}
	})

	t.Run("no observer", func(t *testing.T) {
		client, _ := tokenRateLimitedServer(t, 2, "10", nil)
		reg := newRegistrar(t, client)
		reg.SetClock(newFakeClock())

		if _, err := reg.Register(context.Background()); err != nil {
			t.Fatalf("Register: %v", err)
		}
	})
}

// Each wait is one Warn record an operator can act on: when plexd asks again,
// and why. It is not the generic retry line, and it never carries the token.
// The clock starts at a fixed instant in a zone other than UTC, so retry_at is
// checked for its value and its zone, not only for its format.
func TestRegistrar_TokenRateLimitLogsWait(t *testing.T) {
	const token = "psb_test_e2eproject_node_ratelimitedsecretvalue"
	client, _ := tokenRateLimitedServer(t, 2, "10", nil)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	start := time.Date(2026, 11, 15, 12, 0, 0, 0, time.FixedZone("UTC+1", 3600))
	clk := &fakeClock{now: start}
	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       token,
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 5 * time.Second,
	}, logger)
	reg.SetClock(clk)

	if _, err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	const msg = "registration rate limited by the bootstrap token policy, waiting"
	var waits []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		switch rec["msg"] {
		case msg:
			waits = append(waits, rec)
		case "registration attempt failed, retrying":
			t.Errorf("a rate-limit wait logged the generic retry line: %v", rec)
		}
	}
	if len(waits) != 2 {
		t.Fatalf("logged %d %q records, want 2 (one per wait):\n%s", len(waits), msg, buf.String())
	}
	// The JSON handler writes a duration as integer nanoseconds.
	waitStart := start
	for i, rec := range waits {
		if rec["level"] != "WARN" {
			t.Errorf("wait %d level = %v, want WARN", i+1, rec["level"])
		}
		for _, key := range []string{"attempt", "retry_after", "delay", "retry_at", "error"} {
			if _, ok := rec[key]; !ok {
				t.Errorf("wait %d lacks the %q attribute: %v", i+1, key, rec)
			}
		}
		if got, want := rec["attempt"], float64(i+1); got != want {
			t.Errorf("wait %d attempt = %v, want %v", i+1, got, want)
		}
		if got, want := rec["retry_after"], float64(10*time.Second); got != want {
			t.Errorf("wait %d retry_after = %v, want %v (the 10s hint)", i+1, got, want)
		}
		delayNanos, ok := rec["delay"].(float64)
		if !ok {
			t.Fatalf("wait %d delay = %v, want a duration", i+1, rec["delay"])
		}
		delay := time.Duration(delayNanos)
		retryAt, ok := rec["retry_at"].(string)
		if !ok {
			t.Fatalf("wait %d retry_at = %v, want an RFC 3339 string", i+1, rec["retry_at"])
		}
		if want := waitStart.Add(delay).UTC().Format(time.RFC3339); retryAt != want {
			t.Errorf("wait %d retry_at = %q, want %q (the clock when the wait starts, plus its delay, in UTC)", i+1, retryAt, want)
		}
		waitStart = waitStart.Add(delay)
	}
	if strings.Contains(buf.String(), token) {
		t.Errorf("the log carries the bootstrap token:\n%s", buf.String())
	}
}

// A token at its redemption limit stays a final refusal: one attempt, no wait.
func TestRegistrar_403TokenConsumedStops(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		writeProblem(w, http.StatusForbidden, "token_consumed",
			"POST /v1/register: the BootstrapToken has reached the redemption limit of its bootstrap token policy.")
	})

	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "boot-token",
		ProjectID:        testProjectID,
		ResourceHandle:   testResourceHandle,
		MaxRetryDuration: 30 * time.Second,
	}, discardLogger())
	reg.SetClock(newFakeClock())

	_, err := reg.Register(context.Background())
	if !errors.Is(err, api.ErrForbidden) {
		t.Errorf("Register error = %v, want errors.Is(err, api.ErrForbidden)", err)
	}
	if got := reqCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1 (no retry on token_consumed)", got)
	}
}

// By the time the identity is persisted the control plane has already
// allocated the node and consumed the bootstrap token, and the nsk exists only
// in this process. A write failure therefore strands an orphan record that no
// retry reclaims, so it has to be logged loudly enough for an operator to act.
func TestRegistrar_LogsOrphanWhenSaveIdentityFails(t *testing.T) {
	_, client := testServer(t, successHandler(t))

	dataDir := t.TempDir()
	// Block the node_secret_key write (see the SaveIdentity test in
	// identity_test.go) so persisting fails after registration succeeds.
	if err := os.Mkdir(filepath.Join(dataDir, "node_secret_key"), 0700); err != nil {
		t.Fatalf("mkdir node_secret_key: %v", err)
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError}))

	reg := NewRegistrar(client, Config{
		DataDir:        dataDir,
		TokenValue:     "boot-token",
		ProjectID:      testProjectID,
		ResourceHandle: testResourceHandle,
	}, logger)

	if _, err := reg.Register(context.Background()); err == nil {
		t.Fatal("Register: expected save identity error, got nil")
	}

	out := logs.String()
	if !strings.Contains(out, "node allocated but not persisted") {
		t.Errorf("logs = %q, want the orphan marker", out)
	}
	if !strings.Contains(out, testNodeID) {
		t.Errorf("logs = %q, want the allocated node_id", out)
	}
	// The nsk must never reach the log.
	if strings.Contains(out, testNSK) {
		t.Error("logs leak the node secret key")
	}
}

// recordingClock is a fakeClock that records every delay handed to After.
type recordingClock struct {
	*fakeClock
	mu     sync.Mutex
	delays []time.Duration
}

func (c *recordingClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.delays = append(c.delays, d)
	c.mu.Unlock()
	return c.fakeClock.After(d)
}

func (c *recordingClock) Delays() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.delays...)
}
