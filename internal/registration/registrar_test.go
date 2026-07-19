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
		NodeID:           "node-123",
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
		// Subsequent calls (Ping) observe the post-register auth token.
		mu.Lock()
		postAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
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
	if identity.NodeID != "node-123" {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, "node-123")
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
	if loaded.NodeID != "node-123" {
		t.Errorf("persisted NodeID = %q, want %q", loaded.NodeID, "node-123")
	}
	if loaded.SigningKeyID != "did:web:plexsphere.com#key-2026-04" {
		t.Errorf("persisted SigningKeyID = %q, want %q", loaded.SigningKeyID, "did:web:plexsphere.com#key-2026-04")
	}
	if loaded.DomainMeshCIDR != "100.64.0.0/10" {
		t.Errorf("persisted DomainMeshCIDR = %q, want %q", loaded.DomainMeshCIDR, "100.64.0.0/10")
	}

	// After success the client authenticates subsequent calls with the NSK.
	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	mu.Lock()
	gotPost := postAuth
	mu.Unlock()
	if gotPost != "Bearer "+testNSK {
		t.Errorf("post-register Authorization = %q, want %q", gotPost, "Bearer "+testNSK)
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
// brand-new registration, so a lost 201 response would consume the one-time
// bootstrap token twice and strand an allocated node ID and mesh IP.
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
		NodeID:           "existing-node",
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

	if identity.NodeID != "existing-node" {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, "existing-node")
	}

	// Verify no HTTP requests were made.
	if reqCount.Load() != 0 {
		t.Errorf("request count = %d, want 0", reqCount.Load())
	}
}

func TestRegistrar_ReRegistersOnCorruptIdentity(t *testing.T) {
	var reqCount atomic.Int32
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := newSuccessResponse()
		resp.NodeID = "new-node"
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

	if identity.NodeID != "new-node" {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, "new-node")
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
	if loaded.NodeID != "new-node" {
		t.Errorf("persisted NodeID = %q, want %q", loaded.NodeID, "new-node")
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
		resp.NodeID = "node-retry"
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

	if identity.NodeID != "node-retry" {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, "node-retry")
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
		resp.NodeID = "node-429"
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

	if identity.NodeID != "node-429" {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, "node-429")
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
	if identity.NodeID != "node-123" {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, "node-123")
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
		resp.NodeID = "node-full"
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
	if identity.NodeID != "node-full" {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, "node-full")
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
	if loaded.NodeID != "node-full" {
		t.Errorf("loaded NodeID = %q, want %q", loaded.NodeID, "node-full")
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
	if identity2.NodeID != "node-full" {
		t.Errorf("second call NodeID = %q, want %q", identity2.NodeID, "node-full")
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

// A valid nsk decodes to the raw AES-256-GCM key, while the identity keeps the
// encoded form for the Authorization header.
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
// re-registration that fails must leave the previous credential in place
// instead of wedging every later request as unauthenticated. Register never
// touches the shared token, so the previous nsk is still there for later calls.
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
		w.WriteHeader(http.StatusOK)
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
	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
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
	// writeIdentityFiles writes identity.json with node_id "node-legacy".
	if identity.NodeID != "node-legacy" {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, "node-legacy")
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
// "Retry-After: 86400" parks registration for a day.
func TestRegistrar_RetryAfterCappedByMaxRetryDuration(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "86400")
		writeProblem(w, http.StatusTooManyRequests, "", "rate limited")
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
	if !strings.Contains(out, "node-123") {
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
