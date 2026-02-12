package registration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
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

func successHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/register" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(api.RegisterResponse{
			NodeID:          "node-123",
			MeshIP:          "100.64.0.1",
			SigningPublicKey: "signing-key-base64",
			NodeSecretKey:   "nsk-secret-value",
			Peers:           []api.Peer{},
		})
	}
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
	var capturedReq api.RegisterRequest
	var capturedAuth string

	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		capturedAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&capturedReq)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(api.RegisterResponse{
			NodeID:          "node-123",
			MeshIP:          "100.64.0.1",
			SigningPublicKey: "signing-key-base64",
			NodeSecretKey:   "nsk-secret-value",
			Peers:           []api.Peer{},
		})
	})

	dataDir := t.TempDir()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("boot-token-123"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	reg := NewRegistrar(client, Config{
		DataDir:   dataDir,
		TokenFile: tokenFile,
		Hostname:  "test-host",
	}, discardLogger())

	identity, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Verify identity fields.
	if identity.NodeID != "node-123" {
		t.Errorf("NodeID = %q, want %q", identity.NodeID, "node-123")
	}
	if identity.MeshIP != "100.64.0.1" {
		t.Errorf("MeshIP = %q, want %q", identity.MeshIP, "100.64.0.1")
	}
	if identity.SigningPublicKey != "signing-key-base64" {
		t.Errorf("SigningPublicKey = %q, want %q", identity.SigningPublicKey, "signing-key-base64")
	}
	if identity.NodeSecretKey != "nsk-secret-value" {
		t.Errorf("NodeSecretKey = %q, want %q", identity.NodeSecretKey, "nsk-secret-value")
	}
	if len(identity.PrivateKey) != 32 {
		t.Errorf("PrivateKey length = %d, want 32", len(identity.PrivateKey))
	}

	// Verify request payload.
	if capturedReq.Token != "boot-token-123" {
		t.Errorf("request token = %q, want %q", capturedReq.Token, "boot-token-123")
	}
	if capturedReq.Hostname != "test-host" {
		t.Errorf("request hostname = %q, want %q", capturedReq.Hostname, "test-host")
	}
	if capturedReq.PublicKey == "" {
		t.Error("request public_key is empty")
	}

	// Verify auth header used bootstrap token.
	if capturedAuth != "Bearer boot-token-123" {
		t.Errorf("Authorization = %q, want %q", capturedAuth, "Bearer boot-token-123")
	}

	// Verify identity persisted to disk.
	loaded, err := LoadIdentity(dataDir)
	if err != nil {
		t.Fatalf("LoadIdentity after registration: %v", err)
	}
	if loaded.NodeID != "node-123" {
		t.Errorf("persisted NodeID = %q, want %q", loaded.NodeID, "node-123")
	}

	if reqCount.Load() != 1 {
		t.Errorf("request count = %d, want 1", reqCount.Load())
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
		NodeID:          "existing-node",
		MeshIP:          "100.64.0.99",
		SigningPublicKey: "existing-spk",
		PrivateKey:      make([]byte, 32),
		NodeSecretKey:   "existing-nsk",
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
		_ = json.NewEncoder(w).Encode(api.RegisterResponse{
			NodeID:          "new-node",
			MeshIP:          "100.64.0.2",
			SigningPublicKey: "new-spk",
			NodeSecretKey:   "new-nsk",
			Peers:           []api.Peer{},
		})
	})

	dataDir := t.TempDir()
	// Write corrupt identity.json.
	if err := os.WriteFile(filepath.Join(dataDir, "identity.json"), []byte("{bad json"), 0600); err != nil {
		t.Fatalf("write corrupt identity: %v", err)
	}

	reg := NewRegistrar(client, Config{
		DataDir:    dataDir,
		TokenValue: "boot-token",
		Hostname:   "test-host",
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
		DataDir:    t.TempDir(),
		TokenValue: "bad-token",
		Hostname:   "test-host",
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
		DataDir:    t.TempDir(),
		TokenValue: "token",
		Hostname:   "test-host",
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
		_ = json.NewEncoder(w).Encode(api.RegisterResponse{
			NodeID:          "node-retry",
			MeshIP:          "100.64.0.3",
			SigningPublicKey: "spk",
			NodeSecretKey:   "nsk",
			Peers:           []api.Peer{},
		})
	})

	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "token",
		Hostname:         "test-host",
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
		_ = json.NewEncoder(w).Encode(api.RegisterResponse{
			NodeID:          "node-429",
			MeshIP:          "100.64.0.4",
			SigningPublicKey: "spk",
			NodeSecretKey:   "nsk",
			Peers:           []api.Peer{},
		})
	})

	fc := newFakeClock()
	reg := NewRegistrar(client, Config{
		DataDir:          t.TempDir(),
		TokenValue:       "token",
		Hostname:         "test-host",
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
		Hostname:         "test-host",
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
		Hostname:         "test-host",
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
		DataDir:   t.TempDir(),
		TokenFile: tokenFile,
		Hostname:  "test-host",
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
		DataDir:   t.TempDir(),
		TokenFile: tokenFile,
		Hostname:  "test-host",
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
		NodeID:          "node-1",
		MeshIP:          "100.64.0.1",
		SigningPublicKey: "spk",
		PrivateKey:      make([]byte, 32),
		NodeSecretKey:   "nsk",
	}
	if err := SaveIdentity(dataDir, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	if !reg.IsRegistered() {
		t.Error("IsRegistered() = false after SaveIdentity, want true")
	}
}

func TestRegistrar_SetsAuthTokenBeforeAndAfterRegistration(t *testing.T) {
	var authTokensDuringRequest []string
	var mu sync.Mutex

	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authTokensDuringRequest = append(authTokensDuringRequest, r.Header.Get("Authorization"))
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(api.RegisterResponse{
			NodeID:          "node-auth",
			MeshIP:          "100.64.0.5",
			SigningPublicKey: "spk",
			NodeSecretKey:   "nsk-after-reg",
			Peers:           []api.Peer{},
		})
	})

	reg := NewRegistrar(client, Config{
		DataDir:    t.TempDir(),
		TokenValue: "bootstrap-token-xyz",
		Hostname:   "test-host",
	}, discardLogger())

	_, err := reg.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Verify bootstrap token was used during the request.
	mu.Lock()
	defer mu.Unlock()
	if len(authTokensDuringRequest) == 0 {
		t.Fatal("no requests captured")
	}
	if authTokensDuringRequest[0] != "Bearer bootstrap-token-xyz" {
		t.Errorf("auth during request = %q, want %q", authTokensDuringRequest[0], "Bearer bootstrap-token-xyz")
	}
}

func TestRegistrar_FullFlow(t *testing.T) {
	var capturedReq api.RegisterRequest
	var capturedAuth string

	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/register" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		capturedAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&capturedReq)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(api.RegisterResponse{
			NodeID:          "node-full",
			MeshIP:          "100.64.0.10",
			SigningPublicKey: "full-spk",
			NodeSecretKey:   "full-nsk",
			Peers:           []api.Peer{{ID: "p1", MeshIP: "100.64.0.11"}},
		})
	})

	dataDir := t.TempDir()
	tokenDir := t.TempDir()
	tokenFile := filepath.Join(tokenDir, "token")
	if err := os.WriteFile(tokenFile, []byte("full-flow-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	reg := NewRegistrar(client, Config{
		DataDir:   dataDir,
		TokenFile: tokenFile,
		Hostname:  "full-flow-host",
		Metadata:  map[string]string{"env": "test"},
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
	if identity.NodeSecretKey != "full-nsk" {
		t.Errorf("NodeSecretKey = %q, want %q", identity.NodeSecretKey, "full-nsk")
	}
	if len(identity.PrivateKey) != 32 {
		t.Errorf("PrivateKey length = %d, want 32", len(identity.PrivateKey))
	}

	// Step 3: Verify request fields.
	if capturedReq.Token != "full-flow-token" {
		t.Errorf("request Token = %q, want %q", capturedReq.Token, "full-flow-token")
	}
	if capturedReq.Hostname != "full-flow-host" {
		t.Errorf("request Hostname = %q, want %q", capturedReq.Hostname, "full-flow-host")
	}
	if capturedReq.PublicKey == "" {
		t.Error("request PublicKey is empty")
	}
	if capturedReq.Metadata["env"] != "test" {
		t.Errorf("request Metadata[env] = %q, want %q", capturedReq.Metadata["env"], "test")
	}
	if capturedAuth != "Bearer full-flow-token" {
		t.Errorf("Authorization = %q, want %q", capturedAuth, "Bearer full-flow-token")
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
