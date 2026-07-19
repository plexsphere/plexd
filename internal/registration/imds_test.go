package registration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// imdsHandler is a configurable test handler that simulates an IMDS endpoint
// supporting both IMDSv2 session token acquisition and value reads.
type imdsHandler struct {
	sessionToken   string // returned by PUT /latest/api/token; empty = 404
	bootstrapToken string // returned by GET on tokenPath; empty = 404
	tokenPath      string // expected GET path

	putCalled    bool
	putTTL       string
	getCalled    bool
	getSessionTk string
}

func (h *imdsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
		h.putCalled = true
		h.putTTL = r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds")
		if h.sessionToken == "" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(h.sessionToken))

	case r.Method == http.MethodGet && r.URL.Path == h.tokenPath:
		h.getCalled = true
		h.getSessionTk = r.Header.Get("X-aws-ec2-metadata-token")
		if h.bootstrapToken == "" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(h.bootstrapToken))

	default:
		http.NotFound(w, r)
	}
}

func TestIMDSProvider_ReadValue_IMDSv2(t *testing.T) {
	h := &imdsHandler{
		sessionToken:   "v2-session-token",
		bootstrapToken: "  imds-token-value\n",
		tokenPath:      "/plexd/bootstrap-token",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)

	token, err := p.ReadValue(context.Background(), "/plexd/bootstrap-token")
	if err != nil {
		t.Fatalf("ReadValue() error: %v", err)
	}
	if token != "imds-token-value" {
		t.Fatalf("ReadValue() = %q, want %q", token, "imds-token-value")
	}
	if !h.putCalled {
		t.Error("expected PUT to /latest/api/token")
	}
	if h.putTTL != "21600" {
		t.Errorf("PUT TTL header = %q, want %q", h.putTTL, "21600")
	}
	if h.getSessionTk != "v2-session-token" {
		t.Errorf("GET session token header = %q, want %q", h.getSessionTk, "v2-session-token")
	}
}

func TestIMDSProvider_ReadValue_IMDSv1Fallback(t *testing.T) {
	h := &imdsHandler{
		sessionToken:   "", // IMDSv2 unavailable
		bootstrapToken: "v1-token",
		tokenPath:      "/plexd/bootstrap-token",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)

	token, err := p.ReadValue(context.Background(), "/plexd/bootstrap-token")
	if err != nil {
		t.Fatalf("ReadValue() error: %v", err)
	}
	if token != "v1-token" {
		t.Fatalf("ReadValue() = %q, want %q", token, "v1-token")
	}
	if !h.putCalled {
		t.Error("expected PUT attempt even when IMDSv2 unavailable")
	}
	if h.getSessionTk != "" {
		t.Errorf("GET session token header = %q, want empty (IMDSv1 fallback)", h.getSessionTk)
	}
}

func TestIMDSProvider_ReadValue_CustomPath(t *testing.T) {
	h := &imdsHandler{
		sessionToken:   "",
		bootstrapToken: "custom-path-token",
		tokenPath:      "/custom/token/path",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)

	token, err := p.ReadValue(context.Background(), "/custom/token/path")
	if err != nil {
		t.Fatalf("ReadValue() error: %v", err)
	}
	if token != "custom-path-token" {
		t.Fatalf("ReadValue() = %q, want %q", token, "custom-path-token")
	}
}

func TestIMDSProvider_ReadValue_MultiplePaths(t *testing.T) {
	// A single provider reads distinct values from distinct paths per call,
	// proving the path is supplied per read rather than fixed at construction.
	h := &multiPathHandler{values: map[string]string{
		"/plexd/bootstrap-token": "the-token",
		"/plexd/project-id":      "the-project-id",
	}}
	srv := httptest.NewServer(h)
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)

	token, err := p.ReadValue(context.Background(), "/plexd/bootstrap-token")
	if err != nil {
		t.Fatalf("ReadValue(token path) error: %v", err)
	}
	if token != "the-token" {
		t.Fatalf("ReadValue(token path) = %q, want %q", token, "the-token")
	}

	projectID, err := p.ReadValue(context.Background(), "/plexd/project-id")
	if err != nil {
		t.Fatalf("ReadValue(project-id path) error: %v", err)
	}
	if projectID != "the-project-id" {
		t.Fatalf("ReadValue(project-id path) = %q, want %q", projectID, "the-project-id")
	}
}

// multiPathHandler serves distinct values on distinct GET paths and returns no
// IMDSv2 session token, forcing IMDSv1 GETs.
type multiPathHandler struct {
	values map[string]string
}

func (h *multiPathHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
		http.NotFound(w, r)
		return
	}
	if v, ok := h.values[r.URL.Path]; ok && r.Method == http.MethodGet {
		_, _ = w.Write([]byte(v))
		return
	}
	http.NotFound(w, r)
}

func TestIMDSProvider_ReadValue_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)

	_, err := p.ReadValue(context.Background(), "/plexd/bootstrap-token")
	if err == nil {
		t.Fatal("ReadValue() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("error = %q, want mention of status 500", err.Error())
	}
}

func TestIMDSProvider_ReadValue_EmptyBody(t *testing.T) {
	h := &imdsHandler{
		sessionToken:   "",
		bootstrapToken: "  \n  ",
		tokenPath:      "/plexd/bootstrap-token",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)

	_, err := p.ReadValue(context.Background(), "/plexd/bootstrap-token")
	if err == nil {
		t.Fatal("ReadValue() expected error for empty body, got nil")
	}
	if !strings.Contains(err.Error(), "empty value") {
		t.Fatalf("error = %q, want mention of empty value", err.Error())
	}
}

func TestIMDSProvider_ReadValue_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("token"))
	}))
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.ReadValue(ctx, "/plexd/bootstrap-token")
	if err == nil {
		t.Fatal("ReadValue() expected error for canceled context, got nil")
	}
}

func TestIMDSProvider_TrailingSlashBaseURL(t *testing.T) {
	h := &imdsHandler{
		sessionToken:   "",
		bootstrapToken: "slash-token",
		tokenPath:      "/plexd/bootstrap-token",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL+"/")

	token, err := p.ReadValue(context.Background(), "/plexd/bootstrap-token")
	if err != nil {
		t.Fatalf("ReadValue() error: %v", err)
	}
	if token != "slash-token" {
		t.Fatalf("ReadValue() = %q, want %q", token, "slash-token")
	}
}

func TestIMDSProvider_ReadValue_LargeValue(t *testing.T) {
	// A value larger than the old token cap (512) but within maxValueLength is
	// now returned successfully: the old per-layer token cap no longer applies,
	// since the resolver validates length instead.
	large := strings.Repeat("A", maxTokenLength+100)
	h := &imdsHandler{
		sessionToken:   "",
		bootstrapToken: large,
		tokenPath:      "/plexd/bootstrap-token",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)

	value, err := p.ReadValue(context.Background(), "/plexd/bootstrap-token")
	if err != nil {
		t.Fatalf("ReadValue() error: %v", err)
	}
	if value != large {
		t.Fatalf("ReadValue() length = %d, want %d", len(value), len(large))
	}
}

func TestTokenResolver_FromIMDSProvider(t *testing.T) {
	h := &imdsHandler{
		sessionToken:   "",
		bootstrapToken: "imds-bootstrap-token",
		tokenPath:      "/plexd/bootstrap-token",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	cfg := &Config{
		UseMetadata:       true,
		MetadataTokenPath: "/plexd/bootstrap-token",
		MetadataTimeout:   2 * time.Second,
	}
	provider := NewIMDSProvider(cfg.MetadataTimeout, srv.URL)

	resolver := NewTokenResolver(cfg, provider)
	result, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if result.Value != "imds-bootstrap-token" {
		t.Fatalf("Resolve().Value = %q, want %q", result.Value, "imds-bootstrap-token")
	}
	if result.FilePath != "" {
		t.Fatalf("Resolve().FilePath = %q, want empty", result.FilePath)
	}
}

func TestTokenResolver_IMDSProvider_DirectValueTakesPriority(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("imds-token"))
	}))
	defer srv.Close()

	cfg := &Config{
		TokenValue:        "direct-value",
		UseMetadata:       true,
		MetadataTokenPath: "/plexd/bootstrap-token",
		MetadataTimeout:   2 * time.Second,
	}
	provider := NewIMDSProvider(cfg.MetadataTimeout, srv.URL)

	resolver := NewTokenResolver(cfg, provider)
	result, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if result.Value != "direct-value" {
		t.Fatalf("Resolve().Value = %q, want %q (direct value should take priority)", result.Value, "direct-value")
	}
}

// A 503 from IMDS is a transient failure, not "not provisioned" (which is a
// 404 → ErrMetadataNotFound). The token is the input whose absence stops
// registration, so the read error must surface rather than being reported as a
// missing token.
func TestTokenResolver_IMDSProvider_SurfacesReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cfg := &Config{
		UseMetadata:       true,
		MetadataTokenPath: "/plexd/bootstrap-token",
		MetadataTimeout:   2 * time.Second,
	}
	provider := NewIMDSProvider(cfg.MetadataTimeout, srv.URL)

	resolver := NewTokenResolver(cfg, provider)
	_, err := resolver.Resolve(context.Background())
	if err == nil {
		t.Fatal("Resolve() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "read token from metadata") {
		t.Fatalf("error = %q, want mention of 'read token from metadata'", err.Error())
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error = %q, want it to carry the underlying IMDS status", err.Error())
	}
}

// The IMDSv2 session token is valid for six hours, and registration resolves
// up to four values. Re-acquiring per read multiplies the round-trips and,
// on a host where the link-local address is unroutable, the dead time before
// registration fails.
func TestIMDSProvider_ReusesSessionToken(t *testing.T) {
	var puts, gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == imdsSessionTokenPath {
			puts.Add(1)
			_, _ = w.Write([]byte("v2-session-token"))
			return
		}
		gets.Add(1)
		if got := r.Header.Get("X-aws-ec2-metadata-token"); got != "v2-session-token" {
			t.Errorf("GET %s session token = %q, want %q", r.URL.Path, got, "v2-session-token")
		}
		_, _ = w.Write([]byte("value"))
	}))
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)
	for _, path := range []string{"/plexd/bootstrap-token", "/plexd/project-id", "/plexd/resource-handle"} {
		if _, err := p.ReadValue(context.Background(), path); err != nil {
			t.Fatalf("ReadValue(%s): %v", path, err)
		}
	}

	if puts.Load() != 1 {
		t.Errorf("session token acquired %d times, want 1 (cached across reads)", puts.Load())
	}
	if gets.Load() != 3 {
		t.Errorf("value reads = %d, want 3", gets.Load())
	}
}

// A failed acquisition is not cached, so the IMDSv1 fallback keeps working on
// every read rather than being pinned by one bad PUT.
func TestIMDSProvider_DoesNotCacheFailedSessionToken(t *testing.T) {
	var puts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts.Add(1)
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != "" {
			t.Error("IMDSv1 fallback must not send a session token header")
		}
		_, _ = w.Write([]byte("value"))
	}))
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)
	for i := 0; i < 2; i++ {
		if _, err := p.ReadValue(context.Background(), "/plexd/project-id"); err != nil {
			t.Fatalf("ReadValue: %v", err)
		}
	}
	if puts.Load() != 2 {
		t.Errorf("session token attempts = %d, want 2 (failures are not cached)", puts.Load())
	}
}

// A response longer than maxValueLength must be rejected, not truncated: a
// silently shortened value would be sent to the control plane as a real
// project_id.
func TestIMDSProvider_RejectsOversizedValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			http.NotFound(w, r)
			return
		}
		// Trailing whitespace would let TrimSpace hide the truncation.
		_, _ = w.Write([]byte(strings.Repeat("a", maxValueLength) + "bbb   "))
	}))
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)
	_, err := p.ReadValue(context.Background(), "/plexd/project-id")
	if err == nil {
		t.Fatal("expected error for oversized metadata value, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum length") {
		t.Fatalf("error = %q, want mention of 'exceeds maximum length'", err.Error())
	}
}

// A path the metadata service does not serve is "not provisioned", which
// callers distinguish from a read failure.
func TestIMDSProvider_NotFoundIsSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)
	_, err := p.ReadValue(context.Background(), "/plexd/requested-resource-id")
	if !errors.Is(err, ErrMetadataNotFound) {
		t.Fatalf("error = %v, want ErrMetadataNotFound", err)
	}
}

// Metadata paths come from config (registration.metadata_*_path) and the URL is
// built by concatenation, so a path that does not start with a single "/" can
// retarget the request — and the IMDSv2 session token it carries — at another
// host. Reject those before any request leaves the process.
func TestIMDSProvider_ReadValue_RejectsNonAbsolutePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request must be made for a non-absolute path")
	}))
	defer srv.Close()

	p := NewIMDSProvider(2*time.Second, srv.URL)

	tests := []struct {
		name string
		path string
	}{
		{"userinfo injection", "@evil.example.com/x"},
		{"scheme-relative host", "//evil.example.com/x"},
		{"relative path", "plexd/token"},
		{"empty path", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ReadValue(context.Background(), tt.path)
			if err == nil {
				t.Fatalf("ReadValue(%q): expected error, got nil", tt.path)
			}
			if !strings.Contains(err.Error(), "path must be absolute") {
				t.Errorf("error = %q, want it to report a non-absolute path", err.Error())
			}
		})
	}
}
