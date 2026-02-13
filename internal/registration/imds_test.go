package registration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// imdsHandler is a configurable test handler that simulates an IMDS endpoint
// supporting both IMDSv2 session token acquisition and bootstrap token reads.
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

func TestIMDSProvider_ReadToken_IMDSv2(t *testing.T) {
	h := &imdsHandler{
		sessionToken:   "v2-session-token",
		bootstrapToken: "  imds-token-value\n",
		tokenPath:      "/plexd/bootstrap-token",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	cfg := &Config{MetadataTokenPath: "/plexd/bootstrap-token", MetadataTimeout: 2 * time.Second}
	p := NewIMDSProvider(cfg, srv.URL)

	token, err := p.ReadToken(context.Background())
	if err != nil {
		t.Fatalf("ReadToken() error: %v", err)
	}
	if token != "imds-token-value" {
		t.Fatalf("ReadToken() = %q, want %q", token, "imds-token-value")
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

func TestIMDSProvider_ReadToken_IMDSv1Fallback(t *testing.T) {
	h := &imdsHandler{
		sessionToken:   "", // IMDSv2 unavailable
		bootstrapToken: "v1-token",
		tokenPath:      "/plexd/bootstrap-token",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	cfg := &Config{MetadataTokenPath: "/plexd/bootstrap-token", MetadataTimeout: 2 * time.Second}
	p := NewIMDSProvider(cfg, srv.URL)

	token, err := p.ReadToken(context.Background())
	if err != nil {
		t.Fatalf("ReadToken() error: %v", err)
	}
	if token != "v1-token" {
		t.Fatalf("ReadToken() = %q, want %q", token, "v1-token")
	}
	if !h.putCalled {
		t.Error("expected PUT attempt even when IMDSv2 unavailable")
	}
	if h.getSessionTk != "" {
		t.Errorf("GET session token header = %q, want empty (IMDSv1 fallback)", h.getSessionTk)
	}
}

func TestIMDSProvider_ReadToken_CustomPath(t *testing.T) {
	h := &imdsHandler{
		sessionToken:   "",
		bootstrapToken: "custom-path-token",
		tokenPath:      "/custom/token/path",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	cfg := &Config{MetadataTokenPath: "/custom/token/path", MetadataTimeout: 2 * time.Second}
	p := NewIMDSProvider(cfg, srv.URL)

	token, err := p.ReadToken(context.Background())
	if err != nil {
		t.Fatalf("ReadToken() error: %v", err)
	}
	if token != "custom-path-token" {
		t.Fatalf("ReadToken() = %q, want %q", token, "custom-path-token")
	}
}

func TestIMDSProvider_ReadToken_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := &Config{MetadataTokenPath: "/plexd/bootstrap-token", MetadataTimeout: 2 * time.Second}
	p := NewIMDSProvider(cfg, srv.URL)

	_, err := p.ReadToken(context.Background())
	if err == nil {
		t.Fatal("ReadToken() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("error = %q, want mention of status 500", err.Error())
	}
}

func TestIMDSProvider_ReadToken_EmptyBody(t *testing.T) {
	h := &imdsHandler{
		sessionToken:   "",
		bootstrapToken: "  \n  ",
		tokenPath:      "/plexd/bootstrap-token",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	cfg := &Config{MetadataTokenPath: "/plexd/bootstrap-token", MetadataTimeout: 2 * time.Second}
	p := NewIMDSProvider(cfg, srv.URL)

	_, err := p.ReadToken(context.Background())
	if err == nil {
		t.Fatal("ReadToken() expected error for empty body, got nil")
	}
	if !strings.Contains(err.Error(), "empty token") {
		t.Fatalf("error = %q, want mention of empty token", err.Error())
	}
}

func TestIMDSProvider_ReadToken_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("token"))
	}))
	defer srv.Close()

	cfg := &Config{MetadataTokenPath: "/plexd/bootstrap-token", MetadataTimeout: 2 * time.Second}
	p := NewIMDSProvider(cfg, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.ReadToken(ctx)
	if err == nil {
		t.Fatal("ReadToken() expected error for canceled context, got nil")
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

	cfg := &Config{MetadataTokenPath: "/plexd/bootstrap-token", MetadataTimeout: 2 * time.Second}
	p := NewIMDSProvider(cfg, srv.URL+"/")

	token, err := p.ReadToken(context.Background())
	if err != nil {
		t.Fatalf("ReadToken() error: %v", err)
	}
	if token != "slash-token" {
		t.Fatalf("ReadToken() = %q, want %q", token, "slash-token")
	}
}

func TestIMDSProvider_ReadToken_OversizedToken(t *testing.T) {
	oversized := strings.Repeat("A", maxTokenLength+10)
	h := &imdsHandler{
		sessionToken:   "",
		bootstrapToken: oversized,
		tokenPath:      "/plexd/bootstrap-token",
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	cfg := &Config{MetadataTokenPath: "/plexd/bootstrap-token", MetadataTimeout: 2 * time.Second}
	p := NewIMDSProvider(cfg, srv.URL)

	_, err := p.ReadToken(context.Background())
	if err == nil {
		t.Fatal("ReadToken() expected error for oversized token, got nil")
	}
	if !strings.Contains(err.Error(), "maximum length") {
		t.Fatalf("error = %q, want mention of maximum length", err.Error())
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
	provider := NewIMDSProvider(cfg, srv.URL)

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
	provider := NewIMDSProvider(cfg, srv.URL)

	resolver := NewTokenResolver(cfg, provider)
	result, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if result.Value != "direct-value" {
		t.Fatalf("Resolve().Value = %q, want %q (direct value should take priority)", result.Value, "direct-value")
	}
}

func TestTokenResolver_IMDSProvider_FallbackOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cfg := &Config{
		UseMetadata:       true,
		MetadataTokenPath: "/plexd/bootstrap-token",
		MetadataTimeout:   2 * time.Second,
	}
	provider := NewIMDSProvider(cfg, srv.URL)

	resolver := NewTokenResolver(cfg, provider)
	_, err := resolver.Resolve(context.Background())
	if err == nil {
		t.Fatal("Resolve() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no bootstrap token found") {
		t.Fatalf("error = %q, want mention of 'no bootstrap token found'", err.Error())
	}
}
