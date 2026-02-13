package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type mockTokenReviewClient struct {
	result *TokenReviewResult
	err    error
}

func (m *mockTokenReviewClient) Review(_ context.Context, _ string) (*TokenReviewResult, error) {
	return m.result, m.err
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestTokenReviewAuth_EmptyToken(t *testing.T) {
	auth := NewTokenReviewAuthenticator(&mockTokenReviewClient{}, testLogger(), nil)
	_, err := auth.Authenticate(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if got := err.Error(); got != "kubernetes: authenticate: empty token" {
		t.Fatalf("unexpected error: %s", got)
	}
}

func TestTokenReviewAuth_ValidToken(t *testing.T) {
	client := &mockTokenReviewClient{
		result: &TokenReviewResult{
			Authenticated: true,
			Username:      "system:serviceaccount:default:test-sa",
			UID:           "uid-123",
			Groups:        []string{"system:serviceaccounts"},
			Audiences:     []string{"api"},
		},
	}
	auth := NewTokenReviewAuthenticator(client, testLogger(), nil)
	result, err := auth.Authenticate(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Authenticated {
		t.Fatal("expected authenticated=true")
	}
	if result.Username != "system:serviceaccount:default:test-sa" {
		t.Fatalf("unexpected username: %s", result.Username)
	}
	if result.UID != "uid-123" {
		t.Fatalf("unexpected uid: %s", result.UID)
	}
	if len(result.Groups) != 1 || result.Groups[0] != "system:serviceaccounts" {
		t.Fatalf("unexpected groups: %v", result.Groups)
	}
}

func TestTokenReviewAuth_InvalidToken(t *testing.T) {
	client := &mockTokenReviewClient{
		result: &TokenReviewResult{
			Authenticated: false,
		},
	}
	auth := NewTokenReviewAuthenticator(client, testLogger(), nil)
	_, err := auth.Authenticate(context.Background(), "invalid-token")
	if err == nil {
		t.Fatal("expected error for unauthenticated token")
	}
	if got := err.Error(); got != "kubernetes: authenticate: token not authenticated" {
		t.Fatalf("unexpected error: %s", got)
	}
}

func TestTokenReviewAuth_APIUnavailable(t *testing.T) {
	client := &mockTokenReviewClient{
		err: fmt.Errorf("connection refused"),
	}
	auth := NewTokenReviewAuthenticator(client, testLogger(), nil)
	_, err := auth.Authenticate(context.Background(), "some-token")
	if err == nil {
		t.Fatal("expected error when client fails")
	}
	if got := err.Error(); got != "kubernetes: authenticate: review failed: connection refused" {
		t.Fatalf("unexpected error: %s", got)
	}
}

func TestTokenReviewAuthenticator_AudienceMatch(t *testing.T) {
	client := &mockTokenReviewClient{
		result: &TokenReviewResult{
			Authenticated: true,
			Username:      "user",
			Audiences:     []string{"api", "plexd"},
		},
	}
	auth := NewTokenReviewAuthenticator(client, testLogger(), []string{"plexd"})
	result, err := auth.Authenticate(context.Background(), "good-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Authenticated {
		t.Fatal("expected authenticated=true")
	}
}

func TestTokenReviewAuthenticator_AudienceMismatch(t *testing.T) {
	client := &mockTokenReviewClient{
		result: &TokenReviewResult{
			Authenticated: true,
			Username:      "user",
			Audiences:     []string{"api"},
		},
	}
	auth := NewTokenReviewAuthenticator(client, testLogger(), []string{"plexd"})
	_, err := auth.Authenticate(context.Background(), "good-token")
	if err == nil {
		t.Fatal("expected error for audience mismatch")
	}
	if got := err.Error(); got != "kubernetes: authenticate: audience mismatch" {
		t.Fatalf("unexpected error: %s", got)
	}
}

func TestTokenReviewResult_JSON(t *testing.T) {
	result := TokenReviewResult{
		Authenticated: true,
		Username:      "user",
		UID:           "uid-1",
		Groups:        []string{"g1", "g2"},
		Audiences:     []string{"api"},
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var got TokenReviewResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if got.Authenticated != result.Authenticated {
		t.Fatalf("authenticated mismatch: %v != %v", got.Authenticated, result.Authenticated)
	}
	if got.Username != result.Username {
		t.Fatalf("username mismatch: %q != %q", got.Username, result.Username)
	}
	if got.UID != result.UID {
		t.Fatalf("uid mismatch: %q != %q", got.UID, result.UID)
	}
	if len(got.Groups) != 2 {
		t.Fatalf("groups length mismatch: %d != 2", len(got.Groups))
	}
	if len(got.Audiences) != 1 || got.Audiences[0] != "api" {
		t.Fatalf("audiences mismatch: %v", got.Audiences)
	}
}

func TestTokenReviewRequest_JSON(t *testing.T) {
	req := tokenReviewRequest{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec: tokenReviewSpec{
			Token:     "test-token",
			Audiences: []string{"api"},
		},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if raw["apiVersion"] != "authentication.k8s.io/v1" {
		t.Fatalf("unexpected apiVersion: %v", raw["apiVersion"])
	}
	if raw["kind"] != "TokenReview" {
		t.Fatalf("unexpected kind: %v", raw["kind"])
	}
	spec, ok := raw["spec"].(map[string]interface{})
	if !ok {
		t.Fatal("spec is not a map")
	}
	if spec["token"] != "test-token" {
		t.Fatalf("unexpected token: %v", spec["token"])
	}
}

func TestHTTPTokenReviewClient_Review(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("unexpected content-type: %s", ct)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer sa-token-value" {
			t.Errorf("unexpected authorization header: %s", auth)
		}

		var req tokenReviewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Spec.Token != "user-token" {
			t.Errorf("unexpected token in request: %s", req.Spec.Token)
		}

		resp := tokenReviewResponse{
			Status: tokenReviewStatus{
				Authenticated: true,
				User: &tokenReviewUser{
					Username: "system:serviceaccount:ns:sa",
					UID:      "uid-abc",
					Groups:   []string{"system:serviceaccounts"},
				},
				Audiences: []string{"api"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Write a temporary SA token file.
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("sa-token-value"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	client := &HTTPTokenReviewClient{
		apiServer:  server.URL,
		saToken:    tokenPath,
		httpClient: server.Client(),
	}

	result, err := client.Review(context.Background(), "user-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Authenticated {
		t.Fatal("expected authenticated=true")
	}
	if result.Username != "system:serviceaccount:ns:sa" {
		t.Fatalf("unexpected username: %s", result.Username)
	}
	if result.UID != "uid-abc" {
		t.Fatalf("unexpected uid: %s", result.UID)
	}
	if len(result.Groups) != 1 || result.Groups[0] != "system:serviceaccounts" {
		t.Fatalf("unexpected groups: %v", result.Groups)
	}
	if len(result.Audiences) != 1 || result.Audiences[0] != "api" {
		t.Fatalf("unexpected audiences: %v", result.Audiences)
	}
}

func TestHTTPTokenReviewClient_Review_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("sa-token"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	client := &HTTPTokenReviewClient{
		apiServer:  server.URL,
		saToken:    tokenPath,
		httpClient: server.Client(),
	}

	_, err := client.Review(context.Background(), "some-token")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestHTTPTokenReviewClient_Review_MissingTokenFile(t *testing.T) {
	client := &HTTPTokenReviewClient{
		apiServer:  "https://localhost:6443",
		saToken:    "/nonexistent/token",
		httpClient: http.DefaultClient,
	}

	_, err := client.Review(context.Background(), "some-token")
	if err == nil {
		t.Fatal("expected error for missing token file")
	}
}

func TestHTTPTokenReviewClient_Review_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not valid json at all"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("sa-token"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	client := &HTTPTokenReviewClient{
		apiServer:  server.URL,
		saToken:    tokenPath,
		httpClient: server.Client(),
	}

	_, err := client.Review(context.Background(), "some-token")
	if err == nil {
		t.Fatal("expected error for malformed JSON response")
	}
	if got := err.Error(); !strings.Contains(got, "unmarshal response") {
		t.Fatalf("unexpected error: %s", got)
	}
}

func TestHTTPTokenReviewClient_Review_APIErrorField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := tokenReviewResponse{
			Status: tokenReviewStatus{
				Authenticated: false,
				Error:         "token has expired",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("sa-token"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	client := &HTTPTokenReviewClient{
		apiServer:  server.URL,
		saToken:    tokenPath,
		httpClient: server.Client(),
	}

	_, err := client.Review(context.Background(), "some-token")
	if err == nil {
		t.Fatal("expected error for API error field")
	}
	if got := err.Error(); !strings.Contains(got, "token has expired") {
		t.Fatalf("unexpected error: %s", got)
	}
}

func TestTokenReviewMiddleware_Integration(t *testing.T) {
	// Test: valid token passes through.
	client := &mockTokenReviewClient{
		result: &TokenReviewResult{
			Authenticated: true,
			Username:      "system:serviceaccount:default:test-sa",
			UID:           "uid-123",
		},
	}
	auth := NewTokenReviewAuthenticator(client, testLogger(), nil)
	middleware := TokenReviewMiddleware(auth)

	var gotIdentity *TokenReviewResult
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if gotIdentity == nil {
		t.Fatal("expected identity in context")
	}
	if gotIdentity.Username != "system:serviceaccount:default:test-sa" {
		t.Fatalf("unexpected username: %s", gotIdentity.Username)
	}

	// Test: missing Authorization header returns 401.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing header, got %d", rr2.Code)
	}

	// Test: invalid token returns 401.
	failClient := &mockTokenReviewClient{
		result: &TokenReviewResult{Authenticated: false},
	}
	failAuth := NewTokenReviewAuthenticator(failClient, testLogger(), nil)
	failMiddleware := TokenReviewMiddleware(failAuth)
	failHandler := failMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("Authorization", "Bearer invalid-token")
	rr3 := httptest.NewRecorder()
	failHandler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d", rr3.Code)
	}
}

func TestIdentityFromContext_NoIdentity(t *testing.T) {
	ctx := context.Background()
	if identity := IdentityFromContext(ctx); identity != nil {
		t.Fatalf("expected nil identity, got %+v", identity)
	}
}
