package nodeapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBearerAuth_ValidToken(t *testing.T) {
	const token = "test-secret-token"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := BearerAuthMiddleware(token)(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "ok")
	}
}

func TestBearerAuth_MissingToken(t *testing.T) {
	const token = "test-secret-token"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := BearerAuthMiddleware(token)(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "unauthorized" {
		t.Errorf("error = %q, want %q", body["error"], "unauthorized")
	}
}

func TestBearerAuth_InvalidToken(t *testing.T) {
	const token = "test-secret-token"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := BearerAuthMiddleware(token)(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "unauthorized" {
		t.Errorf("error = %q, want %q", body["error"], "unauthorized")
	}
}

func TestBearerAuth_MalformedHeader(t *testing.T) {
	const token = "test-secret-token"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := BearerAuthMiddleware(token)(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "unauthorized" {
		t.Errorf("error = %q, want %q", body["error"], "unauthorized")
	}
}

func TestBearerAuth_EmptyBearer(t *testing.T) {
	const token = "test-secret-token"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := BearerAuthMiddleware(token)(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "unauthorized" {
		t.Errorf("error = %q, want %q", body["error"], "unauthorized")
	}
}

func TestBearerAuth_CaseInsensitive(t *testing.T) {
	const token = "test-secret-token"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := BearerAuthMiddleware(token)(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "ok")
	}
}

type fakeSecretPolicy struct {
	allow bool
}

func (p fakeSecretPolicy) AllowSecrets(*PeerCredentials) bool {
	return p.allow
}

type mockPeerCredGetter struct {
	creds *PeerCredentials
	err   error
}

func (m *mockPeerCredGetter) GetPeerCredentials(_ *http.Request) (*PeerCredentials, error) {
	return m.creds, m.err
}

// bufferLogger returns a logger that writes into buf at Debug level, so a test
// can assert on what the middleware logged.
func bufferLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestSecretAuthMiddleware_Allowed(t *testing.T) {
	getter := &mockPeerCredGetter{creds: &PeerCredentials{}}

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := SecretAuthMiddleware(fakeSecretPolicy{allow: true}, getter, discardLogger())(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/state/secrets/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "ok")
	}
}

func TestSecretAuthMiddleware_Denied(t *testing.T) {
	getter := &mockPeerCredGetter{creds: &PeerCredentials{}}

	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := SecretAuthMiddleware(fakeSecretPolicy{allow: false}, getter, discardLogger())(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/state/secrets/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "forbidden: insufficient privileges for secret access" {
		t.Errorf("error = %q, want %q", body["error"], "forbidden: insufficient privileges for secret access")
	}
}

func TestSecretAuthMiddleware_CredentialError(t *testing.T) {
	getter := &mockPeerCredGetter{err: errors.New("nodeapi: peer credentials not available")}

	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("inner handler should not be called")
	})

	var buf bytes.Buffer
	handler := SecretAuthMiddleware(fakeSecretPolicy{allow: true}, getter, bufferLogger(&buf))(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/state/secrets/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "forbidden: insufficient privileges for secret access" {
		t.Errorf("error = %q, want %q", body["error"], "forbidden: insufficient privileges for secret access")
	}

	logged := buf.String()
	for _, want := range []string{"level=ERROR", "failed to get peer credentials"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log %q does not contain %q", logged, want)
		}
	}
}

func TestSecretAuthMiddleware_DeniedLogsPath(t *testing.T) {
	getter := &mockPeerCredGetter{creds: &PeerCredentials{}}

	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("inner handler should not be called")
	})

	var buf bytes.Buffer
	handler := SecretAuthMiddleware(fakeSecretPolicy{allow: false}, getter, bufferLogger(&buf))(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/state/secrets/db-password", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	logged := buf.String()
	for _, want := range []string{"level=WARN", "secret access denied", "path=/v1/state/secrets/db-password"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log %q does not contain %q", logged, want)
		}
	}
}

func TestWrapSecretAuth_ProtectsSecretRoutes(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapSecretAuth(inner, fakeSecretPolicy{allow: true}, discardLogger())

	// Non-secret route should pass through.
	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("non-secret route: status = %d, want 200", rec.Code)
	}

	// Secret route without peer creds should be forbidden.
	req = httptest.NewRequest(http.MethodGet, "/v1/state/secrets/key", nil)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("secret route without creds: status = %d, want 403", rec.Code)
	}

	// Secret route with peer creds the policy admits should pass.
	ctx := context.WithValue(req.Context(), peerCredKey{}, &PeerCredentials{})
	req = httptest.NewRequest(http.MethodGet, "/v1/state/secrets/key", nil).WithContext(ctx)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("secret route with creds: status = %d, want 200", rec.Code)
	}
}

func TestWrapSecretAuth_SecretListAlsoProtected(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapSecretAuth(inner, fakeSecretPolicy{allow: true}, discardLogger())

	// /v1/state/secrets (list) should also be protected.
	req := httptest.NewRequest(http.MethodGet, "/v1/state/secrets", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("secret list without creds: status = %d, want 403", rec.Code)
	}
}

func TestWrapSecretAuth_MetadataNotProtected(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapSecretAuth(inner, fakeSecretPolicy{allow: true}, discardLogger())

	paths := []string{"/v1/state", "/v1/state/metadata", "/v1/state/data/key", "/v1/state/report/key"}
	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("path %s: status = %d, want 200", path, rec.Code)
		}
	}
}

func TestIsSecretPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/v1/state/secrets", true},
		{"/v1/state/secrets/key", true},
		{"/v1/state", false},
		{"/v1/state/metadata", false},
		{"/v1/state/data/key", false},
		{"/v1/state/report/key", false},
	}

	for _, tt := range tests {
		got := strings.HasPrefix(tt.path, "/v1/state/secrets")
		if got != tt.want {
			t.Errorf("isSecretPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
