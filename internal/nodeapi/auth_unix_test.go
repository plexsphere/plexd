//go:build linux

package nodeapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockGroupChecker struct {
	groups map[string]bool // "uid:groupName" -> bool
}

func (m *mockGroupChecker) IsInGroup(uid, gid uint32, groupName string) bool {
	key := fmt.Sprintf("%d:%s", uid, groupName)
	return m.groups[key]
}

type mockPeerCredGetter struct {
	creds *PeerCredentials
	err   error
}

func (m *mockPeerCredGetter) GetPeerCredentials(_ *http.Request) (*PeerCredentials, error) {
	return m.creds, m.err
}

func TestSecretAuthMiddleware_RootAlwaysAllowed(t *testing.T) {
	checker := &mockGroupChecker{groups: map[string]bool{}}
	getter := &mockPeerCredGetter{
		creds: &PeerCredentials{PID: 1, UID: 0, GID: 0},
	}
	logger := slog.Default()

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := SecretAuthMiddleware(checker, getter, logger)(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/secrets/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "ok")
	}
}

func TestSecretAuthMiddleware_PlexdSecretsGroupAllowed(t *testing.T) {
	checker := &mockGroupChecker{groups: map[string]bool{
		"1000:plexd-secrets": true,
	}}
	getter := &mockPeerCredGetter{
		creds: &PeerCredentials{PID: 42, UID: 1000, GID: 1000},
	}
	logger := slog.Default()

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := SecretAuthMiddleware(checker, getter, logger)(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/secrets/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "ok")
	}
}

func TestSecretAuthMiddleware_DeniedWithoutGroup(t *testing.T) {
	checker := &mockGroupChecker{groups: map[string]bool{}}
	getter := &mockPeerCredGetter{
		creds: &PeerCredentials{PID: 42, UID: 1000, GID: 1000},
	}
	logger := slog.Default()

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := SecretAuthMiddleware(checker, getter, logger)(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/secrets/test", nil)
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
	checker := &mockGroupChecker{groups: map[string]bool{}}
	getter := &mockPeerCredGetter{
		err: fmt.Errorf("nodeapi: auth: not a Unix socket connection"),
	}
	logger := slog.Default()

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := SecretAuthMiddleware(checker, getter, logger)(inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/secrets/test", nil)
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

func TestPeerCredentials_Struct(t *testing.T) {
	cred := PeerCredentials{
		PID: 123,
		UID: 1000,
		GID: 1000,
	}
	if cred.PID != 123 {
		t.Errorf("PID = %d, want %d", cred.PID, 123)
	}
	if cred.UID != 1000 {
		t.Errorf("UID = %d, want %d", cred.UID, 1000)
	}
	if cred.GID != 1000 {
		t.Errorf("GID = %d, want %d", cred.GID, 1000)
	}
}
