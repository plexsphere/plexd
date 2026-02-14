package tunnel

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewK8sProxy(t *testing.T) {
	proxy, err := NewK8sProxy("http://localhost:6443", nil, slog.Default())
	if err != nil {
		t.Fatalf("NewK8sProxy() error: %v", err)
	}
	if proxy == nil {
		t.Fatal("NewK8sProxy() returned nil")
	}
}

func TestNewK8sProxy_InvalidURL(t *testing.T) {
	_, err := NewK8sProxy("", nil, slog.Default())
	if err == nil {
		t.Fatal("NewK8sProxy() expected error for empty URL")
	}
}

func TestNewK8sProxy_WithTLSConfig(t *testing.T) {
	tlsConf := &tls.Config{InsecureSkipVerify: true}
	proxy, err := NewK8sProxy("https://localhost:6443", tlsConf, slog.Default())
	if err != nil {
		t.Fatalf("NewK8sProxy() error: %v", err)
	}
	if proxy == nil {
		t.Fatal("NewK8sProxy() returned nil")
	}
}

func TestK8sProxy_ForwardsRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"PodList"}`))
	}))
	defer backend.Close()

	proxy, err := NewK8sProxy(backend.URL, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewK8sProxy() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/pods", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); body != `{"kind":"PodList"}` {
		t.Errorf("body = %q, want %q", body, `{"kind":"PodList"}`)
	}
}

func TestK8sProxy_PreservesPathAndQuery(t *testing.T) {
	var gotPath, gotQuery string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy, err := NewK8sProxy(backend.URL, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewK8sProxy() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/pods?namespace=default", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if gotPath != "/api/v1/pods" {
		t.Errorf("path = %q, want %q", gotPath, "/api/v1/pods")
	}
	if gotQuery != "namespace=default" {
		t.Errorf("query = %q, want %q", gotQuery, "namespace=default")
	}
}

func TestK8sProxy_SetsXForwardedFor(t *testing.T) {
	var gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy, err := NewK8sProxy(backend.URL, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewK8sProxy() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/pods", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if !strings.Contains(gotXFF, "10.0.0.1") {
		t.Errorf("X-Forwarded-For = %q, want it to contain %q", gotXFF, "10.0.0.1")
	}
}

func TestK8sProxy_SetsHostHeader(t *testing.T) {
	var gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy, err := NewK8sProxy(backend.URL, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewK8sProxy() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if gotHost != proxy.target.Host {
		t.Errorf("Host = %q, want %q", gotHost, proxy.target.Host)
	}
}

func TestK8sProxy_HandlesUnreachableTarget(t *testing.T) {
	proxy, err := NewK8sProxy("http://127.0.0.1:1", nil, slog.Default())
	if err != nil {
		t.Fatalf("NewK8sProxy() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/pods", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}
