package nodeapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

type mockSecretFetcher struct {
	resp *api.SecretResponse
	err  error
}

func (m *mockSecretFetcher) FetchSecret(ctx context.Context, nodeID, key string) (*api.SecretResponse, error) {
	return m.resp, m.err
}

// newTestHandler creates a Handler with a populated cache and returns the
// httptest.Server wrapping its Mux.
func newTestHandler(t *testing.T, fetcher SecretFetcher) (*httptest.Server, *StateCache) {
	t.Helper()
	dir := t.TempDir()
	cache := NewStateCache(dir, discardLogger())
	if err := cache.Load(); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	nsk := testKey(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewHandler(cache, fetcher, "node-1", nsk, logger)
	srv := httptest.NewServer(h.Mux())
	t.Cleanup(srv.Close)
	return srv, cache
}

func mustGet(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func TestHandler_GetState(t *testing.T) {
	srv, cache := newTestHandler(t, &mockSecretFetcher{})

	now := time.Now().Truncate(time.Second)
	cache.UpdateMetadata(map[string]string{"env": "prod"})
	cache.UpdateData([]api.DataEntry{
		{Key: "cfg", ContentType: "application/json", Payload: json.RawMessage(`{}`), Version: 2, UpdatedAt: now},
	})
	cache.UpdateSecretIndex([]api.SecretRef{
		{Key: "db-pass", Version: 1},
	})
	_, _ = cache.PutReport("health", "application/json", json.RawMessage(`{"ok":true}`), nil)

	resp := mustGet(t, srv.URL+"/v1/state")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result struct {
		Metadata   map[string]string `json:"metadata"`
		DataKeys   []struct {
			Key         string `json:"key"`
			Version     int    `json:"version"`
			ContentType string `json:"content_type"`
		} `json:"data_keys"`
		SecretKeys []struct {
			Key     string `json:"key"`
			Version int    `json:"version"`
		} `json:"secret_keys"`
		ReportKeys []struct {
			Key     string `json:"key"`
			Version int    `json:"version"`
		} `json:"report_keys"`
	}
	decodeJSON(t, resp, &result)

	if result.Metadata["env"] != "prod" {
		t.Errorf("metadata env = %q, want %q", result.Metadata["env"], "prod")
	}
	if len(result.DataKeys) != 1 || result.DataKeys[0].Key != "cfg" {
		t.Errorf("data_keys = %+v, want [{cfg 2 application/json}]", result.DataKeys)
	}
	if len(result.SecretKeys) != 1 || result.SecretKeys[0].Key != "db-pass" {
		t.Errorf("secret_keys = %+v, want [{db-pass 1}]", result.SecretKeys)
	}
	if len(result.ReportKeys) != 1 || result.ReportKeys[0].Key != "health" {
		t.Errorf("report_keys = %+v, want [{health 1}]", result.ReportKeys)
	}
}

func TestHandler_GetState_Empty(t *testing.T) {
	srv, _ := newTestHandler(t, &mockSecretFetcher{})

	resp := mustGet(t, srv.URL+"/v1/state")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result struct {
		Metadata   map[string]string `json:"metadata"`
		DataKeys   []any             `json:"data_keys"`
		SecretKeys []any             `json:"secret_keys"`
		ReportKeys []any             `json:"report_keys"`
	}
	decodeJSON(t, resp, &result)

	if len(result.Metadata) != 0 {
		t.Errorf("metadata = %v, want empty", result.Metadata)
	}
	if len(result.DataKeys) != 0 {
		t.Errorf("data_keys = %v, want empty", result.DataKeys)
	}
}

func TestHandler_GetMetadataAll(t *testing.T) {
	srv, cache := newTestHandler(t, &mockSecretFetcher{})
	cache.UpdateMetadata(map[string]string{"role": "worker", "region": "us-east"})

	resp := mustGet(t, srv.URL+"/v1/state/metadata")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result map[string]string
	decodeJSON(t, resp, &result)
	if result["role"] != "worker" || result["region"] != "us-east" {
		t.Errorf("metadata = %v, want {role:worker, region:us-east}", result)
	}
}

func TestHandler_GetMetadataKey(t *testing.T) {
	srv, cache := newTestHandler(t, &mockSecretFetcher{})
	cache.UpdateMetadata(map[string]string{"role": "worker"})

	// Found case.
	resp := mustGet(t, srv.URL+"/v1/state/metadata/role")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var result struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	decodeJSON(t, resp, &result)
	if result.Key != "role" || result.Value != "worker" {
		t.Errorf("got %+v, want {role worker}", result)
	}

	// Not found case.
	resp2 := mustGet(t, srv.URL+"/v1/state/metadata/nonexistent")
	if resp2.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp2.StatusCode)
	}
	resp2.Body.Close()
}

func TestHandler_GetDataAll(t *testing.T) {
	srv, cache := newTestHandler(t, &mockSecretFetcher{})
	now := time.Now().Truncate(time.Second)
	cache.UpdateData([]api.DataEntry{
		{Key: "cfg-a", ContentType: "application/json", Payload: json.RawMessage(`{}`), Version: 1, UpdatedAt: now},
		{Key: "cfg-b", ContentType: "text/plain", Payload: json.RawMessage(`"hello"`), Version: 3, UpdatedAt: now},
	})

	resp := mustGet(t, srv.URL+"/v1/state/data")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result []struct {
		Key         string `json:"key"`
		Version     int    `json:"version"`
		ContentType string `json:"content_type"`
	}
	decodeJSON(t, resp, &result)
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}

	keys := map[string]bool{}
	for _, r := range result {
		keys[r.Key] = true
	}
	if !keys["cfg-a"] || !keys["cfg-b"] {
		t.Errorf("keys = %v, want {cfg-a, cfg-b}", keys)
	}
}

func TestHandler_GetDataKey(t *testing.T) {
	srv, cache := newTestHandler(t, &mockSecretFetcher{})
	now := time.Now().Truncate(time.Second)
	cache.UpdateData([]api.DataEntry{
		{Key: "cfg-a", ContentType: "application/json", Payload: json.RawMessage(`{"x":1}`), Version: 2, UpdatedAt: now},
	})

	// Found.
	resp := mustGet(t, srv.URL+"/v1/state/data/cfg-a")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var entry api.DataEntry
	decodeJSON(t, resp, &entry)
	if entry.Key != "cfg-a" || entry.Version != 2 {
		t.Errorf("entry = %+v, want {cfg-a 2}", entry)
	}

	// Not found.
	resp2 := mustGet(t, srv.URL+"/v1/state/data/nonexistent")
	if resp2.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp2.StatusCode)
	}
	resp2.Body.Close()
}

func TestHandler_GetSecretsList(t *testing.T) {
	srv, cache := newTestHandler(t, &mockSecretFetcher{})
	cache.UpdateSecretIndex([]api.SecretRef{
		{Key: "db-pass", Version: 1},
		{Key: "api-key", Version: 2},
	})

	resp := mustGet(t, srv.URL+"/v1/state/secrets")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result []api.SecretRef
	decodeJSON(t, resp, &result)
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
}

func TestHandler_GetSecretValue(t *testing.T) {
	nsk := testKey(t)
	ct, nonce := testEncrypt(t, nsk, "supersecret")

	fetcher := &mockSecretFetcher{
		resp: &api.SecretResponse{
			Key:        "db-pass",
			Ciphertext: ct,
			Nonce:      nonce,
			Version:    1,
		},
	}

	dir := t.TempDir()
	cache := NewStateCache(dir, discardLogger())
	if err := cache.Load(); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewHandler(cache, fetcher, "node-1", nsk, logger)
	srv := httptest.NewServer(h.Mux())
	t.Cleanup(srv.Close)

	resp := mustGet(t, srv.URL+"/v1/state/secrets/db-pass")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result struct {
		Key     string `json:"key"`
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	decodeJSON(t, resp, &result)
	if result.Key != "db-pass" {
		t.Errorf("key = %q, want %q", result.Key, "db-pass")
	}
	if result.Value != "supersecret" {
		t.Errorf("value = %q, want %q", result.Value, "supersecret")
	}
	if result.Version != 1 {
		t.Errorf("version = %d, want 1", result.Version)
	}
}

func TestHandler_GetSecretValue_ControlPlaneDown(t *testing.T) {
	fetcher := &mockSecretFetcher{
		err: errors.New("connection refused"),
	}
	srv, _ := newTestHandler(t, fetcher)

	resp := mustGet(t, srv.URL+"/v1/state/secrets/db-pass")
	if resp.StatusCode != 503 {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandler_GetSecretValue_NotFound(t *testing.T) {
	fetcher := &mockSecretFetcher{
		err: api.ErrNotFound,
	}
	srv, _ := newTestHandler(t, fetcher)

	resp := mustGet(t, srv.URL+"/v1/state/secrets/nonexistent")
	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandler_GetSecretValue_DecryptionFailure(t *testing.T) {
	// FetchSecret returns a valid response but with invalid ciphertext,
	// triggering a DecryptSecret failure and a 500 response.
	fetcher := &mockSecretFetcher{
		resp: &api.SecretResponse{
			Key:        "db-pass",
			Ciphertext: "dGhpcyBpcyBub3QgdmFsaWQgY2lwaGVydGV4dA==", // valid base64, invalid ciphertext
			Nonce:      "AAAAAAAAAAAAAAAAAAAAAAAA",                    // valid base64, 12 bytes (16 b64 chars + padding)
			Version:    1,
		},
	}
	srv, _ := newTestHandler(t, fetcher)

	resp := mustGet(t, srv.URL+"/v1/state/secrets/db-pass")
	if resp.StatusCode != 500 {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandler_GetReportAll(t *testing.T) {
	srv, cache := newTestHandler(t, &mockSecretFetcher{})
	_, _ = cache.PutReport("health", "application/json", json.RawMessage(`{"ok":true}`), nil)
	_, _ = cache.PutReport("metrics", "application/json", json.RawMessage(`{"cpu":0.5}`), nil)

	resp := mustGet(t, srv.URL+"/v1/state/report")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result []struct {
		Key     string `json:"key"`
		Version int    `json:"version"`
	}
	decodeJSON(t, resp, &result)
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
}

func TestHandler_GetReportKey(t *testing.T) {
	srv, cache := newTestHandler(t, &mockSecretFetcher{})
	_, _ = cache.PutReport("health", "application/json", json.RawMessage(`{"ok":true}`), nil)

	// Found.
	resp := mustGet(t, srv.URL+"/v1/state/report/health")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var entry ReportEntry
	decodeJSON(t, resp, &entry)
	if entry.Key != "health" || entry.Version != 1 {
		t.Errorf("entry = %+v, want {health 1}", entry)
	}

	// Not found.
	resp2 := mustGet(t, srv.URL+"/v1/state/report/nonexistent")
	if resp2.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp2.StatusCode)
	}
	resp2.Body.Close()
}

func TestHandler_PutReport(t *testing.T) {
	srv, _ := newTestHandler(t, &mockSecretFetcher{})

	body := `{"content_type":"application/json","payload":{"status":"ok"}}`
	req, err := http.NewRequest("PUT", srv.URL+"/v1/state/report/health", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result ReportEntry
	decodeJSON(t, resp, &result)
	if result.Key != "health" {
		t.Errorf("key = %q, want %q", result.Key, "health")
	}
	if result.Version != 1 {
		t.Errorf("version = %d, want 1", result.Version)
	}
	if result.ContentType != "application/json" {
		t.Errorf("content_type = %q, want %q", result.ContentType, "application/json")
	}
}

func TestHandler_PutReport_IfMatchConflict(t *testing.T) {
	srv, cache := newTestHandler(t, &mockSecretFetcher{})
	_, _ = cache.PutReport("health", "application/json", json.RawMessage(`{"ok":true}`), nil)

	body := `{"content_type":"application/json","payload":{"status":"degraded"}}`
	req, err := http.NewRequest("PUT", srv.URL+"/v1/state/report/health", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", "99") // wrong version

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 409 {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandler_PutReport_InvalidJSON(t *testing.T) {
	srv, _ := newTestHandler(t, &mockSecretFetcher{})

	// Completely invalid JSON body.
	req, err := http.NewRequest("PUT", srv.URL+"/v1/state/report/health", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// Missing content_type field.
	req2, err := http.NewRequest("PUT", srv.URL+"/v1/state/report/health", strings.NewReader(`{"payload":{"x":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != 400 {
		t.Errorf("missing content_type: status = %d, want 400", resp2.StatusCode)
	}
	resp2.Body.Close()

	// Missing payload field.
	req3, err := http.NewRequest("PUT", srv.URL+"/v1/state/report/health", strings.NewReader(`{"content_type":"text/plain"}`))
	if err != nil {
		t.Fatal(err)
	}
	req3.Header.Set("Content-Type", "application/json")

	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	if resp3.StatusCode != 400 {
		t.Errorf("missing payload: status = %d, want 400", resp3.StatusCode)
	}
	resp3.Body.Close()
}

func TestHandler_DeleteReport(t *testing.T) {
	srv, cache := newTestHandler(t, &mockSecretFetcher{})
	_, _ = cache.PutReport("health", "application/json", json.RawMessage(`{"ok":true}`), nil)

	req, err := http.NewRequest("DELETE", srv.URL+"/v1/state/report/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 204 {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandler_DeleteReport_NotFound(t *testing.T) {
	srv, _ := newTestHandler(t, &mockSecretFetcher{})

	req, err := http.NewRequest("DELETE", srv.URL+"/v1/state/report/nonexistent", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestValidReportKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"health", true},
		{"my-report", true},
		{"report_v2", true},
		{"", false},
		{".", false},
		{"..", false},
		{"../etc", false},
		{"foo/bar", false},
		{"foo\\bar", false},
		{"/absolute", false},
	}
	for _, tc := range tests {
		got := validReportKey(tc.key)
		if got != tc.want {
			t.Errorf("validReportKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

func TestHandler_PutReport_InvalidKey(t *testing.T) {
	// Test with backslash-containing key (reaches handler since no path separator for URL routing).
	srv, _ := newTestHandler(t, &mockSecretFetcher{})

	body := `{"content_type":"application/json","payload":{"x":1}}`
	req, err := http.NewRequest("PUT", srv.URL+"/v1/state/report/foo%5Cbar", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("PUT key=foo%%5Cbar: status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandler_DeleteReport_InvalidKey(t *testing.T) {
	srv, _ := newTestHandler(t, &mockSecretFetcher{})

	req, err := http.NewRequest("DELETE", srv.URL+"/v1/state/report/foo%5Cbar", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("DELETE key=foo%%5Cbar: status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandler_PutReport_OversizedBody(t *testing.T) {
	srv, _ := newTestHandler(t, &mockSecretFetcher{})

	// Create a payload larger than maxReportBodyBytes (1 MiB).
	bigPayload := strings.Repeat("x", 1<<20+1)
	body := `{"content_type":"application/json","payload":"` + bigPayload + `"}`
	req, err := http.NewRequest("PUT", srv.URL+"/v1/state/report/health", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// MaxBytesReader causes the decode to fail with a 400 (invalid JSON body)
	// because the reader is truncated.
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	srv, _ := newTestHandler(t, &mockSecretFetcher{})

	req, err := http.NewRequest("POST", srv.URL+"/v1/state", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 405 {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
	resp.Body.Close()
}
