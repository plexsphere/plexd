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
		{"cpu-load", true},
		{"status.mesh", true},
		{"", false},
		{".", false},
		{"..", false},
		{"../etc", false},
		{"foo/bar", false},
		{"foo\\bar", false},
		{"/absolute", false},
		{"Bad_Key", false},
		{"9lead", false},
		{".dot", false},
		{"a" + strings.Repeat("b", 128), false},
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

func TestHandler_PutReport_KeyGrammar(t *testing.T) {
	srv, _ := newTestHandler(t, &mockSecretFetcher{})
	body := `{"content_type":"application/json","payload":{"x":1}}`

	put := func(t *testing.T, key string) int {
		t.Helper()
		req, err := http.NewRequest("PUT", srv.URL+"/v1/state/report/"+key, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	for _, key := range []string{"cpu-load", "status.mesh"} {
		if got := put(t, key); got != 200 {
			t.Errorf("PUT key=%q: status = %d, want 200", key, got)
		}
	}

	// A 129-character key exceeds the grammar's 128-character ceiling.
	longKey := "a" + strings.Repeat("b", 128)
	for _, key := range []string{"Bad_Key", "9lead", ".dot", longKey} {
		if got := put(t, key); got != 400 {
			t.Errorf("PUT key=%q: status = %d, want 400", key, got)
		}
	}
}

func TestHandler_PutReport_OversizedValue(t *testing.T) {
	srv, _ := newTestHandler(t, &mockSecretFetcher{})

	// A valid-JSON payload whose serialized form exceeds the 4096-byte value cap
	// but stays well under the 1 MiB transport limit, so the semantic cap (not
	// MaxBytesReader) is what rejects it.
	oversized := `"` + strings.Repeat("x", maxReportValueBytes) + `"` // 4098 bytes
	body := `{"content_type":"application/json","payload":` + oversized + `}`
	req, err := http.NewRequest("PUT", srv.URL+"/v1/state/report/cpu-load", strings.NewReader(body))
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

// --- Action/Hook endpoint tests ---

type mockActionProvider struct {
	actions []api.ActionInfo
	hooks   []api.HookInfo
}

func (m *mockActionProvider) Capabilities() ([]api.ActionInfo, []api.HookInfo) {
	return m.actions, m.hooks
}

type mockActionRunner struct {
	mockActionProvider
	stdout   string
	stderr   string
	exitCode int
	err      error
}

func (m *mockActionRunner) RunLocal(_ context.Context, _ string, _ map[string]string) (string, string, int, error) {
	return m.stdout, m.stderr, m.exitCode, m.err
}

type mockHookReloader struct {
	hooks []api.HookInfo
}

func (m *mockHookReloader) Hooks() []api.HookInfo {
	return m.hooks
}

func newTestHandlerWithActions(t *testing.T, provider ActionProvider, reloader HookReloader) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	cache := NewStateCache(dir, discardLogger())
	if err := cache.Load(); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	nsk := testKey(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewHandler(cache, &mockSecretFetcher{}, "node-1", nsk, logger)
	h.SetActionProvider(provider)
	h.SetHookReloader(reloader)
	srv := httptest.NewServer(h.Mux())
	t.Cleanup(srv.Close)
	return srv
}

func TestHandler_GetActions(t *testing.T) {
	provider := &mockActionProvider{
		actions: []api.ActionInfo{
			{Name: "gather_info", Description: "Gather system info"},
			{Name: "health_check", Description: "Check health"},
		},
		hooks: []api.HookInfo{
			{Name: "deploy.sh", Source: "local", Checksum: "abc123", Description: "Deploy"},
		},
	}
	srv := newTestHandlerWithActions(t, provider, nil)

	resp := mustGet(t, srv.URL+"/v1/actions")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result struct {
		BuiltinActions []api.ActionInfo `json:"builtin_actions"`
		Hooks          []api.HookInfo   `json:"hooks"`
	}
	decodeJSON(t, resp, &result)

	if len(result.BuiltinActions) != 2 {
		t.Errorf("builtin_actions len = %d, want 2", len(result.BuiltinActions))
	}
	if len(result.Hooks) != 1 {
		t.Errorf("hooks len = %d, want 1", len(result.Hooks))
	}
	if result.Hooks[0].Name != "deploy.sh" {
		t.Errorf("hook name = %q, want %q", result.Hooks[0].Name, "deploy.sh")
	}
}

func TestHandler_GetActions_NoProvider(t *testing.T) {
	srv := newTestHandlerWithActions(t, nil, nil)

	resp := mustGet(t, srv.URL+"/v1/actions")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result struct {
		BuiltinActions []api.ActionInfo `json:"builtin_actions"`
		Hooks          []api.HookInfo   `json:"hooks"`
	}
	decodeJSON(t, resp, &result)

	if len(result.BuiltinActions) != 0 {
		t.Errorf("builtin_actions len = %d, want 0", len(result.BuiltinActions))
	}
	if len(result.Hooks) != 0 {
		t.Errorf("hooks len = %d, want 0", len(result.Hooks))
	}
}

func TestHandler_RunAction_Success(t *testing.T) {
	runner := &mockActionRunner{
		mockActionProvider: mockActionProvider{
			actions: []api.ActionInfo{{Name: "gather_info"}},
		},
		stdout:   `{"hostname":"node-1"}`,
		exitCode: 0,
	}
	srv := newTestHandlerWithActions(t, runner, nil)

	body := `{"action":"gather_info","parameters":{"key":"value"}}`
	req, err := http.NewRequest("POST", srv.URL+"/v1/actions/run", strings.NewReader(body))
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

	var result struct {
		Status   string `json:"status"`
		ExitCode int    `json:"exit_code"`
		Stdout   string `json:"stdout"`
	}
	decodeJSON(t, resp, &result)

	if result.Status != "success" {
		t.Errorf("status = %q, want %q", result.Status, "success")
	}
	if result.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", result.ExitCode)
	}
	if result.Stdout != `{"hostname":"node-1"}` {
		t.Errorf("stdout = %q, want JSON output", result.Stdout)
	}
}

func TestHandler_RunAction_Failed(t *testing.T) {
	runner := &mockActionRunner{
		mockActionProvider: mockActionProvider{
			actions: []api.ActionInfo{{Name: "test_action"}},
		},
		stdout:   "",
		stderr:   "something went wrong",
		exitCode: 1,
	}
	srv := newTestHandlerWithActions(t, runner, nil)

	body := `{"action":"test_action"}`
	req, err := http.NewRequest("POST", srv.URL+"/v1/actions/run", strings.NewReader(body))
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

	var result struct {
		Status   string `json:"status"`
		ExitCode int    `json:"exit_code"`
		Stderr   string `json:"stderr"`
	}
	decodeJSON(t, resp, &result)

	if result.Status != "failed" {
		t.Errorf("status = %q, want %q", result.Status, "failed")
	}
	if result.ExitCode != 1 {
		t.Errorf("exit_code = %d, want 1", result.ExitCode)
	}
}

func TestHandler_RunAction_MissingAction(t *testing.T) {
	runner := &mockActionRunner{
		mockActionProvider: mockActionProvider{},
	}
	srv := newTestHandlerWithActions(t, runner, nil)

	body := `{"parameters":{"key":"value"}}`
	req, err := http.NewRequest("POST", srv.URL+"/v1/actions/run", strings.NewReader(body))
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
}

func TestHandler_RunAction_InvalidJSON(t *testing.T) {
	runner := &mockActionRunner{
		mockActionProvider: mockActionProvider{},
	}
	srv := newTestHandlerWithActions(t, runner, nil)

	req, err := http.NewRequest("POST", srv.URL+"/v1/actions/run", strings.NewReader("not json"))
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
}

func TestHandler_RunAction_NoProvider(t *testing.T) {
	srv := newTestHandlerWithActions(t, nil, nil)

	body := `{"action":"gather_info"}`
	req, err := http.NewRequest("POST", srv.URL+"/v1/actions/run", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 503 {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandler_GetHooks(t *testing.T) {
	provider := &mockActionProvider{
		hooks: []api.HookInfo{
			{Name: "alpha.sh", Source: "local", Checksum: "aaa", Description: "Alpha hook"},
			{Name: "beta.sh", Source: "local", Checksum: "bbb", Description: "Beta hook"},
		},
	}
	srv := newTestHandlerWithActions(t, provider, nil)

	resp := mustGet(t, srv.URL+"/v1/hooks")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var hooks []api.HookInfo
	decodeJSON(t, resp, &hooks)

	if len(hooks) != 2 {
		t.Fatalf("hooks len = %d, want 2", len(hooks))
	}
	if hooks[0].Name != "alpha.sh" {
		t.Errorf("hooks[0].Name = %q, want %q", hooks[0].Name, "alpha.sh")
	}
	if hooks[1].Name != "beta.sh" {
		t.Errorf("hooks[1].Name = %q, want %q", hooks[1].Name, "beta.sh")
	}
}

func TestHandler_GetHooks_NoProvider(t *testing.T) {
	srv := newTestHandlerWithActions(t, nil, nil)

	resp := mustGet(t, srv.URL+"/v1/hooks")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var hooks []api.HookInfo
	decodeJSON(t, resp, &hooks)

	if len(hooks) != 0 {
		t.Errorf("hooks len = %d, want 0", len(hooks))
	}
}

func TestHandler_ReloadHooks(t *testing.T) {
	reloader := &mockHookReloader{
		hooks: []api.HookInfo{
			{Name: "refreshed.sh", Source: "local", Checksum: "xyz"},
		},
	}
	srv := newTestHandlerWithActions(t, nil, reloader)

	req, err := http.NewRequest("POST", srv.URL+"/v1/hooks/reload", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result struct {
		Status string         `json:"status"`
		Hooks  []api.HookInfo `json:"hooks"`
	}
	decodeJSON(t, resp, &result)

	if result.Status != "reloaded" {
		t.Errorf("status = %q, want %q", result.Status, "reloaded")
	}
	if len(result.Hooks) != 1 {
		t.Fatalf("hooks len = %d, want 1", len(result.Hooks))
	}
	if result.Hooks[0].Name != "refreshed.sh" {
		t.Errorf("hook name = %q, want %q", result.Hooks[0].Name, "refreshed.sh")
	}
}

func TestHandler_ReloadHooks_NoReloader(t *testing.T) {
	srv := newTestHandlerWithActions(t, nil, nil)

	req, err := http.NewRequest("POST", srv.URL+"/v1/hooks/reload", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 503 {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- Policy endpoint tests ---

type mockPolicyProvider struct {
	policy *api.PolicySnapshot
}

func (m *mockPolicyProvider) ActivePolicy() *api.PolicySnapshot { return m.policy }

func newTestHandlerWithPolicy(t *testing.T, provider PolicyProvider) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	cache := NewStateCache(dir, discardLogger())
	if err := cache.Load(); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}
	nsk := testKey(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewHandler(cache, &mockSecretFetcher{}, "node-1", nsk, logger)
	if provider != nil {
		h.SetPolicyProvider(provider)
	}
	srv := httptest.NewServer(h.Mux())
	t.Cleanup(srv.Close)
	return srv
}

func TestHandler_GetPolicies_MergedBlock(t *testing.T) {
	provider := &mockPolicyProvider{policy: &api.PolicySnapshot{
		RevisionID:  "rev-1",
		Fingerprint: "fp-1",
		Rules: []api.PolicyRule{
			{Action: "allow", Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
		},
	}}
	srv := newTestHandlerWithPolicy(t, provider)

	resp := mustGet(t, srv.URL+"/v1/policies")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got api.PolicySnapshot
	decodeJSON(t, resp, &got)
	if got.Fingerprint != "fp-1" {
		t.Errorf("fingerprint = %q, want %q", got.Fingerprint, "fp-1")
	}
	if len(got.Rules) != 1 || got.Rules[0].Ports == nil || got.Rules[0].Ports.From != 443 {
		t.Errorf("rules = %+v, want a single tcp/443 rule", got.Rules)
	}
}

func TestHandler_GetPolicies_EmptyWhenAbsent(t *testing.T) {
	// Both a nil provider and a nil policy serve an empty JSON object.
	for _, provider := range []PolicyProvider{nil, &mockPolicyProvider{policy: nil}} {
		srv := newTestHandlerWithPolicy(t, provider)
		resp := mustGet(t, srv.URL+"/v1/policies")
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.TrimSpace(string(body)) != "{}" {
			t.Errorf("absent policy body = %q, want {}", strings.TrimSpace(string(body)))
		}
	}
}
