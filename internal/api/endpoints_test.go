package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newEndpointTestClient creates a ControlPlane client backed by the given handler.
func newEndpointTestClient(t *testing.T, handler http.HandlerFunc) (*ControlPlane, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cfg := Config{BaseURL: srv.URL}
	client, err := NewControlPlane(cfg, "1.0.0-test", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	client.SetAuthToken("test-token")
	return client, srv
}

func TestRegister_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/register" {
			t.Errorf("path = %s, want /v1/register", r.URL.Path)
		}

		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Token != "boot-token" {
			t.Errorf("token = %q, want %q", req.Token, "boot-token")
		}
		if req.Hostname != "node-1" {
			t.Errorf("hostname = %q, want %q", req.Hostname, "node-1")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(RegisterResponse{
			NodeID:        "n1",
			MeshIP:        "10.0.0.1",
			NodeSecretKey: "secret-key",
			Peers: []Peer{
				{ID: "p1", MeshIP: "10.0.0.2"},
			},
		})
	})

	resp, err := client.Register(context.Background(), RegisterRequest{
		Token:    "boot-token",
		Hostname: "node-1",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.NodeID != "n1" {
		t.Errorf("NodeID = %q, want %q", resp.NodeID, "n1")
	}
	if resp.MeshIP != "10.0.0.1" {
		t.Errorf("MeshIP = %q, want %q", resp.MeshIP, "10.0.0.1")
	}
	if len(resp.Peers) != 1 {
		t.Fatalf("len(Peers) = %d, want 1", len(resp.Peers))
	}
	if resp.Peers[0].ID != "p1" {
		t.Errorf("Peers[0].ID = %q, want %q", resp.Peers[0].ID, "p1")
	}
}

func TestRegister_UsesBootstrapToken(t *testing.T) {
	var gotAuth string
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(RegisterResponse{NodeID: "n1"})
	})

	client.SetAuthToken("bootstrap-token-xyz")

	_, err := client.Register(context.Background(), RegisterRequest{
		Token:    "bootstrap-token-xyz",
		Hostname: "node-1",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if gotAuth != "Bearer bootstrap-token-xyz" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer bootstrap-token-xyz")
	}
}

func TestHeartbeat_ParsesReconcileFlag(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/heartbeat" {
			t.Errorf("path = %s, want /v1/nodes/n1/heartbeat", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(HeartbeatResponse{Reconcile: true})
	})

	resp, err := client.Heartbeat(context.Background(), "n1", HeartbeatRequest{
		NodeID:    "n1",
		Timestamp: time.Now(),
		Status:    "healthy",
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if !resp.Reconcile {
		t.Error("Reconcile = false, want true")
	}
}

func TestFetchState_ReturnsFullState(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/state" {
			t.Errorf("path = %s, want /v1/nodes/n1/state", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(StateResponse{
			Peers: []Peer{
				{ID: "p1", MeshIP: "10.0.0.2"},
				{ID: "p2", MeshIP: "10.0.0.3"},
			},
			Policies: []Policy{
				{ID: "pol1", Rules: []PolicyRule{{Src: "10.0.0.1", Dst: "10.0.0.2", Port: 443, Protocol: "tcp", Action: "allow"}}},
			},
			SecretRefs: []SecretRef{
				{Key: "tls-cert", Version: 1},
			},
		})
	})

	resp, err := client.FetchState(context.Background(), "n1")
	if err != nil {
		t.Fatalf("FetchState: %v", err)
	}
	if len(resp.Peers) != 2 {
		t.Fatalf("len(Peers) = %d, want 2", len(resp.Peers))
	}
	if resp.Peers[0].MeshIP != "10.0.0.2" {
		t.Errorf("Peers[0].MeshIP = %q, want %q", resp.Peers[0].MeshIP, "10.0.0.2")
	}
	if len(resp.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(resp.Policies))
	}
	if resp.Policies[0].Rules[0].Port != 443 {
		t.Errorf("Policies[0].Rules[0].Port = %d, want 443", resp.Policies[0].Rules[0].Port)
	}
	if len(resp.SecretRefs) != 1 {
		t.Fatalf("len(SecretRefs) = %d, want 1", len(resp.SecretRefs))
	}
}

func TestFetchArtifact_ReturnsBinaryStream(t *testing.T) {
	binaryContent := []byte("fake-binary-content-plexd-v1.0.0")
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v1/artifacts/plexd/1.0.0/linux/amd64" {
			t.Errorf("path = %s, want /v1/artifacts/plexd/1.0.0/linux/amd64", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(binaryContent)
	})

	rc, err := client.FetchArtifact(context.Background(), "1.0.0", "linux", "amd64")
	if err != nil {
		t.Fatalf("FetchArtifact: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != string(binaryContent) {
		t.Errorf("body = %q, want %q", string(got), string(binaryContent))
	}
}

func TestDeregister_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/deregister" {
			t.Errorf("path = %s, want /v1/nodes/n1/deregister", r.URL.Path)
		}
		if r.ContentLength > 0 {
			t.Errorf("expected no body, got ContentLength = %d", r.ContentLength)
		}
		w.WriteHeader(http.StatusOK)
	})

	err := client.Deregister(context.Background(), "n1")
	if err != nil {
		t.Fatalf("Deregister: %v", err)
	}
}

func TestRotateKeys_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/keys/rotate" {
			t.Errorf("path = %s, want /v1/keys/rotate", r.URL.Path)
		}

		var req KeyRotateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.NodeID != "n1" {
			t.Errorf("NodeID = %q, want %q", req.NodeID, "n1")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(KeyRotateResponse{
			UpdatedPeers: []Peer{{ID: "p1", MeshIP: "10.0.0.2"}},
		})
	})

	resp, err := client.RotateKeys(context.Background(), KeyRotateRequest{
		NodeID:       "n1",
		NewPublicKey: "new-pub-key",
	})
	if err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	if len(resp.UpdatedPeers) != 1 {
		t.Fatalf("len(UpdatedPeers) = %d, want 1", len(resp.UpdatedPeers))
	}
	if resp.UpdatedPeers[0].ID != "p1" {
		t.Errorf("UpdatedPeers[0].ID = %q, want %q", resp.UpdatedPeers[0].ID, "p1")
	}
}

func TestUpdateCapabilities_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/capabilities" {
			t.Errorf("path = %s, want /v1/nodes/n1/capabilities", r.URL.Path)
		}

		var caps CapabilitiesPayload
		if err := json.NewDecoder(r.Body).Decode(&caps); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(caps.BuiltinActions) != 1 {
			t.Errorf("len(BuiltinActions) = %d, want 1", len(caps.BuiltinActions))
		}

		w.WriteHeader(http.StatusOK)
	})

	err := client.UpdateCapabilities(context.Background(), "n1", CapabilitiesPayload{
		BuiltinActions: []ActionInfo{{Name: "restart", Description: "restart service"}},
	})
	if err != nil {
		t.Fatalf("UpdateCapabilities: %v", err)
	}
}

func TestReportEndpoint_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/endpoint" {
			t.Errorf("path = %s, want /v1/nodes/n1/endpoint", r.URL.Path)
		}

		var req EndpointReport
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.PublicEndpoint != "1.2.3.4:51820" {
			t.Errorf("PublicEndpoint = %q, want %q", req.PublicEndpoint, "1.2.3.4:51820")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(EndpointResponse{
			PeerEndpoints: []PeerEndpoint{{PeerID: "p1", Endpoint: "5.6.7.8:51820"}},
		})
	})

	resp, err := client.ReportEndpoint(context.Background(), "n1", EndpointReport{
		PublicEndpoint: "1.2.3.4:51820",
		NATType:        "full-cone",
	})
	if err != nil {
		t.Fatalf("ReportEndpoint: %v", err)
	}
	if len(resp.PeerEndpoints) != 1 {
		t.Fatalf("len(PeerEndpoints) = %d, want 1", len(resp.PeerEndpoints))
	}
	if resp.PeerEndpoints[0].Endpoint != "5.6.7.8:51820" {
		t.Errorf("PeerEndpoints[0].Endpoint = %q, want %q", resp.PeerEndpoints[0].Endpoint, "5.6.7.8:51820")
	}
}

func TestReportDrift_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/drift" {
			t.Errorf("path = %s, want /v1/nodes/n1/drift", r.URL.Path)
		}

		var req DriftReport
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Corrections) != 1 {
			t.Errorf("len(Corrections) = %d, want 1", len(req.Corrections))
		}

		w.WriteHeader(http.StatusOK)
	})

	err := client.ReportDrift(context.Background(), "n1", DriftReport{
		Timestamp: time.Now(),
		Corrections: []DriftCorrection{
			{Type: "peer-added", Detail: "added peer p2"},
		},
	})
	if err != nil {
		t.Fatalf("ReportDrift: %v", err)
	}
}

func TestFetchSecret_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/secrets/tls-cert" {
			t.Errorf("path = %s, want /v1/nodes/n1/secrets/tls-cert", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SecretResponse{
			Key:        "tls-cert",
			Ciphertext: "encrypted-data",
			Nonce:      "abc123",
			Version:    3,
		})
	})

	resp, err := client.FetchSecret(context.Background(), "n1", "tls-cert")
	if err != nil {
		t.Fatalf("FetchSecret: %v", err)
	}
	if resp.Key != "tls-cert" {
		t.Errorf("Key = %q, want %q", resp.Key, "tls-cert")
	}
	if resp.Version != 3 {
		t.Errorf("Version = %d, want 3", resp.Version)
	}
	if resp.Ciphertext != "encrypted-data" {
		t.Errorf("Ciphertext = %q, want %q", resp.Ciphertext, "encrypted-data")
	}
}

func TestSyncReports_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/report" {
			t.Errorf("path = %s, want /v1/nodes/n1/report", r.URL.Path)
		}

		var req ReportSyncRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Entries) != 1 {
			t.Errorf("len(Entries) = %d, want 1", len(req.Entries))
		}

		w.WriteHeader(http.StatusOK)
	})

	err := client.SyncReports(context.Background(), "n1", ReportSyncRequest{
		Entries: []ReportEntry{
			{Key: "status", ContentType: "application/json", Version: 1, UpdatedAt: time.Now()},
		},
	})
	if err != nil {
		t.Fatalf("SyncReports: %v", err)
	}
}

func TestAckExecution_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/executions/exec1/ack" {
			t.Errorf("path = %s, want /v1/nodes/n1/executions/exec1/ack", r.URL.Path)
		}

		var req ExecutionAck
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.ExecutionID != "exec1" {
			t.Errorf("ExecutionID = %q, want %q", req.ExecutionID, "exec1")
		}

		w.WriteHeader(http.StatusOK)
	})

	err := client.AckExecution(context.Background(), "n1", "exec1", ExecutionAck{
		ExecutionID: "exec1",
		Status:      "accepted",
	})
	if err != nil {
		t.Fatalf("AckExecution: %v", err)
	}
}

func TestReportResult_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/executions/exec1/result" {
			t.Errorf("path = %s, want /v1/nodes/n1/executions/exec1/result", r.URL.Path)
		}

		var req ExecutionResult
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.ExitCode != 0 {
			t.Errorf("ExitCode = %d, want 0", req.ExitCode)
		}

		w.WriteHeader(http.StatusOK)
	})

	err := client.ReportResult(context.Background(), "n1", "exec1", ExecutionResult{
		ExecutionID: "exec1",
		Status:      "success",
		ExitCode:    0,
		Stdout:      "hello",
		FinishedAt:  time.Now(),
	})
	if err != nil {
		t.Fatalf("ReportResult: %v", err)
	}
}

func TestReportMetrics_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/metrics" {
			t.Errorf("path = %s, want /v1/nodes/n1/metrics", r.URL.Path)
		}
		w.WriteHeader(http.StatusAccepted)
	})

	err := client.ReportMetrics(context.Background(), "n1", MetricBatch{
		{Timestamp: time.Now(), Group: "cpu", Data: json.RawMessage(`{"usage":0.42}`)},
	})
	if err != nil {
		t.Fatalf("ReportMetrics: %v", err)
	}
}

func TestReportLogs_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/logs" {
			t.Errorf("path = %s, want /v1/nodes/n1/logs", r.URL.Path)
		}
		w.WriteHeader(http.StatusAccepted)
	})

	err := client.ReportLogs(context.Background(), "n1", LogBatch{
		{Timestamp: time.Now(), Source: "systemd", Unit: "plexd.service", Message: "started", Severity: "info"},
	})
	if err != nil {
		t.Fatalf("ReportLogs: %v", err)
	}
}

func TestReportAudit_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/audit" {
			t.Errorf("path = %s, want /v1/nodes/n1/audit", r.URL.Path)
		}
		w.WriteHeader(http.StatusAccepted)
	})

	err := client.ReportAudit(context.Background(), "n1", AuditBatch{
		{Timestamp: time.Now(), Source: "plexd", EventType: "config_change", Action: "update", Result: "success"},
	})
	if err != nil {
		t.Fatalf("ReportAudit: %v", err)
	}
}

func TestConnectSSE_SetsHeaders(t *testing.T) {
	var gotAccept, gotLastEventID, gotCacheControl, gotAuth string
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/events" {
			t.Errorf("path = %s, want /v1/nodes/n1/events", r.URL.Path)
		}
		gotAccept = r.Header.Get("Accept")
		gotLastEventID = r.Header.Get("Last-Event-ID")
		gotCacheControl = r.Header.Get("Cache-Control")
		gotAuth = r.Header.Get("Authorization")

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: hello\n\n"))
	})

	resp, err := client.ConnectSSE(context.Background(), "n1", "evt-42")
	if err != nil {
		t.Fatalf("ConnectSSE: %v", err)
	}
	defer resp.Body.Close()

	if gotAccept != "text/event-stream" {
		t.Errorf("Accept = %q, want %q", gotAccept, "text/event-stream")
	}
	if gotLastEventID != "evt-42" {
		t.Errorf("Last-Event-ID = %q, want %q", gotLastEventID, "evt-42")
	}
	if gotCacheControl != "no-cache" {
		t.Errorf("Cache-Control = %q, want %q", gotCacheControl, "no-cache")
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer test-token")
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "data: hello\n\n" {
		t.Errorf("body = %q, want %q", string(body), "data: hello\n\n")
	}
}

func TestEndpoints_PathParametersEscaped(t *testing.T) {
	// Verify that special characters in path parameters are properly escaped.
	maliciousNodeID := "../../../etc/passwd"

	var gotPath string
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawPath
		if gotPath == "" {
			gotPath = r.URL.Path
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"peers":[],"policies":[],"data":[],"secret_refs":[]}`))
	})

	_, err := client.FetchState(context.Background(), maliciousNodeID)
	if err != nil {
		t.Fatalf("FetchState: %v", err)
	}

	// The path should contain the escaped node ID, not the raw traversal.
	if strings.Contains(gotPath, "../") {
		t.Errorf("path contains unescaped traversal: %s", gotPath)
	}
	// url.PathEscape encodes "/" as %2F.
	if !strings.Contains(gotPath, "%2F") && !strings.Contains(gotPath, "%2f") {
		t.Errorf("path does not contain escaped slashes: %s", gotPath)
	}
}

func TestFetchSecret_PathParametersEscaped(t *testing.T) {
	// Verify both nodeID and key parameters are escaped.
	var gotPath string
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawPath
		if gotPath == "" {
			gotPath = r.URL.Path
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"key":"k","ciphertext":"c","nonce":"n","version":1}`))
	})

	_, err := client.FetchSecret(context.Background(), "node/id", "secret/key")
	if err != nil {
		t.Fatalf("FetchSecret: %v", err)
	}

	// Slashes in parameters should be escaped.
	if strings.Contains(gotPath, "node/id") || strings.Contains(gotPath, "secret/key") {
		t.Errorf("path contains unescaped slashes in parameters: %s", gotPath)
	}
}
