package api

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
		if req.ProjectID != "proj-1" {
			t.Errorf("project_id = %q, want %q", req.ProjectID, "proj-1")
		}
		if req.ResourceHandle != "edge-router-01" {
			t.Errorf("resource_handle = %q, want %q", req.ResourceHandle, "edge-router-01")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(RegisterResponse{
			NodeID:           "n1",
			MeshIP:           "10.0.0.1",
			SigningPublicKey: "signing-pub",
			SigningKeyID:     "did:web:plexsphere.com#key-1",
			NSK:              "secret-key",
			DomainMeshCIDR:   "100.64.0.0/10",
			PeerSnapshot: []RegisterPeer{
				{NodeID: "p1", MeshIP: "10.0.0.2", PublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", FallbackEndpoint: "203.0.113.1:51820"},
			},
		})
	})

	resp, err := client.Register(context.Background(), RegisterRequest{
		ProjectID:      "proj-1",
		ResourceHandle: "edge-router-01",
		BootstrapToken: "psb_test_e2eproject_node_aaaaaaaaaaaaaaaaaaaaaa",
		Nonce:          "f3f8c0b8-7a0a-8a0a-a0a0-a0a0a0a0a0a0",
		PublicKey:      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
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
	if resp.SigningPublicKey != "signing-pub" {
		t.Errorf("SigningPublicKey = %q, want %q", resp.SigningPublicKey, "signing-pub")
	}
	if resp.SigningKeyID != "did:web:plexsphere.com#key-1" {
		t.Errorf("SigningKeyID = %q, want %q", resp.SigningKeyID, "did:web:plexsphere.com#key-1")
	}
	if resp.NSK != "secret-key" {
		t.Errorf("NSK = %q, want %q", resp.NSK, "secret-key")
	}
	if resp.DomainMeshCIDR != "100.64.0.0/10" {
		t.Errorf("DomainMeshCIDR = %q, want %q", resp.DomainMeshCIDR, "100.64.0.0/10")
	}
	if len(resp.PeerSnapshot) != 1 {
		t.Fatalf("len(PeerSnapshot) = %d, want 1", len(resp.PeerSnapshot))
	}
	if resp.PeerSnapshot[0].NodeID != "p1" {
		t.Errorf("PeerSnapshot[0].NodeID = %q, want %q", resp.PeerSnapshot[0].NodeID, "p1")
	}
	if resp.PeerSnapshot[0].FallbackEndpoint != "203.0.113.1:51820" {
		t.Errorf("PeerSnapshot[0].FallbackEndpoint = %q, want %q", resp.PeerSnapshot[0].FallbackEndpoint, "203.0.113.1:51820")
	}
}

// POST /v1/register is security: [] — it must never carry the shared bearer
// token, and it must not blank that token on the client the heartbeat, SSE, and
// reconcile paths share. Otherwise those concurrent requests would go out
// unauthenticated during a re-registration and, for SSE, exit for good on the
// resulting 401.
func TestRegister_OmitsAuthHeaderAndPreservesToken(t *testing.T) {
	var registerAuth, followupAuth string
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/register" {
			registerAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(RegisterResponse{NodeID: "n1", MeshIP: "10.0.0.1"})
			return
		}
		followupAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	// newEndpointTestClient already set a bearer token on the client.

	if _, err := client.Register(context.Background(), RegisterRequest{ProjectID: "p"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if registerAuth != "" {
		t.Errorf("register Authorization = %q, want empty", registerAuth)
	}

	// The shared token is untouched, so later calls still authenticate.
	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if followupAuth != "Bearer test-token" {
		t.Errorf("follow-up Authorization = %q, want %q", followupAuth, "Bearer test-token")
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

		// The serialized body must carry exactly the four contract keys.
		var raw map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if len(raw) != 4 {
			t.Errorf("request keys = %d, want 4: %v", len(raw), raw)
		}
		for _, key := range []string{"client_now", "binary_checksum", "binary_version", "nat_summary"} {
			if _, ok := raw[key]; !ok {
				t.Errorf("request missing key %q", key)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(HeartbeatResponse{Reconcile: true})
	})

	resp, err := client.Heartbeat(context.Background(), "n1", HeartbeatRequest{
		ClientNow:      time.Now().UTC(),
		BinaryChecksum: "abc123",
		BinaryVersion:  "1.2.3",
		NATSummary:     map[string]any{},
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if !resp.Reconcile {
		t.Error("Reconcile = false, want true")
	}
}

func TestFetchState_ReturnsSnapshot(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/state" {
			t.Errorf("path = %s, want /v1/nodes/n1/state", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// A full envelope: populated peers and policy, null bridge/state/reports.
		_, _ = w.Write([]byte(`{` +
			`"peers":[{"node_id":"p1","mesh_ip":"10.0.0.2","public_key":"pk1"},` +
			`{"node_id":"p2","mesh_ip":"10.0.0.3","public_key":"pk2","fallback_endpoint":"203.0.113.1:51820"}],` +
			`"reachability":{"state":"healthy","changed_at":"2026-01-01T00:00:00Z"},` +
			`"policy":{"revision_id":"rev-1","fingerprint":"fp","rules":[` +
			`{"action":"allow","protocol":"tcp","source_cidr":"10.0.0.1/32","destination_cidr":"10.0.0.2/32","ports":{"from":443,"to":443}}]},` +
			`"bridge":null,"state":null,"reports":null}`))
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
	if resp.Peers[1].FallbackEndpoint != "203.0.113.1:51820" {
		t.Errorf("Peers[1].FallbackEndpoint = %q, want %q", resp.Peers[1].FallbackEndpoint, "203.0.113.1:51820")
	}
	if resp.Policy == nil {
		t.Fatal("Policy = nil, want populated")
	}
	if len(resp.Policy.Rules) != 1 {
		t.Fatalf("len(Policy.Rules) = %d, want 1", len(resp.Policy.Rules))
	}
	if resp.Policy.Rules[0].Ports == nil || resp.Policy.Rules[0].Ports.From != 443 {
		t.Errorf("Policy.Rules[0].Ports = %+v, want from 443", resp.Policy.Rules[0].Ports)
	}
	// Null blocks decode to nil pointers.
	if resp.Bridge != nil || resp.State != nil || resp.Reports != nil {
		t.Errorf("null blocks should decode to nil, got bridge=%v state=%v reports=%v", resp.Bridge, resp.State, resp.Reports)
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

		var raw map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if _, ok := raw["new_public_key"]; !ok {
			t.Error("request missing new_public_key")
		}
		if _, ok := raw["node_id"]; ok {
			t.Error("request must not carry node_id; the server identifies the node from the NSK")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(KeyRotateResponse{
			RotationID:     "rot-001",
			KID:            "did:web:plexsphere.com#psk-2026-04",
			WrapKeyVersion: 2,
		})
	})

	resp, err := client.RotateKeys(context.Background(), KeyRotateRequest{
		NewPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
	})
	if err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	if resp.RotationID != "rot-001" {
		t.Errorf("RotationID = %q, want %q", resp.RotationID, "rot-001")
	}
	if resp.KID != "did:web:plexsphere.com#psk-2026-04" {
		t.Errorf("KID = %q, want %q", resp.KID, "did:web:plexsphere.com#psk-2026-04")
	}
	if resp.WrapKeyVersion != 2 {
		t.Errorf("WrapKeyVersion = %d, want 2", resp.WrapKeyVersion)
	}
}

func TestRotateKeys_UnchangedProblemCode(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, `{"type":"about:blank","title":"Unprocessable Entity","status":422,"detail":"new_public_key matches the node's current public key","code":"keys_rotate_public_key_unchanged"}`)
	})

	_, err := client.RotateKeys(context.Background(), KeyRotateRequest{
		NewPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As failed to extract *APIError: %v", err)
	}
	if apiErr.StatusCode != 422 {
		t.Errorf("StatusCode = %d, want 422", apiErr.StatusCode)
	}
	if apiErr.Code != "keys_rotate_public_key_unchanged" {
		t.Errorf("Code = %q, want %q", apiErr.Code, "keys_rotate_public_key_unchanged")
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
	reportedAt := time.Now().UTC().Truncate(time.Second)
	acceptedAt := reportedAt.Add(time.Second)
	staleAfter := reportedAt.Add(5 * time.Minute)

	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/endpoint" {
			t.Errorf("path = %s, want /v1/nodes/n1/endpoint", r.URL.Path)
		}

		var req EndpointRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Endpoint != "1.2.3.4:51820" {
			t.Errorf("Endpoint = %q, want %q", req.Endpoint, "1.2.3.4:51820")
		}
		if req.NATType != "full_cone" {
			t.Errorf("NATType = %q, want %q", req.NATType, "full_cone")
		}
		if !req.ReportedAt.Equal(reportedAt) {
			t.Errorf("ReportedAt = %v, want %v", req.ReportedAt, reportedAt)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(EndpointResponse{
			AcceptedAt: acceptedAt,
			StaleAfter: staleAfter,
		})
	})

	resp, err := client.ReportEndpoint(context.Background(), "n1", EndpointRequest{
		Endpoint:   "1.2.3.4:51820",
		NATType:    "full_cone",
		ReportedAt: reportedAt,
	})
	if err != nil {
		t.Fatalf("ReportEndpoint: %v", err)
	}
	if !resp.AcceptedAt.Equal(acceptedAt) {
		t.Errorf("AcceptedAt = %v, want %v", resp.AcceptedAt, acceptedAt)
	}
	if !resp.StaleAfter.Equal(staleAfter) {
		t.Errorf("StaleAfter = %v, want %v", resp.StaleAfter, staleAfter)
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
		_, _ = w.Write([]byte(`{"peers":[],"reachability":null,"policy":null,"bridge":null,"state":null,"reports":null}`))
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

func TestReportIntegrityViolation_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/integrity/violations" {
			t.Errorf("path = %s, want /v1/nodes/n1/integrity/violations", r.URL.Path)
		}

		var req IntegrityViolationReport
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Type != "binary" {
			t.Errorf("Type = %q, want %q", req.Type, "binary")
		}
		if req.Path != "/usr/local/bin/plexd" {
			t.Errorf("Path = %q, want %q", req.Path, "/usr/local/bin/plexd")
		}
		if req.ExpectedChecksum != "abc123" {
			t.Errorf("ExpectedChecksum = %q, want %q", req.ExpectedChecksum, "abc123")
		}
		if req.ActualChecksum != "def456" {
			t.Errorf("ActualChecksum = %q, want %q", req.ActualChecksum, "def456")
		}

		w.WriteHeader(http.StatusNoContent)
	})

	err := client.ReportIntegrityViolation(context.Background(), "n1", IntegrityViolationReport{
		Type:             "binary",
		Path:             "/usr/local/bin/plexd",
		ExpectedChecksum: "abc123",
		ActualChecksum:   "def456",
		Detail:           "binary checksum mismatch",
		Timestamp:        time.Now(),
	})
	if err != nil {
		t.Fatalf("ReportIntegrityViolation: %v", err)
	}
}

func TestExecutionCallback_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n1/executions/exec1" {
			t.Errorf("path = %s, want /v1/nodes/n1/executions/exec1", r.URL.Path)
		}

		var req ExecutionCallbackRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Status != ExecutionStatusSucceeded {
			t.Errorf("Status = %q, want %q", req.Status, ExecutionStatusSucceeded)
		}
		if req.ExitCode == nil || *req.ExitCode != 0 {
			t.Errorf("ExitCode = %v, want pointer to 0", req.ExitCode)
		}
		if req.DeclaredOutputBytes != 32*1024 {
			t.Errorf("DeclaredOutputBytes = %d, want %d", req.DeclaredOutputBytes, 32*1024)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(ExecutionCallbackResponse{
			Status:          "awaiting_output",
			OutputUploadURL: "https://store.example.com/outputs/exec1?sig=abc",
		})
	})

	code := 0
	resp, err := client.ExecutionCallback(context.Background(), "n1", "exec1", ExecutionCallbackRequest{
		Status:              ExecutionStatusSucceeded,
		ExitCode:            &code,
		DeclaredOutputBytes: 32 * 1024,
	})
	if err != nil {
		t.Fatalf("ExecutionCallback: %v", err)
	}
	if resp.Status != "awaiting_output" {
		t.Errorf("Status = %q, want %q", resp.Status, "awaiting_output")
	}
	if resp.OutputUploadURL != "https://store.example.com/outputs/exec1?sig=abc" {
		t.Errorf("OutputUploadURL = %q, want the presigned URL", resp.OutputUploadURL)
	}
}

func TestExecutionCallback_ProblemJSON409(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"type":"about:blank","title":"Conflict","status":409,"detail":"execution is already in a terminal state","code":"invalid_state_transition"}`)
	})

	_, err := client.ExecutionCallback(context.Background(), "n1", "exec1", ExecutionCallbackRequest{
		Status: ExecutionStatusStarted,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As failed to extract *APIError: %v", err)
	}
	if apiErr.StatusCode != 409 {
		t.Errorf("StatusCode = %d, want 409", apiErr.StatusCode)
	}
	if apiErr.Code != "invalid_state_transition" {
		t.Errorf("Code = %q, want %q", apiErr.Code, "invalid_state_transition")
	}
}

func TestUploadExecutionOutput_NoBearerAndOctetStream(t *testing.T) {
	payload := []byte("over-ceiling output bytes")
	var gotMethod, gotContentType, gotAuth string
	var gotBody []byte
	reject := false
	client, srv := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		if reject {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	// newEndpointTestClient already set a bearer token; a presigned PUT must not
	// carry it.

	uploadURL := srv.URL + "/outputs/exec1?sig=abc"
	if err := client.UploadExecutionOutput(context.Background(), uploadURL, payload); err != nil {
		t.Fatalf("UploadExecutionOutput: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", gotMethod)
	}
	if gotContentType != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", gotContentType)
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want empty", gotAuth)
	}
	if string(gotBody) != string(payload) {
		t.Errorf("body = %q, want %q", gotBody, payload)
	}

	// A non-2xx upload response surfaces an error.
	reject = true
	if err := client.UploadExecutionOutput(context.Background(), uploadURL, payload); err == nil {
		t.Fatal("expected error on non-2xx upload response, got nil")
	}
}

func TestUploadExecutionOutput_RejectsSchemeDowngrade(t *testing.T) {
	// The upload URL comes from the control plane and the body is captured
	// action output, so an https control plane must never be able to redirect
	// the upload onto a plaintext leg.
	cfg := Config{BaseURL: "https://control.example.com"}
	client, err := NewControlPlane(cfg, "1.0.0-test", slog.Default())
	if err != nil {
		t.Fatal(err)
	}

	const uploadURL = "http://collector.example/x?X-Amz-Signature=deadbeef"
	err = client.UploadExecutionOutput(context.Background(), uploadURL, []byte("secret output"))
	if err == nil {
		t.Fatal("expected error for plaintext upload url, got nil")
	}
	if strings.Contains(err.Error(), "deadbeef") {
		t.Errorf("error leaks the presigned url: %v", err)
	}
}

func TestUploadExecutionOutput_DoesNotFollowRedirect(t *testing.T) {
	redirected := make(chan []byte, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		redirected <- body
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	client, srv := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusTemporaryRedirect)
	})

	err := client.UploadExecutionOutput(context.Background(), srv.URL+"/outputs/exec1", []byte("secret output"))
	if err == nil {
		t.Fatal("expected error on redirected upload, got nil")
	}
	select {
	case body := <-redirected:
		t.Errorf("body was re-sent to the redirect target: %q", body)
	default:
	}
}

func TestUploadExecutionOutput_TransportErrorRedactsURL(t *testing.T) {
	// The presigned URL is a bearer credential; a transport failure must not
	// write it into the node's log via the wrapped *url.Error.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := srv.URL
	srv.Close()

	cfg := Config{BaseURL: closedURL}
	client, err := NewControlPlane(cfg, "1.0.0-test", slog.Default())
	if err != nil {
		t.Fatal(err)
	}

	err = client.UploadExecutionOutput(context.Background(), closedURL+"/outputs/exec1?X-Amz-Signature=deadbeef", []byte("out"))
	if err == nil {
		t.Fatal("expected transport error, got nil")
	}
	if strings.Contains(err.Error(), "deadbeef") || strings.Contains(err.Error(), "/outputs/exec1") {
		t.Errorf("error leaks the presigned url: %v", err)
	}
}

func TestReportSessionActivity_Success(t *testing.T) {
	client, _ := newEndpointTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/nodes/n-001/sessions/sess-001" {
			t.Errorf("path = %s, want /v1/nodes/n-001/sessions/sess-001", r.URL.Path)
		}

		var req SessionActivityRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.TCP == nil {
			t.Fatal("TCP activity missing")
		}
		if req.TCP.Phase != TCPPhaseSessionEnded {
			t.Errorf("Phase = %q, want %q", req.TCP.Phase, TCPPhaseSessionEnded)
		}
		if req.TCP.BytesIn == nil || *req.TCP.BytesIn != 1024 {
			t.Errorf("BytesIn = %v, want pointer to 1024", req.TCP.BytesIn)
		}
		if req.TCP.TerminatedBy != TerminatedByPlexdClose {
			t.Errorf("TerminatedBy = %q, want %q", req.TCP.TerminatedBy, TerminatedByPlexdClose)
		}

		w.WriteHeader(http.StatusNoContent)
	})

	var in, out int64 = 1024, 2048
	err := client.ReportSessionActivity(context.Background(), "n-001", "sess-001", SessionActivityRequest{
		TCP: &TCPActivity{
			Phase:        TCPPhaseSessionEnded,
			TargetHost:   "10.42.0.5",
			TargetPort:   5432,
			BytesIn:      &in,
			BytesOut:     &out,
			TerminatedBy: TerminatedByPlexdClose,
		},
	})
	if err != nil {
		t.Fatalf("ReportSessionActivity: %v", err)
	}
}
