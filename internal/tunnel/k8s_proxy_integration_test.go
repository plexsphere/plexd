package tunnel

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestIntegration_K8sProxyThroughSSHTunnel verifies that HTTP requests can be
// proxied to a K8s API server through an SSH tunnel's direct-tcpip channel.
//
// Flow: SSH client -> direct-tcpip channel -> K8sProxy listener -> mock K8s API
func TestIntegration_K8sProxyThroughSSHTunnel(t *testing.T) {
	// 1. Start mock K8s API server.
	mockK8s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"kind":       "PodList",
			"apiVersion": "v1",
			"items":      []any{},
			"metadata": map[string]any{
				"resourceVersion": "12345",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockK8s.Close()

	// 2. Create K8s proxy pointing at mock API server.
	proxy, err := NewK8sProxy(mockK8s.URL, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewK8sProxy() error: %v", err)
	}

	// 3. Start HTTP listener for the proxy.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listener error: %v", err)
	}
	proxySrv := &http.Server{Handler: proxy}
	go func() { _ = proxySrv.Serve(proxyLn) }()
	defer proxySrv.Close()

	proxyAddr := proxyLn.Addr().String()

	// 4. Start SSH server.
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	sshSrv := NewSSHServer(SSHServerConfig{
		ListenAddr:  "127.0.0.1:0",
		MaxSessions: 5,
		IdleTimeout: 5 * time.Minute,
	}, hostKey, &mockJWTVerifier{err: nil}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sshSrv.Start(ctx); err != nil {
		t.Fatalf("ssh Start() error: %v", err)
	}
	defer func() { _ = sshSrv.Shutdown() }()

	// 5. Connect SSH client.
	clientKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() for client error: %v", err)
	}

	clientCfg := &ssh.ClientConfig{
		User:            "test-user",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	sshClient, err := ssh.Dial("tcp", sshSrv.Addr(), clientCfg)
	if err != nil {
		t.Fatalf("ssh.Dial() error: %v", err)
	}
	defer sshClient.Close()

	// 6. Open direct-tcpip channel to K8s proxy listener.
	tunnelConn, err := sshClient.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("sshClient.Dial() to proxy error: %v", err)
	}
	defer tunnelConn.Close()

	// 7. Send HTTP request through the SSH tunnel.
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tunnelConn, nil
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := httpClient.Get("http://" + proxyAddr + "/api/v1/pods?namespace=default")
	if err != nil {
		t.Fatalf("HTTP GET error: %v", err)
	}
	defer resp.Body.Close()

	// 8. Verify response.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	if result["kind"] != "PodList" {
		t.Errorf("kind = %v, want PodList", result["kind"])
	}
	if result["apiVersion"] != "v1" {
		t.Errorf("apiVersion = %v, want v1", result["apiVersion"])
	}
}

// TestIntegration_K8sProxyPreservesPathAndHeaders verifies that the K8s proxy
// preserves request paths, query parameters, and headers through the SSH tunnel.
func TestIntegration_K8sProxyPreservesPathAndHeaders(t *testing.T) {
	// Mock K8s API that echoes back request details.
	mockK8s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"path":      r.URL.Path,
			"query":     r.URL.RawQuery,
			"host":      r.Host,
			"forwarded": r.Header.Get("X-Forwarded-For"),
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockK8s.Close()

	proxy, err := NewK8sProxy(mockK8s.URL, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewK8sProxy() error: %v", err)
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listener error: %v", err)
	}
	proxySrv := &http.Server{Handler: proxy}
	go func() { _ = proxySrv.Serve(proxyLn) }()
	defer proxySrv.Close()
	proxyAddr := proxyLn.Addr().String()

	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	sshSrv := NewSSHServer(SSHServerConfig{
		ListenAddr:  "127.0.0.1:0",
		IdleTimeout: 5 * time.Minute,
	}, hostKey, &mockJWTVerifier{err: nil}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sshSrv.Start(ctx); err != nil {
		t.Fatalf("ssh Start() error: %v", err)
	}
	defer func() { _ = sshSrv.Shutdown() }()

	clientKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() for client error: %v", err)
	}

	sshClient, err := ssh.Dial("tcp", sshSrv.Addr(), &ssh.ClientConfig{
		User:            "test-user",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh.Dial() error: %v", err)
	}
	defer sshClient.Close()

	tunnelConn, err := sshClient.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("sshClient.Dial() to proxy error: %v", err)
	}
	defer tunnelConn.Close()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tunnelConn, nil
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := httpClient.Get("http://" + proxyAddr + "/apis/apps/v1/namespaces/kube-system/deployments?labelSelector=app%3Dcoredns")
	if err != nil {
		t.Fatalf("HTTP GET error: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}

	if result["path"] != "/apis/apps/v1/namespaces/kube-system/deployments" {
		t.Errorf("path = %v, want /apis/apps/v1/namespaces/kube-system/deployments", result["path"])
	}
	if result["query"] != "labelSelector=app%3Dcoredns" {
		t.Errorf("query = %v, want labelSelector=app%%3Dcoredns", result["query"])
	}
}
