package actions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockNodeInfo struct {
	nodeID    string
	meshIP    string
	peerCount int
}

func (m *mockNodeInfo) NodeID() string { return m.nodeID }
func (m *mockNodeInfo) MeshIP() string { return m.meshIP }
func (m *mockNodeInfo) PeerCount() int { return m.peerCount }

type mockHealthProvider struct {
	tunnelCount    int
	connectedPeers int
	uptime         time.Duration
	lastHeartbeat  time.Time
	lastReconcile  time.Time
}

func (m *mockHealthProvider) TunnelCount() int        { return m.tunnelCount }
func (m *mockHealthProvider) ConnectedPeers() int     { return m.connectedPeers }
func (m *mockHealthProvider) Uptime() time.Duration   { return m.uptime }
func (m *mockHealthProvider) LastHeartbeat() time.Time { return m.lastHeartbeat }
func (m *mockHealthProvider) LastReconcile() time.Time { return m.lastReconcile }

type mockMeshReconnector struct {
	err error
}

func (m *mockMeshReconnector) Reconnect(_ context.Context) error { return m.err }

type mockConfigProvider struct {
	config string
}

func (m *mockConfigProvider) DumpConfig() string { return m.config }

type mockLogProvider struct {
	lines []string
}

func (m *mockLogProvider) RecentLines(n int) []string {
	if n >= len(m.lines) {
		return m.lines
	}
	return m.lines[:n]
}

func TestBuiltinGatherInfo(t *testing.T) {
	info := &mockNodeInfo{
		nodeID:    "node-abc-123",
		meshIP:    "10.99.0.1",
		peerCount: 3,
	}

	fn := GatherInfo(info)
	stdout, stderr, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}

	expectedKeys := []string{"hostname", "os", "arch", "go_version", "mesh_ip", "peer_count", "node_id"}
	for _, key := range expectedKeys {
		if _, ok := result[key]; !ok {
			t.Errorf("missing key %q in JSON output", key)
		}
	}

	if result["os"] != runtime.GOOS {
		t.Errorf("expected os=%q, got %q", runtime.GOOS, result["os"])
	}
	if result["arch"] != runtime.GOARCH {
		t.Errorf("expected arch=%q, got %q", runtime.GOARCH, result["arch"])
	}
	if result["go_version"] != runtime.Version() {
		t.Errorf("expected go_version=%q, got %q", runtime.Version(), result["go_version"])
	}
	if result["mesh_ip"] != "10.99.0.1" {
		t.Errorf("expected mesh_ip=%q, got %q", "10.99.0.1", result["mesh_ip"])
	}
	if int(result["peer_count"].(float64)) != 3 {
		t.Errorf("expected peer_count=3, got %v", result["peer_count"])
	}
	if result["node_id"] != "node-abc-123" {
		t.Errorf("expected node_id=%q, got %q", "node-abc-123", result["node_id"])
	}
}

func TestBuiltinPingPeer_MissingPeerID(t *testing.T) {
	info := &mockNodeInfo{
		nodeID:    "node-1",
		meshIP:    "10.99.0.1",
		peerCount: 1,
	}

	fn := PingPeer(info)
	_, _, exitCode, err := fn(context.Background(), map[string]string{})

	if err == nil {
		t.Fatal("expected error for missing peer_id")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if err.Error() != "missing required parameter: peer_id" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBuiltinPingPeer_InvalidPeerID(t *testing.T) {
	info := &mockNodeInfo{
		nodeID:    "node-1",
		meshIP:    "10.99.0.1",
		peerCount: 1,
	}

	fn := PingPeer(info)
	_, stderr, exitCode, err := fn(context.Background(), map[string]string{"peer_id": "not-an-ip"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if stderr == "" || !strings.Contains(stderr, "invalid peer_id") {
		t.Errorf("expected stderr to contain 'invalid peer_id', got %q", stderr)
	}
}

func TestBuiltinPingPeer_ValidTarget(t *testing.T) {
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("ping not available")
	}

	info := &mockNodeInfo{
		nodeID:    "node-1",
		meshIP:    "10.99.0.1",
		peerCount: 1,
	}

	fn := PingPeer(info)
	stdout, _, exitCode, err := fn(context.Background(), map[string]string{"peer_id": "127.0.0.1"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0 for localhost ping, got %d", exitCode)
	}
	if stdout == "" {
		t.Error("expected non-empty stdout")
	}
}

func TestBuiltinDiagnosticsCollect(t *testing.T) {
	fn := DiagnosticsCollect()
	stdout, stderr, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}

	expectedKeys := []string{"hostname", "os", "arch", "cpu_count", "memory_total", "disk_total", "load_avg", "kernel_version"}
	for _, key := range expectedKeys {
		if _, ok := result[key]; !ok {
			t.Errorf("missing key %q in JSON output", key)
		}
	}

	if result["os"] != runtime.GOOS {
		t.Errorf("expected os=%q, got %q", runtime.GOOS, result["os"])
	}
	if result["arch"] != runtime.GOARCH {
		t.Errorf("expected arch=%q, got %q", runtime.GOARCH, result["arch"])
	}
	if int(result["cpu_count"].(float64)) != runtime.NumCPU() {
		t.Errorf("expected cpu_count=%d, got %v", runtime.NumCPU(), result["cpu_count"])
	}
}

func TestDiskTotalBytes(t *testing.T) {
	if got := diskTotalBytes(t.TempDir()); got == 0 {
		t.Error("diskTotalBytes(t.TempDir()) = 0, want a non-zero capacity")
	}
	if got := diskTotalBytes(diskRootPath()); got == 0 {
		t.Errorf("diskTotalBytes(%q) = 0, want a non-zero capacity", diskRootPath())
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if got := diskTotalBytes(missing); got != 0 {
		t.Errorf("diskTotalBytes(%q) = %d, want 0", missing, got)
	}
}

func TestKernelRelease(t *testing.T) {
	if kernelRelease() == "" {
		t.Error("kernelRelease() = \"\", want the running kernel release")
	}
}

func TestBuiltinTraceroutePeer_MissingPeerID(t *testing.T) {
	info := &mockNodeInfo{
		nodeID:    "node-1",
		meshIP:    "10.99.0.1",
		peerCount: 1,
	}

	fn := DiagnosticsTraceroutePeer(info)
	_, _, exitCode, err := fn(context.Background(), map[string]string{})

	if err == nil {
		t.Fatal("expected error for missing peer_id")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if err.Error() != "missing required parameter: peer_id" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBuiltinTraceroutePeer_InvalidPeerID(t *testing.T) {
	info := &mockNodeInfo{
		nodeID:    "node-1",
		meshIP:    "10.99.0.1",
		peerCount: 1,
	}

	fn := DiagnosticsTraceroutePeer(info)
	_, stderr, exitCode, err := fn(context.Background(), map[string]string{"peer_id": "not-an-ip"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if stderr == "" || !strings.Contains(stderr, "invalid peer_id") {
		t.Errorf("expected stderr to contain 'invalid peer_id', got %q", stderr)
	}
}

func TestBuiltinServiceUpgrade_MissingVersion(t *testing.T) {
	fn := ServiceUpgrade(nil, nil)
	_, _, exitCode, err := fn(context.Background(), nil)

	if err == nil {
		t.Fatal("expected error for missing version parameter")
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
}

func TestBuiltinServiceUpgrade_MissingChecksum(t *testing.T) {
	fn := ServiceUpgrade(nil, nil)
	params := map[string]string{"version": "1.5.0"}
	_, _, exitCode, err := fn(context.Background(), params)

	if err == nil {
		t.Fatal("expected error for missing checksum parameter")
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
}

// fakeReleaseFetcher is a configurable ReleaseFetcher for upgrade tests. It
// serves fixed binary/bundle bytes or errors and records whether FetchBundle
// was called.
type fakeReleaseFetcher struct {
	binary       []byte
	binaryReader io.Reader
	binaryErr    error
	bundle       []byte
	bundleErr    error
	bundleCalled bool
}

func (f *fakeReleaseFetcher) FetchBinary(_ context.Context, _ string) (io.ReadCloser, error) {
	if f.binaryErr != nil {
		return nil, f.binaryErr
	}
	if f.binaryReader != nil {
		return io.NopCloser(f.binaryReader), nil
	}
	return io.NopCloser(bytes.NewReader(f.binary)), nil
}

func (f *fakeReleaseFetcher) FetchBundle(_ context.Context, _ string) ([]byte, error) {
	f.bundleCalled = true
	if f.bundleErr != nil {
		return nil, f.bundleErr
	}
	return f.bundle, nil
}

// fakeBundleVerifier is a configurable BundleVerifier for upgrade tests. It
// returns a fixed error and records how many times Verify was called.
type fakeBundleVerifier struct {
	err    error
	calls  int
	gotHex string
}

func (v *fakeBundleVerifier) Verify(_ []byte, sha256Hex string) error {
	v.calls++
	v.gotHex = sha256Hex
	return v.err
}

// upgradeSeamFile creates a stand-in binary in a temp dir and points the
// resolveExecutable seam at it, restoring the seam on cleanup. It returns the
// file's path.
func upgradeSeamFile(t *testing.T, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "plexd")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatalf("write seam binary: %v", err)
	}
	orig := resolveExecutable
	resolveExecutable = func() (string, error) { return path, nil }
	t.Cleanup(func() { resolveExecutable = orig })
	return path
}

// assertNoUpgradeTempFiles fails if any .plexd-upgrade-* temp file survives in dir.
func assertNoUpgradeTempFiles(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".plexd-upgrade-*"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected no leftover temp files, found %v", matches)
	}
}

func TestBuiltinServiceUpgrade_HappyPath(t *testing.T) {
	if _, err := exec.LookPath("systemctl"); err == nil {
		t.Skip("systemctl present; upgraded_restart_pending status requires its absence")
	}

	newBinary := []byte("brand-new-plexd-binary-bytes")
	sum := sha256.Sum256(newBinary)
	checksum := hex.EncodeToString(sum[:])

	path := upgradeSeamFile(t, []byte("old binary"))
	fetcher := &fakeReleaseFetcher{binary: newBinary, bundle: []byte(`{"bundle":true}`)}
	verifier := &fakeBundleVerifier{}

	fn := ServiceUpgrade(fetcher, verifier)
	stdout, _, exitCode, err := fn(context.Background(), map[string]string{
		"version":  "1.5.0",
		"checksum": "sha256:" + checksum,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}
	if result["status"] != "upgraded_restart_pending" {
		t.Errorf("expected status='upgraded_restart_pending', got %q", result["status"])
	}

	// The binary at the seam path is replaced with the fetched content.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replaced binary: %v", err)
	}
	if !bytes.Equal(got, newBinary) {
		t.Errorf("binary content = %q, want %q", got, newBinary)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat replaced binary: %v", err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("binary mode = %o, want 0755", fi.Mode().Perm())
	}
	if verifier.calls != 1 {
		t.Errorf("verifier called %d times, want 1", verifier.calls)
	}
	if verifier.gotHex != checksum {
		t.Errorf("verifier digest = %q, want %q", verifier.gotHex, checksum)
	}
}

func TestBuiltinServiceUpgrade_SweepsOrphanedTempFiles(t *testing.T) {
	newBinary := []byte("brand-new-plexd-binary-bytes")
	sum := sha256.Sum256(newBinary)
	checksum := hex.EncodeToString(sum[:])

	path := upgradeSeamFile(t, []byte("old binary"))
	dir := filepath.Dir(path)

	// Simulate a temp file left behind by an earlier upgrade that was killed
	// (SIGKILL, OOM, power loss) before its deferred cleanup could run.
	orphan := filepath.Join(dir, ".plexd-upgrade-orphaned")
	if err := os.WriteFile(orphan, []byte("partial download"), 0o600); err != nil {
		t.Fatalf("write orphan temp file: %v", err)
	}

	fetcher := &fakeReleaseFetcher{binary: newBinary, bundle: []byte(`{"bundle":true}`)}
	verifier := &fakeBundleVerifier{}

	fn := ServiceUpgrade(fetcher, verifier)
	if _, _, _, err := fn(context.Background(), map[string]string{
		"version":  "1.5.0",
		"checksum": checksum,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("orphaned temp file survived the upgrade: stat err = %v", err)
	}
	assertNoUpgradeTempFiles(t, dir)
}

// blockingReader emits its data on the first Read, then closes parked and blocks
// on release before returning EOF. It lets a test hold one ServiceUpgrade in the
// middle of streaming its temp file while a second upgrade is attempted.
type blockingReader struct {
	data    []byte
	parked  chan struct{}
	release chan struct{}
	sent    bool
}

func (r *blockingReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, r.data), nil
	}
	close(r.parked)
	<-r.release
	return 0, io.EOF
}

// TestBuiltinServiceUpgrade_SerializesConcurrentUpgrades checks that a second
// upgrade cannot delete the temp file a first, still-streaming upgrade is
// downloading into. The executor admits concurrent actions with distinct
// execution IDs, so two service.upgrade requests can overlap; the orphan sweep
// must not treat a peer's in-flight download as an orphan. Before the upgrade
// mutex, the second upgrade's sweep unlinked the first's temp file and the first
// then failed to chmod/rename it.
func TestBuiltinServiceUpgrade_SerializesConcurrentUpgrades(t *testing.T) {
	newBinary := []byte("brand-new-plexd-binary-bytes")
	sum := sha256.Sum256(newBinary)
	checksum := hex.EncodeToString(sum[:])

	upgradeSeamFile(t, []byte("old binary"))
	params := map[string]string{"version": "1.5.0", "checksum": checksum}

	// The first upgrade writes its temp file, then parks mid-download.
	parked := make(chan struct{})
	release := make(chan struct{})
	first := ServiceUpgrade(&fakeReleaseFetcher{
		binaryReader: &blockingReader{data: newBinary, parked: parked, release: release},
		bundle:       []byte(`{"bundle":true}`),
	}, &fakeBundleVerifier{})
	second := ServiceUpgrade(&fakeReleaseFetcher{
		binary: newBinary,
		bundle: []byte(`{"bundle":true}`),
	}, &fakeBundleVerifier{})

	var wg sync.WaitGroup
	var errFirst, errSecond error

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, _, errFirst = first(context.Background(), params)
	}()

	// Wait until the first upgrade has written its temp file and is parked.
	<-parked

	bDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, _, errSecond = second(context.Background(), params)
		close(bDone)
	}()

	// Give the second upgrade time to run its orphan sweep. With the mutex it
	// blocks until the first upgrade finishes and cannot touch the first's temp
	// file; without it, the sweep unlinks that file before we release the first.
	select {
	case <-bDone:
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	wg.Wait()

	if errFirst != nil {
		t.Errorf("first upgrade failed under a concurrent upgrade: %v", errFirst)
	}
	if errSecond != nil {
		t.Errorf("second upgrade failed under a concurrent upgrade: %v", errSecond)
	}
}

func TestBuiltinServiceUpgrade_ChecksumMismatch(t *testing.T) {
	original := []byte("original binary content")
	path := upgradeSeamFile(t, original)
	dir := filepath.Dir(path)

	// A zero-byte download can never match a non-empty expected checksum.
	fetcher := &fakeReleaseFetcher{binary: []byte{}}
	verifier := &fakeBundleVerifier{}

	fn := ServiceUpgrade(fetcher, verifier)
	stdout, _, exitCode, err := fn(context.Background(), map[string]string{
		"version":  "1.5.0",
		"checksum": strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}
	if result["status"] != "checksum_mismatch" {
		t.Errorf("expected status='checksum_mismatch', got %q", result["status"])
	}
	if fetcher.bundleCalled {
		t.Error("FetchBundle must not be called on a checksum mismatch")
	}
	if verifier.calls != 0 {
		t.Errorf("verifier called %d times, want 0", verifier.calls)
	}
	assertNoUpgradeTempFiles(t, dir)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("binary was modified: got %q, want %q", got, original)
	}
}

func TestBuiltinServiceUpgrade_BundleVerificationFailed(t *testing.T) {
	original := []byte("original binary content")
	path := upgradeSeamFile(t, original)
	dir := filepath.Dir(path)

	newBinary := []byte("candidate binary")
	sum := sha256.Sum256(newBinary)
	checksum := hex.EncodeToString(sum[:])

	fetcher := &fakeReleaseFetcher{binary: newBinary, bundle: []byte(`{"bundle":true}`)}
	verifier := &fakeBundleVerifier{err: fmt.Errorf("upgrade: verify bundle: untrusted signer")}

	fn := ServiceUpgrade(fetcher, verifier)
	stdout, _, exitCode, err := fn(context.Background(), map[string]string{
		"version":  "1.5.0",
		"checksum": checksum,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}
	if result["status"] != "bundle_verification_failed" {
		t.Errorf("expected status='bundle_verification_failed', got %q", result["status"])
	}
	if result["message"] != "upgrade: verify bundle: untrusted signer" {
		t.Errorf("unexpected message: %q", result["message"])
	}
	if verifier.calls != 1 {
		t.Errorf("verifier called %d times, want 1", verifier.calls)
	}
	assertNoUpgradeTempFiles(t, dir)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("binary was modified: got %q, want %q", got, original)
	}
}

func TestBuiltinServiceUpgrade_BundleFetchError(t *testing.T) {
	original := []byte("original binary content")
	path := upgradeSeamFile(t, original)
	dir := filepath.Dir(path)

	newBinary := []byte("candidate binary")
	sum := sha256.Sum256(newBinary)
	checksum := hex.EncodeToString(sum[:])

	fetcher := &fakeReleaseFetcher{binary: newBinary, bundleErr: fmt.Errorf("unexpected status 404")}
	verifier := &fakeBundleVerifier{}

	fn := ServiceUpgrade(fetcher, verifier)
	_, _, exitCode, err := fn(context.Background(), map[string]string{
		"version":  "1.5.0",
		"checksum": checksum,
	})
	if err == nil {
		t.Fatal("expected error when the bundle fetch fails")
	}
	if !strings.Contains(err.Error(), "download bundle:") {
		t.Errorf("error = %q, want it to wrap 'download bundle:'", err.Error())
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if verifier.calls != 0 {
		t.Errorf("verifier called %d times, want 0", verifier.calls)
	}
	assertNoUpgradeTempFiles(t, dir)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("binary was modified: got %q, want %q", got, original)
	}
}

func TestBuiltinHealthCheck(t *testing.T) {
	now := time.Now().UTC()
	health := &mockHealthProvider{
		tunnelCount:    2,
		connectedPeers: 5,
		uptime:         10 * time.Minute,
		lastHeartbeat:  now,
		lastReconcile:  now.Add(-1 * time.Minute),
	}

	fn := HealthCheck(health)
	stdout, stderr, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}

	expectedKeys := []string{"tunnel_count", "connected_peers", "uptime", "last_heartbeat", "last_reconcile", "status"}
	for _, key := range expectedKeys {
		if _, ok := result[key]; !ok {
			t.Errorf("missing key %q in JSON output", key)
		}
	}

	if result["status"] != "healthy" {
		t.Errorf("expected status='healthy', got %q", result["status"])
	}
	if int(result["tunnel_count"].(float64)) != 2 {
		t.Errorf("expected tunnel_count=2, got %v", result["tunnel_count"])
	}
	if int(result["connected_peers"].(float64)) != 5 {
		t.Errorf("expected connected_peers=5, got %v", result["connected_peers"])
	}
}

func TestBuiltinHealthCheck_Degraded(t *testing.T) {
	now := time.Now().UTC()
	health := &mockHealthProvider{
		tunnelCount:    0,
		connectedPeers: 0,
		uptime:         5 * time.Second,
		lastHeartbeat:  now,
		lastReconcile:  now,
	}

	fn := HealthCheck(health)
	stdout, _, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}

	if result["status"] != "degraded" {
		t.Errorf("expected status='degraded', got %q", result["status"])
	}
}

func TestBuiltinMeshReconnect_Success(t *testing.T) {
	reconnector := &mockMeshReconnector{err: nil}

	fn := MeshReconnect(reconnector)
	stdout, stderr, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}

	if result["status"] != "reconnected" {
		t.Errorf("expected status='reconnected', got %q", result["status"])
	}
}

func TestBuiltinMeshReconnect_Failure(t *testing.T) {
	reconnector := &mockMeshReconnector{err: fmt.Errorf("connection refused")}

	fn := MeshReconnect(reconnector)
	stdout, _, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected system error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}

	if result["status"] != "failed" {
		t.Errorf("expected status='failed', got %q", result["status"])
	}
	if result["error"] != "connection refused" {
		t.Errorf("expected error='connection refused', got %q", result["error"])
	}
}

func TestBuiltinConfigDump(t *testing.T) {
	provider := &mockConfigProvider{config: "listen_addr: 0.0.0.0:8080\nlog_level: info\n"}

	fn := ConfigDump(provider)
	stdout, stderr, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}
	if stdout != "listen_addr: 0.0.0.0:8080\nlog_level: info\n" {
		t.Errorf("expected config output, got %q", stdout)
	}
}

func TestBuiltinLogsSnapshot(t *testing.T) {
	provider := &mockLogProvider{
		lines: []string{"line1", "line2", "line3"},
	}

	fn := LogsSnapshot(provider)
	stdout, stderr, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}
	if !strings.Contains(stdout, "line1") || !strings.Contains(stdout, "line2") || !strings.Contains(stdout, "line3") {
		t.Errorf("expected stdout to contain all lines, got %q", stdout)
	}
}

func TestBuiltinLogsSnapshot_CustomLineCount(t *testing.T) {
	provider := &mockLogProvider{
		lines: []string{"line1", "line2", "line3", "line4", "line5"},
	}

	fn := LogsSnapshot(provider)
	stdout, _, exitCode, err := fn(context.Background(), map[string]string{"lines": "2"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	outputLines := strings.Split(stdout, "\n")
	if len(outputLines) != 2 {
		t.Errorf("expected 2 lines, got %d: %q", len(outputLines), stdout)
	}
}

func TestBuiltinLogsSnapshot_BoundaryValues(t *testing.T) {
	provider := &mockLogProvider{
		lines: []string{"line1", "line2", "line3"},
	}

	tests := []struct {
		name      string
		lines     string
		wantCount int
	}{
		{"zero uses default 100", "0", 3},         // parsed > 0 is false, uses default 100
		{"negative uses default 100", "-1", 3},     // parsed > 0 is false, uses default 100
		{"max_int capped", "999999999", 3},         // capped to MaxSnapshotLines, but provider only has 3
		{"over_max capped", "20000", 3},            // capped to MaxSnapshotLines
		{"invalid string uses default", "abc", 3},  // parse error, uses default 100
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := LogsSnapshot(provider)
			stdout, _, exitCode, err := fn(context.Background(), map[string]string{"lines": tt.lines})

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if exitCode != 0 {
				t.Fatalf("expected exit code 0, got %d", exitCode)
			}

			if stdout == "" {
				if tt.wantCount != 0 {
					t.Errorf("expected non-empty stdout")
				}
				return
			}
			outputLines := strings.Split(stdout, "\n")
			if len(outputLines) != tt.wantCount {
				t.Errorf("expected %d lines, got %d: %q", tt.wantCount, len(outputLines), stdout)
			}
		})
	}
}

func TestBuiltinLogsSnapshot_MaxCap(t *testing.T) {
	// Verify the cap is applied at MaxSnapshotLines.
	requested := 0
	fn := LogsSnapshot(&capturingLogProvider{requestedN: &requested})
	_, _, _, err := fn(context.Background(), map[string]string{"lines": "50000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if requested != MaxSnapshotLines {
		t.Errorf("expected lines capped to %d, got %d", MaxSnapshotLines, requested)
	}
}

// capturingLogProvider records what n was passed to RecentLines.
type capturingLogProvider struct {
	requestedN *int
}

func (c *capturingLogProvider) RecentLines(n int) []string {
	*c.requestedN = n
	return nil
}

