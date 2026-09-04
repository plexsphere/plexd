package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/metrics"
)

// BuiltinFunc is the signature for built-in action implementations.
// It receives a context (with timeout deadline) and parameters, and returns
// stdout, stderr, an exit code, and an optional error.
type BuiltinFunc func(ctx context.Context, params map[string]string) (stdout string, stderr string, exitCode int, err error)

// NodeInfoProvider supplies mesh node information to built-in actions.
type NodeInfoProvider interface {
	NodeID() string
	MeshIP() string
	PeerCount() int
}

// HealthProvider supplies health status information to built-in actions.
type HealthProvider interface {
	TunnelCount() int
	ConnectedPeers() int
	Uptime() time.Duration
	LastHeartbeat() time.Time
	LastReconcile() time.Time
}

// MeshReconnector triggers mesh reconnection.
type MeshReconnector interface {
	Reconnect(ctx context.Context) error
}

// ConfigProvider supplies sanitized configuration for dumping.
type ConfigProvider interface {
	DumpConfig() string
}

// ReleaseFetcher downloads plexd release assets for a version.
type ReleaseFetcher interface {
	FetchBinary(ctx context.Context, version string) (io.ReadCloser, error)
	FetchBundle(ctx context.Context, version string) ([]byte, error)
}

// ServiceController drives the plexd service through the host's service
// manager. packaging.Service implements it.
type ServiceController interface {
	Available() bool
	Restart(ctx context.Context) error
}

// BundleVerifier verifies a Sigstore bundle against an artifact digest.
type BundleVerifier interface {
	Verify(bundleJSON []byte, sha256Hex string) error
}

// LogProvider supplies recent log lines.
type LogProvider interface {
	RecentLines(n int) []string
}

// gatherInfoResult holds the structured output of the GatherInfo action.
type gatherInfoResult struct {
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version"`
	MeshIP    string `json:"mesh_ip"`
	PeerCount int    `json:"peer_count"`
	NodeID    string `json:"node_id"`
}

// GatherInfo returns a BuiltinFunc that collects system information and returns it as JSON.
// The output includes: hostname, os, arch, go_version, mesh_ip, peer_count, node_id.
func GatherInfo(info NodeInfoProvider) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}

		result := gatherInfoResult{
			Hostname:  hostname,
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
			GoVersion: runtime.Version(),
			MeshIP:    info.MeshIP(),
			PeerCount: info.PeerCount(),
			NodeID:    info.NodeID(),
		}

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", "", 1, fmt.Errorf("marshal info: %w", err)
		}

		return string(data), "", 0, nil
	}
}

// PingPeer returns a BuiltinFunc that pings a mesh peer and reports latency.
// Requires a "peer_id" parameter (mesh IP). Optional "count" parameter (default 1).
func PingPeer(info NodeInfoProvider) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		target := params["peer_id"]
		if target == "" {
			return "", "", 1, fmt.Errorf("missing required parameter: peer_id")
		}

		if net.ParseIP(target) == nil {
			return "", fmt.Sprintf("invalid peer_id (IP): %s", target), 1, nil
		}

		count := "1"
		if c := params["count"]; c != "" {
			if n, err := strconv.Atoi(c); err == nil && n > 0 && n <= 10 {
				count = c
			}
		}

		name, args := pingCommand(count, target)
		cmd := exec.CommandContext(ctx, name, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			if cmd.ProcessState != nil {
				return "", string(out), cmd.ProcessState.ExitCode(), nil
			}
			return "", err.Error(), 1, nil
		}
		// The exit status is not the whole answer everywhere: Windows ping.exe
		// exits 0 for any ICMP response, a router's "Destination host
		// unreachable" included, so an unreachable peer would be reported as
		// reachable.
		if !pingSucceeded(out) {
			return "", string(out), 1, nil
		}

		return string(out), "", 0, nil
	}
}

// diagnosticsCollectResult holds the structured output of the DiagnosticsCollect action.
type diagnosticsCollectResult struct {
	Hostname          string `json:"hostname"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	CPUCount          int    `json:"cpu_count"`
	MemoryTotal       uint64 `json:"memory_total"`
	DiskTotal         uint64 `json:"disk_total"`
	LoadAvg           string `json:"load_avg"`
	KernelVersion     string `json:"kernel_version"`
	NetworkInterfaces string `json:"network_interfaces,omitempty"`
	Processes         string `json:"processes,omitempty"`
}

// DiagnosticsCollect returns a BuiltinFunc that collects system diagnostics and returns them as JSON.
// Optional parameters: "include_network" (default "true"), "include_processes" (default "true").
// The reader fills "memory_total" and "load_avg" where the /proc files yield
// nothing, which is the case on macOS and Windows. A nil reader keeps the
// /proc-only behaviour.
func DiagnosticsCollect(reader metrics.SystemReader) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		includeNetwork := params["include_network"] != "false"
		includeProcesses := params["include_processes"] != "false"

		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}

		var memTotal uint64
		if data, err := os.ReadFile("/proc/meminfo"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "MemTotal:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
							memTotal = val * 1024 // convert kB to bytes
						}
					}
					break
				}
			}
		}

		diskTotal := diskTotalBytes(diskRootPath())

		var loadAvg string
		if data, err := os.ReadFile("/proc/loadavg"); err == nil {
			loadAvg = strings.TrimSpace(string(data))
		}

		// The platform reader answers where /proc does not. On Linux the
		// /proc reads already filled both values, so the output there is
		// unchanged. A reader error leaves both values as the /proc reads
		// left them, matching their soft-fail.
		//
		// The macOS and Windows readers are best-effort and report a source
		// they could not read as a zero field under a nil error, so only a
		// non-zero load counts as a reading: a failed vm.loadavg would
		// otherwise surface as "0.00 0.00 0.00", a well-formed measurement
		// claiming the machine is idle. Windows has no load average at all
		// and is excluded outright.
		if reader != nil && (memTotal == 0 || loadAvg == "") {
			if stats, err := reader.ReadStats(ctx); err == nil {
				if memTotal == 0 {
					memTotal = stats.MemoryTotalBytes
				}
				if loadAvg == "" && runtime.GOOS != "windows" &&
					(stats.LoadAvg1 != 0 || stats.LoadAvg5 != 0 || stats.LoadAvg15 != 0) {
					loadAvg = fmt.Sprintf("%.2f %.2f %.2f", stats.LoadAvg1, stats.LoadAvg5, stats.LoadAvg15)
				}
			}
		}

		kernelVersion := kernelRelease()
		if kernelVersion == "" {
			kernelVersion = runtime.GOOS + "/" + runtime.GOARCH
		}

		result := diagnosticsCollectResult{
			Hostname:      hostname,
			OS:            runtime.GOOS,
			Arch:          runtime.GOARCH,
			CPUCount:      runtime.NumCPU(),
			MemoryTotal:   memTotal,
			DiskTotal:     diskTotal,
			LoadAvg:       loadAvg,
			KernelVersion: kernelVersion,
		}

		if includeNetwork {
			name, args := networkListCommand()
			if out, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err == nil {
				result.NetworkInterfaces = string(out)
			}
		}
		if includeProcesses {
			name, args := processListCommand()
			if out, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err == nil {
				result.Processes = string(out)
			}
		}

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", "", 1, fmt.Errorf("marshal diagnostics: %w", err)
		}

		return string(data), "", 0, nil
	}
}

// DiagnosticsTraceroutePeer returns a BuiltinFunc that runs traceroute to a mesh peer.
// Requires a "peer_id" parameter (mesh IP). Optional "max_hops" parameter (default 15).
func DiagnosticsTraceroutePeer(info NodeInfoProvider) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		target := params["peer_id"]
		if target == "" {
			return "", "", 1, fmt.Errorf("missing required parameter: peer_id")
		}

		if net.ParseIP(target) == nil {
			return "", fmt.Sprintf("invalid peer_id (IP): %s", target), 1, nil
		}

		maxHops := "15"
		if mh := params["max_hops"]; mh != "" {
			if n, err := strconv.Atoi(mh); err == nil && n > 0 && n <= 64 {
				maxHops = mh
			}
		}

		name, args, err := tracerouteCommand(maxHops, target)
		if err != nil {
			return "", "", 1, fmt.Errorf("traceroute not available")
		}

		cmd := exec.CommandContext(ctx, name, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			if cmd.ProcessState != nil {
				return "", string(out), cmd.ProcessState.ExitCode(), nil
			}
			return "", err.Error(), 1, nil
		}

		return string(out), "", 0, nil
	}
}

// ServiceRestart returns a BuiltinFunc that restarts plexd through the host's
// service manager: systemd on Linux, launchd on macOS, the Service Control
// Manager on Windows.
func ServiceRestart(ctl ServiceController) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		if !ctl.Available() {
			return "", "", 1, fmt.Errorf("service manager not available")
		}
		if err := ctl.Restart(ctx); err != nil {
			return "", err.Error(), 1, nil
		}
		return "", "", 0, nil
	}
}

// serviceReloadConfigResult holds the structured output of ServiceReloadConfig.
type serviceReloadConfigResult struct {
	Status string `json:"status"`
	PID    int    `json:"pid"`
}

// ServiceReloadConfig returns a BuiltinFunc that sends SIGHUP to the current process
// to trigger a configuration reload.
func ServiceReloadConfig() BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		pid := os.Getpid()
		if err := sendReloadSignal(pid); err != nil {
			return "", "", 1, fmt.Errorf("actions: reload config: %w", err)
		}

		result := serviceReloadConfigResult{
			Status: "reload_signal_sent",
			PID:    pid,
		}

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", "", 1, fmt.Errorf("marshal reload config: %w", err)
		}

		return string(data), "", 0, nil
	}
}

// serviceUpgradeResult holds the structured output of ServiceUpgrade.
type serviceUpgradeResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Version string `json:"version,omitempty"`
}

// resolveExecutable resolves the path of the running binary. It is a package
// var so tests can point the upgrade flow at a temporary file.
var resolveExecutable = os.Executable

// upgradeMu serializes ServiceUpgrade so that at most one in-place upgrade runs
// at a time. The orphan sweep below deletes every .plexd-upgrade-* file in the
// binary's directory; without this guard a second concurrent upgrade (a distinct
// execution ID passes the executor's duplicate check) would remove the temp file
// the first is still streaming into, and two upgrades could each rename over the
// binary, leaving a non-deterministic installed version.
var upgradeMu sync.Mutex

// ServiceUpgrade returns a BuiltinFunc that performs an in-place binary upgrade
// from the GitHub release channel.
//
// It downloads the target release binary, verifies its SHA-256 checksum against
// the dispatched value, then downloads and verifies the release's Sigstore
// bundle against the fetched binary's digest. Only after both checks pass is the
// current binary made executable, replaced, and a restart triggered through the
// host's service manager. A release without a bundle asset (the fetch fails) or
// one whose bundle fails verification is refused, and the on-disk binary is
// left untouched.
//
// Required parameters:
//   - version: target version string (e.g. "1.5.0")
//   - checksum: expected SHA-256 checksum of the new binary (hex-encoded, with or without "sha256:" prefix)
func ServiceUpgrade(fetcher ReleaseFetcher, verifier BundleVerifier, ctl ServiceController) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		upgradeMu.Lock()
		defer upgradeMu.Unlock()

		version := params["version"]
		if version == "" {
			return "", "", 1, fmt.Errorf("missing required parameter: version")
		}
		checksum := params["checksum"]
		if checksum == "" {
			return "", "", 1, fmt.Errorf("missing required parameter: checksum")
		}
		// Strip optional "sha256:" prefix.
		checksum = strings.TrimPrefix(checksum, "sha256:")

		// Determine current binary path.
		binaryPath, err := resolveExecutable()
		if err != nil {
			return "", "", 1, fmt.Errorf("resolve executable path: %w", err)
		}
		binaryPath, err = filepath.EvalSymlinks(binaryPath)
		if err != nil {
			return "", "", 1, fmt.Errorf("resolve symlinks: %w", err)
		}

		// Download the new binary from the release channel.
		rc, err := fetcher.FetchBinary(ctx, version)
		if err != nil {
			return "", "", 1, fmt.Errorf("download binary: %w", err)
		}
		defer rc.Close()

		// Write to a temporary file next to the current binary. First sweep any
		// temp files orphaned by a previous upgrade that was killed (SIGKILL,
		// OOM, power loss) between CreateTemp and Rename, before its deferred
		// cleanup could run — otherwise partially-streamed downloads accumulate
		// here (up to maxBinaryBytes each) until the binary's partition fills.
		dir := filepath.Dir(binaryPath)
		orphans, _ := filepath.Glob(filepath.Join(dir, ".plexd-upgrade-*"))
		for _, orphan := range orphans {
			os.Remove(orphan)
		}
		tmpFile, err := os.CreateTemp(dir, ".plexd-upgrade-*")
		if err != nil {
			return "", "", 1, fmt.Errorf("create temp file: %w", err)
		}
		tmpPath := tmpFile.Name()
		defer func() {
			// Clean up temp file on any failure path.
			os.Remove(tmpPath)
		}()

		// Stream the download and compute SHA-256 simultaneously.
		hasher := sha256.New()
		writer := io.MultiWriter(tmpFile, hasher)
		if _, err := io.Copy(writer, rc); err != nil {
			tmpFile.Close()
			return "", "", 1, fmt.Errorf("stream binary: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			return "", "", 1, fmt.Errorf("close temp file: %w", err)
		}

		// Verify the download's checksum against the dispatched value.
		actualChecksum := hex.EncodeToString(hasher.Sum(nil))
		if actualChecksum != checksum {
			result := serviceUpgradeResult{
				Status:  "checksum_mismatch",
				Message: fmt.Sprintf("expected %s, got %s", checksum, actualChecksum),
				Version: version,
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return string(data), "", 1, nil
		}

		// Download and verify the release's Sigstore bundle against the fetched
		// binary's digest. A missing bundle asset fails the fetch, which is how
		// unsigned releases are refused.
		bundle, err := fetcher.FetchBundle(ctx, version)
		if err != nil {
			return "", "", 1, fmt.Errorf("download bundle: %w", err)
		}
		if err := verifier.Verify(bundle, actualChecksum); err != nil {
			result := serviceUpgradeResult{
				Status:  "bundle_verification_failed",
				Message: err.Error(),
				Version: version,
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return string(data), "", 1, nil
		}

		// Make the verified binary executable, then atomically replace the
		// current binary with it.
		if err := os.Chmod(tmpPath, 0755); err != nil {
			return "", "", 1, fmt.Errorf("chmod binary: %w", err)
		}
		if err := replaceExecutable(tmpPath, binaryPath); err != nil {
			return "", "", 1, fmt.Errorf("replace binary: %w", err)
		}
		// Prevent deferred removal of the (now-replaced) file.
		tmpPath = ""

		// Restart through the host's service manager.
		if !ctl.Available() {
			result := serviceUpgradeResult{
				Status:  "upgraded_restart_pending",
				Message: "binary replaced, but the service manager is not available; manual restart required",
				Version: version,
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return string(data), "", 0, nil
		}

		if err := ctl.Restart(ctx); err != nil {
			result := serviceUpgradeResult{
				Status:  "upgraded_restart_failed",
				Message: fmt.Sprintf("binary replaced, restart failed: %s", err),
				Version: version,
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return string(data), "", 1, nil
		}

		result := serviceUpgradeResult{
			Status:  "upgraded",
			Message: "binary replaced and service restarted",
			Version: version,
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", "", 1, fmt.Errorf("marshal upgrade result: %w", err)
		}
		return string(data), "", 0, nil
	}
}

// healthCheckResult holds the structured output of HealthCheck.
type healthCheckResult struct {
	TunnelCount    int    `json:"tunnel_count"`
	ConnectedPeers int    `json:"connected_peers"`
	Uptime         string `json:"uptime"`
	LastHeartbeat  string `json:"last_heartbeat"`
	LastReconcile  string `json:"last_reconcile"`
	Status         string `json:"status"`
	IncludePeers   bool   `json:"include_peers"`
}

// HealthCheck returns a BuiltinFunc that reports the node's health status.
// Optional parameter: "include_peers" (default "true") — include per-peer status.
// Status is "healthy" if tunnel_count > 0, otherwise "degraded".
func HealthCheck(health HealthProvider) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		status := "healthy"
		if health.TunnelCount() <= 0 {
			status = "degraded"
		}

		result := healthCheckResult{
			TunnelCount:    health.TunnelCount(),
			ConnectedPeers: health.ConnectedPeers(),
			Uptime:         health.Uptime().String(),
			LastHeartbeat:  health.LastHeartbeat().Format(time.RFC3339),
			LastReconcile:  health.LastReconcile().Format(time.RFC3339),
			Status:         status,
			IncludePeers:   params["include_peers"] != "false",
		}

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", "", 1, fmt.Errorf("marshal health check: %w", err)
		}

		return string(data), "", 0, nil
	}
}

// meshReconnectResult holds the structured output of MeshReconnect.
type meshReconnectResult struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// MeshReconnect returns a BuiltinFunc that triggers mesh reconnection.
// On failure, returns exit code 1 with error details but no system error.
func MeshReconnect(reconnector MeshReconnector) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		if err := reconnector.Reconnect(ctx); err != nil {
			result := meshReconnectResult{
				Status: "failed",
				Error:  err.Error(),
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return string(data), "", 1, nil
		}

		result := meshReconnectResult{
			Status: "reconnected",
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", "", 1, fmt.Errorf("marshal reconnect: %w", err)
		}

		return string(data), "", 0, nil
	}
}

// ConfigDump returns a BuiltinFunc that outputs the sanitized configuration.
func ConfigDump(provider ConfigProvider) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		return provider.DumpConfig(), "", 0, nil
	}
}

// MaxSnapshotLines is the maximum number of lines that logs.snapshot will return.
const MaxSnapshotLines = 10000

// LogsSnapshot returns a BuiltinFunc that retrieves recent log lines.
// Accepts optional parameters:
//   - "lines": number of lines to return (default 100, max 10000)
//   - "since": duration string (e.g. "5m", "1h") to filter lines by age
func LogsSnapshot(provider LogProvider) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		n := 100
		if linesStr, ok := params["lines"]; ok && linesStr != "" {
			parsed, err := strconv.Atoi(linesStr)
			if err == nil && parsed > 0 {
				n = parsed
			}
		}
		if n > MaxSnapshotLines {
			n = MaxSnapshotLines
		}

		lines := provider.RecentLines(n)

		// Filter by "since" if provided.
		if sinceStr := params["since"]; sinceStr != "" {
			if dur, err := time.ParseDuration(sinceStr); err == nil {
				cutoff := time.Now().Add(-dur)
				filtered := lines[:0]
				for _, line := range lines {
					// Lines from the ring buffer are prefixed with a timestamp.
					// Accept the line if we cannot parse a timestamp (best effort).
					if ts, err := time.Parse(time.RFC3339, extractTimestamp(line)); err == nil {
						if ts.Before(cutoff) {
							continue
						}
					}
					filtered = append(filtered, line)
				}
				lines = filtered
			}
		}

		return strings.Join(lines, "\n"), "", 0, nil
	}
}

// extractTimestamp attempts to extract a leading RFC3339 timestamp from a log line.
func extractTimestamp(line string) string {
	// Timestamps are typically at the start; try the first 30 chars.
	if len(line) > 30 {
		line = line[:30]
	}
	for i := len(line); i > 15; i-- {
		if _, err := time.Parse(time.RFC3339, line[:i]); err == nil {
			return line[:i]
		}
	}
	return ""
}
