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
	"syscall"
	"time"
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

// ArtifactFetcher downloads a plexd binary artifact.
type ArtifactFetcher interface {
	FetchArtifact(ctx context.Context, version, goos, arch string) (io.ReadCloser, error)
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

		cmd := exec.CommandContext(ctx, "ping", "-c", count, "-W", "3", target)
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
func DiagnosticsCollect() BuiltinFunc {
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

		var diskTotal uint64
		var stat syscall.Statfs_t
		if err := syscall.Statfs("/", &stat); err == nil {
			diskTotal = stat.Blocks * uint64(stat.Bsize)
		}

		var loadAvg string
		if data, err := os.ReadFile("/proc/loadavg"); err == nil {
			loadAvg = strings.TrimSpace(string(data))
		}

		var kernelVersion string
		var uname syscall.Utsname
		if err := syscall.Uname(&uname); err == nil {
			kernelVersion = int8ArrayToString(uname.Release[:])
		} else {
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
			if out, err := exec.CommandContext(ctx, "ip", "addr", "show").CombinedOutput(); err == nil {
				result.NetworkInterfaces = string(out)
			}
		}
		if includeProcesses {
			if out, err := exec.CommandContext(ctx, "ps", "aux", "--no-headers").CombinedOutput(); err == nil {
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

// int8ArrayToString converts a null-terminated int8 array (from syscall.Utsname) to a Go string.
func int8ArrayToString(arr []int8) string {
	buf := make([]byte, 0, len(arr))
	for _, b := range arr {
		if b == 0 {
			break
		}
		buf = append(buf, byte(b))
	}
	return string(buf)
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

		path, err := exec.LookPath("traceroute")
		if err != nil {
			return "", "", 1, fmt.Errorf("traceroute not available")
		}

		cmd := exec.CommandContext(ctx, path, "-n", "-m", maxHops, "-w", "3", target)
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

// ServiceRestart returns a BuiltinFunc that restarts the plexd service via systemctl.
func ServiceRestart() BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		path, err := exec.LookPath("systemctl")
		if err != nil {
			return "", "", 1, fmt.Errorf("systemctl not available")
		}

		cmd := exec.CommandContext(ctx, path, "restart", "plexd.service")
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

// serviceReloadConfigResult holds the structured output of ServiceReloadConfig.
type serviceReloadConfigResult struct {
	Status string `json:"status"`
	PID    int    `json:"pid"`
}

// ServiceReloadConfig returns a BuiltinFunc that sends SIGHUP to the current process
// to trigger a configuration reload.
func ServiceReloadConfig() BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		pid := syscall.Getpid()
		if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
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

// ServiceUpgrade returns a BuiltinFunc that performs an in-place binary upgrade.
// It downloads the new binary from the control plane, verifies its SHA-256
// checksum, atomically replaces the current binary, and triggers a systemd restart.
//
// Required parameters:
//   - version: target version string (e.g. "1.5.0")
//   - checksum: expected SHA-256 checksum of the new binary (hex-encoded, with or without "sha256:" prefix)
func ServiceUpgrade(fetcher ArtifactFetcher) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
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
		binaryPath, err := os.Executable()
		if err != nil {
			return "", "", 1, fmt.Errorf("resolve executable path: %w", err)
		}
		binaryPath, err = filepath.EvalSymlinks(binaryPath)
		if err != nil {
			return "", "", 1, fmt.Errorf("resolve symlinks: %w", err)
		}

		// Download the new binary.
		rc, err := fetcher.FetchArtifact(ctx, version, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return "", "", 1, fmt.Errorf("download artifact: %w", err)
		}
		defer rc.Close()

		// Write to a temporary file next to the current binary.
		dir := filepath.Dir(binaryPath)
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
			return "", "", 1, fmt.Errorf("download binary: %w", err)
		}
		if err := tmpFile.Chmod(0755); err != nil {
			tmpFile.Close()
			return "", "", 1, fmt.Errorf("chmod binary: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			return "", "", 1, fmt.Errorf("close temp file: %w", err)
		}

		// Verify checksum.
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

		// Atomic replace: rename temp file over the current binary.
		if err := os.Rename(tmpPath, binaryPath); err != nil {
			return "", "", 1, fmt.Errorf("replace binary: %w", err)
		}
		// Prevent deferred removal of the (now-replaced) file.
		tmpPath = ""

		// Trigger systemd restart.
		systemctl, lookErr := exec.LookPath("systemctl")
		if lookErr != nil {
			result := serviceUpgradeResult{
				Status:  "upgraded_restart_pending",
				Message: "binary replaced, but systemctl not available; manual restart required",
				Version: version,
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return string(data), "", 0, nil
		}

		cmd := exec.CommandContext(ctx, systemctl, "restart", "plexd.service")
		if out, err := cmd.CombinedOutput(); err != nil {
			result := serviceUpgradeResult{
				Status:  "upgraded_restart_failed",
				Message: fmt.Sprintf("binary replaced, restart failed: %s", strings.TrimSpace(string(out))),
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
