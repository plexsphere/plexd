package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
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

// Ping returns a BuiltinFunc that tests connectivity to a target mesh IP.
// Requires a "target" parameter. Returns exit code 0 on success, 1 on failure.
func Ping(info NodeInfoProvider) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		target, ok := params["target"]
		if !ok || target == "" {
			return "", "", 1, fmt.Errorf("missing required parameter: target")
		}

		if net.ParseIP(target) == nil {
			return "", fmt.Sprintf("invalid target IP: %s", target), 1, nil
		}

		cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "3", target)
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
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	CPUCount      int    `json:"cpu_count"`
	MemoryTotal   uint64 `json:"memory_total"`
	DiskTotal     uint64 `json:"disk_total"`
	LoadAvg       string `json:"load_avg"`
	KernelVersion string `json:"kernel_version"`
}

// DiagnosticsCollect returns a BuiltinFunc that collects system diagnostics and returns them as JSON.
// It gracefully handles errors by using fallback values.
func DiagnosticsCollect() BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
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

// DiagnosticsTraceroutePeer returns a BuiltinFunc that runs traceroute to a target IP.
// Requires a "target" parameter containing a valid IP address.
func DiagnosticsTraceroutePeer(info NodeInfoProvider) BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		target, ok := params["target"]
		if !ok || target == "" {
			return "", "", 1, fmt.Errorf("missing required parameter: target")
		}

		if net.ParseIP(target) == nil {
			return "", fmt.Sprintf("invalid target IP: %s", target), 1, nil
		}

		path, err := exec.LookPath("traceroute")
		if err != nil {
			return "", "", 1, fmt.Errorf("traceroute not available")
		}

		cmd := exec.CommandContext(ctx, path, "-n", "-m", "15", "-w", "3", target)
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
}

// ServiceUpgrade returns a BuiltinFunc placeholder for in-place upgrades.
// Currently returns a message indicating that in-place upgrade is not supported.
func ServiceUpgrade() BuiltinFunc {
	return func(ctx context.Context, params map[string]string) (string, string, int, error) {
		result := serviceUpgradeResult{
			Status:  "upgrade_not_available",
			Message: "in-place upgrade not supported; use package manager or control plane",
		}

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", "", 1, fmt.Errorf("marshal upgrade: %w", err)
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
}

// HealthCheck returns a BuiltinFunc that reports the node's health status.
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
// Accepts an optional "lines" parameter (default 100, max 10000) specifying how many lines to return.
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
		return strings.Join(lines, "\n"), "", 0, nil
	}
}
