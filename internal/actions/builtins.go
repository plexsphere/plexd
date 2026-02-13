package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
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
