package cmd

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

func TestHooksCommand_Help(t *testing.T) {
	output := executeHelp(t, "hooks", "--help")
	if !strings.Contains(output, "list") {
		t.Errorf("help should list 'list' subcommand, got: %s", output)
	}
	if !strings.Contains(output, "verify") {
		t.Errorf("help should list 'verify' subcommand, got: %s", output)
	}
	if !strings.Contains(output, "reload") {
		t.Errorf("help should list 'reload' subcommand, got: %s", output)
	}
}

func TestHooksListCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd hooks list", "hooks", "list")
}

func TestHooksVerifyCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd hooks verify", "hooks", "verify")
}

func TestHooksReloadCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd hooks reload", "hooks", "reload")
}

func TestHooksListCommand(t *testing.T) {
	tests := []struct {
		name     string
		hooks    []api.HookInfo
		wantSubs []string
	}{
		{
			name:     "empty list",
			hooks:    []api.HookInfo{},
			wantSubs: []string{"No hooks registered."},
		},
		{
			name: "single hook with short checksum",
			hooks: []api.HookInfo{
				{Name: "hook-a", Source: "local", Checksum: "abc123", Description: "first hook"},
			},
			wantSubs: []string{"hook-a", "local", "abc123", "first hook"},
		},
		{
			name: "multiple hooks with tabwriter output",
			hooks: []api.HookInfo{
				{Name: "hook-a", Source: "local", Checksum: "abc123def456789", Description: "first hook"},
				{Name: "hook-b", Source: "remote", Checksum: "short", Description: "second hook"},
			},
			wantSubs: []string{
				"NAME", "SOURCE", "CHECKSUM", "DESCRIPTION",
				"hook-a", "local", "abc123def456...", "first hook",
				"hook-b", "remote", "short", "second hook",
			},
		},
		{
			name: "checksum truncation at exactly 12 chars",
			hooks: []api.HookInfo{
				{Name: "exact-12", Source: "local", Checksum: "123456789012", Description: "exactly 12"},
				{Name: "over-12", Source: "local", Checksum: "1234567890123", Description: "13 chars"},
			},
			wantSubs: []string{
				"123456789012",    // exactly 12 chars: no truncation
				"123456789012...", // 13 chars: truncated
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socketPath := startTestSocketServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.hooks)
			}))
			overrideSocketPath(t, socketPath)

			output, err := executeCmd(t, "hooks", "list")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, sub := range tt.wantSubs {
				if !strings.Contains(output, sub) {
					t.Errorf("output should contain %q, got:\n%s", sub, output)
				}
			}
		})
	}
}

func TestHooksVerifyCommand(t *testing.T) {
	tests := []struct {
		name     string
		hooks    []api.HookInfo
		wantSubs []string
		wantNot  []string
	}{
		{
			name:     "no hooks to verify",
			hooks:    []api.HookInfo{},
			wantSubs: []string{"No hooks to verify."},
		},
		{
			name: "all hooks have checksums",
			hooks: []api.HookInfo{
				{Name: "hook-a", Checksum: "abc123"},
				{Name: "hook-b", Checksum: "def456"},
			},
			wantSubs: []string{
				"OK    hook-a: abc123",
				"OK    hook-b: def456",
				"All 2 hooks have checksums.",
			},
			wantNot: []string{"WARN"},
		},
		{
			name: "mixed warn and ok",
			hooks: []api.HookInfo{
				{Name: "hook-good", Checksum: "abc123"},
				{Name: "hook-bad", Checksum: ""},
			},
			wantSubs: []string{
				"OK    hook-good: abc123",
				"WARN  hook-bad: no checksum",
			},
			wantNot: []string{"All 2 hooks have checksums."},
		},
		{
			name: "all hooks missing checksums",
			hooks: []api.HookInfo{
				{Name: "hook-x", Checksum: ""},
				{Name: "hook-y", Checksum: ""},
			},
			wantSubs: []string{
				"WARN  hook-x: no checksum",
				"WARN  hook-y: no checksum",
			},
			wantNot: []string{"All"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socketPath := startTestSocketServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.hooks)
			}))
			overrideSocketPath(t, socketPath)

			output, err := executeCmd(t, "hooks", "verify")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, sub := range tt.wantSubs {
				if !strings.Contains(output, sub) {
					t.Errorf("output should contain %q, got:\n%s", sub, output)
				}
			}
			for _, sub := range tt.wantNot {
				if strings.Contains(output, sub) {
					t.Errorf("output should NOT contain %q, got:\n%s", sub, output)
				}
			}
		})
	}
}

func TestHooksReloadCommand(t *testing.T) {
	socketPath := startTestSocketServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(hooksReloadResponseMsg{
			Status: "ok",
			Hooks: []api.HookInfo{
				{Name: "hook-a", Source: "local"},
				{Name: "hook-b", Source: "remote"},
			},
		})
	}))
	overrideSocketPath(t, socketPath)

	output, err := executeCmd(t, "hooks", "reload")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "Status: ok") {
		t.Errorf("output should contain 'Status: ok', got:\n%s", output)
	}
	if !strings.Contains(output, "Hooks:  2") {
		t.Errorf("output should contain 'Hooks:  2', got:\n%s", output)
	}
}

func TestHooksListCommand_Help(t *testing.T) {
	output := executeHelp(t, "hooks", "list", "--help")
	if !strings.Contains(output, "list") {
		t.Errorf("help should contain 'list', got: %s", output)
	}
}
