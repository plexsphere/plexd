package cmd

import (
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/nodeapi"
)

func TestStatusCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd status", "status")
}

func TestStatusCommand_Success(t *testing.T) {
	socketPath := startFakeAgent(t, nodeapi.StateSummary{
		Metadata: map[string]string{"node_id": "node-123", "mode": "node"},
	})
	overrideSocketPath(t, socketPath)

	output, err := executeCmd(t, "status")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "node-123") {
		t.Errorf("output should contain 'node-123', got: %s", output)
	}
}

// TestStatusCommand_CredentialRefused verifies that a node whose credential
// the control plane refuses gets the cause and the way to enrol again right
// after the counts, ahead of the metadata listing.
func TestStatusCommand_CredentialRefused(t *testing.T) {
	socketPath := startFakeAgent(t, nodeapi.StateSummary{
		Metadata: map[string]string{"control_plane_credential": "refused"},
	})
	overrideSocketPath(t, socketPath)

	output, err := executeCmd(t, "status")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "Metadata entries: 1\n" +
		"Data keys:        0\n" +
		"Secret keys:      0\n" +
		"Report keys:      0\n" +
		"\n" +
		"The control plane refuses this node's credential: the Node was removed or its credential revoked.\n" +
		"To enrol again, run 'plexd deregister', provide a fresh bootstrap token, and restart plexd.\n" +
		"\n" +
		"Metadata:\n" +
		"  control_plane_credential: refused\n"
	if output != want {
		t.Errorf("output = %q, want %q", output, want)
	}
}

// TestStatusCommand_CredentialNotRefused verifies that the output stays as it
// was without the key and with any value other than refused.
func TestStatusCommand_CredentialNotRefused(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
		want     string
	}{
		{
			name:     "key absent",
			metadata: map[string]string{"node_id": "node-123"},
			want: "Metadata entries: 1\n" +
				"Data keys:        0\n" +
				"Secret keys:      0\n" +
				"Report keys:      0\n" +
				"\n" +
				"Metadata:\n" +
				"  node_id: node-123\n",
		},
		{
			name:     "accepted",
			metadata: map[string]string{"control_plane_credential": "accepted"},
			want: "Metadata entries: 1\n" +
				"Data keys:        0\n" +
				"Secret keys:      0\n" +
				"Report keys:      0\n" +
				"\n" +
				"Metadata:\n" +
				"  control_plane_credential: accepted\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socketPath := startFakeAgent(t, nodeapi.StateSummary{Metadata: tt.metadata})
			overrideSocketPath(t, socketPath)

			output, err := executeCmd(t, "status")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if output != tt.want {
				t.Errorf("output = %q, want %q", output, tt.want)
			}
		})
	}
}

func TestStatusCommand_Help(t *testing.T) {
	output := executeHelp(t, "status", "--help")
	if !strings.Contains(output, "status") {
		t.Errorf("help should contain 'status', got: %s", output)
	}
	if !strings.Contains(output, "Unix socket") {
		t.Errorf("help should mention 'Unix socket', got: %s", output)
	}
}
