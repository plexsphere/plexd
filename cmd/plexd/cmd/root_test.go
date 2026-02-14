package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootCommand_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{})

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "plexd") {
		t.Errorf("help output should contain 'plexd', got: %s", output)
	}
	if !strings.Contains(output, "node agent") {
		t.Errorf("help output should contain 'node agent', got: %s", output)
	}
}

func TestRootCommand_Version(t *testing.T) {
	SetVersionInfo("1.2.3", "abc123", "2025-01-01")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--version"})

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "1.2.3") {
		t.Errorf("version output should contain '1.2.3', got: %s", output)
	}
	if !strings.Contains(output, "abc123") {
		t.Errorf("version output should contain 'abc123', got: %s", output)
	}
	if !strings.Contains(output, "2025-01-01") {
		t.Errorf("version output should contain '2025-01-01', got: %s", output)
	}
}

func TestRootCommand_UnknownSubcommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"nonexistent"})

	_ = rootCmd.Execute()

	// Cobra without a Run function prints help for unknown args.
	// Verify it still outputs something sensible rather than crashing.
	output := buf.String()
	if !strings.Contains(output, "plexd") {
		t.Errorf("output for unknown subcommand should contain 'plexd', got: %s", output)
	}
}
