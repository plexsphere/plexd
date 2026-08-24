package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/paths"
)

// TestWarnIfConfigAbsent_SurvivesLogLevelError pins the missing-config line
// against the log level. plexd up runs its logger at the configured level, and
// a DaemonSet on --log-level error that loses its ConfigMap would otherwise
// come up on the default data_dir, find no identity, and register as a new
// node on every restart with nothing on stderr to say so.
func TestWarnIfConfigAbsent_SurvivesLogLevelError(t *testing.T) {
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = old })

	// The command logger at this level drops warn-level records, which is why
	// the helper must not route through it.
	setupLogger("error").Warn("dropped by the level filter")
	warnIfConfigAbsent(false, "/etc/plexd/config.yaml", "/var/lib/plexd")
	warnIfConfigAbsent(true, "/etc/plexd/found.yaml", "/srv/plexd")

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	os.Stderr = old
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}

	output := string(captured)
	if strings.Contains(output, "dropped by the level filter") {
		t.Fatalf("setupLogger(\"error\") should drop warn records, got: %s", output)
	}
	for _, want := range []string{"config file not found", "/etc/plexd/config.yaml", "/var/lib/plexd"} {
		if !strings.Contains(output, want) {
			t.Errorf("stderr should contain %q, got: %s", want, output)
		}
	}
	if strings.Contains(output, "/etc/plexd/found.yaml") {
		t.Errorf("a found config file must not warn, got: %s", output)
	}
}

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

func TestRootCommand_RegistrationFlags(t *testing.T) {
	output := executeHelp(t, "--help")

	for _, flag := range []string{"--project-id", "--resource-handle", "--requested-resource-id"} {
		if !strings.Contains(output, flag) {
			t.Errorf("help output should contain %q, got: %s", flag, output)
		}
	}
}

// TestRootCommand_ConfigFlagDefault pins the --config default to the platform
// configuration file, and keeps PLEXD_CONFIG ahead of it. The path is the
// first thing every command touches, so a default that resolved against the
// current drive on Windows would send the daemon to C:\etc\plexd.
func TestRootCommand_ConfigFlagDefault(t *testing.T) {
	// The flag is registered in init(), so its default froze against the
	// environment as it stood then. This assertion therefore has to run before
	// any t.Setenv below touches PLEXD_CONFIG.
	flag := rootCmd.PersistentFlags().Lookup("config")
	if flag == nil {
		t.Fatal("rootCmd has no --config flag")
	}
	if want := envOrDefault("PLEXD_CONFIG", paths.ConfigFile()); flag.DefValue != want {
		t.Errorf("--config default = %q, want %q", flag.DefValue, want)
	}

	t.Run("empty PLEXD_CONFIG falls back to the platform path", func(t *testing.T) {
		t.Setenv("PLEXD_CONFIG", "")

		if got, want := envOrDefault("PLEXD_CONFIG", paths.ConfigFile()), paths.ConfigFile(); got != want {
			t.Errorf("envOrDefault = %q, want %q", got, want)
		}
	})

	t.Run("PLEXD_CONFIG overrides the platform path", func(t *testing.T) {
		custom := filepath.Join(t.TempDir(), "config.yaml")
		t.Setenv("PLEXD_CONFIG", custom)

		if got := envOrDefault("PLEXD_CONFIG", paths.ConfigFile()); got != custom {
			t.Errorf("envOrDefault = %q, want %q", got, custom)
		}
	})
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
