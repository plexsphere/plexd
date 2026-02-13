package actions

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/integrity"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func writeExecutable(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiscoverHooks_ValidDirectory(t *testing.T) {
	dir := t.TempDir()
	p1 := writeExecutable(t, dir, "alpha.sh", "#!/bin/sh\necho alpha\n")
	p2 := writeExecutable(t, dir, "beta.sh", "#!/bin/sh\necho beta\n")

	hooks, err := DiscoverHooks(dir, testLogger())
	if err != nil {
		t.Fatalf("DiscoverHooks() error = %v", err)
	}
	if len(hooks) != 2 {
		t.Fatalf("len(hooks) = %d, want 2", len(hooks))
	}

	// Sorted by name: alpha.sh, beta.sh
	if hooks[0].Name != "alpha.sh" {
		t.Errorf("hooks[0].Name = %q, want %q", hooks[0].Name, "alpha.sh")
	}
	if hooks[1].Name != "beta.sh" {
		t.Errorf("hooks[1].Name = %q, want %q", hooks[1].Name, "beta.sh")
	}

	// Verify checksums match integrity.HashFile
	wantHash1, err := integrity.HashFile(p1)
	if err != nil {
		t.Fatalf("HashFile(%q) error = %v", p1, err)
	}
	if hooks[0].Checksum != wantHash1 {
		t.Errorf("hooks[0].Checksum = %q, want %q", hooks[0].Checksum, wantHash1)
	}

	wantHash2, err := integrity.HashFile(p2)
	if err != nil {
		t.Fatalf("HashFile(%q) error = %v", p2, err)
	}
	if hooks[1].Checksum != wantHash2 {
		t.Errorf("hooks[1].Checksum = %q, want %q", hooks[1].Checksum, wantHash2)
	}

	// Source must be "local"
	if hooks[0].Source != "local" {
		t.Errorf("hooks[0].Source = %q, want %q", hooks[0].Source, "local")
	}
	if hooks[1].Source != "local" {
		t.Errorf("hooks[1].Source = %q, want %q", hooks[1].Source, "local")
	}
}

func TestDiscoverHooks_MissingDirectory(t *testing.T) {
	hooks, err := DiscoverHooks("/nonexistent/path/hooks", testLogger())
	if err != nil {
		t.Fatalf("DiscoverHooks() error = %v, want nil", err)
	}
	if hooks == nil {
		t.Fatal("hooks = nil, want non-nil empty slice")
	}
	if len(hooks) != 0 {
		t.Errorf("len(hooks) = %d, want 0", len(hooks))
	}
}

func TestDiscoverHooks_EmptyHooksDir(t *testing.T) {
	hooks, err := DiscoverHooks("", testLogger())
	if err != nil {
		t.Fatalf("DiscoverHooks() error = %v, want nil", err)
	}
	if hooks == nil {
		t.Fatal("hooks = nil, want non-nil empty slice")
	}
	if len(hooks) != 0 {
		t.Errorf("len(hooks) = %d, want 0", len(hooks))
	}
}

func TestDiscoverHooks_SidecarMetadata(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "deploy.sh", "#!/bin/sh\necho deploy\n")

	meta := hookMetadata{
		Description: "Deploy to production",
		Parameters: []api.ActionParam{
			{Name: "target", Type: "string", Required: true, Description: "Target address"},
			{Name: "force", Type: "bool", Required: false, Description: "Force deploy"},
		},
		Timeout: "30s",
		Sandbox: "none",
	}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy.sh.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	hooks, err := DiscoverHooks(dir, testLogger())
	if err != nil {
		t.Fatalf("DiscoverHooks() error = %v", err)
	}
	if len(hooks) != 1 {
		t.Fatalf("len(hooks) = %d, want 1", len(hooks))
	}

	h := hooks[0]
	if h.Description != "Deploy to production" {
		t.Errorf("Description = %q, want %q", h.Description, "Deploy to production")
	}
	if len(h.Parameters) != 2 {
		t.Fatalf("len(Parameters) = %d, want 2", len(h.Parameters))
	}
	if h.Parameters[0].Name != "target" {
		t.Errorf("Parameters[0].Name = %q, want %q", h.Parameters[0].Name, "target")
	}
	if !h.Parameters[0].Required {
		t.Error("Parameters[0].Required = false, want true")
	}
	if h.Timeout != "30s" {
		t.Errorf("Timeout = %q, want %q", h.Timeout, "30s")
	}
	if h.Sandbox != "none" {
		t.Errorf("Sandbox = %q, want %q", h.Sandbox, "none")
	}
}

func TestDiscoverHooks_NonExecutableSkipped(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "good.sh", "#!/bin/sh\necho good\n")

	// Non-executable file
	if err := os.WriteFile(filepath.Join(dir, "bad.sh"), []byte("#!/bin/sh\necho bad\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	hooks, err := DiscoverHooks(dir, testLogger())
	if err != nil {
		t.Fatalf("DiscoverHooks() error = %v", err)
	}
	if len(hooks) != 1 {
		t.Fatalf("len(hooks) = %d, want 1", len(hooks))
	}
	if hooks[0].Name != "good.sh" {
		t.Errorf("hooks[0].Name = %q, want %q", hooks[0].Name, "good.sh")
	}
}

func TestDiscoverHooks_DirectorySkipped(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "hook.sh", "#!/bin/sh\necho hook\n")

	// Create a subdirectory with executable bits
	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}

	hooks, err := DiscoverHooks(dir, testLogger())
	if err != nil {
		t.Fatalf("DiscoverHooks() error = %v", err)
	}
	if len(hooks) != 1 {
		t.Fatalf("len(hooks) = %d, want 1", len(hooks))
	}
	if hooks[0].Name != "hook.sh" {
		t.Errorf("hooks[0].Name = %q, want %q", hooks[0].Name, "hook.sh")
	}
}

func TestDiscoverHooks_SidecarParseError(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "broken.sh", "#!/bin/sh\necho broken\n")

	// Invalid JSON sidecar
	if err := os.WriteFile(filepath.Join(dir, "broken.sh.json"), []byte("{invalid json}"), 0o644); err != nil {
		t.Fatal(err)
	}

	hooks, err := DiscoverHooks(dir, testLogger())
	if err != nil {
		t.Fatalf("DiscoverHooks() error = %v", err)
	}
	if len(hooks) != 1 {
		t.Fatalf("len(hooks) = %d, want 1", len(hooks))
	}

	h := hooks[0]
	if h.Name != "broken.sh" {
		t.Errorf("Name = %q, want %q", h.Name, "broken.sh")
	}
	// Metadata should be defaults (empty) since sidecar failed
	if h.Description != "" {
		t.Errorf("Description = %q, want empty", h.Description)
	}
	if h.Parameters != nil {
		t.Errorf("Parameters = %v, want nil", h.Parameters)
	}
	if h.Timeout != "" {
		t.Errorf("Timeout = %q, want empty", h.Timeout)
	}
	if h.Sandbox != "" {
		t.Errorf("Sandbox = %q, want empty", h.Sandbox)
	}
}

func TestDiscoverHooks_JsonFilesSkipped(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "hook.sh", "#!/bin/sh\necho hook\n")

	// Create an executable .json file — should be skipped as it's a sidecar
	writeExecutable(t, dir, "something.json", `{"description": "I am a sidecar"}`)

	hooks, err := DiscoverHooks(dir, testLogger())
	if err != nil {
		t.Fatalf("DiscoverHooks() error = %v", err)
	}
	if len(hooks) != 1 {
		t.Fatalf("len(hooks) = %d, want 1", len(hooks))
	}
	if hooks[0].Name != "hook.sh" {
		t.Errorf("hooks[0].Name = %q, want %q", hooks[0].Name, "hook.sh")
	}
}
