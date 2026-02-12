package integrity

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStore_SetAndGet(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	const path = "/usr/local/bin/plexd"
	const checksum = "abc123def456"

	if err := s.Set(path, checksum); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got := s.Get(path)
	if got != checksum {
		t.Errorf("Get(%q) = %q, want %q", path, got, checksum)
	}
}

func TestStore_GetMissing(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	got := s.Get("/nonexistent/path")
	if got != "" {
		t.Errorf("Get(unknown) = %q, want empty string", got)
	}
}

func TestStore_Remove(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	const path = "/usr/local/bin/plexd"
	if err := s.Set(path, "abc123"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if err := s.Remove(path); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	got := s.Get(path)
	if got != "" {
		t.Errorf("Get(%q) after Remove = %q, want empty string", path, got)
	}
}

func TestStore_PersistAndReload(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	entries := map[string]string{
		"/usr/local/bin/plexd":       "aaa111",
		"/etc/plexd/hooks/pre-start": "bbb222",
		"/etc/plexd/hooks/post-stop": "ccc333",
	}
	for p, c := range entries {
		if err := s1.Set(p, c); err != nil {
			t.Fatalf("Set(%q) error = %v", p, err)
		}
	}

	// Create a new store from the same directory to verify persistence.
	s2, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore() reload error = %v", err)
	}

	for p, want := range entries {
		got := s2.Get(p)
		if got != want {
			t.Errorf("reloaded Get(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestStore_MissingFileOnFirstRun(t *testing.T) {
	dir := t.TempDir()

	// Confirm the checksums file does not exist.
	_, err := os.Stat(filepath.Join(dir, checksumFileName))
	if !os.IsNotExist(err) {
		t.Fatalf("expected checksums.json to not exist, got err = %v", err)
	}

	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore() error = %v, want nil for missing file", err)
	}

	got := s.Get("/anything")
	if got != "" {
		t.Errorf("Get on empty store = %q, want empty string", got)
	}
}

func TestStore_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	const goroutines = 20
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				path := "/bin/tool"
				checksum := "deadbeef"

				if err := s.Set(path, checksum); err != nil {
					t.Errorf("goroutine %d: Set() error = %v", id, err)
					return
				}
				_ = s.Get(path)

				if err := s.Remove(path); err != nil {
					t.Errorf("goroutine %d: Remove() error = %v", id, err)
					return
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestStore_InvalidJSON(t *testing.T) {
	dir := t.TempDir()

	// Write invalid JSON to the checksums file.
	err := os.WriteFile(filepath.Join(dir, checksumFileName), []byte("{not valid json}"), 0o600)
	if err != nil {
		t.Fatalf("failed to write invalid checksums file: %v", err)
	}

	_, err = NewStore(dir)
	if err == nil {
		t.Fatal("NewStore() = nil error, want error for invalid JSON")
	}
}
