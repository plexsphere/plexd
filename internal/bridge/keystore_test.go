package bridge

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The ids of the key store tests: the form of a provider's id.
const (
	testKeyIDA = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1"
	testKeyIDB = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2"
)

// keyStoreDir returns a directory below a fresh temp directory that does not
// exist yet, so the store creates it.
func keyStoreDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "keys")
}

// assertPerm fails when path's permission bits differ from want. Windows
// reports no POSIX bits, so the check runs elsewhere only.
func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("mode of %s = %o, want %o", path, got, want)
	}
}

// dirNames returns the sorted names of dir's entries.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

func TestInterfaceKeyStore_LoadOrCreateKeepsTheKey(t *testing.T) {
	dir := keyStoreDir(t)
	store := NewInterfaceKeyStore(dir)

	first, err := store.LoadOrCreate(testKeyIDA)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if first == (wgtypes.Key{}) {
		t.Fatal("LoadOrCreate returned the zero key")
	}

	second, err := store.LoadOrCreate(testKeyIDA)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if second != first {
		t.Error("second LoadOrCreate returned another key")
	}

	reopened, err := NewInterfaceKeyStore(dir).LoadOrCreate(testKeyIDA)
	if err != nil {
		t.Fatalf("LoadOrCreate from a second store: %v", err)
	}
	if reopened != first {
		t.Error("a second store over the same directory returned another key")
	}

	other, err := store.LoadOrCreate(testKeyIDB)
	if err != nil {
		t.Fatalf("LoadOrCreate of a second id: %v", err)
	}
	if other == first {
		t.Error("two ids share one key")
	}
}

func TestInterfaceKeyStore_LoadOrCreateWritesTheFile(t *testing.T) {
	dir := keyStoreDir(t)
	store := NewInterfaceKeyStore(dir)

	key, err := store.LoadOrCreate(testKeyIDA)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	path := filepath.Join(dir, testKeyIDA+".key")
	assertPerm(t, dir, 0700)
	assertPerm(t, path, 0600)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		t.Fatalf("key file is not standard base64: %v", err)
	}
	if !bytes.Equal(raw, key[:]) {
		t.Error("key file does not hold the returned key")
	}

	if got, want := dirNames(t, dir), []string{testKeyIDA + ".key"}; !slices.Equal(got, want) {
		t.Errorf("directory holds %q, want %q", got, want)
	}
}

func TestInterfaceKeyStore_LoadOrCreateLeavesAnExistingDirectoryMode(t *testing.T) {
	dir := keyStoreDir(t)
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Mkdir applies the umask; set the mode the assertion expects.
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := NewInterfaceKeyStore(dir).LoadOrCreate(testKeyIDA); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	assertPerm(t, dir, 0750)
	assertPerm(t, filepath.Join(dir, testKeyIDA+".key"), 0600)
}

func TestInterfaceKeyStore_LoadOrCreateReadsAKeyWithATrailingNewline(t *testing.T) {
	dir := t.TempDir()
	var want wgtypes.Key
	for i := range want {
		want[i] = byte(i + 1)
	}
	content := base64.StdEncoding.EncodeToString(want[:]) + "\n"
	if err := os.WriteFile(filepath.Join(dir, testKeyIDA+".key"), []byte(content), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	got, err := NewInterfaceKeyStore(dir).LoadOrCreate(testKeyIDA)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if got != want {
		t.Error("LoadOrCreate did not return the stored key")
	}
}

func TestInterfaceKeyStore_LoadOrCreateRefusesAFileThatHoldsNoKey(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"not a key", "not-a-key"},
		{"16 bytes", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"33 bytes", base64.StdEncoding.EncodeToString(make([]byte, 33))},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, testKeyIDA+".key")
			if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
				t.Fatalf("write key file: %v", err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}

			if _, err := NewInterfaceKeyStore(dir).LoadOrCreate(testKeyIDA); err == nil {
				t.Fatal("LoadOrCreate succeeded, want an error")
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read key file: %v", err)
			}
			if string(data) != tt.content {
				t.Errorf("key file holds %q, want it untouched as %q", data, tt.content)
			}
			after, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
				t.Error("key file was replaced")
			}
			if got, want := dirNames(t, dir), []string{testKeyIDA + ".key"}; !slices.Equal(got, want) {
				t.Errorf("directory holds %q, want %q", got, want)
			}
		})
	}
}

func TestInterfaceKeyStore_LoadOrCreateRefusesABadID(t *testing.T) {
	for _, id := range []string{"", "a/b", `a\b`, "/abs", ".", "..", ".hidden", "../escape"} {
		t.Run(id, func(t *testing.T) {
			dir := keyStoreDir(t)
			if _, err := NewInterfaceKeyStore(dir).LoadOrCreate(id); err == nil {
				t.Fatalf("LoadOrCreate(%q) succeeded, want an error", id)
			}
			if _, err := os.Lstat(dir); !os.IsNotExist(err) {
				t.Errorf("LoadOrCreate(%q) touched the directory: stat error %v", id, err)
			}
			if got := dirNames(t, filepath.Dir(dir)); len(got) != 0 {
				t.Errorf("LoadOrCreate(%q) left %q beside the directory", id, got)
			}
		})
	}
}

func TestInterfaceKeyStore_PruneDeletesTheKeysNotKept(t *testing.T) {
	dir := keyStoreDir(t)
	store := NewInterfaceKeyStore(dir)
	keptKey, err := store.LoadOrCreate(testKeyIDA)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if _, err := store.LoadOrCreate(testKeyIDB); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	// Entries Prune leaves alone: a file without the suffix, the temp file of
	// an interrupted write, a hidden file and a directory with the suffix.
	others := []string{"notes.txt", ".tmp-" + testKeyIDB + ".key-123456", ".hidden.key"}
	for _, name := range others {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub.key"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := store.Prune(map[string]struct{}{testKeyIDA: {}}); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	want := append([]string{testKeyIDA + ".key", "sub.key"}, others...)
	slices.Sort(want)
	if got := dirNames(t, dir); !slices.Equal(got, want) {
		t.Errorf("directory holds %q, want %q", got, want)
	}

	again, err := store.LoadOrCreate(testKeyIDA)
	if err != nil {
		t.Fatalf("LoadOrCreate after Prune: %v", err)
	}
	if again != keptKey {
		t.Error("Prune changed a kept key")
	}
}

func TestInterfaceKeyStore_PruneWithNothingKeptDeletesEveryKey(t *testing.T) {
	dir := keyStoreDir(t)
	store := NewInterfaceKeyStore(dir)
	for _, id := range []string{testKeyIDA, testKeyIDB} {
		if _, err := store.LoadOrCreate(id); err != nil {
			t.Fatalf("LoadOrCreate: %v", err)
		}
	}

	if err := store.Prune(nil); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if got := dirNames(t, dir); len(got) != 0 {
		t.Errorf("directory holds %q, want it empty", got)
	}
}

func TestInterfaceKeyStore_PruneOfAMissingDirectory(t *testing.T) {
	dir := keyStoreDir(t)
	if err := NewInterfaceKeyStore(dir).Prune(nil); err != nil {
		t.Errorf("Prune = %v, want nil", err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Errorf("Prune created the directory: stat error %v", err)
	}
}
