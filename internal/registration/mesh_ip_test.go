package registration

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const newMeshIP = "100.64.0.9"

// keyFiles are the files of the identity group CommitMeshIP must not write.
var keyFiles = []string{"private_key", "node_secret_key", "signing_public_key"}

// statFile returns the FileInfo of name in dir with its file identity read
// now. On Windows os.Stat keeps only the path and os.SameFile reads the
// volume and file index on its first call, so an info compared only after
// a rewrite would describe the new file and always match. Comparing the
// info with itself reads the identity at stat time.
func statFile(t *testing.T, dir, name string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	if !os.SameFile(info, info) {
		t.Fatalf("read the file identity of %s", name)
	}
	return info
}

// decodeIdentityJSON reads identity.json in dir as a generic object, so a
// comparison covers every member on disk, not only the ones NodeIdentity
// knows.
func decodeIdentityJSON(t *testing.T, dir string) map[string]any {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal(readFile(t, dir, "identity.json"), &raw); err != nil {
		t.Fatalf("decode identity.json: %v", err)
	}
	return raw
}

func TestCommitMeshIP_RewritesOnlyMeshIP(t *testing.T) {
	dir := t.TempDir()
	saved := saveSigningKeyIdentity(t, dir)
	before := decodeIdentityJSON(t, dir)
	keyData := map[string][]byte{}
	keyInfo := map[string]os.FileInfo{}
	for _, name := range keyFiles {
		keyData[name] = readFile(t, dir, name)
		keyInfo[name] = statFile(t, dir, name)
	}

	if err := CommitMeshIP(dir, newMeshIP); err != nil {
		t.Fatalf("CommitMeshIP: %v", err)
	}

	// identity.json moves in mesh_ip alone; last_rotation and every other
	// member stay as they were saved.
	want := before
	want["mesh_ip"] = newMeshIP
	if got := decodeIdentityJSON(t, dir); !reflect.DeepEqual(got, want) {
		t.Errorf("identity.json after commit = %v, want %v", got, want)
	}

	got, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	wantID := *saved
	wantID.MeshIP = newMeshIP
	if !reflect.DeepEqual(*got, wantID) {
		t.Errorf("identity after commit = %+v, want %+v", *got, wantID)
	}

	// The key files are neither changed nor written again: a rewrite through
	// the atomic rename would leave another file in their place.
	for _, name := range keyFiles {
		if !bytes.Equal(readFile(t, dir, name), keyData[name]) {
			t.Errorf("%s changed", name)
		}
		if !os.SameFile(statFile(t, dir, name), keyInfo[name]) {
			t.Errorf("%s was written again", name)
		}
	}

	if runtime.GOOS != "windows" {
		for _, name := range append([]string{"identity.json"}, keyFiles...) {
			if perm := statFile(t, dir, name).Mode().Perm(); perm != 0600 {
				t.Errorf("%s permissions = %o, want 0600", name, perm)
			}
		}
	}
}

func TestCommitMeshIP_EmptyAddressWritesNothing(t *testing.T) {
	dir := t.TempDir()
	saveSigningKeyIdentity(t, dir)
	identityJSON := readFile(t, dir, "identity.json")
	identityInfo := statFile(t, dir, "identity.json")

	err := CommitMeshIP(dir, "")
	if err == nil || !strings.HasPrefix(err.Error(), "registration: commit mesh ip:") {
		t.Fatalf("error = %v, want prefix %q", err, "registration: commit mesh ip:")
	}
	if !bytes.Equal(readFile(t, dir, "identity.json"), identityJSON) {
		t.Error("identity.json changed after an empty address")
	}
	if !os.SameFile(statFile(t, dir, "identity.json"), identityInfo) {
		t.Error("identity.json was written again after an empty address")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 4 {
		t.Errorf("data dir holds %d entries, want the 4 files SaveIdentity wrote", len(entries))
	}
}

func TestCommitMeshIP_NotRegistered(t *testing.T) {
	dir := t.TempDir()

	err := CommitMeshIP(dir, newMeshIP)
	if !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("error = %v, want one wrapping ErrNotRegistered", err)
	}
	if !strings.HasPrefix(err.Error(), "registration: commit mesh ip:") {
		t.Errorf("error = %v, want prefix %q", err, "registration: commit mesh ip:")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("data dir holds %d entries, want none written", len(entries))
	}
}

func TestCommitMeshIP_UnwritableDirChangesNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions, so the write cannot fail")
	}
	dir := t.TempDir()
	saveSigningKeyIdentity(t, dir)
	identityJSON := readFile(t, dir, "identity.json")

	// Restore the mode so t.TempDir cleanup can remove the tree.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("chmod 0500: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	err := CommitMeshIP(dir, newMeshIP)
	if err == nil || !strings.HasPrefix(err.Error(), "registration: commit mesh ip:") {
		t.Fatalf("error = %v, want prefix %q", err, "registration: commit mesh ip:")
	}
	if !bytes.Equal(readFile(t, dir, "identity.json"), identityJSON) {
		t.Error("identity.json changed after a failed commit")
	}
}
