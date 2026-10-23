//go:build darwin

package tunnel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ptySlavePrefix is where macOS names the slave of a pty.
const ptySlavePrefix = "/dev/ttys"

// ttyOwnerCommand prints the owner uid of the file it is given (BSD stat).
const ttyOwnerCommand = "stat -f %u"

// waitGone polls until pid no longer names a process. An orphan is reparented
// to launchd, which reaps it.
func waitGone(t *testing.T, pid int, within time.Duration) {
	t.Helper()
	waitForCondition(t, within, func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	})
}

// dsclRecord is a record the way dscl -plist -read prints it.
func dsclRecord(entries string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
` + entries + `</dict>
</plist>
`)
}

// rootRecord is what dscl prints for root, two homes and two names included.
const rootRecord = `	<key>dsAttrTypeStandard:NFSHomeDirectory</key>
	<array>
		<string>/var/root</string>
		<string>/private/var/root</string>
	</array>
	<key>dsAttrTypeStandard:PrimaryGroupID</key>
	<array>
		<string>0</string>
	</array>
	<key>dsAttrTypeStandard:RecordName</key>
	<array>
		<string>root</string>
		<string>BUILTIN\Local System</string>
	</array>
	<key>dsAttrTypeStandard:UniqueID</key>
	<array>
		<string>0</string>
	</array>
	<key>dsAttrTypeStandard:UserShell</key>
	<array>
		<string>/bin/sh</string>
	</array>
`

func TestParseDirectoryUser(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		u, err := parseDirectoryUser("root", dsclRecord(rootRecord))
		if err != nil {
			t.Fatalf("parseDirectoryUser() error: %v", err)
		}
		if u.name != "root" || u.uid != 0 || u.gid != 0 || u.home != "/var/root" || u.shell != "/bin/sh" {
			t.Errorf("parseDirectoryUser() = %+v, want root, 0, 0, /var/root, /bin/sh", u)
		}
	})

	t.Run("no shell and no home", func(t *testing.T) {
		u, err := parseDirectoryUser("x", dsclRecord(`	<key>dsAttrTypeStandard:PrimaryGroupID</key>
	<array>
		<string>20</string>
	</array>
	<key>dsAttrTypeStandard:RecordName</key>
	<array>
		<string>x</string>
	</array>
	<key>dsAttrTypeStandard:UniqueID</key>
	<array>
		<string>501</string>
	</array>
`))
		if err != nil {
			t.Fatalf("parseDirectoryUser() error: %v", err)
		}
		if u.uid != 501 || u.gid != 20 || u.shell != "/bin/sh" || u.home != "" {
			t.Errorf("parseDirectoryUser() = %+v, want 501, 20, shell /bin/sh, no home", u)
		}
	})

	// dscl finds root as ROOT or by its alias as well; only the record's own
	// name is that account.
	for _, name := range []string{"ROOT", `BUILTIN\Local System`} {
		want := fmt.Sprintf("user %q does not exist on this node", name)
		if _, err := parseDirectoryUser(name, dsclRecord(rootRecord)); err == nil || err.Error() != want {
			t.Errorf("parseDirectoryUser(%q) error = %v, want %q", name, err, want)
		}
	}

	const malformed = `user "x" has a malformed record in the local directory`
	for _, tc := range []struct {
		name  string
		plist []byte
	}{
		{"empty", nil},
		{"not xml", []byte("not xml")},
		{"no UniqueID", dsclRecord(strings.Replace(rootRecord, "dsAttrTypeStandard:UniqueID", "dsAttrTypeStandard:Comment", 1))},
		{"PrimaryGroupID that is no number", dsclRecord(strings.Replace(rootRecord, "<string>0</string>\n\t</array>\n\t<key>dsAttrTypeStandard:RecordName", "<string>staff</string>\n\t</array>\n\t<key>dsAttrTypeStandard:RecordName", 1))},
		{"no RecordName", dsclRecord(strings.Replace(rootRecord, "dsAttrTypeStandard:RecordName", "dsAttrTypeStandard:Comment", 1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseDirectoryUser("x", tc.plist); err == nil || err.Error() != malformed {
				t.Errorf("parseDirectoryUser() error = %v, want %q", err, malformed)
			}
		})
	}
}

// useDsclPath points the helper at another dscl until the test ends.
func useDsclPath(t *testing.T, path string) {
	t.Helper()
	prev := dsclPath
	dsclPath = path
	t.Cleanup(func() { dsclPath = prev })
}

func TestLookupLocalDirectoryUser(t *testing.T) {
	t.Run("root from the real local directory", func(t *testing.T) {
		u, err := lookupLocalDirectoryUser("root")
		if err != nil {
			t.Fatalf("lookupLocalDirectoryUser(root) error: %v", err)
		}
		if u.uid != 0 || u.gid != 0 || u.home != "/var/root" || u.shell == "" || len(u.groups) == 0 {
			t.Errorf("lookupLocalDirectoryUser(root) = %+v, want uid 0, gid 0, /var/root, a shell and groups", u)
		}
	})

	t.Run("absent user", func(t *testing.T) {
		const want = `user "plexd-no-such-user" does not exist on this node`
		if _, err := lookupLocalDirectoryUser("plexd-no-such-user"); err == nil || err.Error() != want {
			t.Errorf("lookupLocalDirectoryUser() error = %v, want %q", err, want)
		}
	})

	// dscl answers for ROOT with root's record, and for www with _www's.
	t.Run("another case or an alias", func(t *testing.T) {
		for _, name := range []string{"ROOT", "www"} {
			want := `user "` + name + `" does not exist on this node`
			if _, err := lookupLocalDirectoryUser(name); err == nil || err.Error() != want {
				t.Errorf("lookupLocalDirectoryUser(%q) error = %v, want %q", name, err, want)
			}
		}
	})

	// dscl resolves the record path, so a name that could leave /Users is
	// refused before dscl runs: with no dscl at all, the refusal is still the
	// name's, not an exec error.
	t.Run("names that could leave /Users", func(t *testing.T) {
		useDsclPath(t, filepath.Join(t.TempDir(), "no-dscl"))
		for _, name := range []string{"", ".", "..", "../Groups/admin"} {
			want := `user "` + name + `" is not a valid local account name`
			if _, err := lookupLocalDirectoryUser(name); err == nil || err.Error() != want {
				t.Errorf("lookupLocalDirectoryUser(%q) error = %v, want %q", name, err, want)
			}
		}
	})

	t.Run("dscl that cannot run", func(t *testing.T) {
		useDsclPath(t, filepath.Join(t.TempDir(), "no-dscl"))
		const want = `read user "root" from the local directory: `
		if _, err := lookupLocalDirectoryUser("root"); err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("lookupLocalDirectoryUser() error = %v, want prefix %q", err, want)
		}
	})
}

func TestCheckPTYSlave(t *testing.T) {
	master, slave := openTestPTY(t)
	if err := checkPTYSlave(slave); err != nil {
		t.Errorf("checkPTYSlave(%s) error: %v", slave.Name(), err)
	}

	regular, err := os.Create(filepath.Join(t.TempDir(), "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()

	const want = "the pty descriptor is not a pseudo-terminal slave"
	for _, f := range []*os.File{regular, devNull, master} {
		if err := checkPTYSlave(f); err == nil || err.Error() != want {
			t.Errorf("checkPTYSlave(%s) error = %v, want %q", f.Name(), err, want)
		}
	}
}
