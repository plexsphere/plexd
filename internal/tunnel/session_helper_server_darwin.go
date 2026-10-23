//go:build darwin

package tunnel

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// loginUserLookup resolves the login user of a request. It is a variable so
// tests can point it at a passwd fixture.
var loginUserLookup = lookupLocalDirectoryUser

// dsclPath is the directory service command the helper reads accounts with.
// It is a variable so tests can make it fail.
var dsclPath = "/usr/bin/dscl"

// maxSupplementaryGroups is the most supplementary groups a process the helper
// starts gets: macOS's NGROUPS_MAX. An administrator is a member of nearly
// that many groups already.
const maxSupplementaryGroups = 16

// lookupLocalDirectoryUser resolves name from the local directory node, the
// way dscl reads it. Supplementary groups come from os/user, which asks
// libSystem's getgrouplist; the primary group stands in when that fails.
//
// DECISION: the account is read with dscl from the local node ".", not with
// os/user. Real accounts on a Mac live in the local directory rather than in
// /etc/passwd, and os/user's getpwnam_r also answers for directory-service
// accounts (Active Directory, Open Directory), which mediated sessions do not
// serve, and carries no login shell. A network account the local node does not
// hold is therefore "not found". dscl also finds a record by any of its names,
// case-insensitively (ROOT, "BUILTIN\Local System" and root are one record), so
// the name must be the record's first RecordName exactly, as an /etc/passwd
// entry would have to match it on Linux.
func lookupLocalDirectoryUser(name string) (loginUser, error) {
	// dscl resolves the record path, so /Users/../Groups/admin would read a
	// group. A name that could leave /Users is refused before anything runs.
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return loginUser{}, fmt.Errorf("user %q is not a valid local account name", name)
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionHelperIOTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, dsclPath, "-plist", ".", "-read", "/Users/"+name,
		"RecordName", "UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		var exitErr *exec.ExitError
		switch {
		case errors.As(err, &exitErr) && strings.Contains(msg, "eDSRecordNotFound"):
			return loginUser{}, fmt.Errorf("user %q does not exist on this node", name)
		case msg != "":
			return loginUser{}, fmt.Errorf("read user %q from the local directory: %w: %s", name, err, msg)
		default:
			return loginUser{}, fmt.Errorf("read user %q from the local directory: %w", name, err)
		}
	}

	u, err := parseDirectoryUser(name, stdout.Bytes())
	if err != nil {
		return loginUser{}, err
	}
	u.groups = supplementaryGroups(strconv.FormatUint(uint64(u.uid), 10), u.gid)
	return u, nil
}

// directoryRecord is the property list dscl -plist prints for one record: a
// dict whose keys alternate with arrays of string values.
type directoryRecord struct {
	XMLName xml.Name `xml:"plist"`
	Dict    struct {
		Keys   []string `xml:"key"`
		Values []struct {
			Strings []string `xml:"string"`
		} `xml:"array"`
	} `xml:"dict"`
}

// parseDirectoryUser reads the account named name from plist, the output of
// dscl -plist -read. A record whose first RecordName is not name is another
// account's, found through an alias or another case. A missing UserShell means
// /bin/sh, as an empty shell field does in /etc/passwd; a missing home leaves
// the process in /.
func parseDirectoryUser(name string, plist []byte) (loginUser, error) {
	malformed := fmt.Errorf("user %q has a malformed record in the local directory", name)

	var rec directoryRecord
	if err := xml.Unmarshal(plist, &rec); err != nil || len(rec.Dict.Keys) != len(rec.Dict.Values) {
		return loginUser{}, malformed
	}
	attrs := make(map[string]string, len(rec.Dict.Keys))
	for i, key := range rec.Dict.Keys {
		// root carries two homes and two names; the first one is the
		// account's.
		if values := rec.Dict.Values[i].Strings; len(values) > 0 {
			attrs[strings.TrimPrefix(key, "dsAttrTypeStandard:")] = values[0]
		}
	}

	uid, uidErr := strconv.ParseUint(attrs["UniqueID"], 10, 32)
	gid, gidErr := strconv.ParseUint(attrs["PrimaryGroupID"], 10, 32)
	recordName, named := attrs["RecordName"]
	if uidErr != nil || gidErr != nil || !named {
		return loginUser{}, malformed
	}
	if recordName != name {
		return loginUser{}, fmt.Errorf("user %q does not exist on this node", name)
	}
	u := loginUser{name: name, uid: uint32(uid), gid: uint32(gid), home: attrs["NFSHomeDirectory"], shell: attrs["UserShell"]}
	if u.shell == "" {
		u.shell = "/bin/sh"
	}
	return u, nil
}

// checkPTYSlave refuses a descriptor that is not a pseudo-terminal slave: a
// character device that is the device node /dev/ttysNNN of its own minor
// number. XNU picks the pty majors when it registers the devices, so none is
// hard-coded.
func checkPTYSlave(f *os.File) error {
	notSlave := errors.New("the pty descriptor is not a pseudo-terminal slave")

	var st unix.Stat_t
	if err := controlFile(f, func(fd int) error { return unix.Fstat(fd, &st) }); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return notSlave
	}
	var node unix.Stat_t
	path := fmt.Sprintf("/dev/ttys%03d", unix.Minor(uint64(st.Rdev)))
	if err := unix.Stat(path, &node); err != nil || node.Mode&unix.S_IFMT != unix.S_IFCHR || node.Rdev != st.Rdev {
		return notSlave
	}
	return nil
}
