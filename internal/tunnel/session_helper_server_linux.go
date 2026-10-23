//go:build linux

package tunnel

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// loginUserLookup resolves the login user of a request. It is a variable so
// tests can point it at a passwd fixture.
var loginUserLookup = func(name string) (loginUser, error) {
	return lookupPasswdUser("/etc/passwd", name)
}

// maxSupplementaryGroups is the most supplementary groups a process the helper
// starts gets: Linux's NGROUPS_MAX, which no account reaches.
const maxSupplementaryGroups = 65536

// checkPTYSlave refuses a descriptor that is not a pseudo-terminal slave: a
// character device of the Unix98 pty slave majors, 136 to 143, on devpts.
func checkPTYSlave(f *os.File) error {
	var st unix.Stat_t
	var fs unix.Statfs_t
	err := controlFile(f, func(fd int) error {
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		return unix.Fstatfs(fd, &fs)
	})
	major := unix.Major(uint64(st.Rdev))
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || fs.Type != unix.DEVPTS_SUPER_MAGIC || major < 136 || major > 143 {
		return errors.New("the pty descriptor is not a pseudo-terminal slave")
	}
	return nil
}
