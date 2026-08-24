//go:build unix && !darwin

package paths

// The Filesystem Hierarchy Standard layout, unchanged from what plexd shipped
// before it resolved paths per platform.
//
// The constraint is "unix && !darwin" rather than "linux" because every Unix
// but macOS keeps this layout: naming the file paths_linux.go would carry an
// implicit linux constraint and leave freebsd, which has built since #76,
// without a definition.

func configDir() string { return "/etc/plexd" }

func dataDir() string { return "/var/lib/plexd" }

func runDir() string { return "/var/run/plexd" }
