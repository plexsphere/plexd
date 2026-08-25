//go:build unix && !darwin

package packaging

// The install paths on every Unix but macOS, unchanged from what plexd shipped
// before it resolved them per platform.
//
// The constraint is "unix && !darwin" rather than "linux" for the reason
// internal/paths/paths_unix.go gives: naming the file defaults_linux.go would
// carry an implicit linux constraint and leave freebsd without a definition.

func defaultBinaryPath() string { return "/usr/local/bin/plexd" }

func defaultUnitFilePath() string { return "/etc/systemd/system/plexd.service" }

// defaultLogDir is empty because journald keeps the daemon's output.
func defaultLogDir() string { return "" }
