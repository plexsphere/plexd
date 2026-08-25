//go:build darwin

package packaging

// The install paths on macOS. A LaunchDaemon plist belongs in
// /Library/LaunchDaemons, keyed by the reverse-DNS label launchd knows the
// daemon by, and launchd writes the daemon's stdout and stderr to a file
// rather than to a journal, so macOS is the one platform with a log directory.

func defaultBinaryPath() string { return "/usr/local/bin/plexd" }

func defaultUnitFilePath() string { return "/Library/LaunchDaemons/com.plexsphere.plexd.plist" }

func defaultLogDir() string { return "/Library/Logs/plexd" }
