//go:build darwin

package paths

// macOS keeps per-machine application support data under /Library, not under
// /etc and /var/lib. Runtime state stays in /var/run, which is where a launchd
// daemon puts its socket.
//
// These are the system locations only: plexd does not fall back to
// ~/Library/Application Support when it runs unprivileged. The CLI resolves the
// node API socket without knowing who started the daemon, so a per-user runtime
// directory would send plexd status looking for a socket a root daemon never
// created. An unprivileged run sets --config and data_dir instead.

func configDir() string { return "/Library/Application Support/plexd" }

func dataDir() string { return "/Library/Application Support/plexd/data" }

func runDir() string { return "/var/run/plexd" }
