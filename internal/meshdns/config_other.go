//go:build !windows

package meshdns

// DefaultListenPort is the port the resolver listens on when listen_port is
// not set. It is unprivileged, so plexd.service needs no
// CAP_NET_BIND_SERVICE, and systemd-resolved 246 and newer accept a port
// beside the server address of a link.
const DefaultListenPort = 5354
