//go:build windows

package meshdns

// DefaultListenPort is the port the resolver listens on when listen_port is
// not set. On Windows it is 53: a Name Resolution Policy Table rule names its
// server by address only, without a port, and the DNS Client sends every
// query to port 53. Windows has no privileged ports, so the service needs no
// extra right to bind it.
const DefaultListenPort = 53
