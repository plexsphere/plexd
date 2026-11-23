// Package nettest builds the network namespaces, packets and utun devices of
// plexd's real-kernel tests. On Linux a test runs its listeners and clients
// in network namespaces joined by veth pairs. On macOS it writes packets
// into a utun device it owns and reads what the host sends out of it. The
// packet builders and the parser serve both.
//
// The package is imported only from tests.
package nettest
