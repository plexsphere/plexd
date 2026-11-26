//go:build !linux

package bridge

import "net"

// forceRelayBuffers does nothing outside Linux, the only platform with
// options that pass the host's limit on buffer sizes. macOS lowers a request
// above kern.ipc.maxsockbuf to that limit, 8 MiB by default and less on a
// host with little memory, so a socket there keeps the smaller of
// relaySocketBuffer and the limit.
func forceRelayBuffers(*net.UDPConn) error { return nil }
