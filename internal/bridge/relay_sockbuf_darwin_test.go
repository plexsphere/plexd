//go:build darwin

package bridge

import (
	"testing"

	"golang.org/x/sys/unix"
)

// maxSockBuf reads kern.ipc.maxsockbuf. macOS lowers a SO_RCVBUF or SO_SNDBUF
// request above it to that limit (sbreserve in xnu's
// bsd/kern/uipc_socket2.c). The limit is 8 MiB by default and less on a host
// with a small mbuf cluster pool: the macos-latest CI runner granted 6 MiB.
func maxSockBuf(t *testing.T) int {
	t.Helper()
	n, err := unix.SysctlUint32("kern.ipc.maxsockbuf")
	if err != nil {
		t.Fatalf("read kern.ipc.maxsockbuf: %v", err)
	}
	return int(n)
}
