//go:build !darwin

package bridge

import "testing"

// maxSockBuf has no limit to read outside macOS. TestRelay_SocketBuffers
// calls it on macOS alone.
func maxSockBuf(t *testing.T) int {
	t.Helper()
	t.Fatal("kern.ipc.maxsockbuf exists on macOS alone")
	return 0
}
