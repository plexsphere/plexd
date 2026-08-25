//go:build windows

package wireguard

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

// uapiListen serves the WireGuard UAPI for the named device on the named pipe
// \\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>, so wg(8) and any
// wgctrl reader can query the in-process device. The Windows ipc.UAPIListen
// creates the pipe itself and needs no file handle.
func uapiListen(name string) (net.Listener, error) {
	return ipc.UAPIListen(name)
}
