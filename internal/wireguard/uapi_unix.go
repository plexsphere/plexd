//go:build unix

package wireguard

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

// uapiListen serves the WireGuard UAPI for the named device on the Unix domain
// socket /var/run/wireguard/<name>.sock, so wg(8) and any wgctrl reader can
// query the in-process device.
//
// ipc.UAPIOpen creates the socket and returns its *os.File; ipc.UAPIListen
// wraps that file in a net.Listener with its own duplicated descriptor, so the
// file returned by UAPIOpen is closed once the listener holds it, whether or
// not UAPIListen succeeded.
func uapiListen(name string) (net.Listener, error) {
	f, err := ipc.UAPIOpen(name)
	if err != nil {
		return nil, err
	}
	l, err := ipc.UAPIListen(name, f)
	f.Close()
	return l, err
}
