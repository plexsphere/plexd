//go:build windows

package winpipe

import (
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// Listen creates the named pipe called path, guarded by sd, and returns its
// listener wrapped by NewListener. The pipe must not exist yet.
func Listen(path string, sd *windows.SECURITY_DESCRIPTOR) (net.Listener, error) {
	ln, err := (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(path)
	if err != nil {
		return nil, err
	}
	return NewListener(ln), nil
}
