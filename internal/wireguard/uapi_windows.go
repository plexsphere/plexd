//go:build windows

package wireguard

import (
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// uapiPipePrefix is where wg(8) and any wgctrl reader look for a userspace
// WireGuard device on Windows.
const uapiPipePrefix = `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\`

// uapiSecurityDescriptor is wireguard-go's own UAPI descriptor with its owner
// clause removed: full access for LocalSystem and Administrators, and a high
// mandatory label that keeps lower-integrity processes out. The access it
// grants is exactly what ipc.UAPIListen grants.
//
// wireguard-go's descriptor opens with O:SY, assigning the pipe to LocalSystem.
// A process may only name an owner its own token carries, so that succeeds for
// the service and fails for an elevated Administrator with ERROR_INVALID_OWNER
// ("This security ID may not be assigned as the owner of this object"), which
// takes the whole interface down with it. Leaving the owner out makes the
// creator the owner, which is LocalSystem when plexd runs as the service.
//
// The one consequence is for wgctrl, whose client refuses a pipe not owned by
// LocalSystem: `wg show` still works against the service, but not against a
// plexd started by hand from an elevated console.
const uapiSecurityDescriptor = `D:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)`

// uapiListen serves the WireGuard UAPI for the named device on its named pipe,
// so wg(8) and any wgctrl reader can query the in-process device.
func uapiListen(name string) (net.Listener, error) {
	sd, err := windows.SecurityDescriptorFromString(uapiSecurityDescriptor)
	if err != nil {
		return nil, err
	}
	return (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(uapiPipePrefix + name)
}
