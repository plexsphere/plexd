//go:build !windows

package wireguard

import "golang.zx2c4.com/wireguard/conn"

// newDefaultBind returns wireguard-go's default bind, StdNetBind, whose
// sockets the Go net package opens.
func newDefaultBind() conn.Bind {
	return conn.NewDefaultBind()
}
