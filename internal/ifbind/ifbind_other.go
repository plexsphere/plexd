//go:build !linux && !darwin

package ifbind

import "syscall"

// Control returns no socket control, for every iface, so the socket is bound
// to its address alone. Windows receives on the strong host model by
// default, which drops a packet for an address of the host that arrives on
// another adapter, so binding a socket to the mesh IP is enough there.
func Control(string) func(network, address string, c syscall.RawConn) error {
	return nil
}
