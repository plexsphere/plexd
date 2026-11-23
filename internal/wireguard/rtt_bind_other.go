//go:build !linux && !darwin

package wireguard

import "syscall"

// rttBindToInterface returns no socket control. Windows receives on the
// strong host model by default, which drops a datagram for the mesh IP that
// arrives on another adapter, so binding the socket to the mesh IP is enough.
// The DECISION is at listenRTT.
func rttBindToInterface(string) func(network, address string, c syscall.RawConn) error {
	return nil
}
