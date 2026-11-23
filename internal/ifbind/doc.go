// Package ifbind binds a socket to a network interface. On Linux the kernel
// then hands the socket only what arrives on that interface. On macOS the
// binding confines what the socket sends to that interface and does not
// filter what it receives. The round-trip probe and the tcp session
// listener use it to bind their sockets to the mesh interface.
package ifbind
