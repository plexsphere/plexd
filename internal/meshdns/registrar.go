package meshdns

import (
	"context"
	"errors"
	"net/netip"
	"slices"
)

// ErrUnavailable reports that the host has no system resolver plexd can
// register with, such as a Linux host without systemd-resolved or with one
// older than 246, or a macOS host without /usr/sbin/scutil. The resolver
// still answers on its listen address, and the manager logs that once
// instead of warning on every pull.
var ErrUnavailable = errors.New("meshdns: no usable system resolver")

// revertShare divides the time left on Apply's context to give the share the
// steps hold back for the revert after a failure. With 5 the steps end a
// fifth of that time early, a second of the manager's five, so a step that
// runs out its budget still leaves the revert time to reach the system
// resolver.
const revertShare = 5

// Registration is what plexd asks the system resolver to send to the mesh
// resolver: the queries for RoutingDomains and, through the search domain,
// the bare host names of the node's own Project, and with DefaultRoute every
// name no other domain claims. On Linux it is bound to the mesh interface
// only.
type Registration struct {
	// Interface is the name of the mesh interface the registration is bound
	// to, so the system resolver sends the queries through that link. On
	// macOS a dynamic-store entry is bound to no interface, and the name
	// serves the log lines only.
	Interface string
	// Server is the address and port the mesh resolver listens on.
	Server netip.AddrPort
	// SearchDomain is the zone of the node's own Project, or empty when the
	// node has none. A search domain is also a routing domain, so it is not
	// listed again in RoutingDomains.
	SearchDomain string
	// RoutingDomains are the zones, reverse zones and forward zones the
	// system resolver sends to Server, without the search domain.
	RoutingDomains []string
	// DefaultRoute makes Server the host's default resolver, so the system
	// resolver sends it every name that no other domain matches: on Linux
	// the link becomes the host's default DNS route, and on macOS a
	// default-resolver entry joins the others. It is set while the
	// forwarding table has a catch-all resolver.
	DefaultRoute bool
}

// Empty reports whether the registration names no domain at all and does
// not ask for the default resolver. Applying one would route nothing to the
// mesh resolver, so the manager reverts instead.
func (r Registration) Empty() bool {
	return r.SearchDomain == "" && len(r.RoutingDomains) == 0 && !r.DefaultRoute
}

// Equal reports whether r and o register the same thing, comparing every
// field and the routing domains in order. The manager compares the wanted
// registration with the applied one, so a pull that changes no zone issues no
// call to the system resolver.
func (r Registration) Equal(o Registration) bool {
	return r.Interface == o.Interface &&
		r.Server == o.Server &&
		r.SearchDomain == o.SearchDomain &&
		slices.Equal(r.RoutingDomains, o.RoutingDomains) &&
		r.DefaultRoute == o.DefaultRoute
}

// Registrar is the seam to the operating system's resolver. Each platform
// supplies its own, and tests replace it with a recording fake, so no test
// changes the resolver settings of the host it runs on.
type Registrar interface {
	// Apply registers reg, replacing whatever plexd registered before. It
	// returns an error wrapping ErrUnavailable when the host has no usable
	// system resolver.
	Apply(ctx context.Context, reg Registration) error
	// Revert removes every resolver setting plexd made for the interface
	// named iface; a registrar whose settings are bound to no interface, as
	// on macOS, removes all of them whatever iface is. It returns nil when
	// there is nothing to remove, which includes an interface or a system
	// resolver that is gone, so a shutdown on a host without one does not
	// report a failure.
	Revert(ctx context.Context, iface string) error
	// Name names the system resolver the registrar writes to, as the
	// manager's log lines name it: systemd-resolved on Linux, configd on
	// macOS.
	Name() string
}
