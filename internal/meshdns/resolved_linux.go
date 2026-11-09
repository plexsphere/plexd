//go:build linux

package meshdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// The object and interface of systemd-resolved that own the per-link
// resolver settings plexd writes.
const (
	resolvedBusName   = "org.freedesktop.resolve1"
	resolvedPath      = dbus.ObjectPath("/org/freedesktop/resolve1")
	resolvedInterface = "org.freedesktop.resolve1.Manager"
)

// methodRevertLink clears every per-link setting at once. Revert calls it, and
// so does a failed Apply, which must not leave half a registration behind.
const methodRevertLink = "RevertLink"

// Apply reads the Manager property DNSEx before it changes anything. It
// arrived in systemd-resolved 246 together with SetLinkDNSEx, so a failed read
// tells an older systemd-resolved apart without a write: 240 to 245 would
// accept steps 1 to 6 and refuse only step 7.
const (
	methodPropertiesGet = "org.freedesktop.DBus.Properties.Get"
	propertyDNSEx       = "DNSEx"
)

// revertShare divides the time left on Apply's context to give the share the
// steps hold back for the revert after a failure. With 5 the steps end a
// fifth of that time early, a second of the manager's five, so a step that
// runs out its budget still leaves the revert time to reach systemd-resolved.
const revertShare = 5

// The D-Bus error names the registrar tells apart. The first three say that
// nothing answers for systemd-resolved: the bus daemon answers ServiceUnknown
// or NameHasNoOwner when no process owns the name, and systemd answers
// NoSuchUnit when bus activation finds no unit it may start for it.
// UnknownProperty, UnknownInterface and InvalidArgs are refusals of the probe.
const (
	dbusErrServiceUnknown   = "org.freedesktop.DBus.Error.ServiceUnknown"
	dbusErrNameHasNoOwner   = "org.freedesktop.DBus.Error.NameHasNoOwner"
	dbusErrNoSuchUnit       = "org.freedesktop.systemd1.NoSuchUnit"
	dbusErrUnknownMethod    = "org.freedesktop.DBus.Error.UnknownMethod"
	dbusErrUnknownProperty  = "org.freedesktop.DBus.Error.UnknownProperty"
	dbusErrUnknownInterface = "org.freedesktop.DBus.Error.UnknownInterface"
	dbusErrInvalidArgs      = "org.freedesktop.DBus.Error.InvalidArgs"
	dbusErrNoSuchLink       = "org.freedesktop.resolve1.NoSuchLink"
)

// errNoSuchInterface reports that no interface carries the name. It is told
// apart from an interface table that could not be read, because Revert treats
// a missing interface as nothing to remove and an unreadable table as a
// failure.
var errNoSuchInterface = errors.New("no such network interface")

// caller is the seam to systemd-resolved's manager object, so unit tests
// replace the system bus with a recording fake and no test changes the
// resolver settings of the host it runs on.
type caller interface {
	// call invokes method of org.freedesktop.resolve1.Manager with args and
	// returns the error of the reply.
	call(ctx context.Context, method string, args ...any) error
	// getProperty reads property of org.freedesktop.resolve1.Manager and
	// returns the error of the reply. The value is dropped, because Apply
	// only asks whether the property exists.
	getProperty(ctx context.Context, property string) error
}

// resolvedObject is the caller on a real system bus connection. Every call
// carries FlagNoAutoStart, so the bus daemon never starts a stopped
// systemd-resolved on plexd's behalf: an operator who stopped it keeps it
// stopped, and the daemon answers NameHasNoOwner instead, which counts as not
// running. Without the flag, the bus daemon on a host where the activation
// cannot succeed, such as a container without systemd, answers
// Spawn.ChildExited, which is no name the registrar knows and would take the
// Warn path.
type resolvedObject struct {
	obj dbus.BusObject
}

func (o resolvedObject) call(ctx context.Context, method string, args ...any) error {
	return o.obj.CallWithContext(ctx, resolvedInterface+"."+method, dbus.FlagNoAutoStart, args...).Err
}

// getProperty does not use BusObject.GetProperty, which takes no context and
// sends with auto-start allowed.
func (o resolvedObject) getProperty(ctx context.Context, property string) error {
	return o.obj.CallWithContext(ctx, methodPropertiesGet, dbus.FlagNoAutoStart, resolvedInterface, property).Err
}

// connectResolved opens a private connection to the system bus. The
// connection is bound to ctx, which bounds the Auth and Hello handshake:
// godbus sends Hello without a context of its own, and only the connection
// closing when ctx ends stops a bus daemon that never answers it. The same
// binding closes the connection once ctx ends, so Apply runs its steps under a
// shorter deadline and keeps ctx for the revert.
func connectResolved(ctx context.Context) (caller, func() error, error) {
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return nil, nil, err
	}
	return resolvedObject{obj: conn.Object(resolvedBusName, resolvedPath)}, conn.Close, nil
}

// linkDomain is one entry of SetLinkDomains, D-Bus signature (sb). The flag
// marks a routing-only domain: systemd-resolved sends the names under it to
// the link but does not append it to bare host names.
type linkDomain struct {
	Domain      string
	RoutingOnly bool
}

// linkDNSServer is one entry of SetLinkDNSEx, D-Bus signature (iayqs). It is
// the only setter that takes a port, which the resolver needs because it
// listens on an unprivileged one.
type linkDNSServer struct {
	Family  int32
	Address []byte
	Port    uint16
	Name    string
}

// resolvedStep is one call of Apply.
type resolvedStep struct {
	method string
	args   []any
	// tellsVersion marks the methods an older systemd-resolved lacks:
	// SetLinkDefaultRoute arrived in 240 and SetLinkDNSEx in 246, so an
	// UnknownMethod answer from either says the host's systemd-resolved is too
	// old to use rather than broken.
	tellsVersion bool
}

// ResolvedRegistrar registers the mesh resolver with systemd-resolved over
// D-Bus, for the mesh interface only. It holds no connection between calls:
// systemd-resolved and the bus daemon may start, stop or restart between two
// pulls, and a connection kept open would need a goroutine and reconnect logic
// of its own for a handful of calls per change.
type ResolvedRegistrar struct {
	logger *slog.Logger
	// connect opens the connection one Apply or Revert uses and returns the
	// function that closes it.
	connect func(ctx context.Context) (caller, func() error, error)
	// interfaces lists the host's interfaces. It is a listing rather than
	// net.InterfaceByName, which reports an unreadable interface table (a
	// netlink dump that answers ENOBUFS or EMFILE) the same way as an absent
	// name.
	interfaces func() ([]net.Interface, error)
}

// NewResolvedRegistrar returns the Registrar for Linux hosts, which talks to
// systemd-resolved on the system bus.
func NewResolvedRegistrar(logger *slog.Logger) *ResolvedRegistrar {
	if logger == nil {
		logger = slog.Default()
	}
	return &ResolvedRegistrar{
		logger:     logger.With("component", "meshdns"),
		connect:    connectResolved,
		interfaces: net.Interfaces,
	}
}

// Apply registers reg on its interface. It first reads the Manager property
// DNSEx, so a systemd-resolved older than 246 is told apart before anything on
// the link changes; a failed read is followed by no other call. Then it makes
// seven calls. The default-route flag goes first, so the link never answers
// names outside its domains, and the server goes last, so a failure halfway
// leaves a link without a server, which systemd-resolved never asks. A
// failure after the first step reverts the link, ignoring the result, so the
// next Apply starts from a clean link.
//
// When ctx has a deadline, the probe and the steps run under one that is a
// fifth of the remaining time earlier, and the revert runs under ctx. godbus
// sends no call whose context is done, and it closes a connection once the
// context it was opened with ends, so a revert sent after a step ran out ctx
// would never leave plexd. A ctx that was cancelled rather than timed out
// sends no revert either. That only happens while plexd stops, and the
// drain's Shutdown then reverts the link with a context of its own.
//
// The error wraps ErrUnavailable when the bus or systemd-resolved is missing
// or older than 246.
func (r *ResolvedRegistrar) Apply(ctx context.Context, reg Registration) error {
	index, err := r.linkIndex(reg.Interface)
	if err != nil {
		return fmt.Errorf("meshdns: resolved: interface %s: %w", reg.Interface, err)
	}
	bus, closeBus, err := r.connect(ctx)
	if err != nil {
		r.logger.Debug("system bus unreachable", "error", err)
		return fmt.Errorf("meshdns: resolved: systemd-resolved is not running: %w", ErrUnavailable)
	}
	defer func() { _ = closeBus() }()

	stepCtx := ctx
	if deadline, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		stepCtx, cancel = context.WithDeadline(ctx, deadline.Add(-time.Until(deadline)/revertShare))
		defer cancel()
	}

	if err := bus.getProperty(stepCtx, propertyDNSEx); err != nil {
		return r.probeError(err)
	}
	for i, step := range applySteps(index, reg) {
		err := bus.call(stepCtx, step.method, step.args...)
		if err == nil {
			continue
		}
		if i > 0 {
			if revertErr := bus.call(ctx, methodRevertLink, index); revertErr != nil {
				r.logger.Debug("revert after a failed registration failed",
					"interface", reg.Interface, "error", revertErr)
			}
		}
		return r.applyError(step, err)
	}
	return nil
}

// probeError maps a failed read of DNSEx to the error Apply returns. Each of
// UnknownProperty, UnknownInterface, UnknownMethod and InvalidArgs says the
// property is missing, so systemd-resolved is older than 246; 245 answers
// UnknownProperty. Any other error, a deadline among them, names the property.
func (r *ResolvedRegistrar) probeError(err error) error {
	switch name := dbusErrorName(err); {
	case unavailableName(name):
		r.logger.Debug("systemd-resolved not usable", "property", propertyDNSEx, "error", err)
		return fmt.Errorf("meshdns: resolved: systemd-resolved is not running: %w", ErrUnavailable)
	case name == dbusErrUnknownProperty, name == dbusErrUnknownInterface,
		name == dbusErrUnknownMethod, name == dbusErrInvalidArgs:
		r.logger.Debug("systemd-resolved not usable", "property", propertyDNSEx, "error", err)
		return fmt.Errorf("meshdns: resolved: systemd-resolved is older than 246: %w", ErrUnavailable)
	default:
		return fmt.Errorf("meshdns: resolved: %s: %w", propertyDNSEx, err)
	}
}

// applySteps returns the calls of Apply in their order. The search domain is
// listed once, as a search domain, because it routes the names under it as
// well and systemd-resolved keeps one entry for a domain listed twice.
func applySteps(index int32, reg Registration) []resolvedStep {
	domains := make([]linkDomain, 0, len(reg.RoutingDomains)+1)
	if reg.SearchDomain != "" {
		domains = append(domains, linkDomain{Domain: reg.SearchDomain, RoutingOnly: false})
	}
	for _, d := range reg.RoutingDomains {
		domains = append(domains, linkDomain{Domain: d, RoutingOnly: true})
	}

	addr := reg.Server.Addr().Unmap()
	server := linkDNSServer{Port: reg.Server.Port()}
	if addr.Is4() {
		b := addr.As4()
		server.Family = unix.AF_INET
		server.Address = b[:]
	} else {
		b := addr.As16()
		server.Family = unix.AF_INET6
		server.Address = b[:]
	}

	// DNSSEC is off because a private zone such as lab.internal has no chain
	// of trust, and the other transports are off because the resolver speaks
	// plain DNS on the mesh only.
	return []resolvedStep{
		{method: "SetLinkDefaultRoute", args: []any{index, false}, tellsVersion: true},
		{method: "SetLinkDomains", args: []any{index, domains}},
		{method: "SetLinkDNSSEC", args: []any{index, "no"}},
		{method: "SetLinkDNSOverTLS", args: []any{index, "no"}},
		{method: "SetLinkLLMNR", args: []any{index, "no"}},
		{method: "SetLinkMulticastDNS", args: []any{index, "no"}},
		{method: "SetLinkDNSEx", args: []any{index, []linkDNSServer{server}}, tellsVersion: true},
	}
}

// applyError maps the failure of step to the error Apply returns. Only the
// unavailable cases wrap ErrUnavailable, which the manager logs once at Info;
// every other error keeps the original in its chain and names the method, so
// the Warn line says which setting systemd-resolved refused.
func (r *ResolvedRegistrar) applyError(step resolvedStep, err error) error {
	name := dbusErrorName(err)
	switch {
	case unavailableName(name):
		r.logger.Debug("systemd-resolved not usable", "method", step.method, "error", err)
		return fmt.Errorf("meshdns: resolved: systemd-resolved is not running: %w", ErrUnavailable)
	case name == dbusErrUnknownMethod && step.tellsVersion:
		r.logger.Debug("systemd-resolved not usable", "method", step.method, "error", err)
		return fmt.Errorf("meshdns: resolved: systemd-resolved is older than 246: %w", ErrUnavailable)
	default:
		return fmt.Errorf("meshdns: resolved: %s: %w", step.method, err)
	}
}

// Revert clears every resolver setting of the interface named iface with
// RevertLink, including any an operator set there by hand, because plexd owns
// the link. It returns nil when there is nothing to clear: the interface is
// gone, the bus or systemd-resolved is unavailable, or systemd-resolved does
// not know the link. Like every call of the registrar, the RevertLink does not
// start a stopped systemd-resolved, which then counts as unavailable. Revert
// makes that one call, so it runs it under ctx: no revert follows that would
// need time held back.
func (r *ResolvedRegistrar) Revert(ctx context.Context, iface string) error {
	index, err := r.linkIndex(iface)
	if errors.Is(err, errNoSuchInterface) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("meshdns: resolved: interface %s: %w", iface, err)
	}
	bus, closeBus, err := r.connect(ctx)
	if err != nil {
		r.logger.Debug("system bus unreachable", "error", err)
		return nil
	}
	defer func() { _ = closeBus() }()

	err = bus.call(ctx, methodRevertLink, index)
	if err == nil {
		return nil
	}
	name := dbusErrorName(err)
	switch {
	case unavailableName(name):
		r.logger.Debug("systemd-resolved not usable", "method", methodRevertLink, "error", err)
		return nil
	case name == dbusErrNoSuchLink:
		return nil
	default:
		return fmt.Errorf("meshdns: resolved: RevertLink: %w", err)
	}
}

// linkIndex returns the index of the interface named name, which is how
// systemd-resolved addresses a link.
func (r *ResolvedRegistrar) linkIndex(name string) (int32, error) {
	ifaces, err := r.interfaces()
	if err != nil {
		return 0, fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return int32(iface.Index), nil
		}
	}
	return 0, errNoSuchInterface
}

// unavailableName reports whether the D-Bus error name says that nothing
// answers for systemd-resolved on the bus.
func unavailableName(name string) bool {
	switch name {
	case dbusErrServiceUnknown, dbusErrNameHasNoOwner, dbusErrNoSuchUnit:
		return true
	default:
		return false
	}
}

// dbusErrorName returns the name of the D-Bus error in err's chain, or "" when
// there is none. godbus fills Call.Err with an Error value for an error reply,
// while its NewError returns a pointer, so both forms are looked for.
func dbusErrorName(err error) string {
	var value dbus.Error
	if errors.As(err, &value) {
		return value.Name
	}
	var ptr *dbus.Error
	if errors.As(err, &ptr) && ptr != nil {
		return ptr.Name
	}
	return ""
}
