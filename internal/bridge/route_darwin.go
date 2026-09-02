//go:build darwin

package bridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Absolute paths, because launchd starts the daemon with a minimal
// environment and neither tool is guaranteed to be on its PATH.
const (
	routePath  = "/sbin/route"
	sysctlPath = "/usr/sbin/sysctl"

	// forwardingSysctl is the only IPv4 forwarding knob macOS has. Linux has
	// one per interface; this one is global, which is why the ledger tracks
	// who holds it and what it read before the first holder switched it on.
	forwardingSysctl = "net.inet.ip.forwarding"

	// commandTimeout bounds one route or sysctl invocation. Both return
	// immediately; the timeout keeps a wedged host from stalling bridge setup
	// forever.
	commandTimeout = 10 * time.Second
)

// DarwinRouteController implements RouteController on macOS with route(8) for
// routes and sysctl(8) for IPv4 forwarding. Every method needs root.
//
// NAT masquerade is delegated to the NATController the firewall backend
// supplies; a controller built with none reports NAT as unavailable rather
// than letting a gateway come up claiming a masquerade it does not have.
type DarwinRouteController struct {
	exec   CommandExecutor
	nat    NATController
	logger *slog.Logger

	mu     sync.Mutex
	ledger *forwardingLedger[string]
}

// NewDarwinRouteController returns a controller driving the host's route and
// sysctl binaries. nat may be nil, which makes AddNATMasquerade fail with
// ErrNATUnavailable.
func NewDarwinRouteController(logger *slog.Logger, nat NATController) *DarwinRouteController {
	return &DarwinRouteController{
		exec:   NewStdCommandExecutor(),
		nat:    nat,
		logger: logger,
		ledger: newForwardingLedger[string](),
	}
}

// routeFamily returns the address-family flag route(8) takes for a prefix.
func routeFamily(prefix netip.Prefix) string {
	if prefix.Addr().Is4() {
		return "-inet"
	}
	return "-inet6"
}

// run executes one host command under a timeout and returns its combined
// output, which the caller reads even on failure to recognise the idempotent
// cases. A failure carries the command line and the tool's own message,
// because "exit status 1" alone says nothing an operator can act on.
func (c *DarwinRouteController) run(op string, argv ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := c.exec.Run(ctx, argv[0], argv[1:]...)
	if err == nil {
		return out, nil
	}

	detail := strings.TrimSpace(string(out))

	// route(8) refuses with "must be root to alter routing table" and sysctl
	// with "Operation not permitted". Neither says what to change, and the
	// line an operator reads is the one plexd up prints as it aborts.
	hint := ""
	if strings.Contains(detail, "must be root") || strings.Contains(detail, "Operation not permitted") {
		hint = " (bridge mode on macOS requires root)"
	}

	if detail != "" {
		return out, fmt.Errorf("bridge: %s: %s: %w: %s%s", op, strings.Join(argv, " "), err, detail, hint)
	}
	return out, fmt.Errorf("bridge: %s: %s: %w%s", op, strings.Join(argv, " "), err, hint)
}

// AddRoute adds a route for the given CIDR subnet via the given interface.
// Idempotent: adding an existing route returns nil.
func (c *DarwinRouteController) AddRoute(subnet, iface string) error {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return fmt.Errorf("bridge: add route: parse CIDR %q: %w", subnet, err)
	}
	// route(8) would take an empty argument and fail on the next one, with a
	// message that never names the interface as the cause.
	if iface == "" {
		return errors.New("bridge: add route: interface name is empty")
	}

	out, err := c.run(fmt.Sprintf("add route %q via %q", subnet, iface),
		routePath, "-n", "add", routeFamily(prefix), prefix.Masked().String(), "-interface", iface)
	if err != nil {
		// route(8) reports an existing route as "File exists"; re-adding one
		// is success, the idempotency NetlinkRouteController grants EEXIST.
		if bytes.Contains(out, []byte("File exists")) {
			c.logger.Debug("route already exists, idempotent success",
				"component", "bridge",
				"subnet", subnet,
				"interface", iface,
			)
			return nil
		}
		return err
	}

	c.logger.Debug("route added",
		"component", "bridge",
		"subnet", subnet,
		"interface", iface,
	)
	return nil
}

// RemoveRoute removes the route for the given CIDR subnet via the given
// interface. Idempotent: removing a non-existent route returns nil.
func (c *DarwinRouteController) RemoveRoute(subnet, iface string) error {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return fmt.Errorf("bridge: remove route: parse CIDR %q: %w", subnet, err)
	}
	if iface == "" {
		return errors.New("bridge: remove route: interface name is empty")
	}

	// The delete names the destination only: the kernel matches on
	// destination and mask, and an -interface argument would only make the
	// call fail once the interface itself is gone. wg-quick deletes the same
	// way on this platform.
	out, err := c.run(fmt.Sprintf("remove route %q via %q", subnet, iface),
		routePath, "-n", "delete", routeFamily(prefix), prefix.Masked().String())
	if err != nil {
		// route(8) reports a missing route as "not in table", the idempotency
		// NetlinkRouteController grants ESRCH.
		if bytes.Contains(out, []byte("not in table")) {
			c.logger.Debug("route not found, idempotent success",
				"component", "bridge",
				"subnet", subnet,
				"interface", iface,
			)
			return nil
		}
		return err
	}

	c.logger.Debug("route removed",
		"component", "bridge",
		"subnet", subnet,
		"interface", iface,
	)
	return nil
}

// EnableForwarding switches IPv4 forwarding on. The knob is global on macOS,
// so the first caller records what it found and every later one only
// re-asserts the value; the interface names are tracked and logged, not
// programmed.
func (c *DarwinRouteController) EnableForwarding(meshIface, accessIface string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	pair := forwardingPair{meshIface, accessIface}

	var before string
	if !c.ledger.held(forwardingSysctl) {
		out, err := c.run("enable forwarding", sysctlPath, "-n", forwardingSysctl)
		if err != nil {
			return err
		}
		before = strings.TrimSpace(string(out))
		if before != "0" && before != "1" {
			return fmt.Errorf("bridge: enable forwarding: unexpected %s value %q", forwardingSysctl, before)
		}
	}

	if _, err := c.run("enable forwarding", sysctlPath, "-w", forwardingSysctl+"=1"); err != nil {
		return err
	}

	// Recorded only once the write succeeded, so a failed enable leaves
	// nothing for a later disable to restore.
	c.ledger.acquire(forwardingSysctl, pair, before)

	c.logger.Debug("IP forwarding enabled",
		"component", "bridge",
		"mesh_iface", meshIface,
		"access_iface", accessIface,
	)
	return nil
}

// DisableForwarding restores the forwarding value that was in place before the
// first pair enabled it, once the last pair has let go. Idempotent: a pair
// that never enabled forwarding writes nothing.
func (c *DarwinRouteController) DisableForwarding(meshIface, accessIface string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	pair := forwardingPair{meshIface, accessIface}

	before, last := c.ledger.release(forwardingSysctl, pair)
	if !last {
		c.logger.Debug("IP forwarding left as is",
			"component", "bridge",
			"mesh_iface", meshIface,
			"access_iface", accessIface,
			"held", c.ledger.held(forwardingSysctl),
		)
		return nil
	}

	if _, err := c.run("disable forwarding", sysctlPath, "-w", forwardingSysctl+"="+before); err != nil {
		return err
	}

	c.logger.Debug("IP forwarding restored",
		"component", "bridge",
		"mesh_iface", meshIface,
		"access_iface", accessIface,
		"value", before,
	)
	return nil
}

// AddNATMasquerade configures NAT masquerading on the given interface through
// the firewall backend, and reports NAT as unavailable when there is none.
func (c *DarwinRouteController) AddNATMasquerade(iface string) error {
	if c.nat == nil {
		return fmt.Errorf("bridge: add NAT masquerade on %q: %w; set bridge.enable_nat: false to run the bridge without NAT",
			iface, ErrNATUnavailable)
	}
	return c.nat.AddNATMasquerade(iface)
}

// RemoveNATMasquerade removes NAT masquerading from the given interface.
// Idempotent: with no backend there is nothing that could have been added.
func (c *DarwinRouteController) RemoveNATMasquerade(iface string) error {
	if c.nat == nil {
		c.logger.Debug("NAT masquerade backend absent, nothing to remove",
			"component", "bridge",
			"interface", iface,
		)
		return nil
	}
	return c.nat.RemoveNATMasquerade(iface)
}
