package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/registration"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// ownMeshIP is the mesh address plexd uses: the one the identity held at
// startup, or the one the mesh address dispatch handler applied since. The
// handler writes it on the reconcile goroutine while the system.info action
// and the ingress dial policy read it on theirs, so every access takes mu.
type ownMeshIP struct {
	mu sync.RWMutex
	// raw is the address as the identity or Set gave it. addr is raw parsed
	// and unmapped, or the zero Addr when raw does not parse.
	raw  string
	addr netip.Addr
}

// newOwnMeshIP returns the address plexd starts with, meshIP from the
// identity. A meshIP that does not parse is kept as text: String returns it
// and Addr reports no address.
func newOwnMeshIP(meshIP string) *ownMeshIP {
	o := &ownMeshIP{raw: meshIP}
	if addr, err := netip.ParseAddr(meshIP); err == nil {
		o.addr = addr.Unmap()
	}
	return o
}

// String returns the address as text, the way the system.info action reports
// it.
func (o *ownMeshIP) String() string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.raw
}

// Addr returns the address, unmapped, and false while the identity's address
// does not parse and no Set replaced it.
func (o *ownMeshIP) Addr() (netip.Addr, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.addr, o.addr.IsValid()
}

// Set makes addr the address plexd uses.
func (o *ownMeshIP) Set(addr netip.Addr) {
	addr = addr.Unmap()
	o.mu.Lock()
	defer o.mu.Unlock()
	o.addr = addr
	o.raw = addr.String()
}

// meshAddressFollower is a part of plexd that holds a copy of the mesh
// address. apply moves it to the address it is given, and name is the step a
// failure of apply is logged under.
type meshAddressFollower struct {
	name  string
	apply func(context.Context, netip.Addr) error
}

// meshAddressDeps is what meshAddressDispatchHandler works with.
type meshAddressDeps struct {
	// Own is the address plexd uses. The handler sets it once the mesh
	// interface carries a new address.
	Own *ownMeshIP
	// DataDir holds the identity files the handler commits a new address to.
	DataDir string
	// Persisted is the address identity.json holds at startup.
	Persisted string
	// Interface replaces the address on the mesh interface: wgMgr.Readdress,
	// or nil when WireGuard did not come up.
	Interface func(netip.Addr) error
	// Followers are moved, in order, once the interface carries the address.
	Followers []meshAddressFollower
	Logger    *slog.Logger
}

// commitMeshIP persists a new mesh address into the identity files. It is a
// variable so tests can count and order the commits.
var commitMeshIP = registration.CommitMeshIP

// errNoMeshInterface stands for the error of an Interface that does not
// exist, because WireGuard did not come up.
var errNoMeshInterface = errors.New("the mesh interface did not come up")

// meshAddressDispatchHandler returns the dispatch handler that applies the
// mesh_ip every state pull carries. Per pull it does this:
//
//  1. An empty mesh_ip, which a control plane that predates the member sends,
//     keeps the address and is logged at Debug.
//  2. A value that is no IP address, or an unspecified, loopback or multicast
//     one, is refused at Warn, once per value.
//  3. A value that differs from Own goes to Interface. Without one, or when it
//     cannot replace the address while plexd runs, the value is committed for
//     the next start and logged at Error once per value. An address the
//     interface refuses is logged as in step 2 and not committed. Any other
//     error is logged at Error the first time for a value and at Debug while
//     it repeats, and the next pull tries again. Once the interface carries
//     the address, Own takes it and the change is logged at Info.
//  4. Every follower whose last applied address differs from Own is called,
//     in order. A failure is logged as the interface's is, under the
//     follower's name, and keeps that follower's applied address, so the next
//     pull calls it again; it does not stop the others. Every follower starts
//     with the startup address as applied.
//  5. A value that differs from what the identity files hold is committed. A
//     failed commit is logged at Warn and tried again on the next pull.
//
// A crash between step 3 and step 5 starts from the old address, and the
// first pull applies the new one again. The reconcile goroutine is the only
// caller, one cycle at a time, so the closure's state needs no mutex.
//
// DECISION: mesh_ip is consumed on the dispatch seam, on every successful
// pull, as signing_key is, and the differ does not track it. A step that
// failed is therefore tried again on the next pull without holding back the
// snapshot, and a pull that changed nothing else still moves the node.
func meshAddressDispatchHandler(deps meshAddressDeps) reconcile.DispatchHandler {
	logger := deps.Logger
	persisted := deps.Persisted

	start, _ := deps.Own.Addr()
	applied := make([]netip.Addr, len(deps.Followers))
	for i := range applied {
		applied[i] = start
	}

	var (
		// lastRefused is the pulled value last refused, lastUnapplied the
		// address last committed without the interface taking it, and
		// failing the address each step last failed for, by step name.
		lastRefused   string
		lastUnapplied netip.Addr
		failing       = make(map[string]netip.Addr)
	)

	refuse := func(value string, err error) {
		if value == lastRefused {
			return
		}
		logger.Warn("mesh address from state pull refused", "mesh_ip", value, "error", err)
		lastRefused = value
	}
	stepFailed := func(ctx context.Context, step string, addr netip.Addr, err error) {
		level := slog.LevelError
		if last, ok := failing[step]; ok && last == addr {
			level = slog.LevelDebug
		}
		failing[step] = addr
		logger.Log(ctx, level, "mesh address not applied; retrying on the next pull",
			"step", step,
			"mesh_ip", addr.String(),
			"error", err,
		)
	}
	commit := func(addr netip.Addr) {
		value := addr.String()
		if value == persisted {
			return
		}
		if err := commitMeshIP(deps.DataDir, value); err != nil {
			logger.Warn("mesh address not persisted; retrying on the next pull", "mesh_ip", value, "error", err)
			return
		}
		persisted = value
	}

	return func(ctx context.Context, desired *api.NodeStateSnapshot) {
		if desired.MeshIP == "" {
			logger.Debug("state pull carried no mesh_ip; keeping the address")
			return
		}
		addr, err := meshAddressFromPull(desired.MeshIP)
		if err != nil {
			refuse(desired.MeshIP, err)
			return
		}

		if own, _ := deps.Own.Addr(); addr != own {
			err := errNoMeshInterface
			if deps.Interface != nil {
				err = deps.Interface(addr)
			}
			switch {
			case errors.Is(err, wireguard.ErrMeshAddressInvalid):
				refuse(desired.MeshIP, err)
				return
			case errors.Is(err, errNoMeshInterface), errors.Is(err, wireguard.ErrReaddressUnsupported):
				// The interface keeps the address it has, and so do Own and
				// the followers. The next start brings the interface up with
				// the committed one.
				lastRefused = ""
				commit(addr)
				if addr != lastUnapplied {
					logger.Error("mesh address cannot be applied while plexd runs; restart plexd to use it",
						"mesh_ip", addr.String(),
						"error", err,
					)
					lastUnapplied = addr
				}
				return
			case err != nil:
				lastRefused = ""
				stepFailed(ctx, "interface", addr, err)
				return
			}
			previous := deps.Own.String()
			deps.Own.Set(addr)
			logger.Info("mesh address changed from state pull", "previous_mesh_ip", previous, "mesh_ip", addr.String())
		}
		lastRefused = ""
		lastUnapplied = netip.Addr{}
		delete(failing, "interface")

		for i, f := range deps.Followers {
			if applied[i] == addr {
				continue
			}
			if err := f.apply(ctx, addr); err != nil {
				stepFailed(ctx, f.name, addr, err)
				continue
			}
			delete(failing, f.name)
			applied[i] = addr
		}

		commit(addr)
	}
}

// meshAddressFromPull parses the mesh_ip of a state pull, unmapped. It
// refuses a value that is no IP address, and an unspecified, loopback or
// multicast address, which no interface carries as the node's own. Whether
// the address lies inside the mesh prefix is for the interface to say.
func meshAddressFromPull(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	addr = addr.Unmap()
	switch {
	case addr.IsUnspecified():
		return netip.Addr{}, fmt.Errorf("%s is unspecified", addr)
	case addr.IsLoopback():
		return netip.Addr{}, fmt.Errorf("%s is a loopback address", addr)
	case addr.IsMulticast():
		return netip.Addr{}, fmt.Errorf("%s is a multicast address", addr)
	}
	return addr, nil
}
