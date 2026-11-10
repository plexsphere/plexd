package meshdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// registrarTimeout bounds each Apply and each Revert that Handle issues. Handle
// runs inside the reconcile loop, so a system bus that hangs would otherwise
// hold up every handler after it and the next pull.
const registrarTimeout = 5 * time.Second

// maxSkippedLogged is how many of the skipped-entry sentences the warning
// carries. A control plane bug can skip every host of a large Domain, and the
// first few sentences name the rule that was broken as well as all of them
// would.
const maxSkippedLogged = 5

// Manager follows the dns block of the state pull: it builds the records of
// each block, swaps them into its server, and keeps the registration with the
// system resolver in step with them. A mutex guards the state Handle and
// Shutdown share, so a pull racing the drain either finishes before the revert
// or does nothing at all. The manager never touches health or readiness: a
// node whose resolver cannot register still serves its mesh, and the log lines
// are the operator's view of it.
type Manager struct {
	iface     string
	registrar Registrar
	logger    *slog.Logger
	server    *Server

	mu sync.Mutex
	// records is the set the server answers from, nil until the first block.
	records *Records
	// applied is the registration the system resolver accepted last, or nil
	// when none counts as applied: before the first success, after a revert,
	// and after any failure, so the next pull applies again. Nil does not mean
	// the link is clean; mayHold says that.
	applied *Registration
	// mayHold is set when the link may carry plexd's settings. A failed Apply
	// can leave the earlier registration in place or stop before its own
	// cleanup, so it is set before every Apply, kept by a failure, and cleared
	// only by a successful revert. It is set whenever applied is.
	mayHold bool
	// noBlockLogged is set once a pull without a dns block was logged, and
	// cleared when a block arrives.
	noBlockLogged bool
	// unavailableLogged is set once the missing system resolver was logged,
	// and cleared when the state changes: by a success or another failure.
	unavailableLogged bool
	// failureLogged is the text of the registration failure logged last, or
	// empty, so a failure that repeats on every pull warns once.
	failureLogged string
	// closed is set by Shutdown. Every later Handle is a no-op, so a pull that
	// waited for the mutex cannot register again after the revert.
	closed bool
}

// NewManager returns a manager whose resolver listens on meshIP and
// cfg.ListenPort and registers with registrar for the interface iface. It
// binds nothing until Start, so the caller learns about an occupied port from
// Start's error. cfg must have passed Validate; Enabled is not consulted,
// because the caller decides whether to build a manager at all. A ListenPort
// of 0 lets the kernel pick the port, which tests use. Every line the manager
// and its server log carries "component" "meshdns".
func NewManager(cfg Config, iface string, meshIP netip.Addr, registrar Registrar, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "meshdns")
	return &Manager{
		iface:     iface,
		registrar: registrar,
		logger:    logger,
		server:    NewServer(netip.AddrPortFrom(meshIP, uint16(cfg.ListenPort)), logger),
	}
}

// Start binds the resolver's UDP and TCP sockets. It returns the server's
// Listen error, which wraps the error of the bind that failed.
func (m *Manager) Start() error {
	return m.server.Listen()
}

// Addr returns the address the resolver is bound to, with the port the kernel
// picked when the configured port was 0. It is the server of every
// registration, so it is what the log lines name as the listen address.
// Before Start, and after a Start that failed, it is the configured address,
// so a caller can name it in a bind error.
func (m *Manager) Addr() netip.AddrPort {
	return m.server.Addr()
}

// Run answers queries until ctx ends and returns nil then. An error means the
// resolver stopped while ctx was live, and no mesh name is answered after it.
func (m *Manager) Run(ctx context.Context) error {
	return m.server.Serve(ctx)
}

// Handle takes the dns block of one state pull. It has the signature of
// reconcile.DispatchHandler and runs on every successful pull, drift or not:
// the block is not desired state the differ tracks, and a pull that changed
// no name must still retry a registration that failed. A snapshot without a
// block keeps the names and the registration held, because the block is
// missing when the control plane predates it or said nothing this time, not
// when the Domain lost its names.
func (m *Manager) Handle(ctx context.Context, desired *api.NodeStateSnapshot) {
	if desired == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	if desired.DNS == nil {
		if !m.noBlockLogged {
			m.noBlockLogged = true
			m.logger.Info("state pull carries no dns block, keeping the names held")
		}
		return
	}
	m.noBlockLogged = false

	records, skipped := BuildRecords(*desired.DNS)
	m.server.SetRecords(records)
	if len(skipped) > 0 {
		m.logger.Warn("mesh dns skipped invalid entries",
			"count", len(skipped),
			"skipped", skipped[:min(len(skipped), maxSkippedLogged)],
		)
	}
	if !records.Equal(m.records) {
		m.logger.Info("mesh dns records updated",
			"hosts", records.HostCount(),
			"records", records.RecordCount(),
			"zones", records.ZoneCount(),
			"reverse_zones", records.ReverseZoneCount(),
			"search_domain", records.SearchDomain(),
		)
	}
	m.records = records

	m.register(ctx, records.Registration(m.iface, m.server.Addr()))
}

// register brings the system resolver in step with want. The caller holds
// m.mu. A pull whose context is already done is racing the shutdown, so it
// issues no call: the drain's revert is the last word on the link.
func (m *Manager) register(ctx context.Context, want Registration) {
	if ctx.Err() != nil {
		return
	}
	if m.applied != nil && want.Equal(*m.applied) {
		return
	}
	// Applying a registration without a domain would route nothing, so the
	// link is cleared instead, and only when plexd may have set it: after a
	// registration that counts as applied, and after a failed Apply too,
	// which can leave settings behind although none counts as applied.
	if want.Empty() && m.applied == nil && !m.mayHold {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, registrarTimeout)
	defer cancel()

	if want.Empty() {
		// A failed revert keeps applied and mayHold as they were, so the next
		// pull reverts again.
		if err := m.registrar.Revert(cctx, m.iface); err != nil {
			m.logFailure(err)
			return
		}
		m.applied = nil
		m.mayHold = false
		m.resetTrackers()
		return
	}

	// Set before the call, because a failure can come after some of its
	// settings reached the link.
	m.mayHold = true
	err := m.registrar.Apply(cctx, want)
	if err == nil {
		m.applied = &want
		m.resetTrackers()
		m.logger.Info("mesh dns registered with systemd-resolved",
			"interface", want.Interface,
			"server", want.Server.String(),
			"search_domain", want.SearchDomain,
			"routing_domains", len(want.RoutingDomains),
		)
		return
	}
	// Whatever the link holds now, nothing counts as applied, so the next
	// pull applies again. That picks up a
	// systemd-resolved that starts later, or a link that frees up, within one
	// reconcile interval. mayHold stays set, so an empty registration on a
	// later pull still clears what the link holds.
	m.applied = nil
	if errors.Is(err, ErrUnavailable) {
		m.failureLogged = ""
		if !m.unavailableLogged {
			m.unavailableLogged = true
			m.logger.Info("mesh dns not registered, systemd-resolved is not usable",
				"listen", m.server.Addr().String(),
				"reason", err.Error(),
			)
		}
		return
	}
	m.logFailure(err)
}

// logFailure warns about a registrar error unless its text is the one logged
// last, so a failure that repeats on every pull warns once, and a failure
// that changes, or comes back after another state, is seen.
func (m *Manager) logFailure(err error) {
	m.unavailableLogged = false
	if text := err.Error(); text != m.failureLogged {
		m.failureLogged = text
		m.logger.Warn("mesh dns registration failed", "error", err)
	}
}

// resetTrackers forgets the failures logged, so the next one is logged
// again after a success.
func (m *Manager) resetTrackers() {
	m.unavailableLogged = false
	m.failureLogged = ""
}

// Shutdown reverts the registration of the interface and stops every later
// Handle. It reverts on every run, registered or not, so a registration that
// a killed predecessor left behind goes too; otherwise the system resolver
// would keep sending the mesh zones to an address nothing answers. It does
// not stop the server, which Run's context does. A registrar error is
// returned wrapped.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if err := m.registrar.Revert(ctx, m.iface); err != nil {
		return fmt.Errorf("meshdns: shutdown: %w", err)
	}
	m.applied = nil
	m.mayHold = false
	m.logger.Info("mesh dns registration reverted", "interface", m.iface)
	return nil
}
