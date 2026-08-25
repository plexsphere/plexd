package packaging

import "context"

// Service binds a ServiceManager to one InstallConfig. The service.restart
// and service.upgrade actions restart the installed daemon through it.
type Service struct {
	mgr ServiceManager
	cfg InstallConfig
}

// NewService binds mgr to cfg with the platform defaults applied, so a caller
// that only ever drives the default installation passes an empty InstallConfig.
func NewService(mgr ServiceManager, cfg InstallConfig) *Service {
	cfg.ApplyDefaults()
	return &Service{mgr: mgr, cfg: cfg}
}

// Available reports whether the host's service manager can be driven from this
// process.
func (s *Service) Available() bool { return s.mgr.Available() }

// Restart asks the manager to restart the service. It returns once the request
// is accepted; the restart itself completes afterwards, and may end this
// process before it does.
func (s *Service) Restart(ctx context.Context) error { return s.mgr.Restart(ctx, s.cfg) }
