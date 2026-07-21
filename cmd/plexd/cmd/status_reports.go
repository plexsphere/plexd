package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/bridge"
)

// Per-key state report keys for the status blocks that used to ride the
// heartbeat (removed in issue #19, re-homed here in issue #23). All five
// satisfy the node API report key grammar.
const (
	statusMeshKey       = "status.mesh"
	statusBridgeKey     = "status.bridge"
	statusUserAccessKey = "status.user-access"
	statusIngressKey    = "status.ingress"
	statusSiteToSiteKey = "status.site-to-site"
)

// meshStatus is the status.mesh payload. It is a cmd-local struct because
// there is no api type for the mesh status block.
type meshStatus struct {
	Interface  string `json:"interface"`
	PeerCount  int    `json:"peer_count"`
	ListenPort int    `json:"listen_port"`
}

// reportPublisher is the seam through which status blocks are published as
// per-key state reports. It is satisfied by *nodeapi.Server.
type reportPublisher interface {
	PublishReport(key, contentType string, payload json.RawMessage) error
	ReportPayload(key string) (json.RawMessage, bool)
}

// statusSample pairs a report key with its current payload value.
type statusSample struct {
	key     string
	payload any
}

// statusReportPublisher samples the mesh and bridge status blocks and publishes
// each as a per-key state report through the node API cache and syncer. Reports
// are only republished when the payload currently held under the key differs
// from the freshly sampled one, so a steady node converges to a stable set of
// reports and the syncer stays quiet.
type statusReportPublisher struct {
	publisher reportPublisher
	peerCount func() int

	// Bridge status providers are nil when bridge mode is off. Each method may
	// also return nil while the subsystem is inactive; both cases fall back to
	// a disabled payload.
	bridgeMgr     *bridge.Manager
	userAccessMgr *bridge.UserAccessManager
	ingressMgr    *bridge.IngressManager
	s2sMgr        *bridge.SiteToSiteManager

	ifaceName  string
	listenPort int

	interval time.Duration
	logger   *slog.Logger
}

// samples returns the current payload for each status report key.
func (p *statusReportPublisher) samples() []statusSample {
	return []statusSample{
		{statusMeshKey, meshStatus{
			Interface:  p.ifaceName,
			PeerCount:  p.peerCount(),
			ListenPort: p.listenPort,
		}},
		{statusBridgeKey, p.bridgeInfo()},
		{statusUserAccessKey, p.userAccessInfo()},
		{statusIngressKey, p.ingressInfo()},
		{statusSiteToSiteKey, p.siteToSiteInfo()},
	}
}

// bridgeInfo returns the bridge status, or a disabled payload when the manager
// is nil or reports itself inactive.
func (p *statusReportPublisher) bridgeInfo() api.BridgeInfo {
	if p.bridgeMgr != nil {
		if info := p.bridgeMgr.BridgeStatus(); info != nil {
			return *info
		}
	}
	return api.BridgeInfo{Enabled: false}
}

// userAccessInfo returns the user access status, or a disabled payload when the
// manager is nil or reports itself inactive.
func (p *statusReportPublisher) userAccessInfo() api.UserAccessInfo {
	if p.userAccessMgr != nil {
		if info := p.userAccessMgr.UserAccessStatus(); info != nil {
			return *info
		}
	}
	return api.UserAccessInfo{Enabled: false}
}

// ingressInfo returns the ingress status, or a disabled payload when the
// manager is nil or reports itself inactive.
func (p *statusReportPublisher) ingressInfo() api.IngressInfo {
	if p.ingressMgr != nil {
		if info := p.ingressMgr.IngressStatus(); info != nil {
			return *info
		}
	}
	return api.IngressInfo{Enabled: false}
}

// siteToSiteInfo returns the site-to-site status, or a disabled payload when
// the manager is nil or reports itself inactive.
func (p *statusReportPublisher) siteToSiteInfo() api.SiteToSiteInfo {
	if p.s2sMgr != nil {
		if info := p.s2sMgr.SiteToSiteStatus(); info != nil {
			return *info
		}
	}
	return api.SiteToSiteInfo{Enabled: false}
}

// publishOnce samples every status block and publishes the reports whose stored
// payload differs from the sample. The comparison reads the value currently held
// under the key rather than a private memory of the last publish: the report
// keyspace is writable by every local caller, so a forged PUT or a DELETE of a
// status key would otherwise stand until the sampled value happened to change.
// Reading the stored value back makes each tick re-assert the node's own status.
// A publish error is simply skipped, so it is retried on the next tick.
func (p *statusReportPublisher) publishOnce() {
	for _, s := range p.samples() {
		payload, err := json.Marshal(s.payload)
		if err != nil {
			p.logger.Warn("marshal status report failed", "key", s.key, "error", err)
			continue
		}
		if cur, ok := p.publisher.ReportPayload(s.key); ok && bytes.Equal(payload, cur) {
			continue
		}
		if err := p.publisher.PublishReport(s.key, "application/json", payload); err != nil {
			p.logger.Warn("publish status report failed", "key", s.key, "error", err)
		}
	}
}

// run samples once immediately, then on every tick of the configured interval,
// until ctx is cancelled.
func (p *statusReportPublisher) run(ctx context.Context) {
	p.publishOnce()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.publishOnce()
		}
	}
}
