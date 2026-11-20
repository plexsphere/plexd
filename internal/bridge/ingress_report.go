package bridge

import (
	"strings"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// IngressRuleReport is what the bridge says about one rule in an ingress
// status report. It carries no Detail: a Secret name, a directory URL, a slug
// and an error text stay in the bridge's log.
type IngressRuleReport struct {
	RuleID            string
	Listener          string // api.IngressListener*
	ListenerReason    string
	Certificate       string // api.IngressCertificate*; empty when the rule does not listen
	CertificateReason string
	Dial              string // api.IngressDial*; empty when the rule does not listen
	DialReason        string
	DialAt            time.Time // zero unless Dial is succeeded or failed
	// Targets holds the target entries of a rule that listens, in the order
	// of the rule's targets (see RuleReports); nil when the rule has none.
	Targets []IngressTargetReport
}

// IngressClientRefusalReport is the last client the bridge refused for one
// reason on a rule with client_auth.
type IngressClientRefusalReport struct {
	Reason string    // one of the IngressRefusal* constants
	At     time.Time // when the bridge refused that client
}

// IngressTargetReport is what the bridge says about one target of a rule: the
// target as the pull names it and how the last dial to it ended.
type IngressTargetReport struct {
	NodeID     string
	Port       int
	Dial       string // api.IngressDial*
	DialReason string
	DialAt     time.Time // zero unless Dial is succeeded or failed
}

// RuleReports returns one report per rule of the last Apply, in block order,
// and nil while the manager is not active. It skips a rule whose id is no
// UUID in canonical form or the zero UUID, and a rule whose id an earlier rule
// carried, compared without case, since the control plane refuses a whole
// report for one such entry; the Warn "ingress rule not served" names both.
//
// A rule that is not held does not listen, for its reason: invalid_rule,
// listener_conflict or max_rules. A held rule listens when its port is bound
// for its protocol, a TCP listener for a tcp rule and a UDP socket for a udp
// rule, and otherwise reads listen_failed. For a rule that listens, the
// certificate is not_required for passthrough, which every udp rule is; ready
// or not_ready with the overlay's reason for terminate; and for acme,
// not_ready with the plan's reason when it has one, ready once the ACME
// manager reports the host issued, and acme_not_issued until then. The dial is
// how the rule's last unit ended: succeeded when a target took it, failed
// with the reason of the last target dialled when none did, and none before
// the first unit and after a pull that changed the rule's targets. For a udp
// rule the unit is a client flow: it fails when no target takes a client's
// datagram, and succeeds with a send that counts as a dial and reaches a
// target (see forwardUDP).
//
// A rule that listens and whose pull entry carried targets has one target
// entry per target, in list order, with the last dial to that target: none
// before the first and after a pull that changed the rule's targets,
// succeeded, or failed with its reason. Its targets are served whether or
// not they have an entry: an entry is skipped for a target whose node_id is
// no UUID in canonical form or the zero UUID, and for a target whose node_id,
// compared without case, and port an earlier entry of the rule carried, since
// the control plane refuses a whole report for one such entry. A rule that
// does not listen has no target entries, and neither has a rule whose pull
// entry carried no targets, as a control plane before
// plexsphere/plexsphere#1120 sends it: that control plane refuses the member.
func (m *IngressManager) RuleReports() []IngressRuleReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return nil
	}
	states := m.overlayCertificatesLocked()
	out := make([]IngressRuleReport, 0, len(states))
	seen := make(map[string]struct{}, len(states))
	for _, st := range states {
		if !api.ValidIngressRuleID(st.Rule.ID) {
			continue
		}
		id := strings.ToLower(st.Rule.ID)
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, m.ruleReportLocked(st))
	}
	return out
}

// ruleReportLocked returns the report of one rule state. The caller holds mu.
func (m *IngressManager) ruleReportLocked(st IngressRuleState) IngressRuleReport {
	r := IngressRuleReport{RuleID: st.Rule.ID}
	bound := m.listeners[st.Rule.ListenPort] != nil
	if st.Rule.Protocol == api.IngressProtocolUDP {
		bound = m.udp[st.Rule.ListenPort] != nil
	}
	switch {
	case !st.held:
		r.Listener, r.ListenerReason = api.IngressListenerNotListening, st.Reason
		return r
	case !bound:
		r.Listener, r.ListenerReason = api.IngressListenerNotListening, IngressReasonListenFailed
		return r
	}

	r.Listener = api.IngressListenerListening
	switch st.Rule.Mode {
	case api.IngressModePassthrough:
		r.Certificate = api.IngressCertificateNotRequired
	case api.IngressModeTerminate:
		if st.Reason == "" {
			r.Certificate = api.IngressCertificateReady
		} else {
			r.Certificate, r.CertificateReason = api.IngressCertificateNotReady, st.Reason
		}
	default: // api.IngressModeACME
		switch {
		case st.Reason != "":
			r.Certificate, r.CertificateReason = api.IngressCertificateNotReady, st.Reason
		case m.acme.Issued(st.Rule.SNIHost):
			r.Certificate = api.IngressCertificateReady
		default:
			r.Certificate, r.CertificateReason = api.IngressCertificateNotReady, IngressReasonACMENotIssued
		}
	}
	r.Dial = api.IngressDialNone
	b := m.balancers[st.Rule.ID]
	if b == nil {
		return r
	}
	unit, records := b.snapshot()
	r.Dial, r.DialReason, r.DialAt = dialFacet(unit)
	if st.reportsTargets {
		r.Targets = targetReports(b, records)
	}
	return r
}

// targetReports returns the target entries of a rule whose balancer is b,
// records being b's dial record of each target, in the order of the targets.
// It skips a target whose node_id api.ValidIngressTargetNodeID refuses and a
// target whose lowercase node_id and port an earlier entry carried. It
// returns nil when no target has an entry.
func targetReports(b *ingressBalancer, records []dialRecord) []IngressTargetReport {
	type targetKey struct {
		nodeID string
		port   int
	}
	var out []IngressTargetReport
	seen := make(map[targetKey]struct{}, len(records))
	for i, rec := range records {
		// A balancer's targets never change, so they are read without its lock.
		t := b.targets[i].target
		if !api.ValidIngressTargetNodeID(t.NodeID) {
			continue
		}
		key := targetKey{nodeID: strings.ToLower(t.NodeID), port: t.Port}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		e := IngressTargetReport{NodeID: t.NodeID, Port: t.Port}
		e.Dial, e.DialReason, e.DialAt = dialFacet(rec)
		out = append(out, e)
	}
	return out
}

// dialFacet returns the dial, the dial reason and the dial time a report
// reads for rec: none without a dial, succeeded, or failed with its reason.
func dialFacet(rec dialRecord) (dial, reason string, at time.Time) {
	switch {
	case rec.at.IsZero():
		return api.IngressDialNone, "", time.Time{}
	case rec.failed:
		return api.IngressDialFailed, rec.reason, rec.at
	default:
		return api.IngressDialSucceeded, "", rec.at
	}
}

// ReportChanged returns the channel the manager signals, without blocking,
// when what RuleReports returns may have changed: at the end of every Apply,
// every certificate load and Teardown, when the ACME manager reports a change
// of its issued hosts, and when the record of a rule's last unit or of the
// last dial to one of its targets changes its outcome or reason. Several
// signals before the reader wakes collapse into one. The signals are liberal;
// the reader compares before it acts.
func (m *IngressManager) ReportChanged() <-chan struct{} {
	return m.changed
}

// signalReport signals ReportChanged without blocking: a full channel already
// carries the signal.
func (m *IngressManager) signalReport() {
	select {
	case m.changed <- struct{}{}:
	default:
	}
}
