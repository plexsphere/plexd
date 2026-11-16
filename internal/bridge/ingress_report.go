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
}

// RuleReports returns one report per rule of the last Apply, in block order,
// and nil while the manager is not active. It skips a rule whose id is no
// UUID in canonical form or the zero UUID, and a rule whose id an earlier rule
// carried, compared without case, since the control plane refuses a whole
// report for one such entry; the Warn "ingress rule not served" names both.
//
// A rule that is not held does not listen, for its reason: invalid_rule,
// listener_conflict or max_rules. A held rule listens when its port is bound,
// and otherwise reads listen_failed. For a rule that listens, the certificate
// is not_required for passthrough; ready or not_ready with the overlay's
// reason for terminate; and for acme, not_ready with the plan's reason when it
// has one, ready once the ACME manager reports the host issued, and
// acme_not_issued until then. The dial is the last one a client connection
// caused to the rule's current target, and none without one.
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
	switch {
	case !st.held:
		r.Listener, r.ListenerReason = api.IngressListenerNotListening, st.Reason
		return r
	case m.listeners[st.Rule.ListenPort] == nil:
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
	// A record of another target belongs to the rule before it changed.
	if rec, ok := m.dials[st.Rule.ID]; ok && rec.target == ingressTarget(st.Rule) {
		r.Dial, r.DialReason, r.DialAt = api.IngressDialSucceeded, "", rec.at
		if rec.failed {
			r.Dial, r.DialReason = api.IngressDialFailed, rec.reason
		}
	}
	return r
}

// ReportChanged returns the channel the manager signals, without blocking,
// when what RuleReports returns may have changed: at the end of every Apply,
// every certificate load and Teardown, when the ACME manager reports a change
// of its issued hosts, and when a dial record changes its outcome or reason. Several signals before the reader wakes
// collapse into one. The signals are liberal; the reader compares before it
// acts.
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
