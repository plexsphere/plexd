package policy

import (
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/plexsphere/plexd/internal/api"
)

// maxRejectionReasonBytes is the contract's ceiling on a rejection's reason.
const maxRejectionReasonBytes = 1024

// Status is the Enforcer's record of what it did with the policy blocks of
// the pulls, which the policy status report and the node API read.
type Status struct {
	// Enforcement is one of the api.PolicyEnforcement* constants.
	Enforcement string
	// Synced tells whether Sync ran at least once.
	Synced bool
	// HasApplied tells whether a pull's block is applied.
	HasApplied bool
	// Applied is that block; nil when the applied pull carried policy: null.
	Applied *api.PolicySnapshot
	// Received is the block of the latest pull; nil for policy: null.
	Received *api.PolicySnapshot
	// Rejected is the block the latest apply failed on; nil when it did not
	// fail.
	Rejected *api.PolicySnapshot
	// Reason is why Rejected failed, as rejectionReason renders the error;
	// empty without Rejected.
	Reason string
	// Attempts counts the applies of Rejected that failed in a row with the
	// same reason; 0 without Rejected.
	Attempts int
}

// clone returns a copy of s whose blocks share no memory with s.
func (s Status) clone() Status {
	s.Applied = s.Applied.Clone()
	s.Received = s.Received.Clone()
	s.Rejected = s.Rejected.Clone()
	return s
}

// sameReportedState reports whether s and o state the same policy as the
// report and its log of transitions see it: the enforcement, whether and
// which block is applied, and which block was rejected and why. Synced,
// Received and Attempts do not count.
func (s Status) sameReportedState(o Status) bool {
	return s.Enforcement == o.Enforcement &&
		s.HasApplied == o.HasApplied &&
		sameEcho(s.Applied, o.Applied) &&
		sameEcho(s.Rejected, o.Rejected) &&
		s.Reason == o.Reason
}

// sameEcho reports whether a and b echo the same block in a report: both nil,
// or both non-nil with the same fingerprint and revisions.
func sameEcho(a, b *api.PolicySnapshot) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Fingerprint == b.Fingerprint && slices.Equal(a.Revisions, b.Revisions)
}

// sameBlock reports whether the installed policy and a pulled one are the same
// ruleset: both nil, or both non-nil with equal fingerprints that are not
// empty. An empty fingerprint is no comparison key, so a block without one is
// never the same as anything.
func sameBlock(installed, desired *api.PolicySnapshot) bool {
	if installed == nil || desired == nil {
		return installed == nil && desired == nil
	}
	return desired.Fingerprint != "" && installed.Fingerprint == desired.Fingerprint
}

// Sync brings the firewall to the policy block of a pull and records the
// outcome in Status. The reconciler runs it on every successful pull through
// DispatchHandler. It decides in this order:
//
//  1. The block becomes Status.Received.
//  2. With enforcement disabled (policy.enabled: false) or no firewall
//     backend, it records the enforcement as disabled or unavailable, clears
//     the applied and the rejected block, and touches nothing.
//  3. When a ruleset is installed and desired is the same block (both nil, or
//     the same non-empty fingerprint), it makes no kernel call and adopts
//     desired as applied: a first pull with policy: null applies over the
//     startup baseline, and a pull that changes only revision_id or
//     revisions under an unchanged fingerprint is taken as it is.
//  4. With nothing installed and a nil desired, it does nothing: the node
//     whose startup skipped the baseline stays as it was.
//  5. Otherwise it applies desired. On success desired is applied and the
//     rejection cleared.
//  6. On failure the applied block stays, because every backend replaces a
//     chain whole or leaves it. A block with a fingerprint becomes Rejected,
//     with Attempts counting the failures in a row of that fingerprint and
//     reason. A nil block or one without a fingerprint cannot be echoed, so
//     its failure clears Rejected instead.
//
// DECISION: the retry is the next pull. A block that is not installed is
// applied again on every pull, every reconcile interval and on every trigger,
// without a backoff: a ruleset the engine refuses costs one pass over its
// rules and no kernel call, and a backend failure was retried every cycle
// before.
//
// The first failure of a fingerprint and reason logs at Error, a repeat at
// Debug, so a revision stuck behind the retry does not repeat its Error every
// minute. Sync signals Changed when it ran for the first time or changed what
// sameReportedState compares.
func (e *Enforcer) Sync(desired *api.PolicySnapshot, iface string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}

	before := e.status
	first := !e.status.Synced
	e.status.Synced = true
	e.status.Received = desired.Clone()

	switch {
	case !e.cfg.IsEnabled():
		e.status.Enforcement = api.PolicyEnforcementDisabled
		e.status.HasApplied, e.status.Applied = false, nil
		e.clearRejectedLocked()
	case e.firewall == nil:
		e.status.Enforcement = api.PolicyEnforcementUnavailable
		e.status.HasApplied, e.status.Applied = false, nil
		e.clearRejectedLocked()
	default:
		e.status.Enforcement = api.PolicyEnforcementEnforcing
		e.syncLocked(desired, iface)
	}

	if first || !before.sameReportedState(e.status) {
		select {
		case e.changed <- struct{}{}:
		default:
		}
	}
}

// syncLocked runs steps 3 to 6 of Sync with e.mu held, for an Enforcer that
// enforces.
func (e *Enforcer) syncLocked(desired *api.PolicySnapshot, iface string) {
	if e.hasInstalled && sameBlock(e.installed, desired) {
		e.installed = desired.Clone()
		e.adoptLocked(desired)
		return
	}
	if !e.hasInstalled && desired == nil {
		return
	}

	revisionID, fingerprint, ruleCount := "", "", 0
	if desired != nil {
		revisionID, fingerprint, ruleCount = desired.RevisionID, desired.Fingerprint, len(desired.Rules)
		if fingerprint == "" {
			// Without a fingerprint the block is never the installed one, so
			// the ruleset is rebuilt on every pull. Name that explicitly —
			// otherwise the churn is indistinguishable from real revisions.
			e.logger.Warn("policy snapshot carries no fingerprint, ruleset rebuilds every cycle",
				"revision_id", revisionID,
			)
		}
	}

	if _, err := e.applyLocked(desired, iface); err != nil {
		e.recordFailureLocked(desired, err)
		return
	}
	e.adoptLocked(desired)
	e.logger.Info("policy ruleset applied",
		"revision_id", revisionID,
		"fingerprint", fingerprint,
		"rules", ruleCount,
	)
}

// adoptLocked records desired as the applied block and clears the rejection.
func (e *Enforcer) adoptLocked(desired *api.PolicySnapshot) {
	e.status.HasApplied = true
	e.status.Applied = desired.Clone()
	e.clearRejectedLocked()
	e.failKey = ""
}

// clearRejectedLocked forgets the rejected block.
func (e *Enforcer) clearRejectedLocked() {
	e.status.Rejected, e.status.Reason, e.status.Attempts = nil, "", 0
}

// recordFailureLocked records a failed apply of desired and logs it.
func (e *Enforcer) recordFailureLocked(desired *api.PolicySnapshot, err error) {
	reason := rejectionReason(err)
	revisionID, fingerprint := "", ""
	if desired != nil {
		revisionID, fingerprint = desired.RevisionID, desired.Fingerprint
	}

	if fingerprint == "" {
		// The report has to name a rejected block by its fingerprint.
		e.clearRejectedLocked()
	} else {
		if e.status.Rejected != nil && e.status.Rejected.Fingerprint == fingerprint && e.status.Reason == reason {
			e.status.Attempts++
		} else {
			e.status.Attempts = 1
		}
		e.status.Rejected = desired.Clone()
		e.status.Reason = reason
	}

	key := fingerprint + "\x00" + reason
	if key == e.failKey {
		e.logger.Debug("policy revision still rejected",
			"revision_id", revisionID,
			"fingerprint", fingerprint,
			"attempts", e.status.Attempts,
		)
		return
	}
	e.failKey = key
	if errors.Is(err, ErrInvalidRuleset) {
		e.logger.Error("policy revision rejected, keeping previous ruleset",
			"revision_id", revisionID,
			"fingerprint", fingerprint,
			"error", err,
		)
		return
	}
	e.logger.Error("reconcile: apply firewall rules failed",
		"revision_id", revisionID,
		"fingerprint", fingerprint,
		"error", err,
	)
}

// Status returns a copy of the Enforcer's record. Before the first Sync it
// is the zero Status.
func (e *Enforcer) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status.clone()
}

// Changed returns the channel Sync signals on when it ran for the first time
// or changed the enforcement, the applied block or the rejection. It has a
// capacity of one: several changes before the reader wakes collapse into one
// signal, and the reader then reads the latest Status.
func (e *Enforcer) Changed() <-chan struct{} {
	return e.changed
}

// dropCounts are the counts DropCounts read last, with the install they
// belong to.
type dropCounts struct {
	install        uint64
	packets, bytes uint64
	ok             bool
}

// DropCounts returns what the installed ruleset's deny rules dropped since it
// was installed, and whether there is such a count. It is false while
// enforcement is not on, while nothing is installed, and for a backend that
// does not implement DropCounter.
//
// A failed read returns the counts read last for the same install, so a
// report keeps carrying drops through a passing failure: the control plane
// counts the whole value of a report that follows one without counters, and
// a gap would count the same drops twice. Without such counts it returns
// false. The failure is logged at Warn once per run of failures.
//
// An install is an apply the backend accepted. A failed apply leaves the
// chain and its counters as they were, so it keeps the counts read last.
// The read holds the Enforcer's lock, so the counts always belong to the
// install they are remembered with; on macOS that is one pfctl run.
func (e *Enforcer) DropCounts() (packets, bytes uint64, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	counter, isCounter := e.firewall.(DropCounter)
	if !e.cfg.IsEnabled() || !isCounter || !e.hasInstalled {
		return 0, 0, false
	}

	packets, bytes, err := counter.DropCounts(e.cfg.ChainName)
	if err != nil {
		if !e.dropsFailing {
			e.dropsFailing = true
			e.logger.Warn("policy drop counters unavailable",
				"chain", e.cfg.ChainName,
				"error", err,
			)
		}
		if e.lastDrops.ok && e.lastDrops.install == e.installs {
			return e.lastDrops.packets, e.lastDrops.bytes, true
		}
		return 0, 0, false
	}
	e.dropsFailing = false
	e.lastDrops = dropCounts{install: e.installs, packets: packets, bytes: bytes, ok: true}
	return packets, bytes, true
}

// rejectionReason renders err as the reason of a policy status report, which
// the contract bounds to 1 to 1024 bytes of UTF-8 without control characters:
// invalid UTF-8 becomes U+FFFD, U+0000 to U+001F and U+007F become spaces,
// the text is trimmed and cut to 1024 bytes on a rune boundary, and an error
// that leaves nothing reads "apply failed".
func rejectionReason(err error) string {
	text := ""
	if err != nil {
		text = err.Error()
	}
	text = strings.ToValidUTF8(text, "�")
	text = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, text)
	text = strings.TrimSpace(text)
	if len(text) > maxRejectionReasonBytes {
		cut := maxRejectionReasonBytes
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = strings.TrimSpace(text[:cut])
	}
	if text == "" {
		return "apply failed"
	}
	return text
}
