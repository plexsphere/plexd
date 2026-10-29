package tunnel

// A tcp session's session_active rows follow the agent contract, as
// docs/reference/networking/secure-access-tunneling.md#activity-reports
// describes it. A tunnel posts at most one row per interval of
// min(60 s, idle_timeout_seconds/4), or 60 s for an entry without an idle
// window. The first row goes out as soon as a byte crosses after an interval
// without a row; after a row, one more goes out at the end of each interval in
// which bytes crossed, and none once a whole interval passed without a byte. A
// 409 session_already_revoked or session_expired stops the reports, a 400 is
// warned about once and not re-sent, every other failure is retried at the end
// of the interval, and no answer closes the tunnel.

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// sessionActiveReportTimeout bounds one session_active post. Like
// sessionStartedReportTimeout it stays above api.DefaultConnectTimeout.
const sessionActiveReportTimeout = 15 * time.Second

// maxActivityReportInterval is the longest interval between two
// session_active rows of a tunnel that keeps forwarding bytes.
const maxActivityReportInterval = 60 * time.Second

// activityReportInterval returns min(60 s, idle_timeout_seconds/4), or 60 s
// for an entry without an idle window. It divides the Duration rather than the
// seconds, so a window of 10 s reports every 2.5 s instead of every 2.
func activityReportInterval(idleTimeoutSeconds int) time.Duration {
	if idleTimeoutSeconds <= 0 {
		return maxActivityReportInterval
	}
	return min(maxActivityReportInterval, time.Duration(idleTimeoutSeconds)*time.Second/4)
}

// activityReport posts a tcp session's session_active rows.
type activityReport struct {
	reporter  TCPActivityReporter
	sessionID string
	interval  time.Duration
	crossed   atomic.Bool   // bytes crossed that no delivered row covers yet
	quiet     atomic.Bool   // no row is due at an interval's end; the next byte posts at once
	kick      chan struct{} // capacity 1; observe wakes a quiet run through it
}

// newActivityReport returns a quiet report: no row is due yet, so the first
// byte that crosses posts one at once.
func newActivityReport(reporter TCPActivityReporter, sessionID string, interval time.Duration) *activityReport {
	a := &activityReport{
		reporter:  reporter,
		sessionID: sessionID,
		interval:  interval,
		kick:      make(chan struct{}, 1),
	}
	a.quiet.Store(true)
	return a
}

// observe marks that bytes crossed the tunnel. The forwarding path calls it for
// every chunk, so it never blocks: it costs two atomic operations, and a kick
// only while the report is quiet. A full kick channel already holds the wake-up
// this byte needs.
func (a *activityReport) observe() {
	a.crossed.Store(true)
	if a.quiet.Load() {
		select {
		case a.kick <- struct{}{}:
		default:
		}
	}
}

// run posts the session's rows until ctx is done, or until the control plane
// answers that the session is no longer live. The rows are posted on the
// session's own goroutine, so a slow post delays only this session's next row.
//
// observe and run hand the bytes over through crossed and quiet alone, and the
// order of their atomic operations is what keeps a byte from being lost
// between them. observe stores crossed before it reads quiet; run, going quiet,
// stores quiet before it reads crossed a second time. So a byte either is seen
// by that second read, or sees quiet true and kicks.
func (a *activityReport) run(ctx context.Context, logger *slog.Logger) {
	var (
		due    <-chan time.Time // nil while quiet
		warned bool             // a 400 was already warned about
	)
	for {
		var kick <-chan struct{}
		if due == nil {
			kick = a.kick // a kick is only read while quiet, so it can never post early
		}
		select {
		case <-ctx.Done():
			return
		case <-kick:
			if !a.crossed.Load() {
				continue // a kick left over from an earlier quiet spell
			}
			a.quiet.Store(false)
		case <-due:
			if !a.crossed.Load() {
				a.quiet.Store(true)
				if !a.crossed.Load() { // a byte that still saw quiet false did not kick
					due = nil
					continue
				}
				a.quiet.Store(false)
			}
		}
		a.crossed.Store(false)
		due = time.After(a.interval) // measured from the post's start
		postCtx, cancel := context.WithTimeout(ctx, sessionActiveReportTimeout)
		err := a.reporter.ReportSessionActive(postCtx, a.sessionID)
		cancel()

		switch {
		case err == nil:
			logger.Debug("session_active row recorded")
		case ctx.Err() != nil:
			// The session closed during the post, so the error says nothing
			// about the row.
			return
		case api.IsSessionRevokedOrExpired(err):
			// quiet stays false, so observe never kicks a run that has returned.
			logger.Info("session no longer live server-side; stopping its activity reports", "error", err)
			return
		case errors.Is(err, api.ErrBadRequest):
			// The row's bytes are a constant, so re-sending them draws the same
			// 400, and crossed is not restored. Later bytes still post, because
			// a control plane rolled forward mid-session accepts the next row.
			if !warned {
				warned = true
				logger.Warn("control plane refused the session_active row; it revokes the tunnel one idle timeout after it started", "error", err)
			}
		default:
			// Not recorded, so the end of the interval retries the row even if
			// the tunnel went quiet meanwhile. A session with an idle window
			// ends the retries with its own idle close.
			a.crossed.Store(true)
			logger.Warn("session activity report failed; retrying at the end of the interval", "error", err)
		}
	}
}
