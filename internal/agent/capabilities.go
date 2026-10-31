package agent

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"reflect"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The capability report's timing is fixed: no configuration key exists for it,
// and CapabilityReporter holds these values in fields only so a test can
// shorten them.
const (
	// capabilityQuietPeriod is how long a notification waits for the next one
	// before the manifest is built. It folds a burst of file events into one
	// report, and it gives a write in progress time to finish, which matters
	// because the first digest the control plane sees of a hook becomes its
	// baseline. It does not replace an atomic install.
	capabilityQuietPeriod = 1 * time.Second

	// capabilityMaxDelay bounds that wait from the first notification, so a
	// hook rewritten in a loop is still reported.
	capabilityMaxDelay = 10 * time.Second

	// capabilityRetryMin is the delay after the first failed send. It doubles
	// with each further failure up to capabilityRetryMax, which holds a
	// refused manifest to about 12 attempts an hour.
	capabilityRetryMin = 5 * time.Second
	capabilityRetryMax = 5 * time.Minute
)

// CapabilityClient sends the capability manifest to the control plane.
type CapabilityClient interface {
	UpdateCapabilities(ctx context.Context, nodeID string, caps api.CapabilityManifestRequest) error
}

// CapabilityReporter owns the manifest at PUT /v1/nodes/{node_id}/capabilities.
// It sends the manifest when Run starts, sends it again after a Notify that
// changed it, and retries a failed send until one is accepted. Every attempt
// calls build, so a retry always carries the newest content.
//
// DECISION: a manifest equal to the last accepted one is not sent, and nothing
// is re-sent on a timer. The control plane raises an integrity alert on every
// accepted PUT that carries a drifted hook, whether or not the manifest
// changed, so a repeat would only repeat the alert. The accepted manifest lives
// in memory, so a restart always sends once.
//
// DECISION: every failure retries, a refusal included. A refused PUT stores
// nothing and raises nothing at the control plane, capabilityRetryMax bounds
// the rate, and a control plane that gets upgraded then clears the refusal
// without an agent restart.
type CapabilityReporter struct {
	nodeID string
	client CapabilityClient
	build  func() api.CapabilityManifestRequest
	logger *slog.Logger

	// These hold the capability* constants, so a test can shorten them.
	quietPeriod time.Duration
	maxDelay    time.Duration
	retryMin    time.Duration
	retryMax    time.Duration

	// jitter spreads a retry delay. It is Jitter outside tests.
	jitter func(time.Duration) time.Duration

	// now reads the clock a Retry-After hold is measured on. It is time.Now
	// outside tests.
	now func() time.Time

	// notify carries at most one pending notification, because one attempt
	// reads whatever every earlier notification changed.
	notify chan struct{}

	// accepted is the manifest the control plane is known to hold, and nil
	// when that is unknown. Only the Run goroutine reads and writes it, like
	// every field below.
	accepted *api.CapabilityManifestRequest

	// attempted is the manifest of the last failed send, which tells a
	// notification that changed nothing from one that has news to deliver.
	attempted *api.CapabilityManifestRequest

	// backoff is the nominal delay the next failure waits.
	backoff time.Duration

	// holdUntil is when the wait a Retry-After imposed ends. A notification
	// sends nothing before it, whatever it changed.
	holdUntil time.Time

	// retry fires the next attempt while retryArmed is set. An expired timer
	// stays armed until Run receives from it.
	retry      *time.Timer
	retryArmed bool
}

// NewCapabilityReporter creates a CapabilityReporter that reports for nodeID
// through client. It calls build on every attempt, always on the Run goroutine.
func NewCapabilityReporter(nodeID string, client CapabilityClient, build func() api.CapabilityManifestRequest, logger *slog.Logger) *CapabilityReporter {
	return &CapabilityReporter{
		nodeID:      nodeID,
		client:      client,
		build:       build,
		logger:      logger.With("component", "capability-report"),
		quietPeriod: capabilityQuietPeriod,
		maxDelay:    capabilityMaxDelay,
		retryMin:    capabilityRetryMin,
		retryMax:    capabilityRetryMax,
		jitter:      Jitter,
		now:         time.Now,
		notify:      make(chan struct{}, 1),
	}
}

// Notify asks for an attempt once the quiet period ends. It never blocks, so it
// is safe to call from the hook watcher's onChange and before Run starts or
// after it ends.
func (r *CapabilityReporter) Notify() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// Run makes one attempt with no quiet period, so a failed boot PUT retries, and
// then attempts on every notification and whenever the retry timer fires, until
// ctx is cancelled. Run always returns nil.
func (r *CapabilityReporter) Run(ctx context.Context) error {
	r.backoff = r.retryMin
	r.retry = time.NewTimer(r.retryMin)
	r.retry.Stop()
	defer r.retry.Stop()

	r.attempt(ctx, false)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.retry.C:
			r.retryArmed = false
			r.attempt(ctx, false)
		case <-r.notify:
			if !r.waitQuiet(ctx) {
				return nil
			}
			r.attempt(ctx, true)
		}
	}
}

// waitQuiet returns true once no notification has arrived for the quiet period
// or maxDelay has passed, whichever comes first, and false when ctx ends. A
// retry that falls due meanwhile stays pending on its timer, so it runs right
// after the attempt this wait leads to.
func (r *CapabilityReporter) waitQuiet(ctx context.Context) bool {
	quiet := time.NewTimer(r.quietPeriod)
	defer quiet.Stop()
	limit := time.NewTimer(r.maxDelay)
	defer limit.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-r.notify:
			quiet.Reset(r.quietPeriod)
		case <-quiet.C:
			return true
		case <-limit.C:
			return true
		}
	}
}

// attempt builds the manifest and sends it unless the control plane already
// holds it. notified says a notification asked for the attempt, which unlike
// the retry timer may have to leave the send to that timer.
func (r *CapabilityReporter) attempt(ctx context.Context, notified bool) {
	manifest := r.build()
	if r.accepted != nil && reflect.DeepEqual(*r.accepted, manifest) {
		r.clearRetry()
		return
	}
	if notified && r.deferToRetry(manifest) {
		return
	}
	r.send(ctx, manifest)
}

// deferToRetry reports whether a notification's attempt should send nothing and
// leave delivery to the retry timer, which builds the newest content when it
// fires.
//
// A manifest equal to the failed one has no news for a control plane that just
// refused or missed it. Without this check the boot scan's notification, which
// a real boot always has queued, would retry a failed first PUT after the quiet
// period, and a looping touch on a hook would defeat the backoff.
//
// A Retry-After hold applies to any content. It outlives a retry that a revert
// to the accepted manifest stopped, so the next change arms the timer for what
// is left of the hold rather than sending into it.
func (r *CapabilityReporter) deferToRetry(manifest api.CapabilityManifestRequest) bool {
	now := r.now()
	if now.Before(r.holdUntil) {
		if !r.retryArmed {
			r.armRetry(r.holdUntil.Sub(now))
		}
		return true
	}
	return r.retryArmed && r.attempted != nil && reflect.DeepEqual(*r.attempted, manifest)
}

// send makes one PUT of manifest and records the outcome.
func (r *CapabilityReporter) send(ctx context.Context, manifest api.CapabilityManifestRequest) {
	if err := r.client.UpdateCapabilities(ctx, r.nodeID, manifest); err != nil {
		r.recordFailure(ctx, manifest, err)
		return
	}

	r.accepted = &manifest
	r.attempted = nil
	r.holdUntil = time.Time{}
	r.clearRetry()
	r.logger.InfoContext(ctx, "agent: capability report: accepted",
		"declared_hooks", len(manifest.DeclaredHooks),
		"plexd_hooks", len(manifest.PlexdHooks),
	)
}

// recordFailure arms the retry for a failed send of manifest. A cancelled ctx is
// shutdown, not a failure, so it records and logs nothing.
//
// A refused credential costs no I/O and says nothing about the control plane,
// so it leaves the backoff and attempted alone and retries at the shortest
// delay. Delivery then resumes within about one such delay of the mark lifting,
// however long the backoff had grown. It logs at Debug because the heartbeat
// names the cause once when it parks the agent.
//
// RetryAfter is deliberately not capped by retryMax: the control plane asked for
// that wait.
func (r *CapabilityReporter) recordFailure(ctx context.Context, manifest api.CapabilityManifestRequest, err error) {
	if ctx.Err() != nil {
		return
	}

	if errors.Is(err, api.ErrCredentialRefused) {
		wait := r.jitter(r.retryMin)
		r.armRetry(wait)
		r.logger.DebugContext(ctx, "agent: capability report: send failed", "error", err, "retry_in", wait)
		return
	}

	var retryAfter time.Duration
	var apiErr *api.APIError
	isAPIErr := errors.As(err, &apiErr)
	if isAPIErr {
		retryAfter = apiErr.RetryAfter
	}

	// A 4xx stopped before the write, so the row still holds the accepted
	// manifest. Any other failure proves nothing: a PUT that committed can
	// lose its response, and an accepted manifest kept past that would skip
	// the send that puts the row right after a revert.
	if !isAPIErr || apiErr.StatusCode < 400 || apiErr.StatusCode >= 500 {
		r.accepted = nil
	}
	r.attempted = &manifest

	wait := nextDelay(r.backoff, retryAfter, r.jitter)
	r.backoff = min(r.backoff*2, r.retryMax)
	if retryAfter > 0 {
		r.holdUntil = r.now().Add(retryAfter)
	}
	r.armRetry(wait)
	r.logger.WarnContext(ctx, "agent: capability report: send failed", "error", err, "retry_in", wait)
}

// armRetry makes the retry timer fire after d, replacing any earlier deadline.
func (r *CapabilityReporter) armRetry(d time.Duration) {
	r.retry.Reset(d)
	r.retryArmed = true
}

// clearRetry stops the retry timer and resets the backoff, for when the control
// plane holds the current manifest and nothing is left to deliver.
func (r *CapabilityReporter) clearRetry() {
	r.retry.Stop()
	r.retryArmed = false
	r.backoff = r.retryMin
}

// nextDelay returns how long to wait after a failed send: the jittered backoff,
// or retryAfter when that is longer.
func nextDelay(backoff, retryAfter time.Duration, jitter func(time.Duration) time.Duration) time.Duration {
	return max(jitter(backoff), retryAfter)
}

// Jitter returns d moved by a random amount of up to 25% either way, the spread
// the SSE reconnect backoff uses, so agents that failed together do not retry
// in step.
func Jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.75 + rand.Float64()/2))
}
