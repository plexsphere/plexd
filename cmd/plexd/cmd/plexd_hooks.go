package cmd

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/agent"
	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/kubernetes"
)

// The inventory's timing is fixed: no configuration key exists for it, and
// plexdHookInventory holds these values in fields only so a test can shorten
// them.
const (
	// plexdHookWatchTimeout ends every watch, because a stream can die silently
	// with nothing on the wire to report it. Together with the list after each
	// open it bounds how stale the inventory can get.
	plexdHookWatchTimeout = 10 * time.Minute

	// plexdHookCoalesceDelay is how long the first event of a burst waits before
	// the list. An open replays every existing resource as ADDED, so without it
	// each open would cost one list per resource.
	plexdHookCoalesceDelay = 1 * time.Second

	// plexdHookStableStream is how long a stream must live for the next open to
	// follow at once. A stream that ends sooner backs off like a failure, or an
	// API server that drops each watch would be asked for lists in a tight loop.
	plexdHookStableStream = 1 * time.Minute

	// plexdHookBackoffMin is the delay after the first short cycle. It doubles
	// with each further one up to plexdHookBackoffMax, so a role that grants list
	// and not watch settles at one list every 5 minutes.
	plexdHookBackoffMin = 5 * time.Second
	plexdHookBackoffMax = 5 * time.Minute
)

// plexdHookVersion identifies one state of a PlexdHook resource.
type plexdHookVersion struct {
	name            string
	resourceVersion string
}

// plexdHookInventory keeps the plexd_hooks list of the capability manifest
// current. It lists once when it is built and then follows a watch for as long
// as run runs.
//
// DECISION: the watch is only a change signal, and the list stays the source of
// truth. That needs no resourceVersion bookkeeping, and the list after every open
// catches a deletion that happened with no watch running.
//
// DECISION: a list that fails keeps the last good snapshot. Every PUT replaces
// the control plane's row whole, so reporting an empty list on a transient API
// server failure would erase every PlexdHook from it.
type plexdHookInventory struct {
	// lister is nil when the agent runs outside a cluster or has no usable
	// namespace or client. run then returns at once.
	lister    plexdHookLister
	namespace string
	logger    *slog.Logger

	// These hold plexdHookDiscoveryTimeout and the plexdHook* constants above, so
	// a test can shorten them.
	listTimeout  time.Duration
	watchTimeout time.Duration
	coalesce     time.Duration
	stableStream time.Duration
	backoffMin   time.Duration
	backoffMax   time.Duration

	// jitter spreads the watch timeout and the backoff, so a fleet does not stay
	// in phase after an API server restart. It is agent.Jitter outside tests.
	jitter func(time.Duration) time.Duration

	// mu guards hooks, which the capability reporter reads through snapshot. The
	// slice is replaced and never mutated, so a snapshot stays valid after the
	// lock is released.
	mu    sync.Mutex
	hooks []api.DiscoveredPlexdHook

	// versions is what the last successful list returned, sorted by name.
	// degraded is set while an outage lasts, so only its first failure warns.
	// Only the goroutine that called run reads and writes either once the
	// constructor has returned.
	versions []plexdHookVersion
	degraded bool
}

// newPlexdHookInventory lists the PlexdHook resources in the namespace the pod's
// ServiceAccount runs in. Outside a cluster it returns an empty inventory without
// a word. Inside one, every failure (no namespace, no lister, a list refused for
// want of RBAC or a CRD, or one that outlives its budget) logs one warning and
// leaves the snapshot nil: the manifest goes out without plexd_hooks and boot
// carries on.
//
// A failed list keeps its lister and starts the inventory degraded. run then
// recovers it, and a cluster with no CRD logs that one warning in total.
func newPlexdHookInventory(ctx context.Context, env *kubernetes.KubernetesEnvironment, newLister func(*kubernetes.KubernetesEnvironment) (plexdHookLister, error), logger *slog.Logger) *plexdHookInventory {
	inv := &plexdHookInventory{
		logger:       logger,
		listTimeout:  plexdHookDiscoveryTimeout,
		watchTimeout: plexdHookWatchTimeout,
		coalesce:     plexdHookCoalesceDelay,
		stableStream: plexdHookStableStream,
		backoffMin:   plexdHookBackoffMin,
		backoffMax:   plexdHookBackoffMax,
		jitter:       agent.Jitter,
	}

	if env == nil || !env.InCluster {
		return inv
	}
	namespace := strings.TrimSpace(env.Namespace)
	if namespace == "" {
		logger.Warn("plexd hook discovery skipped: the ServiceAccount namespace is empty")
		return inv
	}
	lister, err := newLister(env)
	if err != nil {
		logger.Warn("plexd hook discovery skipped", "error", err)
		return inv
	}
	inv.lister, inv.namespace = lister, namespace

	// Nothing is listening yet: the reporter reads the snapshot for its first
	// manifest, so there is nobody to notify.
	if err := inv.refresh(ctx, func() {}); err != nil {
		logger.Warn("plexd hook discovery failed", "namespace", namespace, "error", err)
		inv.degraded = true
	}
	return inv
}

// snapshot returns the manifest entries of the last successful list, and nil when
// there are none, so the omitempty key stays off the wire. The caller must not
// modify the result.
func (inv *plexdHookInventory) snapshot() []api.DiscoveredPlexdHook {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return inv.hooks
}

// run keeps the snapshot current and calls notify after each change, until ctx
// ends. It returns at once when the inventory has no lister. notify must not
// block.
func (inv *plexdHookInventory) run(ctx context.Context, notify func()) {
	if inv.lister == nil {
		return
	}

	backoff := inv.backoffMin
	for {
		lived, err := inv.watchOnce(ctx, notify)
		if ctx.Err() != nil {
			return
		}
		if err == nil && lived >= inv.stableStream {
			backoff = inv.backoffMin
			continue
		}

		wait := inv.jitter(backoff)
		backoff = min(backoff*2, inv.backoffMax)
		switch {
		case err == nil:
			inv.logger.Debug("plexd hook watch ended early", "namespace", inv.namespace, "retry_in", wait)
		case inv.degraded:
			inv.logger.Debug("plexd hook watch failed", "namespace", inv.namespace, "error", err, "retry_in", wait)
		default:
			inv.degraded = true
			inv.logger.Warn("plexd hook watch failed", "namespace", inv.namespace, "error", err, "retry_in", wait)
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// watchOnce opens one watch, lists, and follows the stream until it ends. It
// returns how long the stream lived and why following it stopped, with a nil
// error for a stream that just ended.
//
// An outage ends only when the open and its list both succeed. A failed open
// still lists, which is all a role that grants list and not watch gets, but it
// keeps its error, so such a role stays in the outage it warned about once.
//
// The list runs on ctx and not on the watch context, so a watch that times out
// does not take down the list that finishes it.
func (inv *plexdHookInventory) watchOnce(ctx context.Context, notify func()) (time.Duration, error) {
	watchCtx, cancel := context.WithTimeout(ctx, inv.jitter(inv.watchTimeout))
	defer cancel()

	events, openErr := inv.lister.WatchPlexdHooks(watchCtx, inv.namespace)
	opened := time.Now()
	listErr := inv.refresh(ctx, notify)
	if openErr != nil {
		return 0, openErr
	}
	if listErr != nil {
		return 0, listErr
	}

	if inv.degraded {
		inv.degraded = false
		inv.logger.Info("plexd hook watch restored", "namespace", inv.namespace)
	}
	err := inv.follow(ctx, events, notify)
	return time.Since(opened), err
}

// follow turns the events on one stream into lists. The first event of a burst
// starts the coalesce timer once, and the events after it are received and
// discarded until it fires, so a burst costs one list however long it is. The
// timer is not restarted, so a steady stream of events cannot hold the list off.
//
// A stream that closes while the timer runs finishes with one list, because what
// comes next may be a backoff. A failed list ends the following with its error.
func (inv *plexdHookInventory) follow(ctx context.Context, events <-chan kubernetes.PlexdHookEvent, notify func()) error {
	timer := time.NewTimer(inv.coalesce)
	timer.Stop()
	defer timer.Stop()

	pending := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-events:
			switch {
			case !ok && pending:
				return inv.refresh(ctx, notify)
			case !ok:
				return nil
			case !pending:
				pending = true
				timer.Reset(inv.coalesce)
			}
		case <-timer.C:
			pending = false
			if err := inv.refresh(ctx, notify); err != nil {
				return err
			}
		}
	}
}

// refresh lists once, under listTimeout, and replaces the snapshot when the list
// changed. A failure leaves everything as it was. The same (Name,
// ResourceVersion) pairs skip the conversion and notify, so a hook the conversion
// omits logs its warning once per change and not once per watch timeout.
func (inv *plexdHookInventory) refresh(ctx context.Context, notify func()) error {
	listCtx, cancel := context.WithTimeout(ctx, inv.listTimeout)
	defer cancel()

	hooks, err := inv.lister.ListPlexdHooks(listCtx, inv.namespace)
	if err != nil {
		return err
	}

	versions := plexdHookVersions(hooks)
	if slices.Equal(versions, inv.versions) {
		return nil
	}
	inv.versions = versions

	converted := discoveredPlexdHooks(hooks, inv.logger)
	inv.mu.Lock()
	inv.hooks = converted
	inv.mu.Unlock()
	notify()
	return nil
}

// plexdHookVersions returns the (Name, ResourceVersion) pairs of hooks, sorted by
// name, because the API server promises no order. Names are unique within the one
// namespace listed, so the sort is total.
func plexdHookVersions(hooks []kubernetes.PlexdHook) []plexdHookVersion {
	versions := make([]plexdHookVersion, len(hooks))
	for i, h := range hooks {
		versions[i] = plexdHookVersion{name: h.Name, resourceVersion: h.ResourceVersion}
	}
	slices.SortFunc(versions, func(a, b plexdHookVersion) int {
		return strings.Compare(a.name, b.name)
	})
	return versions
}
