package meshdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// nrptPort is the only port the DNS Client sends a rule's queries to. A Name
// Resolution Policy Table rule names its servers by address alone.
const nrptPort = 53

// The names of the rule keys plexd writes. Every key starts with
// nrptRulePrefix: one match key per batch of domains, and with a catch-all an
// exemption for .local and the rule for every name.
const (
	nrptRulePrefix  = "plexd-meshdns-"
	nrptMatchPrefix = nrptRulePrefix + "match-"
	nrptExemptRule  = nrptRulePrefix + "exempt-local"
	nrptDefaultRule = nrptRulePrefix + "default"
)

// nrptRuleRE decides which listed key plexd owns, whichever run wrote it.
// Registry key names are case-insensitive, so it ignores case, and names
// are compared with strings.EqualFold.
var nrptRuleRE = regexp.MustCompile(`(?i)^plexd-meshdns-[a-z0-9-]+$`)

// errAdapterGone is what the host's setSearchList returns when no adapter
// carries the interface name.
var errAdapterGone = errors.New("no such adapter")

// nrptStore names one of the two places the DNS Client reads rules from: the
// local store, and the Group Policy store, which replaces the local one
// while its key exists.
type nrptStore string

const (
	nrptLocal  nrptStore = "local"
	nrptPolicy nrptStore = "policy"
)

// nrptRule is one rule key: its name, the namespaces it matches, each with a
// leading dot, and the server addresses, empty for an exemption.
type nrptRule struct {
	name       string
	namespaces []string
	servers    string
}

// nrptHost is the seam to the Windows registry, IP Helper, userenv.dll and
// dnsapi.dll. Tests replace it with a fake, so no test writes the registry of
// the host it runs on.
type nrptHost interface {
	// policyStoreExists reports whether the Group Policy store's key exists.
	policyStoreExists() (bool, error)
	// listRules returns the names of the rule keys in store, nil when the
	// store's key does not exist.
	listRules(store nrptStore) ([]string, error)
	// readRule returns a rule's namespaces and servers. ok is false when the
	// key or one of its values is missing, or its version or options are
	// not the ones plexd writes.
	readRule(store nrptStore, name string) (namespaces []string, servers string, ok bool, err error)
	// writeRule replaces the rule key with a volatile one holding rule.
	writeRule(store nrptStore, rule nrptRule) error
	// deleteRule deletes a rule key; a key that is gone is not an error.
	deleteRule(store nrptStore, name string) error
	// policyStoreEmpty reports whether the Group Policy store's key holds
	// neither a subkey nor a value.
	policyStoreEmpty() (bool, error)
	// deletePolicyStore deletes the Group Policy store's key; a key that is
	// gone is not an error.
	deletePolicyStore() error
	// setSearchList sets the IPv4 search list of the adapter named iface,
	// and returns errAdapterGone when no adapter carries that name.
	setSearchList(iface string, domains []string) error
	// generateGPNotification tells the DNS Client that machine policy
	// changed, without running the policy engine.
	generateGPNotification() error
	// refreshPolicy runs the machine policy engine.
	refreshPolicy() error
	// flush empties the DNS Client's cache.
	flush() error
	// watchPolicy calls onChange after every machine policy change until the
	// returned stop function runs, which waits for a running onChange.
	watchPolicy(onChange func()) (stop func(), err error)
}

// NRPTRegistrar registers the mesh resolver with the Windows DNS Client
// (Dnscache) through the Name Resolution Policy Table. It writes rule keys it
// owns into the registry: match keys for the search domain, the zones, the
// reverse zones and the forward zones, and with a catch-all a rule for every
// name plus an exemption for .local. It writes them into the Group Policy
// store too while that store's key exists, because the DNS Client then
// ignores the local rules, and it watches machine Group Policy to copy them
// again after every change. The rule keys are volatile, so a reboot clears
// whatever a killed run left. The search domain goes into the mesh adapter's
// own search list, because the table routes names but does not expand them.
type NRPTRegistrar struct {
	logger *slog.Logger
	host   nrptHost

	mu sync.Mutex
	// last is the registration the last successful Apply wrote: nil before
	// it, after a failed Apply and after Revert. The Group Policy watcher
	// writes it again.
	last *Registration
	// stopWatch stops the Group Policy watcher, and is nil while none runs.
	stopWatch func()
}

// nrptChanges reports what a pass over the stores found and changed.
type nrptChanges struct {
	// policyStore is whether the Group Policy store's key exists.
	policyStore bool
	// local and policy are whether the pass changed a key in that store.
	local  bool
	policy bool
}

// Name returns "Dnscache", the service name of the DNS Client, for the
// manager's log lines.
func (r *NRPTRegistrar) Name() string { return "Dnscache" }

// Apply registers reg. It checks every domain and the server's port before it
// touches the host, writes the rules into the local store and, while it
// exists, the Group Policy store, removing the stale keys first, and sets the
// adapter's search list. A catch-all that ends therefore stops taking every
// name before anything else changes, and one that starts takes them only
// after the zones are in place. After a failure it clears the search list,
// removes every plexd key and returns the first error. After a success it
// notifies Group Policy when its store changed, flushes the DNS Client's
// cache and starts the Group Policy watcher.
//
// The registry calls take no context, so ctx is checked once, before the
// first one. The error wraps ErrUnavailable when the server's port is not 53.
func (r *NRPTRegistrar) Apply(ctx context.Context, reg Registration) error {
	for _, d := range registrationDomains(reg) {
		if !registrarDomainRE.MatchString(d) {
			return fmt.Errorf("meshdns: nrpt: domain %q cannot be written to the Name Resolution Policy Table", d)
		}
	}
	if reg.Server.Port() != nrptPort {
		return fmt.Errorf("meshdns: nrpt: the Name Resolution Policy Table sends queries to port %d only, and the resolver listens on %s: %w",
			nrptPort, reg.Server, ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("meshdns: nrpt: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	changes, err := r.syncStores(nrptRules(reg))
	if err == nil {
		err = r.setSearchList(reg.Interface, searchList(reg))
	}
	if err != nil {
		r.last = nil
		r.rollback(reg.Interface, changes.policy)
		return err
	}
	if changes.policy {
		r.notifyPolicy(true)
	}
	r.flush()
	applied := reg
	applied.RoutingDomains = slices.Clone(reg.RoutingDomains)
	r.last = &applied
	if r.stopWatch == nil {
		stop, err := r.host.watchPolicy(r.policyChanged)
		if err != nil {
			r.logger.Debug("group policy watch failed", "error", err)
		} else {
			r.stopWatch = stop
		}
	}
	return nil
}

// Revert stops the Group Policy watcher, clears the search list of the
// adapter named iface, and removes every plexd key from both stores whatever
// iface is, the Group Policy store's key too when that left it empty. It
// notifies Group Policy when its store changed and flushes the DNS Client's
// cache when a key went. An adapter that is gone has no search list to
// clear, and Revert returns nil when there was nothing to remove.
func (r *NRPTRegistrar) Revert(ctx context.Context, iface string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("meshdns: nrpt: %w", err)
	}
	// The stop waits for a running policyChanged, which takes mu, so it runs
	// without mu held.
	r.mu.Lock()
	stop := r.stopWatch
	r.stopWatch, r.last = nil, nil
	r.mu.Unlock()
	if stop != nil {
		stop()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	var errs []error
	if err := r.host.setSearchList(iface, nil); err != nil && !errors.Is(err, errAdapterGone) {
		errs = append(errs, fmt.Errorf("meshdns: nrpt: search list %s: %w", iface, err))
	}
	changes, err := r.removeAll()
	errs = append(errs, err)
	if changes.policy {
		r.notifyPolicy(true)
	}
	if changes.local || changes.policy {
		r.flush()
	}
	return errors.Join(errs...)
}

// policyChanged is the Group Policy watcher's handler. It writes the last
// registration's rules again, into the Group Policy store too when that
// store's key appeared, and leaves the search list alone, which Group Policy
// does not change. A pass that changes nothing calls nothing more and logs
// nothing. It never refreshes policy: a refresh signals the watcher again.
// A failure removes nothing, and the next change tries again.
func (r *NRPTRegistrar) policyChanged() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		return
	}
	rules := nrptRules(*r.last)
	changes, err := r.syncStores(rules)
	if err != nil {
		r.logger.Warn("mesh dns re-apply after a group policy change failed", "error", err)
		return
	}
	if !changes.local && !changes.policy {
		return
	}
	if changes.policy {
		r.notifyPolicy(false)
	}
	r.flush()
	r.logger.Info("mesh dns registration re-applied after a group policy change",
		"group_policy", changes.policyStore,
		"rules", len(rules),
	)
}

// rollback undoes a failed Apply: it clears the search list and removes every
// plexd key, and notifies Group Policy when the failed pass or the removal
// touched its store. A failure of its own is logged, because Apply returns
// the error that started it.
func (r *NRPTRegistrar) rollback(iface string, policyTouched bool) {
	var errs []error
	if err := r.host.setSearchList(iface, nil); err != nil && !errors.Is(err, errAdapterGone) {
		errs = append(errs, fmt.Errorf("meshdns: nrpt: search list %s: %w", iface, err))
	}
	changes, err := r.removeAll()
	errs = append(errs, err)
	if policyTouched || changes.policy {
		r.notifyPolicy(true)
	}
	if err := errors.Join(errs...); err != nil {
		r.logger.Debug("revert after a failed registration failed", "interface", iface, "error", err)
	}
}

// syncStores makes the plexd keys of the local store, and of the Group Policy
// store while its key exists, exactly want.
func (r *NRPTRegistrar) syncStores(want []nrptRule) (nrptChanges, error) {
	var changes nrptChanges
	exists, err := r.host.policyStoreExists()
	if err != nil {
		return changes, fmt.Errorf("meshdns: nrpt: open policy store: %w", err)
	}
	changes.policyStore = exists
	if changes.local, err = r.syncStore(nrptLocal, want); err != nil {
		return changes, err
	}
	if exists {
		changes.policy, err = r.syncStore(nrptPolicy, want)
	}
	return changes, err
}

// syncStore deletes every plexd key of store that want does not name, the
// rule for every name first and the rest in listed order, and then writes
// each rule of want that is missing or differs. It reports whether it changed
// anything, also when it fails.
func (r *NRPTRegistrar) syncStore(store nrptStore, want []nrptRule) (bool, error) {
	listed, err := r.listOwned(store)
	if err != nil {
		return false, err
	}
	changed := false
	for _, name := range staleRules(listed, want) {
		if err := r.host.deleteRule(store, name); err != nil {
			return changed, fmt.Errorf("meshdns: nrpt: delete %s %s: %w", store, name, err)
		}
		changed = true
	}
	for _, rule := range want {
		namespaces, servers, ok, err := r.host.readRule(store, rule.name)
		if err != nil {
			return changed, fmt.Errorf("meshdns: nrpt: read %s %s: %w", store, rule.name, err)
		}
		if ok && servers == rule.servers && slices.Equal(namespaces, rule.namespaces) {
			continue
		}
		if err := r.host.writeRule(store, rule); err != nil {
			return changed, fmt.Errorf("meshdns: nrpt: write %s %s: %w", store, rule.name, err)
		}
		changed = true
	}
	return changed, nil
}

// removeAll deletes every plexd key from the local store and, while its key
// exists, the Group Policy store, the rule for every name first. When it
// deleted one from the Group Policy store and left that store empty, it
// deletes the store's key: an empty key alone keeps the DNS Client ignoring
// the local rules. It carries on past a failed delete and returns every
// failure.
func (r *NRPTRegistrar) removeAll() (nrptChanges, error) {
	var changes nrptChanges
	var errs []error
	removed, err := r.removeFrom(nrptLocal)
	changes.local = removed
	errs = append(errs, err)

	exists, err := r.host.policyStoreExists()
	if err != nil {
		errs = append(errs, fmt.Errorf("meshdns: nrpt: open policy store: %w", err))
		return changes, errors.Join(errs...)
	}
	changes.policyStore = exists
	if !exists {
		return changes, errors.Join(errs...)
	}
	removed, err = r.removeFrom(nrptPolicy)
	changes.policy = removed
	errs = append(errs, err)
	if removed {
		empty, err := r.host.policyStoreEmpty()
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("meshdns: nrpt: open policy store: %w", err))
		case empty:
			if err := r.host.deletePolicyStore(); err != nil {
				errs = append(errs, fmt.Errorf("meshdns: nrpt: delete policy store: %w", err))
			}
		}
	}
	return changes, errors.Join(errs...)
}

// removeFrom deletes every plexd key of store, the rule for every name first,
// and reports whether it deleted one. It carries on past a failed delete.
func (r *NRPTRegistrar) removeFrom(store nrptStore) (bool, error) {
	listed, err := r.listOwned(store)
	if err != nil {
		return false, err
	}
	removed := false
	var errs []error
	for _, name := range staleRules(listed, nil) {
		if err := r.host.deleteRule(store, name); err != nil {
			errs = append(errs, fmt.Errorf("meshdns: nrpt: delete %s %s: %w", store, name, err))
			continue
		}
		removed = true
	}
	return removed, errors.Join(errs...)
}

// listOwned returns the keys of store that plexd owns, in listed order.
func (r *NRPTRegistrar) listOwned(store nrptStore) ([]string, error) {
	names, err := r.host.listRules(store)
	if err != nil {
		return nil, fmt.Errorf("meshdns: nrpt: list %s: %w", store, err)
	}
	var owned []string
	for _, name := range names {
		if nrptRuleRE.MatchString(name) {
			owned = append(owned, name)
		}
	}
	return owned, nil
}

// notifyPolicy tells the DNS Client that machine policy changed, so it reads
// the Group Policy store again. GenerateGPNotification broadcasts the change
// without running the policy engine; when it fails and fallback is set, a
// forced refresh runs the machine policy engine instead. A failure is logged
// and changes nothing else: the rules are written, and the DNS Client takes
// them at the next policy application.
func (r *NRPTRegistrar) notifyPolicy(fallback bool) {
	err := r.host.generateGPNotification()
	if err == nil {
		r.logger.Debug("group policy notified", "via", "GenerateGPNotification")
		return
	}
	err = fmt.Errorf("GenerateGPNotification: %w", err)
	if fallback {
		refreshErr := r.host.refreshPolicy()
		if refreshErr == nil {
			r.logger.Debug("group policy notified", "via", "RefreshPolicyEx")
			return
		}
		err = fmt.Errorf("%w; RefreshPolicyEx: %w", err, refreshErr)
	}
	r.logger.Warn("mesh dns group policy notification failed", "error", err)
}

// flush empties the DNS Client's cache. A failure changes nothing else: the
// rules are in place, and a stale answer goes with its TTL.
func (r *NRPTRegistrar) flush() {
	if err := r.host.flush(); err != nil {
		r.logger.Debug("mesh dns cache flush failed", "error", err)
	}
}

// setSearchList sets the search list of the adapter named iface.
func (r *NRPTRegistrar) setSearchList(iface string, domains []string) error {
	if err := r.host.setSearchList(iface, domains); err != nil {
		return fmt.Errorf("meshdns: nrpt: search list %s: %w", iface, err)
	}
	return nil
}

// nrptRules returns the rules reg writes, in the order they are written: the
// search domain and the routing domains in batches, and with DefaultRoute the
// exemption for .local and, last, the rule for every name. RFC 6762 reserves
// .local for multicast DNS, so the exemption, a rule without servers, keeps
// those names away from the catch-all.
func nrptRules(reg Registration) []nrptRule {
	server := reg.Server.Addr().Unmap().String()
	var rules []nrptRule
	for i, batch := range batchDomains(registrationDomains(reg)) {
		namespaces := make([]string, len(batch))
		for j, d := range batch {
			namespaces[j] = "." + d
		}
		rules = append(rules, nrptRule{name: nrptMatchPrefix + strconv.Itoa(i), namespaces: namespaces, servers: server})
	}
	if reg.DefaultRoute {
		rules = append(rules,
			nrptRule{name: nrptExemptRule, namespaces: []string{".local"}},
			nrptRule{name: nrptDefaultRule, namespaces: []string{"."}, servers: server},
		)
	}
	return rules
}

// staleRules returns the listed keys that want does not name, the rule for
// every name first and the rest in listed order.
func staleRules(listed []string, want []nrptRule) []string {
	var first, rest []string
	for _, name := range listed {
		if slices.ContainsFunc(want, func(rule nrptRule) bool { return strings.EqualFold(rule.name, name) }) {
			continue
		}
		if strings.EqualFold(name, nrptDefaultRule) {
			first = append(first, name)
		} else {
			rest = append(rest, name)
		}
	}
	return append(first, rest...)
}

// registrationDomains returns the search domain, when set, followed by the
// routing domains.
func registrationDomains(reg Registration) []string {
	if reg.SearchDomain == "" {
		return reg.RoutingDomains
	}
	return append([]string{reg.SearchDomain}, reg.RoutingDomains...)
}

// searchList returns the adapter's search list for reg: the search domain,
// or none.
func searchList(reg Registration) []string {
	if reg.SearchDomain == "" {
		return nil
	}
	return []string{reg.SearchDomain}
}
