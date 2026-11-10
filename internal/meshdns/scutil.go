package meshdns

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// scutilPath is the tool the macOS registrar writes configd's dynamic store
// with. Release builds set CGO_ENABLED=0, so the SystemConfiguration
// framework is out of reach, and scutil reads its commands on stdin.
const scutilPath = "/usr/sbin/scutil"

// scutilKeyPrefix starts every dynamic-store key plexd writes. plexd owns
// every key under it, whichever run wrote it: the keys do not name the mesh
// interface, because the kernel picks a new utunN on every start, and a
// revert must find what a killed run left behind.
const scutilKeyPrefix = "State:/Network/Service/plexd-meshdns-"

// scutilListPattern is the regular expression scutil's list command matches
// the keys against.
const scutilListPattern = scutilKeyPrefix + ".*/DNS"

// maxDomainsPerKey and maxDomainBytesPerKey bound the domains one key holds.
// scutil takes at most 99 values per d.add and keeps a value buffer of about
// 2048 bytes; these leave the margin NetBird's macOS configurator leaves.
const (
	maxDomainsPerKey     = 50
	maxDomainBytesPerKey = 1500
)

// defaultResolverOrder is the SearchOrder of the default-resolver entry a
// catch-all writes. It orders the entry ahead of the primary network
// service's resolver, as Tailscale's macOS configurator does.
const defaultResolverOrder = 100000

// scutilKeyRE matches a key a list line names that plexd owns.
var scutilKeyRE = regexp.MustCompile(`^` + regexp.QuoteMeta(scutilKeyPrefix) + `[a-z0-9-]+/DNS$`)

// ScutilRegistrar registers the mesh resolver with the macOS resolver. It
// writes DNS entries into configd's dynamic store, from which mDNSResponder
// takes its per-domain resolvers: one entry for the search domain, one or
// more for the routing domains, and with DefaultRoute a default-resolver
// entry. Each entry names the server's address and port and is bound to no
// interface: the server is a local address. The entries live in configd's
// memory, so a reboot clears whatever a killed run left behind.
type ScutilRegistrar struct {
	logger *slog.Logger
	// run feeds script to scutil on stdin and returns its combined output.
	run func(ctx context.Context, script string) ([]byte, error)
	// flush empties the host's DNS cache, so an answer cached before a
	// change, such as a negative one for a mesh name, does not outlive it.
	flush func(ctx context.Context) error
}

// scutilKey is one dynamic-store entry: its key and the d.add lines that
// build its dictionary.
type scutilKey struct {
	name  string
	lines []string
}

// Name returns "configd", the daemon that owns the dynamic store and hands
// mDNSResponder its DNS configuration, for the manager's log lines.
func (r *ScutilRegistrar) Name() string { return "configd" }

// Apply registers reg. It lists the keys plexd holds, then runs one script
// that removes every listed key reg does not write and writes the others:
// stale keys first and the default-resolver entry last, so a catch-all that
// ends stops taking every name before anything else changes, and one that
// starts takes them only after the zones are in place. After a script that
// fails it removes every plexd key once and returns the script's error. After
// one that succeeds it flushes the DNS cache. reg.Interface is used for
// logging only.
//
// When ctx has a deadline, the list and the script run under one that is a
// fifth of the remaining time earlier, and the removal after a failure runs
// under ctx, as ResolvedRegistrar does: exec does not start a command whose
// context is done, so a removal after a script that ran out ctx would never
// run.
//
// The error wraps ErrUnavailable when scutil is missing.
func (r *ScutilRegistrar) Apply(ctx context.Context, reg Registration) error {
	domains := reg.RoutingDomains
	if reg.SearchDomain != "" {
		domains = append([]string{reg.SearchDomain}, domains...)
	}
	for _, d := range domains {
		if !registrarDomainRE.MatchString(d) {
			return fmt.Errorf("meshdns: scutil: domain %q cannot be written to the dynamic store", d)
		}
	}
	stepCtx := ctx
	if deadline, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		stepCtx, cancel = context.WithDeadline(ctx, deadline.Add(-time.Until(deadline)/revertShare))
		defer cancel()
	}
	listed, err := r.list(stepCtx)
	if err != nil {
		return err
	}
	script := scutilScript(listed, scutilKeys(reg))
	if script == "" {
		return nil
	}
	if err := r.write(stepCtx, "apply", script); err != nil {
		if _, revertErr := r.removeAll(ctx); revertErr != nil {
			r.logger.Debug("revert after a failed registration failed",
				"interface", reg.Interface, "error", revertErr)
		}
		return err
	}
	r.flushCache(ctx)
	return nil
}

// Revert removes every key plexd holds in the dynamic store and flushes the
// DNS cache when it removed one. It does not use iface: the keys do not name
// the interface, so a revert also finds what a run on another utunN wrote. A
// missing scutil means there is nothing to remove, and Revert returns nil.
func (r *ScutilRegistrar) Revert(ctx context.Context, _ string) error {
	removed, err := r.removeAll(ctx)
	if errors.Is(err, ErrUnavailable) {
		return nil
	}
	if err != nil {
		return err
	}
	if removed {
		r.flushCache(ctx)
	}
	return nil
}

// removeAll removes every listed plexd key in one script and reports whether
// there was one to remove. It does not flush.
func (r *ScutilRegistrar) removeAll(ctx context.Context) (bool, error) {
	listed, err := r.list(ctx)
	if err != nil || len(listed) == 0 {
		return false, err
	}
	if err := r.write(ctx, "revert", scutilScript(listed, nil)); err != nil {
		return false, err
	}
	return true, nil
}

// list returns the plexd keys the dynamic store holds.
func (r *ScutilRegistrar) list(ctx context.Context) ([]string, error) {
	out, err := r.exec(ctx, "list", "open\nlist "+scutilListPattern+"\nquit\n")
	if err != nil {
		return nil, err
	}
	return parseScutilList(out), nil
}

// write runs a script that changes the dynamic store. scutil exits 0 when a
// command fails, so any output but "No such key", which a remove of a key
// that is already gone prints, counts as a failure.
func (r *ScutilRegistrar) write(ctx context.Context, op, script string) error {
	out, err := r.exec(ctx, op, script)
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" && line != "No such key" {
			return fmt.Errorf("meshdns: scutil: %s: %s", op, scutilOutput(out))
		}
	}
	return nil
}

// exec runs script and maps a failure of the run to the error op returns.
func (r *ScutilRegistrar) exec(ctx context.Context, op, script string) ([]byte, error) {
	out, err := r.run(ctx, script)
	switch {
	case err == nil:
		return out, nil
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, exec.ErrNotFound):
		r.logger.Debug("scutil not usable", "op", op, "error", err)
		return nil, fmt.Errorf("meshdns: scutil: %s is missing: %w", scutilPath, ErrUnavailable)
	case ctx.Err() != nil:
		return nil, fmt.Errorf("meshdns: scutil: %s: %w", op, ctx.Err())
	}
	if text := scutilOutput(out); text != "" {
		return nil, fmt.Errorf("meshdns: scutil: %s: %w: %s", op, err, text)
	}
	return nil, fmt.Errorf("meshdns: scutil: %s: %w", op, err)
}

// flushCache flushes the DNS cache. A failure changes nothing else: the
// registration is in place, and a stale answer goes with its TTL.
func (r *ScutilRegistrar) flushCache(ctx context.Context) {
	if err := r.flush(ctx); err != nil {
		r.logger.Debug("mesh dns cache flush failed", "error", err)
	}
}

// scutilKeys returns the entries reg writes, in the order they are written:
// the search domain, the routing domains in batches, the default resolver.
func scutilKeys(reg Registration) []scutilKey {
	server := []string{
		"d.add ServerAddresses * " + reg.Server.Addr().Unmap().String(),
		"d.add ServerPort # " + strconv.Itoa(int(reg.Server.Port())),
	}
	var keys []scutilKey
	if reg.SearchDomain != "" {
		keys = append(keys, scutilKey{
			name: scutilKeyPrefix + "search/DNS",
			lines: append(slices.Clone(server),
				"d.add SupplementalMatchDomains * "+reg.SearchDomain,
				"d.add SupplementalMatchDomainsNoSearch # 0",
			),
		})
	}
	for i, batch := range batchDomains(reg.RoutingDomains) {
		keys = append(keys, scutilKey{
			name: scutilKeyPrefix + "match-" + strconv.Itoa(i) + "/DNS",
			lines: append(slices.Clone(server),
				"d.add SupplementalMatchDomains * "+strings.Join(batch, " "),
				"d.add SupplementalMatchDomainsNoSearch # 1",
			),
		})
	}
	if reg.DefaultRoute {
		keys = append(keys, scutilKey{
			name: scutilKeyPrefix + "default/DNS",
			lines: append(slices.Clone(server),
				`d.add SupplementalMatchDomains * ""`,
				"d.add SearchOrder # "+strconv.Itoa(defaultResolverOrder),
			),
		})
	}
	return keys
}

// batchDomains splits domains, in order, into batches of at most
// maxDomainsPerKey domains and maxDomainBytesPerKey bytes, counting one
// space between each two domains.
func batchDomains(domains []string) [][]string {
	var batches [][]string
	var batch []string
	size := 0
	for _, d := range domains {
		if len(batch) > 0 && (len(batch) == maxDomainsPerKey || size+1+len(d) > maxDomainBytesPerKey) {
			batches = append(batches, batch)
			batch, size = nil, 0
		}
		if len(batch) > 0 {
			size++
		}
		batch = append(batch, d)
		size += len(d)
	}
	if len(batch) > 0 {
		batches = append(batches, batch)
	}
	return batches
}

// scutilScript returns the script that removes every listed key not among
// keys and then writes keys, or "" when it has nothing to do.
func scutilScript(listed []string, keys []scutilKey) string {
	var b strings.Builder
	b.WriteString("open\n")
	n := 0
	for _, name := range listed {
		if slices.ContainsFunc(keys, func(k scutilKey) bool { return k.name == name }) {
			continue
		}
		b.WriteString("remove " + name + "\n")
		n++
	}
	for _, k := range keys {
		b.WriteString("d.init\n")
		for _, line := range k.lines {
			b.WriteString(line + "\n")
		}
		b.WriteString("set " + k.name + "\n")
		n++
	}
	if n == 0 {
		return ""
	}
	b.WriteString("quit\n")
	return b.String()
}

// parseScutilList returns the plexd keys of the output of scutil's list
// command, which prints one "subKey [i] = <key>" line per key and
// "no subKey(s)." when none matches. Any other line is ignored.
func parseScutilList(out []byte) []string {
	var keys []string
	for line := range strings.SplitSeq(string(out), "\n") {
		i := strings.LastIndex(line, " = ")
		if i < 0 {
			continue
		}
		if key := strings.TrimSpace(line[i+len(" = "):]); scutilKeyRE.MatchString(key) {
			keys = append(keys, key)
		}
	}
	return keys
}

// scutilOutput returns the non-empty lines of out, trimmed and joined with
// "; ", for an error message.
func scutilOutput(out []byte) string {
	var lines []string
	for line := range strings.SplitSeq(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "; ")
}
