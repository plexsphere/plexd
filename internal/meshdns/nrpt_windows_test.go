//go:build windows

package meshdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// The real test's adapter, names and addresses, the ones the macOS test uses.
// 10.255.249.1/30 is used by no other real test on Windows. The resolver
// listens on 127.0.0.1:53, as plexd's does on Windows. The names live under
// TLDs no public resolver answers, and the other addresses are documentation
// ranges.
const (
	realAdapter     = "plexd-dnstest"
	realAddress     = "10.255.249.1/30"
	realMeshIP      = "10.255.249.1"
	realListen      = "127.0.0.1:53"
	realZone        = "plexd-test.internal"
	realReverseZone = "2.0.192.in-addr.arpa"
	realHost        = "host-a.plexd-test.internal"
	realHostIP      = "192.0.2.10"
	realForward     = "fwd.example"
	realResolver    = "192.0.2.53"
	realStubIP      = "198.51.100.53"
)

// The real test's bounds. A check polls every pollInterval, for up to
// localWait where the local store decides and up to policyWait where the
// Group Policy store does, because NetBird's code reports changes there
// taking "a minute or more". The watcher has copyWait to copy the rules after
// a machine policy change, and counts as done with one once it ran no
// handler for watchQuiet. A lookup gets lookupTimeout to answer, and
// lookupLimit bounds the call itself.
const (
	pollInterval  = 500 * time.Millisecond
	localWait     = 10 * time.Second
	copyWait      = 120 * time.Second
	policyWait    = 180 * time.Second
	stillWait     = 10 * time.Second
	watchQuiet    = 10 * time.Second
	lookupTimeout = 5 * time.Second
	lookupLimit   = time.Minute
	diagTimeout   = 20 * time.Second
)

// The rule keys plexd writes for the test's registration with the catch-all,
// sorted.
var realRuleKeys = []string{"plexd-meshdns-default", "plexd-meshdns-exempt-local", "plexd-meshdns-match-0"}

// TestNRPTRegistrar_Real registers a real mesh resolver, listening on
// 127.0.0.1:53 beside a real Wintun adapter, as plexd does on Windows, in the
// Name Resolution Policy Table and the adapter's search list, and resolves
// through the DNS Client with Go's resolver, which on Windows calls
// GetAddrInfoW for names and DnsQuery for addresses (net/lookup_windows.go),
// as other programs on the host do. It is the only test that proves the
// facts the registrar rests on, which come from Tailscale's and NetBird's
// code rather than a measurement; each check names the fact it proves. It
// logs how long each wait took, which gives the delays the documentation
// lists as unmeasured, and the registrar's lines, which name the route each
// Group Policy notification took.
//
// It runs four phases: (a) an Apply without the catch-all, (b) one with it,
// (c) Group Policy taking over the table while the registration stands, and
// (d) the Revert.
//
// It changes the host's resolver configuration while it runs, and it creates
// the Group Policy store's key, so it needs PLEXD_TEST_REAL_RESOLVER=1 on top
// of Administrator, and it skips on a host whose Group Policy configures the
// table. It runs as LocalSystem only, as plexd's service does: the DNS Client
// reads the Group Policy store's key, its rules and its removal only after a
// machine policy change, and GenerateGPNotification, which the test and the
// registrar send that change with, is measured to work for LocalSystem. A
// change the DNS Client never read would leave it on the rules it read
// last, the rule for every name included, with nothing listening on
// 127.0.0.1:53 once the test ends. CI runs it as its own step on the
// Windows runner, as LocalSystem through a scheduled task.
func TestNRPTRegistrar_Real(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_RESOLVER") != "1" {
		t.Skip("set PLEXD_TEST_REAL_RESOLVER=1 to change the host's resolver configuration")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("registering a resolver needs Administrator")
	}
	if !isLocalSystem(t) {
		t.Skip("run as LocalSystem, as plexd's service does: the DNS Client reads the Group Policy store only after GenerateGPNotification")
	}
	// The test creates and deletes the Group Policy store's key, which would
	// destroy a policy's rules.
	if keyExists(t, nrptPolicyPath) {
		t.Skip("group policy configures the NRPT on this host")
	}
	ctx := context.Background()
	// The registrar's lines go into the test log, so the CI log shows the
	// route each Group Policy notification took, and into regLogs, which the
	// checks count.
	regLogs := &logRecorder{}
	logger := newTestLogger(t, regLogs)

	wg := wireguard.NewWindowsController(slog.New(slog.DiscardHandler))
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	if err := wg.CreateInterface(realAdapter, key[:], 0); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	t.Cleanup(func() {
		if err := wg.DeleteInterface(realAdapter); err != nil {
			t.Errorf("DeleteInterface: %v", err)
		}
	})
	if err := wg.ConfigureAddress(realAdapter, realAddress); err != nil {
		t.Fatalf("ConfigureAddress: %v", err)
	}
	if err := wg.SetInterfaceUp(realAdapter); err != nil {
		t.Fatalf("SetInterfaceUp: %v", err)
	}
	searchListPath := adapterSettingsPath(t, waitForAdapter(t).Index)

	records, skipped := BuildRecords(api.NodeStateDNS{
		SearchDomain: realZone,
		Zones:        []string{realZone},
		Hosts:        []api.NodeStateDNSHost{{NodeID: "node-a", FQDN: realHost, MeshIP: realHostIP}},
		ReverseZones: []string{realReverseZone},
	})
	if len(skipped) > 0 {
		t.Fatalf("BuildRecords skipped %q", skipped)
	}

	// The fake stands in for the forward zone's and the catch-all's
	// resolver: every A query gets the stub's address, anything else an
	// empty NOERROR.
	fake := newFakeResolver(t, func(query []byte) [][]byte {
		var p dnsmessage.Parser
		if _, err := p.Start(query); err == nil {
			if q, err := p.Question(); err == nil && q.Type != dnsmessage.TypeA {
				return answerRCode(dnsmessage.RCodeSuccess)(query)
			}
		}
		return answerA(realStubIP)(query)
	})
	// The server's Debug lines name every source it refuses, which is what
	// tells a query that never arrived from one the source rule dropped.
	serverLogs := &logRecorder{}
	s := NewServer(netip.MustParseAddrPort(realListen), slog.New(&recordingHandler{rec: serverLogs}))
	t.Cleanup(func() {
		if t.Failed() {
			logServerLines(t, serverLogs)
		}
	})
	s.upstream.target = routeFakes(t, map[string]*fakeResolver{realResolver: fake})
	fwd, skipped := BuildForwarding(api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{{Zone: realForward, Resolvers: []string{realResolver}}},
		CatchAll:     []string{realResolver},
	}, records, s.Addr().Addr())
	if len(skipped) > 0 {
		t.Fatalf("BuildForwarding skipped %q", skipped)
	}
	s.SetRecords(records)
	s.SetForwarding(fwd)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	t.Cleanup(serve(t, s))

	r := NewNRPTRegistrar(logger)
	// The real host, with the watcher's handler runs counted, so phase (c)
	// can tell when the watcher has handled a machine policy change.
	watch := &watchCountingHost{}
	r.host = watch
	// Cleanups run last in first: the revert goes before the server stops
	// and the adapter goes, so a failed check leaves the runner's resolver as
	// it found it. A revert removes nothing from a policy store it did not
	// write to, so the key the test created goes here too. A machine policy
	// change then makes the DNS Client read the stores again, whatever state
	// a failed check left them in: without one it would keep the rules it
	// read last, the rule for every name included.
	t.Cleanup(func() {
		if err := r.Revert(context.Background(), realAdapter); err != nil {
			t.Errorf("Revert in cleanup: %v", err)
		}
		err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptPolicyPath)
		if err != nil && !errors.Is(err, registry.ErrNotExist) {
			t.Errorf("delete the Group Policy store's key in cleanup: %v", err)
		}
		if err := (winNRPTHost{}).generateGPNotification(); err != nil {
			t.Errorf("GenerateGPNotification in cleanup: %v", err)
		}
	})
	// Registered after the revert, so it runs before it: every lookup ends
	// while the server still answers.
	p := newNRPTProbe(t)

	reg := records.Registration(realAdapter, s.Addr(), fwd)
	split := reg
	split.DefaultRoute = false
	host := winNRPTHost{}

	// Phase (a): the zones, the search domain, the reverse zone and the
	// forward zone, without the catch-all.
	p.startPhase("(a) Apply without the catch-all")
	if err := r.Apply(ctx, split); err != nil {
		t.Fatalf("Apply(without the catch-all) = %v, want nil", err)
	}
	// One rule holds the search domain and then the routing domains in the
	// order the registration lists them: the reverse zones before the
	// forward zones.
	p.wantStoreKeys("local", nrptLocalPath, "plexd-meshdns-match-0")
	p.wantRule(nrptLocalPath, "plexd-meshdns-match-0", []string{"." + realZone, "." + realReverseZone, "." + realForward}, "127.0.0.1")
	p.wantVolatile(nrptLocalPath + `\plexd-meshdns-match-0`)
	// SetDNS stores the adapter's IPv4 search list as SearchList under the
	// adapter's GUID.
	if got, ok := adapterSearchList(t, searchListPath); got != realZone {
		p.fail("SearchList under HKLM\\%s = %q (present %v), want %q", searchListPath, got, ok, realZone)
	}
	// A volatile rule with Version 2, Name, GenericDNSServers and
	// ConfigOptions 8 sends the names under its namespaces to 127.0.0.1:53
	// once the cache is flushed, without a service restart. The answers
	// reach the DNS Client only because its queries arrive from a loopback
	// address, which the server's source rule accepts.
	p.wantResolves(realHost, realHostIP, localWait)
	// The adapter's search list, on an adapter that carries no DNS server,
	// makes a bare host name resolve as <host>.<search domain>.
	p.wantResolves("host-a", realHostIP, localWait)
	// LookupAddr asks through DnsQuery, which the table routes too.
	p.waitFor("LookupAddr("+realHostIP+") returns "+realHost+".", localWait, func() (bool, string) {
		names, err := p.lookupAddr(realHostIP)
		if err != nil {
			return false, fmt.Sprintf("LookupAddr(%s): %v", realHostIP, err)
		}
		return slices.Contains(names, realHost+"."), fmt.Sprintf("LookupAddr(%s) = %q", realHostIP, names)
	})
	p.waitFor("nope."+realZone+" is not found", localWait, func() (bool, string) {
		addrs, err := p.lookupIP("nope." + realZone)
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return true, ""
		}
		return false, fmt.Sprintf("LookupNetIP(nope.%s) = %v, %v", realZone, addrs, err)
	})
	// The forward zone's answer comes from the fake, so plexd accepted the
	// DNS Client's query and forwarded it.
	p.wantResolves("host."+realForward, realStubIP, localWait)
	if !askedFor(fake, "host."+realForward) {
		p.fail("the forward zone's resolver was not asked for host.%s", realForward)
	}

	// Phase (b): the catch-all adds the exemption for .local and the rule
	// for every name.
	p.startPhase("(b) Apply with the catch-all")
	if err := r.Apply(ctx, reg); err != nil {
		t.Fatalf("Apply(with the catch-all) = %v, want nil", err)
	}
	p.wantStoreKeys("local", nrptLocalPath, realRuleKeys...)
	p.wantRule(nrptLocalPath, "plexd-meshdns-exempt-local", []string{".local"}, "")
	p.wantRule(nrptLocalPath, "plexd-meshdns-default", []string{"."}, "127.0.0.1")
	// A rule for "." takes every name that no more specific rule matches.
	p.wantResolves("plexd-catchall-check.example", realStubIP, localWait)
	// A .local rule with an empty GenericDNSServers keeps .local names away
	// from it, so the lookup never reaches the catch-all's resolver,
	// whatever it returns.
	addrs, err := p.lookupIP("plexd-exempt-check.local")
	t.Logf("LookupNetIP(plexd-exempt-check.local) = %v, %v", addrs, err)
	exemptAsked := askedFor(fake, "plexd-exempt-check.local")
	if exemptAsked {
		p.fail("the catch-all's resolver was asked for plexd-exempt-check.local")
	}

	// Phase (c): Group Policy starts configuring the table. The test creates
	// the Group Policy store's key empty, as such a policy would, and sends
	// the machine policy change the policy engine signals once it applied
	// one. RefreshPolicyEx is no stand-in for it: on the CI runner a forced
	// refresh signalled no machine policy change within four minutes, and
	// the DNS Client kept the local rules it had read, deleted ones included.
	p.startPhase("(c) Group Policy configures the table")
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptPolicyPath, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("create HKLM\\%s: %v", nrptPolicyPath, err)
	}
	_ = k.Close()
	p.notify("the takeover")
	// The change signals the event the watcher registered with
	// RegisterGPNotification, and the watcher copies plexd's rules into the
	// Group Policy store and notifies the DNS Client in turn.
	p.waitFor("the Group Policy store lists plexd's keys", copyWait, func() (bool, string) {
		keys := plexdKeys(t, nrptPolicyPath)
		return slices.Equal(keys, realRuleKeys), fmt.Sprintf("plexd keys = %q", keys)
	})
	p.wantRule(nrptPolicyPath, "plexd-meshdns-match-0", []string{"." + realZone, "." + realReverseZone, "." + realForward}, "127.0.0.1")
	p.wantRule(nrptPolicyPath, "plexd-meshdns-exempt-local", []string{".local"}, "")
	p.wantRule(nrptPolicyPath, "plexd-meshdns-default", []string{"."}, "127.0.0.1")
	// The watcher's own notification after its copy signals it again. The
	// local keys must not go before the watcher has handled it, or it would
	// write them back, so the test waits for the watcher to go quiet.
	p.waitForQuietWatcher(watch, 0, "after the copy", watchQuiet+localWait)
	// Once the Group Policy store's key exists, the DNS Client takes its
	// rules from there after a machine policy change. The wait measures when
	// it does, so the cache is flushed before each lookup: a lookup that runs
	// before the switch would leave a negative answer behind.
	p.waitFor(realHost+" resolves to "+realHostIP+" from the Group Policy store", policyWait, func() (bool, string) {
		if err := host.flush(); err != nil {
			return false, fmt.Sprintf("flush: %v", err)
		}
		return p.resolves(realHost, realHostIP)
	})
	// The local keys go by hand, without a machine policy change, so the
	// watcher stays quiet and does not write them back.
	for _, name := range plexdKeys(t, nrptLocalPath) {
		if err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptLocalPath+`\`+name); err != nil {
			t.Fatalf("delete local %s: %v", name, err)
		}
	}
	if err := host.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// A rule deleted from the local store no longer matters.
	p.holds(realHost+" keeps resolving without the local keys", stillWait, func() (bool, string) {
		return p.resolves(realHost, realHostIP)
	})
	// The names came from the Group Policy store only while the local keys
	// stayed gone.
	p.wantStoreKeys("local", nrptLocalPath)
	// plexd's keys are still in the Group Policy store, and the watcher wrote
	// them once: its own notification found nothing left to change.
	p.wantStoreKeys("policy", nrptPolicyPath, realRuleKeys...)
	if n := regLogs.count("mesh dns registration re-applied after a group policy change"); n != 1 {
		p.fail("the watcher re-applied the registration %d times, want once: it wrote again after its own notification, or wrote the local keys back", n)
	}
	// The exempted lookup of phase (b) has ended by now, also when it took
	// longer than its 5 seconds, and it still never reached the catch-all's
	// resolver.
	if !exemptAsked && askedFor(fake, "plexd-exempt-check.local") {
		p.fail("the catch-all's resolver was asked for plexd-exempt-check.local after the lookup's 5 seconds")
	}

	// Phase (d): the revert leaves nothing behind.
	p.startPhase("(d) Revert")
	if err := r.Revert(ctx, realAdapter); err != nil {
		t.Fatalf("Revert() = %v, want nil", err)
	}
	p.wantStoreKeys("local", nrptLocalPath)
	p.wantStoreKeys("policy", nrptPolicyPath)
	if keyExists(t, nrptPolicyPath) {
		p.fail("HKLM\\%s still exists after the revert", nrptPolicyPath)
	}
	if got, ok := adapterSearchList(t, searchListPath); got != "" {
		p.fail("SearchList under HKLM\\%s = %q (present %v) after the revert, want it empty or absent", searchListPath, got, ok)
	}
	p.waitFor(realHost+" stops resolving after the revert", policyWait, func() (bool, string) {
		addrs, err := p.lookupIP(realHost)
		switch {
		case errors.Is(err, errNoAnswer):
			return false, err.Error()
		case err != nil:
			return true, ""
		}
		resolved := slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() == netip.MustParseAddr(realHostIP) })
		return !resolved, fmt.Sprintf("LookupNetIP(%s) = %v", realHost, addrs)
	})
	// Whether GenerateGPNotification refuses an elevated Administrator is not
	// asserted: the lines name the route that ran.
	notified := regLogs.find("group policy notified")
	for _, e := range notified {
		t.Logf("group policy notified via %s", e.attrs["via"])
	}
	if len(notified) == 0 {
		p.fail("no line says %q", "group policy notified")
	}
}

// watchCountingHost is the real host whose Group Policy watcher counts the
// handler runs it completed and when the last one ended.
type watchCountingHost struct {
	winNRPTHost
	mu   sync.Mutex
	runs int
	last time.Time
}

func (h *watchCountingHost) watchPolicy(onChange func()) (func(), error) {
	return h.winNRPTHost.watchPolicy(func() {
		onChange()
		h.mu.Lock()
		defer h.mu.Unlock()
		h.runs++
		h.last = time.Now()
	})
}

// handled returns how many handler runs completed and when the last ended.
func (h *watchCountingHost) handled() (int, time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.runs, h.last
}

// waitForQuietWatcher waits up to timeout until the watcher has completed
// more than after handler runs and then ran none for watchQuiet, and logs how
// long that took. When that does not happen, it fails the test: a machine
// policy change signals the watcher's event.
func (p *nrptProbe) waitForQuietWatcher(h *watchCountingHost, after int, when string, timeout time.Duration) {
	p.t.Helper()
	p.waitFor("the watcher handled the policy change and went quiet "+when, timeout, func() (bool, string) {
		runs, last := h.handled()
		quiet := time.Since(last)
		return runs > after && quiet >= watchQuiet, fmt.Sprintf("handler runs %d (want more than %d), quiet for %v", runs, after, quiet.Round(time.Millisecond))
	})
}

// nrptProbe runs the real test's lookups and checks.
type nrptProbe struct {
	t *testing.T
	// lookups are the lookups started so far, which the test waits for
	// before it ends.
	lookups sync.WaitGroup
	// diagnosed is whether a check of the current phase failed and logged
	// the resolver's state, which the phase's later failures share.
	diagnosed bool
}

// newNRPTProbe returns a probe for t whose cleanup waits for every lookup.
func newNRPTProbe(t *testing.T) *nrptProbe {
	p := &nrptProbe{t: t}
	t.Cleanup(p.lookups.Wait)
	return p
}

// startPhase logs the phase's name and lets its first failed check log the
// resolver's state.
func (p *nrptProbe) startPhase(name string) {
	p.t.Logf("phase %s", name)
	p.diagnosed = false
}

// fail fails the test and, at the first failed check of a phase, logs the
// resolver's state.
func (p *nrptProbe) fail(format string, args ...any) {
	p.t.Helper()
	p.t.Errorf(format, args...)
	if !p.diagnosed {
		p.diagnosed = true
		p.logResolverState()
	}
}

// waitFor checks every pollInterval until check holds or timeout has
// passed, and logs how long check took to hold. When it never holds, it
// fails the test with the last output check gave.
func (p *nrptProbe) waitFor(what string, timeout time.Duration, check func() (bool, string)) {
	p.t.Helper()
	start := time.Now()
	for {
		ok, last := check()
		if ok {
			p.t.Logf("%s: held after %v", what, time.Since(start).Round(time.Millisecond))
			return
		}
		if time.Since(start) >= timeout {
			p.fail("%s: not within %v, last output:\n%s", what, timeout, last)
			return
		}
		time.Sleep(pollInterval)
	}
}

// holds checks every pollInterval for d, and fails the test at the first
// check that does not hold.
func (p *nrptProbe) holds(what string, d time.Duration, check func() (bool, string)) {
	p.t.Helper()
	start := time.Now()
	for {
		ok, last := check()
		if !ok {
			p.fail("%s: stopped holding after %v, last output:\n%s", what, time.Since(start).Round(time.Millisecond), last)
			return
		}
		if time.Since(start) >= d {
			p.t.Logf("%s: held for %v", what, d)
			return
		}
		time.Sleep(pollInterval)
	}
}

// wantResolves fails the test unless name resolves to want within timeout.
func (p *nrptProbe) wantResolves(name, want string, timeout time.Duration) {
	p.t.Helper()
	p.waitFor(name+" resolves to "+want, timeout, func() (bool, string) {
		return p.resolves(name, want)
	})
}

// resolves reports whether name resolves to want, and what the lookup gave.
func (p *nrptProbe) resolves(name, want string) (bool, string) {
	addrs, err := p.lookupIP(name)
	if err != nil {
		return false, fmt.Sprintf("LookupNetIP(%s): %v", name, err)
	}
	wantAddr := netip.MustParseAddr(want)
	ok := slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() == wantAddr })
	return ok, fmt.Sprintf("LookupNetIP(%s) = %v", name, addrs)
}

// errNoAnswer is what a lookup returns when the DNS Client gave no answer
// within lookupTimeout.
var errNoAnswer = fmt.Errorf("no answer within %v", lookupTimeout)

// lookupIP resolves name through net.DefaultResolver, which on Windows asks
// the DNS Client through GetAddrInfoW.
func (p *nrptProbe) lookupIP(name string) ([]netip.Addr, error) {
	return boundedLookup(p, func(ctx context.Context) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	})
}

// lookupAddr resolves addr to names through net.DefaultResolver, which on
// Windows asks the DNS Client through DnsQuery.
func (p *nrptProbe) lookupAddr(addr string) ([]string, error) {
	return boundedLookup(p, func(ctx context.Context) ([]string, error) {
		return net.DefaultResolver.LookupAddr(ctx, addr)
	})
}

// boundedLookup runs lookup in a goroutine and waits lookupTimeout for its
// result. Go's resolver on Windows leaves GetAddrInfoW running in a goroutine
// of its own when the lookup's context ends first, and DnsQuery does not
// watch the context at all (net/lookup_windows.go), so a context deadline
// would bound neither the call nor its goroutine. The lookup gets lookupLimit
// instead, it ends when the DNS Client answers, and the probe's cleanup waits
// for it, so no lookup outlives the test, which goleak checks.
func boundedLookup[T any](p *nrptProbe, lookup func(context.Context) (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	p.lookups.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), lookupLimit)
		defer cancel()
		v, err := lookup(ctx)
		done <- result{v, err}
	})
	timer := time.NewTimer(lookupTimeout)
	defer timer.Stop()
	select {
	case res := <-done:
		return res.v, res.err
	case <-timer.C:
		var zero T
		return zero, errNoAnswer
	}
}

// notify sends a machine policy change as the test's own step, as the
// policy engine does once it applied a policy.
func (p *nrptProbe) notify(which string) {
	p.t.Helper()
	if err := (winNRPTHost{}).generateGPNotification(); err != nil {
		p.t.Fatalf("GenerateGPNotification for %s: %v", which, err)
	}
	p.t.Logf("GenerateGPNotification for %s returned", which)
}

// isLocalSystem reports whether the test runs as LocalSystem.
func isLocalSystem(t *testing.T) bool {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	return user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// wantStoreKeys fails the test unless the plexd keys of the store at path
// are exactly want, sorted.
func (p *nrptProbe) wantStoreKeys(store, path string, want ...string) {
	p.t.Helper()
	if got := plexdKeys(p.t, path); !slices.Equal(got, want) {
		p.fail("plexd keys in the %s store = %q, want %q", store, got, want)
	}
}

// wantRule fails the test unless the rule key name under the store at path
// holds the values the DNS Client reads, with the types it reads them as:
// Name as REG_MULTI_SZ, GenericDNSServers as REG_SZ, and Version 2 and
// ConfigOptions 8 as REG_DWORD. It reads the registry itself rather than
// through readRule, so the check does not rest on the code it checks.
func (p *nrptProbe) wantRule(path, name string, namespaces []string, servers string) {
	p.t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+name, registry.QUERY_VALUE)
	if err != nil {
		p.fail("open HKLM\\%s\\%s: %v", path, name, err)
		return
	}
	defer func() { _ = k.Close() }()
	if got, _, err := k.GetStringsValue("Name"); err != nil || !slices.Equal(got, namespaces) {
		p.fail("%s Name = %q, %v; want %q", name, got, err, namespaces)
	}
	if got, typ, err := k.GetStringValue("GenericDNSServers"); err != nil || typ != registry.SZ || got != servers {
		p.fail("%s GenericDNSServers = %q of type %d, %v; want %q of type %d", name, got, typ, err, servers, registry.SZ)
	}
	for _, v := range []struct {
		name string
		want uint64
	}{{"Version", 2}, {"ConfigOptions", 8}} {
		if got, typ, err := k.GetIntegerValue(v.name); err != nil || typ != registry.DWORD || got != v.want {
			p.fail("%s %s = %d of type %d, %v; want %d of type %d", name, v.name, got, typ, err, v.want, registry.DWORD)
		}
	}
}

// wantVolatile fails the test unless the key at path is volatile, which
// shows as Windows refusing a non-volatile key under it. A volatile key lives
// in memory only, so a reboot clears whatever a killed run left.
func (p *nrptProbe) wantVolatile(path string) {
	p.t.Helper()
	const child = "plexd-volatile-check"
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.CREATE_SUB_KEY)
	if err != nil {
		p.fail("open HKLM\\%s: %v", path, err)
		return
	}
	defer func() { _ = k.Close() }()
	created, _, err := registry.CreateKey(k, child, registry.QUERY_VALUE)
	if err == nil {
		_ = created.Close()
		_ = registry.DeleteKey(k, child)
		p.fail("created a non-volatile key under HKLM\\%s, want ERROR_CHILD_MUST_BE_VOLATILE", path)
		return
	}
	if !errors.Is(err, windows.ERROR_CHILD_MUST_BE_VOLATILE) {
		p.fail("create a non-volatile key under HKLM\\%s = %v, want ERROR_CHILD_MUST_BE_VOLATILE", path, err)
	}
}

// logResolverState logs what decides where the DNS Client sends a name: the
// rules it applies, its answer for the test's host, and both stores' keys.
// The commands share one bound. It asserts nothing; the checks do.
func (p *nrptProbe) logResolverState() {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), diagTimeout)
	defer cancel()
	p.t.Logf("Get-DnsClientNrptPolicy -Effective; Resolve-DnsName %s -DnsOnly:\n%s", realHost,
		commandOutput(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-DnsClientNrptPolicy -Effective | Format-List; Resolve-DnsName "+realHost+" -DnsOnly"))
	for _, path := range []string{nrptLocalPath, nrptPolicyPath} {
		p.t.Logf("reg query HKLM\\%s /s:\n%s", path, commandOutput(ctx, "reg", "query", `HKLM\`+path, "/s"))
	}
}

// commandOutput runs a tool bounded by ctx and returns its output, with the
// error appended when it failed.
func commandOutput(ctx context.Context, name string, args ...string) string {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("%s(%s %s: %v)", out, name, strings.Join(args, " "), err)
	}
	return string(out)
}

// plexdKeys returns the names of the plexd keys under the store at path,
// sorted, or nil when the store's key does not exist. Registry key names are
// case-insensitive, so the prefix is too.
func plexdKeys(t *testing.T, path string) []string {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("open HKLM\\%s: %v", path, err)
	}
	defer func() { _ = k.Close() }()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		t.Fatalf("list HKLM\\%s: %v", path, err)
	}
	var keys []string
	for _, name := range names {
		if strings.HasPrefix(strings.ToLower(name), "plexd-meshdns-") {
			keys = append(keys, name)
		}
	}
	slices.Sort(keys)
	return keys
}

// keyExists reports whether the key at path under HKEY_LOCAL_MACHINE exists.
func keyExists(t *testing.T, path string) bool {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatalf("open HKLM\\%s: %v", path, err)
	}
	_ = k.Close()
	return true
}

// waitForAdapter returns the test's adapter once net.Interfaces lists it
// with the mesh IP, where the registrar looks the adapter up. Windows
// finishes wiring an adapter's IP stack a moment after the calls that set it
// up return.
func waitForAdapter(t *testing.T) net.Interface {
	t.Helper()
	deadline := time.Now().Add(localWait)
	for {
		last := "not listed"
		ifaces, err := net.Interfaces()
		if err != nil {
			last = err.Error()
		}
		if i := slices.IndexFunc(ifaces, func(ifi net.Interface) bool { return ifi.Name == realAdapter }); i >= 0 {
			addrs, err := ifaces[i].Addrs()
			if err != nil {
				last = err.Error()
			} else if slices.ContainsFunc(addrs, func(a net.Addr) bool { return strings.HasPrefix(a.String(), realMeshIP+"/") }) {
				return ifaces[i]
			} else {
				last = fmt.Sprintf("addresses %v", addrs)
			}
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("net.Interfaces did not list %s with %s within %v: %s", realAdapter, realMeshIP, localWait, last)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// adapterSettingsPath returns the path of the adapter's IPv4 settings under
// HKEY_LOCAL_MACHINE, which names the adapter by its GUID in braces.
func adapterSettingsPath(t *testing.T, index int) string {
	t.Helper()
	luid, err := winipcfg.LUIDFromIndex(uint32(index))
	if err != nil {
		t.Fatalf("LUIDFromIndex(%d): %v", index, err)
	}
	guid, err := luid.GUID()
	if err != nil {
		t.Fatalf("GUID of LUID %d: %v", luid, err)
	}
	return `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + guid.String()
}

// adapterSearchList returns the SearchList value of the adapter settings at
// path, and whether the value exists.
func adapterSearchList(t *testing.T, path string) (string, bool) {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("open HKLM\\%s: %v", path, err)
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue("SearchList")
	if errors.Is(err, registry.ErrNotExist) {
		return "", false
	}
	if err != nil {
		t.Fatalf("read SearchList under HKLM\\%s: %v", path, err)
	}
	return v, true
}

// newTestLogger returns a logger at Debug that writes each line into the
// test log and keeps it in rec.
func newTestLogger(t *testing.T, rec *logRecorder) *slog.Logger {
	w := &testLogWriter{t: t}
	t.Cleanup(w.close)
	text := slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(slog.NewMultiHandler(text, &recordingHandler{rec: rec}))
}

// testLogWriter hands each line a slog.TextHandler writes to t.Log until the
// test's last cleanup runs, and drops the lines after it: t.Log panics once a
// test has completed, and the watcher's goroutine logs on its own.
type testLogWriter struct {
	mu   sync.Mutex
	t    *testing.T
	done bool
}

func (w *testLogWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.done {
		w.t.Log(strings.TrimSuffix(string(b), "\n"))
	}
	return len(b), nil
}

// close drops every line from now on.
func (w *testLogWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.done = true
}
