//go:build darwin

package meshdns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// The real test's utun, names and addresses. 10.255.249.1/30 is used by no
// other real test, so the privileged step can run the packages side by side.
// The resolver listens on loopback, as plexd's does on macOS. The names live
// under TLDs no public resolver answers, and the other addresses are
// documentation ranges.
const (
	realUTUN     = "plexd-dnstest"
	realAddress  = "10.255.249.1/30"
	realMeshIP   = "10.255.249.1"
	realListenIP = "127.0.0.1"
	realZone     = "plexd-test.internal"
	realHost     = "host-a.plexd-test.internal"
	realHostIP   = "192.0.2.10"
	realForward  = "fwd.example"
	realResolver = "192.0.2.53"
	realStubIP   = "198.51.100.53"
)

// TestScutilRegistrar_Real registers a real mesh resolver, listening on
// 127.0.0.1 beside a real utun that carries the mesh IP, as plexd does on
// macOS, in configd's dynamic store and resolves through the macOS resolver
// with dscacheutil, which asks mDNSResponder as every program on the host
// does. It is the only test that proves the scripts the fakes above assert do
// what the registration needs on macOS: the search domain joins the search
// list, the routing domains reach the resolver's address and port, the
// queries pass the resolver's source rule, the default-resolver entry takes
// names no other entry matches, and a revert leaves nothing behind.
//
// It changes the host's resolver configuration while it runs, so it needs
// PLEXD_TEST_REAL_RESOLVER=1 on top of root, which creating a utun needs.
// CI runs it in the privileged step on the macOS runner.
func TestScutilRegistrar_Real(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating a utun needs root; run with sudo")
	}
	if os.Getenv("PLEXD_TEST_REAL_RESOLVER") != "1" {
		t.Skip("set PLEXD_TEST_REAL_RESOLVER=1 to change the host's resolver configuration")
	}
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)

	wg := wireguard.NewDarwinController(logger)
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	if err := wg.CreateInterface(realUTUN, key[:], 0); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	t.Cleanup(func() {
		if err := wg.DeleteInterface(realUTUN); err != nil {
			t.Errorf("DeleteInterface: %v", err)
		}
	})
	if err := wg.ConfigureAddress(realUTUN, realAddress); err != nil {
		t.Fatalf("ConfigureAddress: %v", err)
	}
	if err := wg.SetInterfaceUp(realUTUN); err != nil {
		t.Fatalf("SetInterfaceUp: %v", err)
	}
	utun, ok := wg.OSInterfaceName(realUTUN)
	if !ok {
		t.Fatal("no utun name recorded after CreateInterface")
	}

	records, skipped := BuildRecords(api.NodeStateDNS{
		SearchDomain: realZone,
		Zones:        []string{realZone},
		Hosts:        []api.NodeStateDNSHost{{NodeID: "node-a", FQDN: realHost, MeshIP: realHostIP}},
		ReverseZones: []string{"2.0.192.in-addr.arpa"},
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
	s := NewServer(netip.AddrPortFrom(netip.MustParseAddr(realListenIP), 0), slog.New(&recordingHandler{rec: serverLogs}))
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

	r := NewScutilRegistrar(logger)
	// Cleanups run last in first: the revert goes before the server stops
	// and the utun goes, so a failed check leaves the runner's resolver as
	// it found it.
	t.Cleanup(func() {
		if err := r.Revert(context.Background(), utun); err != nil {
			t.Errorf("Revert in cleanup: %v", err)
		}
	})

	reg := records.Registration(utun, s.Addr(), fwd)
	split := reg
	split.DefaultRoute = false

	// The zones, the search domain, the reverse zone and the forward zone.
	if err := r.Apply(ctx, split); err != nil {
		t.Fatalf("Apply(without the catch-all) = %v, want nil", err)
	}
	wantKeys(t, r, "plexd-meshdns-match-0", "plexd-meshdns-search")
	eventually(t, "scutil --dns lists the resolver for "+realZone, func() (bool, string) {
		out := runTool(t, "/usr/sbin/scutil", "--dns")
		return hasResolver(out, realZone, realListenIP, s.Addr().Port()), out
	})
	probeDelivery(t, s, utun, serverLogs)
	wantLookup(t, "name", realHost, "ip_address: "+realHostIP)
	wantLookup(t, "name", "host-a", "ip_address: "+realHostIP)
	wantLookup(t, "ip_address", realHostIP, "name: "+realHost)
	if out := lookup(t, "name", "nope."+realZone); strings.Contains(out, "ip_address:") {
		t.Errorf("dscacheutil found nope.%s:\n%s", realZone, out)
	}
	wantLookup(t, "name", "host."+realForward, "ip_address: "+realStubIP)
	if !askedFor(fake, "host."+realForward) {
		t.Errorf("the forward zone's resolver was not asked for host.%s", realForward)
	}

	// The catch-all adds the default-resolver entry, which takes a name no
	// other entry matches.
	if err := r.Apply(ctx, reg); err != nil {
		t.Fatalf("Apply(with the catch-all) = %v, want nil", err)
	}
	wantKeys(t, r, "plexd-meshdns-default", "plexd-meshdns-match-0", "plexd-meshdns-search")
	wantLookup(t, "name", "plexd-catchall-check.example", "ip_address: "+realStubIP)

	// The revert leaves nothing behind.
	if err := r.Revert(ctx, utun); err != nil {
		t.Fatalf("Revert() = %v, want nil", err)
	}
	wantKeys(t, r)
	// The port is the one the kernel picked for this test's server, so a
	// resolver that names it with 127.0.0.1 is one of plexd's entries: the
	// search, match and default entries all go, and so does the search domain
	// on the primary resolver.
	eventually(t, "scutil --dns stops naming plexd's entries and "+realZone+" after the revert", func() (bool, string) {
		out := runTool(t, "/usr/sbin/scutil", "--dns")
		return !hasServer(out, realListenIP, s.Addr().Port()) && !strings.Contains(out, realZone), out
	})
	eventually(t, realHost+" stops resolving after the revert", func() (bool, string) {
		out := lookup(t, "name", realHost)
		return !strings.Contains(out, "ip_address:"), out
	})
}

// wantKeys fails the test unless the plexd keys in the dynamic store are
// exactly the services suffixes, sorted, each with its /DNS key.
func wantKeys(t *testing.T, r *ScutilRegistrar, suffixes ...string) {
	t.Helper()
	keys, err := r.list(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := make([]string, len(suffixes))
	for i, s := range suffixes {
		want[i] = "State:/Network/Service/" + s + "/DNS"
	}
	slices.Sort(keys)
	if !slices.Equal(keys, want) {
		t.Errorf("plexd keys = %q, want %q", keys, want)
	}
}

// wantLookup fails the test unless dscacheutil's answer for value holds the
// line want within 10 seconds.
func wantLookup(t *testing.T, key, value, want string) {
	t.Helper()
	eventually(t, "dscacheutil -q host -a "+key+" "+value+" says "+want, func() (bool, string) {
		out := lookup(t, key, value)
		for line := range strings.SplitSeq(out, "\n") {
			if strings.TrimSpace(line) == want {
				return true, out
			}
		}
		return false, out
	})
}

// lookup asks the macOS resolver through dscacheutil, which prints nothing
// for a name it cannot resolve. A dscacheutil that does not return within 5
// seconds is killed, and the output says so, so the check that called lookup
// reports it rather than the test ending there.
func lookup(t *testing.T, key, value string) string {
	t.Helper()
	return toolOutput(5*time.Second, "/usr/bin/dscacheutil", "-q", "host", "-a", key, value)
}

// toolOutput runs a tool bounded by timeout and returns its output, with the
// error appended when it failed.
func toolOutput(timeout time.Duration, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("%s(%s %s: %v)", out, name, strings.Join(args, " "), err)
	}
	return string(out)
}

// probeDelivery logs what decides whether mDNSResponder's queries reach the
// server: the routes to the server's address and to the mesh IP, which leads
// into the utun and is why the resolver listens on loopback on macOS, the
// resolver scutil --dns reports for the
// zone, a query the test process itself sends to the server, and a packet
// capture on lo0 and on the utun during one lookup through dscacheutil. It
// asserts nothing; the lookups after it do. The server's Debug lines are
// logged when the test fails.
func probeDelivery(t *testing.T, s *Server, utun string, serverLogs *logRecorder) {
	t.Helper()
	server := s.Addr()
	for _, addr := range []string{server.Addr().String(), realMeshIP} {
		t.Logf("route -n get %s:\n%s", addr, toolOutput(5*time.Second, "/sbin/route", "-n", "get", addr))
	}

	for block := range strings.SplitSeq(toolOutput(5*time.Second, "/usr/sbin/scutil", "--dns"), "resolver #") {
		if strings.Contains(block, realZone) {
			t.Logf("scutil --dns resolver #%s", block)
		}
	}

	conn, err := net.Dial("udp", server.String())
	if err != nil {
		t.Logf("direct query: dial %s: %v", server, err)
	} else {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		reply := make([]byte, maxMessageSize)
		_, err := conn.Write(newQuery(t, 0x0167, realHost+".", dnsmessage.TypeA))
		n := 0
		if err == nil {
			n, err = conn.Read(reply)
		}
		if err != nil {
			t.Logf("direct query from %s to %s: %v", conn.LocalAddr(), server, err)
		} else {
			addr, aErr := firstA(reply[:n])
			t.Logf("direct query from %s to %s: answer %v, error %v", conn.LocalAddr(), server, addr, aErr)
		}
		_ = conn.Close()
	}

	filter := "udp port " + strconv.Itoa(int(server.Port()))
	captures := make([]chan string, 0, 2)
	for _, iface := range []string{"lo0", utun} {
		done := make(chan string, 1)
		captures = append(captures, done)
		go func() {
			done <- fmt.Sprintf("tcpdump -i %s %s:\n%s", iface, filter,
				toolOutput(8*time.Second, "/usr/sbin/tcpdump", "-n", "-l", "-c", "20", "-i", iface, filter))
		}()
	}
	// tcpdump needs a moment to attach before the lookup it is to see.
	time.Sleep(time.Second)
	t.Logf("dscacheutil -q host -a name %s during the capture:\n%s", realHost, lookup(t, "name", realHost))
	for _, done := range captures {
		t.Log(<-done)
	}
	t.Logf("server refused %d UDP packets and %d TCP connections so far",
		serverLogs.count("mesh dns dropped a packet from a source it does not answer"),
		serverLogs.count("mesh dns closed a connection from a source it does not answer"))
}

// logServerLines logs every line the server logged, with its attributes.
func logServerLines(t *testing.T, logs *logRecorder) {
	t.Helper()
	for _, e := range logs.all() {
		attrs := make([]string, 0, len(e.attrs))
		for k, v := range e.attrs {
			attrs = append(attrs, k+"="+v.String())
		}
		slices.Sort(attrs)
		t.Logf("server %s %q %s", e.level, e.msg, strings.Join(attrs, " "))
	}
}

// runTool runs a tool with a 10-second bound and returns its output.
func runTool(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// eventually checks every 500 ms for up to 10 seconds, because configd hands
// mDNSResponder a new configuration asynchronously, and fails the test with
// the last output it saw when check never holds.
func eventually(t *testing.T, what string, check func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ok, last := check()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("%s: not within 10s, last output:\n%s", what, last)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// hasResolver reports whether the output of scutil --dns has a resolver for
// domain with the nameserver addr and a port line naming port.
func hasResolver(out, domain, addr string, port uint16) bool {
	domainRE := regexp.MustCompile(`(?m)^\s*domain\s*:\s*` + regexp.QuoteMeta(domain) + `\s*$`)
	serverRE := regexp.MustCompile(`(?m)^\s*nameserver\[0\]\s*:\s*` + regexp.QuoteMeta(addr) + `\s*$`)
	portRE := regexp.MustCompile(`(?m)^\s*port\s*:\s*` + strconv.Itoa(int(port)) + `\s*$`)
	for block := range strings.SplitSeq(out, "resolver #") {
		if domainRE.MatchString(block) && serverRE.MatchString(block) && portRE.MatchString(block) {
			return true
		}
	}
	return false
}

// hasServer reports whether the output of scutil --dns has a resolver whose
// first nameserver is addr with a port line naming port, whatever its domain.
func hasServer(out, addr string, port uint16) bool {
	serverRE := regexp.MustCompile(`(?m)^\s*nameserver\[0\]\s*:\s*` + regexp.QuoteMeta(addr) + `\s*$`)
	portRE := regexp.MustCompile(`(?m)^\s*port\s*:\s*` + strconv.Itoa(int(port)) + `\s*$`)
	for block := range strings.SplitSeq(out, "resolver #") {
		if serverRE.MatchString(block) && portRE.MatchString(block) {
			return true
		}
	}
	return false
}

// askedFor reports whether f received a query for name.
func askedFor(f *fakeResolver, name string) bool {
	for _, q := range f.received() {
		var p dnsmessage.Parser
		if _, err := p.Start(q.msg); err != nil {
			continue
		}
		question, err := p.Question()
		if err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSuffix(question.Name.String(), "."), name) {
			return true
		}
	}
	return false
}
