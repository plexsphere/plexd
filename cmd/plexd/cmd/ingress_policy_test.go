package cmd

import (
	"net/netip"
	"slices"
	"syscall"
	"testing"
)

// admitCall is one question a fakeDialAdmitter was asked: the method and its
// arguments.
type admitCall struct {
	method string // "AdmitsTCPDial" or "AdmitsUDPDial"
	src    netip.Addr
	dst    netip.AddrPort
}

// fakeDialAdmitter answers AdmitsTCPDial and AdmitsUDPDial with admitted and
// enforced, counts the calls and records each one.
type fakeDialAdmitter struct {
	admitted, enforced bool
	calls              int
	asked              []admitCall
}

func (f *fakeDialAdmitter) AdmitsTCPDial(src netip.Addr, dst netip.AddrPort) (bool, bool) {
	f.calls++
	f.asked = append(f.asked, admitCall{method: "AdmitsTCPDial", src: src, dst: dst})
	return f.admitted, f.enforced
}

func (f *fakeDialAdmitter) AdmitsUDPDial(src netip.Addr, dst netip.AddrPort) (bool, bool) {
	f.calls++
	f.asked = append(f.asked, admitCall{method: "AdmitsUDPDial", src: src, dst: dst})
	return f.admitted, f.enforced
}

var (
	testIngressMeshIP = netip.MustParseAddr("10.99.0.1")
	testIngressTarget = netip.MustParseAddrPort("10.99.0.2:9022")
)

func TestIngressDialPolicy_DoesNotAskForADialOffTheMesh(t *testing.T) {
	tests := []struct {
		name      string
		target    netip.AddrPort
		sourceFor func(netip.AddrPort) (netip.Addr, error)
	}{
		{
			name:   "a target that is the mesh address",
			target: netip.AddrPortFrom(testIngressMeshIP, 9022),
			sourceFor: func(netip.AddrPort) (netip.Addr, error) {
				return testIngressMeshIP, nil
			},
		},
		{
			name:   "no route to the target",
			target: testIngressTarget,
			sourceFor: func(netip.AddrPort) (netip.Addr, error) {
				return netip.Addr{}, syscall.ENETUNREACH
			},
		},
		{
			name:   "another source address",
			target: testIngressTarget,
			sourceFor: func(netip.AddrPort) (netip.Addr, error) {
				return netip.MustParseAddr("192.0.2.7"), nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, protocol := range []string{"tcp", "udp"} {
				enforcer := &fakeDialAdmitter{admitted: false, enforced: true}
				p := ingressDialPolicy{enforcer: enforcer, meshIP: testIngressMeshIP, sourceFor: tt.sourceFor}
				if p.DialDenied(protocol, tt.target) {
					t.Errorf("DialDenied(%s, %s) = true, want false", protocol, tt.target)
				}
				if enforcer.calls != 0 {
					t.Errorf("%s: the Enforcer was asked %d times, want not at all", protocol, enforcer.calls)
				}
			}
		})
	}
}

func TestIngressDialPolicy_AnswersFromTheEnforcer(t *testing.T) {
	tests := []struct {
		admitted, enforced bool
		want               bool
	}{
		{admitted: false, enforced: true, want: true},
		{admitted: true, enforced: true, want: false},
		{admitted: true, enforced: false, want: false},
	}
	fromMesh := func(netip.AddrPort) (netip.Addr, error) { return testIngressMeshIP, nil }
	for _, proto := range []struct{ protocol, method string }{
		{"tcp", "AdmitsTCPDial"},
		{"udp", "AdmitsUDPDial"},
	} {
		for _, tt := range tests {
			enforcer := &fakeDialAdmitter{admitted: tt.admitted, enforced: tt.enforced}
			p := ingressDialPolicy{enforcer: enforcer, meshIP: testIngressMeshIP, sourceFor: fromMesh}
			if got := p.DialDenied(proto.protocol, testIngressTarget); got != tt.want {
				t.Errorf("DialDenied(%s) with the Enforcer answering (%v, %v) = %v, want %v", proto.protocol, tt.admitted, tt.enforced, got, tt.want)
			}
			if enforcer.calls != 1 {
				t.Errorf("DialDenied(%s): the Enforcer was asked %d times, want once", proto.protocol, enforcer.calls)
			}
			want := []admitCall{{method: proto.method, src: testIngressMeshIP, dst: testIngressTarget}}
			if !slices.Equal(enforcer.asked, want) {
				t.Errorf("DialDenied(%s) asked %+v, want %+v", proto.protocol, enforcer.asked, want)
			}
		}
	}
}

func TestNewIngressDialPolicy(t *testing.T) {
	enforcer := &fakeDialAdmitter{}
	p, err := newIngressDialPolicy(enforcer, "10.99.0.1")
	if err != nil {
		t.Fatalf("newIngressDialPolicy(10.99.0.1): %v", err)
	}
	if p.meshIP != testIngressMeshIP || p.sourceFor == nil || p.enforcer != enforcer {
		t.Errorf("policy = %+v, want meshIP 10.99.0.1, the Enforcer and a source lookup", p)
	}
	if _, err := newIngressDialPolicy(enforcer, "not-an-address"); err == nil {
		t.Error("newIngressDialPolicy(not-an-address): nil error, want the parse error")
	}
}

func TestUDPSourceFor(t *testing.T) {
	src, err := udpSourceFor(netip.MustParseAddrPort("127.0.0.1:9"))
	if err != nil {
		t.Fatalf("udpSourceFor(127.0.0.1:9): %v", err)
	}
	if want := netip.MustParseAddr("127.0.0.1"); src != want {
		t.Errorf("udpSourceFor(127.0.0.1:9) = %s, want %s", src, want)
	}
}
