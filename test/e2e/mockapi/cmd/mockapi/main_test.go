package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// TestStartDNSStub_EmptyAddrRunsNoStub pins that mockapi without -dns-addr
// runs no stub: startDNSStub binds nothing, returns nil and logs nothing.
func TestStartDNSStub_EmptyAddrRunsNoStub(t *testing.T) {
	var logs bytes.Buffer
	stub, err := startDNSStub("", slog.New(slog.NewTextHandler(&logs, nil)))
	if stub != nil || err != nil {
		t.Fatalf("startDNSStub(\"\") = %v, %v; want nil, nil", stub, err)
	}
	if logs.Len() != 0 {
		t.Errorf("startDNSStub(\"\") logged %q, want nothing", logs.String())
	}
}

// TestStartDNSStub_BindsAndLogsTheAddress pins that startDNSStub with an
// address returns a stub bound to it, with the port the kernel chose for
// port 0, and logs "DNS stub started" with that address.
func TestStartDNSStub_BindsAndLogsTheAddress(t *testing.T) {
	var logs bytes.Buffer
	stub, err := startDNSStub("127.0.0.1:0", slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("startDNSStub: %v", err)
	}
	if stub == nil {
		t.Fatal("startDNSStub(\"127.0.0.1:0\") = nil, want a stub")
	}
	t.Cleanup(func() {
		// Serve with an ended context closes the sockets and returns.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := stub.Serve(ctx); err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	addr := stub.Addr()
	if addr.Addr() != netip.MustParseAddr("127.0.0.1") || addr.Port() == 0 {
		t.Fatalf("Addr() = %s, want 127.0.0.1 with the port the kernel chose", addr)
	}
	if want := `msg="DNS stub started" addr=` + addr.String(); !strings.Contains(logs.String(), want) {
		t.Errorf("logs = %q, want a line with %q", logs.String(), want)
	}
}

// TestStartDNSStub_FailsOnATakenAddress pins that startDNSStub returns the
// bind's error, and no stub, when the address is taken, which main turns
// into exit status 1.
func TestStartDNSStub_FailsOnATakenAddress(t *testing.T) {
	taken, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	var logs bytes.Buffer
	stub, err := startDNSStub(taken.LocalAddr().String(), slog.New(slog.NewTextHandler(&logs, nil)))
	if err == nil || stub != nil {
		t.Fatalf("startDNSStub on a taken address = %v, %v; want nil and an error", stub, err)
	}
	if strings.Contains(logs.String(), "DNS stub started") {
		t.Errorf("logs = %q, want no start line after a failed bind", logs.String())
	}
}
