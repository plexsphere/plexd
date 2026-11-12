//go:build linux

package policy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// nflogSink records what a reader hands its sink, in order. It is safe for
// concurrent use.
type nflogSink struct {
	mu     sync.Mutex
	calls  []string
	events []ConnEvent
}

func (s *nflogSink) Event(ev ConnEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "event "+ev.Tag)
	s.events = append(s.events, ev)
}

func (s *nflogSink) Lost(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, fmt.Sprintf("lost %d", n))
}

func (s *nflogSink) recorded() (calls []string, events []ConnEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...), append([]ConnEvent(nil), s.events...)
}

// waitEvent waits up to timeout for an event match accepts and reports
// whether one arrived.
func (s *nflogSink) waitEvent(timeout time.Duration, match func(ConnEvent) bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		_, events := s.recorded()
		for _, ev := range events {
			if match(ev) {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// fakeNflogSock stands in for a reader's socket: closing it closes the
// channel, which ends a fake receive blocked on it.
type fakeNflogSock chan struct{}

func (c fakeNflogSock) Close() error {
	close(c)
	return nil
}

// nflogPacketType is the header type of an NFLOG packet message.
const nflogPacketType = netlink.HeaderType(unix.NFNL_SUBSYS_ULOG<<8 | nfulnlMsgPacket)

// nflogPacket builds an NFLOG packet message as the kernel sends it for hook:
// the packet header, the prefix, the input interface index, and the payload.
// A nil prefix or payload leaves that attribute out.
func nflogPacket(t *testing.T, hook uint8, prefix, payload []byte) netlink.Message {
	t.Helper()
	attrs := []netlink.Attribute{
		// ETH_P_IP in network byte order, the hook, a pad byte.
		{Type: nfulaPacketHdr, Data: []byte{0x08, 0x00, hook, 0}},
	}
	if prefix != nil {
		attrs = append(attrs, netlink.Attribute{Type: nfulaPrefix, Data: prefix})
	}
	// NFULA_IFINDEX_INDEV, which the reader skips.
	attrs = append(attrs, netlink.Attribute{Type: 4, Data: []byte{0, 0, 0, 7}})
	if payload != nil {
		attrs = append(attrs, netlink.Attribute{Type: nfulaPayload, Data: payload})
	}
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		t.Fatalf("marshal attributes: %v", err)
	}
	return netlink.Message{
		Header: netlink.Header{Type: nflogPacketType},
		Data:   append([]byte{unix.AF_INET, unix.NFNETLINK_V0, 0x70, 0x64}, b...),
	}
}

var (
	nflogPeer = netip.MustParseAddr("10.99.0.3")
	nflogNode = netip.MustParseAddr("10.99.0.1")
)

// nflogSyn is the payload of a TCP SYN from 10.99.0.3:41001 to 10.99.0.1:7001.
func nflogSyn() []byte {
	return buildIPv4TCPSyn(nflogPeer, nflogNode, 41001, 7001, 1)
}

func TestNflogConfigMessages(t *testing.T) {
	msgs := nflogConfigMessages(28772)
	if len(msgs) != 2 {
		t.Fatalf("nflogConfigMessages returned %d messages, want 2", len(msgs))
	}

	// NFNL_SUBSYS_ULOG<<8 | NFULNL_MSG_CONFIG, a request the kernel
	// acknowledges.
	const configType = netlink.HeaderType(4<<8 | 1)
	// AF_UNSPEC, NFNETLINK_V0, res_id 28772 in network byte order.
	nfgenmsg := []byte{0, 0, 0x70, 0x64}
	// attr builds a netlink attribute header in host byte order, the data,
	// and the padding to 4 bytes.
	attr := func(typ uint16, data ...byte) []byte {
		b := binary.NativeEndian.AppendUint16(nil, uint16(4+len(data)))
		b = binary.NativeEndian.AppendUint16(b, typ)
		b = append(b, data...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	want := [][]byte{
		// NFULA_CFG_CMD: NFULNL_CFG_CMD_BIND.
		append(append([]byte(nil), nfgenmsg...), attr(1, 1)...),
		// NFULA_CFG_MODE: copy_range 128 in network byte order,
		// NFULNL_COPY_PACKET, a pad byte.
		append(append([]byte(nil), nfgenmsg...), attr(2, 0, 0, 0, 128, 2, 0)...),
	}
	for i, msg := range msgs {
		if msg.Header.Type != configType {
			t.Errorf("message %d: type %#x, want %#x", i, msg.Header.Type, configType)
		}
		if msg.Header.Flags != netlink.Request|netlink.Acknowledge {
			t.Errorf("message %d: flags %v, want request and acknowledge", i, msg.Header.Flags)
		}
		if !bytes.Equal(msg.Data, want[i]) {
			t.Errorf("message %d: data % x, want % x", i, msg.Data, want[i])
		}
	}
}

// The reader binds through the same messages the kernel acknowledges one by
// one, and reports a refusal with the group in its error.
func TestBindNflog(t *testing.T) {
	var sent []netlink.Message
	conn := nltest.Dial(func(reqs []netlink.Message) ([]netlink.Message, error) {
		sent = append(sent, reqs...)
		return nltest.Error(0, reqs)
	})
	defer func() { _ = conn.Close() }()
	if err := bindNflog(conn, nflogGroup); err != nil {
		t.Fatalf("bindNflog() error = %v, want nil", err)
	}
	want := nflogConfigMessages(nflogGroup)
	if len(sent) != len(want) {
		t.Fatalf("bindNflog sent %d messages, want %d", len(sent), len(want))
	}
	for i := range want {
		if sent[i].Header.Type != want[i].Header.Type || sent[i].Header.Flags != want[i].Header.Flags || !bytes.Equal(sent[i].Data, want[i].Data) {
			t.Errorf("message %d sent: %+v, want %+v", i, sent[i], want[i])
		}
	}

	busy := nltest.Dial(func(reqs []netlink.Message) ([]netlink.Message, error) {
		return nltest.Error(int(unix.EBUSY), reqs)
	})
	defer func() { _ = busy.Close() }()
	err := bindNflog(busy, nflogGroup)
	if err == nil || !errors.Is(err, unix.EBUSY) {
		t.Fatalf("bindNflog() error = %v, want one wrapping EBUSY", err)
	}
	if want := "policy: nftables: nflog: bind group 28772: "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("bindNflog() error = %q, want one starting %q", err, want)
	}
}

// Without CAP_NET_ADMIN the kernel refuses the bind, and the error names the
// group. As root the test binds in a network namespace of its own.
func TestOpenNflogRequiresPrivileges(t *testing.T) {
	inTestNetns(t, func() {
		r, err := openNflog(nflogGroup, &nflogSink{}, discardLoggerNft())
		if err == nil {
			if err := r.Close(); err != nil {
				t.Errorf("Close() error = %v, want nil", err)
			}
			return
		}
		if want := "policy: nftables: nflog: bind group 28772: "; !strings.HasPrefix(err.Error(), want) {
			t.Errorf("openNflog() error = %q, want one starting %q", err, want)
		}
	})
}

func TestParseNflogPacket(t *testing.T) {
	for _, tc := range []struct {
		hook uint8
		want ConnDir
	}{
		{unix.NF_INET_LOCAL_IN, ConnIn},
		{unix.NF_INET_FORWARD, ConnForward},
		{unix.NF_INET_LOCAL_OUT, ConnOut},
	} {
		got, ok := parseNflogPacket(nflogPacket(t, tc.hook, []byte("1/0\x00"), nflogSyn()))
		if !ok {
			t.Errorf("hook %d: parseNflogPacket returned false, want an event", tc.hook)
			continue
		}
		want := ConnEvent{Tag: "1/0", Dir: tc.want, Src: nflogPeer, Dst: nflogNode, Protocol: 6, SrcPort: 41001, DstPort: 7001}
		if got != want {
			t.Errorf("hook %d: parseNflogPacket = %+v, want %+v", tc.hook, got, want)
		}
	}
}

func TestParseNflogPacketRefuses(t *testing.T) {
	config := nflogPacket(t, unix.NF_INET_LOCAL_IN, []byte("1/0\x00"), nflogSyn())
	config.Header.Type = netlink.HeaderType(unix.NFNL_SUBSYS_ULOG<<8 | nfulnlMsgConfig)
	short := nflogPacket(t, unix.NF_INET_LOCAL_IN, []byte("1/0\x00"), nflogSyn())
	short.Data = short.Data[:3]
	version5 := nflogSyn()
	version5[0] = 0x55

	for name, msg := range map[string]netlink.Message{
		"hook 4 (postrouting)":      nflogPacket(t, unix.NF_INET_POST_ROUTING, []byte("1/0\x00"), nflogSyn()),
		"no NFULA_PAYLOAD":          nflogPacket(t, unix.NF_INET_LOCAL_IN, []byte("1/0\x00"), nil),
		"no NFULA_PREFIX":           nflogPacket(t, unix.NF_INET_LOCAL_IN, nil, nflogSyn()),
		"NFULNL_MSG_CONFIG":         config,
		"shorter than its nfgenmsg": short,
		"a payload of version 5":    nflogPacket(t, unix.NF_INET_LOCAL_IN, []byte("1/0\x00"), version5),
		"multipart done":            {Header: netlink.Header{Type: netlink.Done, Flags: netlink.Multi}, Data: []byte{0, 0, 0, 0}},
	} {
		if ev, ok := parseNflogPacket(msg); ok {
			t.Errorf("%s: parseNflogPacket = %+v, true; want false", name, ev)
		}
	}
}

// A buffer overflow costs records but not the reader: it counts one lost
// record and reads on.
func TestNflogReaderReadsOnAfterENOBUFS(t *testing.T) {
	var buf bytes.Buffer
	sink := &nflogSink{}
	r := newNflogReader(nil, sink, captureLogger(&buf))
	packet := nflogPacket(t, unix.NF_INET_LOCAL_IN, []byte("1/0\x00"), nflogSyn())

	call := 0
	r.read(func() ([]netlink.Message, error) {
		call++
		switch call {
		case 1:
			// What netlink.Conn.Receive returns when the kernel overflowed
			// the receive buffer.
			return nil, &netlink.OpError{Op: "receive", Err: os.NewSyscallError("recvmsg", unix.ENOBUFS)}
		case 2:
			return []netlink.Message{packet}, nil
		default:
			// Close sets the flag before it closes the socket, whose
			// blocked read then fails.
			r.closed.Store(true)
			return nil, errors.New("use of closed file")
		}
	})

	calls, _ := sink.recorded()
	if want := []string{"lost 1", "event 1/0"}; !reflect.DeepEqual(calls, want) {
		t.Errorf("sink calls = %q, want %q", calls, want)
	}
	if r.running() {
		t.Error("running() = true after the loop returned")
	}
	if buf.Len() != 0 {
		t.Errorf("the reader logged %q, want nothing for a closed socket", buf.String())
	}
}

// Any other read error ends the loop with a Warn line.
func TestNflogReaderStopsOnError(t *testing.T) {
	var buf bytes.Buffer
	sink := &nflogSink{}
	r := newNflogReader(nil, sink, captureLogger(&buf))

	calls := 0
	r.read(func() ([]netlink.Message, error) {
		calls++
		return nil, &netlink.OpError{Op: "receive", Err: os.NewSyscallError("recvmsg", unix.EBADMSG)}
	})

	if calls != 1 {
		t.Errorf("receive was called %d times, want once", calls)
	}
	if r.running() {
		t.Error("running() = true after the loop returned")
	}
	out := buf.String()
	for _, want := range []string{"level=WARN", `msg="policy connection log reader stopped"`, "component=policy", "error=", "bad message"} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q lacks %q", out, want)
		}
	}
	if got, _ := sink.recorded(); len(got) != 0 {
		t.Errorf("sink calls = %q, want none", got)
	}
}

// Close ends a read blocked on the socket and waits for the loop, and a second
// Close is a no-op.
func TestNflogReaderClose(t *testing.T) {
	var buf bytes.Buffer
	sock := make(fakeNflogSock)
	r := newNflogReader(sock, &nflogSink{}, captureLogger(&buf))
	go r.read(func() ([]netlink.Message, error) {
		<-sock
		return nil, errors.New("use of closed file")
	})

	if !r.running() {
		t.Fatal("running() = false before Close")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
	if r.running() {
		t.Error("running() = true after Close returned")
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close() error = %v, want nil", err)
	}
	if buf.Len() != 0 {
		t.Errorf("the reader logged %q, want nothing when it is closed", buf.String())
	}
}

// fakeNflog is an openLog seam whose readers read nothing and run until they
// are closed or their fail channel is closed, which ends the loop as a
// failed read would.
type fakeNflog struct {
	mu      sync.Mutex
	groups  []uint16
	sinks   []ConnSink
	readers []*nflogReader
	fails   []chan struct{}
}

func (f *fakeNflog) open(group uint16, sink ConnSink, logger *slog.Logger) (*nflogReader, error) {
	sock := make(fakeNflogSock)
	fail := make(chan struct{})
	r := newNflogReader(sock, sink, logger)
	go r.read(func() ([]netlink.Message, error) {
		select {
		case <-sock:
			return nil, errors.New("use of closed file")
		case <-fail:
			return nil, errors.New("recvmsg: bad message")
		}
	})

	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups = append(f.groups, group)
	f.sinks = append(f.sinks, sink)
	f.readers = append(f.readers, r)
	f.fails = append(f.fails, fail)
	return r, nil
}

func (f *fakeNflog) opened() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.readers)
}
