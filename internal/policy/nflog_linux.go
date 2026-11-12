//go:build linux

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The parts of the kernel's linux/netfilter/nfnetlink_log.h the reader needs,
// which golang.org/x/sys/unix does not carry. It does carry NFNL_SUBSYS_ULOG,
// the subsystem these messages belong to, and the hook numbers.
const (
	nfulnlMsgPacket = 0 // NFULNL_MSG_PACKET: a logged packet
	nfulnlMsgConfig = 1 // NFULNL_MSG_CONFIG: configures a group

	nfulaPacketHdr = 1  // NFULA_PACKET_HDR: hardware protocol, hook, pad
	nfulaPayload   = 9  // NFULA_PAYLOAD: the packet from its network header
	nfulaPrefix    = 10 // NFULA_PREFIX: the log prefix, NUL-terminated

	nfulaCfgCmd  = 1 // NFULA_CFG_CMD: a struct nfulnl_msg_config_cmd
	nfulaCfgMode = 2 // NFULA_CFG_MODE: a packed struct nfulnl_msg_config_mode

	nfulnlCfgCmdBind = 1 // NFULNL_CFG_CMD_BIND: bind the socket to the group
	nfulnlCopyPacket = 2 // NFULNL_COPY_PACKET: copy the packet's first bytes
)

const (
	// nfgenmsgLen is the size of struct nfgenmsg, which opens every
	// nfnetlink message ahead of its attributes.
	nfgenmsgLen = 4

	// nflogCopyRange is how many bytes of a packet the kernel copies into a
	// record: an IPv6 header and the ports of the TCP or UDP header behind
	// it fit with room to spare.
	nflogCopyRange = 128

	// nflogReadBuffer is the receive buffer the reader asks for, so a burst
	// of new connections queues rather than overflows into ENOBUFS.
	nflogReadBuffer = 1 << 20
)

// nflogReader reads the records plexd's log rules write to an NFLOG group and
// hands each one to its sink as a ConnEvent.
type nflogReader struct {
	conn   io.Closer // the socket; closing it ends a blocked read
	sink   ConnSink
	logger *slog.Logger

	closed atomic.Bool
	done   chan struct{} // closed when the read loop ends
}

// newNflogReader returns a reader for conn whose loop has not started.
func newNflogReader(conn io.Closer, sink ConnSink, logger *slog.Logger) *nflogReader {
	return &nflogReader{conn: conn, sink: sink, logger: logger, done: make(chan struct{})}
}

// openNflog binds a NETLINK_NETFILTER socket to NFLOG group group and starts
// the loop that reads it. It dials in the network namespace of the calling
// thread, as google/nftables does for the rules, so the socket receives what
// the rules in that namespace log. Every failure starts
// "policy: nftables: nflog: bind group <group>: ", the kernel's refusal
// included when another socket holds the group.
func openNflog(group uint16, sink ConnSink, logger *slog.Logger) (*nflogReader, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, fmt.Errorf("policy: nftables: nflog: bind group %d: %w", group, err)
	}
	// The option never fails: a host that caps the buffer leaves the reader
	// with less room, which ENOBUFS and Lost then report.
	_ = sizeSocketBuffers(nflogReadBuffer)(conn)

	if err := bindNflog(conn, group); err != nil {
		_ = conn.Close()
		return nil, err
	}

	r := newNflogReader(conn, sink, logger)
	go r.read(conn.Receive)
	return r, nil
}

// bindNflog sends the messages nflogConfigMessages builds and waits for the
// kernel to acknowledge each one.
func bindNflog(conn *netlink.Conn, group uint16) error {
	for _, msg := range nflogConfigMessages(group) {
		if _, err := conn.Execute(msg); err != nil {
			return fmt.Errorf("policy: nftables: nflog: bind group %d: %w", group, err)
		}
	}
	return nil
}

// nflogConfigMessages returns the two acknowledged config messages that bind
// a socket to NFLOG group group: NFULA_CFG_CMD BIND, then NFULA_CFG_MODE with
// a copy range of nflogCopyRange bytes and NFULNL_COPY_PACKET. Each opens with
// a struct nfgenmsg naming no family and the group in network byte order.
func nflogConfigMessages(group uint16) []netlink.Message {
	msg := func(attr netlink.Attribute) netlink.Message {
		// MarshalAttributes fails only for an attribute whose Length is set
		// below the header's, and these leave Length to it.
		attrs, _ := netlink.MarshalAttributes([]netlink.Attribute{attr})
		data := append([]byte{unix.AF_UNSPEC, unix.NFNETLINK_V0, byte(group >> 8), byte(group)}, attrs...)
		return netlink.Message{
			Header: netlink.Header{
				Type:  netlink.HeaderType(unix.NFNL_SUBSYS_ULOG<<8 | nfulnlMsgConfig),
				Flags: netlink.Request | netlink.Acknowledge,
			},
			Data: data,
		}
	}
	return []netlink.Message{
		msg(netlink.Attribute{Type: nfulaCfgCmd, Data: []byte{nfulnlCfgCmdBind}}),
		// copy_range is a 32-bit value in network byte order, then copy_mode
		// and a pad byte.
		msg(netlink.Attribute{Type: nfulaCfgMode, Data: []byte{0, 0, 0, nflogCopyRange, nfulnlCopyPacket, 0}}),
	}
}

// parseNflogPacket turns an NFLOG packet message into the event it reports.
// The hook in byte 2 of NFULA_PACKET_HDR gives the direction, the prefix up to
// its NUL the tag, and NFULA_PAYLOAD the addresses, protocol and ports. It
// returns false for any other message type, a hook other than input, forward
// and output, a missing attribute, and a payload parseIPTuple refuses.
func parseNflogPacket(msg netlink.Message) (ConnEvent, bool) {
	if msg.Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_ULOG<<8|nfulnlMsgPacket) || len(msg.Data) < nfgenmsgLen {
		return ConnEvent{}, false
	}
	ad, err := netlink.NewAttributeDecoder(msg.Data[nfgenmsgLen:])
	if err != nil {
		return ConnEvent{}, false
	}
	var hdr, prefix, payload []byte
	var hasPrefix, hasPayload bool
	for ad.Next() {
		switch ad.Type() {
		case nfulaPacketHdr:
			hdr = ad.Bytes()
		case nfulaPrefix:
			prefix, hasPrefix = ad.Bytes(), true
		case nfulaPayload:
			payload, hasPayload = ad.Bytes(), true
		}
	}
	if ad.Err() != nil || len(hdr) < 3 || !hasPrefix || !hasPayload {
		return ConnEvent{}, false
	}

	var ev ConnEvent
	switch hdr[2] {
	case unix.NF_INET_LOCAL_IN:
		ev.Dir = ConnIn
	case unix.NF_INET_FORWARD:
		ev.Dir = ConnForward
	case unix.NF_INET_LOCAL_OUT:
		ev.Dir = ConnOut
	default:
		return ConnEvent{}, false
	}
	tag, _, _ := bytes.Cut(prefix, []byte{0})
	ev.Tag = string(tag)

	var ok bool
	ev.Src, ev.Dst, ev.Protocol, ev.SrcPort, ev.DstPort, ok = parseIPTuple(payload)
	if !ok {
		return ConnEvent{}, false
	}
	return ev, true
}

// read hands every packet record receive returns to the sink until the reader
// is closed or receive fails. receive is the socket's Receive in production.
//
// An overflowed receive buffer makes the kernel drop records and report
// ENOBUFS once; the reader counts that as one lost record and goes on, since
// the kernel does not say how many it dropped. Any other error ends the loop
// with a Warn line, and the next ApplyRules with a logged rule opens a new
// reader.
func (r *nflogReader) read(receive func() ([]netlink.Message, error)) {
	defer close(r.done)
	for {
		msgs, err := receive()
		if err != nil {
			if r.closed.Load() {
				return
			}
			if errors.Is(err, unix.ENOBUFS) {
				r.sink.Lost(1)
				continue
			}
			r.logger.Warn("policy connection log reader stopped",
				"component", "policy",
				"error", err,
			)
			return
		}
		for _, msg := range msgs {
			if ev, ok := parseNflogPacket(msg); ok {
				r.sink.Event(ev)
			}
		}
	}
}

// running reports whether the read loop still runs.
func (r *nflogReader) running() bool {
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}

// Close closes the socket, which releases the group, and waits for the read
// loop to end, so the sink receives nothing after Close returns.
func (r *nflogReader) Close() error {
	if r.closed.Swap(true) {
		<-r.done
		return nil
	}
	err := r.conn.Close()
	<-r.done
	return err
}
