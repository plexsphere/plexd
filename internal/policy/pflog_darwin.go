//go:build darwin

package policy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// pflogIface is the interface pf hands the packets of its log lines to.
	pflogIface = "pflog0"

	// pflogRuleset is what XNU writes into a record's ruleset field for a
	// line of pfAnchor: the anchor's last path component.
	pflogRuleset = "plexd"

	// pflogHdrLen is the size of XNU's struct pfloghdr (bsd/net/if_pflog.h),
	// which precedes the packet in every pflog record.
	pflogHdrLen = 64

	// pfActionPass is XNU's PF_PASS, and pfDirIn and pfDirOut are its PF_IN
	// and PF_OUT, as a pflog record carries them.
	pfActionPass = 0
	pfDirIn      = 1
	pfDirOut     = 2

	// bpfAlignment is BPF_ALIGNMENT in XNU's bsd/net/bpf.h, sizeof(int32_t).
	// The records one read returns start at multiples of it.
	bpfAlignment = 4

	// bpfMaxDevices bounds the search for a free /dev/bpfN. It is XNU's
	// default bpf_maxdevices.
	bpfMaxDevices = 256

	// pflogReadTimeout bounds one read of the BPF device. macOS does not
	// reliably wake a read blocked on a BPF device when another thread closes
	// the device, so the reader checks for its stop signal after every read
	// and close returns within this time.
	pflogReadTimeout = time.Second

	// localAddrsTTL is how long the reader keeps the host's addresses it read
	// last.
	localAddrsTTL = 5 * time.Second
)

// The offsets of the fields of struct pfloghdr the reader uses. rulenr and
// subrulenr are in network order. For a line of an anchor, subrulenr is the
// line's number within the anchor and rulenr that of the anchor rule.
const (
	pflogOffLength    = 0
	pflogOffAction    = 2
	pflogOffRuleset   = 20
	pflogRulesetSize  = 16
	pflogOffSubrulenr = 40
	pflogOffDir       = 60
)

// The offsets of the fields of a BPF record header the reader uses.
const (
	bpfOffCaplen = int(unsafe.Offsetof(unix.BpfHdr{}.Caplen))
	bpfOffHdrlen = int(unsafe.Offsetof(unix.BpfHdr{}.Hdrlen))
)

// pflogRecord is what the reader takes from one pflog record.
type pflogRecord struct {
	action    uint8
	ruleset   string
	subrulenr uint32
	dir       uint8
	packet    []byte
}

// parsePflogRecord reads the pfloghdr at the start of b and the packet behind
// it. XNU writes the header's length as the size up to its padding, and the
// packet starts at that length rounded up to a multiple of 4. It returns false
// when b is shorter than the header or than the rounded length, or when the
// length puts the packet inside the header.
func parsePflogRecord(b []byte) (pflogRecord, bool) {
	if len(b) < pflogHdrLen {
		return pflogRecord{}, false
	}
	start := (int(b[pflogOffLength]) + 3) &^ 3
	if start < pflogHdrLen || start > len(b) {
		return pflogRecord{}, false
	}
	ruleset := b[pflogOffRuleset : pflogOffRuleset+pflogRulesetSize]
	if i := bytes.IndexByte(ruleset, 0); i >= 0 {
		ruleset = ruleset[:i]
	}
	return pflogRecord{
		action:    b[pflogOffAction],
		ruleset:   string(ruleset),
		subrulenr: binary.BigEndian.Uint32(b[pflogOffSubrulenr:]),
		dir:       b[pflogOffDir],
		packet:    b[start:],
	}, true
}

// bpfRecords calls fn with the captured bytes of each record in b, the buffer
// one read of a BPF device filled. A record whose header runs past b ends the
// walk.
func bpfRecords(b []byte, fn func([]byte)) {
	for len(b) >= bpfOffHdrlen+2 {
		caplen := int(binary.NativeEndian.Uint32(b[bpfOffCaplen:]))
		hdrlen := int(binary.NativeEndian.Uint16(b[bpfOffHdrlen:]))
		end := hdrlen + caplen
		if hdrlen < bpfOffHdrlen+2 || end > len(b) {
			return
		}
		fn(b[hdrlen:end])
		next := (end + bpfAlignment - 1) &^ (bpfAlignment - 1)
		if next >= len(b) {
			return
		}
		b = b[next:]
	}
}

// localAddrs tells whether an address is one of the host's, from
// net.InterfaceAddrs read at most once per localAddrsTTL. Only the reader's
// goroutine uses it.
type localAddrs struct {
	list  func() ([]net.Addr, error)
	now   func() time.Time
	addrs []netip.Addr
	read  time.Time
}

// has reports whether addr is an address of the host. A failed read keeps the
// addresses read before.
func (l *localAddrs) has(addr netip.Addr) bool {
	now := l.now()
	if l.read.IsZero() || now.Sub(l.read) >= localAddrsTTL {
		l.read = now
		if list, err := l.list(); err == nil {
			l.addrs = l.addrs[:0]
			for _, a := range list {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ipAddr, ok := netip.AddrFromSlice(ip); ok {
					l.addrs = append(l.addrs, ipAddr.Unmap())
				}
			}
		}
	}
	return slices.Contains(l.addrs, addr.Unmap())
}

// pflogReader reads pf's log records from pflog0 through a BPF device and
// hands its sink an event for each record of a logged plexd line.
type pflogReader struct {
	sink   ConnSink
	logger *slog.Logger
	tag    func(nr uint32) (string, bool)
	local  localAddrs

	// read, drops and release are the device: one read into buf, the count
	// of records the kernel dropped since the device was opened, and closing
	// it. They are seams, which tests replace.
	read    func(b []byte) (int, error)
	drops   func() (uint32, error)
	release func()
	buf     []byte
	dropped uint32

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// start runs the read loop.
func (r *pflogReader) start() {
	r.stop = make(chan struct{})
	r.done = make(chan struct{})
	go r.loop()
}

// running reports whether the read loop still runs.
func (r *pflogReader) running() bool {
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}

// close stops the read loop and waits until it released the device, which
// takes up to pflogReadTimeout. It is safe to call more than once.
func (r *pflogReader) close() {
	r.stopOnce.Do(func() { close(r.stop) })
	<-r.done
}

func (r *pflogReader) stopped() bool {
	select {
	case <-r.stop:
		return true
	default:
		return false
	}
}

// loop reads until close or a read error other than EINTR, and releases the
// device when it ends. After each read it hands the drops the device counted
// since the last read to the sink.
func (r *pflogReader) loop() {
	defer close(r.done)
	defer r.release()

	for !r.stopped() {
		n, err := r.read(r.buf)
		if r.stopped() {
			return
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			r.logger.Warn("policy connection log reader stopped",
				"component", "policy",
				"error", fmt.Errorf("policy: pf: pflog: read: %w", err),
			)
			return
		}
		bpfRecords(r.buf[:n], r.record)

		if drops, err := r.drops(); err == nil {
			if drops != r.dropped {
				r.sink.Lost(int(drops - r.dropped))
			}
			r.dropped = drops
		}
	}
}

// record hands the sink the event one pflog record reports, when the record
// is a pass of a logged line of plexd's anchor. pf's direction out is the
// node's own traffic. Its direction in is traffic addressed to the node when
// the destination is an address of the host, and traffic it forwards
// otherwise.
func (r *pflogReader) record(b []byte) {
	rec, ok := parsePflogRecord(b)
	if !ok || rec.ruleset != pflogRuleset || rec.action != pfActionPass {
		return
	}
	tag, ok := r.tag(rec.subrulenr)
	if !ok {
		return
	}
	src, dst, proto, srcPort, dstPort, ok := parseIPTuple(rec.packet)
	if !ok {
		return
	}

	var dir ConnDir
	switch rec.dir {
	case pfDirOut:
		dir = ConnOut
	case pfDirIn:
		dir = ConnForward
		if r.local.has(dst) {
			dir = ConnIn
		}
	default:
		return
	}

	r.sink.Event(ConnEvent{
		Tag:      tag,
		Dir:      dir,
		Src:      src,
		Dst:      dst,
		Protocol: proto,
		SrcPort:  srcPort,
		DstPort:  dstPort,
	})
}

// openPflog starts a reader on pflog0 that reports to c.sink. XNU creates no
// pflog instance at boot (bsd/net/if_pflog.c), so openPflog creates pflog0
// when it is missing. XNU hands a log line's packets to pflog0 only while a
// BPF reader is attached, and does not check that the interface is up, so
// plexd leaves its flags alone.
//
// The caller holds c.mu.
func (c *PFController) openPflog() (*pflogReader, error) {
	if _, err := net.InterfaceByName(pflogIface); err != nil {
		if err := c.createPflog(); err != nil {
			return nil, err
		}
	}

	fd, err := openBPF()
	if err != nil {
		return nil, err
	}
	bufLen, err := attachPflog(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	r := &pflogReader{
		sink:   c.sink,
		logger: c.logger,
		tag:    c.pflogTag,
		local:  localAddrs{list: net.InterfaceAddrs, now: time.Now},
		read: func(b []byte) (int, error) {
			return unix.Read(fd, b)
		},
		drops: func() (uint32, error) {
			var st unix.BpfStat
			err := bpfIoctl(fd, unix.BIOCGSTATS, unsafe.Pointer(&st))
			return st.Drop, err
		},
		release: func() {
			_ = unix.Close(fd)
		},
		buf: make([]byte, bufLen),
	}
	r.start()

	c.logger.Debug("pflog reader started",
		"component", "policy",
		"interface", pflogIface,
	)
	return r, nil
}

// createPflog creates pflog0 with ifconfig(8).
func (c *PFController) createPflog() error {
	// Absolute for the reason pfctlPath is.
	const ifconfig = "/sbin/ifconfig"

	ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
	defer cancel()

	out, err := c.run(ctx, nil, ifconfig, pflogIface, "create")
	if err == nil {
		return nil
	}
	argv := ifconfig + " " + pflogIface + " create"
	if detail := strings.TrimSpace(string(out)); detail != "" {
		return fmt.Errorf("policy: pf: pflog: %s: %w: %s", argv, err, detail)
	}
	return fmt.Errorf("policy: pf: pflog: %s: %w", argv, err)
}

// openBPF opens the first free BPF device. XNU creates a further device when
// the last one is opened, up to bpf_maxdevices, so the search ends at the
// first device that does not exist.
func openBPF() (int, error) {
	for i := range bpfMaxDevices {
		name := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		switch {
		case err == nil:
			return fd, nil
		case errors.Is(err, unix.EBUSY):
			continue
		case errors.Is(err, unix.ENOENT):
			return -1, errors.New("policy: pf: pflog: no free bpf device")
		default:
			return -1, fmt.Errorf("policy: pf: pflog: open %s: %w", name, err)
		}
	}
	return -1, errors.New("policy: pf: pflog: no free bpf device")
}

// attachPflog attaches the BPF device fd to pflog0, so that a read returns
// as soon as a record arrives or the read timeout passes. It returns the
// device's buffer length, the size every read has to ask for.
func attachPflog(fd int) (int, error) {
	// BIOCSETIF takes a struct ifreq, 32 bytes on macOS, of which it reads
	// the name.
	var ifr [32]byte
	copy(ifr[:], pflogIface)
	if err := bpfIoctl(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr)); err != nil {
		return 0, fmt.Errorf("policy: pf: pflog: attach to %s: %w", pflogIface, err)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		return 0, fmt.Errorf("policy: pf: pflog: immediate mode: %w", err)
	}
	tv := unix.NsecToTimeval(pflogReadTimeout.Nanoseconds())
	if err := bpfIoctl(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
		return 0, fmt.Errorf("policy: pf: pflog: read timeout: %w", err)
	}
	dlt, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil {
		return 0, fmt.Errorf("policy: pf: pflog: link type: %w", err)
	}
	if dlt != unix.DLT_PFLOG {
		return 0, fmt.Errorf("policy: pf: pflog: %s has link type %d, want %d", pflogIface, dlt, unix.DLT_PFLOG)
	}
	bufLen, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil {
		return 0, fmt.Errorf("policy: pf: pflog: buffer length: %w", err)
	}
	return bufLen, nil
}

// bpfIoctl runs an ioctl whose argument points to a struct that
// golang.org/x/sys/unix has no typed helper for: a struct ifreq, a timeval or
// a bpf_stat. x/sys/unix wraps libSystem's ioctl only for the argument types
// it names, so this call enters the kernel directly.
func bpfIoctl(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)) //nolint:staticcheck // x/sys/unix has no libSystem ioctl for a struct argument
	if errno != 0 {
		return errno
	}
	return nil
}
