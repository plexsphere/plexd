//go:build linux

package relaybpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// object is relay.bpf.c as `make bpf` compiled it.
//
//go:embed relay_bpfel.o
var object []byte

// The names the object declares, as relay.bpf.c spells them.
// TestObject_MatchesTheLoader checks that the embedded object holds them.
const (
	programName     = "relay_forward"
	sessionsMapName = "relay_sessions"
	countersMapName = "relay_counters"
)

// sessionSize is the size of struct relay_session in relay.bpf.c.
const sessionSize = 88

// The offsets of the fields of struct relay_session. An address field holds
// 16 bytes, of which an IPv4 address fills the first 4.
const (
	offsetPartner     = 0  // psrc
	offsetPartnerDst  = 16 // pdst
	offsetOwner       = 32 // dst
	offsetOwnerSrc    = 48 // local
	offsetPartnerPort = 64 // psport, big-endian
	offsetOwnerPort   = 66 // dport, big-endian
	offsetOwnerIf     = 68 // oif, native byte order
	offsetUsedNS      = 72 // used_ns, native byte order
	offsetFamily      = 80 // family; the 7 bytes behind it stay zero
)

// batchSize is how many sessions Ages reads with one system call.
const batchSize = 4096

// probeIfindex is the interface Load attaches to once to find out whether
// the kernel supports tcx. The loopback interface has index 1 in every
// network namespace, so the probe needs no lookup and works in any of them.
const probeIfindex = 1

// errMixedFamilies is what Put returns for a Session whose addresses are not
// all of one family: the program matches and rewrites one family per entry.
var errMixedFamilies = errors.New("relaybpf: session mixes address families")

// Session is one entry of the program's session table.
type Session struct {
	Partner    netip.AddrPort // the datagram's source
	PartnerDst netip.Addr     // the local address the partner sends to
	Owner      netip.AddrPort // the new destination
	OwnerSrc   netip.Addr     // the new source
	OwnerIf    int            // the interface the route to Owner leaves by
}

// Forwarder is the loaded program with its maps and the links that attach it
// to interfaces. Closing it, or the end of the process, detaches the program
// from every interface: nothing is pinned to bpffs. A Forwarder is not safe
// for concurrent use; the relay calls it with its own lock held.
type Forwarder struct {
	coll     *ebpf.Collection
	program  *ebpf.Program
	sessions *ebpf.Map
	counters *ebpf.Map
	// links holds the tcx link of every interface Attach attached to, by
	// interface index.
	links map[int]link.Link
}

// Load loads the program into the kernel for a relay that listens on port and
// routes through the interface with index lookupIfindex, which is the mesh
// interface. It does not raise RLIMIT_MEMLOCK: the kernels with tcx account
// BPF memory to the cgroup instead.
//
// Load attaches the program to the loopback interface and detaches it at once,
// so a kernel without tcx fails here, at the start, with a named error. The
// session table is still empty then, so the probe forwards nothing.
func Load(port uint16, lookupIfindex int) (*Forwarder, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("relaybpf: read object: %w", err)
	}
	// Assign fails when the object lacks one of the two constants.
	var consts struct {
		Port    *ebpf.VariableSpec `ebpf:"relay_port"`
		Ifindex *ebpf.VariableSpec `ebpf:"lookup_ifindex"`
	}
	if err := spec.Assign(&consts); err != nil {
		return nil, fmt.Errorf("relaybpf: read object: %w", err)
	}
	// The program compares relay_port with the UDP header as it stands, so
	// it is set in network byte order whatever the host's byte order is.
	if err := consts.Port.Set([2]byte{byte(port >> 8), byte(port)}); err != nil {
		return nil, fmt.Errorf("relaybpf: read object: %w", err)
	}
	if err := consts.Ifindex.Set(uint32(lookupIfindex)); err != nil {
		return nil, fmt.Errorf("relaybpf: read object: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("relaybpf: load: %w", err)
	}
	f := &Forwarder{
		coll:     coll,
		program:  coll.Programs[programName],
		sessions: coll.Maps[sessionsMapName],
		counters: coll.Maps[countersMapName],
		links:    make(map[int]link.Link),
	}

	probe, err := link.AttachTCX(link.TCXOptions{
		Interface: probeIfindex,
		Program:   f.program,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err == nil {
		err = probe.Close()
	}
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("relaybpf: tcx attach probe: %w", err)
	}
	return f, nil
}

// Attach attaches the program at tcx ingress of the interface with index
// ifindex. A second call for the same interface returns nil and attaches
// nothing more.
func (f *Forwarder) Attach(ifindex int) error {
	if _, ok := f.links[ifindex]; ok {
		return nil
	}
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   f.program,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("relaybpf: tcx attach: %w", err)
	}
	f.links[ifindex] = l
	return nil
}

// Put installs s as the session of index, replacing an entry the table
// already holds for it. The entry counts as used now, so its age starts at 0.
func (f *Forwarder) Put(index uint32, s Session) error {
	now, err := monotonicNow()
	if err != nil {
		return err
	}
	value, err := s.encode(now)
	if err != nil {
		return err
	}
	if err := f.sessions.Update(sessionKey(index), value[:], ebpf.UpdateAny); err != nil {
		return fmt.Errorf("relaybpf: write session: %w", err)
	}
	return nil
}

// Delete removes the session of index. An index the table does not hold is
// no error.
func (f *Forwarder) Delete(index uint32) error {
	err := f.sessions.Delete(sessionKey(index))
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("relaybpf: delete session: %w", err)
	}
	return nil
}

// Age returns how long ago the program last forwarded a datagram naming
// index, or Put installed it when none has been forwarded since. It reports
// false when the table does not hold index.
func (f *Forwarder) Age(index uint32) (time.Duration, bool, error) {
	var value [sessionSize]byte
	if err := f.sessions.Lookup(sessionKey(index), &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("relaybpf: read session: %w", err)
	}
	now, err := monotonicNow()
	if err != nil {
		return 0, false, err
	}
	return elapsed(now, usedNS(value)), true, nil
}

// Ages returns Age for every index the table holds. It reads the table in
// batches, which takes a few system calls for a full table where an
// iteration takes two per entry.
func (f *Forwarder) Ages() (map[uint32]time.Duration, error) {
	keys := make([][4]byte, batchSize)
	values := make([][sessionSize]byte, batchSize)
	used := make(map[uint32]uint64)
	var cursor ebpf.MapBatchCursor
	for {
		n, err := f.sessions.BatchLookup(&cursor, keys, values, nil)
		for i := range n {
			used[binary.LittleEndian.Uint32(keys[i][:])] = usedNS(values[i])
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("relaybpf: read sessions: %w", err)
		}
	}

	// The clock is read after the table, so a datagram forwarded during the
	// read does not make its age negative.
	now, err := monotonicNow()
	if err != nil {
		return nil, err
	}
	ages := make(map[uint32]time.Duration, len(used))
	for index, ns := range used {
		ages[index] = elapsed(now, ns)
	}
	return ages, nil
}

// Counters returns the program's counters, keyed by CounterNames. Each
// counter is the sum of its slot over all CPUs.
func (f *Forwarder) Counters() (map[string]uint64, error) {
	counters := make(map[string]uint64, len(CounterNames))
	var perCPU []uint64
	for slot, name := range CounterNames {
		if err := f.counters.Lookup(uint32(slot), &perCPU); err != nil {
			return nil, fmt.Errorf("relaybpf: read counter %s: %w", name, err)
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		counters[name] = sum
	}
	return counters, nil
}

// Close closes every link, which detaches the program from its interface,
// then the program and its maps.
func (f *Forwarder) Close() error {
	var errs []error
	for ifindex, l := range f.links {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("relaybpf: tcx detach from interface %d: %w", ifindex, err))
		}
		delete(f.links, ifindex)
	}
	f.coll.Close()
	return errors.Join(errs...)
}

// sessionKey returns the key of index in the session table. The program
// looks an entry up by the four index bytes as they stand in the datagram,
// where WireGuard writes the index little-endian, so the key is written
// little-endian too and matches on a host of either byte order.
func sessionKey(index uint32) [4]byte {
	var key [4]byte
	binary.LittleEndian.PutUint32(key[:], index)
	return key
}

// encode returns s as the bytes of struct relay_session, with usedNS as
// used_ns. An IPv4-mapped IPv6 address counts as the IPv4 address it maps,
// because the datagrams of such a peer arrive as IPv4.
func (s Session) encode(usedNS uint64) ([sessionSize]byte, error) {
	var value [sessionSize]byte
	partner := s.Partner.Addr().Unmap()
	partnerDst := s.PartnerDst.Unmap()
	owner := s.Owner.Addr().Unmap()
	ownerSrc := s.OwnerSrc.Unmap()

	var family byte
	switch {
	case partner.Is4() && partnerDst.Is4() && owner.Is4() && ownerSrc.Is4():
		family = unix.AF_INET
	case partner.Is6() && partnerDst.Is6() && owner.Is6() && ownerSrc.Is6():
		family = unix.AF_INET6
	default:
		return value, errMixedFamilies
	}

	// AsSlice gives 4 bytes for an IPv4 address, which fill the start of its
	// 16-byte field, and 16 for an IPv6 address.
	copy(value[offsetPartner:], partner.AsSlice())
	copy(value[offsetPartnerDst:], partnerDst.AsSlice())
	copy(value[offsetOwner:], owner.AsSlice())
	copy(value[offsetOwnerSrc:], ownerSrc.AsSlice())
	binary.BigEndian.PutUint16(value[offsetPartnerPort:], s.Partner.Port())
	binary.BigEndian.PutUint16(value[offsetOwnerPort:], s.Owner.Port())
	binary.NativeEndian.PutUint32(value[offsetOwnerIf:], uint32(s.OwnerIf))
	binary.NativeEndian.PutUint64(value[offsetUsedNS:], usedNS)
	value[offsetFamily] = family
	return value, nil
}

// usedNS returns the used_ns field of an encoded session.
func usedNS(value [sessionSize]byte) uint64 {
	return binary.NativeEndian.Uint64(value[offsetUsedNS:])
}

// monotonicNow returns the CLOCK_MONOTONIC time in nanoseconds, which is the
// clock bpf_ktime_get_ns reads.
func monotonicNow() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("relaybpf: read clock: %w", err)
	}
	return uint64(ts.Nano()), nil
}

// elapsed returns how long before now the monotonic time used was. A used
// time after now, written by a CPU between the two reads, counts as 0.
func elapsed(now, used uint64) time.Duration {
	if used >= now {
		return 0
	}
	return time.Duration(now - used)
}
