// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
//go:build ignore

/*
 * relay_forward forwards the WireGuard transport datagrams of the relay's
 * placed sessions at tc ingress, so they no longer pass through the plexd
 * process.
 *
 * The process owns every decision. It writes one entry into relay_sessions
 * for each session index it has forwarded a transport datagram for itself,
 * and removes the entry whenever its own table drops or changes the index.
 * The program learns nothing: a datagram that does not match an entry
 * exactly passes to the relay's socket unchanged, so a roamed peer, an
 * unknown index, a handshake, a fragment and an oversize datagram reach the
 * code that handles them in the process. The fallback is per datagram.
 *
 * `make bpf` compiles this file with a pinned toolchain into relay_bpfel.o,
 * which is committed and embedded by relaybpf_linux.go. A change here is a
 * change to that object too. The go:build line above keeps the go tool from
 * taking this file for a cgo source of package relaybpf, which would fail
 * every build with cgo enabled; clang reads it as a comment.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/*
 * The address families of struct relay_session and struct bpf_fib_lookup.
 * The uapi headers a BPF program can include do not define them.
 */
#define AF_INET 2
#define AF_INET6 10

/* WG_TRANSPORT is the type byte of a WireGuard transport data message. */
#define WG_TRANSPORT 4

/*
 * WG_TRANSPORT_MIN is the smallest UDP length of a transport message: the
 * 8-byte UDP header, the 16-byte message header (type, reserved, receiver
 * index, counter) and the 16-byte authentication tag of an empty payload,
 * which is a keepalive.
 */
#define WG_TRANSPORT_MIN (sizeof(struct udphdr) + 32)

/* RELAY_TTL is the TTL and hop limit of a forwarded datagram. */
#define RELAY_TTL 64

/*
 * The offsets of the IPv4 and IPv6 headers, of the UDP header behind each and
 * of the WireGuard message behind that. The program takes only an IPv4
 * header without options, so every offset is fixed.
 */
#define IP_OFF ETH_HLEN
#define IPV4_UDP_OFF (IP_OFF + sizeof(struct iphdr))
#define IPV6_UDP_OFF (IP_OFF + sizeof(struct ipv6hdr))
#define IPV4_MSG_OFF (IPV4_UDP_OFF + sizeof(struct udphdr))
#define IPV6_MSG_OFF (IPV6_UDP_OFF + sizeof(struct udphdr))

/*
 * MSG_HEAD is how much of the WireGuard message the program reads: the type
 * byte, three reserved bytes and the four bytes of the receiver index.
 */
#define MSG_HEAD 8

/*
 * struct relay_session is one entry of relay_sessions: transport datagrams
 * from the partner that name the entry's index go to the owner. The loader
 * encodes it byte for byte, so its layout is part of the contract with
 * relaybpf_linux.go.
 */
struct relay_session {
	__u8 psrc[16];   /* partner address: the datagram's source */
	__u8 pdst[16];   /* local address the partner sends to */
	__u8 dst[16];    /* owner address: the new destination */
	__u8 local[16];  /* local address towards the owner: the new source */
	__be16 psport;   /* partner port */
	__be16 dport;    /* owner port */
	__u32 oif;       /* interface the route to the owner leaves by */
	__u64 used_ns;   /* bpf_ktime_get_ns() of the last forwarded datagram */
	__u8 family;     /* AF_INET or AF_INET6 */
	__u8 pad[7];
};                   /* 88 bytes; an IPv4 address fills the first 4 bytes */

_Static_assert(sizeof(struct relay_session) == 88,
	       "struct relay_session must stay 88 bytes, as the loader encodes it");

/*
 * relay_sessions is keyed by the four receiver index bytes as they stand in
 * the datagram. Its size equals the relay's relayMaxIndices, so the process
 * never holds an index the kernel has no room for.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct relay_session);
} relay_sessions SEC(".maps");

/*
 * The counters, in slot order. CounterNames in doc.go names them in the
 * same order, and the process logs them after every sweep. All but the
 * first count a datagram that passed to the socket, by the check that
 * refused it.
 */
enum relay_counter {
	COUNTER_FORWARDED,
	COUNTER_NO_SESSION,
	COUNTER_MISMATCH,
	COUNTER_FIB_FWD_DISABLED,
	COUNTER_FIB_FRAG_NEEDED,
	COUNTER_FIB_NO_NEIGH,
	COUNTER_FIB_OTHER,
	COUNTER_ROUTE_CHANGED,
	COUNTER_GSO,
	COUNTER_MAX,
};

_Static_assert(COUNTER_MAX == 9, "relay_counters must have the nine slots of CounterNames");

/*
 * relay_counters is per CPU, so a slot is incremented without an atomic
 * operation. The loader sums each slot over the CPUs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, COUNTER_MAX);
	__type(key, __u32);
	__type(value, __u64);
} relay_counters SEC(".maps");

/*
 * The loader sets both constants before the program is loaded, so the
 * verifier sees them as known values.
 *
 * relay_port is the relay's listen port in network byte order: the port the
 * partner sends to, and the source port of a forwarded datagram, as the
 * socket would send it.
 *
 * lookup_ifindex is the mesh interface. The route lookup asks through it,
 * not through the interface the datagram arrived on, because
 * bpf_fib_lookup refuses with BPF_FIB_LKUP_RET_FWD_DISABLED when forwarding
 * is off on the device it is asked about. A bridge has forwarding on for the
 * mesh interface already, so the host needs none on its public interface.
 */
volatile const __be16 relay_port;
volatile const __u32 lookup_ifindex;

/* count increments one counter slot on this CPU. */
static __always_inline void count(__u32 slot)
{
	__u64 *value = bpf_map_lookup_elem(&relay_counters, &slot);

	if (value)
		(*value)++;
}

/*
 * is_transport reports whether the UDP datagram is addressed to the relay
 * and carries a WireGuard transport message. Handshake messages, cookie
 * replies and anything shorter than the smallest transport message stay in
 * the process, which routes them. The reserved bytes must be zero, as
 * WireGuard sends them, so a datagram that only looks like one is not taken.
 */
static __always_inline int is_transport(const struct udphdr *udp, const __u8 *msg)
{
	if (udp->dest != relay_port)
		return 0;
	if (bpf_ntohs(udp->len) < WG_TRANSPORT_MIN)
		return 0;
	return msg[0] == WG_TRANSPORT && msg[1] == 0 && msg[2] == 0 && msg[3] == 0;
}

/*
 * lookup_session returns the entry of the receiver index in msg, or NULL.
 * The key is the four index bytes as they stand in the datagram, which is
 * how the loader writes it.
 */
static __always_inline struct relay_session *lookup_session(const __u8 *msg)
{
	__u32 index;

	__builtin_memcpy(&index, msg + 4, sizeof(index));
	return bpf_map_lookup_elem(&relay_sessions, &index);
}

/*
 * fib_failed counts a route lookup that did not succeed and passes the
 * datagram to the socket, which sends it through the stack. That covers a
 * datagram too large for the route (FRAG_NEEDED), a neighbour the kernel has
 * not resolved yet (NO_NEIGH) and forwarding switched off on the mesh
 * interface (FWD_DISABLED).
 */
static __always_inline int fib_failed(long rc)
{
	switch (rc) {
	case BPF_FIB_LKUP_RET_FWD_DISABLED:
		count(COUNTER_FIB_FWD_DISABLED);
		break;
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:
		count(COUNTER_FIB_FRAG_NEEDED);
		break;
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		count(COUNTER_FIB_NO_NEIGH);
		break;
	default:
		count(COUNTER_FIB_OTHER);
	}
	return TCX_NEXT;
}

/*
 * send_to_owner writes the Ethernet addresses the route lookup returned,
 * marks the session used and redirects the rewritten datagram out of the
 * interface the route leaves by. used_ns is what the process reads back to
 * keep the session alive, since a forwarded datagram never reaches it.
 */
static __always_inline int send_to_owner(struct __sk_buff *skb, struct relay_session *s,
					 const struct bpf_fib_lookup *fib)
{
	bpf_skb_store_bytes(skb, 0, fib->dmac, ETH_ALEN, 0);
	bpf_skb_store_bytes(skb, ETH_ALEN, fib->smac, ETH_ALEN, 0);
	s->used_ns = bpf_ktime_get_ns();
	count(COUNTER_FORWARDED);
	return bpf_redirect(fib->ifindex, 0);
}

/*
 * forward_ipv4 forwards an IPv4 datagram that passes the eight checks to the
 * session's owner, rewritten as the relay's socket would send it, and
 * returns TCX_NEXT for any other.
 */
static __always_inline int forward_ipv4(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *ip = data + IP_OFF;
	struct udphdr *udp = data + IPV4_UDP_OFF;
	__u8 *msg = data + IPV4_MSG_OFF;

	/*
	 * Check 1: the headers and the first 8 message bytes lie in the linear
	 * data, so the program reads them without copying. A datagram whose
	 * headers are not linear passes to the socket.
	 */
	if ((void *)(msg + MSG_HEAD) > data_end)
		return TCX_NEXT;

	/*
	 * Check 2: an IPv4 header without options carrying UDP, and not a
	 * fragment. The offsets above assume no options, and only the first
	 * fragment of a datagram carries the UDP header, so the stack
	 * reassembles fragments for the socket.
	 */
	if (ip->ihl != 5 || ip->protocol != IPPROTO_UDP)
		return TCX_NEXT;
	if (ip->frag_off & bpf_htons(0x3fff))
		return TCX_NEXT;

	/* Check 3: a transport message to the relay's port. */
	if (!is_transport(udp, msg))
		return TCX_NEXT;

	/*
	 * Check 4: the process placed this session index. An index the
	 * kernel does not hold is one the process has not forwarded yet, or
	 * one it dropped.
	 */
	struct relay_session *s = lookup_session(msg);
	if (!s) {
		count(COUNTER_NO_SESSION);
		return TCX_NEXT;
	}

	/*
	 * Check 5: the datagram comes from the partner's address and port and
	 * was sent to the local address the entry names. A partner that
	 * roamed fails here, and the process learns its new address from this
	 * very datagram and installs the session again.
	 */
	__be32 psrc, pdst, dst, local;

	__builtin_memcpy(&psrc, s->psrc, sizeof(psrc));
	__builtin_memcpy(&pdst, s->pdst, sizeof(pdst));
	__builtin_memcpy(&dst, s->dst, sizeof(dst));
	__builtin_memcpy(&local, s->local, sizeof(local));
	if (s->family != AF_INET || ip->saddr != psrc || udp->source != s->psport ||
	    ip->daddr != pdst) {
		count(COUNTER_MISMATCH);
		return TCX_NEXT;
	}

	/*
	 * Check 6: a single datagram. A GRO super-packet holds several
	 * datagrams behind one header and is segmented only by the stack.
	 */
	if (skb->gso_segs > 1) {
		count(COUNTER_GSO);
		return TCX_NEXT;
	}

	/*
	 * Check 7: the kernel routes the rewritten datagram as the socket
	 * would send it, from the source the process resolved, and knows the
	 * next hop's Ethernet address. The MTU check against tot_len sends a
	 * datagram too large for the route to the socket, whose stack
	 * fragments it.
	 */
	struct bpf_fib_lookup fib = {};

	fib.family = AF_INET;
	fib.tos = ip->tos;
	fib.l4_protocol = IPPROTO_UDP;
	fib.sport = relay_port;
	fib.dport = s->dport;
	fib.tot_len = bpf_ntohs(ip->tot_len);
	fib.ipv4_src = local;
	fib.ipv4_dst = dst;
	fib.ifindex = lookup_ifindex;

	long rc = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS)
		return fib_failed(rc);

	/*
	 * Check 8: the route still leaves by the interface the process
	 * resolved. The source address the process chose belongs to that
	 * route, so a route that moved passes to the socket until the process
	 * resolves it again.
	 */
	if (fib.ifindex != s->oif) {
		count(COUNTER_ROUTE_CHANGED);
		return TCX_NEXT;
	}

	/*
	 * Every helper below may move the packet data, which invalidates the
	 * header pointers, so all old values are read first.
	 */
	__be32 old_saddr = ip->saddr;
	__be32 old_daddr = ip->daddr;
	__be16 old_sport = udp->source;
	__be16 old_dport = udp->dest;
	__be16 new_sport = relay_port;
	__be16 new_dport = s->dport;
	__be16 old_ttl = bpf_htons(((__u16)ip->ttl << 8) | IPPROTO_UDP);
	__be16 new_ttl = bpf_htons(((__u16)RELAY_TTL << 8) | IPPROTO_UDP);
	__u8 ttl = RELAY_TTL;
	const __u32 udp_csum = IPV4_UDP_OFF + offsetof(struct udphdr, check);
	const __u32 ip_csum = IP_OFF + offsetof(struct iphdr, check);

	/*
	 * The UDP checksum covers the pseudo header with both addresses, and
	 * the two ports. BPF_F_MARK_MANGLED_0 leaves a checksum of 0, which
	 * means none over IPv4, as it is, and writes 0xffff for a result of 0.
	 */
	bpf_l4_csum_replace(skb, udp_csum, old_saddr, local,
			    BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4);
	bpf_l4_csum_replace(skb, udp_csum, old_daddr, dst,
			    BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4);
	bpf_l4_csum_replace(skb, udp_csum, old_sport, new_sport, BPF_F_MARK_MANGLED_0 | 2);
	bpf_l4_csum_replace(skb, udp_csum, old_dport, new_dport, BPF_F_MARK_MANGLED_0 | 2);

	/*
	 * The header checksum covers both addresses and the 16-bit word of
	 * TTL and protocol. TOS, DF and the ID stay as the sender set them.
	 */
	bpf_l3_csum_replace(skb, ip_csum, old_saddr, local, 4);
	bpf_l3_csum_replace(skb, ip_csum, old_daddr, dst, 4);
	bpf_l3_csum_replace(skb, ip_csum, old_ttl, new_ttl, 2);

	bpf_skb_store_bytes(skb, IP_OFF + offsetof(struct iphdr, saddr), &local, sizeof(local), 0);
	bpf_skb_store_bytes(skb, IP_OFF + offsetof(struct iphdr, daddr), &dst, sizeof(dst), 0);
	bpf_skb_store_bytes(skb, IP_OFF + offsetof(struct iphdr, ttl), &ttl, sizeof(ttl), 0);
	bpf_skb_store_bytes(skb, IPV4_UDP_OFF + offsetof(struct udphdr, source), &new_sport,
			    sizeof(new_sport), 0);
	bpf_skb_store_bytes(skb, IPV4_UDP_OFF + offsetof(struct udphdr, dest), &new_dport,
			    sizeof(new_dport), 0);

	return send_to_owner(skb, s, &fib);
}

/*
 * forward_ipv6 forwards an IPv6 datagram that passes the eight checks to the
 * session's owner, rewritten as the relay's socket would send it, and
 * returns TCX_NEXT for any other.
 */
static __always_inline int forward_ipv6(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ipv6hdr *ip6 = data + IP_OFF;
	struct udphdr *udp = data + IPV6_UDP_OFF;
	__u8 *msg = data + IPV6_MSG_OFF;

	/* Check 1: as for IPv4. */
	if ((void *)(msg + MSG_HEAD) > data_end)
		return TCX_NEXT;

	/*
	 * Check 2: UDP directly behind the fixed header. A datagram behind an
	 * extension header, a fragment header included, passes to the socket.
	 */
	if (ip6->nexthdr != IPPROTO_UDP)
		return TCX_NEXT;

	/* Check 3: a transport message to the relay's port. */
	if (!is_transport(udp, msg))
		return TCX_NEXT;

	/* Check 4: the process placed this session index. */
	struct relay_session *s = lookup_session(msg);
	if (!s) {
		count(COUNTER_NO_SESSION);
		return TCX_NEXT;
	}

	/* Check 5: the partner's address and port and the local address. */
	if (s->family != AF_INET6 || __builtin_memcmp(&ip6->saddr, s->psrc, 16) ||
	    udp->source != s->psport || __builtin_memcmp(&ip6->daddr, s->pdst, 16)) {
		count(COUNTER_MISMATCH);
		return TCX_NEXT;
	}

	/* Check 6: a single datagram. */
	if (skb->gso_segs > 1) {
		count(COUNTER_GSO);
		return TCX_NEXT;
	}

	/*
	 * Check 7: the route lookup. tot_len is the length of the whole IPv6
	 * datagram, the fixed header included, for the MTU check.
	 */
	struct bpf_fib_lookup fib = {};

	fib.family = AF_INET6;
	fib.l4_protocol = IPPROTO_UDP;
	fib.sport = relay_port;
	fib.dport = s->dport;
	fib.tot_len = bpf_ntohs(ip6->payload_len) + sizeof(struct ipv6hdr);
	__builtin_memcpy(fib.ipv6_src, s->local, 16);
	__builtin_memcpy(fib.ipv6_dst, s->dst, 16);
	fib.ifindex = lookup_ifindex;

	long rc = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS)
		return fib_failed(rc);

	/* Check 8: the route still leaves by the resolved interface. */
	if (fib.ifindex != s->oif) {
		count(COUNTER_ROUTE_CHANGED);
		return TCX_NEXT;
	}

	/*
	 * old and new hold both addresses of the pseudo header, in the order
	 * of the packet, so the new addresses are stored from new. As for
	 * IPv4, every helper below may move the packet data, so the old ports
	 * are read first.
	 */
	__u8 old[32], new[32];
	__be16 old_sport = udp->source;
	__be16 old_dport = udp->dest;
	__be16 new_sport = relay_port;
	__be16 new_dport = s->dport;
	__u8 hop_limit = RELAY_TTL;
	const __u32 udp_csum = IPV6_UDP_OFF + offsetof(struct udphdr, check);

	__builtin_memcpy(old, &ip6->saddr, 16);
	__builtin_memcpy(old + 16, &ip6->daddr, 16);
	__builtin_memcpy(new, s->local, 16);
	__builtin_memcpy(new + 16, s->dst, 16);

	/*
	 * IPv6 has no header checksum, and the UDP checksum is mandatory. One
	 * difference over the 32 address bytes updates it with
	 * BPF_F_PSEUDO_HDR, then each port is replaced on its own without that
	 * flag, as for IPv4. This departs from the issue's single difference
	 * over 36 bytes. A partner in a container or VM on this host sends
	 * kernel WireGuard's datagrams through a veth or virtio-net device
	 * with the checksum still partial (CHECKSUM_PARTIAL): the field holds
	 * only the pseudo header sum, and the stack sums the UDP header when
	 * it completes the checksum on egress. A port difference applied with
	 * BPF_F_PSEUDO_HDR lands in that partial sum too, so the new ports
	 * would count twice and the owner would drop the datagram. Without
	 * the flag the kernel leaves a partial checksum alone and updates a
	 * complete one.
	 */
	__s64 diff = bpf_csum_diff((__be32 *)old, sizeof(old), (__be32 *)new, sizeof(new), 0);

	bpf_l4_csum_replace(skb, udp_csum, 0, diff, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0);
	bpf_l4_csum_replace(skb, udp_csum, old_sport, new_sport, BPF_F_MARK_MANGLED_0 | 2);
	bpf_l4_csum_replace(skb, udp_csum, old_dport, new_dport, BPF_F_MARK_MANGLED_0 | 2);
	bpf_skb_store_bytes(skb, IP_OFF + offsetof(struct ipv6hdr, saddr), new, 32, 0);
	bpf_skb_store_bytes(skb, IP_OFF + offsetof(struct ipv6hdr, hop_limit), &hop_limit,
			    sizeof(hop_limit), 0);
	bpf_skb_store_bytes(skb, IPV6_UDP_OFF + offsetof(struct udphdr, source), &new_sport,
			    sizeof(new_sport), 0);
	bpf_skb_store_bytes(skb, IPV6_UDP_OFF + offsetof(struct udphdr, dest), &new_dport,
			    sizeof(new_dport), 0);

	return send_to_owner(skb, s, &fib);
}

/*
 * relay_forward runs at tcx ingress on the interfaces the partners' datagrams
 * arrive on. Every packet it does not forward returns TCX_NEXT, so it goes on
 * to the next program and the stack untouched.
 *
 * A datagram for a VLAN interface arrives first at ingress of the VLAN's
 * parent device, and meets the program there too when another partner's
 * datagrams arrive on the parent untagged. The stack has already moved the
 * tag into the skb's metadata by then, and the protocol is the inner one, so
 * the datagram looks like any other and may match an entry. Redirected there,
 * it would leave with its tag still set and be lost.
 */
SEC("tc")
int relay_forward(struct __sk_buff *skb)
{
	/*
	 * Check 1 starts here: only an untagged IPv4 or IPv6 packet is taken.
	 * A tagged one passes untouched, and the stack hands it on untagged to
	 * ingress of the VLAN interface, where the program sees it again and
	 * forwards it when it is attached there.
	 */
	if (skb->vlan_present)
		return TCX_NEXT;
	if (skb->protocol == bpf_htons(ETH_P_IP))
		return forward_ipv4(skb);
	if (skb->protocol == bpf_htons(ETH_P_IPV6))
		return forward_ipv6(skb);
	return TCX_NEXT;
}

/*
 * bpf_fib_lookup is restricted to GPL-compatible programs, so the object
 * declares a dual licence.
 */
char _license[] SEC("license") = "Dual BSD/GPL";
