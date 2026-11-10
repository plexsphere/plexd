---
title: Mesh DNS
package: internal/meshdns
---

# Mesh DNS

The `internal/meshdns` package answers the mesh names of the Node's Domain, and the DNS records the Domain and its Projects define, from a resolver on the Node itself. The names and the records come from the `dns` block of the state pull (see [State](../core/api-endpoints.md#get-v1-nodes-node-id-state)), which the "Mesh DNS names" section of plexsphere's agent contract (`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere) describes. On Linux, plexd registers the resolver with systemd-resolved for the mesh zones only, on the mesh interface. The host then asks plexd for the mesh zones and resolves every other name as before.

plexd is not recursive. It answers `A`, `AAAA` and `PTR` queries for the Nodes' names and mesh IPs, and queries for the records of the six types `A`, `AAAA`, `CNAME`, `TXT`, `SRV` and `MX`. It denies every other name in the mesh zones and refuses every name outside them. It follows a CNAME while its target lies in the mesh zones, and answers one whose target lies outside them with the CNAME alone, for the system resolver to follow. It writes no file and changes no resolver setting of the host outside the mesh interface's link.

Only Linux runs the resolver, in node mode and in bridge mode. On macOS and Windows `plexd up` starts no resolver and logs nothing about it. The `dns` keys are still parsed and validated there.

## Data Flow

```
Control Plane
      │
      │ GET /v1/nodes/{id}/state  →  dns block
      ▼
┌──────────────┐    ┌────────────────────┐
│  Reconciler  │───▶│   meshdns.Manager  │
│              │    │       Handle       │
└──────────────┘    └──┬──────────────┬──┘
                       │ SetRecords   │ Apply / Revert
                       ▼              ▼
               ┌────────────────┐  ┌───────────────────┐
               │     Server     │  │ ResolvedRegistrar │─ D-Bus ─▶ systemd-resolved
               │ mesh IP : 5354 │  └───────────────────┘
               └────────────────┘
                       ▲
                       │ queries for the mesh zones, through the mesh interface
                       │
               systemd-resolved
```

A pull with a `dns` block replaces the names the server answers. It replaces the registration only when the one the block implies differs from the one applied, so a pull that changes only hosts or records issues no call to systemd-resolved. A pull without a block changes nothing. plexd keeps the names in memory only. A restart starts without names, as it starts without peers, and both come back with the first pull.

## Config

`Config` holds the resolver's settings under the key `dns` of the agent configuration (see [Configuration Reference](../core/configuration.md#dns)).

| Field        | Type    | Default         | Description |
|--------------|---------|-----------------|-------------|
| `Enabled`    | `*bool` | `nil` (enabled) | Run the resolver and its registration (`enabled`) |
| `ListenPort` | `int`   | `5354`          | UDP and TCP port the resolver listens on, on the Node's own mesh IP (`listen_port`) |

`Enabled` is a pointer so that an omitted key stays apart from an explicit `false`. `IsEnabled()` returns true unless the field is set to `false`, and `ApplyDefaults` leaves the field alone. An existing deployment that sets nothing therefore runs the resolver, and a `false` survives defaulting. `ApplyDefaults` sets a zero `ListenPort` to `DefaultListenPort` (5354). [`PLEXD_DNS_ENABLED`](../core/environment-variables.md#plexd-up-variables) overrides `enabled`.

```yaml
dns:
  enabled: true
  listen_port: 5354
```

### Validation Rules

| Field        | Rule | Error Message |
|--------------|------|---------------|
| `ListenPort` | Must be 1 to 65535 while the resolver is enabled | `meshdns: config: ListenPort must be between 1 and 65535` |
| `Enabled`    | Not validated; any value is accepted | none |

A disabled resolver binds nothing, so its port is not checked. The check runs on every platform, so a port out of range fails the start on macOS and Windows too.

## Listen Address

The resolver listens on the Node's own mesh IP, the address registration assigned, on `dns.listen_port`, over UDP and TCP. systemd-resolved moves a server to TCP after repeated UDP losses, for example across a plexd restart, so a resolver that answered on UDP only would fail it then. `Start` binds both sockets and fails when either bind fails, closing the socket that did bind. It refuses an unspecified address, `0.0.0.0`, `::` or `::ffff:0.0.0.0`, which would bind every interface of the host, with `meshdns: listen <address>: no address to listen on`. A resolver binds once: every `Start` after one that succeeded fails with `meshdns: listen <address>: already listening`.

The address is the mesh IP and not loopback, because systemd-resolved sends a query for a per-link DNS server out through that link. A listener on `127.0.0.1` is never reached through the mesh interface. The Node's own mesh IP is a local address, so the kernel delivers the query locally, and every query systemd-resolved sends arrives with the mesh IP as its source address.

The port is unprivileged, so `plexd.service` needs no `CAP_NET_BIND_SERVICE` for the resolver.

### Source Rule

The resolver answers the Node itself only. It accepts a query when the source address, with an IPv4-mapped address unmapped, is the listen address itself or a loopback address. It drops every other UDP packet without a reply, and closes every other TCP connection at accept, before reading anything.

This check is what keeps other hosts from using the resolver. plexd's [nftables policy](./nftables-firewall.md) sits on the forward hook only, so it does not filter traffic to the Node itself, and a mesh peer reaches the mesh IP. A mesh peer cannot send from the Node's own address, because WireGuard drops a packet whose source lies outside the sending peer's allowed IPs.

A program on the Node that queries the mesh IP directly, such as `dig @10.99.0.1 -p 5354 peer-1.app.e2e.internal`, sends from the mesh IP and gets an answer. A program in a Pod or container network sends from an address of its own and gets none.

### TCP

TCP frames each message with a two-byte length (RFC 7766). A connection may carry several queries in a row. Each complete query must arrive within 10 seconds, counted from the accept or from the answer before it, or the connection is closed. At most 32 connections are open at a time, and a further one is closed at accept. A message on a connection that gets no reply (see [Malformed and Refused Queries](#malformed-and-refused-queries)) is skipped, and the connection stays open. A skipped message does not restart the 10 seconds: only a reply does.

An accept that fails on a listener that is still open, for example with `EMFILE` while the process is out of file descriptors, is retried. It logs `mesh dns could not accept a connection` at Debug and waits before the next accept: 5 milliseconds at first, doubled after each further failure up to 1 second, and back to 5 milliseconds after an accept that succeeds. The wait ends at once when plexd stops. Such a failure stops neither TCP nor UDP serving.

## What the Resolver Answers

### Records

`BuildRecords(block api.NodeStateDNS) (*Records, []string)` turns a `dns` block into the immutable `Records` the server answers from, and returns one sentence for each entry it skipped. The control plane is trusted, but a bug there must not hand the Node a zone that swallows the host's own resolution, so every entry is checked where it enters.

Every name is folded to ASCII lower case first. A name is valid when it has 1 to 253 characters, no trailing dot, and labels of 1 to 63 characters from `a-z`, `0-9` and `-` that neither start nor end with `-`. The `fqdn` and the `target` of a record may also carry `_` at any position of a label, as `_postgres._tcp.openstack.lab.internal` does. The root zone is never valid, because the empty name is not.

| Entry | Skipped when |
|-------|--------------|
| `zones` | The name is invalid, or it is `arpa`, `local` or `localhost`, or lies under one of them. A zone listed twice is kept once, without a sentence |
| `reverse_zones` | The name is invalid, or it does not end in `.in-addr.arpa` or `.ip6.arpa`. A reverse zone listed twice is kept once, without a sentence |
| `hosts` | The `fqdn` is invalid, lies under no accepted zone, or is an accepted zone itself, because a host lies at least one label below its zone; the `mesh_ip` does not parse as an IP address, an empty one included; or an earlier entry holds the same `fqdn`, so the first one is kept. The checks run in this order, and the sentence names the first one that failed |
| `records` | One of the record checks below fails. The checks run in their order, and the sentence, `record "<fqdn>" of type "<type>" <reason>`, names the first one that failed, with `fqdn` and `type` as the block spelled them |
| `search_domain` | It is not an accepted zone. The Node then has no search domain |

An accepted host's mesh IP is unmapped when it is an IPv4-mapped IPv6 address, and an IPv6 zone is dropped. The reverse name of the address, `<octets reversed>.in-addr.arpa` for IPv4 and `<32 nibbles reversed>.ip6.arpa` for IPv6, maps to the host's FQDN when it lies under an accepted reverse zone. When two hosts share an address, the first one holds the reverse name. Node IDs are carried but never answered.

The records are checked after the hosts. The checks run in this order:

| Check | The record is skipped when | Reason |
|-------|----------------------------|--------|
| Type | `type` is not exactly `A`, `AAAA`, `CNAME`, `TXT`, `SRV` or `MX`, in upper case | `has a type plexd does not answer` |
| Name | `fqdn` is not a valid name | `is not a valid name because it <reason>` |
| Zone | The name is no accepted zone and lies under none. A reverse zone does not count | `lies under no accepted zone` |
| Host | An accepted host holds the name | `is the name of node "<node id>", which is answered from hosts only` |
| Data | The data breaks the rule of its type in the table below | The rule's reason |
| CNAME | The name already holds an accepted CNAME, or the record is a CNAME and the name already holds an accepted record | `shares its name with a CNAME, which is the only record at its name` |
| Repeat | An accepted record of the same name and type has equal data, `text` compared in order | `repeats an earlier record` |

The reason of an invalid name is one of `is empty`, `has more than 253 characters`, `ends in a dot`, `has an empty label`, `has a label of more than 63 characters`, `has a label that starts or ends with -` and `has a character outside a-z, 0-9, - and _`. The data rules:

| Type | Rule | Reason |
|------|------|--------|
| `A` | `address` parses as an IP address without a zone, and it is an IPv4 address | `has address "<address>", which is not an IPv4 address` |
| `AAAA` | `address` parses as an IP address without a zone, and it is an IPv6 address that is not IPv4-mapped | `has address "<address>", which is not an IPv6 address` |
| `CNAME` | `target` is a valid name | `has target "<target>", which is not a valid name because it <reason>` |
| `TXT` | `text` holds at least one string, and none is longer than 255 bytes | `has no text`, or `has a text string of more than 255 bytes` |
| `SRV` | `priority`, `weight` and `port` are present and 0 to 65535, checked in this order, and `target` is a valid name | `has no <member>`, `has a <member> outside 0 to 65535`, or the target reason of a `CNAME` |
| `MX` | `priority` is present and 0 to 65535, and `target` is a valid name | The same reasons as an `SRV` |

A member the record's type does not take is ignored, so an `A` record that also carries a `target` is accepted, and a member a later contract adds costs no record. An empty `TXT` string is valid on the wire and accepted. An IPv4-mapped address is refused by both `A` and `AAAA`, while a host's mesh IP is unmapped. A target may lie inside or outside the mesh zones. plexd checks only what a DNS message needs, not the limits the control plane sets, such as 8 strings and 1,024 bytes per `TXT` or a port of at least 1, so a port of 0 is accepted and a change of those limits needs no new plexd.

The first record at a name decides the CNAME check, so of a CNAME and another record at one name, the one the block lists first stays. The block is ordered by `fqdn`, then `type`, so an `A` or `AAAA` record keeps its name against a CNAME that follows it. The records of one name and type are answered in the block's order, on every query.

An accepted record's name exists, and so does every name between it and its zone, so `_tcp.openstack.lab.internal` answers NODATA when `_postgres._tcp.openstack.lab.internal` holds a record. A record adds no reverse name: the reverse name of a record's `address` answers `NXDOMAIN` when it lies in an accepted reverse zone and no host holds it. A block without a `records` member, or with `null`, has no records. Because the block is the full set, that is no signal to keep the records held.

### Answer Table

Every lookup is case-insensitive. The zone of a name is the accepted zone or reverse zone that is the name itself or its nearest ancestor, label by label. With the zones `lab.internal` and `openstack.lab.internal`, the zone of `x.openstack.lab.internal` is `openstack.lab.internal`.

A name exists when it is a host's FQDN, a reverse name that maps to a host, a record's name, a zone or reverse zone, or a name between a zone and an existing name below it. `0.42.10.in-addr.arpa` exists between the reverse zone `42.10.in-addr.arpa` and the reverse name `3.0.42.10.in-addr.arpa`.

Any query before the first `dns` block, and any name outside every accepted zone and reverse zone, gets `REFUSED`. Any other name is looked up by these steps, in this order, and the first step that applies gives the answer:

1. A host of the queried family: the host's `A` record for an `A` query and an IPv4 mesh IP, or its `AAAA` record for an `AAAA` query and an IPv6 one.
2. A `PTR` query for a reverse name that maps to a host: the `PTR` record naming the host's FQDN.
3. A name that holds a CNAME: the CNAME, whatever the query type. A `CNAME` or `ANY` query gets the CNAME alone. Any other query follows the CNAME to its target and starts again at step 1 there, unless the CNAME ends the answer (see below).
4. The records of the queried type at the name, in the block's order.
5. An `SOA` query at an accepted zone or reverse zone itself: the synthesized `SOA`.
6. A name that exists: NODATA.
7. Any other name: `NXDOMAIN`.

The CNAME step comes before the `SOA` step, so a CNAME at a zone itself answers an `SOA` query too. An `ANY` query gets no treatment of its own: it gets the CNAME at a name that holds one, and NODATA at any other name that exists.

| Query | Response code | Records |
|-------|---------------|---------|
| Any query before the first `dns` block | `REFUSED` | none |
| A name outside every accepted zone and reverse zone | `REFUSED` | none |
| A host's FQDN, type `A`, IPv4 mesh IP | `NOERROR` | One `A` record |
| A host's FQDN, type `AAAA`, IPv6 mesh IP | `NOERROR` | One `AAAA` record |
| The reverse name of a host's mesh IP, type `PTR` | `NOERROR` | One `PTR` record naming the FQDN |
| A name that holds a CNAME, type `CNAME` or `ANY` | `NOERROR` | The CNAME |
| A name that holds a CNAME, any other type | The target's response code while the target lies in the zones, `NOERROR` otherwise | The CNAME, then the answer at its target; see the paragraph below the table |
| A record's name, asked for a type it holds records of | `NOERROR` | Every record of that type at the name, in the block's order |
| A zone or reverse zone itself that holds no CNAME, type `SOA` | `NOERROR` | The synthesized `SOA` as the answer |
| A name that exists, asked for a type it has no record of: a host or a reverse name asked for another type, a record's name asked for a type it holds none of, a zone or reverse zone asked for anything but `SOA` and the types of its records, or a name between a zone and a name below it (NODATA) | `NOERROR` | No answer; the `SOA` of the zone in the authority section |
| Any other name in an accepted zone or reverse zone | `NXDOMAIN` | No answer; the `SOA` of the zone in the authority section |

A CNAME is followed while its target lies under an accepted zone or reverse zone. The answer section then holds the CNAME first and the target's answer after it, and the response code is that of the last name (RFC 6604). A target name that does not exist gets `NXDOMAIN` with the CNAME in the answer section and the `SOA` of the target's zone in the authority section. A target that exists without a record of the queried type gets NODATA with the CNAME. A target outside every accepted zone and reverse zone ends the answer: the response is `NOERROR` with the CNAME alone, and the system resolver follows the target through its own servers, as systemd-resolved does. One answer holds at most 8 CNAME records, and a chain that comes back to a name it passed stops at the CNAME that points back. Both end the answer like a target outside the zones, so the client follows on from the last CNAME, and a loop fails at the client's own limit.

Every record carries a TTL of 10 seconds. systemd-resolved caches an answer for its TTL, so it serves a changed name or record for at most 10 seconds after the pull that changed it, and plexd never flushes its cache. A record in the answer section whose owner is the question's name is owned by that name as the query spelled it. Any other record, such as the target's records after a CNAME, is owned by its folded name. The `SOA` is owned by the zone as the query spelled it: the question name's last labels, as many as the zone has. A query for `NOPE.OpenStack.Lab.Internal` gets an `SOA` owned by `OpenStack.Lab.Internal`. When the question's name does not end in the zone, as after a CNAME into another zone, the `SOA` is owned by the folded zone. An owner spelled like the question compresses to a pointer into it. An answer too large for its transport is handled as [Response Header](#response-header) describes.

The synthesized `SOA`:

| Field | Value |
|-------|-------|
| Owner | The zone, spelled as in the question, or folded when the question's name does not end in it |
| TTL | `10` |
| MNAME | `ns.plexd.invalid.` |
| RNAME | `hostmaster.plexd.invalid.` |
| Serial | `1` |
| Refresh | `3600` |
| Retry | `600` |
| Expire | `86400` |
| Minimum | `10` |

Nothing transfers these zones, so only the minimum matters. RFC 2308 makes a resolver cache a negative answer for the lower of the minimum and the `SOA`'s TTL, so a name that a pull adds stays denied for at most 10 seconds.

### Response Header

The response echoes the query's ID, its opcode, its RD bit and its question exactly as received, upper case included. It sets QR and clears RA. AA is set on every `NOERROR` and `NXDOMAIN` answer from the records, and clear on `REFUSED`, `FORMERR`, `NOTIMP` and `SERVFAIL`.

A response over UDP carries at most 512 bytes when the query has no OPT record. With one, it carries at most the UDP payload size the client offers, but never less than 512 and never more than 1232 bytes. A response over that limit is sent with TC set and otherwise the same header, the question, no record in the answer and authority sections, and an OPT record when the query had one. The client then asks again over TCP. systemd-resolved offers 1472 bytes, so it gets up to 1232, and it repeats a truncated query over TCP. busybox `nslookup` sends no OPT record and ignores TC, so for an answer of more than 512 bytes it prints nothing and exits 0.

A response over TCP carries up to 65,535 bytes, the most the two-byte length of a TCP message can count. A response over that limit, which takes more than 64 KiB of records at one name and type, is sent as `SERVFAIL` with AA clear, the question, no record, and an OPT record when the query had one. The server then logs `mesh dns answer does not fit a message` at Debug. The limit counts the message alone, not the two-byte length in front of it.

When the query carries an OPT record, the response carries one with a UDP payload size of 1232 bytes, EDNS version 0, the DO bit clear and no options. plexd does not negotiate the EDNS version: a query with a higher version gets the same answer. A query with more than one OPT record gets `FORMERR` (RFC 6891), with one OPT record. A `FORMERR` response has no question section. It carries an OPT record when the query had one and the query's questions parse. A query with a question that does not parse gets a `FORMERR` without one, because plexd cannot find where its additional section begins.

### Malformed and Refused Queries

| Message | Response |
|---------|----------|
| Shorter than the 12-byte header | No reply |
| QR set, so a response itself | No reply |
| An opcode other than `QUERY` | `NOTIMP` |
| A question count other than 1, or a question that does not parse | `FORMERR`, with no question section |
| More than one OPT record | `FORMERR`, with no question section |
| A class other than `IN` | `REFUSED` |
| A source that is neither the listen address nor a loopback address | No reply over UDP; the TCP connection is closed at accept |

The opcode is checked before the questions and the OPT records, so a query with another opcode gets `NOTIMP` however many OPT records it carries.

## Registration with systemd-resolved

`Registrar` is the seam to the operating system's resolver. Tests replace it with a recording fake, so no test changes the resolver settings of the host it runs on.

```go
type Registration struct {
    Interface      string
    Server         netip.AddrPort
    SearchDomain   string
    RoutingDomains []string
}

type Registrar interface {
    Apply(ctx context.Context, reg Registration) error
    Revert(ctx context.Context, iface string) error
}

var ErrUnavailable = errors.New("meshdns: no usable system resolver")
```

`(*Records).Registration(iface, server)` builds what the Node registers. `Interface` is the mesh interface and `Server` the listen address. `SearchDomain` is the accepted search domain, or empty. `RoutingDomains` holds every accepted zone that has no other accepted zone above it, without the search domain, followed by every accepted reverse zone, each group in ascending byte order. Routing a domain routes every name under it, so a Project zone below the Domain's default domain adds no entry, and the search domain routes the names under it as well. Reverse zones are never merged: a wider zone would make plexd answer `NXDOMAIN` for addresses outside the mesh. A registration is empty when it names no search domain and no routing domain.

The contract's example is a Node of the Project `openstack` in the Domain `lab`, whose mesh CIDR is `10.42.0.0/16`. Its block carries the search domain `openstack.lab.internal`, the zones `edge.example.com`, `lab.internal` and `openstack.lab.internal`, and the reverse zone `42.10.in-addr.arpa`. The Node registers the search domain `openstack.lab.internal` and the routing domains `edge.example.com`, `lab.internal` and `42.10.in-addr.arpa`. `resolvectl domain` shows each routing domain with a leading `~`.

### ResolvedRegistrar

`NewResolvedRegistrar(logger *slog.Logger) *ResolvedRegistrar` (`resolved_linux.go`) is the `Registrar` on Linux. It talks to systemd-resolved over D-Bus, on the object `/org/freedesktop/resolve1` of `org.freedesktop.resolve1`. Each `Apply` and each `Revert` opens its own connection to the system bus and closes it, so no connection outlives the call, and a systemd-resolved or bus daemon that starts, stops or restarts between two pulls is found on the next call.

Every call the registrar makes carries the D-Bus flag `NO_AUTO_START`, so the bus daemon never starts a stopped systemd-resolved for plexd. An operator who stopped it keeps it stopped: the bus daemon answers `org.freedesktop.DBus.Error.NameHasNoOwner`, which counts as not running.

`Apply` looks the interface up in the host's interface list before it opens a connection. It then reads the `DNSEx` property of `org.freedesktop.resolve1.Manager` with `org.freedesktop.DBus.Properties.Get`, which changes nothing. systemd-resolved 246 added the property together with `SetLinkDNSEx`, so a failed read tells an older one apart before anything on the link changes. No other call follows a failed read, not even a `RevertLink`. After the read, `Apply` calls these methods of `org.freedesktop.resolve1.Manager`, in this order:

| Step | Method (signature) | Arguments |
|------|--------------------|-----------|
| 1 | `SetLinkDefaultRoute` (`ib`) | The interface index, `false` |
| 2 | `SetLinkDomains` (`ia(sb)`) | The index; the search domain with `false` when there is one, then each routing domain with `true` |
| 3 | `SetLinkDNSSEC` (`is`) | The index, `no` |
| 4 | `SetLinkDNSOverTLS` (`is`) | The index, `no` |
| 5 | `SetLinkLLMNR` (`is`) | The index, `no` |
| 6 | `SetLinkMulticastDNS` (`is`) | The index, `no` |
| 7 | `SetLinkDNSEx` (`ia(iayqs)`) | The index; one entry: `AF_INET` with the 4 address bytes or `AF_INET6` with the 16, the port, and an empty server name |

The `true` flag of `SetLinkDomains` marks a routing-only domain, which systemd-resolved sends to the link but never appends to a bare host name. The default-route flag goes first, so the link never answers names outside its domains. The server goes last, so a failure halfway leaves a link without a server, which systemd-resolved never asks. DNSSEC is off because a private zone such as `lab.internal` has no chain of trust. DNS over TLS, LLMNR and mDNS are off because the resolver speaks plain DNS on the mesh only. A failure in steps 2 to 7 is followed by one `RevertLink`, whose result is ignored, so the next `Apply` starts from a clean link.

When the context of `Apply` has a deadline, the read and the steps run under one a fifth of the remaining time earlier, about 4 seconds of the manager's 5. A step that runs out of time then fails with `context deadline exceeded`. When it is one of steps 2 to 7, its `RevertLink` is still sent, under the full deadline, in the fifth held back for it. A context that is cancelled during a step, which happens only while plexd stops, sends no `RevertLink`: the drain's revert clears the link then.

`SetLinkDNSEx` is the only setter that takes a port, and systemd-resolved has it since version 246. plexd therefore needs systemd-resolved 246 or newer and a reachable system bus. An older systemd-resolved counts as none: the read of `DNSEx` fails on it, so plexd sets nothing on its link.

| Failure of `Apply` | Error | Wraps `ErrUnavailable` |
|--------------------|-------|------------------------|
| No interface carries the name | `meshdns: resolved: interface <name>: no such network interface` | no |
| The interface list cannot be read | `meshdns: resolved: interface <name>: list interfaces: <cause>` | no |
| The system bus connection fails, for example `dial unix /var/run/dbus/system_bus_socket: connect: no such file or directory` | `meshdns: resolved: systemd-resolved is not running: meshdns: no usable system resolver` | yes |
| The read of `DNSEx` or any step answers `org.freedesktop.DBus.Error.ServiceUnknown`, `org.freedesktop.DBus.Error.NameHasNoOwner` or `org.freedesktop.systemd1.NoSuchUnit`. For a stopped systemd-resolved the bus daemon answers `NameHasNoOwner`, because no call starts it | `meshdns: resolved: systemd-resolved is not running: meshdns: no usable system resolver` | yes |
| The read of `DNSEx` answers `org.freedesktop.DBus.Error.UnknownProperty`, `org.freedesktop.DBus.Error.UnknownInterface`, `org.freedesktop.DBus.Error.UnknownMethod` or `org.freedesktop.DBus.Error.InvalidArgs`. systemd-resolved 245 answers `UnknownProperty` | `meshdns: resolved: systemd-resolved is older than 246: meshdns: no usable system resolver` | yes |
| Step 1 or step 7 answers `org.freedesktop.DBus.Error.UnknownMethod` | `meshdns: resolved: systemd-resolved is older than 246: meshdns: no usable system resolver` | yes |
| Any other error of the read of `DNSEx`, such as `Permission denied` or the deadline running out | `meshdns: resolved: DNSEx: <cause>` | no |
| Any other error of a step, such as `org.freedesktop.resolve1.LinkBusy` on a link systemd-networkd manages, or the deadline running out during a call | `meshdns: resolved: <method>: <cause>` | no |

The manager logs an error that wraps `ErrUnavailable` once at Info, and the resolver keeps answering on its listen address.

`Revert` calls `RevertLink` (`i`) with the interface index. It returns `nil` when there is nothing to clear: the interface does not exist, the bus connection fails, systemd-resolved answers `ServiceUnknown`, `NameHasNoOwner` or `NoSuchUnit`, or it answers `org.freedesktop.resolve1.NoSuchLink`. An interface list that cannot be read returns `meshdns: resolved: interface <name>: list interfaces: <cause>`, and any other error, such as `org.freedesktop.DBus.Error.AccessDenied`, returns `meshdns: resolved: RevertLink: <cause>`.

### plexd Owns the Link

plexd owns the per-link resolver settings of its mesh interface. Each `Apply` replaces the link's default-route flag, domains, DNSSEC, DNS over TLS, LLMNR and mDNS settings and its DNS servers. `RevertLink` clears all of them, including any an operator set there by hand. plexd does not read the link back: a setting changed by hand after a registration stays until the registration changes, the next start applies it again or reverts the link, or a stop reverts it. Set nothing by hand on that link.

## Following the State Pull

`Manager` ties the records, the server and the registrar together. Every line it and its server log carries `component=meshdns`.

```go
func NewManager(cfg Config, iface string, meshIP netip.Addr, registrar Registrar, logger *slog.Logger) *Manager
func (m *Manager) Start() error
func (m *Manager) Addr() netip.AddrPort
func (m *Manager) Run(ctx context.Context) error
func (m *Manager) Handle(ctx context.Context, desired *api.NodeStateSnapshot)
func (m *Manager) Shutdown(ctx context.Context) error
```

`Start` binds the sockets on `meshIP` and `cfg.ListenPort`, and `Run` serves them until its context ends. `Addr` is the listen address the log lines name. `Handle` has the signature of a [dispatch handler](../core/reconciliation.md#dispatchhandler) and runs on every successful pull, drift or not. A mutex guards the state `Handle` and `Shutdown` share.

1. A nil snapshot returns at once.
2. A snapshot without a `dns` block, the wire's `null` or a pull from a control plane that predates the block, keeps the names and the registration. The first such pull logs `state pull carries no dns block, keeping the names held`. Later ones log nothing until a block arrived in between.
3. A block is built into records, which the server takes with an atomic swap, so a pull never blocks a query. Skipped entries log `mesh dns skipped invalid entries` with the count and the first five sentences, on every pull that carries them. Records that differ from the previous ones log `mesh dns records updated`, and the first block always counts as a change.
4. The wanted registration is compared with the one systemd-resolved accepted last. When they are equal, nothing is called, so a pull that changes only hosts or records issues no bus call. When the wanted registration is empty, `Revert` is called, bounded by 5 seconds, if this run called `Apply` since its last successful revert, whether that `Apply` succeeded or failed. Otherwise `Apply` is called, bounded by 5 seconds.
5. After a failed `Apply` nothing counts as applied, so the next pull calls `Apply` again. A systemd-resolved that starts later, or a link that frees up, is picked up within one reconcile interval. On a host without a usable systemd-resolved each retry costs at most one bus call, the read of `DNSEx`, and changes nothing. A failed `Apply` can leave settings on the link, the earlier registration's or those of the steps that succeeded, so an empty registration on a later pull still reverts it. A failed revert counts as nothing reverted, so the next pull whose registration is empty reverts again.

A pull whose context is already done, because plexd is stopping, still swaps the records but calls no registrar method. The drain's revert is the last word on the link.

A successful `Apply` logs `mesh dns registered with systemd-resolved`. A revert from `Handle` logs nothing when it succeeds. An error wrapping `ErrUnavailable` logs `mesh dns not registered, systemd-resolved is not usable` at Info, once per change into that state: a success or another failure in between makes it log again. Any other error, from `Apply` or from the revert, logs `mesh dns registration failed` at Warn, unless its text is the one this line logged last. A success or an unavailable answer in between makes the same text log again.

A resolver failure never changes readiness. The health endpoints do not report the resolver, and the log lines are the operator's view of it.

## Every Zone on Every Node

The block lists every zone of the Domain: its default domain and the zone of every Project. Every Node of the Domain answers and registers all of them, not only its own Project's. A Project whose zone is overridden to a name such as `edge.example.com` therefore takes that zone on this Node. The host sends every name under `edge.example.com` to plexd, which answers the mesh hosts and the records there and `NXDOMAIN` for any other name, so the host no longer resolves the rest of that zone through its own DNS servers.

The block also carries the records of the Domain and of every Project, and every Node answers all of them. A record a Project defines therefore resolves on every Node of the Domain, not only on the Nodes of that Project.

`dns.enabled: false` is the Node operator's way out. It turns the resolver and its registration off on this Node, and plexd reverts the link at start.

## Startup in plexd up

`plexd up` sets the resolver up right after the WireGuard interface. It checks these conditions in this order:

| Condition | What happens |
|-----------|--------------|
| The platform has no registrar (macOS, Windows, any platform but Linux) | Nothing, and no log line |
| `dns.enabled: false` | Logs `mesh dns disabled by dns.enabled`, then reverts the mesh interface's link within 5 seconds. A failed revert logs `mesh dns revert failed` |
| The WireGuard interface did not come up | Logs `wireguard unavailable, mesh dns not started`, then reverts the link the same way |
| The mesh IP does not parse | Logs `mesh dns not started, the mesh ip does not parse`, then reverts the link the same way |
| A bind fails, or the mesh IP is unspecified | Logs `mesh dns listener cannot bind, mesh names are not answered` with the hint `set dns.listen_port to a free port`, reverts the link the same way, and goes on without the resolver |
| Both binds succeed | Logs `mesh dns listening` with the listen address |

Every start that runs no resolver reverts the link, whatever the reason, and a start whose resolver listens applies on the first pull. A registration a killed run left behind would otherwise keep sending the mesh zones to a port nothing listens on: a kill leaves `plexd0` behind, and the next start's WireGuard setup fails on it (see [Stop, Crash and Opt-Out](#stop-crash-and-opt-out)). The revert does nothing when the link does not exist.

The sockets are bound before the dispatch handler is registered, so a Node that cannot answer never registers a server. Only a resolver that listens gets the dispatch handler, registered after the reachability observer, and a goroutine that serves its sockets. `Run` returns once plexd stops. Only a failed UDP read, or a TCP listener that something other than the stop closed, ends it before that. plexd then logs `mesh dns stopped`, and no mesh name is answered for the rest of the run, while the registration stays until the drain reverts it. A failed accept is retried and stops nothing (see [TCP](#tcp)). Nothing here stops startup: the mesh works without names.

## Stop, Crash and Opt-Out

| Event | What plexd does | What the link holds afterwards |
|-------|-----------------|--------------------------------|
| A stop of a run whose resolver listens, such as `systemctl stop plexd` | The drain calls `Shutdown` first, right after `shutting down` and before any other subsystem stops, with a fresh context bounded by 5 seconds. It goes first because the resolver stopped answering when the stop began. The interface still exists then, because WireGuard is torn down last. `Shutdown` reverts the link on every run, registered or not, and logs `mesh dns registration reverted`. An error logs `mesh dns shutdown error` | Nothing plexd set |
| A stop of a run that runs no resolver | Nothing for mesh DNS: the start reverted the link already | Nothing plexd set |
| A crash or a kill | No drain runs, so `plexd0` stays, and so does its registration | The last registration, until the next start reverts it. The link's default-route flag stays off, so only the mesh zones go to the mesh IP, where nothing answers |
| The next start after a crash or a kill | WireGuard setup fails on the leftover `plexd0` (`EEXIST`), so the run logs `wireguard unavailable, mesh dns not started`, starts no resolver and reverts the link at start. The drain of that run deletes the leftover `plexd0`, so the start after it creates a fresh one | Nothing plexd set |
| A start whose resolver listens | WireGuard has just created `plexd0`, so the link holds no settings. The first pull whose block names an accepted zone or reverse zone applies its registration | The new registration |
| A start with `dns.enabled: false`, without WireGuard, with a mesh IP that does not parse, or with a listener that cannot bind | Starts no resolver and reverts the link at start | Nothing plexd set |

To turn the resolver off, set `dns.enabled: false` in the config file, or set `PLEXD_DNS_ENABLED=false`, for example in `/etc/plexd/environment` under the shipped `plexd.service`, and restart plexd. plexd reads the setting once, when it starts.

## Hosts without systemd-resolved

On a Linux host without systemd-resolved, with one older than 246, or without a reachable system bus, the resolver still runs and answers on its listen address. plexd sets no DNS setting of the host: on an older systemd-resolved the read of `DNSEx` fails before the first setter. Only `RevertLink` reaches an older one: at a stop, at a start that runs no resolver, and on a pull whose registration is empty. It clears whatever the mesh interface's link holds. plexd names the address in `mesh dns listening` when it binds, and again in `mesh dns not registered, systemd-resolved is not usable` on the first pull whose block names an accepted zone or reverse zone:

```text
level=INFO msg="mesh dns listening" listen=10.99.0.1:5354
level=INFO msg="mesh dns not registered, systemd-resolved is not usable" component=meshdns listen=10.99.0.1:5354 reason="meshdns: resolved: systemd-resolved is not running: meshdns: no usable system resolver"
```

plexd keeps calling `Apply` on every pull without logging again, so a systemd-resolved that starts later is picked up within one reconcile interval. Each of these calls is at most the read of `DNSEx`, and none changes the link.

To use the names on such a host, point a local forwarding resolver at the listen address for the mesh zones and the reverse zones. For dnsmasq on the Node with the mesh IP `10.99.0.1`, in a Domain whose zones lie under `e2e.internal` and whose mesh CIDR is `10.99.0.0/24`:

```text
server=/e2e.internal/10.99.0.1#5354
rev-server=10.99.0.0/24,10.99.0.1#5354
```

`server=` sends every name under `e2e.internal` to the resolver, and `rev-server=` sends the reverse names of `10.99.0.0/24`.

- The resolver answers the Node itself only. dnsmasq on the Node sends its queries to the Node's own mesh IP, and the kernel sends a packet for a local address from that address, so the [source rule](#source-rule) accepts them. A resolver in a Pod or container network sends from an address of its own, so the resolver drops its queries, and it cannot use the names this way.
- The zone list of such a hand-written rule follows the Domain's zones by hand. When the Domain gains a zone that the lines do not cover, such as a Project's zone override, or its mesh CIDR changes, change the lines yourself: nothing updates them.
- A CNAME whose target lies outside the mesh zones resolves only when the local resolver follows it, as systemd-resolved does. plexd answers such a name with the CNAME alone. A forwarder that passes the answer on as it is leaves the target to the program that asked.

## Log Lines

`plexd up` logs these lines without a `component` key:

| Level   | Message | Keys |
|---------|---------|------|
| `Warn`  | `invalid PLEXD_DNS_ENABLED, leaving dns.enabled unchanged` | `value` |
| `Info`  | `mesh dns disabled by dns.enabled` | none |
| `Warn`  | `mesh dns revert failed` | `interface`, `error`. The revert at the start of a run that starts no resolver |
| `Warn`  | `wireguard unavailable, mesh dns not started` | none |
| `Warn`  | `mesh dns not started, the mesh ip does not parse` | `mesh_ip`, `error` |
| `Warn`  | `mesh dns listener cannot bind, mesh names are not answered` | `listen`, `error`, `hint` (`set dns.listen_port to a free port`) |
| `Info`  | `mesh dns listening` | `listen` |
| `Error` | `mesh dns stopped` | `error`. The resolver stopped while plexd was running |
| `Error` | `mesh dns shutdown error` | `error`. The drain's revert failed |

The manager logs these with `component=meshdns`:

| Level  | Message | Keys |
|--------|---------|------|
| `Info` | `state pull carries no dns block, keeping the names held` | none. Once, and again only after a block arrived in between |
| `Warn` | `mesh dns skipped invalid entries` | `count`, `skipped` (the first five sentences). On every pull whose block has skipped entries |
| `Info` | `mesh dns records updated` | `hosts`, `records` (the number of accepted records), `zones`, `reverse_zones`, `search_domain` (empty when the Node has none) |
| `Info` | `mesh dns registered with systemd-resolved` | `interface`, `server`, `search_domain`, `routing_domains` (the count) |
| `Info` | `mesh dns not registered, systemd-resolved is not usable` | `listen`, `reason`. Once per change into that state |
| `Warn` | `mesh dns registration failed` | `error`. Once per distinct error text |
| `Info` | `mesh dns registration reverted` | `interface`. The drain's revert returned no error. It also logs where there was nothing to revert, such as on a host without systemd-resolved or a system bus |

The server and the registrar log at Debug only, with `component=meshdns`:

| Message | Keys |
|---------|------|
| `mesh dns dropped a packet from a source it does not answer` | `source` |
| `mesh dns closed a connection from a source it does not answer` | `source` |
| `mesh dns closed a connection, too many are open` | `source`, `limit` |
| `mesh dns could not accept a connection` | `error`, `delay` (the wait before the next accept) |
| `mesh dns dropped a packet that gets no reply` | `source`, `bytes` |
| `mesh dns dropped a message that gets no reply` | `bytes` (TCP) |
| `mesh dns could not send a reply` | `source`, `error` |
| `mesh dns answer does not fit a message` | `name`, `type`, `bytes` (the size of the full response). TCP; the response goes out as `SERVFAIL` |
| `mesh dns could not pack a reply` | `error` |
| `system bus unreachable` | `error` |
| `systemd-resolved not usable` | `method`, or `property` (`DNSEx`) for the read before step 1; `error` |
| `revert after a failed registration failed` | `interface`, `error` |

A registered Node logs, for the [mock control plane's](../development/mock-api-server.md#get-v1-nodes-id-state) block:

```text
level=INFO msg="mesh dns listening" listen=10.99.0.1:5354
level=INFO msg="mesh dns records updated" component=meshdns hosts=3 records=8 zones=2 reverse_zones=1 search_domain=app.e2e.internal
level=INFO msg="mesh dns registered with systemd-resolved" component=meshdns interface=plexd0 server=10.99.0.1:5354 search_domain=app.e2e.internal routing_domains=2
```

See [A mesh name does not resolve](../../guide/troubleshooting.md#a-mesh-name-does-not-resolve) for how to read them on a Node.
