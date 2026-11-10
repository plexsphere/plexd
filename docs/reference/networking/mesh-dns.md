---
title: Mesh DNS
package: internal/meshdns
---

# Mesh DNS

The `internal/meshdns` package answers the mesh names of the Node's Domain, and the DNS records the Domain and its Projects define, from a resolver on the Node itself. The same resolver forwards the names of the forward zones the Node's forwarding setting names to the resolvers listed with them, and with a catch-all every other name to the catch-all resolvers. The names, the records and the forwarding setting come from the `dns` block of the state pull (see [State](../core/api-endpoints.md#get-v1-nodes-node-id-state)), which the "Mesh DNS names" section of plexsphere's agent contract (`docs/reference/api/plexd-agent-contract.md` in plexsphere/plexsphere) describes. On Linux, plexd registers the resolver with systemd-resolved for the mesh zones and the forward zones, on the mesh interface, and with a catch-all it makes that link the host's default DNS route. On macOS, plexd writes DNS entries for the same zones into configd's SystemConfiguration dynamic store with `/usr/sbin/scutil`, from which mDNSResponder takes its per-domain resolvers, and with a catch-all it writes a default-resolver entry (see [Registration on macOS](#registration-on-macos)). The host then asks plexd for those zones, and with a catch-all for every name no other domain of the host's resolver configuration matches, and resolves every other name as before.

plexd is not recursive. It answers `A`, `AAAA` and `PTR` queries for the Nodes' names and mesh IPs, and queries for the records of the six types `A`, `AAAA`, `CNAME`, `TXT`, `SRV` and `MX`. It denies every other name in the mesh zones. A name outside them goes to the resolvers of the forwarding setting when a forward zone covers it or a catch-all is set: plexd passes the query on and relays the reply, and keeps no cache (see [Forwarding](#forwarding)). It refuses every other name outside the mesh zones. It follows a CNAME while its target lies in the mesh zones, and answers one whose target lies outside them with the CNAME alone, for the system resolver to follow. It answers the Node itself only, forwarded names included. It writes no file. On Linux it changes no resolver setting of the host outside the mesh interface's link, although a catch-all makes that link the host's default DNS route. On macOS it changes no resolver setting of the host but the dynamic-store entries it owns, and it empties mDNSResponder's cache whenever it changes them (see [The Cache Flush](#the-cache-flush)), although a catch-all's entry is a default resolver ordered ahead of the primary network service's.

Linux and macOS run the resolver, in node mode and in bridge mode. On Windows `plexd up` starts no resolver and logs nothing about it. The `dns` keys are still parsed and validated there.

## Data Flow

```
Control Plane
      │
      │ GET /v1/nodes/{id}/state  →  dns block
      ▼
┌──────────────┐    ┌──────────────────────────┐
│  Reconciler  │───▶│     meshdns.Manager      │
│              │    │          Handle          │
└──────────────┘    └──┬────────────────────┬──┘
                       │ SetRecords         │ Apply / Revert
                       │ SetForwarding      │
                       ▼                    ▼
               ┌────────────────┐       ┌───────────────────┐
               │     Server     │       │ ResolvedRegistrar │─ D-Bus ──▶ systemd-resolved (Linux)
               │ mesh IP : 5354 │       │        or         │
               │ (Linux), or    │       │  ScutilRegistrar  │─ scutil ─▶ configd (macOS)
               │ 127.0.0.1:5354 │       └───────────────────┘
               │ (macOS)        │
               └────────────────┘
                   ▲          │
                   │          │ forwarded queries over UDP or TCP, port 53
                   │          ▼
                   │    forward zone and catch-all resolvers
                   │
                   │ queries for the mesh zones and the forward zones, and with a
                   │ catch-all every name no other domain matches: on Linux through
                   │ the mesh interface, on macOS to 127.0.0.1
                   │
           systemd-resolved (Linux) or mDNSResponder (macOS)
```

A pull with a `dns` block replaces the names the server answers and the forwarding table it forwards with. It replaces the registration only when the one the block implies differs from the one applied, so a pull that changes only hosts, records or resolvers issues no call to the system resolver, as long as the accepted forward zones stay the same and an accepted catch-all resolver neither appears nor goes. A pull without a block changes nothing. plexd keeps the names and the forwarding table in memory only. A restart starts without names and forwards nothing, as it starts without peers, and all of them come back with the first pull.

## Config

`Config` holds the resolver's settings under the key `dns` of the agent configuration (see [Configuration Reference](../core/configuration.md#dns)).

| Field        | Type    | Default         | Description |
|--------------|---------|-----------------|-------------|
| `Enabled`    | `*bool` | `nil` (enabled) | Run the resolver and its registration (`enabled`) |
| `ListenPort` | `int`   | `5354`          | UDP and TCP port the resolver listens on, on the Node's own mesh IP on Linux and on `127.0.0.1` on macOS (`listen_port`) |

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

On Linux the resolver listens on the Node's own mesh IP, the address registration assigned, and on macOS on `127.0.0.1`, on `dns.listen_port`, over UDP and TCP. systemd-resolved moves a server to TCP after repeated UDP losses, for example across a plexd restart, so a resolver that answered on UDP only would fail it then. `Start` binds both sockets and fails when either bind fails, closing the socket that did bind. It refuses an unspecified address, `0.0.0.0`, `::` or `::ffff:0.0.0.0`, which would bind every interface of the host, with `meshdns: listen <address>: no address to listen on`. A resolver binds once: every `Start` after one that succeeded fails with `meshdns: listen <address>: already listening`.

The address is the mesh IP and not loopback, because systemd-resolved sends a query for a per-link DNS server out through that link. A listener on `127.0.0.1` is never reached through the mesh interface. The Node's own mesh IP is a local address, so the kernel delivers the query locally, and every query systemd-resolved sends arrives with the mesh IP as its source address.

On macOS the address is `127.0.0.1`, because a Mac cannot reach its own utun mesh IP. The mesh address's alias makes the mesh IP the utun's point-to-point destination too, so the route to it leads into the utun: `route -n get <mesh IP>` names the utun, and a packet the Mac sends to its own mesh IP enters the tunnel, where wireguard-go drops it. That was measured on the CI macOS runner, for mDNSResponder's queries and for a plain UDP socket alike. The dynamic-store entries are bound to no interface and name `127.0.0.1`, so mDNSResponder's queries arrive over `lo0` from a loopback address, which the [source rule](#source-rule) accepts. plexd's [pf anchor](./pf-wfp-firewall.md) does not see them, because every rule of the anchor names the mesh utun.

The port is unprivileged, so `plexd.service` needs no `CAP_NET_BIND_SERVICE` for the resolver.

### Source Rule

The resolver answers the Node itself only. It accepts a query when the source address, with an IPv4-mapped address unmapped, is the listen address itself or a loopback address. It drops every other UDP packet without a reply, and closes every other TCP connection at accept, before reading anything.

This check is what keeps other hosts from using the resolver. plexd's [nftables policy](./nftables-firewall.md) sits on the forward hook only, so it does not filter traffic to the Node itself, and a mesh peer reaches the mesh IP. A mesh peer cannot send from the Node's own address, because WireGuard drops a packet whose source lies outside the sending peer's allowed IPs. On macOS the resolver listens on `127.0.0.1`, which no other host reaches at all.

A program on the Node that queries the mesh IP directly, such as `dig @10.99.0.1 -p 5354 peer-1.app.e2e.internal`, sends from the mesh IP and gets an answer. On macOS it asks `127.0.0.1` instead, such as `dig @127.0.0.1 -p 5354 peer-1.app.e2e.internal`. A program in a Pod or container network sends from an address of its own and gets none.

### TCP

TCP frames each message with a two-byte length (RFC 7766). A connection may carry several queries, and a client may send the next one before the reply to the one before has arrived, as systemd-resolved does for lookups that run at the same time. plexd reads the queries in order and answers every query it does not forward at once, a mesh name included. A forwarded query gets its reply once its resolvers answered or failed, so the replies can go out in another order than the queries, as RFC 7766 section 7 allows, and the client matches them by message ID (see [The Reply](#the-reply)). Each reply goes out whole, behind its own length.

plexd reads a connection for 10 seconds after the accept, and for 10 seconds again after each reply it sends and after each query it forwards. A forwarded query gets its reply within 4 seconds (see [Asking the Resolvers](#asking-the-resolvers)), so the 10 seconds do not pass while it waits for its resolvers, and plexd reads on meanwhile. When the 10 seconds pass, or the client closes its side, plexd reads no further query from the connection, waits for its forwarded queries still in flight, sends their replies, and closes it. Each reply has 10 seconds to be written, and a write that fails closes the connection. At most 32 connections are open at a time, and a further one is closed at accept. A message on a connection that gets no reply (see [Malformed and Refused Queries](#malformed-and-refused-queries)) is skipped, and the connection stays open. A skipped message does not restart the 10 seconds: only a reply or a forwarded query does.

A connection holds at most 16 forwarded queries whose replies are not written yet (see [The Reply](#the-reply)). A client that stops reading its replies therefore stops plexd reading its queries once 16 replies to its forwarded queries wait for it, until it reads again or the 10 seconds of the waiting write pass, which closes the connection.

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

Any query before the first `dns` block gets `REFUSED`, and so does any name outside every accepted zone and reverse zone that the forwarding table does not route. A name outside them that the table routes goes to its resolvers instead (see [Forwarding](#forwarding)). Any other name is looked up by these steps, in this order, and the first step that applies gives the answer:

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
| A name outside every accepted zone and reverse zone that `Route` does not route: no forward zone covers it and no catch-all resolver is accepted | `REFUSED` | none |
| A name outside every accepted zone and reverse zone that `Route` routes, in a query plexd forwards (see [What Is Forwarded](#what-is-forwarded)) | The resolver's, or `SERVFAIL` when no resolver answers | The resolver's reply; see [Forwarding](#forwarding) |
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

The response echoes the query's ID, its opcode, its RD bit and its question exactly as received, upper case included. It sets QR and clears RA. AA is set on every `NOERROR` and `NXDOMAIN` answer from the records, and clear on `REFUSED`, `FORMERR`, `NOTIMP` and `SERVFAIL`. A relayed reply is the resolver's own message with the query's ID written back, so it keeps the resolver's header, its flags and its response code (see [The Reply](#the-reply)).

A response over UDP carries at most 512 bytes when the query has no OPT record. With one, it carries at most the UDP payload size the client offers, but never less than 512 and never more than 1232 bytes. A response over that limit is sent with TC set and otherwise the same header, the question, no record in the answer and authority sections, and an OPT record when the query had one. The client then asks again over TCP. The limit holds for a relayed reply too. systemd-resolved offers 1472 bytes, so it gets up to 1232, and it repeats a truncated query over TCP. busybox `nslookup` sends no OPT record and ignores TC, so for an answer of more than 512 bytes it prints nothing and exits 0.

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

The opcode is checked before the questions and the OPT records, so a query with another opcode gets `NOTIMP` however many OPT records it carries. None of these messages is forwarded, whatever its name.

## Forwarding

The `forwarding` member of the `dns` block says where the names outside the mesh go: each forward zone with the resolvers that answer the names under it, and the catch-all resolvers that answer every name outside the mesh zones, the reverse zones and the forward zones. The control plane sends the setting that applies to the Node: its Project's when the Project holds one, otherwise its Domain's, otherwise two empty lists. Forward zones come ascending by zone, each with 1 to 3 resolvers, and the catch-all holds 0 to 3. A resolver is an IPv4 or IPv6 address in text form, asked in list order on port 53 over plain DNS. The contract's example:

```json
"forwarding": {
  "forward_zones": [
    { "zone": "2.0.192.in-addr.arpa", "resolvers": ["10.1.2.3"] },
    { "zone": "corp.example.com", "resolvers": ["10.1.2.3", "10.1.2.4"] },
    { "zone": "corp.local", "resolvers": ["10.1.2.5"] }
  ],
  "catch_all": ["10.1.2.53"]
}
```

A block without the member, or with `"forwarding": null`, keeps the forwarding the Node holds (see [Following the State Pull](#following-the-state-pull)). Two empty lists end it. A `null` or missing list inside the member is an empty one.

plexd forwards on its listen address, for the Node itself only, as it answers the mesh names (see [Source Rule](#source-rule)). It is still not recursive: it passes the client's query on to the resolvers and relays their reply, and it keeps no cache.

### Forward Zones and Resolvers

`BuildForwarding(setting api.NodeStateDNSForwarding, records *Records, self netip.Addr) (*Forwarding, []string)` turns the member into the immutable `Forwarding` table the server forwards with, and returns one sentence for each entry it skipped. `records` supplies the accepted zones and reverse zones, and a nil `records` has none. `self` is the resolver's listen address. As with the records, the control plane is trusted, but every entry is checked where it enters for what would break the host: a zone that takes the host's own names, or a resolver that sends the query back to the host. plexd does not check the limits the control plane sets on the number of forward zones and resolvers, so a change of those limits needs no new plexd.

A forward zone is folded to ASCII lower case and checked in this order, and the first check it fails skips it with its sentence. `<zone>` is the zone as the member spelled it, and `<name>` the folded name:

| Check | The forward zone is skipped when | Sentence |
|-------|----------------------------------|----------|
| Name | The name is not valid by the rule of [Records](#records), with `_` allowed at any position of a label, as in `_msdcs.corp.example.com` | `forward zone "<zone>" is not a valid name because it <reason>` |
| Reserved | The name is `local`, `localhost`, `arpa`, `in-addr.arpa` or `ip6.arpa` | `forward zone "<zone>" is <name> itself, which the contract rules out` |
| Reserved | The name lies under `localhost`, or under `arpa` but not under `in-addr.arpa` or `ip6.arpa` | `forward zone "<zone>" is under localhost, which the contract rules out`, or the same with `arpa` |
| Shadow | The name is an accepted zone or reverse zone, or lies under one. The sentence names the nearest one, a reverse zone included | `forward zone "<zone>" is shadowed by the mesh zone "<mesh zone>", which answers its names` |
| Repeat | An accepted forward zone has the same folded name | `forward zone "<zone>" repeats an earlier forward zone` |
| Resolvers | No resolver of the zone is accepted, an empty `resolvers` list included | `forward zone "<zone>" has no usable resolver` |

The reason of an invalid name is one of those listed under [Records](#records), so a zone with a trailing dot is skipped too. A name under `local`, such as the Active Directory zone `corp.local`, is accepted, and so are a reverse zone under `in-addr.arpa` or `ip6.arpa`, such as `2.0.192.in-addr.arpa`, a single label such as `corp`, a forward zone above a mesh zone, such as `example.com` while `edge.example.com` is a zone of the Domain, and a forward zone under another forward zone. The mesh zone below a forward zone keeps its names, because the records answer first, and of two nested forward zones the longer one takes the names under it (see [Route](#route)).

The resolvers of an accepted zone, and then those of the catch-all, are checked in this order. A skipped resolver costs only itself: the other resolvers of the same owner stay, in their order. `<owner>` is `forward zone "<zone>"` or `the catch-all`, and `<value>` is the resolver as the member spelled it:

| Check | The resolver is skipped when | Sentence |
|-------|------------------------------|----------|
| Address | It does not parse as an IP address | `resolver "<value>" of <owner> is not an IP address` |
| Forwardable | It carries an IPv6 zone such as `%eth0`, or it is an IPv4-mapped IPv6 address, the unspecified address, a loopback, multicast or link-local unicast address, or `255.255.255.255` | `resolver "<value>" of <owner> is not an address plexd forwards to` |
| Self | It is the resolver's own listen address, an IPv4-mapped listen address compared as the IPv4 address it carries. On macOS that address is `127.0.0.1`, which the loopback check above already refuses, so the node's own mesh IP is accepted there; the Mac cannot reach it, so a forward to it fails like one to any resolver that does not answer | `resolver "<value>" of <owner> is the resolver's own listen address` |
| Repeat | An accepted resolver of the same owner has the same address | `resolver "<value>" of <owner> repeats an earlier resolver` |

A loopback resolver is refused because `127.0.0.53` is systemd-resolved's stub listener, which would send the query back to plexd, and the listen address would loop the same way. The resolvers of a zone that an earlier check skipped are not checked. The sentences come in the member's order: each zone in turn, a zone's resolver sentences before its `has no usable resolver`, and the catch-all last. The manager logs them after the sentences of the records, in the one `mesh dns skipped invalid entries` line (see [Following the State Pull](#following-the-state-pull)).

### Route

```go
func (f *Forwarding) Route(name string) (resolvers []netip.Addr, zone string, ok bool)
func (f *Forwarding) Equal(o *Forwarding) bool
func (f *Forwarding) ZoneCount() int
func (f *Forwarding) CatchAllCount() int
```

`Route` folds the name to ASCII lower case and drops one trailing dot. It returns the resolvers of the longest accepted forward zone that is the name itself or lies above it, label by label, together with that zone. Otherwise it returns the catch-all resolvers with the zone `.`, when the table has any. Otherwise `ok` is false. With the forward zones `corp.example.com` and `eu.corp.example.com`, `db.eu.corp.example.com` goes to the resolvers of `eu.corp.example.com`, `www.corp.example.com` to those of `corp.example.com`, and `xcorp.example.com` to neither, because the match is by labels. A nil `*Forwarding` routes nothing.

`Equal` compares the zones, the resolvers of each zone and the catch-all, in order, and counts a nil table as one without zones and without a catch-all. `ZoneCount` returns the number of accepted forward zones and `CatchAllCount` the number of accepted catch-all resolvers, both 0 on a nil table.

### What Is Forwarded

The server forwards a query only when all of this holds:

1. The source passes the [source rule](#source-rule).
2. The opcode is `QUERY`, the message has exactly one question and at most one OPT record, and the class is `IN`.
3. The records answer `REFUSED`: the name lies outside every accepted zone and reverse zone.
4. The type is neither `AXFR` nor `IXFR`.
5. `Route` returns resolvers for the name.

Every other query is answered as [What the Resolver Answers](#what-the-resolver-answers) describes, so the mesh zones always win. A name in a mesh zone that does not exist gets `NXDOMAIN` from the records, even under a forward zone above the mesh zone. A zone transfer, another class, another opcode, two questions or two OPT records get the answer they get without forwarding. A name outside every zone that `Route` does not route gets `REFUSED`, and so does every query before the first `dns` block, because the manager swaps a table in only together with the records of a block.

plexd never follows a CNAME of a mesh zone into a forward zone itself. It answers the CNAME alone, as for any target outside the mesh zones, and the system resolver asks for the target. systemd-resolved sends that query to plexd again when the target lies under a forward zone, or, with a catch-all, under no domain of another link.

### Asking the Resolvers

| Rule | Behavior |
|------|----------|
| Transport | A query that arrived over UDP goes to the resolvers over UDP, and one that arrived over TCP over TCP, with the two-byte length frame. Every resolver is asked on port 53 (`resolverPort`) over plain DNS. Each attempt uses a socket of its own, a connected UDP socket or a TCP connection, which it closes when it ends |
| Message ID | The query goes out as the client sent it, but with a message ID of two random bytes from `crypto/rand`, drawn again when they equal the client's ID. A reply matches when it has at least the 12-byte header, carries that ID, has QR set, and its question has the query's name, compared without regard to case, and the query's type and class. Any other datagram or message is dropped, and the attempt reads on |
| Time | One forwarded query has 4 seconds (`forwardTimeout`) for all its resolvers together. That stays below the 5 seconds systemd-resolved and glibc wait for a server, so the client gets `SERVFAIL` from plexd rather than count plexd as a server that does not answer, which would cost it the mesh names as well. systemd-resolved 255 asks again after a `SERVFAIL`, first at the same feature level and after a second `SERVFAIL` at the next lower one. With DNSSEC and DNS over TLS off on the mesh link, a lookup therefore asks plexd three times, with EDNS0, with EDNS0 again and over plain UDP, before it fails with `SERVFAIL`. Under a zone whose resolvers send nothing back, each round waits the 4 seconds, so the lookup fails only after about 12 seconds. Resolvers that refuse the query, with an ICMP port unreachable or a TCP reset, fail each round as soon as the refusal arrives: plexd answers `SERVFAIL` after one round trip to each resolver it asks, well under a millisecond for a resolver on the same host, and the lookup fails just as quickly. The mesh names keep answering meanwhile: in the systemd e2e suite, with systemd-resolved 255, a mesh name asked during a lookup under a resolver that sends nothing back answered in 59 milliseconds |
| Order | The resolvers that are not marked down are asked first, then the marked ones, each group in list order. Each attempt gets the time left divided by the resolvers not yet asked, so with three resolvers that never answer each one waits about 1.3 seconds. A resolver that refuses the connection at once leaves its time to the next. When the time runs out, the resolvers not yet asked are neither asked nor marked |
| Response code | A matching reply with any response code but `SERVFAIL` or `REFUSED` ends the query. A `SERVFAIL` or `REFUSED` is kept while the next resolver is asked, and when no resolver gives another code, the last one kept goes to the client, so the client sees the resolver's own code. Such a reply counts as an answer and marks no resolver down |
| Down mark | An attempt that ends without a matching reply marks its resolver down for 30 seconds (`resolverRetry`): its time ran out, the resolver refused the connection (`ECONNREFUSED`, from an ICMP port unreachable over UDP or a refused TCP connection), or the socket failed in any other way. A query whose resolvers include a marked one asks it after the others. After the 30 seconds it is asked in its turn again, and a further failure marks it for another 30 seconds. The first matching reply of any code clears the mark |

A mark belongs to the resolver's address, so it holds for every forward zone and the catch-all that list it. The marks live in memory only, and a table that no longer names a resolver drops its mark. `mesh dns resolver does not answer` is logged at Warn when a resolver without a mark gets one, with the zone of the query that marked it, and nothing more is logged while it stays down, even when it is asked first again and fails. `mesh dns resolver answers again` is logged at Info when a marked resolver gives a matching reply. A resolver that answers `SERVFAIL` to every query is never marked, so it logs neither line.

### The Reply

The reply goes to the client as the resolver sent it, with the client's ID written back: its response code, its flags, TC included, its records and their TTLs. A reply with TC set stays truncated, so the client asks again over TCP. plexd keeps no cache, because systemd-resolved caches every reply for its TTL, and a second cache would be a second place where a changed name stays stale.

A reply relayed over UDP is held to the limit of [Response Header](#response-header): 512 bytes without an OPT record, otherwise the client's offer clamped to 512 to 1232 bytes. A larger reply is replaced by a response with TC set, the resolver's response code and its AA and RA bits, the question, no record, and an OPT record when the query had one. The client then asks again over TCP and gets the full reply there.

When no resolver answered, plexd answers `SERVFAIL` itself, with the query's ID, opcode, RD bit and question, AA and RA clear, no record, and an OPT record when the query had one. It logs `mesh dns forwarded query failed` at Debug with the error, which reads `meshdns: forward to <zone>: <cause>`, such as `meshdns: forward to corp.example.com: context deadline exceeded`.

A forwarded query waits for its resolvers in a goroutine of its own, over UDP and TCP alike, off the loop that reads the socket or the connection, so a resolver that is slow to answer never holds up a mesh answer, not even one asked on the same TCP connection. Two caps bound the forwarded queries. A query over either gets `SERVFAIL` at once and logs `mesh dns dropped a forwarded query, too many are in flight` at Debug, with the cap it hit as `limit`:

- At most 256 (`maxForwards`) forwarded queries wait for their resolvers at a time, UDP and TCP together. A slot frees as soon as its resolvers answered or failed, before the reply goes out.
- One TCP connection holds at most 16 (`maxConnForwards`) forwarded queries, each from the time plexd reads it until its reply is written. A reply waits to be written while the client does not read it, so without this cap a client that sends queries and stops reading the replies would keep a goroutine and a reply waiting for every query it sent. At the cap, plexd answers the next forwarded query with `SERVFAIL` from the connection's read loop. When the client has stopped reading, that reply waits behind the others, so plexd reads nothing more from the connection until the client reads again or the 10 seconds of the waiting write pass. A forward gives its place back when its reply is written, before the next reply goes out, so a client that has read a reply finds free the place of every forward whose reply went out before it.

On a TCP connection the replies go out in the order they are ready, not in the order of the queries: a mesh name asked after a forwarded query is answered first, and of two forwarded queries the one whose resolvers answer first gets its reply first. Each reply goes out whole, behind its two-byte length, and starts the connection's 10 seconds again, and so does each forwarded query when plexd reads it (see [TCP](#tcp)). A forward ends within its 4 seconds, so the 10 seconds do not pass while it waits, and plexd keeps reading the queries sent behind it. When the connection ends with forwarded queries still in flight, because the client closed its side or a read failed, plexd waits for them and sends their replies before it closes it.

When plexd stops, the forwarded queries in flight end without a reply: a UDP client gets none, and a TCP connection is closed. Nothing is logged for them, and no resolver is marked.

## Registration with systemd-resolved

`Registrar` is the seam to the operating system's resolver. Tests replace it with a recording fake, so no test changes the resolver settings of the host it runs on. `Name` names the system resolver the registrar writes to, as the manager's log lines name it: `systemd-resolved` for `ResolvedRegistrar` and `configd` for `ScutilRegistrar` (see [Registration on macOS](#registration-on-macos)).

```go
type Registration struct {
    Interface      string
    Server         netip.AddrPort
    SearchDomain   string
    RoutingDomains []string
    DefaultRoute   bool
}

type Registrar interface {
    Apply(ctx context.Context, reg Registration) error
    Revert(ctx context.Context, iface string) error
    Name() string
}

var ErrUnavailable = errors.New("meshdns: no usable system resolver")
```

`(*Records).Registration(iface string, server netip.AddrPort, fwd *Forwarding) Registration` builds what the Node registers. `Interface` is the mesh interface and `Server` the listen address. `SearchDomain` is the accepted search domain, or empty. `RoutingDomains` holds every accepted zone that has no other accepted zone above it, without the search domain, followed by every accepted reverse zone, and then every accepted forward zone of `fwd`, each group in ascending byte order. Routing a domain routes every name under it, so a Project zone below the Domain's default domain adds no entry, and the search domain routes the names under it as well. Reverse zones are never merged: a wider zone would make plexd answer `NXDOMAIN` for addresses outside the mesh. Forward zones are not merged either, neither with each other nor with the mesh zones, so the link lists every zone the Node forwards. `DefaultRoute` makes the link the host's default DNS route, and it is set when `fwd` has an accepted catch-all resolver. On macOS `DefaultRoute` writes a default-resolver entry instead, and `Interface` serves the log lines only, because a dynamic-store entry is bound to no interface. A nil `*Records` adds no zone and no search domain, and a nil `fwd` no forward zone and no default route. A registration is empty when it names no search domain and no routing domain and `DefaultRoute` is false.

The contract's example is a Node of the Project `openstack` in the Domain `lab`, whose mesh CIDR is `10.42.0.0/16`. Its block carries the search domain `openstack.lab.internal`, the zones `edge.example.com`, `lab.internal` and `openstack.lab.internal`, and the reverse zone `42.10.in-addr.arpa`. The Node registers the search domain `openstack.lab.internal` and the routing domains `edge.example.com`, `lab.internal` and `42.10.in-addr.arpa`. With the forwarding of the example in [Forwarding](#forwarding), it adds the routing domains `2.0.192.in-addr.arpa`, `corp.example.com` and `corp.local`, and `DefaultRoute` for the catch-all. `resolvectl domain` shows each routing domain with a leading `~`, and the catch-all as `~.`.

### ResolvedRegistrar

`NewResolvedRegistrar(logger *slog.Logger) *ResolvedRegistrar` (`resolved_linux.go`) is the `Registrar` on Linux. It talks to systemd-resolved over D-Bus, on the object `/org/freedesktop/resolve1` of `org.freedesktop.resolve1`. Each `Apply` and each `Revert` opens its own connection to the system bus and closes it, so no connection outlives the call, and a systemd-resolved or bus daemon that starts, stops or restarts between two pulls is found on the next call.

Every call the registrar makes carries the D-Bus flag `NO_AUTO_START`, so the bus daemon never starts a stopped systemd-resolved for plexd. An operator who stopped it keeps it stopped: the bus daemon answers `org.freedesktop.DBus.Error.NameHasNoOwner`, which counts as not running.

`Apply` looks the interface up in the host's interface list before it opens a connection. It then reads the `DNSEx` property of `org.freedesktop.resolve1.Manager` with `org.freedesktop.DBus.Properties.Get`, which changes nothing. systemd-resolved 246 added the property together with `SetLinkDNSEx`, so a failed read tells an older one apart before anything on the link changes. No other call follows a failed read, not even a `RevertLink`. After the read, `Apply` calls these methods of `org.freedesktop.resolve1.Manager`, in this order:

| Step | Method (signature) | Arguments |
|------|--------------------|-----------|
| 1 | `SetLinkDefaultRoute` (`ib`) | The interface index; `DefaultRoute`, so `true` with a catch-all and `false` without one |
| 2 | `SetLinkDomains` (`ia(sb)`) | The index; the search domain with `false` when there is one, then each routing domain with `true`, and with `DefaultRoute` the root domain `.` with `true` last |
| 3 | `SetLinkDNSSEC` (`is`) | The index, `no` |
| 4 | `SetLinkDNSOverTLS` (`is`) | The index, `no` |
| 5 | `SetLinkLLMNR` (`is`) | The index, `no` |
| 6 | `SetLinkMulticastDNS` (`is`) | The index, `no` |
| 7 | `SetLinkDNSEx` (`ia(iayqs)`) | The index; one entry: `AF_INET` with the 4 address bytes or `AF_INET6` with the 16, the port, and an empty server name |

The `true` flag of `SetLinkDomains` marks a routing-only domain, which systemd-resolved sends to the link but never appends to a bare host name. The default-route flag goes first, so a registration without a catch-all turns it off before anything else changes, and the link never answers names outside its domains. The server goes last, so a failure halfway leaves a link without a server, which systemd-resolved never asks. DNSSEC is off because a private zone such as `lab.internal` has no chain of trust. DNS over TLS, LLMNR and mDNS are off because the resolver speaks plain DNS on the mesh only. These settings hold for every name the link resolves, so the forward zones, and with a catch-all every name the host resolves through the link, are resolved without DNSSEC validation and without DNS over TLS. A failure in steps 2 to 7 is followed by one `RevertLink`, whose result is ignored, so the next `Apply` starts from a clean link.

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

### The Catch-All as Default Route

A catch-all sets both the default-route flag and the routing domain `~.`, because the flag alone does not make the link the only one asked. Measured on 2026-11-10 with systemd-resolved 255.4, on a link whose server is `10.99.0.1:5354`:

- `~.` sends every name that no other link's domain matches to this link only. Neither a second link with its own DNS server and `DefaultRoute` on nor a global DNS server sees the query. `SetLinkDefaultRoute(true)` without `~.` does not do that: both links are asked.
- A `SERVFAIL` from the link's server, or a port nothing listens on, fails the lookup at once. systemd-resolved does not fall back to another server.
- A name under a domain another link holds, such as a search domain the DHCP client of `eth0` set, still goes to that link.
- A routing domain such as `~corp.local` or `~2.0.192.in-addr.arpa` sends its names to the link's server, as `~lab.internal` does.

The catch-all therefore has these limits:

- It takes only the names no other link claims. A name under another link's domain, a DHCP search domain included, goes to that link and not to the catch-all resolvers.
- Another link that also holds `~.`, such as one a VPN client set up, shares the default route with the mesh interface, so the names no domain matches go to both links.
- A catch-all whose resolvers do not answer fails every lookup that the catch-all takes, because systemd-resolved does not fall back, as a forward zone whose resolvers do not answer fails the lookups of its names. plexd answers each query of such a lookup with `SERVFAIL`, and systemd-resolved asks three times before it gives up. Under resolvers that send nothing back, each round waits the 4 seconds, so the lookup fails after about 12 seconds; resolvers that refuse the query fail it at once (see [Asking the Resolvers](#asking-the-resolvers)). The mesh names keep answering. plexd keeps reaching its control plane through the last address of its name (see [Dial Fallback](../core/control-plane-client.md#dial-fallback)), so the pull that corrects the setting still arrives.
- A program that does not resolve through systemd-resolved never asks plexd, for example one that reads an `/etc/resolv.conf` naming other servers, or a container with a resolver configuration of its own.

### plexd Owns the Link

plexd owns the per-link resolver settings of its mesh interface. Each `Apply` replaces the link's default-route flag, domains, DNSSEC, DNS over TLS, LLMNR and mDNS settings and its DNS servers. `RevertLink` clears all of them, including any an operator set there by hand. plexd does not read the link back: a setting changed by hand after a registration stays until the registration changes, the next start applies it again or reverts the link, or a stop reverts it. Set nothing by hand on that link.

## Registration on macOS

`NewScutilRegistrar(logger *slog.Logger) *ScutilRegistrar` (`scutil_darwin.go`) is the `Registrar` on macOS. It writes DNS entries into configd's SystemConfiguration dynamic store with `/usr/sbin/scutil`, which reads each script on its stdin, and mDNSResponder takes its per-domain resolvers from that store. `Name` returns `configd`, the daemon that owns the dynamic store and hands mDNSResponder its DNS configuration. Release builds set `CGO_ENABLED=0`, which rules out the SystemConfiguration framework, so plexd drives the store through `scutil`, as it drives `ifconfig`, `route` and `pfctl` on macOS. The logic sits in `scutil.go`, which has no build tag, so its unit tests run on every platform. Only `scutil_darwin.go`, which runs the tools, is built for macOS alone. The registrar runs nothing until the first `Apply` or `Revert`. It needs root, which plexd on macOS has already for its utun.

Every entry names `127.0.0.1` and `dns.listen_port`, where the resolver listens on macOS, and is bound to no interface (see [Listen Address](#listen-address)). The entries live in configd's memory, so a reboot clears whatever a killed run left behind, and so does the next start of plexd (see [Startup in plexd up](#startup-in-plexd-up)). plexd writes no file under `/etc/resolver`: such a file survives a reboot and cannot express a default resolver.

### The Keys

| Key | Written when | Lines after the server's two |
|-----|--------------|------------------------------|
| `State:/Network/Service/plexd-meshdns-search/DNS` | The registration has a search domain | `d.add SupplementalMatchDomains * <search domain>`, `d.add SupplementalMatchDomainsNoSearch # 0` |
| `State:/Network/Service/plexd-meshdns-match-<i>/DNS` | The registration has routing domains. One key per batch, with `i` counting from 0 | `d.add SupplementalMatchDomains * <its domains, space-separated>`, `d.add SupplementalMatchDomainsNoSearch # 1` |
| `State:/Network/Service/plexd-meshdns-default/DNS` | `DefaultRoute` is set, so the forwarding has an accepted catch-all resolver | `d.add SupplementalMatchDomains * ""`, `d.add SearchOrder # 100000` |

Every key starts with the server's two lines, `d.add ServerAddresses * <listen address>` and `d.add ServerPort # <dns.listen_port>`, which on macOS read `d.add ServerAddresses * 127.0.0.1` and `d.add ServerPort # 5354` by default. The registrar writes whatever address the registration names: an IPv6 address as it is, such as `d.add ServerAddresses * fd00::1`, and an IPv4-mapped one as the IPv4 address it carries.

`SupplementalMatchDomains` sends the names under the entry's domains to its server. `SupplementalMatchDomainsNoSearch` `0` also puts the search domain on the host's search list, so a bare host name of the Node's own Project resolves through it, and `1` keeps the routing domains off that list, as the routing-only domains of systemd-resolved do on Linux. An empty match domain with `SearchOrder` 100000 makes a default resolver, which answers the names no other entry's domain matches and is ordered ahead of the primary network service's resolver (see [The Catch-All as Default Resolver](#the-catch-all-as-default-resolver)). The search and match entries follow NetBird's macOS DNS configurator, and the default entry follows Tailscale's.

The routing domains fill the match keys in order. A key holds at most 50 domains (`maxDomainsPerKey`) and at most 1500 bytes of domain text (`maxDomainBytesPerKey`), counting the domains' lengths and one space between each two, and a domain that would take the key over either limit starts the next key. 120 routing domains of 10 bytes each therefore go into `match-0` and `match-1` with 50 each and into `match-2` with 20, and 10 routing domains of 200 bytes each go into two keys of 7 and 3. The limits leave the margin NetBird's configurator leaves under scutil's cap of 99 values per `d.add` and its value buffer of about 2048 bytes.

### Apply and Revert

`Apply` runs these steps:

1. Every domain of the registration, the search domain and the routing domains, must match `^[a-z0-9_.-]{1,253}$`. Any other domain returns `meshdns: scutil: domain "<d>" cannot be written to the dynamic store` before scutil runs. The domains come from the control plane and land in a script that root runs, so a newline in one would add a command of its own. `BuildRecords` and `BuildForwarding` refuse such names already, so only a test reaches this check.
2. It lists the plexd keys with the script `open`, `list State:/Network/Service/plexd-meshdns-.*/DNS`, `quit`. scutil prints one `subKey [i] = <key>` line per key, or `no subKey(s).` when none matches. A line that contains ` = ` yields the text after its last ` = `, trimmed, and that text counts when it matches `^State:/Network/Service/plexd-meshdns-[a-z0-9-]+/DNS$`. Every other line is ignored.
3. It runs one script: `open`, a `remove <key>` for every listed key the registration does not write, then the search key, the match keys in order and the default key last, each as `d.init`, its `d.add` lines and `set <key>`, then `quit`. A listed key that the registration writes again is not removed first: its `set` replaces it.
4. After that script succeeded, it flushes the DNS cache (see [The Cache Flush](#the-cache-flush)).

Stale keys go first and the default key goes last. A catch-all that ends therefore stops taking every name before anything else changes, and one that starts takes them only after the zones are in place. For the registration of the [mock control plane's](../development/mock-api-server.md#get-v1-nodes-id-state) block, with the server `127.0.0.1:5354`, the search domain `app.e2e.internal` and the routing domains `e2e.internal` and `0.99.10.in-addr.arpa`, with a catch-all, and with `State:/Network/Service/plexd-meshdns-match-1/DNS` listed from an earlier registration, the script is:

```text
open
remove State:/Network/Service/plexd-meshdns-match-1/DNS
d.init
d.add ServerAddresses * 127.0.0.1
d.add ServerPort # 5354
d.add SupplementalMatchDomains * app.e2e.internal
d.add SupplementalMatchDomainsNoSearch # 0
set State:/Network/Service/plexd-meshdns-search/DNS
d.init
d.add ServerAddresses * 127.0.0.1
d.add ServerPort # 5354
d.add SupplementalMatchDomains * e2e.internal 0.99.10.in-addr.arpa
d.add SupplementalMatchDomainsNoSearch # 1
set State:/Network/Service/plexd-meshdns-match-0/DNS
d.init
d.add ServerAddresses * 127.0.0.1
d.add ServerPort # 5354
d.add SupplementalMatchDomains * ""
d.add SearchOrder # 100000
set State:/Network/Service/plexd-meshdns-default/DNS
quit
```

A registration that writes no key only removes the listed keys. The manager calls `Revert` for such a registration instead, so only a test reaches that case. An `Apply` costs two scutil runs and the flush, and the manager calls it only when the registration changed or the previous call failed (see [Following the State Pull](#following-the-state-pull)), so a Mac whose zones do not change runs scutil only on its first pull that registers.

scutil exits 0 when one of its commands fails, so plexd reads the output of every script that changes the store. A line that is neither empty nor `No such key`, which a `remove` of a key that is already gone prints, counts as a failure. A failed `apply` script is followed by one revert, a list and, when it names a key, a script that removes every listed key, and by no flush. An error of that revert logs `revert after a failed registration failed` at Debug with `interface` and `error`, and `Apply` returns the script's error either way. When the call has a deadline, as the manager's 5 seconds are, the list and the `apply` script end a fifth of the time left early, and the revert runs under the call's own deadline, as on Linux: scutil cannot be started once a context is done, so a script that ran out the whole time would leave the revert none.

`Revert(ctx, iface)` lists the keys as in step 2. With none listed it returns `nil` without another scutil run and without a flush. Otherwise it runs `open`, a `remove <key>` for each listed key and `quit`, then flushes the cache. It does not use `iface`. The keys do not name the interface, because the kernel picks a new `utunN` on every start (see [The utunN name](./wireguard.md#the-utunn-name)), so a revert also finds what a run on another `utunN` wrote, a killed run's keys included. A missing scutil means there is nothing to remove, and `Revert` returns `nil`.

### The Cache Flush

After the `apply` script of `Apply` succeeded, and after the remove script of a `Revert` succeeded, the registrar flushes the macOS DNS cache: it runs `/usr/bin/dscacheutil -flushcache`, then `/usr/bin/killall -HUP mDNSResponder`, which is Apple's documented flush and the one NetBird runs. mDNSResponder keeps one cache for the whole host. Without the flush, a negative answer that the host's own servers gave for a mesh name before plexd registered would outlive the registration. On Linux a new link scope starts with an empty cache, and plexd flushes nothing there. A failed flush logs `mesh dns cache flush failed` at Debug with `error` and changes nothing else: the registration is in place, and a stale answer goes with its TTL. No flush follows a failed `apply` script, nor the removal that follows it.

plexd flushes only when it changes the registration, not when a pull changes only hosts, records or resolvers. mDNSResponder then serves a changed name or record from its cache for up to the TTL of 10 seconds, as systemd-resolved does on Linux.

### scutil Errors

Every scutil run maps its outcome to an error, where `<op>` is `list`, `apply` or `revert`. The rows apply in this order:

| Outcome of the run | `Apply` returns | `Revert` returns |
|--------------------|-----------------|------------------|
| scutil is missing: the run fails with an error that is `fs.ErrNotExist` or `exec.ErrNotFound` | `meshdns: scutil: /usr/sbin/scutil is missing: meshdns: no usable system resolver`, which wraps `ErrUnavailable` | `nil` |
| Any other error while the context is done | `meshdns: scutil: <op>: <context error>`, such as `meshdns: scutil: list: context deadline exceeded` | The same |
| Any other error, such as `exit status 1` | `meshdns: scutil: <op>: <error>: <output>`, with the output's lines trimmed and joined by `; `, and without `: <output>` when scutil printed nothing | The same |
| No error, but the output of an `apply` or `revert` script has a line that is neither empty nor `No such key` | `meshdns: scutil: <op>: <output>`, with the output's lines trimmed and joined by `; ` | The same |

A domain outside `^[a-z0-9_.-]{1,253}$` makes `Apply` return `meshdns: scutil: domain "<d>" cannot be written to the dynamic store` before any run. On macOS `ErrUnavailable` therefore means that `/usr/sbin/scutil` is missing. The manager logs it once at Info as `mesh dns not registered, configd is not usable`, and the resolver keeps answering on its listen address. A `Revert` on such a host returns `nil`, so a stop reports no failure.

The registrar logs these at Debug, with `component=meshdns`:

| Message | Keys |
|---------|------|
| `scutil not usable` | `op`, `error`. scutil is missing, in `Apply` and in `Revert` alike |
| `mesh dns cache flush failed` | `error`, which reads `dscacheutil -flushcache: <cause>` or `killall -HUP mDNSResponder: <cause>` |
| `revert after a failed registration failed` | `interface`, `error`. The revert after a failed `apply` script failed. The Linux registrar logs the same text |

### Seeing the Entries

`scutil --dns` prints the resolver configuration mDNSResponder uses. While plexd is registered, it lists a resolver for each domain of plexd's entries, with the domain as `domain`, `127.0.0.1` as `nameserver[0]`, and a `port` line naming `dns.listen_port` when the port is not 53. The search domain also appears as a `search domain` of the primary resolver. After a revert none of plexd's domains appears any more. The keys themselves are listed by the script of step 2, and `show <key>` in `sudo scutil` prints what one key holds:

```sh
printf 'open\nlist State:/Network/Service/plexd-meshdns-.*/DNS\nquit\n' | sudo scutil
```

To resolve a name through the system resolver, as a program on the Mac does, use `dscacheutil -q host -a name <name>`, or `dscacheutil -q host -a ip_address <address>` for a reverse lookup. `dig` and `nslookup` read `/etc/resolv.conf` and never reach a supplemental entry, so they do not resolve the mesh names through plexd.

### plexd Owns Its Keys

plexd owns every key under `State:/Network/Service/plexd-meshdns-`. It counts a listed key as its own when the key matches `^State:/Network/Service/plexd-meshdns-[a-z0-9-]+/DNS$`. Each `Apply` removes those its registration does not write and replaces the others, and `Revert` removes all of them, whichever run wrote them, including a key an operator wrote there by hand. One plexd runs per Mac. plexd never touches the key of another program, such as `State:/Network/Service/NetBird-Match-0/DNS`, nor a key under the prefix that is not a DNS key, such as `State:/Network/Service/plexd-meshdns-match-0/IPv4`. Write nothing by hand under that prefix.

To remove the keys without plexd, for example after a kill when no start follows, run `sudo scutil` with `remove <key>` for each key the list above names, as `Revert` does. A reboot clears them as well.

### The Catch-All as Default Resolver

A catch-all writes plexd's own default-resolver entry, `State:/Network/Service/plexd-meshdns-default/DNS`, with an empty match domain and `SearchOrder` 100000, which orders it ahead of the primary network service's resolver. plexd does not change the primary service's DNS, so removing the entry leaves the host's resolver configuration as it was. The catch-all on macOS has these limits:

- macOS keeps the primary network service's resolver as a second default resolver. Whether mDNSResponder ever asks that resolver for a name the catch-all should take, for example after plexd answers `SERVFAIL` for a catch-all whose resolvers do not answer, was not measured. A catch-all on macOS therefore does not guarantee that the catch-all resolvers see every name.
- It takes only the names no other entry's domain matches. A name under a domain another entry holds, such as one a VPN client registered, goes to that entry's servers and not to the catch-all resolvers.
- A catch-all whose resolvers do not answer makes plexd answer `SERVFAIL` for every name the default entry takes, after at most 4 seconds (see [Asking the Resolvers](#asking-the-resolvers)). The mesh names keep answering, and plexd keeps reaching its control plane through the last address of its name (see [Dial Fallback](../core/control-plane-client.md#dial-fallback)), so the pull that corrects the setting still arrives.
- A program that does not resolve through mDNSResponder never asks plexd, for example `dig` and `nslookup` (see [Seeing the Entries](#seeing-the-entries)).

## Following the State Pull

`Manager` ties the records, the forwarding table, the server and the registrar together. Every line it and its server log carries `component=meshdns`.

```go
func NewManager(cfg Config, iface string, listenIP netip.Addr, registrar Registrar, logger *slog.Logger) *Manager
func (m *Manager) Start() error
func (m *Manager) Addr() netip.AddrPort
func (m *Manager) Run(ctx context.Context) error
func (m *Manager) Handle(ctx context.Context, desired *api.NodeStateSnapshot)
func (m *Manager) Shutdown(ctx context.Context) error
```

`Start` binds the sockets on `listenIP` and `cfg.ListenPort`, where `plexd up` passes the mesh IP on Linux and `127.0.0.1` on macOS (see [Listen Address](#listen-address)), and `Run` serves them until its context ends. `Addr` is the listen address the log lines name. `Handle` has the signature of a [dispatch handler](../core/reconciliation.md#dispatchhandler) and runs on every successful pull, drift or not. A mutex guards the state `Handle` and `Shutdown` share.

1. A nil snapshot returns at once.
2. A snapshot without a `dns` block, the wire's `null` or a pull from a control plane that predates the block, keeps the names, the forwarding and the registration. The first such pull logs `state pull carries no dns block, keeping the names held`. Later ones log nothing until a block arrived in between.
3. A block is built into records, which the server takes with an atomic swap, so a pull never blocks a query.
4. A block that carries the `forwarding` member replaces the member the manager keeps, as a copy. A block without it, or with `null`, keeps the member held. When one is held, the first such block logs `dns block carries no forwarding member, keeping the forwarding held`, and later ones log nothing until a member arrived in between. The kept member is built with `BuildForwarding` against the records of this pull and the listen address, and the server takes the table with an atomic swap, which also drops the down marks of the resolvers the table no longer names. Without a kept member the table is nil and forwards nothing. Because the kept member is built anew on every pull, a forward zone that a new mesh zone shadows goes with the pull that brings the mesh zone, and comes back with the pull that removes it.
5. Skipped entries log `mesh dns skipped invalid entries` with the count and the first five sentences, those of `BuildRecords` before those of `BuildForwarding`, on every pull that carries them. Records that differ from the previous ones log `mesh dns records updated`, and the first block always counts as a change. A table that differs from the previous one by `Equal` logs `mesh dns forwarding updated`. A nil table equals an empty one, so a Node that never forwards logs nothing.
6. The wanted registration, built from the records and the table, is compared with the one the system resolver accepted last. When they are equal, nothing is called, so a pull that changes only hosts, records or resolvers issues no bus call on Linux and runs no scutil on macOS, as long as the accepted forward zones stay the same and an accepted catch-all resolver neither appears nor goes. When the wanted registration is empty, `Revert` is called, bounded by 5 seconds, if this run called `Apply` since its last successful revert, whether that `Apply` succeeded or failed. Otherwise `Apply` is called, bounded by 5 seconds.
7. After a failed `Apply` nothing counts as applied, so the next pull calls `Apply` again, while the server already forwards with the new table. A systemd-resolved that starts later, or a link that frees up, is picked up within one reconcile interval. On a host without a usable systemd-resolved each retry costs at most one bus call, the read of `DNSEx`, and changes nothing. On a Mac without `/usr/sbin/scutil` each retry costs one attempt to run it and changes nothing. A failed `Apply` can leave settings on the link, the earlier registration's or those of the steps that succeeded, or on macOS keys in the dynamic store, so an empty registration on a later pull still reverts it. A failed revert counts as nothing reverted, so the next pull whose registration is empty reverts again.

A pull whose context is already done, because plexd is stopping, still swaps the records and the table but calls no registrar method. The drain's revert is the last word on the link.

`NewManager` builds the two log lines that name the system resolver once, from the registrar's `Name`, so the registrar must not be nil. A successful `Apply` logs `mesh dns registered with systemd-resolved` on Linux and `mesh dns registered with configd` on macOS, whose `default_route` key says whether a catch-all made the link the host's default DNS route, or on macOS wrote the default-resolver entry. A revert from `Handle` logs nothing when it succeeds. An error wrapping `ErrUnavailable` logs `mesh dns not registered, systemd-resolved is not usable` on Linux and `mesh dns not registered, configd is not usable` on macOS at Info, once per change into that state: a success or another failure in between makes it log again. Any other error, from `Apply` or from the revert, logs `mesh dns registration failed` at Warn, unless its text is the one this line logged last. A success or an unavailable answer in between makes the same text log again.

A resolver failure never changes readiness. The health endpoints do not report the resolver, and the log lines are the operator's view of it.

## Every Zone on Every Node

The block lists every zone of the Domain: its default domain and the zone of every Project. Every Node of the Domain answers and registers all of them, not only its own Project's. A Project whose zone is overridden to a name such as `edge.example.com` therefore takes that zone on this Node. The host sends every name under `edge.example.com` to plexd, which answers the mesh hosts and the records there and `NXDOMAIN` for any other name, so the host no longer resolves the rest of that zone through its own DNS servers.

The block also carries the records of the Domain and of every Project, and every Node answers all of them. A record a Project defines therefore resolves on every Node of the Domain, not only on the Nodes of that Project.

The forwarding member is different: it carries one setting, the one that applies to this Node, which is its Project's when the Project holds one and its Domain's otherwise. A forward zone and a catch-all therefore apply to the Nodes of one Project only when that Project sets them, and to every Node of the Domain whose Project sets nothing when the Domain sets them. Whoever manages the Domain or the Project chooses the resolvers, and with them where the Node's queries for the forward zones go. With a catch-all they also choose where every name goes that the host resolves through the system resolver and that no other domain of the host's resolver configuration matches. On Linux those names are resolved without DNSSEC validation and without DNS over TLS (see [ResolvedRegistrar](#resolvedregistrar)). On macOS, whether the primary network service's resolver ever sees one of them was not measured (see [The Catch-All as Default Resolver](#the-catch-all-as-default-resolver)).

`dns.enabled: false` is the Node operator's way out. It turns the resolver, the forwarding and the registration off on this Node, and plexd reverts the link at start. No key turns the forwarding off on its own.

## Startup in plexd up

`plexd up` sets the resolver up right after the WireGuard interface. It checks these conditions in this order:

| Condition | What happens |
|-----------|--------------|
| The platform has no registrar (Windows, any platform but Linux and macOS) | Nothing, and no log line |
| `dns.enabled: false` | Logs `mesh dns disabled by dns.enabled`, then reverts the mesh interface's link within 5 seconds. A failed revert logs `mesh dns revert failed` |
| The WireGuard interface did not come up | Logs `wireguard unavailable, mesh dns not started`, then reverts the link the same way |
| The mesh IP does not parse | Logs `mesh dns not started, the mesh ip does not parse`, then reverts the link the same way |
| A bind fails, or on Linux the mesh IP is unspecified | Logs `mesh dns listener cannot bind, mesh names are not answered` with the hint `set dns.listen_port to a free port`, reverts the link the same way, and goes on without the resolver |
| Both binds succeed | On macOS, reverts first the same way, which removes whatever keys a killed run left. Then logs `mesh dns listening` with the listen address |

Every start that runs no resolver reverts the link, whatever the reason, and a start whose resolver listens applies on the first pull. A registration a killed run left behind would otherwise keep sending the mesh zones and the forward zones, and with a catch-all every other name, to a port nothing listens on: on Linux a kill leaves `plexd0` behind, and the next start's WireGuard setup fails on it (see [Stop, Crash and Opt-Out](#stop-crash-and-opt-out)). On Linux the revert does nothing when the link does not exist. On macOS the utun goes with the process, but the keys stay in the dynamic store, bound to no interface, and the revert removes them whatever interface it is given. A macOS start whose resolver listens therefore reverts too, before a run that resumed its identity first dials the control plane: with a catch-all, the killed run's default-resolver entry would send the control plane's own name to this run's resolver, which refuses every name until the first pull, so that pull might never arrive. A Linux start whose resolver listens does not revert, because WireGuard has just created its `plexd0`, which holds nothing.

The sockets are bound before the dispatch handler is registered, so a Node that cannot answer never registers a server. Only a resolver that listens gets the dispatch handler, registered after the reachability observer, and a goroutine that serves its sockets. `Run` returns once plexd stops. Only a failed UDP read, or a TCP listener that something other than the stop closed, ends it before that. plexd then logs `mesh dns stopped`, and no mesh name is answered and nothing is forwarded for the rest of the run. It shuts the manager down at once, with a fresh context bounded by 5 seconds, as the drain does: `Shutdown` reverts the link and logs `mesh dns registration reverted`, or `mesh dns shutdown error` when the revert fails, and every later pull registers nothing. Otherwise the registration would keep sending the zones, and with a catch-all every other name, to a port nothing answers on for the rest of the run. A failed accept is retried and stops nothing (see [TCP](#tcp)). Nothing here stops startup: the mesh works without names.

## Stop, Crash and Opt-Out

On macOS, the link in this table stands for plexd's keys in configd's dynamic store, and a revert removes every one of them (see [Registration on macOS](#registration-on-macos)).

| Event | What plexd does | What the link holds afterwards |
|-------|-----------------|--------------------------------|
| A stop of a run whose resolver listens, such as `systemctl stop plexd` | The drain calls `Shutdown` first, right after `shutting down` and before any other subsystem stops, with a fresh context bounded by 5 seconds. It goes first because the resolver stopped answering when the stop began. The interface still exists then, because WireGuard is torn down last. `Shutdown` reverts the link on every run, registered or not, and logs `mesh dns registration reverted`. An error logs `mesh dns shutdown error` | Nothing plexd set |
| A stop of a run that runs no resolver | Nothing for mesh DNS: the start reverted the link already | Nothing plexd set |
| The resolver stops while plexd runs, which logs `mesh dns stopped` | `Shutdown` right away, with a fresh context bounded by 5 seconds: it reverts the link, logs `mesh dns registration reverted` or `mesh dns shutdown error`, and stops every later `Handle`. The drain's `Shutdown` still runs at the stop, reverts again and logs `mesh dns registration reverted` again | Nothing plexd set |
| A crash or a kill on Linux | No drain runs, so `plexd0` stays, and so does its registration | The last registration, until the next start reverts it. Without a catch-all the link's default-route flag stays off, so only the mesh zones and the forward zones go to the mesh IP, where nothing answers. With a catch-all the link keeps `~.` and the flag, so every lookup through systemd-resolved that no other link's domain matches fails as well, until the next start reverts the link |
| A crash or a kill on macOS | No drain runs. The utun goes with the process, but the keys stay in the dynamic store, bound to no interface | The last registration's keys, until the next start removes them or a reboot clears the dynamic store. The mesh zones and the forward zones go to `127.0.0.1`, where nothing answers. With a catch-all, every name the default entry takes fails meanwhile as well |
| The next start after a crash or a kill on Linux | WireGuard setup fails on the leftover `plexd0` (`EEXIST`), so the run logs `wireguard unavailable, mesh dns not started`, starts no resolver and reverts the link at start. The drain of that run deletes the leftover `plexd0`, so the start after it creates a fresh one | Nothing plexd set |
| The next start after a crash or a kill on macOS | WireGuard creates a fresh utun. Whether the resolver listens again or not, the start removes every key the killed run left, a start whose resolver listens before it first dials the control plane | Nothing plexd set, until the first pull applies its registration |
| A start whose resolver listens | WireGuard has just created the mesh interface, so the link holds no settings; on macOS the start removed whatever keys a killed run left (see the row above). The first pull whose block names an accepted zone, reverse zone or forward zone, or an accepted catch-all resolver, applies its registration | The new registration |
| A start with `dns.enabled: false`, without WireGuard, with a mesh IP that does not parse, or with a listener that cannot bind | Starts no resolver and reverts the link at start | Nothing plexd set |

To turn the resolver off, set `dns.enabled: false` in the config file, or set `PLEXD_DNS_ENABLED=false`, for example in `/etc/plexd/environment` under the shipped `plexd.service`, and restart plexd. plexd reads the setting once, when it starts.

## Hosts without systemd-resolved

On a Linux host without systemd-resolved, with one older than 246, or without a reachable system bus, the resolver still runs and answers on its listen address. plexd sets no DNS setting of the host: on an older systemd-resolved the read of `DNSEx` fails before the first setter. Only `RevertLink` reaches an older one: at a stop, at a start that runs no resolver, and on a pull whose registration is empty. It clears whatever the mesh interface's link holds. plexd names the address in `mesh dns listening` when it binds, and again in `mesh dns not registered, systemd-resolved is not usable` on the first pull whose block names an accepted zone, reverse zone or forward zone, or an accepted catch-all resolver:

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

plexd forwards on its listen address on such a host too, so the same resolver can carry the forwarding setting. For the forward zone `corp.example.com`, and for a catch-all:

```text
server=/corp.example.com/10.99.0.1#5354
server=10.99.0.1#5354
```

The first line sends every name under `corp.example.com` to plexd, which passes it on to the zone's resolvers. The second makes plexd an upstream server for every other name, which plexd passes on to the catch-all resolvers. plexd answers `REFUSED` for a name outside the mesh zones that its forwarding table does not route, so point a line at it only for what the setting covers.

- The resolver answers the Node itself only. dnsmasq on the Node sends its queries to the Node's own mesh IP, and the kernel sends a packet for a local address from that address, so the [source rule](#source-rule) accepts them. A resolver in a Pod or container network sends from an address of its own, so the resolver drops its queries, and it cannot use the names this way.
- The zone list of such a hand-written rule follows the Domain's zones by hand. When the Domain gains a zone that the lines do not cover, such as a Project's zone override, or its mesh CIDR changes, change the lines yourself: nothing updates them. The same holds for the forward zones and the catch-all.
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
| `Error` | `mesh dns stopped` | `error`. The resolver stopped while plexd was running. plexd reverts the link right after it |
| `Error` | `mesh dns shutdown error` | `error`. The revert after `mesh dns stopped`, or the drain's revert, failed |

The control-plane client logs these without a `component` key when the control plane's name stops resolving, as it does on a Node whose catch-all resolvers do not answer (see [Dial Fallback](../core/control-plane-client.md#dial-fallback)):

| Level  | Message | Keys |
|--------|---------|------|
| `Warn` | `control plane name does not resolve, dialing its last address` | `host`, `address` (the last address with the request's port), `error`. Once, and again only after the name resolved in between |
| `Info` | `control plane name resolves again` | `host`. The first ordinary dial that succeeds after the line above |

The manager, and the server for the forward resolvers, log these with `component=meshdns`:

| Level  | Message | Keys |
|--------|---------|------|
| `Info` | `state pull carries no dns block, keeping the names held` | none. Once, and again only after a block arrived in between |
| `Warn` | `mesh dns skipped invalid entries` | `count`, `skipped` (the first five sentences). On every pull whose block has skipped entries |
| `Info` | `dns block carries no forwarding member, keeping the forwarding held` | none. Once while a member is held, and again only after a member arrived in between |
| `Info` | `mesh dns records updated` | `hosts`, `records` (the number of accepted records), `zones`, `reverse_zones`, `search_domain` (empty when the Node has none) |
| `Info` | `mesh dns forwarding updated` | `forward_zones` (the number of accepted forward zones), `catch_all` (the number of accepted catch-all resolvers). On every pull whose table differs from the previous one |
| `Info` | `mesh dns registered with systemd-resolved` on Linux, `mesh dns registered with configd` on macOS | `interface` (on macOS the `utunN`, which the entries are not bound to), `server`, `search_domain`, `routing_domains` (the count, the forward zones included), `default_route` (`true` with a catch-all) |
| `Info` | `mesh dns not registered, systemd-resolved is not usable` on Linux, `mesh dns not registered, configd is not usable` on macOS | `listen`, `reason`. Once per change into that state |
| `Warn` | `mesh dns registration failed` | `error`. Once per distinct error text |
| `Info` | `mesh dns registration reverted` | `interface`. The drain's revert, or the revert after `mesh dns stopped`, returned no error. It also logs where there was nothing to revert, such as on a host without systemd-resolved or a system bus |
| `Warn` | `mesh dns resolver does not answer` | `resolver`, `zone` (the forward zone, or `.` for the catch-all), `error` (`context deadline exceeded`, or the socket error, such as a refused connection). Once when a resolver gets a down mark, and not again while it stays down |
| `Info` | `mesh dns resolver answers again` | `resolver`. Once when a marked resolver gives a matching reply |

The server and the registrar log these at Debug, with `component=meshdns`:

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
| `mesh dns forwarded query failed` | `name` (as the question spells it, with the trailing dot), `type`, `zone`, `error`. No resolver answered, and the query gets `SERVFAIL` |
| `mesh dns dropped a forwarded query, too many are in flight` | `limit`: `256` when the forwarded queries in flight over UDP and TCP together are at their cap, `16` when the query's TCP connection already holds that many forwarded queries whose replies are not written yet. The query gets `SERVFAIL` |
| `system bus unreachable` | `error`. Linux |
| `systemd-resolved not usable` | `method`, or `property` (`DNSEx`) for the read before step 1; `error`. Linux |
| `scutil not usable` | `op` (`list`, `apply` or `revert`), `error`. macOS, when `/usr/sbin/scutil` is missing |
| `mesh dns cache flush failed` | `error`. macOS, when the flush after a change of the registration failed (see [The Cache Flush](#the-cache-flush)) |
| `revert after a failed registration failed` | `interface`, `error`. Linux and macOS |

A registered Node logs, for the [mock control plane's](../development/mock-api-server.md#get-v1-nodes-id-state) block:

```text
level=INFO msg="mesh dns listening" listen=10.99.0.1:5354
level=INFO msg="mesh dns records updated" component=meshdns hosts=3 records=8 zones=2 reverse_zones=1 search_domain=app.e2e.internal
level=INFO msg="mesh dns registered with systemd-resolved" component=meshdns interface=plexd0 server=10.99.0.1:5354 search_domain=app.e2e.internal routing_domains=2 default_route=false
```

The block's `forwarding` member holds two empty lists, so no `mesh dns forwarding updated` line follows. The same Node after a pull that adds the forward zone `corp.example.com` with a resolver that does not answer, and a catch-all:

```text
level=INFO msg="mesh dns forwarding updated" component=meshdns forward_zones=1 catch_all=1
level=INFO msg="mesh dns registered with systemd-resolved" component=meshdns interface=plexd0 server=10.99.0.1:5354 search_domain=app.e2e.internal routing_domains=3 default_route=true
level=WARN msg="mesh dns resolver does not answer" component=meshdns resolver=192.0.2.1 zone=corp.example.com error="context deadline exceeded"
```

A macOS Node logs the same lines, except that it listens on `127.0.0.1` (`mesh dns listening` says `listen=127.0.0.1:5354`) and the two registration lines name configd, the `utunN` the kernel picked, such as `utun4`, and that server:

```text
level=INFO msg="mesh dns registered with configd" component=meshdns interface=utun4 server=127.0.0.1:5354 search_domain=app.e2e.internal routing_domains=2 default_route=false
level=INFO msg="mesh dns registered with configd" component=meshdns interface=utun4 server=127.0.0.1:5354 search_domain=app.e2e.internal routing_domains=3 default_route=true
```

See [A mesh name does not resolve](../../guide/troubleshooting.md#a-mesh-name-does-not-resolve) for how to read them on a Node.
