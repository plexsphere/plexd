# syntax=docker/dockerfile:1

# E2E-only WireGuard peer for phase 12e of the Docker suite. It stands in for
# the state fixture's peer 0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2: the phase gives
# its wg0 a key pair of its own and the edge PSK the mock derives for that peer,
# peers it with plexd, and probes plexd's policy enforcement through the tunnel
# with nc. openssl derives the PSK, ss tells when a listener is up, and socat
# holds UDP ports 9 and 7911 in step (d1), so the relay and round-trip probes
# plexd sends meet a socket and draw no ICMP answer. rtt-echo.sh is the
# round-trip probe responder: under the phase's empty policy socat runs it for
# each probe plexd sends to port 7911, and it turns plexd's request into the
# reply plexd waits for. Like the plexd container it needs CAP_NET_ADMIN and
# the host's wireguard module.
#
# The systemd suite's public ingress phase runs the same image, without
# CAP_NET_ADMIN, as the ingress rules' target: openssl serves TLS on three
# ports, nc writes a banner, socat echoes UDP datagrams and runs
# http-target.sh for each connection to two HTTP ports, and openssl, nc and
# curl probe the bridge.
FROM alpine:3.22

RUN apk add --no-cache wireguard-tools iproute2 netcat-openbsd openssl socat curl

COPY --chmod=0755 http-target.sh /usr/local/bin/http-target.sh
COPY --chmod=0755 rtt-echo.sh /usr/local/bin/rtt-echo.sh

CMD ["sleep", "infinity"]
