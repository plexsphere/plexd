# syntax=docker/dockerfile:1

# E2E-only WireGuard peer for phase 12e of the Docker suite. It stands in for
# the state fixture's peer 0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2: the phase gives
# its wg0 a key pair of its own and the edge PSK the mock derives for that peer,
# peers it with plexd, and probes plexd's policy enforcement through the tunnel
# with nc. openssl derives the PSK, ss tells when a listener is up. Like the
# plexd container it needs CAP_NET_ADMIN and the host's wireguard module.
FROM alpine:3.22

RUN apk add --no-cache wireguard-tools iproute2 netcat-openbsd openssl

CMD ["sleep", "infinity"]
