#!/bin/sh
# The round-trip probe responder for phase 12e of the Docker suite. plexd
# sends a 16-byte request to UDP port 7911 of each peer it has a fresh
# handshake with: the magic PXRT, version 1, kind 1, two zero bytes and an
# 8-byte nonce. The phase starts the responder in meshpeer as
#
#   socat UDP4-RECVFROM:7911,bind=<mesh ip>,fork EXEC:/usr/local/bin/rtt-echo.sh
#
# socat forks a child for each datagram that arrives and runs this script with
# the datagram on stdin, and it sends what the script writes back to the
# datagram's source address and port. The script copies the magic and the
# version, writes 2, the kind of a reply, in place of the request's kind, and
# copies the rest, so plexd reads back its own request as a reply with its
# nonce unchanged.
#
# socat sends each read from the script's output as a datagram of its own, and
# dd bs=1 writes byte by byte. Without the last dd the reply would leave as
# three or four datagrams of 1 to 10 bytes, and plexd drops every datagram that
# is not 16 bytes long. dd obs=16 collects the reply and writes its 16 bytes at
# once.
{
    dd bs=1 count=5 2>/dev/null
    dd bs=1 count=1 of=/dev/null 2>/dev/null
    printf '\002'
    cat
} | dd obs=16 2>/dev/null
