#!/bin/sh
# An HTTP target for the request routing step of the systemd suite's public
# ingress phase. socat runs it per connection with the socket on stdin and
# stdout. It reads one request head up to the empty line and answers 200,
# closing the connection, with a text body whose first line is
# target=<first argument>, followed by the request line and every header
# line it read, so a probe can tell which target the bridge chose and what
# the bridge sent it.
cr=$(printf '\r')
nl='
'
head=
while IFS= read -r line; do
    line=${line%"${cr}"}
    if [ -z "${line}" ]; then
        break
    fi
    head="${head}${line}${nl}"
done
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n'
printf 'target=%s\n%s' "$1" "${head}"
