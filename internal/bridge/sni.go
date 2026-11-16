package bridge

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"slices"
	"time"
)

// sniPeekTimeout bounds the wait for a client's TLS ClientHello, so a client
// that connects and stays silent cannot hold the connection open.
const sniPeekTimeout = 5 * time.Second

// sniPeekLimit bounds the bytes read while waiting for a client's TLS
// ClientHello. A Go 1.26 client with its default key shares sends 1,505
// bytes.
const sniPeekLimit = 16 << 10

// errClientHelloPeeked stops the handshake peekClientHello runs once the
// ClientHello is parsed. A handshake error that wraps it is a successful peek.
var errClientHelloPeeked = errors.New("bridge: ingress: client hello peeked")

// errSNIPeekLimit fails a peek whose ClientHello needs more than sniPeekLimit
// bytes.
var errSNIPeekLimit = errors.New("bridge: ingress: client hello exceeds the peek limit")

// clientHello is what the bridge routes a TLS connection by: the server name
// of its ClientHello and the ALPN protocols it offers, in the client's order.
// ALPN is nil when the client offers none.
type clientHello struct {
	ServerName string
	ALPN       []string
}

// peekClientHello reads the client's TLS ClientHello from conn without
// answering it and returns its server name, its ALPN protocols and the bytes
// it read.
//
// crypto/tls parses the hello, so a hello that spans several reads or records
// and a server name behind any other extension are read in full. The bytes
// come back also on an error, and the caller replays them to the target
// through newPeekConn. An empty server name with a nil error is a hello
// without SNI.
func peekClientHello(conn net.Conn, timeout time.Duration) (hello clientHello, peeked []byte, err error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return clientHello{}, nil, err
	}
	rec := &recordingConn{Conn: conn}
	cfg := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = clientHello{ServerName: info.ServerName, ALPN: slices.Clone(info.SupportedProtos)}
			return nil, errClientHelloPeeked
		},
	}
	err = tls.Server(rec, cfg).Handshake()
	if !errors.Is(err, errClientHelloPeeked) {
		if err == nil {
			err = errors.New("bridge: ingress: handshake completed without a client hello")
		}
		return clientHello{}, rec.buf.Bytes(), err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return clientHello{}, rec.buf.Bytes(), err
	}
	return hello, rec.buf.Bytes(), nil
}

// recordingConn records every byte read from the connection and discards
// every write, so the handshake peekClientHello runs never answers the client.
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	if c.buf.Len() > sniPeekLimit {
		return 0, errSNIPeekLimit
	}
	n, err := c.Conn.Read(p)
	c.buf.Write(p[:n])
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	return len(p), nil
}

// peekConn wraps a net.Conn, prepending already-read bytes before the underlying connection.
type peekConn struct {
	net.Conn
	reader io.Reader
}

func newPeekConn(conn net.Conn, peeked []byte) *peekConn {
	return &peekConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(peeked), conn),
	}
}

func (c *peekConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
