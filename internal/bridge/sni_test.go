package bridge

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"
)

// clientWriteRecorder records every byte a client writes and can split each
// write into chunks of a fixed size, so the peer reads the bytes in pieces.
type clientWriteRecorder struct {
	net.Conn
	chunk int

	mu      sync.Mutex
	written bytes.Buffer
}

func (c *clientWriteRecorder) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.written.Write(p)
	c.mu.Unlock()
	if c.chunk <= 0 {
		return c.Conn.Write(p)
	}
	var n int
	for len(p) > 0 {
		k := min(c.chunk, len(p))
		m, err := c.Conn.Write(p[:k])
		n += m
		if err != nil {
			return n, err
		}
		p = p[k:]
	}
	return n, nil
}

func (c *clientWriteRecorder) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.written.Bytes())
}

// startTLSClient runs a crypto/tls client handshake on its end of a pipe and
// returns the bridge's end, the client's write recorder, and a function that
// closes both ends and waits for the client to give up.
func startTLSClient(t *testing.T, cfg *tls.Config, chunk int) (net.Conn, *clientWriteRecorder, func()) {
	t.Helper()
	bridgeEnd, clientEnd := net.Pipe()
	rec := &clientWriteRecorder{Conn: clientEnd, chunk: chunk}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tls.Client(rec, cfg).Handshake()
	}()
	stop := func() {
		_ = bridgeEnd.Close()
		_ = clientEnd.Close()
		<-done
	}
	t.Cleanup(stop)
	return bridgeEnd, rec, stop
}

func TestPeekClientHello_ServerName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chunk int
	}{
		{name: "whole", chunk: 0},
		{name: "700-byte chunks", chunk: 700},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, rec, stop := startTLSClient(t, &tls.Config{ServerName: "App.Example.com"}, tc.chunk)

			hello, peeked, err := peekClientHello(conn, 2*time.Second)
			if err != nil {
				t.Fatalf("peekClientHello: %v", err)
			}
			if hello.ServerName != "App.Example.com" {
				t.Errorf("server name = %q, want %q", hello.ServerName, "App.Example.com")
			}
			if len(peeked) <= 1024 {
				t.Errorf("peeked %d bytes, want a ClientHello above 1,024 bytes", len(peeked))
			}
			stop()
			if written := rec.bytes(); !bytes.Equal(peeked, written) {
				t.Errorf("peeked %d bytes, want the %d bytes the client wrote", len(peeked), len(written))
			}
		})
	}
}

func TestPeekClientHello_NoSNI(t *testing.T) {
	conn, _, _ := startTLSClient(t, &tls.Config{InsecureSkipVerify: true}, 0)

	hello, peeked, err := peekClientHello(conn, 2*time.Second)
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}
	if hello.ServerName != "" {
		t.Errorf("server name = %q, want empty", hello.ServerName)
	}
	if len(peeked) == 0 {
		t.Error("peeked no bytes")
	}
}

func TestPeekClientHello_ALPN(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offers []string
	}{
		{name: "h2 and http/1.1", offers: []string{"h2", "http/1.1"}},
		{name: "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, _, _ := startTLSClient(t, &tls.Config{ServerName: "app.example.com", NextProtos: tc.offers}, 0)

			hello, _, err := peekClientHello(conn, 2*time.Second)
			if err != nil {
				t.Fatalf("peekClientHello: %v", err)
			}
			if !slices.Equal(hello.ALPN, tc.offers) {
				t.Errorf("ALPN = %q, want %q", hello.ALPN, tc.offers)
			}
			if tc.offers == nil && hello.ALPN != nil {
				t.Errorf("ALPN = %#v, want nil", hello.ALPN)
			}
		})
	}
}

// tcpPair returns the two ends of a loopback TCP connection: the end the
// bridge accepted and the client's end.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	clientEnd, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	bridgeEnd, err := ln.Accept()
	if err != nil {
		_ = clientEnd.Close()
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() {
		_ = bridgeEnd.Close()
		_ = clientEnd.Close()
	})
	return bridgeEnd, clientEnd
}

func TestPeekClientHello_Errors(t *testing.T) {
	t.Run("plain HTTP", func(t *testing.T) {
		bridgeEnd, clientEnd := tcpPair(t)
		go func() { _, _ = clientEnd.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")) }()

		_, _, err := peekClientHello(bridgeEnd, 2*time.Second)
		var rhe tls.RecordHeaderError
		if !errors.As(err, &rhe) {
			t.Fatalf("err = %v (%T), want a tls.RecordHeaderError", err, err)
		}
	})

	t.Run("silent client", func(t *testing.T) {
		bridgeEnd, _ := tcpPair(t)

		start := time.Now()
		_, _, err := peekClientHello(bridgeEnd, 100*time.Millisecond)
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("err = %v (%T), want a net.Error with Timeout()", err, err)
		}
		if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
			t.Errorf("returned after %v, want the 100ms timeout", elapsed)
		}
	})

	t.Run("closed client", func(t *testing.T) {
		bridgeEnd, clientEnd := tcpPair(t)
		_ = clientEnd.Close()

		_, _, err := peekClientHello(bridgeEnd, 2*time.Second)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("err = %v, want io.EOF", err)
		}
	})

	t.Run("oversized handshake", func(t *testing.T) {
		bridgeEnd, clientEnd := tcpPair(t)
		writerDone := make(chan struct{})
		// A ClientHello header announcing 60,000 bytes, then the body in 16 KiB
		// handshake records.
		const helloLen = 60000
		go func() {
			defer close(writerDone)
			body := append([]byte{0x01, byte(helloLen >> 16), byte(helloLen >> 8), byte(helloLen & 0xff)}, make([]byte, helloLen)...)
			for len(body) > 0 {
				k := min(16<<10, len(body))
				record := append([]byte{0x16, 0x03, 0x01, byte(k >> 8), byte(k)}, body[:k]...)
				if _, err := clientEnd.Write(record); err != nil {
					return
				}
				body = body[k:]
			}
		}()

		_, peeked, err := peekClientHello(bridgeEnd, 2*time.Second)
		_ = clientEnd.Close()
		<-writerDone
		if !errors.Is(err, errSNIPeekLimit) {
			t.Fatalf("err = %v, want errSNIPeekLimit", err)
		}
		if len(peeked) >= 4+helloLen {
			t.Errorf("peeked %d bytes, want the peek to stop before the %d-byte message is read", len(peeked), 4+helloLen)
		}
	})
}
