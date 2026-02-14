package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

// directTCPIPPayload represents the SSH direct-tcpip channel extra data
// as defined in RFC 4254 section 7.2.
type directTCPIPPayload struct {
	DestHost   string
	DestPort   uint32
	OriginHost string
	OriginPort uint32
}

// handleDirectTCPIP handles an incoming direct-tcpip channel request by dialing
// the requested destination and forwarding data bidirectionally.
func handleDirectTCPIP(ctx context.Context, newChannel ssh.NewChannel, logger *slog.Logger) {
	var payload directTCPIPPayload
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		if rejectErr := newChannel.Reject(ssh.ConnectionFailed, "failed to parse payload"); rejectErr != nil {
			logger.Error("failed to reject channel", "error", rejectErr)
		}
		logger.Error("failed to parse payload", "error", err)
		return
	}

	destAddr := net.JoinHostPort(payload.DestHost, strconv.Itoa(int(payload.DestPort)))
	originAddr := net.JoinHostPort(payload.OriginHost, strconv.Itoa(int(payload.OriginPort)))

	logger.Info("opening connection",
		"dest", destAddr,
		"origin", originAddr,
	)

	var d net.Dialer
	targetConn, err := d.DialContext(ctx, "tcp", destAddr)
	if err != nil {
		if rejectErr := newChannel.Reject(ssh.ConnectionFailed, "connect failed"); rejectErr != nil {
			logger.Error("failed to reject channel", "error", rejectErr)
		}
		logger.Error("failed to connect",
			"dest", destAddr,
			"error", err,
		)
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		targetConn.Close()
		logger.Error("failed to accept channel", "error", err)
		return
	}
	go ssh.DiscardRequests(requests)

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			channel.Close()
			targetConn.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, channel)
		cleanup()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(channel, targetConn)
		cleanup()
	}()

	wg.Wait()
}
