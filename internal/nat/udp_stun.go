package nat

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"time"
)

// UDPSTUNClient performs STUN binding requests over UDP.
type UDPSTUNClient struct {
	Timeout time.Duration
}

// Bind sends a STUN Binding Request to serverAddr from localPort and returns
// the mapped address from the response.
func (c *UDPSTUNClient) Bind(ctx context.Context, serverAddr string, localPort int) (MappedAddress, error) {
	if err := ctx.Err(); err != nil {
		return MappedAddress{}, fmt.Errorf("nat: udp stun: %w", err)
	}

	remoteAddr, err := net.ResolveUDPAddr("udp4", serverAddr)
	if err != nil {
		return MappedAddress{}, fmt.Errorf("nat: udp stun: resolve: %w", err)
	}

	localAddr := net.UDPAddr{Port: localPort}
	conn, err := net.DialUDP("udp4", &localAddr, remoteAddr)
	if err != nil {
		return MappedAddress{}, fmt.Errorf("nat: udp stun: dial: %w", err)
	}
	defer conn.Close()

	// Use the earlier of Timeout or context deadline.
	deadline := time.Now().Add(c.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return MappedAddress{}, fmt.Errorf("nat: udp stun: set deadline: %w", err)
	}

	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return MappedAddress{}, fmt.Errorf("nat: udp stun: random tx id: %w", err)
	}

	req := buildBindingRequest(txID)
	if _, err := conn.Write(req); err != nil {
		return MappedAddress{}, fmt.Errorf("nat: udp stun: write: %w", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return MappedAddress{}, fmt.Errorf("nat: udp stun: read: %w", err)
	}

	addr, err := parseBindingResponse(buf[:n], txID)
	if err != nil {
		return MappedAddress{}, fmt.Errorf("nat: udp stun: parse: %w", err)
	}

	return addr, nil
}
