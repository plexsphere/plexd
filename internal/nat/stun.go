// Package nat implements STUN-based NAT traversal and endpoint discovery.
package nat

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// STUNClient abstracts STUN binding operations for testability.
type STUNClient interface {
	Bind(ctx context.Context, serverAddr string, localPort int) (MappedAddress, error)
}

// MappedAddress represents a STUN XOR-MAPPED-ADDRESS result.
type MappedAddress struct {
	IP   net.IP
	Port int
}

// String returns the address in "ip:port" format.
func (m MappedAddress) String() string {
	return fmt.Sprintf("%s:%d", m.IP, m.Port)
}

// NATType represents the classified NAT behavior.
type NATType string

const (
	NATNone      NATType = "none"
	NATFullCone  NATType = "full_cone"
	NATSymmetric NATType = "symmetric"
	NATUnknown   NATType = "unknown"
)

// stunMagicCookie is the fixed magic cookie value per RFC 5389.
const stunMagicCookie uint32 = 0x2112A442

// STUN message types.
const (
	stunBindingRequest         uint16 = 0x0001
	stunBindingSuccessResponse uint16 = 0x0101
)

// STUN attribute types.
const (
	stunAttrMappedAddress    uint16 = 0x0001
	stunAttrXORMappedAddress uint16 = 0x0020
)

// STUN address families.
const (
	stunFamilyIPv4 byte = 0x01
)

// buildBindingRequest creates a 20-byte STUN Binding Request.
// Format: type (2) | length (2) | magic cookie (4) | transaction ID (12)
func buildBindingRequest(transactionID [12]byte) []byte {
	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(buf[2:4], 0) // no attributes
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	copy(buf[8:20], transactionID[:])
	return buf
}

// parseBindingResponse parses a STUN Binding Response and extracts the XOR-MAPPED-ADDRESS.
func parseBindingResponse(data []byte, transactionID [12]byte) (MappedAddress, error) {
	if len(data) < 20 {
		return MappedAddress{}, errors.New("nat: stun: response too short")
	}

	msgType := binary.BigEndian.Uint16(data[0:2])
	msgLen := binary.BigEndian.Uint16(data[2:4])
	cookie := binary.BigEndian.Uint32(data[4:8])

	if cookie != stunMagicCookie {
		return MappedAddress{}, fmt.Errorf("nat: stun: invalid magic cookie 0x%08X", cookie)
	}

	var rxTxID [12]byte
	copy(rxTxID[:], data[8:20])
	if rxTxID != transactionID {
		return MappedAddress{}, errors.New("nat: stun: transaction ID mismatch")
	}

	if msgType != stunBindingSuccessResponse {
		return MappedAddress{}, fmt.Errorf("nat: stun: unexpected message type 0x%04X", msgType)
	}

	// Parse attributes.
	attrs := data[20:]
	if int(msgLen) > len(attrs) {
		return MappedAddress{}, errors.New("nat: stun: attributes truncated")
	}
	attrs = attrs[:msgLen]

	var mapped *MappedAddress
	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := binary.BigEndian.Uint16(attrs[2:4])
		if int(attrLen) > len(attrs)-4 {
			break
		}
		attrVal := attrs[4 : 4+attrLen]

		switch attrType {
		case stunAttrXORMappedAddress:
			addr, err := parseXORMappedAddress(attrVal)
			if err != nil {
				return MappedAddress{}, err
			}
			return addr, nil
		case stunAttrMappedAddress:
			addr, err := parseMappedAddress(attrVal)
			if err != nil {
				return MappedAddress{}, err
			}
			mapped = &addr
		}

		// Advance past attribute, padded to 4-byte boundary.
		padded := int(attrLen)
		if padded%4 != 0 {
			padded += 4 - padded%4
		}
		attrs = attrs[4+padded:]
	}

	if mapped != nil {
		return *mapped, nil
	}
	return MappedAddress{}, errors.New("nat: stun: no address attribute found")
}

// parseXORMappedAddress decodes an XOR-MAPPED-ADDRESS attribute value.
func parseXORMappedAddress(val []byte) (MappedAddress, error) {
	// Format: 0x00 (1) | family (1) | xor-port (2) | xor-address (4 for IPv4)
	if len(val) < 8 {
		return MappedAddress{}, errors.New("nat: stun: XOR-MAPPED-ADDRESS too short")
	}

	family := val[1]
	if family != stunFamilyIPv4 {
		return MappedAddress{}, fmt.Errorf("nat: stun: unsupported address family 0x%02X", family)
	}

	xorPort := binary.BigEndian.Uint16(val[2:4])
	port := xorPort ^ uint16(stunMagicCookie>>16)

	cookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cookieBytes, stunMagicCookie)
	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		ip[i] = val[4+i] ^ cookieBytes[i]
	}

	return MappedAddress{IP: ip, Port: int(port)}, nil
}

// parseMappedAddress decodes a MAPPED-ADDRESS attribute value.
func parseMappedAddress(val []byte) (MappedAddress, error) {
	// Format: 0x00 (1) | family (1) | port (2) | address (4 for IPv4)
	if len(val) < 8 {
		return MappedAddress{}, errors.New("nat: stun: MAPPED-ADDRESS too short")
	}

	family := val[1]
	if family != stunFamilyIPv4 {
		return MappedAddress{}, fmt.Errorf("nat: stun: unsupported address family 0x%02X", family)
	}

	port := binary.BigEndian.Uint16(val[2:4])
	ip := make(net.IP, 4)
	copy(ip, val[4:8])

	return MappedAddress{IP: ip, Port: int(port)}, nil
}
