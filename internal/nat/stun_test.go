package nat

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildBindingRequest_ValidHeader(t *testing.T) {
	var txID [12]byte
	copy(txID[:], []byte("ABCDEFGHIJKL"))

	req := buildBindingRequest(txID)
	if len(req) != 20 {
		t.Fatalf("len(req) = %d, want 20", len(req))
	}

	// Type = 0x0001 (Binding Request)
	msgType := binary.BigEndian.Uint16(req[0:2])
	if msgType != 0x0001 {
		t.Errorf("message type = 0x%04X, want 0x0001", msgType)
	}

	// Length = 0x0000
	msgLen := binary.BigEndian.Uint16(req[2:4])
	if msgLen != 0x0000 {
		t.Errorf("message length = 0x%04X, want 0x0000", msgLen)
	}

	// Magic cookie = 0x2112A442
	cookie := binary.BigEndian.Uint32(req[4:8])
	if cookie != 0x2112A442 {
		t.Errorf("magic cookie = 0x%08X, want 0x2112A442", cookie)
	}

	// Transaction ID
	if !bytes.Equal(req[8:20], txID[:]) {
		t.Errorf("transaction ID = %x, want %x", req[8:20], txID[:])
	}
}

func TestBuildBindingRequest_DifferentTransactionIDs(t *testing.T) {
	var txID1 [12]byte
	copy(txID1[:], []byte("AAAAAAAAAAAA"))

	var txID2 [12]byte
	copy(txID2[:], []byte("BBBBBBBBBBBB"))

	req1 := buildBindingRequest(txID1)
	req2 := buildBindingRequest(txID2)

	if bytes.Equal(req1, req2) {
		t.Error("requests with different transaction IDs should differ")
	}

	// The header (first 8 bytes) should be identical.
	if !bytes.Equal(req1[:8], req2[:8]) {
		t.Error("header portion should be identical for both requests")
	}
}

func TestParseBindingResponse_XORMappedAddressIPv4(t *testing.T) {
	// Build a STUN Binding Success Response with XOR-MAPPED-ADDRESS.
	// Target: IP 203.0.113.5, port 54321
	// XOR port: 0xD431 ^ 0x2112 = 0xF523
	// XOR IP:   0xCB007105 ^ 0x2112A442 = 0xEA12D547
	var txID [12]byte
	copy(txID[:], []byte("TESTTXID1234"))

	// Attribute: XOR-MAPPED-ADDRESS (0x0020)
	attr := []byte{
		0x00, 0x20, // type: XOR-MAPPED-ADDRESS
		0x00, 0x08, // length: 8
		0x00,       // reserved
		0x01,       // family: IPv4
		0xF5, 0x23, // XOR'd port
		0xEA, 0x12, 0xD5, 0x47, // XOR'd IP
	}

	resp := buildTestResponse(0x0101, txID, attr)

	addr, err := parseBindingResponse(resp, txID)
	if err != nil {
		t.Fatalf("parseBindingResponse() error = %v", err)
	}

	wantIP := net.IPv4(203, 0, 113, 5)
	if !addr.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", addr.IP, wantIP)
	}
	if addr.Port != 54321 {
		t.Errorf("Port = %d, want 54321", addr.Port)
	}
}

func TestParseBindingResponse_MappedAddressFallback(t *testing.T) {
	// Build a response with only MAPPED-ADDRESS (no XOR).
	// IP 192.168.1.100, port 12345
	var txID [12]byte
	copy(txID[:], []byte("FALLBACKTXID"))

	attr := []byte{
		0x00, 0x01, // type: MAPPED-ADDRESS
		0x00, 0x08, // length: 8
		0x00,       // reserved
		0x01,       // family: IPv4
		0x30, 0x39, // port: 12345
		0xC0, 0xA8, 0x01, 0x64, // IP: 192.168.1.100
	}

	resp := buildTestResponse(0x0101, txID, attr)

	addr, err := parseBindingResponse(resp, txID)
	if err != nil {
		t.Fatalf("parseBindingResponse() error = %v", err)
	}

	wantIP := net.IPv4(192, 168, 1, 100)
	if !addr.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", addr.IP, wantIP)
	}
	if addr.Port != 12345 {
		t.Errorf("Port = %d, want 12345", addr.Port)
	}
}

func TestParseBindingResponse_RejectsWrongTransactionID(t *testing.T) {
	var txID [12]byte
	copy(txID[:], []byte("CORRECTTXID!"))

	var wrongTxID [12]byte
	copy(wrongTxID[:], []byte("WRONG_TXID!!"))

	resp := buildTestResponse(0x0101, wrongTxID, nil)

	_, err := parseBindingResponse(resp, txID)
	if err == nil {
		t.Fatal("parseBindingResponse() = nil error, want error for wrong transaction ID")
	}
}

func TestParseBindingResponse_RejectsTruncatedResponse(t *testing.T) {
	var txID [12]byte
	_, err := parseBindingResponse([]byte{0x01, 0x01, 0x00}, txID)
	if err == nil {
		t.Fatal("parseBindingResponse() = nil error, want error for truncated response")
	}
}

func TestParseBindingResponse_RejectsNonSuccessResponse(t *testing.T) {
	var txID [12]byte
	copy(txID[:], []byte("ERRORTXID123"))

	resp := buildTestResponse(0x0111, txID, nil)

	_, err := parseBindingResponse(resp, txID)
	if err == nil {
		t.Fatal("parseBindingResponse() = nil error, want error for non-success response")
	}
}

func TestParseBindingResponse_RejectsNoAddressAttribute(t *testing.T) {
	var txID [12]byte
	copy(txID[:], []byte("NOADDRATTR!!"))

	// Valid header but no attributes at all.
	resp := buildTestResponse(0x0101, txID, nil)

	_, err := parseBindingResponse(resp, txID)
	if err == nil {
		t.Fatal("parseBindingResponse() = nil error, want error for no address attribute")
	}
}

func TestParseBindingResponse_RejectsWrongMagicCookie(t *testing.T) {
	var txID [12]byte
	copy(txID[:], []byte("BADCOOKIETX!"))

	// Build a response manually with wrong magic cookie.
	resp := make([]byte, 20)
	binary.BigEndian.PutUint16(resp[0:2], 0x0101)
	binary.BigEndian.PutUint16(resp[2:4], 0x0000)
	binary.BigEndian.PutUint32(resp[4:8], 0xDEADBEEF) // wrong cookie
	copy(resp[8:20], txID[:])

	_, err := parseBindingResponse(resp, txID)
	if err == nil {
		t.Fatal("parseBindingResponse() = nil error, want error for wrong magic cookie")
	}
}

// buildTestResponse constructs a minimal STUN response for testing.
func buildTestResponse(msgType uint16, txID [12]byte, attributes []byte) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], msgType)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(attributes)))
	binary.BigEndian.PutUint32(header[4:8], 0x2112A442)
	copy(header[8:20], txID[:])
	return append(header, attributes...)
}
