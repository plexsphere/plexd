package bridge

import (
	"encoding/binary"
	"testing"

	"golang.zx2c4.com/wireguard/device"
)

// wgDatagram returns a datagram of size bytes with WireGuard message type typ,
// zero reserved bytes, and the little-endian index a at b[4:8] and b at
// b[8:12] where the size leaves room for them.
func wgDatagram(typ byte, size int, a, b uint32) []byte {
	msg := make([]byte, size)
	msg[0] = typ
	if size >= 8 {
		binary.LittleEndian.PutUint32(msg[4:8], a)
	}
	if size >= 12 {
		binary.LittleEndian.PutUint32(msg[8:12], b)
	}
	return msg
}

func TestParseWGMessage_AcceptsTheFourTypes(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want wgMessage
	}{
		{
			"initiation",
			wgDatagram(device.MessageInitiationType, device.MessageInitiationSize, 0x11223344, 0),
			wgMessage{typ: device.MessageInitiationType, sender: 0x11223344},
		},
		{
			"response",
			wgDatagram(device.MessageResponseType, device.MessageResponseSize, 0x01020304, 0x0a0b0c0d),
			wgMessage{typ: device.MessageResponseType, sender: 0x01020304, receiver: 0x0a0b0c0d},
		},
		{
			"cookie reply",
			wgDatagram(device.MessageCookieReplyType, device.MessageCookieReplySize, 0xdeadbeef, 0),
			wgMessage{typ: device.MessageCookieReplyType, receiver: 0xdeadbeef},
		},
		{
			"keepalive",
			wgDatagram(device.MessageTransportType, device.MessageTransportSize, 7, 0),
			wgMessage{typ: device.MessageTransportType, receiver: 7},
		},
		{
			"transport with payload",
			wgDatagram(device.MessageTransportType, 1420, 0xfffffffe, 0),
			wgMessage{typ: device.MessageTransportType, receiver: 0xfffffffe},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseWGMessage(tt.b)
			if !ok {
				t.Fatalf("parseWGMessage rejected a valid %s", tt.name)
			}
			if got != tt.want {
				t.Errorf("parseWGMessage = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseWGMessage_Rejects(t *testing.T) {
	reserved := func(i int) []byte {
		b := wgDatagram(device.MessageTransportType, device.MessageTransportSize, 1, 0)
		b[i] = 1
		return b
	}
	tests := []struct {
		name string
		b    []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"three bytes", []byte{device.MessageTransportType, 0, 0}},
		{"147-byte initiation", wgDatagram(device.MessageInitiationType, device.MessageInitiationSize-1, 1, 0)},
		{"149-byte initiation", wgDatagram(device.MessageInitiationType, device.MessageInitiationSize+1, 1, 0)},
		{"91-byte response", wgDatagram(device.MessageResponseType, device.MessageResponseSize-1, 1, 2)},
		{"93-byte response", wgDatagram(device.MessageResponseType, device.MessageResponseSize+1, 1, 2)},
		{"63-byte cookie reply", wgDatagram(device.MessageCookieReplyType, device.MessageCookieReplySize-1, 1, 0)},
		{"65-byte cookie reply", wgDatagram(device.MessageCookieReplyType, device.MessageCookieReplySize+1, 1, 0)},
		{"31-byte transport", wgDatagram(device.MessageTransportType, device.MessageTransportSize-1, 1, 0)},
		{"non-zero reserved byte 1", reserved(1)},
		{"non-zero reserved byte 2", reserved(2)},
		{"non-zero reserved byte 3", reserved(3)},
		{"type 0", wgDatagram(0, device.MessageTransportSize, 1, 0)},
		{"type 5", wgDatagram(5, device.MessageTransportSize, 1, 0)},
		{"text", []byte("hello")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, ok := parseWGMessage(tt.b); ok {
				t.Errorf("parseWGMessage accepted %s as %+v", tt.name, got)
			}
		})
	}
}
