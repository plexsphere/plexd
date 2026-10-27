package bridge

import (
	"encoding/binary"

	"golang.zx2c4.com/wireguard/device"
)

// wgMessage is the part of a WireGuard message header the relay forwards by:
// the message type and the session indices it carries. sender is set for an
// initiation and a response, receiver for a response, a cookie reply and a
// transport message.
type wgMessage struct {
	typ      byte
	sender   uint32
	receiver uint32
}

// parseWGMessage classifies b as a WireGuard message. It accepts b when its
// three reserved bytes b[1:4] are zero and its type and length match one of
// the four message formats: an initiation of exactly MessageInitiationSize
// bytes, a response of exactly MessageResponseSize, a cookie reply of exactly
// MessageCookieReplySize, or a transport message of at least
// MessageTransportSize. Indices are little-endian.
//
// The exact sizes matter beyond classification: CookieChecker.CheckMAC1 takes
// the MACs from the last 32 bytes of whatever it is given and checks no
// length, so only a datagram this function accepted may reach it.
func parseWGMessage(b []byte) (wgMessage, bool) {
	if len(b) < 4 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return wgMessage{}, false
	}
	msg := wgMessage{typ: b[0]}
	switch b[0] {
	case device.MessageInitiationType:
		if len(b) != device.MessageInitiationSize {
			return wgMessage{}, false
		}
		msg.sender = binary.LittleEndian.Uint32(b[4:8])
	case device.MessageResponseType:
		if len(b) != device.MessageResponseSize {
			return wgMessage{}, false
		}
		msg.sender = binary.LittleEndian.Uint32(b[4:8])
		msg.receiver = binary.LittleEndian.Uint32(b[8:12])
	case device.MessageCookieReplyType:
		if len(b) != device.MessageCookieReplySize {
			return wgMessage{}, false
		}
		msg.receiver = binary.LittleEndian.Uint32(b[4:8])
	case device.MessageTransportType:
		if len(b) < device.MessageTransportSize {
			return wgMessage{}, false
		}
		msg.receiver = binary.LittleEndian.Uint32(b[4:8])
	default:
		return wgMessage{}, false
	}
	return msg, true
}
