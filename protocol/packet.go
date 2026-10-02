package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	// MagicHeader identifies the UDP tunnel protocol ("BOND")
	MagicHeader uint32 = 0x424F4E44

	// Protocol versions
	ProtocolVersion1 uint8 = 1 // Phase 3A (22-byte header)
	ProtocolVersion2 uint8 = 2 // Phase 3B (46-byte header with SessionID, PathID, AuthTag)

	// Default/current version
	ProtocolVersion uint8 = ProtocolVersion1

	// Packet types
	PacketTypeProbe        uint8 = 1
	PacketTypeEcho         uint8 = 2
	PacketTypeKeepalive    uint8 = 3
	PacketTypeKeepaliveAck uint8 = 4

	// Header sizes
	MinPacketSize = 22 // Version 1 base size (Phase 3A backward compatibility)
	HeaderSizeV1  = 22 // 22 bytes
	HeaderSizeV2  = 46 // 46 bytes: Magic(4) + Ver(1) + Type(1) + PathID(1) + Res(1) + SessionID(8) + Seq(4) + Ts(8) + PayloadLen(2) + AuthTag(16)
)

var (
	ErrPacketTooShort     = errors.New("packet data smaller than minimum header")
	ErrInvalidMagic       = errors.New("invalid protocol magic bytes")
	ErrUnsupportedVersion = errors.New("unsupported protocol version")
	ErrInvalidAuthTag     = errors.New("packet HMAC authentication failed")
)

// Packet represents the tunnel frame for Phase 3A (V1) and Phase 3B (V2).
type Packet struct {
	Magic     uint32
	Version   uint8
	Type      uint8
	PathID    uint8  // Dynamically selected physical interface identifier (1, 2, etc.)
	SessionID uint64 // Logical bonding session identifier
	SeqNum    uint32 // Per-path sequence number
	Timestamp time.Time
	AuthTag   [16]byte // Truncated HMAC-SHA256 signature
	Payload   []byte
}

// ComputeAuthTag calculates a truncated 16-byte HMAC-SHA256 signature over:
// SessionID (8B) | PathID (1B) | PacketType (1B) | SeqNum (4B) | Timestamp (8B) | Payload (NB)
func ComputeAuthTag(key []byte, sessionID uint64, pathID uint8, pktType uint8, seqNum uint32, ts time.Time, payload []byte) [16]byte {
	mac := hmac.New(sha256.New, key)
	var buf [22]byte
	binary.BigEndian.PutUint64(buf[0:8], sessionID)
	buf[8] = pathID
	buf[9] = pktType
	binary.BigEndian.PutUint32(buf[10:14], seqNum)
	binary.BigEndian.PutUint64(buf[14:22], uint64(ts.UnixNano()))
	mac.Write(buf[:])
	if len(payload) > 0 {
		mac.Write(payload)
	}
	sum := mac.Sum(nil)
	var tag [16]byte
	copy(tag[:], sum[:16])
	return tag
}

// VerifyAuthTag checks the authenticity and integrity of a Version 2 packet using constant-time comparison.
func VerifyAuthTag(key []byte, pkt *Packet) bool {
	if len(key) == 0 {
		return false
	}
	expected := ComputeAuthTag(key, pkt.SessionID, pkt.PathID, pkt.Type, pkt.SeqNum, pkt.Timestamp, pkt.Payload)
	return hmac.Equal(pkt.AuthTag[:], expected[:])
}

// NewProbePacket constructs a Phase 3A test probe packet (Version 1).
func NewProbePacket(seqNum uint32, payload []byte) *Packet {
	return &Packet{
		Magic:     MagicHeader,
		Version:   ProtocolVersion1,
		Type:      PacketTypeProbe,
		SeqNum:    seqNum,
		Timestamp: time.Now(),
		Payload:   payload,
	}
}

// NewV2Packet constructs an authenticated Phase 3B packet (Version 2) with HMAC-SHA256.
func NewV2Packet(pktType uint8, sessionID uint64, pathID uint8, seqNum uint32, payload []byte, key []byte) *Packet {
	now := time.Now()
	var tag [16]byte
	if len(key) > 0 {
		tag = ComputeAuthTag(key, sessionID, pathID, pktType, seqNum, now, payload)
	}
	return &Packet{
		Magic:     MagicHeader,
		Version:   ProtocolVersion2,
		Type:      pktType,
		PathID:    pathID,
		SessionID: sessionID,
		SeqNum:    seqNum,
		Timestamp: now,
		AuthTag:   tag,
		Payload:   payload,
	}
}

// MarshalBinary serializes the packet into wire format based on its Version.
func (p *Packet) MarshalBinary() ([]byte, error) {
	payloadLen := len(p.Payload)

	if p.Version == ProtocolVersion2 {
		buf := make([]byte, HeaderSizeV2+payloadLen)
		binary.BigEndian.PutUint32(buf[0:4], p.Magic)
		buf[4] = p.Version
		buf[5] = p.Type
		buf[6] = p.PathID
		buf[7] = 0 // Reserved
		binary.BigEndian.PutUint64(buf[8:16], p.SessionID)
		binary.BigEndian.PutUint32(buf[16:20], p.SeqNum)
		binary.BigEndian.PutUint64(buf[20:28], uint64(p.Timestamp.UnixNano()))
		binary.BigEndian.PutUint16(buf[28:30], uint16(payloadLen))
		copy(buf[30:46], p.AuthTag[:])
		if payloadLen > 0 {
			copy(buf[46:], p.Payload)
		}
		return buf, nil
	}

	// Default to Version 1 (Phase 3A format)
	buf := make([]byte, HeaderSizeV1+payloadLen)
	binary.BigEndian.PutUint32(buf[0:4], p.Magic)
	buf[4] = ProtocolVersion1
	buf[5] = p.Type
	buf[6] = 0 // Reserved
	buf[7] = 0 // Reserved
	binary.BigEndian.PutUint32(buf[8:12], p.SeqNum)
	binary.BigEndian.PutUint64(buf[12:20], uint64(p.Timestamp.UnixNano()))
	binary.BigEndian.PutUint16(buf[20:22], uint16(payloadLen))
	if payloadLen > 0 {
		copy(buf[22:], p.Payload)
	}
	return buf, nil
}

// UnmarshalBinary parses raw wire bytes into a Packet structure (handling both V1 and V2).
func (p *Packet) UnmarshalBinary(data []byte) error {
	if len(data) < MinPacketSize {
		return ErrPacketTooShort
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != MagicHeader {
		return fmt.Errorf("%w: got 0x%08X, expected 0x%08X", ErrInvalidMagic, magic, MagicHeader)
	}

	version := data[4]

	if version == ProtocolVersion2 {
		if len(data) < HeaderSizeV2 {
			return ErrPacketTooShort
		}
		p.Magic = magic
		p.Version = version
		p.Type = data[5]
		p.PathID = data[6]
		p.SessionID = binary.BigEndian.Uint64(data[8:16])
		p.SeqNum = binary.BigEndian.Uint32(data[16:20])
		p.Timestamp = time.Unix(0, int64(binary.BigEndian.Uint64(data[20:28])))
		payloadLen := int(binary.BigEndian.Uint16(data[28:30]))
		copy(p.AuthTag[:], data[30:46])

		if len(data) < HeaderSizeV2+payloadLen {
			return errors.New("packet truncated: payload length exceeds buffer")
		}
		if payloadLen > 0 {
			p.Payload = make([]byte, payloadLen)
			copy(p.Payload, data[46:46+payloadLen])
		} else {
			p.Payload = nil
		}
		return nil
	}

	if version == ProtocolVersion1 {
		p.Magic = magic
		p.Version = version
		p.Type = data[5]
		p.PathID = 1
		p.SessionID = 0
		p.SeqNum = binary.BigEndian.Uint32(data[8:12])
		p.Timestamp = time.Unix(0, int64(binary.BigEndian.Uint64(data[12:20])))
		payloadLen := int(binary.BigEndian.Uint16(data[20:22]))

		if len(data) < HeaderSizeV1+payloadLen {
			return errors.New("packet truncated: payload length exceeds buffer")
		}
		if payloadLen > 0 {
			p.Payload = make([]byte, payloadLen)
			copy(p.Payload, data[22:22+payloadLen])
		} else {
			p.Payload = nil
		}
		return nil
	}

	return fmt.Errorf("%w: got %d, expected %d or %d", ErrUnsupportedVersion, version, ProtocolVersion1, ProtocolVersion2)
}
