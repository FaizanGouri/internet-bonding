package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	// MagicHeader identifies the test UDP tunnel protocol ("BOND")
	MagicHeader uint32 = 0x424F4E44

	// ProtocolVersion defines the current phase test protocol version
	ProtocolVersion uint8 = 1

	// Packet types
	PacketTypeProbe uint8 = 1
	PacketTypeEcho  uint8 = 2

	// MinPacketSize is Magic(4) + Version(1) + Type(1) + Reserved(2) + Seq(4) + Timestamp(8) + PayloadLen(2) = 22 bytes
	MinPacketSize = 22
)

var (
	ErrPacketTooShort     = errors.New("packet data smaller than minimum header")
	ErrInvalidMagic       = errors.New("invalid protocol magic bytes")
	ErrUnsupportedVersion = errors.New("unsupported protocol version")
)

// Packet represents the Phase 3A test packet format.
type Packet struct {
	Magic     uint32
	Version   uint8
	Type      uint8
	SeqNum    uint32
	Timestamp time.Time
	Payload   []byte
}

// NewProbePacket constructs a test probe packet with the current timestamp.
func NewProbePacket(seqNum uint32, payload []byte) *Packet {
	return &Packet{
		Magic:     MagicHeader,
		Version:   ProtocolVersion,
		Type:      PacketTypeProbe,
		SeqNum:    seqNum,
		Timestamp: time.Now(),
		Payload:   payload,
	}
}

// MarshalBinary serializes the packet into wire format.
func (p *Packet) MarshalBinary() ([]byte, error) {
	payloadLen := len(p.Payload)
	buf := make([]byte, MinPacketSize+payloadLen)

	binary.BigEndian.PutUint32(buf[0:4], p.Magic)
	buf[4] = p.Version
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

// UnmarshalBinary parses raw wire bytes into a Packet structure.
func (p *Packet) UnmarshalBinary(data []byte) error {
	if len(data) < MinPacketSize {
		return ErrPacketTooShort
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != MagicHeader {
		return fmt.Errorf("%w: got 0x%08X, expected 0x%08X", ErrInvalidMagic, magic, MagicHeader)
	}

	version := data[4]
	if version != ProtocolVersion {
		return fmt.Errorf("%w: got %d, expected %d", ErrUnsupportedVersion, version, ProtocolVersion)
	}

	p.Magic = magic
	p.Version = version
	p.Type = data[5]
	p.SeqNum = binary.BigEndian.Uint32(data[8:12])
	p.Timestamp = time.Unix(0, int64(binary.BigEndian.Uint64(data[12:20])))

	payloadLen := int(binary.BigEndian.Uint16(data[20:22]))
	if len(data) < MinPacketSize+payloadLen {
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
