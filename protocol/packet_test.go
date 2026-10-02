package protocol

import (
	"bytes"
	"testing"
)

func TestPacketV1_Compatibility(t *testing.T) {
	orig := NewProbePacket(42, []byte("TestV1Payload"))
	data, err := orig.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != HeaderSizeV1+len("TestV1Payload") {
		t.Errorf("Expected length %d, got %d", HeaderSizeV1+len("TestV1Payload"), len(data))
	}

	var parsed Packet
	if err := parsed.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if parsed.Version != ProtocolVersion1 {
		t.Errorf("Version = %d; want %d", parsed.Version, ProtocolVersion1)
	}
	if parsed.SeqNum != 42 {
		t.Errorf("SeqNum = %d; want 42", parsed.SeqNum)
	}
}

func TestPacketV2_MarshalUnmarshal(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32-byte test key
	sessionID := uint64(0x1122334455667788)
	pathID := uint8(2) // dynamically assigned path 2
	seqNum := uint32(1001)
	payload := []byte("DualPathPayloadTest")

	orig := NewV2Packet(PacketTypeKeepalive, sessionID, pathID, seqNum, payload, key)
	data, err := orig.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != HeaderSizeV2+len(payload) {
		t.Errorf("Expected length %d (HeaderSizeV2=46 + len=%d), got %d", HeaderSizeV2+len(payload), len(payload), len(data))
	}

	var parsed Packet
	if err := parsed.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if parsed.Magic != MagicHeader {
		t.Errorf("Magic = 0x%08X; want 0x%08X", parsed.Magic, MagicHeader)
	}
	if parsed.Version != ProtocolVersion2 {
		t.Errorf("Version = %d; want %d", parsed.Version, ProtocolVersion2)
	}
	if parsed.Type != PacketTypeKeepalive {
		t.Errorf("Type = %d; want %d", parsed.Type, PacketTypeKeepalive)
	}
	if parsed.PathID != pathID {
		t.Errorf("PathID = %d; want %d", parsed.PathID, pathID)
	}
	if parsed.SessionID != sessionID {
		t.Errorf("SessionID = 0x%016X; want 0x%016X", parsed.SessionID, sessionID)
	}
	if parsed.SeqNum != seqNum {
		t.Errorf("SeqNum = %d; want %d", parsed.SeqNum, seqNum)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Errorf("Payload = %s; want %s", string(parsed.Payload), string(payload))
	}

	// Verify HMAC
	if !VerifyAuthTag(key, &parsed) {
		t.Errorf("HMAC verification failed on valid packet")
	}
}

func TestPacketV2_TamperedHMACRejection(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	sessionID := uint64(0x9988776655443322)
	pathID := uint8(1)
	seqNum := uint32(50)
	payload := []byte("IntegrityProtectedData")

	pkt := NewV2Packet(PacketTypeProbe, sessionID, pathID, seqNum, payload, key)
	if !VerifyAuthTag(key, pkt) {
		t.Fatalf("Expected valid HMAC initially")
	}

	// 1. Tamper AuthTag
	pkt.AuthTag[0] ^= 0xFF
	if VerifyAuthTag(key, pkt) {
		t.Errorf("Expected HMAC verification to fail with tampered AuthTag")
	}
	pkt.AuthTag[0] ^= 0xFF // restore

	// 2. Tamper SeqNum
	pkt.SeqNum = 999
	if VerifyAuthTag(key, pkt) {
		t.Errorf("Expected HMAC verification to fail with modified SeqNum")
	}
	pkt.SeqNum = 50 // restore

	// 3. Tamper Payload
	pkt.Payload[0] ^= 0x01
	if VerifyAuthTag(key, pkt) {
		t.Errorf("Expected HMAC verification to fail with modified Payload")
	}

	// 4. Verify wrong key
	wrongKey := []byte("completely_different_key_12345678")
	if VerifyAuthTag(wrongKey, pkt) {
		t.Errorf("Expected HMAC verification to fail with wrong key")
	}
}
