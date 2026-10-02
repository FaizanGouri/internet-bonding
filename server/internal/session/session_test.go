package session

import (
	"errors"
	"net"
	"testing"

	"internet-bonding/protocol"
)

func TestSessionTable_ValidPacketProcessing(t *testing.T) {
	st := NewSessionTable()
	psk := []byte("0123456789abcdef0123456789abcdef")

	sessionID := uint64(0xABCD1234EF567890)
	path1Addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 45000}
	path2Addr := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 55000}

	// 1. Process Path 1 Keepalive
	pkt1 := protocol.NewV2Packet(protocol.PacketTypeKeepalive, sessionID, 1, 101, nil, psk)
	resp1, err := st.ProcessPacket(pkt1, path1Addr, psk)
	if err != nil {
		t.Fatalf("ProcessPacket for path 1 failed: %v", err)
	}
	if resp1.Type != protocol.PacketTypeKeepaliveAck {
		t.Errorf("Expected KeepaliveAck, got %d", resp1.Type)
	}

	// 2. Process Path 2 Keepalive under same session
	pkt2 := protocol.NewV2Packet(protocol.PacketTypeKeepalive, sessionID, 2, 201, nil, psk)
	resp2, err := st.ProcessPacket(pkt2, path2Addr, psk)
	if err != nil {
		t.Fatalf("ProcessPacket for path 2 failed: %v", err)
	}
	if resp2.Type != protocol.PacketTypeKeepaliveAck {
		t.Errorf("Expected KeepaliveAck, got %d", resp2.Type)
	}

	// 3. Verify Session and Endpoints
	if st.SessionCount() != 1 {
		t.Errorf("SessionCount = %d; want 1", st.SessionCount())
	}

	ep1, err := st.GetEndpoint(sessionID, 1)
	if err != nil || ep1.String() != path1Addr.String() {
		t.Errorf("Endpoint 1 = %v; want %v", ep1, path1Addr)
	}

	ep2, err := st.GetEndpoint(sessionID, 2)
	if err != nil || ep2.String() != path2Addr.String() {
		t.Errorf("Endpoint 2 = %v; want %v", ep2, path2Addr)
	}

	if st.SecurityDropCount() != 0 {
		t.Errorf("SecurityDropCount = %d; want 0", st.SecurityDropCount())
	}
}

func TestSessionTable_InvalidHMAC_SecurityEnforcement(t *testing.T) {
	st := NewSessionTable()
	psk := []byte("0123456789abcdef0123456789abcdef")

	sessionID := uint64(0xFEDCBA9876543210)
	legitAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.50"), Port: 40000}
	attackerAddr := &net.UDPAddr{IP: net.ParseIP("198.51.100.99"), Port: 6666}

	// 1. Establish legitimate session with Path 1
	validPkt := protocol.NewV2Packet(protocol.PacketTypeKeepalive, sessionID, 1, 1, nil, psk)
	_, err := st.ProcessPacket(validPkt, legitAddr, psk)
	if err != nil {
		t.Fatalf("Initial valid packet failed: %v", err)
	}

	initialEndpoint, _ := st.GetEndpoint(sessionID, 1)
	if initialEndpoint.String() != legitAddr.String() {
		t.Fatalf("Endpoint not mapped correctly: got %v", initialEndpoint)
	}
	initialDropCount := st.SecurityDropCount()

	// 2. Attacker attempts to spoof Path 1 with an invalid / altered AuthTag
	spoofedPkt := protocol.NewV2Packet(protocol.PacketTypeKeepalive, sessionID, 1, 2, nil, psk)
	spoofedPkt.AuthTag[0] ^= 0xAA // Corrupt the AuthTag

	resp, err := st.ProcessPacket(spoofedPkt, attackerAddr, psk)
	if resp != nil {
		t.Errorf("Expected nil response for invalid HMAC packet, got %v", resp)
	}
	if !errors.Is(err, protocol.ErrInvalidAuthTag) {
		t.Errorf("Expected ErrInvalidAuthTag, got %v", err)
	}

	// 3. Verify Security Requirements:
	// A. SecurityDropCount MUST increment
	if st.SecurityDropCount() != initialDropCount+1 {
		t.Errorf("SecurityDropCount = %d; want %d", st.SecurityDropCount(), initialDropCount+1)
	}

	// B. Session mapping must remain UNCHANGED (still 1 session)
	if st.SessionCount() != 1 {
		t.Errorf("SessionCount = %d; want 1", st.SessionCount())
	}

	// C. Path endpoint mapping must remain UNCHANGED (still legitAddr, NOT attackerAddr)
	currentEndpoint, err := st.GetEndpoint(sessionID, 1)
	if err != nil {
		t.Fatalf("Failed to get endpoint: %v", err)
	}
	if currentEndpoint.String() != legitAddr.String() {
		t.Errorf("CRITICAL SECURITY FAILURE: Endpoint was corrupted by invalid HMAC! Got %v, want %v",
			currentEndpoint, legitAddr)
	}

	// D. Attempt to register a brand new session with invalid HMAC
	newAttackerSessionID := uint64(0xDEADBEEFCAFE0001)
	newSpoofedPkt := protocol.NewV2Packet(protocol.PacketTypeProbe, newAttackerSessionID, 1, 1, nil, psk)
	newSpoofedPkt.AuthTag[5] ^= 0x55 // Corrupt HMAC

	_, err = st.ProcessPacket(newSpoofedPkt, attackerAddr, psk)
	if !errors.Is(err, protocol.ErrInvalidAuthTag) {
		t.Errorf("Expected ErrInvalidAuthTag for new session spoof, got %v", err)
	}

	// Verify no new session was created in the table
	if st.SessionCount() != 1 {
		t.Errorf("Session table created new session from invalid HMAC! Count = %d", st.SessionCount())
	}
	if st.SecurityDropCount() != initialDropCount+2 {
		t.Errorf("SecurityDropCount = %d; want %d", st.SecurityDropCount(), initialDropCount+2)
	}
}
