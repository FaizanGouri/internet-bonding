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

func TestSessionTable_SelectDownstreamPath_RoundRobin(t *testing.T) {
	st := NewSessionTable()
	psk := []byte("0123456789abcdef0123456789abcdef")
	sessionID := uint64(0x1122334455667788)

	addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 50001}
	addr2 := &net.UDPAddr{IP: net.ParseIP("192.168.2.100"), Port: 50002}

	// Register P1 and P2
	pkt1 := protocol.NewV2Packet(protocol.PacketTypeKeepalive, sessionID, 1, 1, nil, psk)
	_, _ = st.ProcessPacket(pkt1, addr1, psk)

	pkt2 := protocol.NewV2Packet(protocol.PacketTypeKeepalive, sessionID, 2, 1, nil, psk)
	_, _ = st.ProcessPacket(pkt2, addr2, psk)

	// Should round-robin across both active paths: P1, P2, P1, P2
	expectedPIDs := []uint8{1, 2, 1, 2}
	for i, wantPID := range expectedPIDs {
		pid, ep, err := st.SelectDownstreamPath(sessionID)
		if err != nil {
			t.Fatalf("Iteration %d: SelectDownstreamPath failed: %v", i, err)
		}
		if pid != wantPID {
			t.Errorf("Iteration %d: got PathID %d, want %d", i, pid, wantPID)
		}
		if (wantPID == 1 && ep.String() != addr1.String()) || (wantPID == 2 && ep.String() != addr2.String()) {
			t.Errorf("Iteration %d: unexpected endpoint %v for path %d", i, ep, wantPID)
		}
	}

	// Test RecordDownstreamTx
	st.RecordDownstreamTx(sessionID, 1, 1400)
}

func TestSessionTable_DownstreamSWRR_WeightFeedback(t *testing.T) {
	st := NewSessionTable()
	psk := []byte("0123456789abcdef0123456789abcdef")
	sessionID := uint64(0x9988776655443322)

	addr1 := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	addr2 := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}

	// 1. P1 reports weight 2, P2 reports weight 1 in keepalive payload
	kp1 := protocol.NewV2Packet(protocol.PacketTypeKeepalive, sessionID, 1, 1, []byte{2}, psk)
	_, _ = st.ProcessPacket(kp1, addr1, psk)

	kp2 := protocol.NewV2Packet(protocol.PacketTypeKeepalive, sessionID, 2, 1, []byte{1}, psk)
	_, _ = st.ProcessPacket(kp2, addr2, psk)

	// SWRR with weights 2:1 over 3 iterations should yield: P1, P2, P1
	expected := []uint8{1, 2, 1}
	for i, wantPID := range expected {
		pid, _, err := st.SelectDownstreamPath(sessionID)
		if err != nil {
			t.Fatalf("Iteration %d: SelectDownstreamPath failed: %v", i, err)
		}
		if pid != wantPID {
			t.Errorf("Iteration %d: got PathID %d, want %d", i, pid, wantPID)
		}
	}

	// 2. P2 reports weight 0 (path DOWN)
	kp2Down := protocol.NewV2Packet(protocol.PacketTypeKeepalive, sessionID, 2, 2, []byte{0}, psk)
	_, _ = st.ProcessPacket(kp2Down, addr2, psk)

	// Now only P1 should be selected
	for i := 0; i < 5; i++ {
		pid, _, err := st.SelectDownstreamPath(sessionID)
		if err != nil {
			t.Fatalf("P1 only: SelectDownstreamPath failed: %v", err)
		}
		if pid != 1 {
			t.Errorf("P1 only: got PathID %d, want 1", pid)
		}
	}

	// 3. P2 recovers with slow-start weight 1
	kp2Up := protocol.NewV2Packet(protocol.PacketTypeKeepalive, sessionID, 2, 3, []byte{1}, psk)
	_, _ = st.ProcessPacket(kp2Up, addr2, psk)

	pCounts := make(map[uint8]int)
	for i := 0; i < 6; i++ {
		pid, _, _ := st.SelectDownstreamPath(sessionID)
		pCounts[pid]++
	}
	if pCounts[1] == 0 || pCounts[2] == 0 {
		t.Errorf("Expected both P1 and P2 to receive traffic after recovery, got counts: %v", pCounts)
	}
}
