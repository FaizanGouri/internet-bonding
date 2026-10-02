package session

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"internet-bonding/protocol"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrPathNotFound    = errors.New("path not registered in session")
)

// PathEndpoint stores runtime state and endpoint mappings for a specific physical path.
type PathEndpoint struct {
	PathID     uint8
	Addr       *net.UDPAddr
	LastSeen   time.Time
	PacketsIn  uint64
	PacketsOut uint64
	LastSeqNum uint32
}

// SessionRecord holds active state for a multi-path client bonding session.
type SessionRecord struct {
	SessionID    uint64
	CreatedAt    time.Time
	LastActivity time.Time
	Paths        map[uint8]*PathEndpoint
}

// SessionTable provides a thread-safe registry of active bonding sessions.
type SessionTable struct {
	mu                sync.RWMutex
	sessions          map[uint64]*SessionRecord
	securityDropCount uint64
}

// NewSessionTable constructs an initialized SessionTable.
func NewSessionTable() *SessionTable {
	return &SessionTable{
		sessions: make(map[uint64]*SessionRecord),
	}
}

// SecurityDropCount returns the total number of packets dropped due to failed HMAC or integrity checks.
func (st *SessionTable) SecurityDropCount() uint64 {
	return atomic.LoadUint64(&st.securityDropCount)
}

// RecordSecurityDrop increments the security drop counter.
func (st *SessionTable) RecordSecurityDrop() {
	atomic.AddUint64(&st.securityDropCount, 1)
}

// SessionCount returns the number of active sessions in memory.
func (st *SessionTable) SessionCount() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.sessions)
}

// GetEndpoint retrieves the currently mapped remote UDP address for a given session and path.
func (st *SessionTable) GetEndpoint(sessionID uint64, pathID uint8) (*net.UDPAddr, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	s, exists := st.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}
	p, exists := s.Paths[pathID]
	if !exists || p.Addr == nil {
		return nil, ErrPathNotFound
	}
	return p.Addr, nil
}

// ProcessPacket validates HMAC authentication and safely updates session state.
// SECURITY ENFORCEMENT: If HMAC verification fails, state and endpoints are NEVER updated.
func (st *SessionTable) ProcessPacket(pkt *protocol.Packet, clientAddr *net.UDPAddr, psk []byte) (*protocol.Packet, error) {
	// 1. Mandatory HMAC verification for Version 2 packets
	if pkt.Version == protocol.ProtocolVersion2 {
		if !protocol.VerifyAuthTag(psk, pkt) {
			st.RecordSecurityDrop()
			return nil, protocol.ErrInvalidAuthTag
		}
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()

	// 2. Lookup or initialize session record
	sess, exists := st.sessions[pkt.SessionID]
	if !exists {
		sess = &SessionRecord{
			SessionID:    pkt.SessionID,
			CreatedAt:    now,
			LastActivity: now,
			Paths:        make(map[uint8]*PathEndpoint),
		}
		st.sessions[pkt.SessionID] = sess
	}
	sess.LastActivity = now

	// 3. Lookup or initialize path endpoint
	path, exists := sess.Paths[pkt.PathID]
	if !exists {
		path = &PathEndpoint{
			PathID: pkt.PathID,
		}
		sess.Paths[pkt.PathID] = path
	}

	// 4. Update learned NAT endpoint mapping and counters
	path.Addr = clientAddr
	path.LastSeen = now
	path.PacketsIn++
	path.LastSeqNum = pkt.SeqNum

	// 5. Construct response packet
	var respType uint8
	switch pkt.Type {
	case protocol.PacketTypeKeepalive:
		respType = protocol.PacketTypeKeepaliveAck
	case protocol.PacketTypeProbe:
		respType = protocol.PacketTypeEcho
	default:
		respType = protocol.PacketTypeEcho
	}

	resp := protocol.NewV2Packet(respType, pkt.SessionID, pkt.PathID, pkt.SeqNum, pkt.Payload, psk)
	path.PacketsOut++

	return resp, nil
}
