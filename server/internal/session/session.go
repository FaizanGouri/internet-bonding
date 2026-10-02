package session

import (
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"internet-bonding/protocol"
	"internet-bonding/reorder"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrPathNotFound    = errors.New("path not registered in session")
	ErrNoActivePaths   = errors.New("no active physical paths available for session")
)

// PathEndpoint stores runtime state and endpoint mappings for a specific physical path.
type PathEndpoint struct {
	PathID     uint8
	Addr       *net.UDPAddr
	LastSeen   time.Time
	PacketsIn  uint64
	PacketsOut uint64
	BytesIn    uint64
	BytesOut   uint64
	LastSeqNum uint32
	Weight     int
}

// SessionRecord holds active state for a multi-path client bonding session.
type SessionRecord struct {
	SessionID      uint64
	VirtualIP      net.IP
	CreatedAt      time.Time
	LastActivity   time.Time
	Paths          map[uint8]*PathEndpoint
	ReorderBuffer  *reorder.ReorderBuffer
	downstreamSeq  uint32
	downstreamIdx  uint32
	currentWeights map[uint8]int
}

// SessionTable provides a thread-safe registry of active bonding sessions.
type SessionTable struct {
	mu                sync.RWMutex
	sessions          map[uint64]*SessionRecord
	virtualIPMap      map[string]uint64
	securityDropCount uint64
}

// NewSessionTable constructs an initialized SessionTable.
func NewSessionTable() *SessionTable {
	return &SessionTable{
		sessions:     make(map[uint64]*SessionRecord),
		virtualIPMap: make(map[string]uint64),
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

// GetSessionByVirtualIP locates the session associated with a client virtual IP address.
func (st *SessionTable) GetSessionByVirtualIP(ip net.IP) (*SessionRecord, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	// 1. Primary lookup by virtualIPMap
	sessID, exists := st.virtualIPMap[ip.String()]
	if exists {
		if s, ok := st.sessions[sessID]; ok {
			return s, nil
		}
	}

	// 2. Deterministic match on session VirtualIP
	for _, s := range st.sessions {
		if s.VirtualIP != nil && s.VirtualIP.Equal(ip) {
			return s, nil
		}
	}

	// 3. Fallback for client tunnel IP (10.8.0.2): match active session
	if ip.String() == "10.8.0.2" {
		var activeSess *SessionRecord
		for _, s := range st.sessions {
			if activeSess == nil || s.LastActivity.After(activeSess.LastActivity) {
				activeSess = s
			}
		}
		if activeSess != nil {
			return activeSess, nil
		}
	}

	return nil, ErrSessionNotFound
}

// SelectDownstreamPath selects an active path endpoint to transmit return traffic to the client using SWRR.
func (st *SessionTable) SelectDownstreamPath(sessionID uint64) (uint8, *net.UDPAddr, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	s, exists := st.sessions[sessionID]
	if !exists {
		return 0, nil, ErrSessionNotFound
	}

	if s.currentWeights == nil {
		s.currentWeights = make(map[uint8]int)
	}

	now := time.Now()
	type eligibleEP struct {
		pathID uint8
		addr   *net.UDPAddr
		weight int
	}

	var eligible []eligibleEP
	totalWeight := 0
	activeSet := make(map[uint8]bool)

	for pathID := uint8(1); pathID <= 32; pathID++ {
		if ep, ok := s.Paths[pathID]; ok && ep.Addr != nil {
			if now.Sub(ep.LastSeen) <= 3000*time.Millisecond {
				w := ep.Weight
				if w < 1 {
					// Path reported as DOWN or 0 weight; exclude from downstream
					continue
				}
				eligible = append(eligible, eligibleEP{pathID: pathID, addr: ep.Addr, weight: w})
				totalWeight += w
				activeSet[pathID] = true
			}
		}
	}

	// Clean up stale or inactive paths from currentWeights
	for pid := range s.currentWeights {
		if !activeSet[pid] {
			delete(s.currentWeights, pid)
		}
	}

	// Fallback 1: If no path had Weight > 0, but some paths were seen within 3000ms
	if len(eligible) == 0 {
		for pathID := uint8(1); pathID <= 32; pathID++ {
			if ep, ok := s.Paths[pathID]; ok && ep.Addr != nil {
				if now.Sub(ep.LastSeen) <= 3000*time.Millisecond {
					eligible = append(eligible, eligibleEP{pathID: pathID, addr: ep.Addr, weight: 1})
					totalWeight += 1
					activeSet[pathID] = true
				}
			}
		}
	}

	// Fallback 2: If no path was seen within 3000ms, pick the most recently active path
	if len(eligible) == 0 {
		var bestPath uint8
		var bestAddr *net.UDPAddr
		var bestTime time.Time

		for pathID, ep := range s.Paths {
			if ep.Addr != nil {
				if bestAddr == nil || ep.LastSeen.After(bestTime) {
					bestPath = pathID
					bestAddr = ep.Addr
					bestTime = ep.LastSeen
				}
			}
		}

		if bestAddr == nil {
			return 0, nil, ErrNoActivePaths
		}
		return bestPath, bestAddr, nil
	}

	if len(eligible) == 1 {
		return eligible[0].pathID, eligible[0].addr, nil
	}

	// Smooth Weighted Round-Robin (SWRR)
	var best *eligibleEP
	bestVal := -math.MaxInt32

	for i := range eligible {
		ep := &eligible[i]
		s.currentWeights[ep.pathID] += ep.weight
		if s.currentWeights[ep.pathID] > bestVal {
			bestVal = s.currentWeights[ep.pathID]
			best = ep
		}
	}

	if best != nil {
		s.currentWeights[best.pathID] -= totalWeight
		return best.pathID, best.addr, nil
	}

	return eligible[0].pathID, eligible[0].addr, nil
}

// RecordDownstreamTx records transmitted bytes and packets on a path endpoint.
func (st *SessionTable) RecordDownstreamTx(sessionID uint64, pathID uint8, bytes int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if s, ok := st.sessions[sessionID]; ok {
		if ep, ok := s.Paths[pathID]; ok {
			ep.PacketsOut++
			ep.BytesOut += uint64(bytes)
		}
	}
}

// CheckAllReorderTimeouts iterates over all active sessions and flushes ready packets from expired gaps.
func (st *SessionTable) CheckAllReorderTimeouts() [][]byte {
	st.mu.RLock()
	defer st.mu.RUnlock()

	var allReady [][]byte
	for _, s := range st.sessions {
		if s.ReorderBuffer != nil {
			if ready := s.ReorderBuffer.CheckTimeout(); len(ready) > 0 {
				allReady = append(allReady, ready...)
			}
		}
	}
	return allReady
}

// NextDownstreamSeq atomically generates the next data sequence number for return traffic.
func (st *SessionTable) NextDownstreamSeq(sessionID uint64) uint32 {
	st.mu.RLock()
	s, exists := st.sessions[sessionID]
	st.mu.RUnlock()
	if !exists {
		return 1
	}
	return atomic.AddUint32(&s.downstreamSeq, 1)
}

// ProcessPacket maintains Phase 3B backward compatibility.
func (st *SessionTable) ProcessPacket(pkt *protocol.Packet, clientAddr *net.UDPAddr, psk []byte) (*protocol.Packet, error) {
	resp, _, err := st.ProcessIncomingPacket(pkt, clientAddr, psk)
	return resp, err
}

// ProcessIncomingPacket validates HMAC authentication, updates endpoints, and returns control response or data frames.
func (st *SessionTable) ProcessIncomingPacket(pkt *protocol.Packet, clientAddr *net.UDPAddr, psk []byte) (*protocol.Packet, [][]byte, error) {
	// 1. Mandatory HMAC verification for Version 2 packets
	if pkt.Version == protocol.ProtocolVersion2 {
		if !protocol.VerifyAuthTag(psk, pkt) {
			st.RecordSecurityDrop()
			return nil, nil, protocol.ErrInvalidAuthTag
		}
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()

	// 2. Lookup or initialize session record
	sess, exists := st.sessions[pkt.SessionID]
	if !exists {
		sess = &SessionRecord{
			SessionID:      pkt.SessionID,
			CreatedAt:      now,
			LastActivity:   now,
			Paths:          make(map[uint8]*PathEndpoint),
			ReorderBuffer:  reorder.NewReorderBuffer(reorder.DefaultReorderTimeout),
			currentWeights: make(map[uint8]int),
		}
		st.sessions[pkt.SessionID] = sess
	}
	sess.LastActivity = now

	// 3. Lookup or initialize path endpoint
	path, exists := sess.Paths[pkt.PathID]
	if !exists {
		path = &PathEndpoint{
			PathID: pkt.PathID,
			Weight: 5,
		}
		sess.Paths[pkt.PathID] = path
	}

	// 4. Update learned NAT endpoint mapping and counters
	path.Addr = clientAddr
	path.LastSeen = now
	path.PacketsIn++
	path.BytesIn += uint64(len(pkt.Payload))
	path.LastSeqNum = pkt.SeqNum

	// Update client-reported weight if present in Keepalive payload
	if pkt.Type == protocol.PacketTypeKeepalive && len(pkt.Payload) >= 1 {
		reportedWeight := int(pkt.Payload[0])
		if reportedWeight >= 0 && reportedWeight <= 10 {
			path.Weight = reportedWeight
		}
	}

	// 5. Handle Phase 3C Data Traffic
	if pkt.Type == protocol.PacketTypeData {
		// Auto-learn virtual IP from IPv4 header if payload is valid
		if len(pkt.Payload) >= 20 && (pkt.Payload[0]>>4) == 4 {
			srcIP := net.IP(pkt.Payload[12:16])
			sess.VirtualIP = srcIP
			st.virtualIPMap[srcIP.String()] = pkt.SessionID
		}

		// Insert into reorder buffer and return any in-order datagrams
		inOrderPackets := sess.ReorderBuffer.Insert(pkt.SeqNum, pkt.Payload)
		return nil, inOrderPackets, nil
	}

	// Default association for active session to standard client IP
	if sess.VirtualIP == nil {
		sess.VirtualIP = net.ParseIP("10.8.0.2")
		st.virtualIPMap["10.8.0.2"] = pkt.SessionID
	}

	// 6. Handle Phase 3B Control Traffic (Keepalive / Probe)
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
	// Preserve the sender's original transmit timestamp so RTT is evaluated in sender's local clock domain!
	resp.Timestamp = pkt.Timestamp
	if len(psk) > 0 {
		resp.AuthTag = protocol.ComputeAuthTag(psk, resp.SessionID, resp.PathID, resp.Type, resp.SeqNum, resp.Timestamp, resp.Payload)
	}
	path.PacketsOut++

	return resp, nil, nil
}
