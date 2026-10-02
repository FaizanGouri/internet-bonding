package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"internet-bonding/client/internal/adapter"
	"internet-bonding/protocol"
)

// GenerateSessionID produces a cryptographically secure 64-bit random session identifier.
func GenerateSessionID() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	id := binary.BigEndian.Uint64(b[:])
	if id == 0 {
		id = 1
	}
	return id
}

// TxItem represents a queued datagram destined for physical transmission.
type TxItem struct {
	Raw  []byte
	Size int
	Seq  uint32
}

// ManagedPath represents an interface-agnostic physical tunnel path within a bonding session.
type ManagedPath struct {
	PathID          uint8
	Interface       adapter.NetworkInterface
	Tunnel          *ClientTunnel
	Health          *PathHealth
	seqNum          uint32
	bytesSent       uint64
	packetsSent     uint64
	packetsAssigned uint64
	bytesRecv       uint64
	packetsRecv     uint64

	txQueue    chan TxItem
	workerStop chan struct{}
	workerDone sync.WaitGroup
	workerMu   sync.Mutex
	workerRun  bool
}

func (mp *ManagedPath) NextSeq() uint32 {
	return atomic.AddUint32(&mp.seqNum, 1)
}

// RecordTx increments per-path transmitted bytes and packets.
func (mp *ManagedPath) RecordTx(bytes int) {
	atomic.AddUint64(&mp.bytesSent, uint64(bytes))
	atomic.AddUint64(&mp.packetsSent, 1)
}

// RecordRx increments per-path received bytes and packets.
func (mp *ManagedPath) RecordRx(bytes int) {
	atomic.AddUint64(&mp.bytesRecv, uint64(bytes))
	atomic.AddUint64(&mp.packetsRecv, 1)
}

// TrafficStats returns atomic snapshots of transmitted and received traffic on this path.
func (mp *ManagedPath) TrafficStats() (txBytes, txPkts, rxBytes, rxPkts uint64) {
	return atomic.LoadUint64(&mp.bytesSent),
		atomic.LoadUint64(&mp.packetsSent),
		atomic.LoadUint64(&mp.bytesRecv),
		atomic.LoadUint64(&mp.packetsRecv)
}

// PacketConn returns the underlying packet socket connection, if open.
func (mp *ManagedPath) PacketConn() net.PacketConn {
	if mp.Tunnel != nil {
		return mp.Tunnel.PacketConn()
	}
	return nil
}

// WriteRaw transmits raw packet bytes directly to the remote endpoint.
func (mp *ManagedPath) WriteRaw(data []byte, addr *net.UDPAddr) (int, error) {
	if mp.Tunnel == nil || mp.Tunnel.conn == nil {
		return 0, fmt.Errorf("path %d socket not bound", mp.PathID)
	}
	return mp.Tunnel.conn.WriteTo(data, addr)
}

// StartTxWorker initializes a bounded TX queue and launches a dedicated path transmission worker.
func (mp *ManagedPath) StartTxWorker(remoteAddr *net.UDPAddr, queueCap int) {
	mp.workerMu.Lock()
	defer mp.workerMu.Unlock()

	if mp.workerRun {
		return
	}
	if queueCap <= 0 {
		queueCap = 512
	}
	mp.txQueue = make(chan TxItem, queueCap)
	mp.workerStop = make(chan struct{})
	mp.workerRun = true

	mp.workerDone.Add(1)
	go func() {
		defer mp.workerDone.Done()
		for {
			select {
			case <-mp.workerStop:
				// Drain any remaining packets
				for {
					select {
					case item := <-mp.txQueue:
						_, _ = mp.WriteRaw(item.Raw, remoteAddr)
						mp.RecordTx(item.Size)
					default:
						return
					}
				}
			case item, ok := <-mp.txQueue:
				if !ok {
					return
				}
				_, err := mp.WriteRaw(item.Raw, remoteAddr)
				if err == nil {
					mp.RecordTx(item.Size)
				} else {
					mp.Health.RecordProbeResult(false, 0, err)
				}
			}
		}
	}()
}

// StopTxWorker gracefully stops the path's transmission worker and drains pending items.
func (mp *ManagedPath) StopTxWorker() {
	mp.workerMu.Lock()
	if !mp.workerRun {
		mp.workerMu.Unlock()
		return
	}
	mp.workerRun = false
	close(mp.workerStop)
	mp.workerMu.Unlock()
	mp.workerDone.Wait()
}

// TxQueueDepth returns the current number of packets buffered in this path's TX queue.
func (mp *ManagedPath) TxQueueDepth() int {
	if mp.txQueue == nil {
		return 0
	}
	return len(mp.txQueue)
}

// PacketsAssigned returns the total number of packets queued to this path.
func (mp *ManagedPath) PacketsAssigned() uint64 {
	return atomic.LoadUint64(&mp.packetsAssigned)
}

// TryEnqueueTx attempts non-blocking submission of a packet to this path's worker queue.
// Returns false if queue is saturated or worker is not running.
func (mp *ManagedPath) TryEnqueueTx(raw []byte, size int, seq uint32) bool {
	if mp.txQueue == nil {
		return false
	}
	select {
	case mp.txQueue <- TxItem{Raw: raw, Size: size, Seq: seq}:
		atomic.AddUint64(&mp.packetsAssigned, 1)
		return true
	default:
		return false
	}
}

// EnqueueTxOrBlock submits a packet to the TX queue with a timeout to apply backpressure.
func (mp *ManagedPath) EnqueueTxOrBlock(raw []byte, size int, seq uint32, timeout time.Duration) bool {
	if mp.txQueue == nil {
		return false
	}
	select {
	case mp.txQueue <- TxItem{Raw: raw, Size: size, Seq: seq}:
		atomic.AddUint64(&mp.packetsAssigned, 1)
		return true
	case <-time.After(timeout):
		return false
	}
}

// TunnelManager coordinates multiple dynamic physical tunnels under a unified SessionID.
type TunnelManager struct {
	mu         sync.RWMutex
	sessionID  uint64
	psk        []byte
	remoteAddr *net.UDPAddr
	paths      []*ManagedPath
}

// NewTunnelManager dynamically assigns physical interfaces to PathID 1, PathID 2, etc.
// INTERFACE-AGNOSTIC: Supports Wi-Fi + Ethernet, Wi-Fi + USB tethering, dual-Ethernet, etc.
func NewTunnelManager(candidates []adapter.NetworkInterface, remoteAddr *net.UDPAddr, psk []byte) (*TunnelManager, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("at least one physical interface candidate required")
	}

	sessionID := GenerateSessionID()
	tm := &TunnelManager{
		sessionID:  sessionID,
		psk:        psk,
		remoteAddr: remoteAddr,
		paths:      make([]*ManagedPath, 0, len(candidates)),
	}

	for i, iface := range candidates {
		pathID := uint8(i + 1)
		health := NewPathHealth(pathID, iface.Name, iface.Index, iface.IPv4)

		mp := &ManagedPath{
			PathID:    pathID,
			Interface: iface,
			Health:    health,
		}

		// Only bind sockets for active interfaces with valid non-APIPA IPv4 and gateway
		if iface.IsUp && iface.IPv4 != nil && !iface.IPv4.IsLinkLocalUnicast() && iface.Gateway != nil {
			cfg := TunnelConfig{
				InterfaceName: iface.Name,
				IfIndex:       iface.Index,
				LocalIP:       iface.IPv4,
				RemoteAddr:    remoteAddr,
				ReadTimeout:   1000 * time.Millisecond,
			}

			tunnel, err := NewClientTunnel(cfg)
			if err != nil {
				return nil, fmt.Errorf("failed to bind socket for path %d (%s): %w", pathID, iface.Name, err)
			}
			mp.Tunnel = tunnel
		}

		tm.paths = append(tm.paths, mp)
	}

	return tm, nil
}

// SessionID returns the active 64-bit session identifier.
func (tm *TunnelManager) SessionID() uint64 {
	return tm.sessionID
}

// RemoteAddr returns the configured VPS address.
func (tm *TunnelManager) RemoteAddr() *net.UDPAddr {
	return tm.remoteAddr
}

// PSK returns the pre-shared key.
func (tm *TunnelManager) PSK() []byte {
	return tm.psk
}

// Paths returns a list of all managed paths.
func (tm *TunnelManager) Paths() []*ManagedPath {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.paths
}

// GetPath returns the managed path for a given PathID.
func (tm *TunnelManager) GetPath(pathID uint8) *ManagedPath {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	for _, p := range tm.paths {
		if p.PathID == pathID {
			return p
		}
	}
	return nil
}

// SendKeepalive transmits an authenticated Keepalive frame on the specified path and updates health state.
func (tm *TunnelManager) SendKeepalive(pathID uint8) (*protocol.Packet, time.Duration, error) {
	p := tm.GetPath(pathID)
	if p == nil {
		return nil, 0, fmt.Errorf("path %d not found", pathID)
	}
	if p.Tunnel == nil {
		p.Health.RecordProbeResult(false, 0, fmt.Errorf("path is disconnected/unbound"))
		return nil, 0, fmt.Errorf("path %d is not bound to an active socket", pathID)
	}

	seq := p.NextSeq()
	pkt := protocol.NewV2Packet(protocol.PacketTypeKeepalive, tm.sessionID, pathID, seq, nil, tm.psk)
	raw, err := pkt.MarshalBinary()
	if err != nil {
		return nil, 0, err
	}

	start := time.Now()
	_, err = p.Tunnel.conn.WriteTo(raw, tm.remoteAddr)
	if err != nil {
		p.Health.RecordProbeResult(false, 0, err)
		return nil, 0, err
	}

	_ = p.Tunnel.conn.SetReadDeadline(time.Now().Add(1000 * time.Millisecond))

	buf := make([]byte, 2048)
	for {
		n, from, err := p.Tunnel.conn.ReadFrom(buf)
		if err != nil {
			p.Health.RecordProbeResult(false, 0, err)
			return nil, 0, err
		}

		rtt := time.Since(start)

		var resp protocol.Packet
		if err := resp.UnmarshalBinary(buf[:n]); err != nil {
			continue
		}

		// Verify HMAC on response
		if len(tm.psk) > 0 && !protocol.VerifyAuthTag(tm.psk, &resp) {
			continue
		}

		if resp.Type == protocol.PacketTypeKeepaliveAck && resp.SeqNum == seq && resp.SessionID == tm.sessionID {
			_ = from
			p.Health.RecordProbeResult(true, rtt, nil)
			return &resp, rtt, nil
		}
	}
}

// SendProbe transmits an authenticated test probe frame with payload on the specified path.
func (tm *TunnelManager) SendProbe(pathID uint8, payload []byte) (*protocol.Packet, time.Duration, error) {
	p := tm.GetPath(pathID)
	if p == nil {
		return nil, 0, fmt.Errorf("path %d not found", pathID)
	}
	if p.Tunnel == nil {
		p.Health.RecordProbeResult(false, 0, fmt.Errorf("path is disconnected/unbound"))
		return nil, 0, fmt.Errorf("path %d is not bound to an active socket", pathID)
	}

	seq := p.NextSeq()
	pkt := protocol.NewV2Packet(protocol.PacketTypeProbe, tm.sessionID, pathID, seq, payload, tm.psk)
	raw, err := pkt.MarshalBinary()
	if err != nil {
		return nil, 0, err
	}

	start := time.Now()
	_, err = p.Tunnel.conn.WriteTo(raw, tm.remoteAddr)
	if err != nil {
		p.Health.RecordProbeResult(false, 0, err)
		return nil, 0, err
	}

	_ = p.Tunnel.conn.SetReadDeadline(time.Now().Add(1000 * time.Millisecond))

	buf := make([]byte, 2048)
	for {
		n, from, err := p.Tunnel.conn.ReadFrom(buf)
		if err != nil {
			p.Health.RecordProbeResult(false, 0, err)
			return nil, 0, err
		}

		rtt := time.Since(start)

		var resp protocol.Packet
		if err := resp.UnmarshalBinary(buf[:n]); err != nil {
			continue
		}

		// Verify HMAC on response
		if len(tm.psk) > 0 && !protocol.VerifyAuthTag(tm.psk, &resp) {
			continue
		}

		if resp.Type == protocol.PacketTypeEcho && resp.SeqNum == seq && resp.SessionID == tm.sessionID {
			_ = from
			p.Health.RecordProbeResult(true, rtt, nil)
			return &resp, rtt, nil
		}
	}
}

// StartAllTxWorkers starts dedicated asynchronous transmit workers for all active paths.
func (tm *TunnelManager) StartAllTxWorkers(queueCap int) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	for _, p := range tm.paths {
		if p.Tunnel != nil {
			p.StartTxWorker(tm.remoteAddr, queueCap)
		}
	}
}

// Close releases all open socket connections and stops all TX workers across all managed paths.
func (tm *TunnelManager) Close() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for _, p := range tm.paths {
		p.StopTxWorker()
		if p.Tunnel != nil {
			_ = p.Tunnel.Close()
		}
	}
}
