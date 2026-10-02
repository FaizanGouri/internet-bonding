package tunnel

import (
	"fmt"
	"net"
	"time"

	"internet-bonding/protocol"
)

// TunnelConfig defines client connection parameters.
type TunnelConfig struct {
	InterfaceName string
	IfIndex       uint32
	LocalIP       net.IP
	RemoteAddr    *net.UDPAddr
	ReadTimeout   time.Duration
}

// TunnelStats holds test transmission metrics.
type TunnelStats struct {
	PacketsSent     uint32
	PacketsReceived uint32
	LossPercent     float64
	MinRTT          time.Duration
	AvgRTT          time.Duration
	MaxRTT          time.Duration
}

func (s TunnelStats) String() string {
	return fmt.Sprintf("Packets Sent: %d | Packets Received: %d | Loss: %.1f%%\nMin RTT: %.2f ms | Avg RTT: %.2f ms | Max RTT: %.2f ms",
		s.PacketsSent, s.PacketsReceived, s.LossPercent,
		float64(s.MinRTT.Microseconds())/1000.0,
		float64(s.AvgRTT.Microseconds())/1000.0,
		float64(s.MaxRTT.Microseconds())/1000.0)
}

// ClientTunnel manages an interface-bound UDP tunnel to the VPS.
type ClientTunnel struct {
	cfg     TunnelConfig
	conn    net.PacketConn
	readBuf []byte
}

// Close releases the tunnel socket resources.
func (t *ClientTunnel) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// LocalAddr returns the local socket address.
func (t *ClientTunnel) LocalAddr() net.Addr {
	if t.conn != nil {
		return t.conn.LocalAddr()
	}
	return nil
}

// RemoteAddr returns the configured VPS address.
func (t *ClientTunnel) RemoteAddr() *net.UDPAddr {
	return t.cfg.RemoteAddr
}

// PacketConn returns the underlying packet socket connection.
func (t *ClientTunnel) PacketConn() net.PacketConn {
	return t.conn
}

// SendProbe transmits a test packet and waits synchronously for the echo response.
func (t *ClientTunnel) SendProbe(seqNum uint32, payload []byte) (*protocol.Packet, time.Duration, error) {
	pkt := protocol.NewProbePacket(seqNum, payload)
	raw, err := pkt.MarshalBinary()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal probe: %w", err)
	}

	start := time.Now()
	_, err = t.conn.WriteTo(raw, t.cfg.RemoteAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("socket write error: %w", err)
	}

	deadline := time.Now().Add(t.cfg.ReadTimeout)
	if err := t.conn.SetReadDeadline(deadline); err != nil {
		return nil, 0, fmt.Errorf("failed to set read deadline: %w", err)
	}

	for {
		n, from, err := t.conn.ReadFrom(t.readBuf)
		if err != nil {
			return nil, 0, err
		}

		rtt := time.Since(start)

		var resp protocol.Packet
		if err := resp.UnmarshalBinary(t.readBuf[:n]); err != nil {
			// Ignore non-protocol packets
			continue
		}

		if resp.Type == protocol.PacketTypeEcho && resp.SeqNum == seqNum {
			_ = from
			return &resp, rtt, nil
		}
	}
}

// ComputeStats calculates aggregate transmission statistics from sample RTTs.
func ComputeStats(sent, received uint32, rtts []time.Duration) TunnelStats {
	stats := TunnelStats{
		PacketsSent:     sent,
		PacketsReceived: received,
	}

	if sent > 0 {
		stats.LossPercent = (float64(sent-received) / float64(sent)) * 100.0
	}

	if len(rtts) == 0 {
		return stats
	}

	minRTT := rtts[0]
	maxRTT := rtts[0]
	var total time.Duration

	for _, d := range rtts {
		if d < minRTT {
			minRTT = d
		}
		if d > maxRTT {
			maxRTT = d
		}
		total += d
	}

	stats.MinRTT = minRTT
	stats.MaxRTT = maxRTT
	stats.AvgRTT = total / time.Duration(len(rtts))

	return stats
}
