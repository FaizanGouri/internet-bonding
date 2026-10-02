package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"

	"internet-bonding/protocol"
)

func TestPacket_MarshalUnmarshal(t *testing.T) {
	payload := []byte("AntigravityPhase3ATestPayload")
	orig := protocol.NewProbePacket(42, payload)

	data, err := orig.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	var parsed protocol.Packet
	if err := parsed.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if parsed.Magic != protocol.MagicHeader {
		t.Errorf("Magic = 0x%08X; want 0x%08X", parsed.Magic, protocol.MagicHeader)
	}
	if parsed.Version != protocol.ProtocolVersion {
		t.Errorf("Version = %d; want %d", parsed.Version, protocol.ProtocolVersion)
	}
	if parsed.Type != protocol.PacketTypeProbe {
		t.Errorf("Type = %d; want %d", parsed.Type, protocol.PacketTypeProbe)
	}
	if parsed.SeqNum != 42 {
		t.Errorf("SeqNum = %d; want 42", parsed.SeqNum)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Errorf("Payload = %s; want %s", string(parsed.Payload), string(payload))
	}
	if parsed.Timestamp.UnixNano() != orig.Timestamp.UnixNano() {
		t.Errorf("Timestamp mismatch: got %v, want %v", parsed.Timestamp, orig.Timestamp)
	}
}

func TestPacket_InvalidMagic(t *testing.T) {
	orig := protocol.NewProbePacket(1, nil)
	data, _ := orig.MarshalBinary()
	data[0] = 0xFF // corrupt magic

	var parsed protocol.Packet
	if err := parsed.UnmarshalBinary(data); err == nil {
		t.Errorf("Expected error for invalid magic, got nil")
	}
}

func TestPacket_InvalidVersion(t *testing.T) {
	orig := protocol.NewProbePacket(1, nil)
	data, _ := orig.MarshalBinary()
	data[4] = 99 // unsupported version

	var parsed protocol.Packet
	if err := parsed.UnmarshalBinary(data); err == nil {
		t.Errorf("Expected error for unsupported version, got nil")
	}
}

func TestComputeStats(t *testing.T) {
	rtts := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
	}

	stats := ComputeStats(4, 3, rtts)
	if stats.PacketsSent != 4 {
		t.Errorf("PacketsSent = %d; want 4", stats.PacketsSent)
	}
	if stats.PacketsReceived != 3 {
		t.Errorf("PacketsReceived = %d; want 3", stats.PacketsReceived)
	}
	if stats.LossPercent != 25.0 {
		t.Errorf("LossPercent = %.1f; want 25.0", stats.LossPercent)
	}
	if stats.MinRTT != 10*time.Millisecond {
		t.Errorf("MinRTT = %v; want 10ms", stats.MinRTT)
	}
	if stats.MaxRTT != 30*time.Millisecond {
		t.Errorf("MaxRTT = %v; want 30ms", stats.MaxRTT)
	}
	if stats.AvgRTT != 20*time.Millisecond {
		t.Errorf("AvgRTT = %v; want 20ms", stats.AvgRTT)
	}
}

func TestLoopbackEcho(t *testing.T) {
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	stopServer := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)
		for {
			select {
			case <-stopServer:
				return
			default:
				serverConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, clientAddr, err := serverConn.ReadFrom(buf)
				if err != nil {
					continue
				}

				var req protocol.Packet
				if err := req.UnmarshalBinary(buf[:n]); err != nil {
					continue
				}

				// Small delay to ensure measurable non-zero RTT
				time.Sleep(2 * time.Millisecond)

				req.Type = protocol.PacketTypeEcho
				respBytes, _ := req.MarshalBinary()
				serverConn.WriteTo(respBytes, clientAddr)
			}
		}
	}()
	defer close(stopServer)

	cfg := TunnelConfig{
		InterfaceName: "Loopback",
		IfIndex:       1,
		LocalIP:       net.ParseIP("127.0.0.1"),
		RemoteAddr:    serverAddr,
		ReadTimeout:   500 * time.Millisecond,
	}

	tunnel, err := NewClientTunnel(cfg)
	if err != nil {
		t.Fatalf("NewClientTunnel failed: %v", err)
	}
	defer tunnel.Close()

	resp, rtt, err := tunnel.SendProbe(101, []byte("HelloLoopback"))
	if err != nil {
		t.Fatalf("SendProbe failed: %v", err)
	}

	if resp.SeqNum != 101 {
		t.Errorf("SeqNum = %d; want 101", resp.SeqNum)
	}
	if resp.Type != protocol.PacketTypeEcho {
		t.Errorf("Type = %d; want %d", resp.Type, protocol.PacketTypeEcho)
	}
	if rtt < 0 {
		t.Errorf("Expected non-negative RTT, got %v", rtt)
	}
}
