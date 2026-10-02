//go:build !windows

package tunnel

import (
	"fmt"
	"net"
	"time"
)

// NewClientTunnel establishes a UDP socket bound to local IP on non-Windows platforms.
func NewClientTunnel(cfg TunnelConfig) (*ClientTunnel, error) {
	if cfg.LocalIP == nil || cfg.LocalIP.To4() == nil {
		return nil, fmt.Errorf("valid local IPv4 required")
	}
	if cfg.RemoteAddr == nil {
		return nil, fmt.Errorf("remote VPS address required")
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 1000 * time.Millisecond
	}

	bindAddr := fmt.Sprintf("%s:0", cfg.LocalIP.String())
	conn, err := net.ListenPacket("udp4", bindAddr)
	if err != nil {
		return nil, err
	}

	if udpConn, ok := conn.(*net.UDPConn); ok {
		const targetBuf = 4 * 1024 * 1024
		_ = udpConn.SetReadBuffer(targetBuf)
		_ = udpConn.SetWriteBuffer(targetBuf)
	}

	return &ClientTunnel{
		cfg:     cfg,
		conn:    conn,
		readBuf: make([]byte, 2048),
	}, nil
}
