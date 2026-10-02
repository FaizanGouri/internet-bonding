//go:build windows

package tunnel

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// toNetworkByteOrder converts host byte order uint32 to network byte order DWORD.
func toNetworkByteOrder(val uint32) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], val)
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

// NewClientTunnel establishes a UDP socket bound to a specific Windows interface index and local IP.
func NewClientTunnel(cfg TunnelConfig) (*ClientTunnel, error) {
	if cfg.LocalIP == nil || cfg.LocalIP.To4() == nil {
		return nil, fmt.Errorf("valid local IPv4 required for interface binding")
	}
	if cfg.RemoteAddr == nil {
		return nil, fmt.Errorf("remote VPS UDP address required")
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 1000 * time.Millisecond
	}

	optVal := toNetworkByteOrder(cfg.IfIndex)

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				// IPPROTO_IP = 0, IP_UNICAST_IF = 31 in Winsock ws2ipdef.h
				sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(optVal))
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}

	bindAddr := fmt.Sprintf("%s:0", cfg.LocalIP.String())
	conn, err := lc.ListenPacket(nil, "udp4", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind UDP socket to %s with IP_UNICAST_IF=%d: %w", bindAddr, cfg.IfIndex, err)
	}

	return &ClientTunnel{
		cfg:     cfg,
		conn:    conn,
		readBuf: make([]byte, 2048),
	}, nil
}
