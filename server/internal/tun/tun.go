package tun

import (
	"io"
)

// Device represents an instantiated Layer 3 TUN network interface.
type Device interface {
	io.ReadWriteCloser
	Name() string
}
