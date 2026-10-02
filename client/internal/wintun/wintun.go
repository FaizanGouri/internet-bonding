package wintun

import "io"

// VirtualAdapter provides packet-level Layer 3 read/write operations to the virtual network adapter.
type VirtualAdapter interface {
	io.ReadWriteCloser
	AdapterName() string
	IfIndex() uint32
}
