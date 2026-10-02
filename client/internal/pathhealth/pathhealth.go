package pathhealth

import "net"

// InterfaceState represents the real-time physical network adapter status reported by the OS.
type InterfaceState struct {
	IfIndex    uint32
	Name       string
	IsUp       bool
	HasIPv4    bool
	HasGateway bool
	IPv4       net.IP
	Gateway    net.IP
	Reason     string
}

// Available returns true if the physical adapter is operationally UP and has a valid IPv4 address and default gateway.
func (s InterfaceState) Available() bool {
	return s.IsUp && s.HasIPv4 && s.HasGateway
}

// MonitoredTarget identifies an adapter to inspect by interface index and/or friendly name.
type MonitoredTarget struct {
	IfIndex uint32
	Name    string
}

// Monitor defines the interface for polling OS-level physical network adapter statuses.
type Monitor interface {
	CheckAll(targets []MonitoredTarget) (map[uint32]InterfaceState, error)
}
