package adapter

import (
	"fmt"
	"net"
)

// InterfaceType categorizes the physical network medium.
type InterfaceType string

const (
	TypeEthernet InterfaceType = "Ethernet"
	TypeWiFi     InterfaceType = "Wi-Fi"
	TypeOther    InterfaceType = "Other"
)

// FilterReason documents why a discovered interface was excluded from bonding candidates.
type FilterReason string

const (
	ReasonLoopback     FilterReason = "Loopback interface"
	ReasonVirtualOrVPN FilterReason = "Virtual, VPN, or container adapter"
	ReasonTunnel       FilterReason = "Tunnel or pseudo-interface"
	ReasonNoIPv4       FilterReason = "No valid IPv4 address assigned"
	ReasonNotUp        FilterReason = "Interface is disconnected or down"
	ReasonNoGateway    FilterReason = "No active IPv4 default gateway found"
	ReasonInvalidMAC   FilterReason = "Missing or invalid physical MAC address"
	ReasonUnknownType  FilterReason = "Unsupported interface type"
)

// NetworkInterface represents a verified physical network adapter ready for bonding.
type NetworkInterface struct {
	Index       uint32           `json:"index"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	MAC         net.HardwareAddr `json:"mac"`
	IPv4        net.IP           `json:"ipv4"`
	SubnetMask  net.IPMask       `json:"subnet_mask"`
	Gateway     net.IP           `json:"gateway"`
	Type        InterfaceType    `json:"type"`
	IsUp        bool             `json:"is_up"`
}

func (ni NetworkInterface) String() string {
	status := "DOWN"
	if ni.IsUp {
		status = "UP"
	}
	gw := "<none>"
	if len(ni.Gateway) > 0 {
		gw = ni.Gateway.String()
	}
	ipStr := "<none>"
	if len(ni.IPv4) > 0 {
		if len(ni.SubnetMask) == 4 {
			ipStr = fmt.Sprintf("%s (mask: %d.%d.%d.%d)", ni.IPv4, ni.SubnetMask[0], ni.SubnetMask[1], ni.SubnetMask[2], ni.SubnetMask[3])
		} else {
			ipStr = ni.IPv4.String()
		}
	}
	macStr := "<none>"
	if len(ni.MAC) > 0 {
		macStr = ni.MAC.String()
	}

	return fmt.Sprintf("Interface: %s\nType: %s\nIfIndex: %d\nIPv4: %s\nGateway: %s\nStatus: %s\nDescription: %s\nMAC: %s",
		ni.Name, ni.Type, ni.Index, ipStr, gw, status, ni.Description, macStr)
}

// FilteredInterface records metadata and rejection rationale for non-viable interfaces.
type FilteredInterface struct {
	Index       uint32       `json:"index"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	IfType      uint32       `json:"if_type"`
	Reason      FilterReason `json:"reason"`
}

func (fi FilteredInterface) String() string {
	return fmt.Sprintf("[Filtered] Name: %-25s | Desc: %-35s | Reason: %s",
		fi.Name, fi.Description, fi.Reason)
}

// DiscoveryResult aggregates all discovered physical interfaces alongside filtered items.
type DiscoveryResult struct {
	Physical []NetworkInterface  `json:"physical"`
	Filtered []FilteredInterface `json:"filtered"`
}

// Discoverer defines the network discovery contract.
type Discoverer interface {
	Discover() (*DiscoveryResult, error)
}
