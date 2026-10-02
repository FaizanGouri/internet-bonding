//go:build windows

package adapter

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WindowsDiscoverer queries network interfaces using the Windows IP Helper API.
type WindowsDiscoverer struct{}

// NewDiscoverer returns a new Discoverer instance for the Windows platform.
func NewDiscoverer() Discoverer {
	return &WindowsDiscoverer{}
}

// Discover queries the system for network adapters and classifies them.
func (d *WindowsDiscoverer) Discover() (*DiscoveryResult, error) {
	flags := uint32(windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_INCLUDE_PREFIX)
	family := uint32(windows.AF_INET) // Query IPv4 stack

	var size uint32 = 15000
	var buffer []byte
	var err error

	// Retry loop for buffer sizing in case network state changes concurrently
	for i := 0; i < 3; i++ {
		buffer = make([]byte, size)
		err = windows.GetAdaptersAddresses(
			family,
			flags,
			0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])),
			&size,
		)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, fmt.Errorf("GetAdaptersAddresses failed: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses failed after buffer resize: %w", err)
	}

	var physical []NetworkInterface
	var filtered []FilteredInterface

	curr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
	for curr != nil {
		name := windows.UTF16PtrToString(curr.FriendlyName)
		desc := windows.UTF16PtrToString(curr.Description)
		ifIndex := curr.IfIndex
		ifType := curr.IfType
		operStatus := curr.OperStatus

		// 1. Filter loopback adapters
		if IsLoopback(ifType) {
			filtered = append(filtered, FilteredInterface{
				Index:       ifIndex,
				Name:        name,
				Description: desc,
				IfType:      ifType,
				Reason:      ReasonLoopback,
			})
			curr = curr.Next
			continue
		}

		// 2. Filter tunnel pseudo-interfaces
		if IsTunnel(ifType) {
			filtered = append(filtered, FilteredInterface{
				Index:       ifIndex,
				Name:        name,
				Description: desc,
				IfType:      ifType,
				Reason:      ReasonTunnel,
			})
			curr = curr.Next
			continue
		}

		// 3. Filter known virtual, VPN, or container adapters
		if IsVirtualOrVPN(name, desc) {
			filtered = append(filtered, FilteredInterface{
				Index:       ifIndex,
				Name:        name,
				Description: desc,
				IfType:      ifType,
				Reason:      ReasonVirtualOrVPN,
			})
			curr = curr.Next
			continue
		}

		// 4. Classify hardware medium
		classifiedType := ClassifyType(ifType, name, desc)
		if classifiedType == TypeOther {
			filtered = append(filtered, FilteredInterface{
				Index:       ifIndex,
				Name:        name,
				Description: desc,
				IfType:      ifType,
				Reason:      ReasonUnknownType,
			})
			curr = curr.Next
			continue
		}

		// Extract MAC address
		var mac net.HardwareAddr
		if curr.PhysicalAddressLength > 0 && curr.PhysicalAddressLength <= 8 {
			mac = make([]byte, curr.PhysicalAddressLength)
			copy(mac, curr.PhysicalAddress[:curr.PhysicalAddressLength])
		}

		// Extract Primary IPv4 and Subnet Mask
		var ipv4 net.IP
		var subnetMask net.IPMask
		for unicast := curr.FirstUnicastAddress; unicast != nil; unicast = unicast.Next {
			ip := unicast.Address.IP()
			if ip != nil && ip.To4() != nil {
				ipv4 = ip.To4()
				prefixLen := int(unicast.OnLinkPrefixLength)
				if prefixLen > 0 && prefixLen <= 32 {
					subnetMask = net.CIDRMask(prefixLen, 32)
				}
				break
			}
		}

		// Extract Default Gateway
		var gateway net.IP
		for gw := curr.FirstGatewayAddress; gw != nil; gw = gw.Next {
			ip := gw.Address.IP()
			if ip != nil && ip.To4() != nil && !ip.IsUnspecified() {
				gateway = ip.To4()
				break
			}
		}

		isUp := (operStatus == windows.IfOperStatusUp)

		physical = append(physical, NetworkInterface{
			Index:       ifIndex,
			Name:        name,
			Description: desc,
			MAC:         mac,
			IPv4:        ipv4,
			SubnetMask:  subnetMask,
			Gateway:     gateway,
			Type:        classifiedType,
			IsUp:        isUp,
		})

		curr = curr.Next
	}

	return &DiscoveryResult{
		Physical: physical,
		Filtered: filtered,
	}, nil
}
