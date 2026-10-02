//go:build windows

package pathhealth

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WindowsMonitor uses the native Windows IP Helper API (GetAdaptersAddresses)
// to inspect physical adapter link state, IP address, and default gateway without spawning processes.
type WindowsMonitor struct{}

// NewMonitor returns a new WindowsMonitor instance.
func NewMonitor() Monitor {
	return &WindowsMonitor{}
}

// CheckAll queries GetAdaptersAddresses and evaluates the operational state of the requested targets.
func (m *WindowsMonitor) CheckAll(targets []MonitoredTarget) (map[uint32]InterfaceState, error) {
	flags := uint32(windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_INCLUDE_PREFIX)
	family := uint32(windows.AF_INET)

	var size uint32 = 15000
	var buffer []byte
	var err error

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

	results := make(map[uint32]InterfaceState)
	for _, t := range targets {
		results[t.IfIndex] = InterfaceState{
			IfIndex: t.IfIndex,
			Name:    t.Name,
			IsUp:    false,
			Reason:  "adapter not found or disabled in OS",
		}
	}

	curr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
	for curr != nil {
		name := windows.UTF16PtrToString(curr.FriendlyName)
		ifIndex := curr.IfIndex
		operStatus := curr.OperStatus

		// Match by IfIndex or Name
		var matchedIndex uint32
		found := false
		for _, t := range targets {
			if t.IfIndex == ifIndex || (t.Name != "" && t.Name == name) {
				matchedIndex = t.IfIndex
				found = true
				break
			}
		}

		if found {
			var ipv4 net.IP
			for unicast := curr.FirstUnicastAddress; unicast != nil; unicast = unicast.Next {
				ip := unicast.Address.IP()
				if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
					ipv4 = ip.To4()
					break
				}
			}

			var gateway net.IP
			for gw := curr.FirstGatewayAddress; gw != nil; gw = gw.Next {
				ip := gw.Address.IP()
				if ip != nil && ip.To4() != nil && !ip.IsUnspecified() {
					gateway = ip.To4()
					break
				}
			}

			isUp := (operStatus == windows.IfOperStatusUp)
			hasIPv4 := (ipv4 != nil)
			hasGateway := (gateway != nil)

			var reason string
			if !isUp {
				reason = fmt.Sprintf("adapter oper status %d (down/disabled)", operStatus)
			} else if !hasIPv4 {
				reason = "missing IPv4 address"
			} else if !hasGateway {
				reason = "missing default gateway"
			} else {
				reason = "operational"
			}

			results[matchedIndex] = InterfaceState{
				IfIndex:    matchedIndex,
				Name:       name,
				IsUp:       isUp,
				HasIPv4:    hasIPv4,
				HasGateway: hasGateway,
				IPv4:       ipv4,
				Gateway:    gateway,
				Reason:     reason,
			}
		}

		curr = curr.Next
	}

	return results, nil
}
