package adapter

import (
	"strings"

	"golang.org/x/sys/windows"
)

// VirtualAdapterKeywords contains substring patterns matching virtual, VPN, or emulated adapters.
var VirtualAdapterKeywords = []string{
	"virtual",
	"vmware",
	"virtualbox",
	"hyper-v",
	"vethernet",
	"tap-",
	"tap ",
	"wintun",
	"wireguard",
	"tailscale",
	"zerotier",
	"npcap",
	"bluetooth",
	"loopback",
	"host-only",
	"wsl",
	"pseudo",
	"teredo",
	"isatap",
	"docker",
	"openvpn",
	"cisco",
	"fortinet",
	"checkpoint",
	"pango",
	"wan miniport",
	"direct virtual",
	"wi-fi direct",
	"wifi direct",
}

// IsLoopback returns true if the adapter type is an RFC loopback device.
func IsLoopback(ifType uint32) bool {
	return ifType == windows.IF_TYPE_SOFTWARE_LOOPBACK
}

// IsTunnel returns true if the adapter type is a tunnel pseudo-interface.
func IsTunnel(ifType uint32) bool {
	return ifType == windows.IF_TYPE_TUNNEL
}

// IsVirtualOrVPN inspects adapter name and description against known virtualization keywords.
func IsVirtualOrVPN(name, desc string) bool {
	combined := strings.ToLower(name + " " + desc)
	for _, kw := range VirtualAdapterKeywords {
		if strings.Contains(combined, kw) {
			return true
		}
	}
	return false
}

// ClassifyType categorizes the interface based on Windows IfType and descriptive markers.
func ClassifyType(ifType uint32, name, desc string) InterfaceType {
	combined := strings.ToLower(name + " " + desc)

	if ifType == windows.IF_TYPE_IEEE80211 {
		return TypeWiFi
	}

	if strings.Contains(combined, "wi-fi") ||
		strings.Contains(combined, "wireless") ||
		strings.Contains(combined, "802.11") ||
		strings.Contains(combined, "wlan") {
		return TypeWiFi
	}

	if ifType == windows.IF_TYPE_ETHERNET_CSMACD {
		return TypeEthernet
	}

	return TypeOther
}
