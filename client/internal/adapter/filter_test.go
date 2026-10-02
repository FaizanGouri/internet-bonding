package adapter

import (
	"net"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsLoopback(t *testing.T) {
	if !IsLoopback(windows.IF_TYPE_SOFTWARE_LOOPBACK) {
		t.Errorf("Expected IF_TYPE_SOFTWARE_LOOPBACK to be identified as loopback")
	}
	if IsLoopback(windows.IF_TYPE_ETHERNET_CSMACD) {
		t.Errorf("Expected Ethernet to not be identified as loopback")
	}
}

func TestIsTunnel(t *testing.T) {
	if !IsTunnel(windows.IF_TYPE_TUNNEL) {
		t.Errorf("Expected IF_TYPE_TUNNEL to be identified as tunnel")
	}
	if IsTunnel(windows.IF_TYPE_IEEE80211) {
		t.Errorf("Expected Wi-Fi to not be identified as tunnel")
	}
}

func TestIsVirtualOrVPN(t *testing.T) {
	cases := []struct {
		name     string
		desc     string
		expected bool
	}{
		{"Ethernet", "Realtek PCIe GbE Family Controller", false},
		{"Wi-Fi", "Intel(R) Wi-Fi 6 AX201 160MHz", false},
		{"Ethernet 2", "VMware Virtual Ethernet Adapter for VMnet1", true},
		{"vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter", true},
		{"Tailscale", "Tailscale Tunnel", true},
		{"WireGuard", "WireGuard Tunnel", true},
		{"OpenVPN TAP", "TAP-Windows Adapter V9", true},
		{"Wintun", "Wintun Userspace Tunnel", true},
		{"WAN Miniport (IP)", "WAN Miniport (IP)", true},
		{"Local Area Connection* 1", "Microsoft Wi-Fi Direct Virtual Adapter", true},
		{"Bluetooth Network Connection", "Bluetooth Device (Personal Area Network)", true},
	}

	for _, c := range cases {
		got := IsVirtualOrVPN(c.name, c.desc)
		if got != c.expected {
			t.Errorf("IsVirtualOrVPN(%q, %q) = %v; want %v", c.name, c.desc, got, c.expected)
		}
	}
}

func TestClassifyType(t *testing.T) {
	cases := []struct {
		ifType   uint32
		name     string
		desc     string
		expected InterfaceType
	}{
		{windows.IF_TYPE_IEEE80211, "Wi-Fi", "Intel Wi-Fi 6", TypeWiFi},
		{windows.IF_TYPE_ETHERNET_CSMACD, "Wi-Fi", "Broadcom 802.11ac Wireless Network Adapter", TypeWiFi},
		{windows.IF_TYPE_ETHERNET_CSMACD, "Ethernet", "Realtek PCIe GbE Family Controller", TypeEthernet},
		{windows.IF_TYPE_OTHER, "Unknown", "Unknown Adapter", TypeOther},
	}

	for _, c := range cases {
		got := ClassifyType(c.ifType, c.name, c.desc)
		if got != c.expected {
			t.Errorf("ClassifyType(%d, %q, %q) = %v; want %v", c.ifType, c.name, c.desc, got, c.expected)
		}
	}
}

func TestNetworkInterfaceString(t *testing.T) {
	ni := NetworkInterface{
		Index:       12,
		Name:        "Ethernet",
		Description: "Realtek GbE",
		MAC:         net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		IPv4:        net.ParseIP("192.168.1.50"),
		SubnetMask:  net.CIDRMask(24, 32),
		Gateway:     net.ParseIP("192.168.1.1"),
		Type:        TypeEthernet,
		IsUp:        true,
	}

	str := ni.String()
	if !strings.Contains(str, "Interface: Ethernet") ||
		!strings.Contains(str, "Type: Ethernet") ||
		!strings.Contains(str, "IfIndex: 12") ||
		!strings.Contains(str, "IPv4: 192.168.1.50") ||
		!strings.Contains(str, "Gateway: 192.168.1.1") ||
		!strings.Contains(str, "Status: UP") {
		t.Errorf("NetworkInterface.String() missing expected output:\n%s", str)
	}
}
