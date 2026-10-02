package pathhealth

import (
	"net"
	"testing"
)

func TestInterfaceState_Available(t *testing.T) {
	tests := []struct {
		name     string
		state    InterfaceState
		expected bool
	}{
		{
			name: "All conditions met",
			state: InterfaceState{
				IfIndex:    1,
				Name:       "Ethernet",
				IsUp:       true,
				HasIPv4:    true,
				HasGateway: true,
				IPv4:       net.ParseIP("192.168.1.100"),
				Gateway:    net.ParseIP("192.168.1.1"),
			},
			expected: true,
		},
		{
			name: "Adapter down",
			state: InterfaceState{
				IfIndex:    1,
				Name:       "Ethernet",
				IsUp:       false,
				HasIPv4:    true,
				HasGateway: true,
			},
			expected: false,
		},
		{
			name: "Missing IPv4",
			state: InterfaceState{
				IfIndex:    1,
				Name:       "Ethernet",
				IsUp:       true,
				HasIPv4:    false,
				HasGateway: true,
			},
			expected: false,
		},
		{
			name: "Missing Gateway",
			state: InterfaceState{
				IfIndex:    1,
				Name:       "Ethernet",
				IsUp:       true,
				HasIPv4:    true,
				HasGateway: false,
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.state.Available(); got != tc.expected {
				t.Fatalf("Available() = %v, expected %v", got, tc.expected)
			}
		})
	}
}

func TestMonitor_CheckAll(t *testing.T) {
	mon := NewMonitor()
	targets := []MonitoredTarget{
		{IfIndex: 999999, Name: "NonExistentInterface"},
	}

	res, err := mon.CheckAll(targets)
	if err != nil {
		t.Fatalf("CheckAll failed: %v", err)
	}

	st, ok := res[999999]
	if !ok {
		t.Fatalf("expected entry for target IfIndex 999999")
	}

	if st.Available() {
		t.Fatalf("expected non-existent interface to NOT be available")
	}
}
