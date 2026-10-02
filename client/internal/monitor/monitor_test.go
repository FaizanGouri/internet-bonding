package monitor

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"internet-bonding/client/internal/adapter"
)

type mockProber struct {
	results []ProbeResult
	index   int
}

func (m *mockProber) Probe(srcIP, dstIP net.IP, timeout time.Duration) ProbeResult {
	if len(m.results) == 0 {
		return ProbeResult{Success: false, Err: errors.New("no result configured")}
	}
	res := m.results[m.index%len(m.results)]
	m.index++
	return res
}

func TestCalculateMetrics_Empty(t *testing.T) {
	rtt, loss, jitter := CalculateMetrics(nil)
	if loss != 100.0 {
		t.Errorf("Expected loss 100%% for nil samples, got %.1f", loss)
	}
	if rtt != 0 || jitter != 0 {
		t.Errorf("Expected 0 RTT and jitter for nil samples")
	}
}

func TestCalculateMetrics_AllSuccess(t *testing.T) {
	samples := []ProbeResult{
		{Success: true, RTT: 10 * time.Millisecond},
		{Success: true, RTT: 14 * time.Millisecond},
		{Success: true, RTT: 12 * time.Millisecond},
		{Success: true, RTT: 16 * time.Millisecond},
	}

	rtt, loss, jitter := CalculateMetrics(samples)
	if loss != 0.0 {
		t.Errorf("Expected 0%% loss, got %.1f%%", loss)
	}
	expectedRTT := (10 + 14 + 12 + 16) / 4 * time.Millisecond
	if rtt != expectedRTT {
		t.Errorf("Expected RTT %v, got %v", expectedRTT, rtt)
	}
	// Jitter: |14-10| = 4, |12-14| = 2, |16-12| = 4. Mean = (4+2+4)/3 = 3.33ms
	if jitter < 3*time.Millisecond || jitter > 4*time.Millisecond {
		t.Errorf("Expected jitter ~3.3ms, got %v", jitter)
	}
}

func TestCalculateMetrics_PartialLoss(t *testing.T) {
	samples := []ProbeResult{
		{Success: true, RTT: 20 * time.Millisecond},
		{Success: false, Err: errors.New("timeout")},
		{Success: true, RTT: 30 * time.Millisecond},
		{Success: false, Err: errors.New("timeout")},
	}

	rtt, loss, jitter := CalculateMetrics(samples)
	if loss != 50.0 {
		t.Errorf("Expected 50%% loss, got %.1f%%", loss)
	}
	expectedRTT := 25 * time.Millisecond
	if rtt != expectedRTT {
		t.Errorf("Expected RTT %v, got %v", expectedRTT, rtt)
	}
	// Consecutive successful: |30 - 20| = 10ms
	expectedJitter := 10 * time.Millisecond
	if jitter != expectedJitter {
		t.Errorf("Expected jitter %v, got %v", expectedJitter, jitter)
	}
}

func TestPathState_StringFormatting(t *testing.T) {
	upState := PathState{
		IfIndex:      8,
		Name:         "Wi-Fi",
		Status:       "UP",
		Reachability: ReachabilityOK,
		RTT:          12500 * time.Microsecond,
		PacketLoss:   0.0,
		Jitter:       2100 * time.Microsecond,
	}

	upStr := upState.String()
	if !strings.Contains(upStr, "Interface: Wi-Fi") ||
		!strings.Contains(upStr, "IfIndex: 8") ||
		!strings.Contains(upStr, "Status: UP") ||
		!strings.Contains(upStr, "Reachability: OK") ||
		!strings.Contains(upStr, "RTT: 12.5 ms") ||
		!strings.Contains(upStr, "Loss: 0.0%") ||
		!strings.Contains(upStr, "Jitter: 2.1 ms") {
		t.Errorf("PathState.String() unexpected formatting for UP state:\n%s", upStr)
	}

	downState := PathState{
		IfIndex:      23,
		Name:         "Ethernet",
		Status:       "DOWN",
		Reachability: ReachabilityUnavailable,
	}

	downStr := downState.String()
	if !strings.Contains(downStr, "Interface: Ethernet") ||
		!strings.Contains(downStr, "IfIndex: 23") ||
		!strings.Contains(downStr, "Status: DOWN") ||
		!strings.Contains(downStr, "Reachability: UNAVAILABLE") {
		t.Errorf("PathState.String() unexpected formatting for DOWN state:\n%s", downStr)
	}
}

func TestMonitor_CheckPath_Disconnected(t *testing.T) {
	prober := &mockProber{}
	mon := NewMonitor(prober, DefaultConfig())

	iface := adapter.NetworkInterface{
		Index:   23,
		Name:    "Ethernet",
		IPv4:    net.ParseIP("169.254.85.217"),
		Gateway: nil,
		IsUp:    false,
	}

	state := mon.CheckPath(iface)
	if state.Reachability != ReachabilityUnavailable {
		t.Errorf("Expected disconnected interface to be UNAVAILABLE, got %s", state.Reachability)
	}
	if prober.index != 0 {
		t.Errorf("Expected 0 probes sent for disconnected interface, got %d", prober.index)
	}
}

func TestMonitor_CheckPath_APIPA(t *testing.T) {
	prober := &mockProber{}
	mon := NewMonitor(prober, DefaultConfig())

	iface := adapter.NetworkInterface{
		Index:   23,
		Name:    "Ethernet",
		IPv4:    net.ParseIP("169.254.85.217"),
		Gateway: net.ParseIP("169.254.1.1"),
		IsUp:    true,
	}

	state := mon.CheckPath(iface)
	if state.Reachability != ReachabilityUnavailable {
		t.Errorf("Expected APIPA interface to be UNAVAILABLE, got %s", state.Reachability)
	}
	if prober.index != 0 {
		t.Errorf("Expected 0 probes sent for APIPA interface, got %d", prober.index)
	}
}

func TestMonitor_CheckPath_Healthy(t *testing.T) {
	prober := &mockProber{
		results: []ProbeResult{
			{Success: true, RTT: 15 * time.Millisecond},
			{Success: true, RTT: 17 * time.Millisecond},
		},
	}
	cfg := MonitorConfig{
		TargetIP:     net.ParseIP("1.1.1.1"),
		ProbeCount:   2,
		ProbeTimeout: 500 * time.Millisecond,
	}
	mon := NewMonitor(prober, cfg)

	iface := adapter.NetworkInterface{
		Index:   8,
		Name:    "Wi-Fi",
		IPv4:    net.ParseIP("192.168.1.100"),
		Gateway: net.ParseIP("192.168.1.1"),
		IsUp:    true,
	}

	state := mon.CheckPath(iface)
	if state.Reachability != ReachabilityOK {
		t.Errorf("Expected healthy interface to be OK, got %s", state.Reachability)
	}
	if state.PacketLoss != 0.0 {
		t.Errorf("Expected 0%% loss, got %.1f%%", state.PacketLoss)
	}
	if state.RTT != 16*time.Millisecond {
		t.Errorf("Expected 16ms RTT, got %v", state.RTT)
	}
}
