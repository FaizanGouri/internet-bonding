package monitor

import (
	"fmt"
	"math"
	"net"
	"time"

	"internet-bonding/client/internal/adapter"
)

// Reachability represents the operational quality state of an Internet path.
type Reachability string

const (
	ReachabilityOK          Reachability = "OK"
	ReachabilityDegraded    Reachability = "DEGRADED"
	ReachabilityUnavailable Reachability = "UNAVAILABLE"
)

// PathState encapsulates real-time health and quality metrics for an interface path.
type PathState struct {
	IfIndex       uint32        `json:"if_index"`
	Name          string        `json:"name"`
	IPv4          net.IP        `json:"ipv4"`
	Gateway       net.IP        `json:"gateway"`
	Status        string        `json:"status"` // "UP" or "DOWN"
	Reachability  Reachability  `json:"reachability"`
	RTT           time.Duration `json:"rtt"`
	PacketLoss    float64       `json:"packet_loss"` // Percentage [0.0, 100.0]
	Jitter        time.Duration `json:"jitter"`
	LastProbeTime time.Time     `json:"last_probe_time"`
	LastError     string        `json:"last_error,omitempty"`
}

func (ps PathState) String() string {
	if ps.Reachability == ReachabilityUnavailable {
		return fmt.Sprintf("Interface: %s\nIfIndex: %d\nStatus: %s\nReachability: %s",
			ps.Name, ps.IfIndex, ps.Status, ps.Reachability)
	}

	return fmt.Sprintf("Interface: %s\nIfIndex: %d\nStatus: %s\nReachability: %s\nRTT: %.1f ms\nLoss: %.1f%%\nJitter: %.1f ms",
		ps.Name, ps.IfIndex, ps.Status, ps.Reachability,
		float64(ps.RTT.Microseconds())/1000.0,
		ps.PacketLoss,
		float64(ps.Jitter.Microseconds())/1000.0)
}

// ProbeResult represents the outcome of a single probe request.
type ProbeResult struct {
	Success bool
	RTT     time.Duration
	Err     error
}

// Prober defines the interface for executing interface-bound health probes.
type Prober interface {
	Probe(srcIP, dstIP net.IP, timeout time.Duration) ProbeResult
}

// CalculateMetrics derives average RTT, packet loss percentage, and jitter from probe samples.
func CalculateMetrics(samples []ProbeResult) (rtt time.Duration, loss float64, jitter time.Duration) {
	if len(samples) == 0 {
		return 0, 100.0, 0
	}

	var successfulRTTs []time.Duration
	var failedCount int

	for _, s := range samples {
		if s.Success {
			successfulRTTs = append(successfulRTTs, s.RTT)
		} else {
			failedCount++
		}
	}

	loss = (float64(failedCount) / float64(len(samples))) * 100.0

	if len(successfulRTTs) == 0 {
		return 0, loss, 0
	}

	// Average RTT across successful probes
	var total time.Duration
	for _, d := range successfulRTTs {
		total += d
	}
	rtt = total / time.Duration(len(successfulRTTs))

	// Mean deviation of consecutive successful RTTs (RFC 3550 jitter calculation)
	if len(successfulRTTs) > 1 {
		var diffSum float64
		for i := 1; i < len(successfulRTTs); i++ {
			diff := math.Abs(float64(successfulRTTs[i] - successfulRTTs[i-1]))
			diffSum += diff
		}
		jitter = time.Duration(diffSum / float64(len(successfulRTTs)-1))
	}

	return rtt, loss, jitter
}

// MonitorConfig defines configuration parameters for path probing.
type MonitorConfig struct {
	TargetIP     net.IP
	ProbeCount   int
	ProbeTimeout time.Duration
}

// DefaultConfig provides standard probe defaults (4 probes to 1.1.1.1 with 1s timeout).
func DefaultConfig() MonitorConfig {
	return MonitorConfig{
		TargetIP:     net.ParseIP("1.1.1.1"),
		ProbeCount:   4,
		ProbeTimeout: 1000 * time.Millisecond,
	}
}

// Monitor evaluates adapter path quality using an interface-specific prober.
type Monitor struct {
	prober       Prober
	targetIP     net.IP
	probeCount   int
	probeTimeout time.Duration
}

// NewMonitor constructs a path monitor with the specified prober and configuration.
func NewMonitor(prober Prober, cfg MonitorConfig) *Monitor {
	if cfg.TargetIP == nil {
		cfg.TargetIP = net.ParseIP("1.1.1.1")
	}
	if cfg.ProbeCount <= 0 {
		cfg.ProbeCount = 4
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 1000 * time.Millisecond
	}
	return &Monitor{
		prober:       prober,
		targetIP:     cfg.TargetIP,
		probeCount:   cfg.ProbeCount,
		probeTimeout: cfg.ProbeTimeout,
	}
}

// CheckPath monitors a single network interface and computes its PathState.
func (m *Monitor) CheckPath(iface adapter.NetworkInterface) PathState {
	now := time.Now()
	status := "DOWN"
	if iface.IsUp {
		status = "UP"
	}

	state := PathState{
		IfIndex:       iface.Index,
		Name:          iface.Name,
		IPv4:          iface.IPv4,
		Gateway:       iface.Gateway,
		Status:        status,
		Reachability:  ReachabilityUnavailable,
		LastProbeTime: now,
	}

	// 1. Check physical link status
	if !iface.IsUp {
		state.LastError = "physical link is down / disconnected"
		return state
	}

	// 2. Check for routable IPv4 (exclude link-local APIPA 169.254.0.0/16)
	if iface.IPv4 == nil || iface.IPv4.IsUnspecified() || iface.IPv4.IsLinkLocalUnicast() {
		state.LastError = "no valid routable IPv4 address assigned"
		return state
	}

	// 3. Check for active default gateway
	if iface.Gateway == nil || iface.Gateway.IsUnspecified() {
		state.LastError = "no active default gateway configured"
		return state
	}

	// 4. Perform interface-bound probes
	samples := make([]ProbeResult, 0, m.probeCount)
	for i := 0; i < m.probeCount; i++ {
		res := m.prober.Probe(iface.IPv4, m.targetIP, m.probeTimeout)
		samples = append(samples, res)
		if i < m.probeCount-1 {
			time.Sleep(30 * time.Millisecond)
		}
	}

	rtt, loss, jitter := CalculateMetrics(samples)
	state.RTT = rtt
	state.PacketLoss = loss
	state.Jitter = jitter

	if loss >= 100.0 {
		state.Reachability = ReachabilityUnavailable
		state.LastError = "100% probe packet loss"
	} else if loss > 25.0 || rtt > 300*time.Millisecond {
		state.Reachability = ReachabilityDegraded
	} else {
		state.Reachability = ReachabilityOK
	}

	return state
}
