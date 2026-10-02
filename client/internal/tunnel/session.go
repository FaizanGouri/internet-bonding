package tunnel

import (
	"fmt"
	"math"
	"net"
	"sync"
	"time"
)

// PathStatus represents the operational health of a physical tunnel path.
type PathStatus string

const (
	StatusStandby  PathStatus = "STANDBY"
	StatusUp       PathStatus = "UP"
	StatusDegraded PathStatus = "DEGRADED"
	StatusDown     PathStatus = "DOWN"
)

// PathHealth tracks real-time network quality and state transitions for a single physical path.
type PathHealth struct {
	mu                   sync.RWMutex
	PathID               uint8
	InterfaceName        string
	IfIndex              uint32
	LocalIP              net.IP
	PhysicallyAvailable  bool
	PhysicalReason       string
	Status               PathStatus
	SRTT                 time.Duration
	Jitter               time.Duration
	LossPercent          float64
	RecentSamples        []bool // Rolling window of recent probe outcomes (true=success, false=loss)
	ConsecutiveSuccesses int
	ConsecutiveFailures  int
	LastProbeTime        time.Time
	LastError            string
}

// NewPathHealth initializes health tracking for a physical interface path.
func NewPathHealth(pathID uint8, name string, ifIndex uint32, localIP net.IP) *PathHealth {
	return &PathHealth{
		PathID:              pathID,
		InterfaceName:       name,
		IfIndex:             ifIndex,
		LocalIP:             localIP,
		Status:              StatusStandby,
		PhysicallyAvailable: true,
		PhysicalReason:      "operational",
		RecentSamples:       make([]bool, 0, 20),
	}
}

// SetPhysicalState updates the OS-level adapter presence and link state.
// If an adapter becomes unavailable, its status immediately transitions to StatusDown.
// When an adapter becomes available again, its status remains StatusDown (or StatusStandby)
// until normal probe health checks succeed.
func (ph *PathHealth) SetPhysicalState(available bool, reason string) (bool, PathStatus, PathStatus) {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	oldAvail := ph.PhysicallyAvailable
	oldStatus := ph.Status
	ph.PhysicallyAvailable = available
	ph.PhysicalReason = reason

	if !available {
		if ph.Status != StatusDown {
			ph.Status = StatusDown
			ph.ConsecutiveSuccesses = 0
			ph.LastError = reason
			return true, oldStatus, StatusDown
		}
		return false, oldStatus, ph.Status
	}

	// Restored to available: clear stale health history so past disconnect losses do not penalize recovered path
	if !oldAvail && available {
		ph.RecentSamples = ph.RecentSamples[:0]
		ph.LossPercent = 0.0
		ph.SRTT = 0
		ph.Jitter = 0
		ph.ConsecutiveSuccesses = 0
		ph.ConsecutiveFailures = 0
		ph.LastError = ""
	}

	return false, oldStatus, ph.Status
}

// IsPhysicallyAvailable returns whether the OS reports the adapter as operational.
func (ph *PathHealth) IsPhysicallyAvailable() bool {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	return ph.PhysicallyAvailable
}

// RecordProbeResult updates path health metrics and executes state transitions.
func (ph *PathHealth) RecordProbeResult(success bool, rtt time.Duration, err error) (bool, PathStatus, PathStatus) {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	oldStatus := ph.Status
	ph.LastProbeTime = time.Now()

	// 1. If physically unavailable in OS, force StatusDown regardless of probe outcomes
	if !ph.PhysicallyAvailable {
		ph.Status = StatusDown
		return (ph.Status != oldStatus), oldStatus, ph.Status
	}

	// 2. Maintain rolling 20-sample window
	if len(ph.RecentSamples) >= 20 {
		ph.RecentSamples = ph.RecentSamples[1:]
	}
	ph.RecentSamples = append(ph.RecentSamples, success)

	// Calculate loss percentage over window
	var failed int
	for _, ok := range ph.RecentSamples {
		if !ok {
			failed++
		}
	}
	ph.LossPercent = (float64(failed) / float64(len(ph.RecentSamples))) * 100.0

	if success {
		ph.ConsecutiveFailures = 0
		ph.ConsecutiveSuccesses++
		ph.LastError = ""

		// Update smoothed RTT (sRTT) and jitter using RFC 6298 / RFC 3550 standard EWMA
		if ph.SRTT == 0 {
			ph.SRTT = rtt
		} else {
			// sRTT = 0.875 * sRTT + 0.125 * rtt
			diff := math.Abs(float64(rtt - ph.SRTT))
			ph.SRTT = time.Duration(0.875*float64(ph.SRTT) + 0.125*float64(rtt))
			ph.Jitter = time.Duration(0.875*float64(ph.Jitter) + 0.125*diff)
		}
	} else {
		ph.ConsecutiveFailures++
		if ph.ConsecutiveFailures >= 3 {
			ph.ConsecutiveSuccesses = 0
		}
		if err != nil {
			ph.LastError = err.Error()
		} else {
			ph.LastError = "keepalive timeout"
		}
	}

	// 3. Deterministic State Machine Transitions
	switch ph.Status {
	case StatusStandby:
		if success {
			ph.Status = StatusUp
		}

	case StatusUp:
		if ph.ConsecutiveFailures >= 3 {
			ph.Status = StatusDown
		} else if ph.LossPercent > 15.0 || ph.SRTT > 280*time.Millisecond {
			ph.Status = StatusDegraded
		}

	case StatusDegraded:
		if ph.ConsecutiveFailures >= 3 {
			ph.Status = StatusDown
		} else if ph.LossPercent <= 10.0 && ph.SRTT <= 250*time.Millisecond && ph.ConsecutiveSuccesses >= 5 {
			ph.Status = StatusUp
		}

	case StatusDown:
		// Recovery requires 3 consecutive successful keepalives
		if ph.ConsecutiveSuccesses >= 3 {
			ph.Status = StatusUp
			ph.LossPercent = 0.0
			ph.RecentSamples = []bool{true, true, true}
		}
	}

	return (ph.Status != oldStatus), oldStatus, ph.Status
}

// Snapshot returns a copy of the current path state.
func (ph *PathHealth) Snapshot() (PathStatus, time.Duration, float64, time.Duration) {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	return ph.Status, ph.SRTT, ph.LossPercent, ph.Jitter
}

// SchedulingMetrics returns the operational status, smoothed RTT, and consecutive successes for traffic scheduling.
func (ph *PathHealth) SchedulingMetrics() (PathStatus, time.Duration, int) {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	return ph.Status, ph.SRTT, ph.ConsecutiveSuccesses
}

// QualityMetrics returns status, smoothed RTT, loss percentage, consecutive successes, and physical availability.
func (ph *PathHealth) QualityMetrics() (status PathStatus, srtt time.Duration, loss float64, consec int, available bool) {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	return ph.Status, ph.SRTT, ph.LossPercent, ph.ConsecutiveSuccesses, ph.PhysicallyAvailable
}

func (ph *PathHealth) String() string {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	return fmt.Sprintf("Path %d (%s, IfIndex %d): Status=%-8s | RTT=%6.2f ms | Loss=%5.1f%% | Jitter=%5.2f ms",
		ph.PathID, ph.InterfaceName, ph.IfIndex, ph.Status,
		float64(ph.SRTT.Microseconds())/1000.0,
		ph.LossPercent,
		float64(ph.Jitter.Microseconds())/1000.0)
}
