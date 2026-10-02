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
		PathID:        pathID,
		InterfaceName: name,
		IfIndex:       ifIndex,
		LocalIP:       localIP,
		Status:        StatusStandby,
		RecentSamples: make([]bool, 0, 20),
	}
}

// RecordProbeResult updates path health metrics and executes state transitions.
func (ph *PathHealth) RecordProbeResult(success bool, rtt time.Duration, err error) {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	ph.LastProbeTime = time.Now()

	// 1. Maintain rolling 20-sample window
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
		ph.ConsecutiveSuccesses = 0
		ph.ConsecutiveFailures++
		if err != nil {
			ph.LastError = err.Error()
		} else {
			ph.LastError = "keepalive timeout"
		}
	}

	// 2. Deterministic State Machine Transitions
	switch ph.Status {
	case StatusStandby:
		if success {
			ph.Status = StatusUp
		}

	case StatusUp:
		if ph.ConsecutiveFailures >= 3 {
			ph.Status = StatusDown
		} else if ph.LossPercent > 15.0 || ph.SRTT > 250*time.Millisecond {
			ph.Status = StatusDegraded
		}

	case StatusDegraded:
		if ph.ConsecutiveFailures >= 3 {
			ph.Status = StatusDown
		} else if ph.LossPercent <= 10.0 && ph.SRTT <= 200*time.Millisecond && ph.ConsecutiveSuccesses >= 10 {
			ph.Status = StatusUp
		}

	case StatusDown:
		// Recovery requires 3 consecutive successful keepalives
		if ph.ConsecutiveSuccesses >= 3 {
			ph.Status = StatusUp
		}
	}
}

// Snapshot returns a copy of the current path state.
func (ph *PathHealth) Snapshot() (PathStatus, time.Duration, float64, time.Duration) {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	return ph.Status, ph.SRTT, ph.LossPercent, ph.Jitter
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
