package scheduler

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"internet-bonding/client/internal/tunnel"
)

// Scheduler decides which active physical path carries each outgoing IP packet.
type Scheduler struct {
	mu             sync.Mutex
	dataSeqNum     uint32
	currentWeights map[uint8]int
	manualWeights  map[uint8]int
}

// NewScheduler creates an initialized multi-path packet scheduler.
func NewScheduler() *Scheduler {
	return &Scheduler{
		currentWeights: make(map[uint8]int),
		manualWeights:  make(map[uint8]int),
	}
}

// SetManualWeight configures an explicit manual weight for a path ID.
func (s *Scheduler) SetManualWeight(pathID uint8, weight int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.manualWeights == nil {
		s.manualWeights = make(map[uint8]int)
	}
	s.manualWeights[pathID] = weight
}

// NextDataSeqNum returns the next monotonically increasing sequence number for data packets.
func (s *Scheduler) NextDataSeqNum() uint32 {
	return atomic.AddUint32(&s.dataSeqNum, 1)
}

// CalculateWeight determines scheduling weight for a path based on its health and latency.
func CalculateWeight(status tunnel.PathStatus, srtt time.Duration) int {
	return CalculateWeightWithQuality(status, srtt, 0.0, 10)
}

// CalculateWeightWithRamp determines scheduling weight, incorporating a slow-start ramp-up for recovered paths.
func CalculateWeightWithRamp(status tunnel.PathStatus, srtt time.Duration, consecutiveSuccesses int) int {
	return CalculateWeightWithQuality(status, srtt, 0.0, consecutiveSuccesses)
}

// CalculateWeightWithManual determines scheduling weight, respecting an explicit manual weight override if positive.
func CalculateWeightWithManual(status tunnel.PathStatus, srtt time.Duration, lossPercent float64, consecutiveSuccesses int, manualWeight int) int {
	if manualWeight > 0 {
		switch status {
		case tunnel.StatusUp:
			return manualWeight
		case tunnel.StatusDegraded:
			// If degraded latency exceeds the reorder buffer window (> 380ms) or severe loss (> 20%),
			// exclude from active striping to prevent Head-of-Line blocking and TCP collapse.
			if srtt > 380*time.Millisecond || lossPercent > 20.0 {
				return 0
			}
			d := manualWeight / 3
			if d < 1 {
				d = 1
			}
			return d
		default:
			return 0
		}
	}
	return CalculateWeightWithQuality(status, srtt, lossPercent, consecutiveSuccesses)
}

// CalculateWeightWithQuality determines scheduling weight based on status, RTT, packet loss, and recovery stage.
func CalculateWeightWithQuality(status tunnel.PathStatus, srtt time.Duration, lossPercent float64, consecutiveSuccesses int) int {
	switch status {
	case tunnel.StatusUp:
		// Slow-start ramp-up for newly recovered paths
		// For the first 3 probe cycles after recovery (consecutiveSuccesses 1..5), use weight 1.
		if consecutiveSuccesses > 0 && consecutiveSuccesses < 6 {
			return 1
		}

		if srtt <= 0 {
			return 5 // Default weight for fresh healthy path
		}
		ms := float64(srtt.Milliseconds())
		if ms < 10 {
			ms = 10
		}
		var base int
		if ms <= 180 {
			base = 10
		} else if ms <= 240 {
			base = 3
		} else {
			// Higher latency mobile/cellular link (> 240ms)
			// Safe baseline is weight 1 to prevent bufferbloat and Head-of-Line blocking on fast Wi-Fi
			base = 1
		}

		// Account for packet loss if present (e.g. 5% loss reduces capacity factor)
		if lossPercent > 0 {
			factor := 1.0 - (lossPercent / 100.0)
			if factor < 0.2 {
				factor = 0.2
			}
			base = int(math.Floor(float64(base) * factor))
			if base < 1 {
				base = 1
			}
		}

		// Intermediate ramp-up stage (consecutiveSuccesses 6..9): scale to half weight
		if consecutiveSuccesses > 0 && consecutiveSuccesses < 10 {
			half := base / 2
			if half < 1 {
				half = 1
			}
			return half
		}

		return base

	case tunnel.StatusDegraded:
		// Degraded path gets reduced weight proportional to quality.
		// If latency exceeds reorder window (> 380ms) or severe packet loss (> 20%), exclude to prevent HoL blocking.
		if srtt > 380*time.Millisecond || lossPercent > 20.0 {
			return 0
		}
		if srtt <= 0 {
			return 1
		}
		ms := float64(srtt.Milliseconds())
		if ms < 10 {
			ms = 10
		}
		base := int(math.Floor(500.0 / ms))
		if base < 1 {
			base = 1
		}
		scaled := int(math.Floor(float64(base) * 0.3))
		if lossPercent > 0 {
			factor := 1.0 - (lossPercent / 100.0)
			if factor < 0.2 {
				factor = 0.2
			}
			scaled = int(math.Floor(float64(scaled) * factor))
		}
		if scaled < 1 {
			scaled = 1
		}
		if scaled > 3 {
			scaled = 3
		}
		return scaled

	case tunnel.StatusDown, tunnel.StatusStandby:
		// Down or standby paths NEVER receive data packets
		return 0

	default:
		return 0
	}
}

// SelectPath chooses the best active path for the next packet using Smooth Weighted Round-Robin (SWRR).
// Returns nil if no paths are eligible.
func (s *Scheduler) SelectPath(paths []*tunnel.ManagedPath) *tunnel.ManagedPath {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentWeights == nil {
		s.currentWeights = make(map[uint8]int)
	}

	type eligiblePath struct {
		path   *tunnel.ManagedPath
		weight int
	}

	var eligible []eligiblePath
	totalWeight := 0
	activeSet := make(map[uint8]bool)

	for _, p := range paths {
		if p == nil || p.Tunnel == nil || p.Health == nil {
			continue
		}
		status, srtt, loss, consec, available := p.Health.QualityMetrics()
		if !available {
			continue
		}
		manualW := 0
		if s.manualWeights != nil {
			manualW = s.manualWeights[p.PathID]
		}
		weight := CalculateWeightWithManual(status, srtt, loss, consec, manualW)
		if weight > 0 {
			eligible = append(eligible, eligiblePath{path: p, weight: weight})
			totalWeight += weight
			activeSet[p.PathID] = true
		}
	}

	// Clean up stale or inactive paths from currentWeights
	for pid := range s.currentWeights {
		if !activeSet[pid] {
			delete(s.currentWeights, pid)
		}
	}

	if len(eligible) == 0 || totalWeight == 0 {
		return nil
	}

	if len(eligible) == 1 {
		return eligible[0].path
	}

	// Smooth Weighted Round-Robin (SWRR)
	var best *eligiblePath
	bestWeight := -math.MaxInt32

	for i := range eligible {
		ep := &eligible[i]
		pid := ep.path.PathID
		s.currentWeights[pid] += ep.weight
		if s.currentWeights[pid] > bestWeight {
			bestWeight = s.currentWeights[pid]
			best = ep
		}
	}

	if best != nil {
		s.currentWeights[best.path.PathID] -= totalWeight
		return best.path
	}

	return eligible[0].path
}
