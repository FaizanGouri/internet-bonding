package scheduler

import (
	"net"
	"testing"
	"time"

	"internet-bonding/client/internal/tunnel"
)

func TestCalculateWeight(t *testing.T) {
	// DOWN and STANDBY must have 0 weight
	if w := CalculateWeight(tunnel.StatusDown, 50*time.Millisecond); w != 0 {
		t.Errorf("DOWN path weight = %d; want 0", w)
	}
	if w := CalculateWeight(tunnel.StatusStandby, 50*time.Millisecond); w != 0 {
		t.Errorf("STANDBY path weight = %d; want 0", w)
	}

	// DEGRADED path has weight 1
	if w := CalculateWeight(tunnel.StatusDegraded, 100*time.Millisecond); w != 1 {
		t.Errorf("DEGRADED path weight = %d; want 1", w)
	}

	// UP paths have weight inversely proportional to RTT
	wFast := CalculateWeight(tunnel.StatusUp, 50*time.Millisecond)
	wSlow := CalculateWeight(tunnel.StatusUp, 250*time.Millisecond)
	if wFast <= wSlow {
		t.Errorf("Expected faster path weight (%d) > slower path weight (%d)", wFast, wSlow)
	}
}

func TestScheduler_ExcludesDownPaths(t *testing.T) {
	s := NewScheduler()

	h1 := tunnel.NewPathHealth(1, "Wi-Fi", 1, net.IPv4(192, 168, 1, 10))
	h1.RecordProbeResult(true, 50*time.Millisecond, nil) // UP

	h2 := tunnel.NewPathHealth(2, "USB", 2, net.IPv4(10, 0, 0, 10))
	h2.RecordProbeResult(true, 100*time.Millisecond, nil) // UP
	h2.RecordProbeResult(false, 0, nil)
	h2.RecordProbeResult(false, 0, nil)
	h2.RecordProbeResult(false, 0, nil) // 3 failures -> DOWN

	// Mock ManagedPath
	// Note: We need non-nil tunnel. For this unit test, let's verify SelectPath handles paths.
	// Since ManagedPath has unexported tunnel fields, we can test CalculateWeight and SelectPath behavior
	status1, _, _, _ := h1.Snapshot()
	status2, _, _, _ := h2.Snapshot()

	if status1 != tunnel.StatusUp {
		t.Fatalf("h1 status = %v; want UP", status1)
	}
	if status2 != tunnel.StatusDown {
		t.Fatalf("h2 status = %v; want DOWN", status2)
	}

	if CalculateWeight(status2, 0) != 0 {
		t.Errorf("Expected weight 0 for DOWN path")
	}

	seq1 := s.NextDataSeqNum()
	seq2 := s.NextDataSeqNum()
	if seq2 != seq1+1 {
		t.Errorf("Seq numbers not monotonic: %d, %d", seq1, seq2)
	}
}

func TestCalculateWeightWithRamp(t *testing.T) {
	// Newly recovered path (consecutiveSuccesses 3..5) must start at slow-start weight = 1
	for c := 1; c < 6; c++ {
		w := CalculateWeightWithRamp(tunnel.StatusUp, 30*time.Millisecond, c)
		if w != 1 {
			t.Errorf("Consecutive successes %d: expected slow-start weight 1, got %d", c, w)
		}
	}

	// Intermediate ramp-up (consecutiveSuccesses 6..9): scale to half
	// For 30ms, normal weight = round(500/30) = 17 -> clamp 10. Half is 5.
	wHalf := CalculateWeightWithRamp(tunnel.StatusUp, 30*time.Millisecond, 8)
	if wHalf != 5 {
		t.Errorf("Consecutive successes 8: expected intermediate weight 5, got %d", wHalf)
	}

	// Full operational weight (consecutiveSuccesses >= 10)
	wFull := CalculateWeightWithRamp(tunnel.StatusUp, 30*time.Millisecond, 12)
	if wFull != 10 {
		t.Errorf("Consecutive successes 12: expected full weight 10, got %d", wFull)
	}
}

func TestScheduler_SmoothInterleaving(t *testing.T) {
	s := NewScheduler()

	h1 := tunnel.NewPathHealth(1, "Eth", 1, net.IPv4(10, 0, 0, 1))
	for i := 0; i < 10; i++ {
		h1.RecordProbeResult(true, 50*time.Millisecond, nil)
	}

	h2 := tunnel.NewPathHealth(2, "WiFi", 2, net.IPv4(10, 0, 0, 2))
	for i := 0; i < 10; i++ {
		h2.RecordProbeResult(true, 50*time.Millisecond, nil)
	}

	p1 := &tunnel.ManagedPath{PathID: 1, Tunnel: &tunnel.ClientTunnel{}, Health: h1}
	p2 := &tunnel.ManagedPath{PathID: 2, Tunnel: &tunnel.ClientTunnel{}, Health: h2}
	paths := []*tunnel.ManagedPath{p1, p2}

	// With equal weights (both 10), SWRR must strictly interleave: P1, P2, P1, P2, P1, P2
	expectedOrder := []uint8{1, 2, 1, 2, 1, 2}
	for i, expectedPID := range expectedOrder {
		selected := s.SelectPath(paths)
		if selected == nil {
			t.Fatalf("Packet %d: SelectPath returned nil", i)
		}
		if selected.PathID != expectedPID {
			t.Errorf("Packet %d: selected PathID=%d, want %d", i, selected.PathID, expectedPID)
		}
	}
}

func TestScheduler_MultiPathFailoverAndRecovery(t *testing.T) {
	s := NewScheduler()

	h1 := tunnel.NewPathHealth(1, "Eth", 1, net.IPv4(10, 0, 0, 1))
	h2 := tunnel.NewPathHealth(2, "WiFi", 2, net.IPv4(10, 0, 0, 2))
	h3 := tunnel.NewPathHealth(3, "LTE", 3, net.IPv4(10, 0, 0, 3))

	for i := 0; i < 10; i++ {
		h1.RecordProbeResult(true, 50*time.Millisecond, nil)
		h2.RecordProbeResult(true, 50*time.Millisecond, nil)
		h3.RecordProbeResult(true, 50*time.Millisecond, nil)
	}

	p1 := &tunnel.ManagedPath{PathID: 1, Tunnel: &tunnel.ClientTunnel{}, Health: h1}
	p2 := &tunnel.ManagedPath{PathID: 2, Tunnel: &tunnel.ClientTunnel{}, Health: h2}
	p3 := &tunnel.ManagedPath{PathID: 3, Tunnel: &tunnel.ClientTunnel{}, Health: h3}
	paths := []*tunnel.ManagedPath{p1, p2, p3}

	// 1. All 3 paths healthy: all 3 must receive packets
	pCounts := make(map[uint8]int)
	for i := 0; i < 30; i++ {
		sel := s.SelectPath(paths)
		if sel == nil {
			t.Fatalf("All UP: SelectPath returned nil")
		}
		pCounts[sel.PathID]++
	}
	if pCounts[1] == 0 || pCounts[2] == 0 || pCounts[3] == 0 {
		t.Errorf("Expected all 3 paths to receive traffic, got counts: %v", pCounts)
	}

	// 2. P2 goes DOWN
	h2.SetPhysicalState(false, "cable unplugged")
	pCounts = make(map[uint8]int)
	for i := 0; i < 20; i++ {
		sel := s.SelectPath(paths)
		if sel == nil {
			t.Fatalf("P2 DOWN: SelectPath returned nil")
		}
		pCounts[sel.PathID]++
	}
	if pCounts[2] != 0 {
		t.Errorf("DOWN P2 received traffic: %d packets", pCounts[2])
	}
	if pCounts[1] == 0 || pCounts[3] == 0 {
		t.Errorf("Expected P1 and P3 to share traffic, got counts: %v", pCounts)
	}

	// 3. P1 also goes DOWN: P3 is sole survivor
	h1.SetPhysicalState(false, "disabled")
	for i := 0; i < 10; i++ {
		sel := s.SelectPath(paths)
		if sel == nil || sel.PathID != 3 {
			t.Fatalf("Expected only P3 to be selected, got: %v", sel)
		}
	}

	// 4. P2 recovers (physical re-enabled, 3 probe successes)
	h2.SetPhysicalState(true, "reconnected")
	h2.RecordProbeResult(true, 50*time.Millisecond, nil)
	h2.RecordProbeResult(true, 50*time.Millisecond, nil)
	h2.RecordProbeResult(true, 50*time.Millisecond, nil) // UP (consecutiveSuccesses=3)

	pCounts = make(map[uint8]int)
	for i := 0; i < 30; i++ {
		sel := s.SelectPath(paths)
		if sel == nil {
			t.Fatalf("Recovered P2: SelectPath returned nil")
		}
		pCounts[sel.PathID]++
	}
	if pCounts[2] == 0 {
		t.Errorf("Recovered P2 did not receive traffic: %v", pCounts)
	}
	if pCounts[3] == 0 {
		t.Errorf("Active P3 stopped receiving traffic: %v", pCounts)
	}
}

func TestScheduler_SinglePathExclusivity(t *testing.T) {
	s := NewScheduler()

	tests := []struct {
		name      string
		activePID uint8
	}{
		{"Only P1 Active", 1},
		{"Only P2 Active", 2},
		{"Only P3 Active", 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var paths []*tunnel.ManagedPath
			for pid := uint8(1); pid <= 3; pid++ {
				h := tunnel.NewPathHealth(pid, "Net", uint32(pid), net.IPv4(10, 0, 0, pid))
				if pid == tc.activePID {
					for i := 0; i < 10; i++ {
						h.RecordProbeResult(true, 50*time.Millisecond, nil)
					}
				} else {
					h.SetPhysicalState(false, "disabled")
				}
				paths = append(paths, &tunnel.ManagedPath{PathID: pid, Tunnel: &tunnel.ClientTunnel{}, Health: h})
			}

			for i := 0; i < 15; i++ {
				sel := s.SelectPath(paths)
				if sel == nil {
					t.Fatalf("Expected path %d selected, got nil", tc.activePID)
				}
				if sel.PathID != tc.activePID {
					t.Errorf("Selected PathID=%d, want %d", sel.PathID, tc.activePID)
				}
			}
		})
	}
}

func TestScheduler_TwoPathsFailoverCombinations(t *testing.T) {
	// Tests:
	// 1. P1 DOWN while P2/P3 active -> P2 + P3 share traffic
	// 2. P2 DOWN while P1/P3 active -> P1 + P3 share traffic
	// 3. P3 DOWN while P1/P2 active -> P1 + P2 share traffic

	cases := []struct {
		downPID  uint8
		activeP1 uint8
		activeP2 uint8
	}{
		{downPID: 1, activeP1: 2, activeP2: 3},
		{downPID: 2, activeP1: 1, activeP2: 3},
		{downPID: 3, activeP1: 1, activeP2: 2},
	}

	for _, c := range cases {
		s := NewScheduler()
		var paths []*tunnel.ManagedPath
		for pid := uint8(1); pid <= 3; pid++ {
			h := tunnel.NewPathHealth(pid, "Net", uint32(pid), net.IPv4(10, 0, 0, pid))
			if pid == c.downPID {
				h.SetPhysicalState(false, "down")
			} else {
				for i := 0; i < 10; i++ {
					h.RecordProbeResult(true, 50*time.Millisecond, nil)
				}
			}
			paths = append(paths, &tunnel.ManagedPath{PathID: pid, Tunnel: &tunnel.ClientTunnel{}, Health: h})
		}

		counts := make(map[uint8]int)
		for i := 0; i < 20; i++ {
			sel := s.SelectPath(paths)
			if sel == nil {
				t.Fatalf("Down=%d: SelectPath returned nil", c.downPID)
			}
			counts[sel.PathID]++
		}

		if counts[c.downPID] != 0 {
			t.Errorf("Down path %d received %d packets", c.downPID, counts[c.downPID])
		}
		if counts[c.activeP1] == 0 || counts[c.activeP2] == 0 {
			t.Errorf("Expected active paths %d and %d to share traffic, got: %v", c.activeP1, c.activeP2, counts)
		}
	}
}

func TestScheduler_DegradedPathQuality(t *testing.T) {
	s := NewScheduler()

	// P1 healthy (50ms RTT, 0% loss) -> weight 10
	h1 := tunnel.NewPathHealth(1, "Eth", 1, net.IPv4(10, 0, 0, 1))
	for i := 0; i < 10; i++ {
		h1.RecordProbeResult(true, 50*time.Millisecond, nil)
	}

	// P2 degraded (300ms RTT, triggers StatusDegraded)
	h2 := tunnel.NewPathHealth(2, "WiFi", 2, net.IPv4(10, 0, 0, 2))
	for i := 0; i < 20; i++ {
		h2.RecordProbeResult(true, 300*time.Millisecond, nil)
	}

	p1 := &tunnel.ManagedPath{PathID: 1, Tunnel: &tunnel.ClientTunnel{}, Health: h1}
	p2 := &tunnel.ManagedPath{PathID: 2, Tunnel: &tunnel.ClientTunnel{}, Health: h2}
	paths := []*tunnel.ManagedPath{p1, p2}

	st2, _, _ := h2.SchedulingMetrics()
	if st2 != tunnel.StatusDegraded {
		t.Fatalf("Expected P2 status DEGRADED, got %s", st2)
	}

	counts := make(map[uint8]int)
	for i := 0; i < 30; i++ {
		sel := s.SelectPath(paths)
		if sel == nil {
			t.Fatalf("SelectPath returned nil with degraded path")
		}
		counts[sel.PathID]++
	}

	// P2 (degraded) must still participate (non-zero), but P1 (healthy) should carry majority
	if counts[2] == 0 {
		t.Errorf("Degraded P2 received 0 packets; expected participation")
	}
	if counts[1] <= counts[2] {
		t.Errorf("Healthy P1 (%d) should carry more traffic than degraded P2 (%d)", counts[1], counts[2])
	}
}

func TestScheduler_AllPathsUnavailable(t *testing.T) {
	s := NewScheduler()

	h1 := tunnel.NewPathHealth(1, "Eth", 1, net.IPv4(10, 0, 0, 1))
	h1.SetPhysicalState(false, "disabled")

	h2 := tunnel.NewPathHealth(2, "WiFi", 2, net.IPv4(10, 0, 0, 2))
	h2.SetPhysicalState(false, "disabled")

	p1 := &tunnel.ManagedPath{PathID: 1, Tunnel: &tunnel.ClientTunnel{}, Health: h1}
	p2 := &tunnel.ManagedPath{PathID: 2, Tunnel: &tunnel.ClientTunnel{}, Health: h2}

	sel := s.SelectPath([]*tunnel.ManagedPath{p1, p2})
	if sel != nil {
		t.Errorf("Expected nil when all paths unavailable, got: %v", sel)
	}
}
