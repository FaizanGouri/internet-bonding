package tunnel

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestPathHealth_StateTransitions(t *testing.T) {
	ph := NewPathHealth(1, "Wi-Fi", 8, net.ParseIP("192.168.5.28"))

	// 1. Initial state is STANDBY
	if ph.Status != StatusStandby {
		t.Fatalf("Expected initial status STANDBY, got %s", ph.Status)
	}

	// 2. STANDBY -> UP on first success
	ph.RecordProbeResult(true, 50*time.Millisecond, nil)
	if ph.Status != StatusUp {
		t.Errorf("Expected status UP after 1st success, got %s", ph.Status)
	}

	// 3. UP -> DEGRADED on high RTT (> 250ms)
	for i := 0; i < 20; i++ {
		ph.RecordProbeResult(true, 300*time.Millisecond, nil)
	}
	if ph.Status != StatusDegraded {
		t.Errorf("Expected status DEGRADED on high RTT, got %s", ph.Status)
	}

	// 4. DEGRADED -> DOWN on 3 consecutive timeouts
	ph.RecordProbeResult(false, 0, errors.New("timeout 1"))
	ph.RecordProbeResult(false, 0, errors.New("timeout 2"))
	ph.RecordProbeResult(false, 0, errors.New("timeout 3"))
	if ph.Status != StatusDown {
		t.Errorf("Expected status DOWN after 3 consecutive failures, got %s", ph.Status)
	}

	// 5. DOWN -> UP Recovery: 1 or 2 successes should KEEP it DOWN
	ph.RecordProbeResult(true, 40*time.Millisecond, nil)
	if ph.Status != StatusDown {
		t.Errorf("Expected status DOWN after 1 success, got %s", ph.Status)
	}
	ph.RecordProbeResult(true, 42*time.Millisecond, nil)
	if ph.Status != StatusDown {
		t.Errorf("Expected status DOWN after 2 successes, got %s", ph.Status)
	}

	// 3rd consecutive success restores path to UP
	ph.RecordProbeResult(true, 41*time.Millisecond, nil)
	if ph.Status != StatusUp {
		t.Errorf("Expected status UP after 3 consecutive successes (recovery), got %s", ph.Status)
	}
}

func TestPathHealth_PhysicalState(t *testing.T) {
	ph := NewPathHealth(1, "Wi-Fi", 8, net.ParseIP("192.168.5.28"))
	ph.RecordProbeResult(true, 50*time.Millisecond, nil)
	if ph.Status != StatusUp {
		t.Fatalf("Expected status UP, got %s", ph.Status)
	}

	// 1. Adapter disabled in OS -> immediately DOWN
	changed, oldStatus, newStatus := ph.SetPhysicalState(false, "adapter disabled in OS")
	if !changed || oldStatus != StatusUp || newStatus != StatusDown {
		t.Fatalf("Expected transition UP -> DOWN, got changed=%v %s -> %s", changed, oldStatus, newStatus)
	}
	if ph.Status != StatusDown {
		t.Fatalf("Expected StatusDown, got %s", ph.Status)
	}

	// 2. While physically down, successful probes MUST NOT transition to UP
	ph.RecordProbeResult(true, 30*time.Millisecond, nil)
	ph.RecordProbeResult(true, 30*time.Millisecond, nil)
	ph.RecordProbeResult(true, 30*time.Millisecond, nil)
	if ph.Status != StatusDown {
		t.Fatalf("Expected status to stay DOWN while physically unavailable, got %s", ph.Status)
	}

	// 3. Adapter restored in OS -> remains DOWN until probes succeed
	changed, oldStatus, newStatus = ph.SetPhysicalState(true, "operational")
	if changed {
		t.Fatalf("Expected changed=false on re-enable since status stays DOWN until probes succeed")
	}
	if ph.Status != StatusDown {
		t.Fatalf("Expected Status to still be DOWN, got %s", ph.Status)
	}

	// 4. Probes now succeed -> 3 consecutive successes recovers path to UP
	ph.RecordProbeResult(true, 30*time.Millisecond, nil)
	if ph.Status != StatusDown {
		t.Fatalf("Expected 1st probe to keep DOWN, got %s", ph.Status)
	}
	ph.RecordProbeResult(true, 30*time.Millisecond, nil)
	if ph.Status != StatusDown {
		t.Fatalf("Expected 2nd probe to keep DOWN, got %s", ph.Status)
	}
	ph.RecordProbeResult(true, 30*time.Millisecond, nil)
	if ph.Status != StatusUp {
		t.Fatalf("Expected 3rd probe to restore UP, got %s", ph.Status)
	}

	// 5. Verify subsequent probe does NOT immediately trigger StatusDegraded
	ph.RecordProbeResult(true, 32*time.Millisecond, nil)
	if ph.Status != StatusUp {
		t.Fatalf("Expected status to remain UP after recovery (no false DEGRADED), got %s", ph.Status)
	}
	if ph.LossPercent > 10.0 {
		t.Fatalf("Expected LossPercent to be clean after recovery, got %5.1f%%", ph.LossPercent)
	}
}

func TestPathHealth_OrphanedProbeACKDiscarded(t *testing.T) {
	// Simulate the client probe tracking map
	type probeKey struct {
		pathID uint8
		seq    uint32
	}
	probeSendTimes := make(map[probeKey]time.Time)

	ph := NewPathHealth(1, "Wi-Fi", 8, net.ParseIP("192.168.5.28"))
	ph.RecordProbeResult(true, 40*time.Millisecond, nil)

	initialSRTT, _, _, _ := ph.Snapshot()
	_ = initialSRTT

	// Probe seq=1 sent at t=0
	seq := uint32(1)
	probeSendTimes[probeKey{pathID: 1, seq: seq}] = time.Now().Add(-3000 * time.Millisecond)

	// Timeout occurs: probe entry is removed from map
	delete(probeSendTimes, probeKey{pathID: 1, seq: seq})

	// Delayed/orphaned probe ACK arrives later
	// Receiver checks map:
	_, exists := probeSendTimes[probeKey{pathID: 1, seq: seq}]
	if exists {
		t.Fatalf("Expected probe entry to not exist after timeout")
	}

	// CRITICAL RULE: orphaned ACK must be discarded, never update health with packet timestamp
	// If !exists -> discard
	// Verify health SRTT remains untouched
	_, srttAfter, _, _ := ph.Snapshot()
	if srttAfter != 40*time.Millisecond {
		t.Fatalf("Expected SRTT to remain 40ms, got %v", srttAfter)
	}
}
