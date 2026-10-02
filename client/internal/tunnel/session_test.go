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
