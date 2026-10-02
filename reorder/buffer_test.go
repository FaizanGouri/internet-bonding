package reorder

import (
	"bytes"
	"testing"
	"time"
)

func TestReorderBuffer_InOrder(t *testing.T) {
	rb := NewReorderBuffer(100 * time.Millisecond)

	for i := uint32(1); i <= 5; i++ {
		payload := []byte{byte(i)}
		ready := rb.Insert(i, payload)
		if len(ready) != 1 || ready[0][0] != byte(i) {
			t.Fatalf("Expected immediate in-order delivery of packet %d, got %v", i, ready)
		}
	}

	stats := rb.Stats()
	if stats.Delivered != 5 || stats.Received != 5 || stats.Reordered != 0 || stats.Duplicates != 0 || stats.Dropped != 0 {
		t.Fatalf("Unexpected stats: %+v", stats)
	}
}

func TestReorderBuffer_OutOfOrder(t *testing.T) {
	rb := NewReorderBuffer(100 * time.Millisecond)

	// Packet 1 arrives -> delivered
	p1 := rb.Insert(1, []byte("pkt1"))
	if len(p1) != 1 || string(p1[0]) != "pkt1" {
		t.Fatalf("Expected pkt1 delivered, got %v", p1)
	}

	// Packet 3 arrives -> buffered
	p3 := rb.Insert(3, []byte("pkt3"))
	if len(p3) != 0 {
		t.Fatalf("Expected pkt3 to be buffered, got %v", p3)
	}

	// Packet 2 arrives -> delivers pkt2 then pkt3 in order
	p2 := rb.Insert(2, []byte("pkt2"))
	if len(p2) != 2 {
		t.Fatalf("Expected 2 packets delivered, got %d", len(p2))
	}
	if string(p2[0]) != "pkt2" || string(p2[1]) != "pkt3" {
		t.Fatalf("Delivered packets out of order: %v, %v", string(p2[0]), string(p2[1]))
	}

	stats := rb.Stats()
	if stats.Received != 3 || stats.Delivered != 3 || stats.Reordered != 1 || stats.Duplicates != 0 {
		t.Fatalf("Unexpected stats: %+v", stats)
	}
}

func TestReorderBuffer_ReverseBurst(t *testing.T) {
	rb := NewReorderBuffer(100*time.Millisecond, 1)

	// Send in reverse: 5, 4, 3, 2, 1
	for i := uint32(5); i >= 2; i-- {
		ready := rb.Insert(i, []byte{byte(i)})
		if len(ready) != 0 {
			t.Fatalf("Expected packet %d to be buffered, got %v", i, ready)
		}
	}

	// Finally send 1
	ready := rb.Insert(1, []byte{1})
	if len(ready) != 5 {
		t.Fatalf("Expected 5 packets delivered upon receiving 1, got %d", len(ready))
	}

	for i := 0; i < 5; i++ {
		expected := byte(i + 1)
		if ready[i][0] != expected {
			t.Fatalf("Packet at index %d has value %d, expected %d", i, ready[i][0], expected)
		}
	}
}

func TestReorderBuffer_DuplicateHandling(t *testing.T) {
	rb := NewReorderBuffer(100 * time.Millisecond)

	rb.Insert(1, []byte("pkt1"))
	rb.Insert(2, []byte("pkt2"))

	// Duplicate 2 arrives
	dup := rb.Insert(2, []byte("pkt2_dup"))
	if len(dup) != 0 {
		t.Fatalf("Expected duplicate to be rejected, got %v", dup)
	}

	stats := rb.Stats()
	if stats.Duplicates != 1 {
		t.Fatalf("Expected 1 duplicate counter, got %d", stats.Duplicates)
	}
}

func TestReorderBuffer_GapTimeout(t *testing.T) {
	timeout := 50 * time.Millisecond
	rb := NewReorderBuffer(timeout)

	// Packet 1 delivered
	rb.Insert(1, []byte("pkt1"))

	// Packet 3 arrives (pkt 2 missing)
	rb.Insert(3, []byte("pkt3"))

	// Sleep past timeout
	time.Sleep(70 * time.Millisecond)

	// CheckTimeout should flush pkt3 and mark pkt2 as dropped
	flushed := rb.CheckTimeout()
	if len(flushed) != 1 || !bytes.Equal(flushed[0], []byte("pkt3")) {
		t.Fatalf("Expected pkt3 flushed after timeout, got %v", flushed)
	}

	stats := rb.Stats()
	if stats.Dropped != 1 {
		t.Fatalf("Expected 1 dropped packet, got %d", stats.Dropped)
	}
	if stats.Delivered != 2 {
		t.Fatalf("Expected 2 delivered packets (pkt1 and pkt3), got %d", stats.Delivered)
	}
}
