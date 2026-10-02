package reorder

import (
	"sync"
	"sync/atomic"
	"time"
)

// DefaultReorderTimeout is the default duration to wait for a missing sequence number before skipping the gap.
const DefaultReorderTimeout = 40 * time.Millisecond

// DefaultMaxBufferSize is the maximum number of out-of-order packets retained before forcing a flush.
const DefaultMaxBufferSize = 512

// ReorderStats tracks operational metrics for the reorder buffer.
type ReorderStats struct {
	Received   uint64
	Reordered  uint64
	Duplicates uint64
	Dropped    uint64
	Delivered  uint64
}

// packetEntry holds a buffered packet and its arrival timestamp.
type packetEntry struct {
	data      []byte
	arrivedAt time.Time
}

// ReorderBuffer manages packet reordering to deliver in-order datagrams to the virtual interface.
type ReorderBuffer struct {
	mu              sync.Mutex
	nextExpectedSeq uint32
	initialized     bool
	timeout         time.Duration
	maxBufferSize   int
	buffer          map[uint32]packetEntry
	gapTimerStart   time.Time
	hasGap          bool

	// Stats
	received   uint64
	reordered  uint64
	duplicates uint64
	dropped    uint64
	delivered  uint64
}

// NewReorderBuffer creates a new ReorderBuffer with specified timeout.
// If initialSeq is provided, it explicitly defines the expected first sequence number.
func NewReorderBuffer(timeout time.Duration, initialSeq ...uint32) *ReorderBuffer {
	if timeout <= 0 {
		timeout = DefaultReorderTimeout
	}
	rb := &ReorderBuffer{
		timeout:       timeout,
		maxBufferSize: DefaultMaxBufferSize,
		buffer:        make(map[uint32]packetEntry),
	}
	if len(initialSeq) > 0 {
		rb.initialized = true
		rb.nextExpectedSeq = initialSeq[0]
	}
	return rb
}

// SetNextExpectedSeq explicitly sets the expected sequence number.
func (rb *ReorderBuffer) SetNextExpectedSeq(seq uint32) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.initialized = true
	rb.nextExpectedSeq = seq
}

// Stats returns a snapshot of reorder buffer counters.
func (rb *ReorderBuffer) Stats() ReorderStats {
	return ReorderStats{
		Received:   atomic.LoadUint64(&rb.received),
		Reordered:  atomic.LoadUint64(&rb.reordered),
		Duplicates: atomic.LoadUint64(&rb.duplicates),
		Dropped:    atomic.LoadUint64(&rb.dropped),
		Delivered:  atomic.LoadUint64(&rb.delivered),
	}
}

// Insert processes an incoming packet with its sequence number and returns any packets ready for delivery in order.
func (rb *ReorderBuffer) Insert(seqNum uint32, data []byte) [][]byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	now := time.Now()
	atomic.AddUint64(&rb.received, 1)

	// First packet initializes the sequence stream
	if !rb.initialized {
		rb.initialized = true
		rb.nextExpectedSeq = seqNum
	}

	var ready [][]byte

	// Case 1: Exactly the expected sequence number
	if seqNum == rb.nextExpectedSeq {
		ready = append(ready, data)
		atomic.AddUint64(&rb.delivered, 1)
		rb.nextExpectedSeq++

		// Deliver any contiguous packets waiting in the buffer
		for {
			if entry, exists := rb.buffer[rb.nextExpectedSeq]; exists {
				ready = append(ready, entry.data)
				delete(rb.buffer, rb.nextExpectedSeq)
				atomic.AddUint64(&rb.delivered, 1)
				rb.nextExpectedSeq++
			} else {
				break
			}
		}

		if len(rb.buffer) == 0 {
			rb.hasGap = false
		} else {
			// There is still a subsequent gap; reset gap timer for new nextExpectedSeq
			rb.hasGap = true
			rb.gapTimerStart = now
		}
		return ready
	}

	// Case 2: Past sequence number (Duplicate or Late packet)
	// Using signed 32-bit comparison to handle wrap-around correctly
	diff := int32(seqNum - rb.nextExpectedSeq)
	if diff < 0 {
		atomic.AddUint64(&rb.duplicates, 1)
		return nil
	}

	// Case 3: Future sequence number (Out of order)
	atomic.AddUint64(&rb.reordered, 1)

	// Prevent buffer exhaustion if gap is unreasonably large
	if len(rb.buffer) >= rb.maxBufferSize || diff > int32(rb.maxBufferSize) {
		// Flush all buffered packets and advance
		ready = rb.flushGapsLocked(now)
		// Now insert this packet
		rb.nextExpectedSeq = seqNum + 1
		ready = append(ready, data)
		atomic.AddUint64(&rb.delivered, 1)
		rb.hasGap = false
		return ready
	}

	// Store in buffer
	if _, exists := rb.buffer[seqNum]; !exists {
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		rb.buffer[seqNum] = packetEntry{
			data:      dataCopy,
			arrivedAt: now,
		}
	} else {
		atomic.AddUint64(&rb.duplicates, 1)
		return nil
	}

	if !rb.hasGap {
		rb.hasGap = true
		rb.gapTimerStart = now
	}

	// Check if the current gap has timed out
	if now.Sub(rb.gapTimerStart) >= rb.timeout {
		gapPackets := rb.flushGapsLocked(now)
		ready = append(ready, gapPackets...)
	}

	return ready
}

// CheckTimeout inspects if the waiting gap has exceeded the timeout and flushes ready packets.
// Call this periodically or when idle.
func (rb *ReorderBuffer) CheckTimeout() [][]byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if !rb.hasGap || len(rb.buffer) == 0 {
		return nil
	}

	now := time.Now()
	if now.Sub(rb.gapTimerStart) >= rb.timeout {
		return rb.flushGapsLocked(now)
	}

	return nil
}

// flushGapsLocked skips missing packets up to the earliest buffered sequence and delivers contiguous items.
// Must be called with rb.mu held.
func (rb *ReorderBuffer) flushGapsLocked(now time.Time) [][]byte {
	if len(rb.buffer) == 0 {
		rb.hasGap = false
		return nil
	}

	// Find the minimum sequence number currently buffered
	var minSeq uint32
	first := true
	for seq := range rb.buffer {
		if first {
			minSeq = seq
			first = false
		} else {
			if int32(seq-minSeq) < 0 {
				minSeq = seq
			}
		}
	}

	// Record skipped packets as dropped
	skipped := uint64(minSeq - rb.nextExpectedSeq)
	atomic.AddUint64(&rb.dropped, skipped)

	rb.nextExpectedSeq = minSeq

	var ready [][]byte
	for {
		if entry, exists := rb.buffer[rb.nextExpectedSeq]; exists {
			ready = append(ready, entry.data)
			delete(rb.buffer, rb.nextExpectedSeq)
			atomic.AddUint64(&rb.delivered, 1)
			rb.nextExpectedSeq++
		} else {
			break
		}
	}

	if len(rb.buffer) == 0 {
		rb.hasGap = false
	} else {
		rb.hasGap = true
		rb.gapTimerStart = now
	}

	return ready
}
