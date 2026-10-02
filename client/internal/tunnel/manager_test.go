package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"

	"internet-bonding/client/internal/adapter"
)

func TestManagedPath_TxWorker_QueueAndDrain(t *testing.T) {
	// Set up local UDP listener to act as mock remote server
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to bind UDP server: %v", err)
	}
	defer serverConn.Close()
	remoteAddr := serverConn.LocalAddr().(*net.UDPAddr)

	// Set up client tunnel
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to bind UDP client: %v", err)
	}
	tun := &ClientTunnel{
		conn: clientConn,
		cfg: TunnelConfig{
			InterfaceName: "TestLoopback",
			LocalIP:       net.ParseIP("127.0.0.1"),
			RemoteAddr:    remoteAddr,
		},
	}

	mp := &ManagedPath{
		PathID: 1,
		Interface: adapter.NetworkInterface{
			Index: 1,
			Name:  "TestLoopback",
			IPv4:  net.ParseIP("127.0.0.1"),
		},
		Tunnel: tun,
		Health: NewPathHealth(1, "TestLoopback", 1, net.ParseIP("127.0.0.1")),
	}

	// Start asynchronous TX worker with queue capacity 32
	mp.StartTxWorker(remoteAddr, 32)
	defer mp.StopTxWorker()

	testData := [][]byte{
		[]byte("packet-1-alpha"),
		[]byte("packet-2-bravo"),
		[]byte("packet-3-charlie"),
	}

	for i, d := range testData {
		ok := mp.TryEnqueueTx(d, len(d), uint32(i+1))
		if !ok {
			t.Fatalf("Failed to enqueue packet %d", i+1)
		}
	}

	// Verify server receives all 3 packets
	_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	for i, expected := range testData {
		n, _, err := serverConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("Failed to read packet %d on server: %v", i+1, err)
		}
		if !bytes.Equal(buf[:n], expected) {
			t.Errorf("Packet %d mismatch: got %s, want %s", i+1, string(buf[:n]), string(expected))
		}
	}

	// Verify traffic stats recorded
	txB, txP, _, _ := mp.TrafficStats()
	if txP != 3 {
		t.Errorf("Expected 3 TX packets recorded, got %d", txP)
	}
	expectedBytes := uint64(len(testData[0]) + len(testData[1]) + len(testData[2]))
	if txB != expectedBytes {
		t.Errorf("Expected %d TX bytes recorded, got %d", expectedBytes, txB)
	}
}

func TestManagedPath_TryEnqueueTx_Saturation(t *testing.T) {
	mp := &ManagedPath{
		PathID:  2,
		txQueue: make(chan TxItem, 2), // Capacity 2, worker not started
	}

	p1 := []byte("p1")
	p2 := []byte("p2")
	p3 := []byte("p3")

	if !mp.TryEnqueueTx(p1, len(p1), 1) {
		t.Errorf("Expected p1 enqueue to succeed")
	}
	if !mp.TryEnqueueTx(p2, len(p2), 2) {
		t.Errorf("Expected p2 enqueue to succeed")
	}
	if mp.TxQueueDepth() != 2 {
		t.Errorf("Expected TxQueueDepth=2, got %d", mp.TxQueueDepth())
	}

	// 3rd item must fail non-blocking without panic
	if mp.TryEnqueueTx(p3, len(p3), 3) {
		t.Errorf("Expected p3 enqueue to fail due to queue saturation")
	}

	// Test EnqueueTxOrBlock with short timeout
	blocked := mp.EnqueueTxOrBlock(p3, len(p3), 3, 20*time.Millisecond)
	if blocked {
		t.Errorf("Expected EnqueueTxOrBlock to return false on full queue after timeout")
	}
}
