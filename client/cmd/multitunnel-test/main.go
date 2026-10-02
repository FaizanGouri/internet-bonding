package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"internet-bonding/client/internal/adapter"
	"internet-bonding/client/internal/tunnel"
)

func main() {
	serverFlag := flag.String("server", "", "VPS server UDP address (host:port, e.g. 20.255.152.76:51820)")
	pskHex := flag.String("psk", "", "Hex-encoded 32-byte Pre-Shared Key (or set BONDING_PSK env)")
	countFlag := flag.Int("count", 50, "Number of probes to transmit per active path")
	intervalFlag := flag.Duration("interval", 100*time.Millisecond, "Interval between probe transmissions")
	flag.Parse()

	if *serverFlag == "" {
		fmt.Println("Usage: multitunnel-test -server <VPS_IP:PORT> [-psk <hex_key>] [-count 50] [-interval 100ms]")
		os.Exit(1)
	}

	// Resolve PSK from flag or environment
	var psk []byte
	pskStr := *pskHex
	if pskStr == "" {
		pskStr = os.Getenv("BONDING_PSK")
	}
	if pskStr != "" {
		decoded, err := hex.DecodeString(pskStr)
		if err != nil || len(decoded) != 32 {
			fmt.Fprintf(os.Stderr, "Error: Invalid PSK: must be a 64-character hex string (32 bytes)\n")
			os.Exit(1)
		}
		psk = decoded
	}

	remoteAddr, err := net.ResolveUDPAddr("udp4", *serverFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid VPS address %q: %v\n", *serverFlag, err)
		os.Exit(1)
	}

	fmt.Println("==================================================")
	fmt.Println(" True Internet Bonding: Phase 3B Multi-Tunnel Test")
	fmt.Println("==================================================")
	fmt.Println()

	// 1. Discover physical network interfaces
	discoverer := adapter.NewDiscoverer()
	res, err := discoverer.Discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Adapter discovery failed: %v\n", err)
		os.Exit(1)
	}

	if len(res.Physical) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No physical adapters discovered.\n")
		os.Exit(1)
	}

	// 2. Initialize TunnelManager
	tm, err := tunnel.NewTunnelManager(res.Physical, remoteAddr, psk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize TunnelManager: %v\n", err)
		os.Exit(1)
	}
	defer tm.Close()

	fmt.Printf("Active Session ID : 0x%016X\n", tm.SessionID())
	fmt.Printf("VPS Target        : %s\n", remoteAddr.String())
	if len(psk) > 0 {
		fmt.Printf("Security          : HMAC-SHA256 active (32-byte PSK)\n")
	} else {
		fmt.Printf("Security          : Compatibility mode (zero PSK)\n")
	}
	fmt.Println()

	var activePaths []*tunnel.ManagedPath
	fmt.Println("--- Discovered Physical Paths ---")
	for _, p := range tm.Paths() {
		if p.Tunnel != nil {
			activePaths = append(activePaths, p)
			fmt.Printf("[ACTIVE]  Path %d: %-15s (IfIndex: %2d) | IP: %-15s | Gateway: %s\n",
				p.PathID, p.Interface.Name, p.Interface.Index, p.Interface.IPv4, p.Interface.Gateway)
		} else {
			fmt.Printf("[STANDBY] Path %d: %-15s (IfIndex: %2d) | Link: %s (disconnected/no gateway)\n",
				p.PathID, p.Interface.Name, p.Interface.Index, p.Interface.String())
		}
	}
	fmt.Println()

	if len(activePaths) == 0 {
		fmt.Println("Error: No paths are currently active with a valid gateway.")
		os.Exit(1)
	}

	if len(activePaths) < 2 {
		fmt.Println("NOTE: Only 1 physical interface is currently connected.")
		fmt.Println("      Path 1 will be tested while Path 2 remains in STANDBY.")
		fmt.Println("      A true dual-path PASS requires two simultaneously connected physical interfaces.")
		fmt.Println()
	}

	// 3. Step 1: Initial Keepalives across active paths
	fmt.Println("--- Step 1: Initial Keepalive Exchange ---")
	for _, p := range activePaths {
		ack, rtt, err := tm.SendKeepalive(p.PathID)
		if err != nil {
			fmt.Printf("Path %d (%s) Keepalive: FAILED (%v)\n", p.PathID, p.Interface.Name, err)
		} else {
			fmt.Printf("Path %d (%s) Keepalive: ACK RECEIVED | Seq=%d | RTT=%.2f ms | Status=%s\n",
				p.PathID, p.Interface.Name, ack.SeqNum, float64(rtt.Microseconds())/1000.0, p.Health.Status)
		}
	}
	fmt.Println()

	// 4. Step 2: Concurrent Multi-Path Probe Transmission
	fmt.Printf("--- Step 2: Transmitting %d Probes per Active Path (interval: %v) ---\n", *countFlag, *intervalFlag)

	type pathStat struct {
		sent uint32
		recv uint32
		rtts []time.Duration
	}
	stats := make(map[uint8]*pathStat)
	for _, p := range activePaths {
		stats[p.PathID] = &pathStat{}
	}

	payload := []byte("Phase3BDualPathProbePayload123")

	for i := 1; i <= *countFlag; i++ {
		for _, p := range activePaths {
			st := stats[p.PathID]
			st.sent++

			resp, rtt, err := tm.SendProbe(p.PathID, payload)
			if err != nil {
				fmt.Printf("[Path %d] Seq %-3d: TIMEOUT (%v)\n", p.PathID, p.NextSeq()-1, err)
			} else {
				st.recv++
				st.rtts = append(st.rtts, rtt)
				_ = resp
				fmt.Printf("[Path %d] Seq %-3d: [OK] RTT=%6.2f ms | Status=%s\n",
					p.PathID, resp.SeqNum, float64(rtt.Microseconds())/1000.0, p.Health.Status)
			}
		}
		if i < *countFlag {
			time.Sleep(*intervalFlag)
		}
	}

	fmt.Println()
	fmt.Println("==================================================")
	fmt.Println("          Phase 3B Multi-Tunnel Test Summary       ")
	fmt.Println("==================================================")
	fmt.Printf("Session ID : 0x%016X\n", tm.SessionID())
	fmt.Printf("VPS Target : %s\n\n", remoteAddr.String())

	for _, p := range tm.Paths() {
		st := stats[p.PathID]
		if st == nil {
			fmt.Printf("Path %d (%s):\n", p.PathID, p.Interface.Name)
			fmt.Printf("  Status       : %s\n", p.Health.Status)
			fmt.Printf("  Reason       : Physical link down / no gateway (Standby)\n\n")
			continue
		}

		tunnelStats := tunnel.ComputeStats(st.sent, st.recv, st.rtts)
		status, srtt, _, jitter := p.Health.Snapshot()
		fmt.Printf("Path %d (%s, IfIndex: %d):\n", p.PathID, p.Interface.Name, p.Interface.Index)
		fmt.Printf("  Local IPv4   : %s\n", p.Interface.IPv4)
		fmt.Printf("  Status       : %s\n", status)
		fmt.Printf("  Packets Sent : %d\n", tunnelStats.PacketsSent)
		fmt.Printf("  Packets Recv : %d\n", tunnelStats.PacketsReceived)
		fmt.Printf("  Packet Loss  : %.1f%%\n", tunnelStats.LossPercent)
		if st.recv > 0 {
			fmt.Printf("  Min RTT      : %.2f ms\n", float64(tunnelStats.MinRTT.Microseconds())/1000.0)
			fmt.Printf("  Avg RTT      : %.2f ms\n", float64(tunnelStats.AvgRTT.Microseconds())/1000.0)
			fmt.Printf("  Max RTT      : %.2f ms\n", float64(tunnelStats.MaxRTT.Microseconds())/1000.0)
			fmt.Printf("  Smoothed RTT : %.2f ms\n", float64(srtt.Microseconds())/1000.0)
			fmt.Printf("  Jitter       : %.2f ms\n", float64(jitter.Microseconds())/1000.0)
		}
		fmt.Println()
	}
}
