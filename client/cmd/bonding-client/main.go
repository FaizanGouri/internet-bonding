package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"internet-bonding/client/internal/adapter"
	"internet-bonding/client/internal/pathhealth"
	"internet-bonding/client/internal/routing"
	"internet-bonding/client/internal/scheduler"
	"internet-bonding/client/internal/tunnel"
	"internet-bonding/client/internal/wintun"
	"internet-bonding/protocol"
	"internet-bonding/reorder"
)

const ProbeTimeoutThreshold = 2500 * time.Millisecond

type ClientMetrics struct {
	IPPacketsFromWintun uint64
	IPBytesFromWintun   uint64
	IPPacketsToWintun   uint64
	IPBytesToWintun     uint64
	DataPacketsSent     uint64
	DataPacketsRecv     uint64
	SecurityDrops       uint64
}

func main() {
	serverStr := flag.String("server", "20.255.152.76:51820", "Azure VPS UDP endpoint (host:port)")
	pskHex := flag.String("psk", "", "Hex-encoded 32-byte Pre-Shared Key (or set BONDING_PSK env)")
	clientIP := flag.String("ip", "10.8.0.2", "Client virtual tunnel IP")
	mask := flag.String("mask", "255.255.255.0", "Virtual tunnel subnet mask")
	vpsIP := flag.String("vps-ip", "10.8.0.1", "VPS virtual tunnel gateway IP")
	mtu := flag.Int("mtu", 1400, "Virtual adapter MTU")
	extraRoutes := flag.String("extra-routes", "", "Comma-separated extra CIDRs to route into tunnel (e.g. 1.1.1.1/32)")
	p1WeightFlag := flag.Int("p1-weight", 0, "Manual weight override for Path 1 (0 = dynamic auto-weight)")
	p2WeightFlag := flag.Int("p2-weight", 0, "Manual weight override for Path 2 (0 = dynamic auto-weight)")
	flag.Parse()

	if runtime.GOOS != "windows" {
		log.Fatalf("bonding-client is designed for Windows clients with Wintun")
	}

	// 1. Resolve PSK
	var psk []byte
	pskStr := *pskHex
	if pskStr == "" {
		pskStr = os.Getenv("BONDING_PSK")
	}
	if pskStr != "" {
		decoded, err := hex.DecodeString(pskStr)
		if err != nil || len(decoded) != 32 {
			log.Fatalf("Invalid PSK: must be a 64-character hex string (32 bytes)")
		}
		psk = decoded
	}

	// 2. Resolve Remote VPS Endpoint
	remoteAddr, err := net.ResolveUDPAddr("udp4", *serverStr)
	if err != nil {
		log.Fatalf("Failed to resolve server endpoint %s: %v", *serverStr, err)
	}

	fmt.Println("==========================================================")
	fmt.Println("   True Internet Bonding: Phase 3C Dual-Path Client       ")
	fmt.Println("==========================================================")
	fmt.Printf("Remote VPS Endpoint: %s\n", remoteAddr.String())
	fmt.Printf("Virtual Tunnel IP:   %s / %s (Gateway: %s, MTU: %d)\n", *clientIP, *mask, *vpsIP, *mtu)
	if len(psk) > 0 {
		fmt.Println("Security:            HMAC-SHA256 authenticated (PSK loaded)")
	} else {
		fmt.Println("Security:            Compatibility mode (no PSK)")
	}

	// 3. Discover Physical Network Adapters
	discoverer := adapter.NewDiscoverer()
	res, err := discoverer.Discover()
	if err != nil {
		log.Fatalf("Adapter discovery failed: %v", err)
	}

	var candidates []adapter.NetworkInterface
	for _, iface := range res.Physical {
		if iface.IsUp && iface.IPv4 != nil && !iface.IPv4.IsLinkLocalUnicast() && iface.Gateway != nil {
			candidates = append(candidates, iface)
		}
	}

	if len(candidates) == 0 {
		log.Fatalf("No active physical network interfaces found")
	}

	fmt.Printf("Detected %d active physical interface(s):\n", len(candidates))
	for i, c := range candidates {
		fmt.Printf("  [Path %d] %s (Index: %d, IP: %s, Gateway: %s)\n",
			i+1, c.Name, c.Index, c.IPv4.String(), c.Gateway.String())
	}
	fmt.Println()

	// 4. Initialize Tunnel Manager
	tm, err := tunnel.NewTunnelManager(candidates, remoteAddr, psk)
	if err != nil {
		log.Fatalf("Failed to initialize TunnelManager: %v", err)
	}
	defer tm.Close()

	// Start asynchronous per-path transmit workers (512 packet queue capacity each)
	tm.StartAllTxWorkers(512)

	fmt.Printf("Session Established: SessionID=0x%016X\n", tm.SessionID())

	// 5. Initialize Components: Scheduler, ReorderBuffer, RouteManager
	sched := scheduler.NewScheduler()
	for _, p := range tm.Paths() {
		initW := getPathBaselineWeight(p, *p1WeightFlag, *p2WeightFlag)
		sched.SetManualWeight(p.PathID, initW)
		fmt.Printf("[SCHEDULER] Path %d (%s) initialized with baseline weight %d\n",
			p.PathID, p.Interface.Name, initW)
	}
	reorderBuf := reorder.NewReorderBuffer(250*time.Millisecond, 1)
	routeMgr := routing.NewRouteManager()
	var metrics ClientMetrics

	// 6. Open Wintun Virtual Network Adapter
	fmt.Println("Initializing Wintun virtual adapter 'BondingAdapter'...")
	vAdapter, err := wintun.OpenWintun("BondingAdapter", *clientIP, *mask, *mtu)
	if err != nil {
		log.Fatalf("Failed to open Wintun adapter: %v\nNOTE: Administrator privileges required.", err)
	}
	defer vAdapter.Close()
	fmt.Printf("Wintun Adapter Ready: IfIndex=%d (IP=%s)\n", vAdapter.IfIndex(), *clientIP)

	// 7. Configure Windows Routing
	fmt.Println("Configuring route table...")
	// A. Host routes for VPS public IP via physical gateways to prevent routing loops
	for _, c := range candidates {
		vpsHostCIDR := fmt.Sprintf("%s/32", remoteAddr.IP.String())
		_ = routeMgr.AddRoute(vpsHostCIDR, c.Index, c.Gateway.String(), 1)
	}

	// B. Route for Tunnel Subnet (10.8.0.0/24) via Wintun interface
	tunnelSubnet := "10.8.0.0/24"
	if err := routeMgr.AddRoute(tunnelSubnet, vAdapter.IfIndex(), *vpsIP, 1); err != nil {
		log.Printf("[WARN] Failed to add tunnel subnet route: %v", err)
	} else {
		fmt.Printf("[ROUTING] Subnet %s -> Wintun gateway %s\n", tunnelSubnet, *vpsIP)
	}

	// C. Extra test routes if specified
	if *extraRoutes != "" {
		routes := strings.Split(*extraRoutes, ",")
		for _, r := range routes {
			r = strings.TrimSpace(r)
			if r != "" {
				if err := routeMgr.AddRoute(r, vAdapter.IfIndex(), *vpsIP, 1); err != nil {
					log.Printf("[WARN] Failed to add route %s: %v", r, err)
				} else {
					fmt.Printf("[ROUTING] Custom target %s -> Wintun gateway %s\n", r, *vpsIP)
				}
			}
		}
	}
	fmt.Println("Routing configured successfully.")
	fmt.Println("Bonding Engine ACTIVE. Press Ctrl+C to stop.")
	fmt.Println()

	// 8. Graceful Shutdown Hook
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	shutdownChan := make(chan struct{})

	go func() {
		<-sigChan
		fmt.Println("\nStopping Bonding Client gracefully...")
		close(shutdownChan)
		routeMgr.Cleanup()
		vAdapter.Close()
		tm.Close()
		fmt.Println("Cleanup complete. Exited.")
		os.Exit(0)
	}()

	// 9. Dedicated UDP Receiver Loop for each managed physical path
	type probeKey struct {
		pathID uint8
		seq    uint32
	}
	var probeMu sync.Mutex
	probeSendTimes := make(map[probeKey]time.Time)

	for _, p := range tm.Paths() {
		if p.PacketConn() == nil {
			continue
		}
		pathRef := p
		go func(mp *tunnel.ManagedPath) {
			recvBuf := make([]byte, 2048)
			for {
				select {
				case <-shutdownChan:
					return
				default:
				}

				n, _, err := mp.PacketConn().ReadFrom(recvBuf)
				if err != nil {
					return
				}

				var pkt protocol.Packet
				if err := pkt.UnmarshalBinary(recvBuf[:n]); err != nil {
					continue
				}

				// Validate SessionID
				if pkt.SessionID != tm.SessionID() {
					continue
				}

				// Verify HMAC
				if len(psk) > 0 && !protocol.VerifyAuthTag(psk, &pkt) {
					atomic.AddUint64(&metrics.SecurityDrops, 1)
					continue
				}

				// Process DATA packets from VPS
				if pkt.Type == protocol.PacketTypeData {
					mp.RecordRx(len(pkt.Payload))
					atomic.AddUint64(&metrics.DataPacketsRecv, 1)
					inOrder := reorderBuf.Insert(pkt.SeqNum, pkt.Payload)
					for _, ipPkt := range inOrder {
						wn, err := vAdapter.Write(ipPkt)
						if err == nil {
							atomic.AddUint64(&metrics.IPBytesToWintun, uint64(wn))
							delivered := atomic.AddUint64(&metrics.IPPacketsToWintun, 1)
							if delivered <= 10 || delivered%25 == 0 {
								fmt.Printf("[%s] DATA In: Delivered %d bytes to Wintun (Total delivered: %d)\n",
									time.Now().Format("15:04:05.000"), wn, delivered)
							}
						} else {
							log.Printf("[WINTUN WRITE ERROR] %v", err)
						}
					}
					continue
				}

				// Process KeepaliveAck packets: Monotonic client-side RTT measurement
				if pkt.Type == protocol.PacketTypeKeepaliveAck {
					probeMu.Lock()
					key := probeKey{pathID: mp.PathID, seq: pkt.SeqNum}
					sendTime, exists := probeSendTimes[key]
					if exists {
						delete(probeSendTimes, key)
					}
					probeMu.Unlock()

					// Discard orphaned or late ACKs whose probe was already timed out/removed
					// Never calculate RTT using pkt.Timestamp as fallback
					if !exists {
						continue
					}

					rtt := time.Since(sendTime)
					if rtt < 0 {
						rtt = 0
					}
					changed, oldStatus, newStatus := mp.Health.RecordProbeResult(true, rtt, nil)
					if changed {
						fmt.Printf("[%s] [PATH] P%d (%s): %s -> %s (RTT: %.1fms)\n",
							time.Now().Format("15:04:05.000"), mp.PathID, mp.Interface.Name, oldStatus, newStatus, float64(rtt.Microseconds())/1000.0)
					}
					continue
				}
			}
		}(pathRef)
	}

	// 10. Real-Time Physical Interface Monitor (polls OS every 300ms via native IP Helper API)
	physMonitor := pathhealth.NewMonitor()
	var monitoredTargets []pathhealth.MonitoredTarget
	for _, p := range tm.Paths() {
		monitoredTargets = append(monitoredTargets, pathhealth.MonitoredTarget{
			IfIndex: p.Interface.Index,
			Name:    p.Interface.Name,
		})
	}

	go func() {
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-shutdownChan:
				return
			case <-ticker.C:
				states, err := physMonitor.CheckAll(monitoredTargets)
				if err != nil {
					continue
				}

				for _, p := range tm.Paths() {
					st, ok := states[p.Interface.Index]
					if !ok {
						for _, s := range states {
							if s.Name == p.Interface.Name {
								st = s
								ok = true
								break
							}
						}
					}

					available := ok && st.Available()
					reason := "operational"
					if !ok {
						reason = "adapter not found or disabled in OS"
					} else if !available {
						reason = st.Reason
					}

					changed, oldStatus, newStatus := p.Health.SetPhysicalState(available, reason)
					if changed {
						fmt.Printf("[%s] [PHYSICAL] P%d (%s): %s -> %s (Reason: %s)\n",
							time.Now().Format("15:04:05.000"),
							p.PathID, p.Interface.Name,
							oldStatus, newStatus, reason)
					}
				}
			}
		}
	}()

	// 11. Background Keepalive Prober, Probe Timeout Checker & Gap Timer
	go func() {
		ticker := time.NewTicker(1000 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-shutdownChan:
				return
			case <-ticker.C:
				now := time.Now()

				// Check for timed out probes (> ProbeTimeoutThreshold)
				var timedOutPaths []uint8
				probeMu.Lock()
				for k, t := range probeSendTimes {
					if now.Sub(t) > ProbeTimeoutThreshold {
						delete(probeSendTimes, k)
						timedOutPaths = append(timedOutPaths, k.pathID)
					}
				}
				probeMu.Unlock()

				for _, pid := range timedOutPaths {
					p := tm.GetPath(pid)
					if p != nil {
						changed, oldStatus, newStatus := p.Health.RecordProbeResult(false, 0, fmt.Errorf("probe timeout (>%v)", ProbeTimeoutThreshold))
						if changed {
							fmt.Printf("[%s] [PROBE] P%d (%s): %s -> %s (keepalive timeout)\n",
								time.Now().Format("15:04:05.000"), p.PathID, p.Interface.Name, oldStatus, newStatus)
						}
					}
				}

				// Send keepalive probe with client path weight feedback on each path
				for _, p := range tm.Paths() {
					if p.PacketConn() == nil {
						continue
					}
					seq := p.NextSeq()

					// Compute client path weight to feedback to VPS downstream scheduler
					st, srtt, loss, consec, available := p.Health.QualityMetrics()
					w := uint8(0)
					if available {
						baseW := getPathBaselineWeight(p, *p1WeightFlag, *p2WeightFlag)
						w = uint8(scheduler.CalculateWeightWithManual(st, srtt, loss, consec, baseW))
						sched.SetManualWeight(p.PathID, int(w))
					}

					kp := protocol.NewV2Packet(protocol.PacketTypeKeepalive, tm.SessionID(), p.PathID, seq, []byte{w}, psk)
					raw, err := kp.MarshalBinary()
					if err == nil {
						probeMu.Lock()
						probeSendTimes[probeKey{pathID: p.PathID, seq: seq}] = time.Now()
						// Prune old entries if map grows
						if len(probeSendTimes) > 200 {
							for k, t := range probeSendTimes {
								if now.Sub(t) > 10*time.Second {
									delete(probeSendTimes, k)
								}
							}
						}
						probeMu.Unlock()

						_, _ = p.WriteRaw(raw, remoteAddr)
					}
				}
			}
		}
	}()

	// Reorder Buffer High-Frequency Gap Flush Loop (10ms ticker, 250ms timeout)
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-shutdownChan:
				return
			case <-ticker.C:
				flushed := reorderBuf.CheckTimeout()
				for _, ipPkt := range flushed {
					wn, err := vAdapter.Write(ipPkt)
					if err == nil {
						atomic.AddUint64(&metrics.IPBytesToWintun, uint64(wn))
						delivered := atomic.AddUint64(&metrics.IPPacketsToWintun, 1)
						if delivered <= 10 || delivered%50 == 0 {
							fmt.Printf("[%s] DATA In (Gap Flush): Delivered %d bytes to Wintun (Total: %d)\n",
								time.Now().Format("15:04:05.000"), wn, delivered)
						}
					}
				}
			}
		}
	}()

	// 11. Wintun Reader Loop: Intercepts Outgoing IP datagrams and sends via dual UDP paths
	go func() {
		wintunBuf := make([]byte, 2048)
		for {
			select {
			case <-shutdownChan:
				return
			default:
			}

			n, err := vAdapter.Read(wintunBuf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}

			atomic.AddUint64(&metrics.IPPacketsFromWintun, 1)
			atomic.AddUint64(&metrics.IPBytesFromWintun, uint64(n))

			// Select active path via scheduler
			selectedPath := sched.SelectPath(tm.Paths())
			if selectedPath == nil {
				// No paths active; drop packet
				continue
			}

			seq := sched.NextDataSeqNum()
			dataPkt := protocol.NewDataPacket(tm.SessionID(), selectedPath.PathID, seq, wintunBuf[:n], psk)
			raw, err := dataPkt.MarshalBinary()
			if err != nil {
				continue
			}

			// Non-blocking submission to selected path's asynchronous TX worker queue
			if selectedPath.TryEnqueueTx(raw, n, seq) {
				sentCount := atomic.AddUint64(&metrics.DataPacketsSent, 1)
				if sentCount <= 20 || sentCount%100 == 0 {
					fmt.Printf("[%s] [SCHEDULER] DATA seq=%d (%dB) -> P%d (%s) [Q=%d/512] (Total: %d)\n",
						time.Now().Format("15:04:05.000"), seq, n, selectedPath.PathID, selectedPath.Interface.Name, selectedPath.TxQueueDepth(), sentCount)
				}
				continue
			}

			// Selected path queue saturated: divert packet to alternate active path without dropping
			diverted := false
			for _, altPath := range tm.Paths() {
				if altPath.PathID != selectedPath.PathID {
					st, _, _, _, avail := altPath.Health.QualityMetrics()
					if avail && (st == tunnel.StatusUp || st == tunnel.StatusDegraded) {
						altPkt := protocol.NewDataPacket(tm.SessionID(), altPath.PathID, seq, wintunBuf[:n], psk)
						if altRaw, altErr := altPkt.MarshalBinary(); altErr == nil {
							if altPath.TryEnqueueTx(altRaw, n, seq) {
								sentCount := atomic.AddUint64(&metrics.DataPacketsSent, 1)
								if sentCount <= 20 || sentCount%50 == 0 {
									fmt.Printf("[%s] [SCHEDULER] DATA seq=%d (%dB) -> P%d (%s) [DIVERT P%d Q-FULL] (Total: %d)\n",
										time.Now().Format("15:04:05.000"), seq, n, altPath.PathID, altPath.Interface.Name, selectedPath.PathID, sentCount)
								}
								diverted = true
								break
							}
						}
					}
				}
			}

			if !diverted {
				// All active queues temporarily saturated: apply bounded backpressure (up to 50ms)
				if selectedPath.EnqueueTxOrBlock(raw, n, seq, 50*time.Millisecond) {
					atomic.AddUint64(&metrics.DataPacketsSent, 1)
				} else {
					// Drop packet after backpressure timeout to prevent unbounded buffer growth
					atomic.AddUint64(&metrics.SecurityDrops, 1)
				}
			}
		}
	}()

	// 12. Real-Time Status Display
	statusTicker := time.NewTicker(3 * time.Second)
	defer statusTicker.Stop()

	var lastStatusTime time.Time = time.Now()
	var lastTxBytes uint64
	var lastRxBytes uint64
	var lastWintunInBytes uint64
	var lastWintunOutBytes uint64
	lastPathTxBytes := make(map[uint8]uint64)
	lastPathRxBytes := make(map[uint8]uint64)

	for {
		select {
		case <-shutdownChan:
			return
		case <-statusTicker.C:
			now := time.Now()
			elapsed := now.Sub(lastStatusTime).Seconds()
			if elapsed <= 0 {
				elapsed = 1
			}

			type pathInfo struct {
				p          *tunnel.ManagedPath
				st         tunnel.PathStatus
				srtt       time.Duration
				loss       float64
				weight     int
				txB        uint64
				txP        uint64
				assigned   uint64
				rxB        uint64
				rxP        uint64
				qDepth     int
				txRateMbps float64
				rxRateMbps float64
			}

			var pathsInfo []pathInfo
			var totalTxBytes, totalTxPkts, totalRxBytes, totalRxPkts uint64

			for _, p := range tm.Paths() {
				st, srtt, loss, consec, available := p.Health.QualityMetrics()
				w := 0
				if available {
					manualW := 0
					if p.PathID == 1 && *p1WeightFlag > 0 {
						manualW = *p1WeightFlag
					} else if p.PathID == 2 && *p2WeightFlag > 0 {
						manualW = *p2WeightFlag
					}
					w = scheduler.CalculateWeightWithManual(st, srtt, loss, consec, manualW)
				}
				txB, txP, rxB, rxP := p.TrafficStats()
				assigned := p.PacketsAssigned()
				totalTxBytes += txB
				totalTxPkts += txP
				totalRxBytes += rxB
				totalRxPkts += rxP

				prevTx := lastPathTxBytes[p.PathID]
				prevRx := lastPathRxBytes[p.PathID]
				pTxRate := float64((txB-prevTx)*8) / (elapsed * 1_000_000)
				pRxRate := float64((rxB-prevRx)*8) / (elapsed * 1_000_000)
				lastPathTxBytes[p.PathID] = txB
				lastPathRxBytes[p.PathID] = rxB

				pathsInfo = append(pathsInfo, pathInfo{
					p:          p,
					st:         st,
					srtt:       srtt,
					loss:       loss,
					weight:     w,
					txB:        txB,
					txP:        txP,
					assigned:   assigned,
					rxB:        rxB,
					rxP:        rxP,
					qDepth:     p.TxQueueDepth(),
					txRateMbps: pTxRate,
					rxRateMbps: pRxRate,
				})
			}

			txRateMbps := float64((totalTxBytes-lastTxBytes)*8) / (elapsed * 1_000_000)
			rxRateMbps := float64((totalRxBytes-lastRxBytes)*8) / (elapsed * 1_000_000)
			lastTxBytes = totalTxBytes
			lastRxBytes = totalRxBytes

			currWintunInBytes := atomic.LoadUint64(&metrics.IPBytesFromWintun)
			currWintunOutBytes := atomic.LoadUint64(&metrics.IPBytesToWintun)
			wintunInRateMbps := float64((currWintunInBytes-lastWintunInBytes)*8) / (elapsed * 1_000_000)
			wintunOutRateMbps := float64((currWintunOutBytes-lastWintunOutBytes)*8) / (elapsed * 1_000_000)
			lastWintunInBytes = currWintunInBytes
			lastWintunOutBytes = currWintunOutBytes

			lastStatusTime = now

			rStats := reorderBuf.Stats()

			fmt.Println("--------------------------------------------------------------------------------")
			fmt.Printf("[%s] BONDING STATUS | Wire Agg: TX %5.2f Mbps, RX %5.2f Mbps | Wintun: TX %5.2f Mbps, RX %5.2f Mbps\n",
				now.Format("15:04:05"), txRateMbps, rxRateMbps, wintunInRateMbps, wintunOutRateMbps)

			var pathDetails []string
			for _, pi := range pathsInfo {
				pathDetails = append(pathDetails, fmt.Sprintf("P%d(%s): %-8s RTT=%5.1fms Loss=%4.1f%% W=%-2d TX=%5.2fM RX=%5.2fM Q=%d/512 (Sent=%d, Assigned=%d)",
					pi.p.PathID, pi.p.Interface.Name, pi.st, float64(pi.srtt.Milliseconds()), pi.loss, pi.weight, pi.txRateMbps, pi.rxRateMbps, pi.qDepth, pi.txP, pi.assigned))
			}
			fmt.Printf("  PATHS: %s\n", strings.Join(pathDetails, " | "))

			var txParts []string
			for _, pi := range pathsInfo {
				share := 0.0
				if totalTxBytes > 0 {
					share = float64(pi.txB) / float64(totalTxBytes) * 100.0
				}
				txParts = append(txParts, fmt.Sprintf("P%d: %s (%d sent, %d assigned, %4.1f%%, %5.2f Mbps)",
					pi.p.PathID, formatBytes(pi.txB), pi.txP, pi.assigned, share, pi.txRateMbps))
			}
			fmt.Printf("  TX:    %s (%d pkts) | %s\n", formatBytes(totalTxBytes), totalTxPkts, strings.Join(txParts, " | "))

			var rxParts []string
			for _, pi := range pathsInfo {
				share := 0.0
				if totalRxBytes > 0 {
					share = float64(pi.rxB) / float64(totalRxBytes) * 100.0
				}
				rxParts = append(rxParts, fmt.Sprintf("P%d: %s (%d pkts, %4.1f%%, %5.2f Mbps)",
					pi.p.PathID, formatBytes(pi.rxB), pi.rxP, share, pi.rxRateMbps))
			}
			fmt.Printf("  RX:    %s (%d pkts) | %s\n", formatBytes(totalRxBytes), totalRxPkts, strings.Join(rxParts, " | "))

			fmt.Printf("  QUEUE: Reorder(Q=%d, Recv=%d, Reord=%d, Drop=%d, Dupl=%d, Deliv=%d) | Wintun(In=%d pkts, Out=%d pkts, Drops=%d)\n",
				rStats.QueueDepth, rStats.Received, rStats.Reordered, rStats.Dropped, rStats.Duplicates, rStats.Delivered,
				atomic.LoadUint64(&metrics.IPPacketsFromWintun),
				atomic.LoadUint64(&metrics.IPPacketsToWintun),
				atomic.LoadUint64(&metrics.SecurityDrops),
			)
			fmt.Println("--------------------------------------------------------------------------------")
		}
	}
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.2f GB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.2f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// getPathBaselineWeight determines the appropriate baseline weight for an interface.
// Respects manual overrides if configured. For auto-mode: cellular tethering (Remote NDIS / Mobile)
// gets weight 1 to prevent queue saturation, while Wi-Fi and wired Gigabit Ethernet get weight 10.
func getPathBaselineWeight(p *tunnel.ManagedPath, p1W int, p2W int) int {
	if p == nil {
		return 1
	}
	if p.PathID == 1 && p1W > 0 {
		return p1W
	}
	if p.PathID == 2 && p2W > 0 {
		return p2W
	}
	descLower := strings.ToLower(p.Interface.Description)
	nameLower := strings.ToLower(p.Interface.Name)
	isCellular := strings.Contains(descLower, "remote ndis") ||
		strings.Contains(descLower, "cellular") ||
		strings.Contains(descLower, "mobile") ||
		strings.Contains(nameLower, "cellular")
	if isCellular {
		return 1
	}
	return 10
}
