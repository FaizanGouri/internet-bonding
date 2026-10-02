package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"internet-bonding/client/internal/adapter"
	"internet-bonding/client/internal/tunnel"
)

func main() {
	serverFlag := flag.String("server", "", "VPS server address (host:port, e.g. 203.0.113.50:51820)")
	countFlag := flag.Int("count", 100, "Number of test packets to transmit")
	intervalFlag := flag.Duration("interval", 20*time.Millisecond, "Interval between packet transmissions")
	ifaceFlag := flag.String("iface", "", "Specific interface name to use (default: first active physical adapter, e.g. Wi-Fi)")
	flag.Parse()

	if *serverFlag == "" {
		fmt.Println("Usage: tunnel-test -server <VPS_IP:PORT> [-count 100] [-interval 20ms] [-iface <name>]")
		os.Exit(1)
	}

	remoteAddr, err := net.ResolveUDPAddr("udp4", *serverFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid VPS address %q: %v\n", *serverFlag, err)
		os.Exit(1)
	}

	fmt.Println("==================================================")
	fmt.Println("    True Internet Bonding: UDP Tunnel Test (CLI)  ")
	fmt.Println("==================================================")
	fmt.Println()

	// 1. Discover physical adapters via Phase 1 adapter package
	discoverer := adapter.NewDiscoverer()
	res, err := discoverer.Discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Adapter discovery failed: %v\n", err)
		os.Exit(1)
	}

	var selected *adapter.NetworkInterface
	for i := range res.Physical {
		candidate := &res.Physical[i]
		if *ifaceFlag != "" {
			if candidate.Name == *ifaceFlag {
				selected = candidate
				break
			}
		} else {
			// Prefer Wi-Fi or any active adapter with an assigned IPv4 and gateway
			if candidate.IsUp && candidate.IPv4 != nil && candidate.Gateway != nil {
				if candidate.Type == adapter.TypeWiFi {
					selected = candidate
					break
				}
				if selected == nil {
					selected = candidate
				}
			}
		}
	}

	if selected == nil {
		fmt.Fprintf(os.Stderr, "Error: No active physical network interface available for testing.\n")
		os.Exit(1)
	}

	// 2. Configure interface-bound tunnel
	cfg := tunnel.TunnelConfig{
		InterfaceName: selected.Name,
		IfIndex:       selected.Index,
		LocalIP:       selected.IPv4,
		RemoteAddr:    remoteAddr,
		ReadTimeout:   1000 * time.Millisecond,
	}

	fmt.Println("--- Path Configuration ---")
	fmt.Printf("Selected Interface : %s (%s)\n", selected.Name, selected.Description)
	fmt.Printf("IfIndex            : %d\n", selected.Index)
	fmt.Printf("Local IPv4         : %s\n", selected.IPv4)
	fmt.Printf("Gateway            : %s\n", selected.Gateway)
	fmt.Printf("VPS Destination    : %s\n", remoteAddr.String())
	fmt.Printf("Socket Binding     : Local IP %s:0 with IP_UNICAST_IF=%d\n", selected.IPv4, selected.Index)
	fmt.Println()

	clientTunnel, err := tunnel.NewClientTunnel(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to establish client tunnel socket: %v\n", err)
		os.Exit(1)
	}
	defer clientTunnel.Close()

	fmt.Printf("Sending %d test packets (interval: %v)...\n\n", *countFlag, *intervalFlag)

	var sentCount uint32
	var recvCount uint32
	var rtts []time.Duration

	payload := []byte("AntigravityBondingTunnelTestProbeData")

	for i := 1; i <= *countFlag; i++ {
		seqNum := uint32(i)
		sentCount++

		resp, rtt, err := clientTunnel.SendProbe(seqNum, payload)
		if err != nil {
			fmt.Printf("Seq %-3d: [TIMEOUT/LOST] (%v)\n", seqNum, err)
		} else {
			recvCount++
			rtts = append(rtts, rtt)
			_ = resp
			fmt.Printf("Seq %-3d: [OK] RTT = %6.2f ms\n", seqNum, float64(rtt.Microseconds())/1000.0)
		}

		if i < *countFlag {
			time.Sleep(*intervalFlag)
		}
	}

	fmt.Println()
	fmt.Println("--- Tunnel Test Summary ---")
	stats := tunnel.ComputeStats(sentCount, recvCount, rtts)
	fmt.Printf("Interface         : %s\n", selected.Name)
	fmt.Printf("IfIndex           : %d\n", selected.Index)
	fmt.Printf("Local IP          : %s\n", selected.IPv4)
	fmt.Printf("VPS IP/Port       : %s\n", remoteAddr.String())
	fmt.Printf("Packets Sent      : %d\n", stats.PacketsSent)
	fmt.Printf("Packets Received  : %d\n", stats.PacketsReceived)
	fmt.Printf("Packet Loss       : %.1f%%\n", stats.LossPercent)
	if stats.PacketsReceived > 0 {
		fmt.Printf("Minimum RTT       : %.2f ms\n", float64(stats.MinRTT.Microseconds())/1000.0)
		fmt.Printf("Average RTT       : %.2f ms\n", float64(stats.AvgRTT.Microseconds())/1000.0)
		fmt.Printf("Maximum RTT       : %.2f ms\n", float64(stats.MaxRTT.Microseconds())/1000.0)
	}
}
